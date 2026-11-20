import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildWebDist } from '../scripts/build-web-dist.mjs';
import { HostBridge } from '../src/host-bridge.js';
import {
  decodeClientFrame,
  decodeJSON,
  encodeClientFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
  MSG_E2EE_BOX,
  MSG_E2EE_CLIENT_HELLO,
  MSG_E2EE_ERROR,
  MSG_E2EE_HOST_HELLO,
  MSG_HTTP_REQ_END,
  MSG_HTTP_REQ_HEAD,
  MSG_HTTP_RES_BODY,
  MSG_HTTP_RES_END,
  MSG_HTTP_RES_HEAD,
  MSG_WS_CLOSE,
  MSG_WS_DATA_TEXT,
  MSG_WS_OPEN,
  MSG_WS_OPENED,
} from '../src/protocol.js';
import { generateE2eeSecret } from '../src/state.js';
import { createClientHandshake, generateLogicalSessionId, MSG_E2EE_CTRL } from '../web-src/e2ee.js';
import { createPath, MultipathSession } from '../web-src/multipath.js';
import { sendFragments, FragmentReader } from '../web-src/ws-fragments.js';

const PROJECT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));

async function getFreePort() {
  const srv = http.createServer();
  await new Promise((resolveListen) => srv.listen(0, '127.0.0.1', resolveListen));
  const { port } = srv.address();
  await new Promise((resolveClose) => srv.close(resolveClose));
  return port;
}

function acceptSimpleWebSocket(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    '',
  ].join('\r\n'));

  let buf = Buffer.alloc(0);
  const sendText = (text) => {
    const body = Buffer.from(text, 'utf8');
    const hdr = Buffer.alloc(2 + (body.length >= 126 ? 2 : 0));
    hdr[0] = 0x81;
    if (body.length < 126) {
      hdr[1] = body.length;
    } else {
      hdr[1] = 126;
      hdr.writeUInt16BE(body.length, 2);
    }
    socket.write(Buffer.concat([hdr, body]));
  };

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      }
      if (masked && buf.length < off + 4) return;
      const mask = masked ? buf.subarray(off, off + 4) : null;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      const payload = Buffer.from(buf.subarray(off, off + len));
      buf = buf.subarray(off + len);
      if (mask) {
        for (let i = 0; i < payload.length; i += 1) {
          payload[i] ^= mask[i % 4];
        }
      }
      if (opcode === 0x8) {
        socket.end();
        return;
      }
      if (opcode === 0x1) {
        sendText(`echo:${payload.toString('utf8')}`);
      }
    }
  });
}

test('buildWebDist produces valid .tweb bundle under 200 KiB without symlinks, dotfiles, or E2EE secrets', () => {
  const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-web-dist-'));
  try {
    const res = buildWebDist({
      outDir: tmpDir,
      config: { functionId: 'fn-test', webId: 'testweb00001', defaultHostId: 'my-host', appTitle: 'Test App' },
    });
    assert.ok(res.fileCount > 5 && res.fileCount < 4096);
    assert.ok(res.totalBytes < 200 * 1024);
    assert.equal(res.config.frontendEntry, undefined);
    assert.equal(res.config.pluginBundles, undefined);
    assert.equal('e2ee' in res.config, false);
    assert.equal('secret' in res.config, false);
    assert.equal(res.config.webId, 'testweb00001');
    assert.ok(!readdirSync(tmpDir, { recursive: true, withFileTypes: true }).some(
      (entry) => entry.isSymbolicLink() || entry.name.startsWith('.'),
    ));
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('local E2E: Relay + HostBridge enforces E2EE, encrypts HTTP/bootstrap/WS, rejects downgrade & wrong key & intruder', { timeout: 15000 }, async () => {
  const relayPort = await getFreePort();
  const target = { hostId: 'test-host', webId: 'testweb00001' };
  const owner = { userId: 'prn-owner-1', tenantId: 'tenant-test', origin: 'https://site.example.test' };
  const registrationKey = generateE2eeSecret();
  const access = JSON.stringify({
    ...target,
    hostDigest: createHash('sha256').update(registrationKey).digest('hex'),
    ownerUserId: owner.userId, ownerTenantId: owner.tenantId, origin: owner.origin,
  });
  const tmpDir = mkdtempSync(join(tmpdir(), 'dsh-remote-e2e-'));
  const binPath = join(tmpDir, 'relay');
  execFileSync('go', ['build', '-buildvcs=false', '-ldflags', `-X main.relayConfigJSON=${access}`, '-o', binPath, '.'], {
    cwd: join(PROJECT_ROOT, 'relay-go'),
    stdio: 'pipe',
  });

  const relayProc = spawn(binPath, [], {
    env: { ...process.env, PORT: String(relayPort) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Mock local DSH WebServer enforcing browser/operator cookies & serving /api/remote.mux
  let cookieExchanges = 0;
  const mockDsh = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/' && url.searchParams.get('token') === 'launch-secret') {
      cookieExchanges++;
      res.writeHead(303, { 'set-cookie': 'dsh_web=browser-ok; Path=/; HttpOnly' });
      res.end();
      return;
    }
    if (url.pathname === '/connect' && url.searchParams.get('token') === 'launch-secret') {
      cookieExchanges++;
      res.writeHead(302, { 'set-cookie': 'dsh_web=op-ok; Path=/; HttpOnly' });
      res.end();
      return;
    }
    if (!String(req.headers.cookie || '').includes('dsh_web=browser-ok')) {
      res.writeHead(401);
      res.end('unauthorized');
      return;
    }
    if (url.pathname === '/api/ping') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ pong: true, secretPayload: 'SUPER_SENSITIVE_CLEARTEXT_CHECK', method: req.method }));
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });
  mockDsh.on('upgrade', (req, socket) => {
    if (!String(req.headers.cookie || '').includes('dsh_web=op-ok')) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    acceptSimpleWebSocket(req, socket);
  });

  await new Promise((resolveListen) => mockDsh.listen(0, '127.0.0.1', resolveListen));
  const dshPort = mockDsh.address().port;

  // Wait for relay /health
  const relayHttp = `http://127.0.0.1:${relayPort}`;
  for (let i = 0; i < 40; i += 1) {
    try {
      const r = await fetch(`${relayHttp}/health`);
      if (r.ok) break;
    } catch {
      await new Promise((r) => setTimeout(r, 50));
    }
  }

  const e2eeSecret = generateE2eeSecret();
  const wrongSecret = generateE2eeSecret();

  const bridge = new HostBridge({
    relayUrl: relayHttp,
    e2eeSecret,
    ...target,
    registrationKey,
    allowInsecureLoopback: true,
    hostName: 'Test Host',
    localOrigin: `http://127.0.0.1:${dshPort}`,
    getLaunchToken: () => 'launch-secret',
    collectIndexInjections: () => [
      { kind: 'global', name: '__DSH_BOOT__', value: { entries: [], batches: [], release: { version: 'fixture' }, rev: 'fixture' } },
      { kind: 'script', placement: 'body', text: 'const preference = "dark"; document.documentElement.dataset.dsThemeSource = preference;' },
    ],
    ownerUserId: owner.userId,
    ownerTenantId: owner.tenantId,
    log: () => {},
  });

  let ownerWs;
  try {
    await bridge.start();
    await new Promise((r) => setTimeout(r, 50));

    // 1. Connect as owner client
    ownerWs = new WebSocket(`ws://127.0.0.1:${relayPort}/client`, {
      headers: {
        'Tiana-Caller-User-Id': owner.userId,
        'Tiana-Caller-Tenant-Id': owner.tenantId,
        'Tiana-Caller-Web-Id': target.webId,
        Origin: owner.origin,
      },
    });
    ownerWs.binaryType = 'arraybuffer';

    const ownerQueue = [];
    const rawWireMessages = [];
    let ownerNotify = null;
    ownerWs.addEventListener('message', (ev) => {
      rawWireMessages.push(Buffer.from(ev.data));
      ownerQueue.push(decodeClientFrame(ev.data));
      ownerNotify?.();
    });
    const nextOwnerFrame = async () => {
      while (ownerQueue.length === 0) {
        await new Promise((r) => { ownerNotify = r; });
      }
      ownerNotify = null;
      return ownerQueue.shift();
    };

    const welcome = await nextOwnerFrame();
    assert.equal(welcome.msgType, MSG_CONTROL_JSON);
    const welcomeObj = decodeJSON(welcome.payload);
    assert.equal(welcomeObj.selectedHostId, 'test-host');

    // 1a. Verify anti-downgrade: plaintext HTTP before E2EE handshake is rejected with 403
    ownerWs.send(encodeClientFrame(99, MSG_HTTP_REQ_HEAD, encodeJSON({ method: 'GET', path: '/api/ping', headers: {} })));
    ownerWs.send(encodeClientFrame(99, MSG_HTTP_REQ_END));
    const dgHead = await nextOwnerFrame();
    assert.equal(dgHead.streamId, 99);
    assert.equal(dgHead.msgType, MSG_HTTP_RES_HEAD);
    assert.equal(decodeJSON(dgHead.payload).status, 403);
    await nextOwnerFrame(); // body
    await nextOwnerFrame(); // end

    // 1b. Wrong E2EE key -> host returns AUTH_FAILED, allowing retry on same socket
    const sessionIdentity = { ...target, ownerUserId: owner.userId,
      tenantId: owner.tenantId, logicalSessionId: generateLogicalSessionId() };
    const badHs = await createClientHandshake(wrongSecret, sessionIdentity);
    ownerWs.send(encodeClientFrame(0, MSG_E2EE_CLIENT_HELLO, badHs.helloPayload));
    const authErr = await nextOwnerFrame();
    assert.equal(authErr.msgType, MSG_E2EE_ERROR);
    assert.equal(decodeJSON(authErr.payload).code, 'AUTH_FAILED');

    // 1c. Valid E2EE handshake
    const clientHs = await createClientHandshake(e2eeSecret, sessionIdentity);
    ownerWs.send(encodeClientFrame(0, MSG_E2EE_CLIENT_HELLO, clientHs.helloPayload));
    const hostHello = await nextOwnerFrame();
    assert.equal(hostHello.streamId, 0);
    assert.equal(hostHello.msgType, MSG_E2EE_HOST_HELLO);
    const cipher = await clientHs.finalize(hostHello.payload);

    const decrypted = [];
    let notify;
    const path = createPath({
      send: (type, box) => ownerWs.send(encodeClientFrame(0, type, box)),
      ready: () => ownerWs.readyState === 1,
      bufferedAmount: () => ownerWs.bufferedAmount,
      close: () => ownerWs.close(),
    });
    const session = new MultipathSession({ cipher, onData: (bytes) => {
      decrypted.push(decodeClientFrame(bytes));
      notify?.();
    } });
    ownerWs.addEventListener('close', () => session.close(), { once: true });
    session.setRelay(path);
    ownerWs.addEventListener('message', (event) => {
      const raw = decodeClientFrame(event.data);
      if (raw.msgType === MSG_E2EE_BOX || raw.msgType === MSG_E2EE_CTRL) {
        session.receive(raw.msgType, raw.payload, path);
      }
    });
    const sendEncrypted = (streamId, msgType, payload) => session.send(encodeClientFrame(streamId, msgType, payload));
    const nextDecryptedFrame = async () => {
      while (!decrypted.length) await new Promise((resolve) => { notify = resolve; });
      return decrypted.shift();
    };

    const wireMarkBeforeApp = rawWireMessages.length;

    // 2. Request /__dsh_remote__/bootstrap.json over E2EE
    await sendEncrypted(1, MSG_HTTP_REQ_HEAD, encodeJSON({ method: 'GET', path: '/__dsh_remote__/bootstrap.json', headers: {} }));
    await sendEncrypted(1, MSG_HTTP_REQ_END);
    const bootHead = await nextDecryptedFrame();
    assert.equal(bootHead.streamId, 1);
    assert.equal(bootHead.msgType, MSG_HTTP_RES_HEAD);
    assert.equal(decodeJSON(bootHead.payload).status, 200);
    const bootBody = await nextDecryptedFrame();
    assert.equal(bootBody.msgType, MSG_HTTP_RES_BODY);
    const bootData = decodeJSON(bootBody.payload);
    assert.equal(bootData.host.hostId, 'test-host');
    assert.equal(bootData.theme.preference, 'dark');
    const bootEnd = await nextDecryptedFrame();
    assert.equal(bootEnd.msgType, MSG_HTTP_RES_END);

    // 3. Request /api/ping over E2EE (verifies browserAuth cookie exchange + ciphertext opacity)
    await sendEncrypted(2, MSG_HTTP_REQ_HEAD, encodeJSON({ method: 'POST', path: '/api/ping', headers: {} }));
    await sendEncrypted(2, MSG_HTTP_REQ_END);
    const pingHead = await nextDecryptedFrame();
    assert.equal(decodeJSON(pingHead.payload).status, 200);
    const pingBody = await nextDecryptedFrame();
    assert.deepEqual(decodeJSON(pingBody.payload), {
      pong: true,
      secretPayload: 'SUPER_SENSITIVE_CLEARTEXT_CHECK',
      method: 'POST',
    });
    await nextDecryptedFrame(); // END

    // 4. Open /api/remote.mux WebSocket over E2EE
    await sendEncrypted(3, MSG_WS_OPEN, encodeJSON({ path: '/api/remote.mux' }));
    const wsOpened = await nextDecryptedFrame();
    assert.equal(wsOpened.streamId, 3);
    assert.equal(wsOpened.msgType, MSG_WS_OPENED);
    await sendFragments('hello-mux-confidential', (bytes) => sendEncrypted(3, MSG_WS_DATA_TEXT, bytes));
    const wsEcho = await nextDecryptedFrame();
    assert.equal(wsEcho.streamId, 3);
    assert.equal(wsEcho.msgType, MSG_WS_DATA_TEXT);
    assert.equal(Buffer.from(new FragmentReader().push(wsEcho.msgType, wsEcho.payload)).toString('utf8'), 'echo:hello-mux-confidential');
    await sendEncrypted(3, MSG_WS_CLOSE, encodeJSON({ code: 1000, reason: 'done' }));

    // Verify Relay wire bytes never contained plaintext payloads
    const postHandshakeWire = Buffer.concat(rawWireMessages.slice(wireMarkBeforeApp));
    assert.equal(postHandshakeWire.includes('SUPER_SENSITIVE_CLEARTEXT_CHECK'), false);
    assert.equal(postHandshakeWire.includes('hello-mux-confidential'), false);
    assert.equal(postHandshakeWire.includes('test-host'), false);

    // External targets are rejected before local credentials are used.
    const exchangesBeforeRejection = cookieExchanges;
    await sendEncrypted(4, MSG_HTTP_REQ_HEAD, encodeJSON({ path: 'https://example.invalid/resource' }));
    await sendEncrypted(4, MSG_HTTP_REQ_END);
    const rejectedHead = await nextDecryptedFrame();
    assert.equal(rejectedHead.streamId, 4);
    assert.equal(decodeJSON(rejectedHead.payload).status, 404);
    assert.equal((await nextDecryptedFrame()).msgType, MSG_HTTP_RES_END);

    await sendEncrypted(5, MSG_WS_OPEN, encodeJSON({ path: '//example.invalid/socket' }));
    const rejectedSocket = await nextDecryptedFrame();
    assert.equal(rejectedSocket.streamId, 5);
    assert.equal(rejectedSocket.msgType, MSG_WS_CLOSE);
    assert.equal(cookieExchanges, exchangesBeforeRejection);

    // Missing site caller context is rejected at the relay, before WebSocket upgrade.
    const anonymous = await fetch(`${relayHttp}/client`);
    assert.equal(anonymous.status, 403);
    const health = await fetch(`${relayHttp}/health`);
    assert.deepEqual(await health.json(), { ok: true, paired: true });

    ownerWs.close();
  } finally {
    ownerWs?.close();
    bridge.stop();
    mockDsh.close();
    relayProc.kill('SIGKILL');
    rmSync(tmpDir, { recursive: true, force: true });
  }
});
