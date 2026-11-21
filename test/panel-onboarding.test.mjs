import assert from 'node:assert/strict';
import { execFileSync, fork } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';
import { createHostController } from '../host-main.js';
import { scanWorktreeAndGitHistory } from '../scripts/pack-plugin.mjs';
import { copyToClipboard, maskPairingKey } from '../src/clipboard.js';
import {
  buildDshStartArgs,
  checkNodeVersion,
  ensureDshPlugins,
  ensureTianaToolchain,
  isLocalDshResponsive,
  mergeCordisPatchYml,
  parseAppArg,
  resolveDshBinary,
  resolveTianaBinary,
  runConnect,
} from '../src/connect.js';
import { FrontendAssets, selectAllowedWebPlugins } from '../src/frontend-assets.js';
import { classifyHttpRoute, HostBridge } from '../src/host-bridge.js';
import {
  decodeClientFrame,
  decodeHostFrame,
  encodeClientFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
} from '../src/protocol.js';
import {
  createRemoteApiHandler,
  guardAdminRequest,
  isLoopbackAddress,
  isLoopbackHostHeader,
  isPrivateOrLocalAddress,
  isValidHostHeader,
  registerRemoteRoutes,
  registerWebServerRoutes,
} from '../src/remote-api.js';
import {
  formatPairingKey,
  generateE2eeSecret,
  loadRemoteState,
  migrateRemoteState,
  saveRemoteState,
  withStateLock,
} from '../src/state.js';
import { bindTianaRemoteWeb } from '../src/tiana-cli.js';
import { readStoredKey, TunnelClient, writeStoredKey } from '../web-src/dsh-remote-entry.mjs';
import { computeKeyFingerprint, decodeMasterSecret, generateLogicalSessionId } from '../web-src/e2ee.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

test('state.js v1->v2 lossless migration, file locking, and dshk1_ pairing key round-trip', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-v2-state-'));
  const filePath = join(dir, 'state.json');
  try {
    const rawSecret = generateE2eeSecret();
    const formatted = formatPairingKey(rawSecret);
    assert.ok(formatted.startsWith('dshk1_'));
    assert.deepEqual(decodeMasterSecret(formatted), decodeMasterSecret(rawSecret));
    assert.equal(await computeKeyFingerprint(formatted), await computeKeyFingerprint(rawSecret));

    // Lossless v1 -> v2 migration preserves hostId, hostSigningKeyPair, e2eeKeySeed, tiana
    const v1 = {
      version: 1,
      hostId: 'legacy-mac',
      hostSigningKeyPair: { publicKey: 'pub-test', privateKey: 'priv-test' },
      e2eeKeySeed: rawSecret,
      tiana: { webId: 'legacy000001' },
      owner: { userId: 'u1', tenantId: 't1' },
    };
    const v2 = migrateRemoteState(v1);
    assert.equal(v2.version, 2);
    assert.equal(v2.configVersion, 2);
    assert.equal(v2.hostId, 'legacy-mac');
    assert.equal(v2.host.hostId, 'legacy-mac');
    assert.deepEqual(v2.hostSigningKeyPair, v1.hostSigningKeyPair);
    assert.equal(v2.e2eeKeySeed, rawSecret);
    assert.equal(v2.e2ee.secret, rawSecret);
    assert.deepEqual(v2.tiana, v1.tiana);
    assert.deepEqual(v2.network, { p2pEnabled: true, stunUrls: ['stun:stun.cloudflare.com:3478'] });
    assert.deepEqual(v2.security, { allowedWebPlugins: [] });

    // withStateLock serializes concurrent writers cleanly
    saveRemoteState({ count: 0 }, filePath);
    await Promise.all(Array.from({ length: 5 }, () => withStateLock(async () => {
      const cur = loadRemoteState(filePath);
      await new Promise((r) => setTimeout(r, 10));
      saveRemoteState({ count: cur.count + 1 }, filePath);
    }, filePath)));
    assert.equal(loadRemoteState(filePath).count, 5);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Node >= 24.9.0 gate, app arg parser, cordis.patch.yml merge, clipboard stdin, and zero-URL-key connect', async () => {
  // Node version gate
  const low = checkNodeVersion('22.13.0');
  assert.equal(low.ok, false);
  assert.match(low.message, /24\.9\.0/);
  assert.match(low.message, /fnm|nvm/);
  assert.match(low.message, /winget/);
  assert.equal(checkNodeVersion('24.9.0').ok, true);
  assert.equal(checkNodeVersion('26.13.0').ok, true);

  // parseAppArg accepts both bare ID and full URL
  assert.equal(parseAppArg('abc123456789'), 'abc123456789');
  assert.equal(parseAppArg('https://abc123456789.tianacloud.site/web/abc123456789/'), 'abc123456789');
  assert.equal(parseAppArg('invalid'), '');

  // mergeCordisPatchYml preserves user plugins and is idempotent
  const userYml = "- insert:\n    - id: my-custom\n      name: '@user/custom-plugin'\n";
  const merged = mergeCordisPatchYml(userYml);
  assert.ok(merged.includes('@user/custom-plugin'));
  assert.ok(merged.includes('@tianacloud/dsh-tiana'));
  assert.ok(merged.includes('@tianacloud/dsh-remote'));
  assert.equal(mergeCordisPatchYml(merged), merged, 'mergeCordisPatchYml must be idempotent');

  // Clipboard writes strictly via stdin callback (never argv)
  const calls = [];
  const copied = await copyToClipboard('dshk1_secretvalue', {
    platform: 'darwin',
    writeFn: async (bin, args, text) => { calls.push({ bin, args, text }); },
  });
  assert.equal(copied.ok, true);
  assert.equal(copied.tool, 'pbcopy');
  assert.deepEqual(calls, [{ bin: 'pbcopy', args: [], text: 'dshk1_secretvalue' }]);
  assert.match(maskPairingKey('dshk1_1234567890abcd'), /^dshk1_•+abcd$/);

  // Full runConnect rejects Node < 24.9.0 with exitCode 2
  await assert.rejects(
    () => runConnect({ app: 'abc123456789' }, { nodeVersion: '22.14.0', log: () => {} }),
    (err) => err.exitCode === 2,
  );

  // Full runConnect copies dshk1_ to clipboard and opens clean URL (NO #rk=)
  const secret = generateE2eeSecret();
  let openedUrl = '';
  let clipboardText = '';
  const summary = await runConnect({
    app: 'https://abc123456789.tianacloud.site/web/abc123456789/',
    noStart: true,
  }, {
    nodeVersion: '24.9.0',
    log: () => {},
    resolveDsh: async () => ({ bin: '/usr/local/bin/dsh', version: '0.2.2' }),
    ensurePlugins: async () => {},
    ensureTianaToolchain: async () => ({ bin: '/usr/local/bin/tiana', version: '1.0.32' }),
    ensureLogin: async () => ({ logged_in: true }),
    readRuntime: () => ({ pid: process.pid, origin: 'http://127.0.0.1:3080' }),
    checkDshResponsive: async () => true,
    bindRemoteWeb: async () => ({
      host: { hostId: 'my-mac', hostName: 'My Mac' },
      e2ee: { secret, fingerprint: 'aa:bb:cc' },
      web: { id: 'abc123456789', endpoint: 'https://abc123456789.tianacloud.site/web/abc123456789/' },
    }),
    copyToClipboard: async (txt) => { clipboardText = txt; return { ok: true, tool: 'pbcopy' }; },
    openBrowser: (url) => { openedUrl = url; return true; },
  });
  assert.equal(summary.ok, true);
  assert.equal(summary.clipboardCopied, true);
  assert.equal(clipboardText, `dshk1_${secret}`);
  assert.equal(openedUrl, 'https://abc123456789.tianacloud.site/web/abc123456789/');
  assert.equal(openedUrl.includes('#rk='), false);
  assert.equal(openedUrl.includes(secret), false);
});

test('HostBridge blocks /api/tiana-remote/admin/* with 403, local triple-guard allows owner, and key rotation kicks clients with 4001', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-s3-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  const initialSecret = generateE2eeSecret();

  saveRemoteState({
    version: 2,
    configVersion: 2,
    enabled: true,
    updatedAt: new Date().toISOString(),
    owner: { userId: 'usr-1', tenantId: 'ten-1', email: 'owner@example.test' },
    host: { hostId: 'host-s3', hostName: 'S3 Host', registrationKey: 'C'.repeat(43) },
    e2ee: { algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM', secret: initialSecret, fingerprint: '1122:3344:5566' },
    function: { id: 'fn-1', url: 'https://relay.example.test', token: 'tok-1', expiresAt: Math.floor(Date.now() / 1000) + 864000 },
    web: { id: 'web000000115', name: 'DSH Remote', endpoint: 'https://web000000115.example.test/web/web000000115/' },
    network: { p2pEnabled: false, stunUrls: ['stun:stun.cloudflare.com:3478'] },
    security: { allowedWebPlugins: [] },
  }, statePath);

  // Classify checks
  assert.equal(classifyHttpRoute('/api/tiana-remote/admin')?.kind, 'forbidden');
  assert.equal(classifyHttpRoute('/api/tiana-remote/admin/overview')?.kind, 'forbidden');
  assert.equal(classifyHttpRoute('/api/tiana-remote/admin/pairing-key/reveal')?.kind, 'forbidden');
  assert.equal(classifyHttpRoute('/api/tiana-remote/ADMIN/toggle')?.kind, 'forbidden');
  assert.equal(classifyHttpRoute('/api/tiana-remote/status')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/api/tiana-remote/public-status')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/connect'), null);

  let bridgeInstance = null;
  let localServer;
  const mockConnection = {
    async requestRejection(req) {
      if (req.headers.get('cookie')?.includes('dsh_web=owner-ok')) return null;
      return new Response('Unauthorized', { status: 401 });
    },
  };

  const controller = createHostController({
    statePath,
    runtimePath,
    log: () => {},
    localOrigin: () => `http://127.0.0.1:${localServer.address().port}`,
    getLaunchToken: () => 'launch-s3',
    createBridge: (cfg) => {
      bridgeInstance = new HostBridge({ ...cfg, p2p: 'off' });
      return bridgeInstance;
    },
  });
  const apiHandler = createRemoteApiHandler(controller, mockConnection);

  const seenTunnelHeaders = [];
  localServer = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/' && url.searchParams.get('token') === 'launch-s3') {
      res.writeHead(303, { 'set-cookie': 'dsh_web=owner-ok; Path=/; HttpOnly' });
      res.end();
      return;
    }
    seenTunnelHeaders.push({ path: url.pathname, tunnelHdr: req.headers['x-dsh-remote-tunnel'] || '' });
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    const fetchReq = new Request(`http://127.0.0.1:${localServer.address().port}${req.url}`, {
      method: req.method,
      headers: req.headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : body,
    });
    const apiResp = await apiHandler(fetchReq, { remoteAddress: req.socket.remoteAddress });
    if (apiResp) {
      res.writeHead(apiResp.status, Object.fromEntries(apiResp.headers.entries()));
      res.end(Buffer.from(await apiResp.arrayBuffer()));
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;

  // Wire in-memory HostBridge <-> TunnelClient
  bridgeInstance = new HostBridge({
    relayUrl: 'https://relay.example.test',
    e2eeSecret: initialSecret,
    hostId: 'host-s3',
    hostName: 'S3 Host',
    registrationKey: 'C'.repeat(43),
    localOrigin,
    getLaunchToken: () => 'launch-s3',
    ownerUserId: 'usr-1',
    ownerTenantId: 'ten-1',
    webId: 'web000000115',
    p2p: 'off',
    log: () => {},
  });
  // Inject bridge directly into controller for unit testing
  const origGetBridge = controller.getBridge;
  assert.equal(origGetBridge(), null);
  // Start controller with a stubbed createBridge that doesn't open real WSS
  const testCtrl = createHostController({
    statePath,
    runtimePath,
    log: () => {},
    localOrigin: () => localOrigin,
    getLaunchToken: () => 'launch-s3',
    createBridge: () => {
      bridgeInstance.start = async () => { bridgeInstance.registered = true; };
      return bridgeInstance;
    },
  });
  const testApi = createRemoteApiHandler(testCtrl, mockConnection);

  const clientListeners = new Map();
  const emitToClient = (clientBytes) => {
    const ab = clientBytes.buffer.slice(clientBytes.byteOffset, clientBytes.byteOffset + clientBytes.byteLength);
    for (const fn of clientListeners.get('message') ?? []) fn({ data: ab });
  };
  bridgeInstance.ws = {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    send(raw) {
      const hf = decodeHostFrame(raw);
      if (hf.sessionId === 1) emitToClient(encodeClientFrame(hf.streamId, hf.msgType, hf.payload));
    },
    close() { this.readyState = WebSocket.CLOSED; },
  };
  bridgeInstance.paceRelay = () => true;
  await testCtrl.boot();

  const fakeClientWs = {
    readyState: 1,
    bufferedAmount: 0,
    binaryType: 'arraybuffer',
    addEventListener(type, fn) {
      if (!clientListeners.has(type)) clientListeners.set(type, new Set());
      clientListeners.get(type).add(fn);
    },
    removeEventListener(type, fn) { clientListeners.get(type)?.delete(fn); },
    send(raw) {
      const cf = decodeClientFrame(raw);
      void bridgeInstance.handleFrame({ sessionId: 1, streamId: cf.streamId, msgType: cf.msgType, payload: cf.payload });
    },
    close() { this.readyState = 3; },
  };

  let keyRotatedEvent = null;
  const challenge = generateLogicalSessionId();
  const tunnel = new TunnelClient(
    async () => {
      await bridgeInstance.handleFrame({
        sessionId: 0, streamId: 0, msgType: MSG_CONTROL_JSON,
        payload: encodeJSON({
          type: 'open_session', sessionId: 1, hostId: 'host-s3',
          userId: 'usr-1', tenantId: 'ten-1', webId: 'web000000115', challenge, remainingMs: 60_000,
        }),
      });
      setTimeout(() => emitToClient(encodeClientFrame(0, MSG_CONTROL_JSON, encodeJSON({
        type: 'welcome', sessionId: 1, paired: true, challenge, selectedHostId: 'host-s3',
        user: { userId: 'usr-1', tenantId: 'ten-1', webId: 'web000000115' },
      }))), 5);
      return fakeClientWs;
    },
    { hostId: 'host-s3', webId: 'web000000115', ownerUserId: 'usr-1', tenantId: 'ten-1' },
    () => {},
    () => {},
    null,
    { onKeyRotated: (err) => { keyRotatedEvent = err; } },
  );

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, `dshk1_${initialSecret}`);

    // 1. Remote tunnel -> /api/tiana-remote/admin/* strictly returns 403 and NEVER hits localServer!
    const hitsBefore = seenTunnelHeaders.length;
    for (const p of ['/api/tiana-remote/admin/overview', '/api/tiana-remote/admin/pairing-key/reveal', '/api/tiana-remote/admin/toggle']) {
      const r = await tunnel.fetch(p, { method: p.includes('overview') ? 'GET' : 'POST' });
      assert.equal(r.status, 403, `expected 403 over tunnel for ${p}`);
    }
    assert.equal(seenTunnelHeaders.length, hitsBefore);

    // 2. Remote tunnel -> /api/tiana-remote/status returns exact 8 spec fields (no ok/relayConnected/activeSessionCount)
    const pubResp = await tunnel.fetch('/api/tiana-remote/status');
    assert.equal(pubResp.status, 200);
    const pubJson = await pubResp.json();
    assert.deepEqual(Object.keys(pubJson).sort(), [
      'configured',
      'e2eeFingerprint',
      'enabled',
      'hostId',
      'hostName',
      'p2pEnabled',
      'webEndpoint',
      'webId',
    ]);
    assert.equal(pubJson.configured, true);
    assert.equal(pubJson.hostId, 'host-s3');
    assert.equal(JSON.stringify(pubJson).includes(initialSecret), false);
    assert.equal(JSON.stringify(pubJson).includes('dshk1_'), false);
    assert.equal(seenTunnelHeaders.at(-1).tunnelHdr, '1');

    // 3. Direct triple-guard tests on remote-api.js:
    // 3a. Non-loopback remoteAddress -> 403
    const nonLoop = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/overview', {
      headers: { cookie: 'dsh_web=owner-ok' },
    }), { remoteAddress: '203.0.113.5' });
    assert.equal(nonLoop.status, 403);

    // 3b. X-DSH-Remote-Tunnel header -> 403
    const tunHdr = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/overview', {
      headers: { cookie: 'dsh_web=owner-ok', 'x-dsh-remote-tunnel': '1' },
    }), { remoteAddress: '127.0.0.1' });
    assert.equal(tunHdr.status, 403);

    // 3c. Missing local owner cookie -> 403
    const noAuth = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/overview'), { remoteAddress: '127.0.0.1' });
    assert.equal(noAuth.status, 403);

    // 3d. Valid local loopback owner -> 200 overview & reveal & settings
    const okOverview = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/overview', {
      headers: { cookie: 'dsh_web=owner-ok' },
    }), { remoteAddress: '127.0.0.1' });
    assert.equal(okOverview.status, 200);
    const ov = await okOverview.json();
    assert.equal(ov.configured, true);
    assert.equal(ov.bridge.sessions.length, 1);
    assert.equal(JSON.stringify(ov).includes(initialSecret), false, 'overview must not expose raw secret');

    const revealResp = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/pairing-key/reveal', {
      method: 'POST',
      headers: { cookie: 'dsh_web=owner-ok' },
      body: '{}',
    }), { remoteAddress: '127.0.0.1' });
    assert.equal(revealResp.status, 200);
    assert.equal((await revealResp.json()).pairingKey, `dshk1_${initialSecret}`);

    // 4. Hot rotate pairing key -> kicks active remote client with 4001 key_rotated!
    const rotateResp = await testApi(new Request('http://127.0.0.1/api/tiana-remote/admin/pairing-key/rotate', {
      method: 'POST',
      headers: { cookie: 'dsh_web=owner-ok', 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    }), { remoteAddress: '127.0.0.1' });
    assert.equal(rotateResp.status, 200);
    const rotated = await rotateResp.json();
    assert.ok(rotated.pairingKey.startsWith('dshk1_'));
    assert.notEqual(rotated.secret, initialSecret);
    assert.equal(rotated.kickedSessions, 1);

    // Wait briefly for encrypted session_closed control frame delivery
    for (let i = 0; i < 20 && !keyRotatedEvent; i += 1) {
      await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(keyRotatedEvent, 'client must receive 4001 key_rotated callback');
    assert.equal(keyRotatedEvent.closeCode, 4001);
    assert.equal(bridgeInstance.sessions.size, 0);
  } finally {
    tunnel.close();
    testCtrl.dispose();
    bridgeInstance.stop();
    localServer.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('unchecked remember stores in memory only (neither localStorage nor sessionStorage); checked persists to localStorage', () => {
  const makeMemStorage = () => {
    const m = new Map();
    return {
      getItem: (k) => m.get(k) ?? null,
      setItem: (k, v) => m.set(k, String(v)),
      removeItem: (k) => m.delete(k),
    };
  };
  const session = makeMemStorage();
  const local = makeMemStorage();
  const key = 'dsh-remote:v2:key:web1:u1:h1';

  // Seed legacy sessionStorage to prove it gets scrubbed
  session.setItem(key, 'legacy-session');

  // Unchecked remember=false -> writes to NEITHER localStorage NOR sessionStorage
  writeStoredKey(key, 'sec-memory-only', { remember: false, session, local });
  assert.equal(session.getItem(key), null);
  assert.equal(local.getItem(key), null);
  assert.deepEqual(readStoredKey(key, { local }), { secret: null, remembered: false });

  // Checked remember=true -> persists to localStorage only (clears sessionStorage)
  writeStoredKey(key, 'sec-local', { remember: true, session, local });
  assert.equal(session.getItem(key), null);
  assert.equal(local.getItem(key), 'sec-local');
  assert.deepEqual(readStoredKey(key, { local }), { secret: 'sec-local', remembered: true });
});

test('Round 2 #1: real HTTP webServer.register enforces loopback socket, loopback Host, empty tunnel header, numeric requestRejection, and fetch-fallback fail-closed', async () => {
  assert.equal(isLoopbackAddress(undefined), false);
  assert.equal(isLoopbackAddress(''), false);
  assert.equal(isLoopbackAddress('127.0.0.1'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddress('192.168.1.5'), false);
  assert.equal(isLoopbackHostHeader(''), false);
  assert.equal(isLoopbackHostHeader('127.0.0.1:3080'), true);
  assert.equal(isLoopbackHostHeader('localhost:3080'), true);
  assert.equal(isLoopbackHostHeader('[::1]:3080'), true);
  assert.equal(isLoopbackHostHeader('evil.example.test:3080'), false);

  const routes = [];
  const mockWebServer = {
    register(route) {
      routes.push(route);
      return () => {};
    },
  };
  // Simulate real DSH rc.5 connection.requestRejection returning numeric 401/403 or undefined on Node IncomingMessage
  const mockConnection = {
    requestRejection(req) {
      const host = String(req.headers?.host || '');
      if (!isLoopbackHostHeader(host)) return 403;
      const cookie = String(req.headers?.cookie || '');
      if (cookie.includes('dsh_owner=valid')) return undefined;
      return 401;
    },
  };
  const stubController = {
    async getPublicStatus() {
      return {
        configured: true, enabled: true, hostName: 'H', hostId: 'h1',
        webId: 'w1', webEndpoint: 'https://w1.example.test/web/w1/', e2eeFingerprint: 'aa:bb:cc', p2pEnabled: true,
      };
    },
    async getAdminOverview() {
      return { ok: true, configured: true };
    },
  };

  registerWebServerRoutes(mockWebServer, mockConnection, stubController);
  let forceRemoteAddr = null;
  const server = createServer(async (req, res) => {
    if (forceRemoteAddr !== null) {
      Object.defineProperty(req, 'socket', { value: { remoteAddress: forceRemoteAddr }, configurable: true });
    }
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    const match = routes.find((r) => (r.kind === 'exact' ? pathname === r.path : pathname === r.path || pathname.startsWith(`${r.path}/`)));
    if (!match) { res.writeHead(404).end(); return; }
    await match.handler(req, res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    // 1. Valid loopback + loopback Host + valid owner cookie -> 200
    const okRes = await fetch(`http://127.0.0.1:${port}/api/tiana-remote/admin/status`, {
      headers: { Cookie: 'dsh_owner=valid' },
    });
    assert.equal(okRes.status, 200);

    // 2. Numeric requestRejection(401) -> 403
    const unauthRes = await fetch(`http://127.0.0.1:${port}/api/tiana-remote/admin/status`);
    assert.equal(unauthRes.status, 403);

    // 3. Empty-value X-DSH-Remote-Tunnel header -> 403
    const emptyTunnelRes = await fetch(`http://127.0.0.1:${port}/api/tiana-remote/admin/status`, {
      headers: { Cookie: 'dsh_owner=valid', 'X-DSH-Remote-Tunnel': '' },
    });
    assert.equal(emptyTunnelRes.status, 403);

    // 4. Non-loopback Host header via raw HTTP request -> 403
    const net = await import('node:net');
    const rawHostStatus = await new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write(
          'GET /api/tiana-remote/admin/status HTTP/1.1\r\n' +
          'Host: attacker.example.test:3080\r\n' +
          'Cookie: dsh_owner=valid\r\n' +
          'Connection: close\r\n\r\n',
        );
      });
      let buf = '';
      sock.on('data', (c) => { buf += c.toString('utf8'); });
      sock.on('end', () => resolve(Number(buf.split(' ')[1])));
      sock.on('error', reject);
    });
    assert.equal(rawHostStatus, 403);

    // 5. Non-loopback socket remoteAddress -> 403
    forceRemoteAddr = '203.0.113.42';
    const remoteIpRes = await fetch(`http://127.0.0.1:${port}/api/tiana-remote/admin/status`, {
      headers: { Cookie: 'dsh_owner=valid' },
    });
    assert.equal(remoteIpRes.status, 403);
    forceRemoteAddr = null;

    // 6. Fetch fallback (no webServer.register -> no remoteAddress) MUST fail closed (403) on admin
    const registeredFetch = new Map();
    const fetchOnlyConn = {
      requestRejection: () => undefined,
      fetch: {
        register(r) {
          registeredFetch.set(r.path, r.fetch);
          return () => {};
        },
      },
    };
    registerRemoteRoutes(fetchOnlyConn, stubController);
    const adminFallbackResp = await registeredFetch.get('/api/tiana-remote/admin/status')(
      new Request('http://127.0.0.1/api/tiana-remote/admin/status'),
    );
    assert.equal(adminFallbackResp.status, 403);
    const pubFallbackResp = await registeredFetch.get('/api/tiana-remote/public-status')(
      new Request('http://127.0.0.1/api/tiana-remote/public-status'),
    );
    assert.equal(pubFallbackResp.status, 200);
  } finally {
    server.close();
  }
});

test('Round 2 #6: empty allowedWebPlugins [] blocks third-party plugins while keeping @deepseek-ai/dsh-* core + dsh-remote; "*" allows all', () => {
  const corePackages = [
    '@deepseek-ai/dsh-client-modules',
    '@deepseek-ai/dsh-client-ui-layout',
    '@deepseek-ai/dsh-api-remotes',
    '@deepseek-ai/dsh-typert-registry',
    '@deepseek-ai/dsh-api-gateway',
    '@deepseek-ai/dsh-api-session-controller',
    '@deepseek-ai/dsh-api-workspace-controller',
    '@deepseek-ai/dsh-api-remote-access',
    '@deepseek-ai/dsh-api-job-controller',
    '@deepseek-ai/dsh-api-terminal-controller',
    '@deepseek-ai/dsh-api-workspace-files',
    '@deepseek-ai/dsh-cordis-client-runner',
    '@deepseek-ai/dsh-message-quotes',
    '@deepseek-ai/dsh-session-log-export',
  ];
  const modules = new Map([
    ...corePackages.map((id) => [id, {}]),
    ['@tianacloud/dsh-remote', {}],
    ['@acme/custom-plugin', {}],
    ['community-plugin', {}],
  ]);

  const emptySel = [...selectAllowedWebPlugins(modules, [])].sort();
  assert.deepEqual(emptySel, [...corePackages, '@tianacloud/dsh-remote'].sort());
  assert.equal(emptySel.includes('@acme/custom-plugin'), false);
  assert.equal(emptySel.includes('community-plugin'), false);

  const explicitSel = [...selectAllowedWebPlugins(modules, ['@acme/custom-plugin'])].sort();
  assert.deepEqual(explicitSel, [...corePackages, '@tianacloud/dsh-remote', '@acme/custom-plugin'].sort());

  const starSel = [...selectAllowedWebPlugins(modules, ['*'])].sort();
  assert.deepEqual(starSel, [...modules.keys()].sort());
});

test('Round 2 #7 & #8: persistent state lock never steals live PID, CLI --json redacts key, and connect toolchain/liveness checks', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r2-lock-'));
  const statePath = join(dir, 'state.json');
  try {
    // Persistent .lock remains on disk after unlock
    await withStateLock(() => saveRemoteState({ version: 2, e2ee: { secret: generateE2eeSecret(), fingerprint: 'aa:bb:cc', algorithm: 'x' }, host: { hostId: 'h1', hostName: 'H1', registrationKey: generateE2eeSecret() }, web: { id: 'w1', endpoint: 'https://w1.example.test/web/w1/' } }, statePath), statePath);
    assert.equal(existsSync(`${statePath}.lock`), true, 'persistent lock file must remain on disk');

    // Backdated ticket owned by LIVE process must NOT be stolen (times out instead of stealing!)
    const claimsDir = `${statePath}.lock.claims`;
    mkdirSync(claimsDir, { recursive: true, mode: 0o700 });
    const liveTicketPath = join(claimsDir, `ticket-0000000000000001-${process.pid}-${'a'.repeat(32)}`);
    writeFileSync(liveTicketPath, '', { mode: 0o600 });
    const oldTime = new Date(Date.now() - 120_000);
    utimesSync(liveTicketPath, oldTime, oldTime);
    await assert.rejects(() => withStateLock(() => {}, statePath, { timeoutMs: 120 }), /Timed out/);
    assert.equal(existsSync(liveTicketPath), true, 'live holder ticket must not be deleted');
    unlinkSync(liveTicketPath);

    // Dead PID entering-* and ticket-* claims ARE reclaimed cleanly
    const deadEnteringPath = join(claimsDir, `entering-99999999-${'b'.repeat(32)}`);
    const deadTicketPath = join(claimsDir, `ticket-0000000000000001-99999999-${'c'.repeat(32)}`);
    writeFileSync(deadEnteringPath, '', { mode: 0o600 });
    writeFileSync(deadTicketPath, '', { mode: 0o600 });
    let ran = false;
    await withStateLock(() => { ran = true; }, statePath, { timeoutMs: 500 });
    assert.equal(ran, true);
    assert.equal(existsSync(deadEnteringPath), false, 'dead entering marker must be reclaimed');
    assert.equal(existsSync(deadTicketPath), false, 'dead ticket marker must be reclaimed');

    // CLI `key --json` omits plaintext secret unless `--print-key` is explicitly passed
    const env = { ...process.env, DSH_HOME: dir };
    const dshStatePath = join(dir, 'tiana-remote', 'state.json');
    const sec = generateE2eeSecret();
    saveRemoteState({
      version: 2,
      host: { hostId: 'h1', hostName: 'H1', registrationKey: generateE2eeSecret() },
      e2ee: { algorithm: 'x25519', secret: sec, fingerprint: 'aa:bb:cc' },
      web: { id: 'w1', endpoint: 'https://w1.example.test/web/w1/' },
    }, dshStatePath);
    const jsonRedacted = JSON.parse(execFileSync(process.execPath, [join(PROJECT_ROOT, 'cli.js'), 'key', '--json'], { env, encoding: 'utf8' }));
    assert.equal(jsonRedacted.secret, undefined);
    assert.equal(jsonRedacted.pairingKey, undefined);
    assert.match(jsonRedacted.fingerprint, /^[0-9a-f]{4}:[0-9a-f]{4}:[0-9a-f]{4}$/u);
    const jsonWithKey = JSON.parse(execFileSync(process.execPath, [join(PROJECT_ROOT, 'cli.js'), 'key', '--json', '--print-key'], { env, encoding: 'utf8' }));
    assert.equal(jsonWithKey.secret, sec);
    assert.equal(jsonWithKey.pairingKey, `dshk1_${sec}`);

    // ensureDshPlugins fails immediately on non-zero exit (no swallowing)
    await assert.rejects(
      () => ensureDshPlugins('dsh', {
        execFn: async () => { throw new Error('plugin add failed'); },
        log: () => {},
      }),
      /Failed to install DSH plugin/,
    );

    // ensureTianaToolchain installs @tianacloud/cli@latest when missing/old and syncs skills into $DSH_HOME/skills
    const calls = [];
    let cliInstalled = false;
    const tc = await ensureTianaToolchain({
      dshHome: dir,
      log: () => {},
      execFn: async (bin, args) => {
        calls.push([bin, ...args]);
        if (args[0] === 'version') {
          if (!cliInstalled) return { stdout: 'tiana v1.0.20\n', stderr: '' };
          return { stdout: 'tiana v1.0.35\n', stderr: '' };
        }
        if (args[0] === 'install') {
          cliInstalled = true;
          return { stdout: 'ok', stderr: '' };
        }
        return { stdout: 'skills ok', stderr: '' };
      },
    });
    assert.equal(tc.installedCli, true);
    assert.equal(tc.version, '1.0.35');
    assert.ok(calls.some((c) => c.includes('@tianacloud/cli@latest')));
    assert.ok(calls.some((c) => c.includes('@tianacloud/agent-skills@latest') && c.includes(join(dir, 'skills'))));

    // isLocalDshResponsive rejects 404 and 500, accepts 200 public-status and 401/403
    assert.equal(await isLocalDshResponsive('http://127.0.0.1:9999', { fetchFn: async () => new Response('nope', { status: 404 }) }), false);
    assert.equal(await isLocalDshResponsive('http://127.0.0.1:9999', { fetchFn: async () => new Response('err', { status: 500 }) }), false);
    assert.equal(await isLocalDshResponsive('http://127.0.0.1:9999', { fetchFn: async () => Response.json({ configured: true }) }), true);
    assert.equal(await isLocalDshResponsive('http://127.0.0.1:9999', { fetchFn: async () => new Response('', { status: 401 }) }), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Round 2 #14: client.js QR encoder produces standards-compliant ISO/IEC 18004 scannable QR codes verified by full RS decode', () => {
  const clientCode = readFileSync(join(PROJECT_ROOT, 'client.js'), 'utf8');
  const sandbox = { globalThis: {}, TextEncoder };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(clientCode, sandbox);
  const encodeQrMatrix = sandbox.__DSH_REMOTE_QR_ENCODE__;
  assert.equal(typeof encodeQrMatrix, 'function');

  // Minimal ISO/IEC 18004 decoder & RS syndrome verifier for EC Level M
  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) GF_EXP[i] = GF_EXP[i - 255];
  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]);

  const SPECS_M = [
    null,
    { totalData: 16, ecPerBlock: 10, g1Blocks: 1, g1Data: 16, g2Blocks: 0, g2Data: 0, align: [] },
    { totalData: 28, ecPerBlock: 16, g1Blocks: 1, g1Data: 28, g2Blocks: 0, g2Data: 0, align: [6, 18] },
    { totalData: 44, ecPerBlock: 26, g1Blocks: 1, g1Data: 44, g2Blocks: 0, g2Data: 0, align: [6, 22] },
    { totalData: 64, ecPerBlock: 18, g1Blocks: 2, g1Data: 32, g2Blocks: 0, g2Data: 0, align: [6, 26] },
    { totalData: 86, ecPerBlock: 24, g1Blocks: 2, g1Data: 43, g2Blocks: 0, g2Data: 0, align: [6, 30] },
    { totalData: 108, ecPerBlock: 16, g1Blocks: 4, g1Data: 27, g2Blocks: 0, g2Data: 0, align: [6, 34] },
    { totalData: 124, ecPerBlock: 18, g1Blocks: 4, g1Data: 31, g2Blocks: 0, g2Data: 0, align: [6, 22, 38] },
  ];

  const maskFn = (mask, r, c) => [
    (r + c) % 2 === 0,
    r % 2 === 0,
    c % 3 === 0,
    (r + c) % 3 === 0,
    (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    ((r * c) % 2) + ((r * c) % 3) === 0,
    (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ][mask];

  function decodeAndVerifyQr(qr) {
    const { version, size, matrix } = qr;
    assert.equal(size, version * 4 + 17);
    assert.equal(matrix[size - 8][8], true, 'fixed dark module must be dark');
    // Verify all 3 finder patterns
    for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let r = 0; r < 7; r += 1) {
        for (let c = 0; c < 7; c += 1) {
          const expected = r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
          assert.equal(matrix[r0 + r][c0 + c], expected);
        }
      }
    }
    // Read format bits from Copy 1 and verify BCH(15, 5)
    let fmt = 0;
    const coords = [
      [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
      [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
    ];
    for (const [r, c] of coords) fmt = (fmt << 1) | (matrix[r][c] ? 1 : 0);
    const unmaskedFmt = fmt ^ 0x5412;
    let rem = unmaskedFmt;
    for (let i = 4; i >= 0; i -= 1) {
      if (rem & (1 << (i + 10))) rem ^= 0x537 << i;
    }
    assert.equal(rem, 0, 'format info BCH remainder must be 0');
    const ecBits = (unmaskedFmt >>> 13) & 0x03;
    const mask = (unmaskedFmt >>> 10) & 0x07;
    assert.equal(ecBits, 0, 'EC level M must encode as 00');

    // Mark function modules & extract unmasked data bits
    const spec = SPECS_M[version];
    const isFunc = Array.from({ length: size }, () => Array(size).fill(false));
    for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let dr = -1; dr <= 7; dr += 1) {
        for (let dc = -1; dc <= 7; dc += 1) {
          if (r0 + dr >= 0 && r0 + dr < size && c0 + dc >= 0 && c0 + dc < size) isFunc[r0 + dr][c0 + dc] = true;
        }
      }
    }
    for (const cr of spec.align) {
      for (const cc of spec.align) {
        if (isFunc[cr][cc]) continue;
        for (let dr = -2; dr <= 2; dr += 1) {
          for (let dc = -2; dc <= 2; dc += 1) isFunc[cr + dr][cc + dc] = true;
        }
      }
    }
    for (let i = 0; i < size; i += 1) { isFunc[6][i] = true; isFunc[i][6] = true; }
    for (let i = 0; i <= 8; i += 1) { isFunc[8][i] = true; isFunc[i][8] = true; }
    for (let i = 0; i < 8; i += 1) { isFunc[8][size - 1 - i] = true; isFunc[size - 1 - i][8] = true; }
    if (version >= 7) {
      for (let i = 0; i < 18; i += 1) {
        const a = Math.floor(i / 3);
        const b = size - 11 + (i % 3);
        isFunc[b][a] = true;
        isFunc[a][b] = true;
      }
    }

    const bits = [];
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let step = 0; step < size; step += 1) {
        const r = upward ? size - 1 - step : step;
        for (let dx = 0; dx < 2; dx += 1) {
          const c = right - dx;
          if (!isFunc[r][c]) {
            const bit = matrix[r][c] !== maskFn(mask, r, c);
            bits.push(bit ? 1 : 0);
          }
        }
      }
      upward = !upward;
    }

    const numBlocks = spec.g1Blocks + spec.g2Blocks;
    const totalCodewords = spec.totalData + numBlocks * spec.ecPerBlock;
    const cw = new Uint8Array(totalCodewords);
    for (let i = 0; i < totalCodewords; i += 1) {
      let val = 0;
      for (let b = 0; b < 8; b += 1) val = (val << 1) | bits[i * 8 + b];
      cw[i] = val;
    }

    // De-interleave blocks & verify Reed-Solomon syndromes == 0 for every block
    const blocks = [];
    for (let b = 0; b < spec.g1Blocks; b += 1) blocks.push({ data: new Uint8Array(spec.g1Data), ec: new Uint8Array(spec.ecPerBlock) });
    for (let b = 0; b < spec.g2Blocks; b += 1) blocks.push({ data: new Uint8Array(spec.g2Data), ec: new Uint8Array(spec.ecPerBlock) });
    let pos = 0;
    const maxData = Math.max(spec.g1Data, spec.g2Data);
    for (let i = 0; i < maxData; i += 1) {
      for (const blk of blocks) if (i < blk.data.length) blk.data[i] = cw[pos++];
    }
    for (let i = 0; i < spec.ecPerBlock; i += 1) {
      for (const blk of blocks) blk.ec[i] = cw[pos++];
    }
    for (const blk of blocks) {
      const full = new Uint8Array([...blk.data, ...blk.ec]);
      for (let s = 0; s < spec.ecPerBlock; s += 1) {
        let acc = 0;
        const root = GF_EXP[s];
        for (let j = 0; j < full.length; j += 1) acc = gfMul(acc, root) ^ full[j];
        assert.equal(acc, 0, `RS syndrome ${s} must be 0`);
      }
    }

    // Concatenate data bytes and decode Byte mode payload
    const dataBytes = Buffer.concat(blocks.map((b) => Buffer.from(b.data)));
    const mode = dataBytes[0] >>> 4;
    assert.equal(mode, 0b0100, 'must be Byte mode');
    const len = ((dataBytes[0] & 0x0f) << 4) | (dataBytes[1] >>> 4);
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i += 1) {
      out[i] = ((dataBytes[1 + i] & 0x0f) << 4) | (dataBytes[2 + i] >>> 4);
    }
    return new TextDecoder().decode(out);
  }

  for (const url of [
    'https://w12345678901.tianacloud.site/web/w12345678901/',
    'https://w98765432109.tianacloud.site/web/w98765432109/?view=workbench&ref=qr-round2-verification-long-url',
  ]) {
    const qr = encodeQrMatrix(url);
    assert.equal(decodeAndVerifyQr(qr), url);
  }
});

test('FrontendAssets.prepare() with allowlist: [] blocks third-party inject and rejects unallowlisted third-party external', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-allowlist-e2e-'));
  try {
    const frontendDir = join(dir, 'dsh-web-frontend');
    mkdirSync(join(frontendDir, 'dist', 'assets'), { recursive: true });
    writeFileSync(
      join(frontendDir, 'dist', 'index.html'),
      '<!doctype html><link rel="stylesheet" href="./assets/app.css"><script type="module" src="./assets/index.js"></script>',
    );
    writeFileSync(join(frontendDir, 'dist', 'assets', 'app.css'), 'body{margin:0}');
    writeFileSync(
      join(frontendDir, 'dist', 'assets', 'index.js'),
      'const __e = new Function("ctx","expr",`return eval(expr)`); const __p=function(load,deps){let p=Promise.resolve();if(deps){new Event("vite:preloadError")}return p.then(()=>{return load().catch(err)})}; void __e; void __p;',
    );

    const makePluginPkg = (name) => {
      const pkgDir = join(dir, 'pkgs', name.replace('/', '__'));
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name, exports: { './client': './client.js' } }));
      const clientPath = join(pkgDir, 'client.js');
      writeFileSync(clientPath, `window.__ModuleLoader__.load({id:${JSON.stringify(name)},factory(){return {};}});`);
      return clientPath;
    };

    const clientPaths = new Map([
      ['@deepseek-ai/dsh-client-modules', makePluginPkg('@deepseek-ai/dsh-client-modules')],
      ['@tianacloud/dsh-remote', makePluginPkg('@tianacloud/dsh-remote')],
      ['fixture-third-party', makePluginPkg('fixture-third-party')],
      ['fixture-selected-plugin', makePluginPkg('fixture-selected-plugin')],
    ]);

    const bootRows = [{
      kind: 'global',
      name: '__DSH_BOOT__',
      value: {
        entries: [
          {
            id: '@deepseek-ai/dsh-client-modules',
            url: 'plugins/??@deepseek-ai/dsh-client-modules/client.js&rev=r1',
            rev: 'r1',
            inject: ['@tianacloud/dsh-remote', 'fixture-third-party'],
          },
          {
            id: '@tianacloud/dsh-remote',
            url: 'plugins/??@tianacloud/dsh-remote/client.js&rev=r2',
            rev: 'r2',
          },
          {
            id: 'fixture-third-party',
            url: 'plugins/??fixture-third-party/client.js&rev=r3',
            rev: 'r3',
          },
        ],
        batches: [],
      },
    }];

    const assets = new FrontendAssets({
      frontend: frontendDir,
      allowlist: [],
      activeClientPath: (id) => clientPaths.get(id),
    });
    const prepared = await assets.prepare(bootRows);
    assert.deepEqual(
      prepared.manifest.boot.entries.map((e) => e.id),
      ['@deepseek-ai/dsh-client-modules', '@tianacloud/dsh-remote'],
      'allowlist: [] must block fixture-third-party even when listed in bootstrap inject',
    );
    const bootstrapRow = prepared.manifest.boot.entries.find((e) => e.id === '@deepseek-ai/dsh-client-modules');
    assert.deepEqual(bootstrapRow.inject, ['@tianacloud/dsh-remote']);

    // Bootstrap/builtin module referencing unallowlisted third-party in `external` must succeed and strip it
    const emptyAllowlistExternal = structuredClone(bootRows);
    emptyAllowlistExternal[0].value.entries[0].external = ['react', '@tianacloud/dsh-remote', 'fixture-third-party'];
    const preparedExt = await assets.prepare(emptyAllowlistExternal);
    assert.deepEqual(
      preparedExt.manifest.boot.entries.map((e) => e.id),
      ['@deepseek-ai/dsh-client-modules', '@tianacloud/dsh-remote'],
      'allowlist: [] must keep permitted graph when bootstrap external lists third-party plugins',
    );
    const bootstrapExtRow = preparedExt.manifest.boot.entries.find((e) => e.id === '@deepseek-ai/dsh-client-modules');
    assert.deepEqual(bootstrapExtRow.external, ['react', '@tianacloud/dsh-remote']);

    const onlyThirdPartyExternal = structuredClone(bootRows);
    onlyThirdPartyExternal[0].value.entries[0].external = ['fixture-third-party'];
    const preparedOnlyThird = await assets.prepare(onlyThirdPartyExternal);
    const bootstrapOnlyThird = preparedOnlyThird.manifest.boot.entries.find((e) => e.id === '@deepseek-ai/dsh-client-modules');
    assert.deepEqual(bootstrapOnlyThird.external, []);

    // Hard external dependency on a non-allowlisted third-party module from a selected third-party plugin must throw
    const extAssets = new FrontendAssets({
      frontend: frontendDir,
      allowlist: ['fixture-selected-plugin'],
      activeClientPath: (id) => clientPaths.get(id),
    });
    await assert.rejects(
      () => extAssets.prepare([{
        kind: 'global',
        name: '__DSH_BOOT__',
        value: {
          entries: [
            { id: '@deepseek-ai/dsh-client-modules', url: 'u1', rev: 'r1' },
            { id: 'fixture-selected-plugin', url: 'u2', rev: 'r2', external: ['fixture-third-party'] },
            { id: 'fixture-third-party', url: 'u3', rev: 'r3' },
          ],
          batches: [],
        },
      }]),
      /Required third-party DSH module is not allowlisted: fixture-third-party/u,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('connect.js checks npm prefix -g, throws on startup readiness failure, and always redacts pairingKey in --json mode', async () => {
  // 1. resolveDshBinary and resolveTianaBinary fall back to `npm prefix -g` on POSIX and win32
  const posixDsh = await resolveDshBinary(async (bin, args) => {
    if (bin === 'npm' && args[0] === 'prefix' && args[1] === '-g') return { stdout: '/opt/npm-global\n', stderr: '' };
    if (bin === '/opt/npm-global/bin/dsh') return { stdout: '0.2.2\n', stderr: '' };
    throw new Error('ENOENT');
  }, 'linux');
  assert.deepEqual(posixDsh, { bin: '/opt/npm-global/bin/dsh', version: '0.2.2' });

  const winTiana = await resolveTianaBinary(async (bin, args) => {
    if (bin === 'npm.cmd' && args[0] === 'prefix' && args[1] === '-g') return { stdout: 'C:\\npm-global\n', stderr: '' };
    if (bin === join('C:\\npm-global', 'tiana.cmd')) return { stdout: 'tiana v1.0.34\n', stderr: '' };
    throw new Error('ENOENT');
  }, 'win32');
  assert.deepEqual(winTiana, { bin: join('C:\\npm-global', 'tiana.cmd'), version: '1.0.34' });

  // 2. Startup readiness failure (startDsh returns false) MUST throw instead of returning ok: true
  const secret = generateE2eeSecret();
  const baseDeps = {
    nodeVersion: '24.9.0',
    log: () => {},
    resolveDsh: async () => ({ bin: '/usr/local/bin/dsh', version: '0.2.2' }),
    ensurePlugins: async () => {},
    ensureTianaToolchain: async () => ({ bin: '/usr/local/bin/tiana', version: '1.0.34' }),
    ensureLogin: async () => ({ logged_in: true }),
    readRuntime: () => null,
    bindRemoteWeb: async () => ({
      host: { hostId: 'my-mac', hostName: 'My Mac' },
      e2ee: { secret, fingerprint: 'aa:bb:cc' },
      web: { id: 'abc123456789', endpoint: 'https://abc123456789.tianacloud.site/web/abc123456789/' },
    }),
  };
  await assert.rejects(
    () => runConnect({ app: 'abc123456789', port: '4123' }, {
      ...baseDeps,
      startDsh: async () => false,
    }),
    /Local DSH web server failed to become ready on 127\.0\.0\.1:4123/u,
  );

  // 3. --json mode MUST NEVER include pairingKey on stdout even when --print-key is also passed
  const origConsoleLog = console.log;
  const origConsoleError = console.error;
  const stdoutLines = [];
  console.log = (...args) => stdoutLines.push(args.join(' '));
  console.error = () => {};
  try {
    const jsonSummary = await runConnect({
      app: 'abc123456789',
      noStart: true,
      json: true,
      printKey: true,
    }, baseDeps);
    assert.equal(jsonSummary.pairingKey, undefined);
    const printed = stdoutLines.join('\n');
    const parsed = JSON.parse(printed);
    assert.equal(parsed.pairingKey, undefined);
    assert.equal(printed.includes(secret), false, '--json stdout must never contain raw secret');
    assert.equal(printed.includes('dshk1_'), false, '--json stdout must never contain dshk1_ pairing key');
  } finally {
    console.log = origConsoleLog;
    console.error = origConsoleError;
  }
});

test('Lamport Bakery state lock maintains strict mutual exclusion across forked processes with adversarial pauses', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-bakery-race-'));
  const statePath = join(dir, 'state.json');
  const claimsDir = `${statePath}.lock.claims`;
  const workerScript = join(dir, 'worker.mjs');
  const stateModuleUrl = pathToFileURL(join(PROJECT_ROOT, 'src', 'state.js')).href;

  try {
    mkdirSync(claimsDir, { recursive: true, mode: 0o700 });
    const deadEntering = join(claimsDir, `entering-99999999-${'d'.repeat(32)}`);
    const deadTicket = join(claimsDir, `ticket-0000000000000001-99999999-${'e'.repeat(32)}`);
    writeFileSync(deadEntering, '', { mode: 0o600 });
    writeFileSync(deadTicket, '', { mode: 0o600 });

    writeFileSync(workerScript, `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const dir = process.argv[2];
const role = process.argv[3];
const statePath = join(dir, 'state.json');
const claimsDir = statePath + '.lock.claims';
const deadTicket = join(claimsDir, 'ticket-0000000000000001-99999999-' + 'e'.repeat(32));
const mark = (name) => join(dir, name);
const sleepBuf = new Int32Array(new SharedArrayBuffer(4));

function signalThenPause(signal, until) {
  fs.writeFileSync(mark(signal), '');
  const deadline = Date.now() + 8000;
  while (!fs.existsSync(mark(until))) {
    if (Date.now() > deadline) throw new Error('Timed out waiting for ' + until);
    Atomics.wait(sleepBuf, 0, 0, 2);
  }
}

const origUnlink = fs.unlinkSync;
let paused = false;

fs.unlinkSync = function (file, ...args) {
  if (role === 'B' && file === deadTicket && !paused) {
    paused = true;
    // B holds ticket #2; pause right before reaping deadTicket so A also enters, picks ticket #3,
    // and reaches unlinkSync(deadTicket) before B acquires the critical section.
    signalThenPause('B-has-ticket', 'A-before-dead-unlink');
  } else if (role === 'A' && file === deadTicket && !paused) {
    paused = true;
    // A pauses right before reaping deadTicket until B is actively inside the critical section.
    signalThenPause('A-before-dead-unlink', 'B-acquired');
  }
  return origUnlink(file, ...args);
};

syncBuiltinESMExports();
const { withStateLock } = await import(${JSON.stringify(stateModuleUrl)});

await withStateLock(async () => {
  const activeFile = mark('active-holder');
  if (fs.existsSync(activeFile)) {
    fs.writeFileSync(mark('overlap-detected'), role);
  }
  fs.writeFileSync(activeFile, role);
  fs.writeFileSync(mark(role + '-acquired'), '');
  if (role === 'B') {
    await delay(150);
  } else {
    await delay(30);
  }
  fs.unlinkSync(activeFile);
  fs.writeFileSync(mark(role + '-released'), '');
}, statePath, { timeoutMs: 8000 });
`);

    const runChild = (role) => new Promise((resolve, reject) => {
      const child = fork(workerScript, [dir, role], { stdio: 'pipe' });
      let stderr = '';
      child.stderr?.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
      child.on('exit', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Worker ${role} exited ${code}: ${stderr}`));
      });
      child.on('error', reject);
    });

    const childB = runChild('B');
    const waitDeadline = Date.now() + 5000;
    while (!existsSync(join(dir, 'B-has-ticket')) && Date.now() < waitDeadline) {
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.equal(existsSync(join(dir, 'B-has-ticket')), true, 'Process B must reach ticket pause');
    const childA = runChild('A');
    await Promise.all([childA, childB]);

    assert.equal(existsSync(join(dir, 'A-before-dead-unlink')), true, 'Process A pause point must have triggered');
    assert.equal(existsSync(join(dir, 'A-released')), true, 'Process A must complete critical section');
    assert.equal(existsSync(join(dir, 'B-released')), true, 'Process B must complete critical section');
    assert.equal(existsSync(join(dir, 'overlap-detected')), false, 'Critical sections MUST NEVER overlap');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('pack-plugin scanWorktreeAndGitHistory fails closed on shallow clone and scans full HEAD history', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-shallow-scan-'));
  const originRepo = join(dir, 'origin');
  const shallowRepo = join(dir, 'shallow');
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_NAME: 'Test Author',
    GIT_AUTHOR_EMAIL: 'test@example.test',
    GIT_COMMITTER_NAME: 'Test Author',
    GIT_COMMITTER_EMAIL: 'test@example.test',
  };
  try {
    mkdirSync(originRepo, { recursive: true });
    execFileSync('git', ['init', '-b', 'main'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    writeFileSync(join(originRepo, 'README.md'), '# Clean public repo\n');
    execFileSync('git', ['add', 'README.md'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'Initial clean commit'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    writeFileSync(join(originRepo, 'hello.txt'), 'hello world\n');
    execFileSync('git', ['add', 'hello.txt'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'Add hello file'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });

    // Full non-shallow repo with clean history passes with zero findings
    assert.deepEqual(scanWorktreeAndGitHistory(originRepo), []);

    // Shallow --depth 1 clone MUST fail closed
    execFileSync('git', ['clone', '--depth', '1', pathToFileURL(originRepo).href, shallowRepo], {
      cwd: dir,
      env: gitEnv,
      stdio: 'pipe',
    });
    const shallowFindings = scanWorktreeAndGitHistory(shallowRepo);
    assert.equal(shallowFindings.length, 1);
    assert.match(shallowFindings[0], /shallow git repository: fetch-depth: 0 is required/u);

    // Full history scan detects forbidden token even if removed in a later commit
    const syntheticPat = ['ghp', '_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'].join('');
    writeFileSync(join(originRepo, 'hello.txt'), `token=${syntheticPat}\n`);
    execFileSync('git', ['add', 'hello.txt'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'Add synthetic token'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    writeFileSync(join(originRepo, 'hello.txt'), 'cleaned\n');
    execFileSync('git', ['add', 'hello.txt'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'Remove synthetic token'], { cwd: originRepo, env: gitEnv, stdio: 'pipe' });

    const historyFindings = scanWorktreeAndGitHistory(originRepo);
    assert.ok(historyFindings.some((f) => f.includes('git-diff-added(HEAD)') && f.includes('GitHub PAT token')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function writeConcurrentBindMockTiana(binary, dir, { delayOnA = 80, failAfterPublishOnA = false } = {}) {
  writeFileSync(binary, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const paramsFile = path.join(dir, 'function-params.json');
let data;
if (args[0] === 'status') {
  data = { logged_in: true, user: { user_id: 'fixture-user', tenant_id: 'fixture-tenant', email: 'owner@example.test' } };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = {
    items: [{
      id: 'fixture00001',
      owner_id: 'fixture-user',
      tenant_id: 'fixture-tenant',
      enabled: true,
      deletion_pending: false,
      endpoint: 'https://fixture.invalid/web/fixture00001/',
    }],
  };
} else if (args[0] === 'web' && args[1] === 'functions' && args[2] === 'get') {
  data = { function_instance_ids: ['fixture-function'], project_revision: 1 };
} else if (args[0] === 'function' && args[1] === 'show') {
  data = {
    instance: {
      id: 'fixture-function',
      product_state: 'ACTIVE',
      enabled: true,
      deletion_pending: false,
      connection: { hostname: 'function.invalid', url: 'https://function.invalid/' },
    },
    function: { instance_id: 'fixture-function', source_dir: '.' },
    release: { published: { id: '1', build_commit: 'built-commit' } },
  };
} else if (args[0] === 'token' && args[1] === 'create') {
  data = { token: 'fixture-new-token', token_id: 'fixture-new-id' };
} else if (args.slice(0, 3).join(' ') === 'function parameters get') {
  data = {
    parameters: fs.existsSync(paramsFile)
      ? JSON.parse(fs.readFileSync(paramsFile, 'utf8'))
      : { EXISTING_KEY: { kind: 'plain', value: 'keep' } },
  };
} else if (args.slice(0, 3).join(' ') === 'function parameters set') {
  const fileArg = args[args.indexOf('--file') + 1];
  fs.copyFileSync(fileArg, paramsFile);
  if (path.basename(process.argv[1]) === 'tiana-a') {
    fs.writeFileSync(path.join(dir, 'a-published'), '');
    const wait = new Int32Array(new SharedArrayBuffer(4));
    Atomics.wait(wait, 0, 0, ${Number(delayOnA)});
    if (${JSON.stringify(Boolean(failAfterPublishOnA))}) {
      process.stderr.write('simulated mid-publish CLI failure after writing cloud policy');
      process.exit(8);
    }
  }
  data = { ok: true };
} else {
  process.exit(5);
}
console.log(JSON.stringify({ data }));
`, { mode: 0o700 });
}

test('R4-1: overlapping concurrent first binds serialize cleanly with matching local key and Relay policy digest', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-concurrent-bind-ok-'));
  try {
    const statePath = join(dir, 'state.json');
    const tianaA = join(dir, 'tiana-a');
    const tianaB = join(dir, 'tiana-b');
    writeConcurrentBindMockTiana(tianaA, dir, { delayOnA: 80, failAfterPublishOnA: false });
    writeConcurrentBindMockTiana(tianaB, dir, { delayOnA: 80, failAfterPublishOnA: false });

    const common = { webId: 'fixture00001', hostId: 'same-host', statePath, log: () => {} };
    let releaseA;
    let releaseB;
    const aReady = new Promise((resolve) => { releaseB = resolve; });
    const bReady = new Promise((resolve) => { releaseA = resolve; });

    const first = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaA,
      hostName: 'Bind A',
      probeRelayHealth: async () => {
        releaseB();
        await bReady;
        return { ok: true, paired: false };
      },
    });
    const second = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaB,
      hostName: 'Bind B',
      probeRelayHealth: async () => {
        await aReady;
        releaseA();
        const deadline = Date.now() + 5000;
        while (!existsSync(join(dir, 'a-published'))) {
          if (Date.now() >= deadline) throw new Error('Timed out waiting for Bind A to publish');
          await new Promise((r) => setTimeout(r, 5));
        }
        return { ok: true, paired: false };
      },
    });

    const [resA, resB] = await Promise.all([first, second]);
    assert.equal(resA.host.hostId, 'same-host');
    assert.equal(resB.host.hostId, 'same-host');
    assert.equal(resB.host.registrationKey, resA.host.registrationKey, 'second overlapping bind must reuse committed registrationKey');

    const local = loadRemoteState(statePath);
    const cloud = JSON.parse(JSON.parse(readFileSync(join(dir, 'function-params.json'), 'utf8')).DSH_REMOTE_POLICY.value);
    const localDigest = createHash('sha256').update(local.host.registrationKey).digest('hex');
    assert.equal(localDigest, cloud.hostDigest, 'sha256(local.host.registrationKey) must match cloud.hostDigest');
    assert.equal(local.host.hostName, cloud.hostName, 'local hostName must match cloud hostName');
    assert.equal(local.pendingBind, undefined, 'pendingBind must be cleared after commit');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-1: fault-injected mid-publish failure during overlapping binds rejects first explicitly and lets second recover coherently', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-concurrent-bind-fault-'));
  try {
    const statePath = join(dir, 'state.json');
    const tianaA = join(dir, 'tiana-a');
    const tianaB = join(dir, 'tiana-b');
    writeConcurrentBindMockTiana(tianaA, dir, { delayOnA: 150, failAfterPublishOnA: true });
    writeConcurrentBindMockTiana(tianaB, dir, { delayOnA: 150, failAfterPublishOnA: false });

    const common = { webId: 'fixture00001', hostId: 'same-host', statePath, log: () => {} };
    let releaseA;
    let releaseB;
    const aReady = new Promise((resolve) => { releaseB = resolve; });
    const bReady = new Promise((resolve) => { releaseA = resolve; });

    const first = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaA,
      hostName: 'Bind A',
      probeRelayHealth: async () => {
        releaseB();
        await bReady;
        return { ok: true, paired: false };
      },
    });
    const second = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaB,
      hostName: 'Bind B',
      probeRelayHealth: async () => {
        await aReady;
        releaseA();
        const deadline = Date.now() + 5000;
        while (!existsSync(join(dir, 'a-published'))) {
          if (Date.now() >= deadline) throw new Error('Timed out waiting for Bind A to publish');
          await new Promise((r) => setTimeout(r, 5));
        }
        return { ok: true, paired: false };
      },
    });

    const [settledA, settledB] = await Promise.allSettled([first, second]);
    assert.equal(settledA.status, 'rejected', 'fault-injected first bind must reject explicitly');
    assert.match(String(settledA.reason?.message || settledA.reason), /simulated mid-publish CLI failure/u);
    assert.equal(settledB.status, 'fulfilled', 'second overlapping bind must recover seamlessly from pendingBind + cloud policy');

    const local = loadRemoteState(statePath);
    const cloud = JSON.parse(JSON.parse(readFileSync(join(dir, 'function-params.json'), 'utf8')).DSH_REMOTE_POLICY.value);
    const localDigest = createHash('sha256').update(local.host.registrationKey).digest('hex');
    assert.equal(localDigest, cloud.hostDigest, 'recovered local registrationKey must match cloud.hostDigest');
    assert.equal(local.host.hostName, 'Bind B');
    assert.equal(cloud.hostName, 'Bind B');
    assert.equal(local.pendingBind, undefined, 'pendingBind must be cleared after recovery commit');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-1: interrupted bind preserves later E2EE rotation, equal-expiry token renewal survives overlapping binds, and concurrent fallback binds converge on one Relay Function', async () => {
  // 1. publish-failure + independent E2EE rotation & equal-expiry token renewal
  const dir1 = mkdtempSync(join(tmpdir(), 'dsh-remote-r4-1-rot-renew-'));
  try {
    const statePath = join(dir1, 'state.json');
    const tianaA = join(dir1, 'tiana-a');
    const tianaB = join(dir1, 'tiana-b');
    writeConcurrentBindMockTiana(tianaA, dir1, { delayOnA: 150, failAfterPublishOnA: true });
    writeConcurrentBindMockTiana(tianaB, dir1, { delayOnA: 50, failAfterPublishOnA: false });

    const initialSecret = generateE2eeSecret();
    const rotatedSecret = generateE2eeSecret();
    const sameExpiry = Math.floor(Date.now() / 1000) + 35 * 86400;
    const regKey = generateE2eeSecret();

    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'same-host', hostName: 'Before', registrationKey: regKey },
      e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: initialSecret, fingerprint: '1111:2222:3333' },
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      web: { id: 'fixture00001', endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: 'tok-initial', tokenId: 'tid-initial', expiresAt: sameExpiry },
    }, statePath);

    writeFileSync(join(dir1, 'function-params.json'), JSON.stringify({
      DSH_REMOTE_POLICY: {
        kind: 'plain',
        value: JSON.stringify({
          version: 1,
          webId: 'fixture00001',
          origin: 'https://fixture.invalid',
          ownerUserId: 'fixture-user',
          ownerTenantId: 'fixture-tenant',
          hostId: 'same-host',
          hostName: 'Before',
          hostDigest: createHash('sha256').update(regKey).digest('hex'),
        }),
      },
    }), { mode: 0o600 });

    const common = { webId: 'fixture00001', hostId: 'same-host', statePath, log: () => {} };
    const first = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaA,
      hostName: 'Bind A',
      probeRelayHealth: async () => ({ ok: true, paired: true }),
    });
    const deadline = Date.now() + 5000;
    while (!existsSync(join(dir1, 'a-published'))) {
      if (Date.now() >= deadline) throw new Error('Timed out waiting for A publish');
      await new Promise((r) => setTimeout(r, 5));
    }
    const second = bindTianaRemoteWeb({
      ...common,
      tianaBin: tianaB,
      hostName: 'Bind B',
      probeRelayHealth: async () => ({ ok: true, paired: true }),
    });

    // Independent E2EE rotation + equal-expiry token renewal committed while A is failing & B is waiting
    await withStateLock(() => {
      const cur = loadRemoteState(statePath);
      cur.e2ee = { algorithm: 'x25519-chacha20poly1305-v1', secret: rotatedSecret, fingerprint: '4444:5555:6666' };
      cur.function = { ...cur.function, token: 'tok-renewed-same-exp', tokenId: 'tid-renewed', expiresAt: sameExpiry };
      saveRemoteState(cur, statePath);
    }, statePath);

    const [settledA, settledB] = await Promise.allSettled([first, second]);
    assert.equal(settledA.status, 'rejected');
    assert.equal(settledB.status, 'fulfilled');

    const local = loadRemoteState(statePath);
    assert.equal(local.e2ee.secret, rotatedSecret, 'interrupted bind recovery must preserve independent E2EE rotation');
    assert.equal(local.function.token, 'tok-renewed-same-exp', 'equal-expiry independent token renewal must survive');
    assert.equal(local.function.tokenId, 'tid-renewed');
    assert.equal(local.pendingBind, undefined);
  } finally {
    rmSync(dir1, { recursive: true, force: true });
  }

  // 2. Concurrent fallback binds when Web app has no Relay Function converge on the SAME Relay Function
  const dir2 = mkdtempSync(join(tmpdir(), 'dsh-remote-r4-1-fallback-'));
  try {
    const statePath = join(dir2, 'state.json');
    const writeFallbackMock = (binPath, role) => {
      writeFileSync(binPath, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const role = ${JSON.stringify(role)};
const args = process.argv.slice(2);
const key = args.slice(0, 3).join(' ');
const read = (n, fb) => fs.existsSync(path.join(dir, n)) ? JSON.parse(fs.readFileSync(path.join(dir, n), 'utf8')) : fb;
const write = (n, v) => fs.writeFileSync(path.join(dir, n), JSON.stringify(v));
let data;
if (args[0] === 'status') {
  data = { logged_in: true, user: { user_id: 'fixture-user', tenant_id: 'fixture-tenant' } };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = { items: [{ id: 'fixture00001', owner_id: 'fixture-user', tenant_id: 'fixture-tenant', enabled: true, endpoint: 'https://fixture.invalid/web/fixture00001/' }] };
} else if (key === 'web functions get') {
  data = read('web-binding.json', { function_instance_ids: [], project_revision: 1 });
} else if (key === 'web functions set') {
  const cur = read('web-binding.json', { project_revision: 1 });
  if (String(cur.project_revision) !== args[args.indexOf('--expected-revision') + 1]) { process.stderr.write('revision conflict'); process.exit(8); }
  write('web-binding.json', { function_instance_ids: [args[args.indexOf('--function-id') + 1]], project_revision: cur.project_revision + 1 });
  data = {};
} else if (args[0] === 'function' && args[1] === 'create') {
  data = { instance_id: 'fixture-fn-' + role };
} else if (args[0] === 'function' && args[1] === 'show') {
  const fn = args[2];
  data = { instance: { id: fn, product_state: 'ACTIVE', enabled: true, connection: { hostname: fn + '.invalid', url: 'https://' + fn + '.invalid/' } }, function: { instance_id: fn }, release: { published: { id: '1', build_commit: 'b1' } } };
} else if (key === 'function source list') {
  data = { commit: 'c0' };
} else if (key === 'function source read') {
  process.stdout.write('old'); process.exit(0);
} else if (key === 'function source save') {
  data = { commit: 'c1' };
} else if (args[0] === 'function' && args[1] === 'publish') {
  data = {};
} else if (args[0] === 'function' && args[1] === 'builds') {
  data = { items: [{ id: '1', source_commit: 'c1', build_commit: 'b1' }] };
} else if (args[0] === 'token' && args[1] === 'create') {
  data = { token: 'tok-' + role, token_id: 'tid-' + role };
} else if (key === 'function parameters get') {
  data = { parameters: read(args[3] + '.json', {}) };
} else if (key === 'function parameters set') {
  fs.copyFileSync(args[args.indexOf('--file') + 1], path.join(dir, args[3] + '.json'));
  fs.writeFileSync(path.join(dir, role + '-published'), '');
  data = {};
} else {
  process.exit(5);
}
console.log(JSON.stringify({ data }));
`, { mode: 0o700 });
    };
    const tianaA = join(dir2, 'tiana-a');
    const tianaB = join(dir2, 'tiana-b');
    writeFallbackMock(tianaA, 'a');
    writeFallbackMock(tianaB, 'b');

    let releaseB;
    const aBound = new Promise((resolve) => { releaseB = resolve; });
    const first = bindTianaRemoteWeb({
      webId: 'fixture00001',
      hostId: 'same-host',
      hostName: 'Bind A',
      statePath,
      tianaBin: tianaA,
      log: () => {},
      probeRelayHealth: async () => {
        releaseB();
        const deadline = Date.now() + 5000;
        while (!existsSync(join(dir2, 'b-published'))) {
          if (Date.now() >= deadline) throw new Error('Timed out waiting for B publish');
          await new Promise((r) => setTimeout(r, 5));
        }
        return { ok: true, paired: false };
      },
    });
    const second = bindTianaRemoteWeb({
      webId: 'fixture00001',
      hostId: 'same-host',
      hostName: 'Bind B',
      statePath,
      tianaBin: tianaB,
      log: () => {},
      probeRelayHealth: async () => {
        await aBound;
        return { ok: true, paired: false };
      },
    });

    const [resA, resB] = await Promise.all([first, second]);
    const webFn = JSON.parse(readFileSync(join(dir2, 'web-binding.json'), 'utf8')).function_instance_ids[0];
    const local = loadRemoteState(statePath);
    assert.equal(resA.function.id, webFn);
    assert.equal(resB.function.id, webFn);
    assert.equal(local.function.id, webFn);
    const cloud = JSON.parse(JSON.parse(readFileSync(join(dir2, `${webFn}.json`), 'utf8')).DSH_REMOTE_POLICY.value);
    assert.equal(createHash('sha256').update(local.host.registrationKey).digest('hex'), cloud.hostDigest);
  } finally {
    rmSync(dir2, { recursive: true, force: true });
  }
});

test('R4-2: scanWorktreeAndGitHistory scans commit author/committer identity and allows GitHub noreply addresses only', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-identity-scan-'));
  const noreplyRepo = join(dir, 'noreply');
  const syntheticPersonalEmail = ['dev.user', '@', 'gmail', '.com'].join('');
  const syntheticGithubEmail = ['someone', '@', 'github', '.com'].join('');
  const syntheticUkEmail = ['synthetic.person', '@', 'fixture', '.uk'].join('');
  const syntheticGithubLookalike = ['noreply', '@', 'github', '.com.fixture.org'].join('');
  const syntheticUsersNoreplyLookalike = ['12345+fixture', '@', 'users.noreply.github', '.com.fixture.org'].join('');
  const publicIdentity = '39755142+oocococo@users.noreply.github.com';
  try {
    // 1. Personal .com, non-noreply @github.com, .uk personal, and GitHub noreply lookalike domains MUST all be flagged
    for (const [slug, authorEmail, committerEmail] of [
      ['personal', syntheticPersonalEmail, syntheticPersonalEmail],
      ['github-personal', syntheticGithubEmail, syntheticGithubEmail],
      ['uk-committer', publicIdentity, syntheticUkEmail],
      ['github-lookalike', publicIdentity, syntheticGithubLookalike],
      ['users-noreply-lookalike', syntheticUsersNoreplyLookalike, publicIdentity],
    ]) {
      const repoDir = join(dir, slug);
      mkdirSync(repoDir, { recursive: true });
      const env = {
        ...process.env,
        GIT_AUTHOR_NAME: 'Dev User',
        GIT_AUTHOR_EMAIL: authorEmail,
        GIT_COMMITTER_NAME: 'Dev User',
        GIT_COMMITTER_EMAIL: committerEmail,
      };
      execFileSync('git', ['init', '-b', 'main'], { cwd: repoDir, env, stdio: 'pipe' });
      writeFileSync(join(repoDir, 'README.md'), '# Clean content\n');
      execFileSync('git', ['add', 'README.md'], { cwd: repoDir, env, stdio: 'pipe' });
      execFileSync('git', ['commit', '-m', 'Clean commit message'], { cwd: repoDir, env, stdio: 'pipe' });
      const findings = scanWorktreeAndGitHistory(repoDir);
      assert.ok(
        findings.some((f) => f.includes('git-commit-metadata(HEAD)') && f.includes('real personal email')),
        `Expected real personal email finding for ${slug}, got: ${JSON.stringify(findings)}`,
      );
    }

    // 2. GitHub users.noreply.github.com and noreply@github.com MUST pass cleanly
    mkdirSync(noreplyRepo, { recursive: true });
    const noreplyEnv = {
      ...process.env,
      GIT_AUTHOR_NAME: 'oocococo',
      GIT_AUTHOR_EMAIL: publicIdentity,
      GIT_COMMITTER_NAME: 'oocococo',
      GIT_COMMITTER_EMAIL: publicIdentity,
    };
    execFileSync('git', ['init', '-b', 'main'], { cwd: noreplyRepo, env: noreplyEnv, stdio: 'pipe' });
    writeFileSync(join(noreplyRepo, 'README.md'), '# Clean content\n');
    execFileSync('git', ['add', 'README.md'], { cwd: noreplyRepo, env: noreplyEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'Release @tianacloud/dsh-remote v0.2.0'], { cwd: noreplyRepo, env: noreplyEnv, stdio: 'pipe' });
    execFileSync('git', ['commit', '--allow-empty', '-m', 'Merge check'], {
      cwd: noreplyRepo,
      env: { ...noreplyEnv, GIT_COMMITTER_NAME: 'GitHub', GIT_COMMITTER_EMAIL: 'noreply@github.com' },
      stdio: 'pipe',
    });
    assert.deepEqual(scanWorktreeAndGitHistory(noreplyRepo), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('R4-3: README.md accurately documents checked-by-default localStorage, memory-only unchecked mode, and single-line SSE keepalive', () => {
  const readme = readFileSync(join(PROJECT_ROOT, 'README.md'), 'utf8');
  assert.match(readme, /默认勾选「在此受信任浏览器记住密钥」/u);
  assert.match(readme, /取消勾选时密钥仅驻留当前标签页 JS 内存，绝不写入 `localStorage` 或 `sessionStorage`/u);
  assert.doesNotMatch(readme, /默认不勾选|未勾选存\s*`?sessionStorage`?/u);
  assert.ok(readme.includes('`: keepalive\\n`'), 'README must document single-line SSE keepalive comment');
  assert.equal(readme.includes('`: keepalive\\n\\n`'), false, 'README must not claim double-newline SSE keepalive');
});

test('connect accepts canonical --web and --app alias, and binds Online empty owner_id via tenant_id + can_manage proof', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-online-connect-'));
  try {
    // 1. Canonical --web and alias --app both parse cleanly, with --web taking precedence when both supplied
    let seenWebId = '';
    const secret = generateE2eeSecret();
    const mkDeps = () => ({
      nodeVersion: '24.9.0',
      log: () => {},
      resolveDsh: async () => ({ bin: '/usr/local/bin/dsh', version: '0.2.2' }),
      ensurePlugins: async () => {},
      ensureTianaToolchain: async () => ({ bin: '/usr/local/bin/tiana', version: '1.0.34' }),
      ensureLogin: async () => ({ logged_in: true }),
      readRuntime: () => ({ pid: process.pid, origin: 'http://127.0.0.1:3080' }),
      checkDshResponsive: async () => true,
      bindRemoteWeb: async (opts) => {
        seenWebId = opts.webId;
        return {
          host: { hostId: 'my-mac', hostName: 'My Mac' },
          e2ee: { secret, fingerprint: 'aa:bb:cc' },
          web: { id: opts.webId, endpoint: `https://${opts.webId}.tianacloud.site/web/${opts.webId}/` },
        };
      },
      copyToClipboard: async () => ({ ok: true, tool: 'pbcopy' }),
      openBrowser: () => true,
    });

    await runConnect({ web: 'webcanon0001', noStart: true, noOpen: true, noClipboard: true }, mkDeps());
    assert.equal(seenWebId, 'webcanon0001');
    await runConnect({ app: 'appalias0002', noStart: true, noOpen: true, noClipboard: true }, mkDeps());
    assert.equal(seenWebId, 'appalias0002');
    await runConnect({ web: 'webcanon0001', app: 'appalias0002', noStart: true, noOpen: true, noClipboard: true }, mkDeps());
    assert.equal(seenWebId, 'webcanon0001');

    // 2. Real bindTianaRemoteWeb through runConnect with Online empty owner_id + can_manage: true / false
    const makeOnlineCli = (binPath, { ownerId, tenantId, spaceCanManage, webCanManage }) => {
      writeFileSync(binPath, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const paramsFile = path.join(dir, path.basename(process.argv[1]) + '-params.json');
let data;
if (args[0] === 'status') {
  data = {
    logged_in: true,
    user: { user_id: 'usr-online-1', tenant_id: 'ten-online-1', email: 'owner@example.test' },
    space: { tenant_id: 'ten-online-1', role: 'owner', can_manage: ${JSON.stringify(spaceCanManage)} },
  };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = {
    items: [{
      id: 'onlineapp001',
      owner_id: ${JSON.stringify(ownerId)},
      tenant_id: ${JSON.stringify(tenantId)},
      enabled: true,
      deletion_pending: false,
      endpoint: 'https://onlineapp001.tianacloud.site/web/onlineapp001/',
    }],
  };
} else if (args.slice(0, 3).join(' ') === 'web functions get') {
  data = {
    web_id: 'onlineapp001',
    function_instance_ids: ['fn-online-1'],
    project_revision: 3,
    can_manage: ${JSON.stringify(webCanManage)},
  };
} else if (args[0] === 'function' && args[1] === 'show') {
  data = {
    instance: {
      id: 'fn-online-1',
      product_state: 'ACTIVE',
      enabled: true,
      deletion_pending: false,
      connection: { hostname: 'fn-online-1.invalid', url: 'https://fn-online-1.invalid/' },
    },
    function: { instance_id: 'fn-online-1' },
    release: { published: { id: 'rel-1', build_commit: 'bc-1' } },
  };
} else if (args[0] === 'token' && args[1] === 'create') {
  data = { token: 'tok-online-1', token_id: 'tid-online-1' };
} else if (args.slice(0, 3).join(' ') === 'function parameters get') {
  data = { parameters: fs.existsSync(paramsFile) ? JSON.parse(fs.readFileSync(paramsFile, 'utf8')) : {} };
} else if (args.slice(0, 3).join(' ') === 'function parameters set') {
  fs.copyFileSync(args[args.indexOf('--file') + 1], paramsFile);
  data = { ok: true };
} else {
  process.exit(5);
}
console.log(JSON.stringify({ data }));
`, { mode: 0o700 });
    };

    const okBin = join(dir, 'tiana-ok');
    const okState = join(dir, 'state-ok.json');
    makeOnlineCli(okBin, { ownerId: '', tenantId: 'ten-online-1', spaceCanManage: true, webCanManage: true });
    const okSummary = await runConnect({
      web: 'onlineapp001',
      statePath: okState,
      noStart: true,
      noOpen: true,
      noClipboard: true,
    }, {
      nodeVersion: '24.9.0',
      log: () => {},
      resolveDsh: async () => ({ bin: '/usr/local/bin/dsh', version: '0.2.2' }),
      ensurePlugins: async () => {},
      ensureTianaToolchain: async () => ({ bin: okBin, version: '1.0.34' }),
      ensureLogin: async () => ({ logged_in: true }),
      readRuntime: () => ({ pid: process.pid, origin: 'http://127.0.0.1:3080' }),
      checkDshResponsive: async () => true,
      bindRemoteWeb: (opts) => bindTianaRemoteWeb({ ...opts, probeRelayHealth: async () => ({ ok: true, paired: false }) }),
    });
    assert.equal(okSummary.ok, true);
    assert.equal(okSummary.webId, 'onlineapp001');
    assert.equal(existsSync(join(dir, 'tiana-ok-params.json')), true);

    // Negative: can_manage: false rejects before writing params or state
    const denyBin = join(dir, 'tiana-deny');
    const denyState = join(dir, 'state-deny.json');
    makeOnlineCli(denyBin, { ownerId: '', tenantId: 'ten-online-1', spaceCanManage: true, webCanManage: false });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'onlineapp001',
        statePath: denyState,
        tianaBin: denyBin,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      }),
      /owner/iu,
    );
    assert.equal(existsSync(join(dir, 'tiana-deny-params.json')), false);
    assert.equal(existsSync(denyState), false);

    // R8-2: concurrent space switch before locked recheck rejects fail-closed without writing params or state
    const spaceFlipBin = join(dir, 'tiana-space-flip');
    const spaceFlipState = join(dir, 'state-space-flip.json');
    const spaceOverrideFile = join(dir, 'space-override.json');
    writeFileSync(spaceFlipBin, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const ov = fs.existsSync(${JSON.stringify(spaceOverrideFile)}) ? JSON.parse(fs.readFileSync(${JSON.stringify(spaceOverrideFile)}, 'utf8')) : {};
const paramsFile = path.join(dir, 'tiana-space-flip-params.json');
let data;
if (args[0] === 'status') {
  const tid = ov.tenantId || 'ten-online-1';
  data = {
    logged_in: true,
    user: { user_id: 'usr-online-1', tenant_id: tid, email: 'owner@example.test' },
    space: { tenant_id: tid, role: 'owner', can_manage: true },
  };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = { items: [{ id: 'onlineapp001', owner_id: ov.ownerId ?? '', tenant_id: 'ten-online-1', enabled: true, endpoint: 'https://onlineapp001.tianacloud.site/web/onlineapp001/' }] };
} else if (args.slice(0, 3).join(' ') === 'web functions get') {
  data = { web_id: 'onlineapp001', function_instance_ids: ['fn-online-1'], project_revision: 3, can_manage: true };
} else if (args[0] === 'function' && args[1] === 'show') {
  data = { instance: { id: 'fn-online-1', product_state: 'ACTIVE', enabled: true, connection: { url: 'https://fn-online-1.invalid/' } }, function: { instance_id: 'fn-online-1' }, release: { published: { id: 'rel-1', build_commit: 'bc-1' } } };
} else if (args[0] === 'token' && args[1] === 'create') {
  data = { token: 'tok-online-1', token_id: 'tid-online-1' };
} else if (args.slice(0, 3).join(' ') === 'function parameters get') {
  data = { parameters: {} };
} else if (args.slice(0, 3).join(' ') === 'function parameters set') {
  fs.copyFileSync(args[args.indexOf('--file') + 1], paramsFile);
  data = { ok: true };
} else {
  process.exit(5);
}
console.log(JSON.stringify({ data }));
`, { mode: 0o700 });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'onlineapp001',
        spaceId: 'ten-online-1',
        statePath: spaceFlipState,
        tianaBin: spaceFlipBin,
        probeRelayHealth: async () => {
          writeFileSync(spaceOverrideFile, JSON.stringify({ tenantId: 'ten-other-space' }));
          return { ok: true, paired: false };
        },
        log: () => {},
      }),
      /owner/iu,
    );
    assert.equal(existsSync(join(dir, 'tiana-space-flip-params.json')), false);
    assert.equal(existsSync(spaceFlipState), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('v0.2.3 P0 regressions: dsh cold-start never passes positional "web" with --profile, and host-main excludes @deepseek-ai/dsh-* from third-party list', async () => {
  // 1. P0 Bug #1: buildDshStartArgs and runConnect cold-start spawn args
  const defaultArgs = buildDshStartArgs({ profile: 'web', port: 3080 });
  assert.deepEqual(defaultArgs, ['--profile', 'web', '--port', '3080', '--no-open']);
  assert.equal(defaultArgs[0], '--profile', 'must never pass positional "web" alongside --profile');

  const spawnedCalls = [];
  const secret = generateE2eeSecret();
  const res = await runConnect({
    web: 'coldstart001',
    profile: 'web',
    port: '4123',
    noOpen: true,
    noClipboard: true,
  }, {
    nodeVersion: '24.9.0',
    log: () => {},
    resolveDsh: async () => ({ bin: '/usr/local/bin/dsh', version: '0.2.2-rc.5' }),
    ensurePlugins: async () => {},
    ensureTianaToolchain: async () => ({ bin: '/usr/local/bin/tiana', version: '1.0.34' }),
    ensureLogin: async () => ({ logged_in: true }),
    readRuntime: () => null,
    bindRemoteWeb: async (opts) => ({
      host: { hostId: 'cold-host', hostName: 'Cold Host' },
      e2ee: { secret, fingerprint: 'aa:bb:cc' },
      web: { id: opts.webId, endpoint: `https://${opts.webId}.tianacloud.site/web/${opts.webId}/` },
    }),
    spawnFn: (bin, args) => {
      spawnedCalls.push({ bin, args });
      return { on() {}, unref() {} };
    },
    fetchFn: async () => Response.json({ configured: true }),
  });
  assert.equal(res.ok, true);
  assert.equal(res.dshStarted, true);
  assert.equal(spawnedCalls.length, 1);
  assert.equal(spawnedCalls[0].bin, '/usr/local/bin/dsh');
  assert.deepEqual(spawnedCalls[0].args, ['--profile', 'web', '--port', '4123', '--no-open']);
  assert.equal(spawnedCalls[0].args.filter((a) => a === 'web').length, 1, 'profile "web" must appear only once as --profile value');

  // 2. P0 Bug #2: host-main availableWebPlugins treats @deepseek-ai/dsh-* as built-in core, listing only third-party plugins
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-v023-plugins-'));
  try {
    const statePath = join(dir, 'state.json');
    const runtimePath = join(dir, 'runtime.json');
    const mockWebServer = {
      async collectIndexInjections() {
        return [{
          kind: 'global',
          name: '__DSH_BOOT__',
          value: {
            entries: [
              { id: '@deepseek-ai/dsh-client-modules' },
              { id: '@deepseek-ai/dsh-api-remotes' },
              { id: '@deepseek-ai/dsh-typert-registry' },
              { id: '@deepseek-ai/dsh-api-gateway' },
              { id: '@tianacloud/dsh-remote' },
              { id: '@acme/custom-plugin' },
              { id: 'community-plugin' },
            ],
          },
        }];
      },
    };
    const controller = createHostController({
      statePath,
      runtimePath,
      log: () => {},
      getWebServer: () => mockWebServer,
      getConnection: () => ({ browserPeer: {} }),
    });
    const overview = await controller.getAdminOverview();
    assert.deepEqual(overview.installedWebPlugins.sort(), ['@acme/custom-plugin', 'community-plugin']);
    controller.dispose();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('v0.2.4: isPrivateOrLocalAddress accepts all standard local/private/Tailnet ranges and rejects boundaries and public IPs', () => {
  const allowed = [
    // Loopback
    '127.0.0.1',
    '127.0.0.2',
    '127.255.255.254',
    '::1',
    '[::1]',
    '::ffff:127.0.0.1',
    '::ffff:7f00:0001',
    // RFC 1918 Private LAN
    '10.0.0.1',
    '10.255.255.254',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.0.1',
    '192.168.1.50',
    '192.168.255.254',
    // RFC 6598 CGNAT / Tailscale
    '100.64.0.1',
    '100.98.45.17',
    '100.127.255.254',
    // Link-Local
    '169.254.0.1',
    '169.254.1.1',
    '169.254.255.254',
    'fe80::1',
    'fe80::1%eth0',
    'fe80::1%eth0:1',
    '[fe80::1%eth0]',
    'febf:ffff::1',
    // IPv6 ULA (including Tailscale fd7a::)
    'fc00::1',
    'fd7a:115c:a1e0::1',
    'fdff:ffff::1',
    // IPv4-mapped IPv6 private / Tailscale (dotted-quad and hex)
    '::ffff:192.168.1.10',
    '::ffff:100.98.45.17',
    '::ffff:c0a8:010a',
    '0:0:0:0:0:ffff:10.0.0.5',
    '::FFFF:100.98.45.17',
  ];
  for (const addr of allowed) {
    assert.equal(isPrivateOrLocalAddress(addr), true, `expected ${JSON.stringify(addr)} to be allowed`);
  }

  const rejected = [
    // Exact range boundaries
    '100.63.255.255',
    '100.128.0.0',
    '172.15.255.255',
    '172.32.0.0',
    '192.167.255.255',
    '192.169.0.0',
    '169.253.255.255',
    '169.255.0.0',
    'fbff:ffff::1',
    'fe00::1',
    'fec0::1',
    // Public IPv4 / IPv6 & IPv4-mapped public
    '8.8.8.8',
    '1.1.1.1',
    '203.0.113.5',
    '2001:4860:4860::8888',
    '::ffff:8.8.8.8',
    '::ffff:0808:0808',
    '0:0:0:0:0:ffff:0808:0808',
    // Unspecified, multicast, broadcast, empty, malformed
    '0.0.0.0',
    '::',
    '224.0.0.1',
    'ff02::1',
    '255.255.255.255',
    '',
    '   ',
    ' 10.0.0.1 ',
    ' 127.0.0.1 ',
    null,
    undefined,
    'not-an-ip',
    '127.0.0.256',
    '010.0.0.1',
    '127.0.0.1%eth0',
    'fe80::1%',
    '[::1',
    '::1]',
  ];
  for (const addr of rejected) {
    assert.equal(isPrivateOrLocalAddress(addr), false, `expected ${JSON.stringify(addr)} to be rejected`);
  }
});

test('v0.2.4: guardAdminRequest supports Tailnet/LAN with DSH requestRejection, fails closed without it, and supports HTTP/2 :authority', async () => {
  const stubController = {
    async getAdminOverview() {
      return { ok: true, configured: true, enabled: true };
    },
  };
  const tailnetHost = 'workstation.tailnet.example.test:3080';
  const trustedHosts = new Set([tailnetHost, '192.168.1.20:3080']);
  const dshConnection = {
    seenHosts: [],
    requestRejection(req) {
      const host = req.headers instanceof Headers
        ? (req.headers.get('host') || '')
        : String(req.headers?.host || '');
      const cookie = req.headers instanceof Headers
        ? (req.headers.get('cookie') || '')
        : String(req.headers?.cookie || '');
      this.seenHosts.push(host);
      if (!isLoopbackHostHeader(host) && !trustedHosts.has(host)) return 403;
      if (!cookie.includes('dsh_web=owner-ok')) return 401;
      return null;
    },
  };
  const api = createRemoteApiHandler(stubController, dshConnection);

  // 1. Tailnet IP + trusted Host + valid owner cookie -> 200
  const tailnetOk = await api(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost, cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: '100.98.45.17', hostHeader: tailnetHost },
  );
  assert.equal(tailnetOk.status, 200);

  // 2. LAN IP + trusted Host + valid owner cookie -> 200
  const lanOk = await api(
    new Request('http://192.168.1.20:3080/api/tiana-remote/admin/overview', {
      headers: { host: '192.168.1.20:3080', cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: '192.168.1.20', hostHeader: '192.168.1.20:3080' },
  );
  assert.equal(lanOk.status, 200);

  // 3. Tailscale IPv6 ULA + trusted Host + valid owner cookie -> 200
  const ulaOk = await api(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost, cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: 'fd7a:115c:a1e0::1', hostHeader: tailnetHost },
  );
  assert.equal(ulaOk.status, 200);

  // 4. Tailnet IP when connection.requestRejection rejects (untrusted host or missing cookie) -> 403
  const untrustedHost = await api(
    new Request('https://evil.example.test:3080/api/tiana-remote/admin/overview', {
      headers: { host: 'evil.example.test:3080', cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: '100.98.45.17', hostHeader: 'evil.example.test:3080' },
  );
  assert.equal(untrustedHost.status, 403);

  const missingCookie = await api(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost },
    }),
    { remoteAddress: '100.98.45.17', hostHeader: tailnetHost },
  );
  assert.equal(missingCookie.status, 403);

  // 5. Tailnet/LAN IP when connection is null (no requestRejection) -> fail-closed 403
  const noConnApi = createRemoteApiHandler(stubController, null);
  const tailnetNoConn = await noConnApi(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost, cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: '100.98.45.17', hostHeader: tailnetHost },
  );
  assert.equal(tailnetNoConn.status, 403);

  const loopbackNonLoopbackHostNoConn = await noConnApi(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost, cookie: 'dsh_web=owner-ok' },
    }),
    { remoteAddress: '127.0.0.1', hostHeader: tailnetHost },
  );
  assert.equal(loopbackNonLoopbackHostNoConn.status, 403);

  // 6. Public IP even with valid connection.requestRejection returning null -> 403
  const permissiveConn = { requestRejection: () => null };
  const publicIpReject = await guardAdminRequest(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { host: tailnetHost, cookie: 'dsh_web=owner-ok' },
    }),
    permissiveConn,
    { remoteAddress: '8.8.8.8', hostHeader: tailnetHost },
  );
  assert.equal(publicIpReject?.status, 403);

  // 7. X-DSH-Remote-Tunnel header (including empty string) -> 403 on both loopback and Tailnet
  for (const [ip, host] of [
    ['127.0.0.1', '127.0.0.1:3080'],
    ['100.98.45.17', tailnetHost],
  ]) {
    for (const val of ['1', '']) {
      const tunReject = await guardAdminRequest(
        new Request(`http://${host}/api/tiana-remote/admin/overview`, {
          headers: { host, cookie: 'dsh_web=owner-ok', 'x-dsh-remote-tunnel': val },
        }),
        dshConnection,
        { remoteAddress: ip, hostHeader: host },
      );
      assert.equal(tunReject?.status, 403);
    }
  }

  // 8. Malformed Host headers -> 403
  for (const badHost of [
    '',
    '   ',
    ' 127.0.0.1:3080',
    'bad host:3080',
    `user@${tailnetHost}`,
    'workstation.tailnet.example.test/path',
    'workstation.tailnet.example.test?q=1',
    'workstation.tailnet.example.test#frag',
    'workstation.tailnet.example.test\\evil',
    'workstation.tailnet.example.test:',
    'workstation.tailnet.example.test:notaport',
  ]) {
    assert.equal(isValidHostHeader(badHost), false, `expected Host ${JSON.stringify(badHost)} invalid`);
    const badRes = await guardAdminRequest(
      new Request('http://127.0.0.1/api/tiana-remote/admin/overview', {
        headers: { cookie: 'dsh_web=owner-ok' },
      }),
      dshConnection,
      { remoteAddress: '100.98.45.17', hostHeader: badHost },
    );
    assert.equal(badRes?.status, 403, `expected 403 for malformed Host ${JSON.stringify(badHost)}`);
  }

  // 9. registerWebServerRoutes handles HTTP/2 :authority pseudo-header without throwing on Headers.set
  const routes = [];
  registerWebServerRoutes(
    { register(r) { routes.push(r); return () => {}; } },
    dshConnection,
    stubController,
  );
  const adminRoute = routes.find((r) => r.path === '/api/tiana-remote/admin');
  const h2Res = {
    statusCode: 0,
    headers: {},
    body: '',
    headersSent: false,
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    end(buf) { this.headersSent = true; this.body = buf ? Buffer.from(buf).toString('utf8') : ''; },
  };
  const h2Req = {
    method: 'GET',
    url: '/api/tiana-remote/admin/overview',
    headers: {
      ':method': 'GET',
      ':scheme': 'https',
      ':path': '/api/tiana-remote/admin/overview',
      ':authority': tailnetHost,
      cookie: 'dsh_web=owner-ok',
    },
    socket: { remoteAddress: '100.98.45.17' },
  };
  await adminRoute.handler(h2Req, h2Res);
  assert.equal(h2Res.statusCode, 200);
  assert.equal(JSON.parse(h2Res.body).configured, true);
  assert.equal(dshConnection.seenHosts.at(-1), tailnetHost);

  // 10. Conflicting Host and :authority headers -> 403
  const conflictRes = await guardAdminRequest(
    new Request(`https://${tailnetHost}/api/tiana-remote/admin/overview`, {
      headers: { cookie: 'dsh_web=owner-ok' },
    }),
    dshConnection,
    {
      remoteAddress: '100.98.45.17',
      nodeReq: {
        headers: {
          host: tailnetHost,
          ':authority': 'evil.example.test:3080',
          cookie: 'dsh_web=owner-ok',
        },
      },
    },
  );
  assert.equal(conflictRes?.status, 403);
});

test('v0.2.4: client.js renders explicit error card on admin 403 instead of onboarding form, recovers on retry, and uses theme-aware primary button contrast', async () => {
  const clientCode = readFileSync(join(PROJECT_ROOT, 'client.js'), 'utf8');
  const appendedStyles = [];
  const fakeDoc = {
    getElementById: (id) => appendedStyles.find((el) => el.id === id) || null,
    createElement: (tag) => ({ tag, id: '', textContent: '' }),
    head: { appendChild: (el) => appendedStyles.push(el) },
  };

  let fetchResponder = async () => new Response(
    JSON.stringify({ ok: false, error: 'Admin endpoints require local or private network access' }),
    { status: 403, headers: { 'content-type': 'application/json' } },
  );

  const timers = [];
  const sandbox = {
    globalThis: {},
    TextEncoder,
    document: fakeDoc,
    navigator: { language: 'zh-CN' },
    fetch: (url, opts) => fetchResponder(url, opts),
    setInterval: (fn) => { timers.push(fn); return timers.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(clientCode, sandbox);

  // Minimal deterministic React hook runner for TianaRemotePanel
  const states = [];
  const refs = [];
  const effects = [];
  let cursor = 0;
  let refCursor = 0;
  let effectCursor = 0;
  const miniReact = {
    createElement(type, props, ...children) {
      return { type, props: props || {}, children: children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false) };
    },
    useState(init) {
      const idx = cursor++;
      if (!(idx in states)) states[idx] = typeof init === 'function' ? init() : init;
      return [states[idx], (next) => { states[idx] = typeof next === 'function' ? next(states[idx]) : next; }];
    },
    useRef(init) {
      const idx = refCursor++;
      if (!(idx in refs)) refs[idx] = { current: init };
      return refs[idx];
    },
    useCallback(fn) { return fn; },
    useEffect(fn, deps) {
      const idx = effectCursor++;
      const prev = effects[idx];
      const changed = !prev || !deps || deps.length !== prev.deps.length || deps.some((d, i) => !Object.is(d, prev.deps[i]));
      if (changed) effects[idx] = { fn, deps, pending: true };
    },
  };

  const mod = sandbox.__DSH_REMOTE_CLIENT_FACTORY__((id) => (id === 'react' ? miniReact : {}));
  const renderPanel = () => {
    cursor = 0;
    refCursor = 0;
    effectCursor = 0;
    return mod.TianaRemotePanel({ forceMode: 'local' });
  };
  const flushEffects = async () => {
    for (const eff of effects) {
      if (eff?.pending) {
        eff.pending = false;
        eff.fn();
      }
    }
    await new Promise((r) => setTimeout(r, 10));
  };

  const findById = (node, id) => {
    if (!node || typeof node !== 'object') return null;
    if (node.props?.id === id) return node;
    for (const child of node.children || []) {
      const hit = findById(child, id);
      if (hit) return hit;
    }
    return null;
  };
  const collectText = (node) => {
    if (node === null || node === undefined || typeof node === 'boolean') return '';
    if (typeof node === 'string' || typeof node === 'number') return String(node);
    return (node.children || []).map(collectText).join(' ');
  };

  // Initial render before fetch resolves -> loading card, NOT unconfigured onboarding form
  const tree0 = renderPanel();
  assert.ok(findById(tree0, 'dshr-admin-loading-card'), 'initial render should show loading state');
  assert.equal(findById(tree0, 'dshr-unconfigured-card'), null, 'initial loading must not falsely render onboarding form');

  // Flush useEffect -> 403 response from /api/tiana-remote/admin/overview
  await flushEffects();
  const tree403 = renderPanel();
  const errCard = findById(tree403, 'dshr-admin-error-card');
  assert.ok(errCard, '403 admin/overview must render explicit error card');
  assert.equal(findById(tree403, 'dshr-unconfigured-card'), null, '403 must NOT render onboarding bind form');
  assert.equal(findById(tree403, 'dshr-bind-form'), null, '403 must NOT render bind form');
  const full403Text = collectText(tree403);
  assert.ok(full403Text.includes('HTTP 403'), 'error card must show HTTP 403 status');
  assert.ok(full403Text.includes('Admin endpoints require local or private network access'), 'error card must display server error message');
  assert.ok(full403Text.includes('访问受限'), 'status pill must show localized access-denied status');
  assert.equal(full403Text.includes('尚未绑定'), false, '403 must NOT display "尚未绑定"');
  const retryBtn = findById(tree403, 'dshr-admin-retry-btn');
  assert.ok(retryBtn, 'error card must render a Retry button');

  // Switch fetch to 200 overview & click Retry -> error card clears and configured panel renders
  fetchResponder = async () => new Response(
    JSON.stringify({
      ok: true,
      configured: true,
      enabled: true,
      host: { hostId: 'workstation-1', hostName: 'Workstation' },
      web: { id: 'web123456789', endpoint: 'https://web123456789.example.test/web/web123456789/' },
      e2ee: { fingerprint: '1122:3344:5566' },
      bridge: { relayConnected: true, sessions: [] },
      network: { p2pEnabled: true, stunUrls: ['stun:stun.cloudflare.com:3478'] },
      allowedWebPlugins: [],
      installedWebPlugins: [],
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
  retryBtn.props.onClick();
  await new Promise((r) => setTimeout(r, 10));
  const tree200 = renderPanel();
  assert.equal(findById(tree200, 'dshr-admin-error-card'), null, 'error card must clear after 200 retry');
  assert.equal(findById(tree200, 'dshr-unconfigured-card'), null);
  assert.ok(collectText(tree200).includes('在线运行中'), 'recovered panel must display Online status');

  // Verify injected CSS uses theme-aware inverted foreground for primary buttons & active tabs (fixes dark-mode white-on-white Open button)
  assert.equal(appendedStyles.length, 1);
  const css = appendedStyles[0].textContent;
  assert.match(css, /\.dshr-btn-primary[\s\S]*a\.dshr-btn-primary[\s\S]*color:\s*var\(--dsw-alias-label-primary-foreground,\s*#ffffff\)/u);
  assert.match(css, /\.dshr-tab\[aria-selected="true"\][\s\S]*color:\s*var\(--dsw-alias-label-primary-foreground,\s*#ffffff\)/u);

  // Polled 403 after initial 200 { configured: false } switches to #dshr-admin-error-card with Retry and hides bind form
  assert.equal(isLoopbackAddress(' 127.0.0.1 '), false);
  const states2 = [];
  const refs2 = [];
  const effects2 = [];
  let c2 = 0;
  let r2 = 0;
  let e2 = 0;
  const pollTimers2 = [];
  let responder2 = async () => new Response(
    JSON.stringify({ ok: true, configured: false, enabled: false }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
  const sb2 = {
    globalThis: {},
    TextEncoder,
    document: {
      getElementById: () => ({ id: 'dsh-remote-panel-styles' }),
      createElement: (tag) => ({ tag, id: '', textContent: '' }),
      head: { appendChild: () => {} },
    },
    navigator: { language: 'en-US' },
    fetch: (url, opts) => responder2(url, opts),
    setInterval: (fn) => { pollTimers2.push(fn); return pollTimers2.length; },
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
  };
  sb2.globalThis = sb2;
  vm.runInNewContext(clientCode, sb2);
  const miniReact2 = {
    createElement: miniReact.createElement,
    useState(init) {
      const idx = c2++;
      if (!(idx in states2)) states2[idx] = typeof init === 'function' ? init() : init;
      return [states2[idx], (next) => { states2[idx] = typeof next === 'function' ? next(states2[idx]) : next; }];
    },
    useRef(init) {
      const idx = r2++;
      if (!(idx in refs2)) refs2[idx] = { current: init };
      return refs2[idx];
    },
    useCallback(fn) { return fn; },
    useEffect(fn, deps) {
      const idx = e2++;
      const prev = effects2[idx];
      const changed = !prev || !deps || deps.length !== prev.deps.length || deps.some((d, i) => !Object.is(d, prev.deps[i]));
      if (changed) effects2[idx] = { fn, deps, pending: true };
    },
  };
  const mod2 = sb2.__DSH_REMOTE_CLIENT_FACTORY__((id) => (id === 'react' ? miniReact2 : {}));
  const render2 = () => { c2 = 0; r2 = 0; e2 = 0; return mod2.TianaRemotePanel({ forceMode: 'local' }); };
  render2();
  for (const eff of effects2) {
    if (eff?.pending) { eff.pending = false; eff.fn(); }
  }
  await new Promise((r) => setTimeout(r, 10));
  const treeUnconf = render2();
  assert.ok(findById(treeUnconf, 'dshr-unconfigured-card'), 'initial 200 configured:false must show onboarding card');
  assert.ok(findById(treeUnconf, 'dshr-bind-form'), 'initial 200 configured:false must show bind form');
  assert.equal(findById(treeUnconf, 'dshr-admin-error-card'), null);

  // Subsequent poll returns 403 -> must switch to #dshr-admin-error-card with Retry and hide bind form
  responder2 = async () => new Response(
    JSON.stringify({ ok: false, error: 'Local DSH owner session required' }),
    { status: 403, headers: { 'content-type': 'application/json' } },
  );
  assert.ok(pollTimers2.length >= 1, 'panel must register background poll timer');
  pollTimers2[0]();
  await new Promise((r) => setTimeout(r, 10));
  const treePolled403 = render2();
  assert.ok(findById(treePolled403, 'dshr-admin-error-card'), 'polled 403 after unconfigured 200 must show error card');
  assert.ok(findById(treePolled403, 'dshr-admin-retry-btn'), 'polled 403 error card must show Retry button');
  assert.equal(findById(treePolled403, 'dshr-unconfigured-card'), null, 'polled 403 must hide unconfigured onboarding card');
  assert.equal(findById(treePolled403, 'dshr-bind-form'), null, 'polled 403 must hide bind form');
});
