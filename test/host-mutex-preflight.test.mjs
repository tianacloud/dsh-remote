import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

import { createHostController } from '../host-main.js';
import { runConnect } from '../src/connect.js';
import { HostBridge } from '../src/host-bridge.js';
import { encodeHostFrame, MSG_CONTROL_JSON } from '../src/protocol.js';
import { createRemoteApiHandler } from '../src/remote-api.js';
import {
  claimBridgeOwnership,
  detectLocalRunningHost,
  generateE2eeSecret,
  loadRemoteState,
  releaseBridgeOwnership,
  saveRemoteState,
} from '../src/state.js';
import {
  bindTianaRemoteWeb,
  probeRelayHostStatus,
  provisionTianaRemote,
} from '../src/tiana-cli.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));
const RELAY_GO_DIR = join(PROJECT_ROOT, 'relay-go');

function writeMockTiana(binary, dir, { initialPolicy = null } = {}) {
  const paramsFile = join(dir, 'function-params.json');
  const initialParams = { EXISTING_KEY: { kind: 'plain', value: 'keep' } };
  if (initialPolicy) {
    initialParams.DSH_REMOTE_POLICY = { kind: 'plain', value: JSON.stringify(initialPolicy) };
  }
  writeFileSync(paramsFile, JSON.stringify(initialParams), { mode: 0o600 });

  writeFileSync(binary, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const paramsFile = path.join(dir, 'function-params.json');
const web = {
  id: 'mutexweb0001',
  owner_id: 'usr-owner',
  tenant_id: 'ten-owner',
  enabled: true,
  deletion_pending: false,
  endpoint: 'https://mutexweb0001.example.test/web/mutexweb0001/'
};
let data;
if (args[0] === 'status') {
  data = {
    logged_in: true,
    user: { user_id: 'usr-owner', tenant_id: 'ten-owner', display_name: 'Owner', email: 'owner@example.test' },
    space: { tenant_id: 'ten-owner', display_name: 'Personal', role: 'tenant_owner', is_default: true, can_manage: false },
  };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = { items: [web] };
} else if (args[0] === 'web' && args[1] === 'create') {
  data = { project: web };
} else if (args[0] === 'web' && args[1] === 'functions' && args[2] === 'get') {
  data = { web_id: web.id, function_instance_ids: ['fn-mutex-1'], project_revision: 1, can_manage: true };
} else if (args[0] === 'web' && args[1] === 'functions' && args[2] === 'set') {
  data = { ok: true };
} else if (args[0] === 'web' && args[1] === 'publish') {
  data = { status: 'ok' };
} else if (args[0] === 'function' && args[1] === 'show') {
  data = {
    instance: {
      id: 'fn-mutex-1',
      display_name: 'dsh-remote-relay',
      product_state: 'ACTIVE',
      enabled: true,
      deletion_pending: false,
      connection: { hostname: 'relay.invalid', url: 'https://relay.invalid/' },
    },
    release: { published: { id: 'rel-1', build_commit: 'built-1' } },
  };
} else if (args.slice(0, 3).join(' ') === 'function source list') {
  data = { commit: 'saved-1' };
} else if (args.slice(0, 3).join(' ') === 'function source read') {
  process.stdout.write('old');
  process.exit(0);
} else if (args.slice(0, 3).join(' ') === 'function source save') {
  data = { commit: 'saved-1' };
} else if (args.slice(0, 2).join(' ') === 'function publish') {
  data = {};
} else if (args.slice(0, 2).join(' ') === 'function builds') {
  data = { items: [{ id: 'rel-1', source_commit: 'saved-1', build_commit: 'built-1' }] };
} else if (args.slice(0, 3).join(' ') === 'function parameters get') {
  data = { parameters: JSON.parse(fs.readFileSync(paramsFile, 'utf8')) };
} else if (args.slice(0, 3).join(' ') === 'function parameters set') {
  fs.copyFileSync(args[args.indexOf('--file') + 1], paramsFile);
  data = { ok: true };
} else if (args.slice(0, 2).join(' ') === 'token create') {
  data = { token: 'fn-tok-1', token_id: 'tok-id-1' };
} else {
  process.exit(5);
}
console.log(JSON.stringify({ data }));
`, { mode: 0o700 });
}

function sendRawWsFrame(socket, opcode, payloadBuf) {
  const len = payloadBuf.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  }
  socket.write(Buffer.concat([header, payloadBuf]));
}

async function getFreePort() {
  const srv = net.createServer();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  await new Promise((r) => srv.close(r));
  return port;
}

test('cloud online preflight blocks bind/setup when hostConnected=true and --force-rebind rotates registrationKey even for same hostId', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-cloud-preflight-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  const webId = 'mutexweb0001';
  const initialRegKey = generateE2eeSecret();
  const initialDigest = createHash('sha256').update(initialRegKey).digest('hex');

  try {
    writeMockTiana(binary, dir, {
      initialPolicy: {
        version: 1,
        webId,
        origin: 'https://mutexweb0001.example.test',
        ownerUserId: 'usr-owner',
        ownerTenantId: 'ten-owner',
        hostId: 'ws-main',
        hostName: 'Workstation Main',
        hostDigest: initialDigest,
        updatedAt: '2026-11-22T00:00:00Z',
      },
    });

    // Seed local state with the SAME hostId + registrationKey
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      owner: { userId: 'usr-owner', tenantId: 'ten-owner' },
      host: { hostId: 'ws-main', hostName: 'Workstation Main', registrationKey: initialRegKey },
      e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: generateE2eeSecret(), fingerprint: 'aa:bb:cc' },
      function: { id: 'fn-mutex-1', url: 'https://relay.invalid/', token: 'fn-tok-1', expiresAt: Math.floor(Date.now() / 1000) + 30 * 86400 },
      web: { id: webId, endpoint: 'https://mutexweb0001.example.test/web/mutexweb0001/' },
    }, statePath);
    const paramsBefore = readFileSync(join(dir, 'function-params.json'), 'utf8');

    // 1. Default bindTianaRemoteWeb (even with rebind: true!) MUST block when hostConnected === true
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'ws-main',
        hostName: 'Workstation Main',
        rebind: true,
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: true }),
        probeRelayHostStatus: async () => ({
          supported: true,
          ok: true,
          paired: true,
          hostConnected: true,
          hostId: 'ws-main',
          hostName: 'Workstation Main',
          updatedAt: '2026-11-22T00:00:00Z',
        }),
        log: () => {},
      }),
      (err) => {
        assert.equal(err.code, 'ACTIVE_HOST_ONLINE');
        assert.equal(err.status, 409);
        assert.equal(err.details.hostId, 'ws-main');
        assert.equal(err.details.hostConnected, true);
        assert.match(err.message, /已有活跃宿主.*Workstation Main.*ws-main/u);
        assert.match(err.message, /--force-rebind/u);
        return true;
      },
    );
    assert.equal(readFileSync(join(dir, 'function-params.json'), 'utf8'), paramsBefore, 'cloud policy must not be touched on preflight block');

    // 2. With forceRebind: true, takeover succeeds AND MUST rotate registrationKey even for identical hostId
    const forced = await bindTianaRemoteWeb({
      webId,
      hostId: 'ws-main',
      hostName: 'Workstation Takeover',
      forceRebind: true,
      statePath,
      tianaBin: binary,
      probeRelayHealth: async () => ({ ok: true, paired: true }),
      probeRelayHostStatus: async () => ({
        supported: true,
        ok: true,
        paired: true,
        hostConnected: true,
        hostId: 'ws-main',
        hostName: 'Workstation Main',
      }),
      log: () => {},
    });
    assert.equal(forced.host.hostId, 'ws-main');
    assert.notEqual(forced.host.registrationKey, initialRegKey, '--force-rebind MUST rotate registrationKey even when hostId is identical');
    const updatedParams = JSON.parse(readFileSync(join(dir, 'function-params.json'), 'utf8'));
    const updatedPolicy = JSON.parse(updatedParams.DSH_REMOTE_POLICY.value);
    const expectedNewDigest = createHash('sha256').update(forced.host.registrationKey).digest('hex');
    assert.equal(updatedPolicy.hostDigest, expectedNewDigest);
    assert.notEqual(updatedPolicy.hostDigest, initialDigest);

    // 3. provisionTianaRemote also blocks when hostConnected === true and rotates registrationKey on forceRebind
    const beforeSetupKey = forced.host.registrationKey;
    await assert.rejects(
      () => provisionTianaRemote({
        hostId: 'ws-main',
        statePath,
        tianaBin: binary,
        probeRelayHostStatus: async () => ({
          supported: true,
          ok: true,
          paired: true,
          hostConnected: true,
          hostId: 'ws-main',
          hostName: 'Workstation Takeover',
        }),
        log: () => {},
      }),
      (err) => err.code === 'ACTIVE_HOST_ONLINE' && err.status === 409,
    );

    const forcedSetup = await provisionTianaRemote({
      hostId: 'ws-main',
      forceRebind: true,
      statePath,
      tianaBin: binary,
      probeRelayHostStatus: async () => ({
        supported: true,
        ok: true,
        paired: true,
        hostConnected: true,
        hostId: 'ws-main',
        hostName: 'Workstation Takeover',
      }),
      log: () => {},
    });
    assert.notEqual(forcedSetup.host.registrationKey, beforeSetupKey);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('local preflight blocks conflicting live bridge-owner/runtime PIDs while preserving connect same-config reuse', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-local-preflight-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  const secret = generateE2eeSecret();
  const fakeOtherPid = 424242;

  try {
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'local-box', hostName: 'Local Box', registrationKey: generateE2eeSecret() },
      e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret, fingerprint: '11:22:33' },
      function: { id: 'fn-1', url: 'https://relay.invalid/', token: 'tok', expiresAt: Math.floor(Date.now() / 1000) + 86400 },
      web: { id: 'sameweb00001', endpoint: 'https://sameweb00001.example.test/web/sameweb00001/' },
    }, statePath);

    await claimBridgeOwnership({
      instanceId: 'other-live-inst',
      hostId: 'local-box',
      origin: 'http://127.0.0.1:3080',
    }, statePath, { pid: fakeOtherPid, isAlive: (p) => p === fakeOtherPid });

    // 1. detectLocalRunningHost reports the live other PID and port
    const detected = detectLocalRunningHost({
      statePath,
      runtimePath,
      currentPid: process.pid,
      isAlive: (p) => p === fakeOtherPid,
    });
    assert.equal(detected.running, true);
    assert.equal(detected.pid, fakeOtherPid);
    assert.equal(detected.port, 3080);

    // 2. bindTianaRemoteWeb rejects when another local host is running
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'otherweb0002',
        statePath,
        runtimePath,
        isPidAlive: (p) => p === fakeOtherPid,
        log: () => {},
      }),
      (err) => {
        assert.equal(err.code, 'LOCAL_HOST_ALREADY_RUNNING');
        assert.match(err.message, /424242/);
        assert.match(err.message, /3080/);
        return true;
      },
    );

    // 3. runConnect to a DIFFERENT webId is blocked before touching bind or spawning DSH
    let spawned = false;
    let bound = false;
    await assert.rejects(
      () => runConnect({
        web: 'otherweb0002',
        statePath,
        runtimePath,
        noOpen: true,
        noClipboard: true,
      }, {
        nodeVersion: '24.9.0',
        isPidAlive: (p) => p === fakeOtherPid,
        bindRemoteWeb: async () => { bound = true; return {}; },
        startDsh: async () => { spawned = true; return true; },
        log: () => {},
      }),
      (err) => err.code === 'LOCAL_HOST_ALREADY_RUNNING',
    );
    assert.equal(bound, false);
    assert.equal(spawned, false);

    // 4. runConnect to the SAME already-configured webId cleanly reuses the running local host without rebinding or spawning
    const reused = await runConnect({
      web: 'sameweb00001',
      statePath,
      runtimePath,
      noOpen: true,
      noClipboard: true,
    }, {
      nodeVersion: '24.9.0',
      isPidAlive: (p) => p === fakeOtherPid,
      bindRemoteWeb: async () => { bound = true; return {}; },
      startDsh: async () => { spawned = true; return true; },
      log: () => {},
    });
    assert.equal(reused.ok, true);
    assert.equal(reused.reusedExistingHost, true);
    assert.equal(reused.dshStarted, true);
    assert.equal(bound, false, 'same-config reuse must not re-bind');
    assert.equal(spawned, false, 'same-config reuse must never spawn a second bridge');

    await releaseBridgeOwnership('other-live-inst', statePath, { pid: fakeOtherPid });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('HostBridge terminates immediately with 0 reconnects on HTTP 409, WS 4009, and HTTP 403 while retrying transient 503', async () => {
  async function runScenario(mode) {
    let attempts = 0;
    const sockets = new Set();
    const server = http.createServer((_req, res) => {
      if (mode === 'http409') {
        res.writeHead(409, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'host_already_connected' }));
      } else if (mode === 'http403') {
        res.writeHead(403, { 'content-type': 'text/plain' });
        res.end('forbidden');
      } else {
        res.writeHead(426);
        res.end();
      }
    });
    server.on('upgrade', (req, socket) => {
      attempts += 1;
      if (mode === 'http409') {
        const body = JSON.stringify({ ok: false, error: 'host_already_connected' });
        socket.write(`HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
        socket.end();
        return;
      }
      if (mode === 'http403') {
        const body = 'forbidden';
        socket.write(`HTTP/1.1 403 Forbidden\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
        socket.end();
        return;
      }
      if (mode === 'transient503' && attempts === 1) {
        const body = 'service unavailable';
        socket.write(`HTTP/1.1 503 Service Unavailable\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
        socket.end();
        return;
      }
      const key = req.headers['sec-websocket-key'];
      const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      if (mode === 'ws4009') {
        const reason = Buffer.from('host_already_connected', 'utf8');
        const payload = Buffer.alloc(2 + reason.length);
        payload.writeUInt16BE(4009, 0);
        reason.copy(payload, 2);
        sendRawWsFrame(socket, 0x08, payload);
        socket.end();
        return;
      }
      const reg = encodeHostFrame(0, 0, MSG_CONTROL_JSON, JSON.stringify({
        type: 'host_registered',
        hostId: 'term-host',
        version: 2,
      }));
      sendRawWsFrame(socket, 0x02, Buffer.from(reg));
    });

    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address();
    const logs = [];
    const bridge = new HostBridge({
      relayUrl: `http://127.0.0.1:${port}`,
      allowInsecureLoopback: true,
      relayToken: 'tok-term',
      e2eeSecret: generateE2eeSecret(),
      hostId: 'term-host',
      hostName: 'TermHost',
      registrationKey: generateE2eeSecret(),
      ownerUserId: 'usr-1',
      ownerTenantId: 'ten-1',
      webId: 'web000000099',
      localOrigin: 'http://127.0.0.1:1',
      reconnectBaseMs: 30,
      reconnectMaxMs: 60,
      log: (m) => logs.push(m),
    });

    try {
      let startErr = null;
      try {
        await bridge.start();
      } catch (err) {
        startErr = err;
      }
      await new Promise((r) => setTimeout(r, 220));
      return { attempts, startErr, snap: bridge.getStatusSnapshot(), logs };
    } finally {
      bridge.stop();
      for (const s of sockets) s.destroy();
      server.closeAllConnections?.();
      await new Promise((r) => server.close(r));
    }
  }

  // 1. HTTP 409 -> immediate terminal conflict_active_host, 0 retries
  const r409 = await runScenario('http409');
  assert.equal(r409.attempts, 1, 'HTTP 409 must trigger 0 automatic reconnects');
  assert.equal(r409.startErr?.code, 'HOST_ALREADY_CONNECTED');
  assert.equal(r409.snap.terminalState, 'conflict_active_host');
  assert.equal(r409.snap.hostConflict, true);
  assert.equal(r409.snap.lastHttpStatus, 409);
  assert.equal(r409.snap.running, false);

  // 2. WS 4009 -> immediate terminal conflict_active_host, 0 retries
  const r4009 = await runScenario('ws4009');
  assert.equal(r4009.attempts, 1, 'WS 4009 must trigger 0 automatic reconnects');
  assert.equal(r4009.startErr?.code, 'HOST_ALREADY_CONNECTED');
  assert.equal(r4009.snap.terminalState, 'conflict_active_host');
  assert.equal(r4009.snap.lastCloseCode, 4009);
  assert.equal(r4009.snap.hostConflict, true);
  assert.equal(r4009.snap.running, false);

  // 3. HTTP 403 -> immediate terminal credentials_revoked, 0 retries
  const r403 = await runScenario('http403');
  assert.equal(r403.attempts, 1, 'HTTP 403 must trigger 0 automatic reconnects');
  assert.equal(r403.startErr?.code, 'CREDENTIALS_REVOKED');
  assert.equal(r403.snap.terminalState, 'credentials_revoked');
  assert.equal(r403.snap.credentialsRevoked, true);
  assert.equal(r403.snap.lastHttpStatus, 403);
  assert.equal(r403.snap.running, false);

  // 4. Transient HTTP 503 -> MUST retry and succeed on attempt 2
  const r503 = await runScenario('transient503');
  assert.ok(r503.attempts >= 2, `transient 503 must auto-reconnect (got ${r503.attempts})`);
  assert.equal(r503.snap.relayConnected, true);
  assert.equal(r503.snap.terminalState, null);
  assert.equal(r503.snap.running, true);
});

test('local sidebar admin API & client.js render conflict/revoked banners, reconnect action, and force takeover dialog', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-sidebar-mutex-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  try {
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'panel-host', hostName: 'Panel Host', registrationKey: generateE2eeSecret() },
      owner: { userId: 'u1', tenantId: 't1', email: 'u@example.test' },
      web: { id: 'panelweb0001', name: 'DSH Remote', endpoint: 'https://panelweb0001.example.test/web/panelweb0001/' },
      function: { id: 'fn-1', name: 'fn', url: 'https://fn.example.test', token: 'tok', expiresAt: Math.floor(Date.now() / 1000) + 30 * 86400 },
      e2ee: { secret: generateE2eeSecret(), fingerprint: 'aa:bb:cc', algorithm: 'AES-256-GCM' },
      network: { p2pEnabled: true, stunUrls: [] },
    }, statePath);

    let startCount = 0;
    let currentSnap = {
      running: false,
      relayConnected: false,
      hostConflict: true,
      credentialsRevoked: false,
      terminalState: 'conflict_active_host',
      terminalReason: 'host_already_connected',
      lastHttpStatus: 409,
      lastCloseCode: 1006,
      lastCloseReason: '',
      sessions: [],
    };
    const bindCalls = [];
    const controller = createHostController({
      statePath,
      runtimePath,
      disableBridgeLock: true,
      createBridge: () => ({
        registered: false,
        terminalState: currentSnap.terminalState,
        e2eeSecret: '',
        async start() {
          startCount += 1;
          if (startCount === 1) {
            const err = new Error('conflict');
            err.terminalState = 'conflict_active_host';
            throw err;
          }
          this.registered = true;
          this.terminalState = null;
          currentSnap = { ...currentSnap, running: true, relayConnected: true, hostConflict: false, terminalState: null };
        },
        stop() {},
        updateSettings() {},
        getStatusSnapshot() { return currentSnap; },
      }),
      bindRemoteWeb: async (opts) => {
        bindCalls.push(opts);
        if (!opts.forceRebind) {
          const err = new Error('检测到该云端 Relay 当前已有活跃宿主 "OldHost (old-1)" 在线');
          err.code = 'ACTIVE_HOST_ONLINE';
          err.status = 409;
          err.details = { code: 'ACTIVE_HOST_ONLINE', webId: opts.webId, hostConnected: true, hostId: 'old-1', hostName: 'OldHost' };
          throw err;
        }
        return loadRemoteState(statePath);
      },
      getWebServer: () => ({ getOrigin: () => 'http://127.0.0.1:3080', collectIndexInjections: async () => [] }),
      getConnection: () => ({ browserPeer: {}, authenticatedUrl: (u) => u, requestRejection: () => null }),
      log: () => {},
    });

    await controller.boot();
    const handler = createRemoteApiHandler(controller, { requestRejection: () => null });
    const localMeta = { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false };

    try {
      // 1. Overview exposes terminal conflict_active_host without crashing boot()
      const ovResp = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/overview'), localMeta);
      assert.equal(ovResp.status, 200);
      const ov = await ovResp.json();
      assert.equal(ov.bridge.terminalState, 'conflict_active_host');
      assert.equal(ov.bridge.hostConflict, true);

      // 2. Provision without forceRebind records structured ACTIVE_HOST_ONLINE error
      const p1 = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/provision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ mode: 'bind', webId: 'panelweb0001', rebind: true }),
      }), localMeta);
      assert.equal(p1.status, 202);
      await new Promise((r) => setTimeout(r, 40));
      const st1 = await (await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/provision-status'), localMeta)).json();
      assert.equal(st1.step, 'error');
      assert.equal(st1.errorCode, 'ACTIVE_HOST_ONLINE');
      assert.equal(st1.errorDetails.hostId, 'old-1');

      // 3. Provision WITH forceRebind: true succeeds
      const p2 = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/provision', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ mode: 'bind', webId: 'panelweb0001', rebind: true, forceRebind: true }),
      }), localMeta);
      assert.equal(p2.status, 202);
      await new Promise((r) => setTimeout(r, 40));
      const st2 = await (await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/provision-status'), localMeta)).json();
      assert.equal(st2.step, 'done');
      assert.equal(bindCalls.at(-1).forceRebind, true);

      // 4. POST /api/tiana-remote/admin/reconnect restarts bridge cleanly
      const rcResp = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/reconnect', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      }), localMeta);
      assert.equal(rcResp.status, 200);
      const rcBody = await rcResp.json();
      assert.equal(rcBody.relayConnected, true);
    } finally {
      controller.dispose();
    }

    // 5. Verify client.js renders conflict_active_host and credentials_revoked banners + action buttons
    const clientCode = readFileSync(new URL('../client.js', import.meta.url), 'utf8');
    const findById = (node, id) => {
      if (!node || typeof node !== 'object') return null;
      if (node.props?.id === id) return node;
      for (const child of node.children || []) {
        const hit = findById(child, id);
        if (hit) return hit;
      }
      return null;
    };

    function mountLocal(overviewPayload) {
      const states = [];
      const refs = [];
      const effects = [];
      const requests = [];
      let sc = 0; let rc = 0; let ec = 0;
      const sb = {
        globalThis: {},
        window: { location: { reload() {} } },
        TextEncoder,
        document: {
          getElementById: () => ({ id: 'dsh-remote-panel-styles' }),
          createElement: (tag) => ({ tag, id: '', textContent: '' }),
          head: { appendChild: () => {} },
        },
        navigator: { language: 'zh-CN' },
        fetch: async (url, opts) => {
          requests.push({ url, method: opts?.method || 'GET', body: opts?.body ? JSON.parse(opts.body) : null });
          if (url === '/api/tiana-remote/admin/overview') {
            return new Response(JSON.stringify(overviewPayload), { status: 200 });
          }
          if (url === '/api/tiana-remote/admin/reconnect') {
            return new Response(JSON.stringify({ ok: true, relayConnected: true }), { status: 200 });
          }
          if (url === '/api/tiana-remote/admin/provision') {
            return new Response(JSON.stringify({ ok: true, started: true, step: 'starting' }), { status: 202 });
          }
          if (url === '/api/tiana-remote/admin/provision-status') {
            return new Response(JSON.stringify({ ok: true, running: false, step: 'done', logs: [] }), { status: 200 });
          }
          return new Response('{}', { status: 404 });
        },
        setInterval: () => 1,
        clearInterval: () => {},
        setTimeout: () => 0,
        clearTimeout: () => {},
      };
      sb.globalThis = sb;
      vm.runInNewContext(clientCode, sb);
      const miniReact = {
        createElement(type, props, ...children) {
          return { type, props: props || {}, children: children.flat(Infinity) };
        },
        useState(init) {
          const idx = sc++;
          if (!(idx in states)) states[idx] = typeof init === 'function' ? init() : init;
          return [states[idx], (next) => { states[idx] = typeof next === 'function' ? next(states[idx]) : next; }];
        },
        useRef(init) {
          const idx = rc++;
          if (!(idx in refs)) refs[idx] = { current: init };
          return refs[idx];
        },
        useCallback(fn) { return fn; },
        useEffect(fn, deps) {
          const idx = ec++;
          const prev = effects[idx];
          const changed = !prev || !deps || deps.length !== prev.deps.length || deps.some((d, i) => !Object.is(d, prev.deps[i]));
          if (changed) effects[idx] = { fn, deps, pending: true };
        },
      };
      const mod = sb.__DSH_REMOTE_CLIENT_FACTORY__((id) => (id === 'react' ? miniReact : {}));
      const render = () => { sc = 0; rc = 0; ec = 0; return mod.TianaRemotePanel({ forceMode: 'local' }); };
      const flush = async () => {
        for (const eff of effects) {
          if (eff?.pending) { eff.pending = false; eff.fn(); }
        }
        await new Promise((r) => setTimeout(r, 15));
      };
      return { render, flush, requests };
    }

    // Conflict terminal state UI
    const conflictMount = mountLocal({
      ok: true,
      configured: true,
      enabled: true,
      host: { hostId: 'h1', hostName: 'HostOne' },
      web: { id: 'panelweb0001', endpoint: 'https://panelweb0001.example.test/web/panelweb0001/' },
      e2ee: { fingerprint: '11:22' },
      bridge: { relayConnected: false, hostConflict: true, terminalState: 'conflict_active_host', lastHttpStatus: 409, sessions: [] },
      network: { p2pEnabled: true, stunUrls: [] },
    });
    conflictMount.render();
    await conflictMount.flush();
    let tree = conflictMount.render();
    assert.ok(findById(tree, 'dshr-bridge-conflict-banner'));
    const retryBtn = findById(tree, 'dshr-retry-connect-btn');
    assert.ok(retryBtn, 'conflict banner must expose Retry Connection button');
    assert.ok(findById(tree, 'dshr-force-takeover-btn'), 'conflict banner must expose Force Takeover button');
    await retryBtn.props.onClick();
    assert.ok(conflictMount.requests.some((r) => r.url === '/api/tiana-remote/admin/reconnect' && r.method === 'POST'));

    // Click Force Takeover -> confirm dialog -> sends forceRebind: true
    findById(tree, 'dshr-force-takeover-btn').props.onClick();
    tree = conflictMount.render();
    const dialog = findById(tree, 'dshr-force-takeover-dialog');
    assert.ok(dialog);
    await dialog.props.onClose({ currentTarget: { returnValue: 'confirm' } });
    const provReq = conflictMount.requests.find((r) => r.url === '/api/tiana-remote/admin/provision');
    assert.ok(provReq, 'confirming force takeover dialog must trigger provision');
    assert.equal(provReq.body.forceRebind, true);
    assert.equal(provReq.body.rebind, true);

    // Credentials revoked (403) UI
    const revokedMount = mountLocal({
      ok: true,
      configured: true,
      enabled: true,
      host: { hostId: 'h1', hostName: 'HostOne' },
      web: { id: 'panelweb0001', endpoint: 'https://panelweb0001.example.test/web/panelweb0001/' },
      e2ee: { fingerprint: '11:22' },
      bridge: { relayConnected: false, credentialsRevoked: true, terminalState: 'credentials_revoked', lastHttpStatus: 403, sessions: [] },
      network: { p2pEnabled: true, stunUrls: [] },
    });
    revokedMount.render();
    await revokedMount.flush();
    const rTree = revokedMount.render();
    assert.ok(findById(rTree, 'dshr-credentials-revoked-banner'), 'local view must render credentials_revoked banner');
    assert.ok(findById(rTree, 'dshr-revoked-force-takeover-btn'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('E2E with real relay-go process: strict host mutex, zero kick loop, /host-status probe, and force-rebind 403 terminal eviction', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-e2e-real-relay-'));
  const relayBin = join(dir, 'relay-go-bin');
  const cfgPath = join(dir, 'function-config.json');
  const port = await getFreePort();
  const relayUrl = `http://127.0.0.1:${port}`;
  const webId = 'e2eweb000001';
  const hostId = 'e2e-workstation';
  const regKeyA = generateE2eeSecret();
  const digestA = createHash('sha256').update(regKeyA).digest('hex');

  const writeRelayPolicy = (regKey, hostName) => {
    const digest = createHash('sha256').update(regKey).digest('hex');
    const policy = {
      version: 1,
      hostId,
      hostName,
      hostDigest: digest,
      ownerUserId: 'usr-e2e',
      ownerTenantId: 'ten-e2e',
      webId,
      origin: 'https://e2eweb000001.example.test',
      updatedAt: new Date().toISOString(),
    };
    writeFileSync(cfgPath, JSON.stringify({
      DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(policy) },
    }), { mode: 0o600 });
    return policy;
  };

  let relayProc = null;
  let bridgeA = null;
  let bridgeB = null;

  try {
    execFileSync('go', ['build', '-buildvcs=false', '-o', relayBin, '.'], { cwd: RELAY_GO_DIR, stdio: 'pipe' });
    const policyA = writeRelayPolicy(regKeyA, 'Host-A');

    relayProc = spawn(relayBin, [], {
      env: { ...process.env, PORT: String(port), FUNCTION_CONFIG_FILE: cfgPath },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    // Wait for real relay-go /healthz to become ready
    const deadline = Date.now() + 8_000;
    let ready = false;
    while (Date.now() < deadline) {
      try {
        const res = await fetch(`${relayUrl}/healthz`);
        if (res.ok) {
          const body = await res.json();
          if (body.ok === true && body.paired === true) {
            ready = true;
            break;
          }
        }
      } catch {
        // wait
      }
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(ready, true, 'real relay-go failed to start');

    // Unauthorized /host-status MUST return 403
    const unauthResp = await fetch(`${relayUrl}/host-status`);
    assert.equal(unauthResp.status, 403);

    // Authorized /host-status before host A connects reports hostConnected=false
    const probeBefore = await probeRelayHostStatus(relayUrl, '', {
      existingPolicy: policyA,
      allowInsecureLoopback: true,
    });
    assert.equal(probeBefore.paired, true);
    assert.equal(probeBefore.hostConnected, false);

    // Phase 1: Instance A connects to real relay-go
    const logsA = [];
    bridgeA = new HostBridge({
      relayUrl,
      allowInsecureLoopback: true,
      e2eeSecret: generateE2eeSecret(),
      hostId,
      hostName: 'Host-A',
      registrationKey: regKeyA,
      ownerUserId: 'usr-e2e',
      ownerTenantId: 'ten-e2e',
      webId,
      localOrigin: 'http://127.0.0.1:1',
      reconnectBaseMs: 40,
      reconnectMaxMs: 80,
      log: (m) => logsA.push(m),
    });
    await bridgeA.start();
    assert.equal(bridgeA.getStatusSnapshot().relayConnected, true);

    // /host-status now reports hostConnected=true (without needing regKeyA!)
    const probeOnline = await probeRelayHostStatus(relayUrl, '', {
      existingPolicy: policyA,
      allowInsecureLoopback: true,
    });
    assert.equal(probeOnline.paired, true);
    assert.equal(probeOnline.hostConnected, true);
    assert.equal(probeOnline.hostId, hostId);
    assert.equal(probeOnline.hostName, 'Host-A');

    // Phase 2: Instance B (different instanceId, SAME hostId + regKeyA) tries to connect -> 409 terminal stop, 0 reconnect storm, A stays 0 disconnects!
    const logsB = [];
    bridgeB = new HostBridge({
      relayUrl,
      allowInsecureLoopback: true,
      e2eeSecret: generateE2eeSecret(),
      hostId,
      hostName: 'Host-B',
      registrationKey: regKeyA,
      ownerUserId: 'usr-e2e',
      ownerTenantId: 'ten-e2e',
      webId,
      localOrigin: 'http://127.0.0.1:1',
      reconnectBaseMs: 40,
      reconnectMaxMs: 80,
      log: (m) => logsB.push(m),
    });
    assert.notEqual(bridgeA.instanceId, bridgeB.instanceId);

    await assert.rejects(
      () => bridgeB.start(),
      (err) => err.code === 'HOST_ALREADY_CONNECTED' && err.terminalState === 'conflict_active_host',
    );
    const snapBConflict = bridgeB.getStatusSnapshot();
    assert.equal(snapBConflict.terminalState, 'conflict_active_host');
    assert.equal(snapBConflict.hostConflict, true);
    assert.equal(snapBConflict.lastHttpStatus, 409);
    assert.equal(snapBConflict.running, false);

    // Wait 350ms (~8x reconnectBaseMs) to verify Instance B does 0 reconnect retries and Instance A has 0 disconnects
    await new Promise((r) => setTimeout(r, 350));
    assert.equal(bridgeA.getStatusSnapshot().relayConnected, true, 'Instance A must stay stably connected with 0 disconnects');
    assert.equal(bridgeA.getStatusSnapshot().lastCloseCode, null, 'Instance A must have experienced 0 closes');
    assert.equal(logsA.filter((l) => l.includes('Relay disconnected')).length, 0);
    assert.equal(logsB.filter((l) => l.includes('reconnecting')).length, 0, 'Instance B must never schedule reconnects after 409');

    // Phase 3: Simulate --force-rebind rotating registrationKey -> write new policy -> Instance B connects -> old Instance A gets 1012 then 403 and stops permanently!
    const regKeyB = generateE2eeSecret();
    assert.notEqual(regKeyB, regKeyA);
    assert.notEqual(createHash('sha256').update(regKeyB).digest('hex'), digestA);
    await new Promise((r) => setTimeout(r, 25)); // ensure mtime changes on filesystem
    const policyB = writeRelayPolicy(regKeyB, 'Host-B');

    bridgeB.registrationKey = regKeyB;
    await bridgeB.start();
    assert.equal(bridgeB.getStatusSnapshot().relayConnected, true, 'Instance B must take over cleanly with rotated registrationKey');

    // Wait for Instance A to receive 1012 -> attempt reconnect with old regKeyA -> receive HTTP 403 -> enter terminal credentials_revoked!
    const revokeDeadline = Date.now() + 3_000;
    while (Date.now() < revokeDeadline && bridgeA.getStatusSnapshot().terminalState !== 'credentials_revoked') {
      await new Promise((r) => setTimeout(r, 30));
    }
    const snapARevoked = bridgeA.getStatusSnapshot();
    assert.equal(snapARevoked.terminalState, 'credentials_revoked', `expected Instance A terminalState=credentials_revoked, got ${JSON.stringify(snapARevoked)}`);
    assert.equal(snapARevoked.credentialsRevoked, true);
    assert.equal(snapARevoked.lastHttpStatus, 403);
    assert.equal(snapARevoked.running, false);

    const logCountAfterRevoke = logsA.length;
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(logsA.length, logCountAfterRevoke, 'Instance A must produce 0 further reconnect logs after 403 terminal stop');

    // Instance B stays stably online and /host-status reports Host-B
    assert.equal(bridgeB.getStatusSnapshot().relayConnected, true);
    assert.equal(bridgeB.getStatusSnapshot().lastCloseCode, null);
    const probeAfterTakeover = await probeRelayHostStatus(relayUrl, '', {
      existingPolicy: policyB,
      allowInsecureLoopback: true,
    });
    assert.equal(probeAfterTakeover.hostConnected, true);
    assert.equal(probeAfterTakeover.hostName, 'Host-B');
  } finally {
    bridgeA?.stop();
    bridgeB?.stop();
    if (relayProc && !relayProc.killed) {
      relayProc.kill('SIGTERM');
      await new Promise((r) => setTimeout(r, 100));
      if (!relayProc.killed) relayProc.kill('SIGKILL');
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
