import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import vm from 'node:vm';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  comparePnpmPackageEntriesDesc,
  resolveDshPackageDirs,
} from '../src/dsh-packages.js';
import {
  PLUGIN_ACCESS_MODE_ALLOW_ALL,
  PLUGIN_ACCESS_MODE_DENY_ALL,
  migrateRemoteState,
  claimBridgeOwnership,
  releaseBridgeOwnership,
  writeRuntimeInfo,
  readRuntimeInfo,
  saveRemoteState,
  loadRemoteState,
} from '../src/state.js';
import {
  isProtectedWebPlugin,
  normalizePluginPolicy,
  selectAllowedWebPlugins,
  FrontendAssets,
} from '../src/frontend-assets.js';
import { HostBridge, classifyHttpRoute } from '../src/host-bridge.js';
import { isTcpEndpointReachable } from '../src/connect.js';
import { createHostController } from '../host-main.js';
import { createRemoteApiHandler } from '../src/remote-api.js';
import { encodeHostFrame, MSG_CONTROL_JSON } from '../src/protocol.js';

test('v0.2.7: dsh-packages semver-sorts .pnpm entries desc and prefers active dsh entry tree', () => {
  const unsorted = [
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.1_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.5_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.10_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.1_react@19.0.0',
  ];
  const sorted = [...unsorted].sort((a, b) => comparePnpmPackageEntriesDesc(a, b, '@deepseek-ai+dsh-web-frontend@'));
  assert.deepEqual(sorted, [
    '@deepseek-ai+dsh-web-frontend@0.2.2_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.10_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.5_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.2-rc.1_react@19.0.0',
    '@deepseek-ai+dsh-web-frontend@0.2.1_react@19.0.0',
  ]);

  const root = mkdtempSync(join(tmpdir(), 'dsh-pkg-resolve-'));
  try {
    // Active dsh installation nested dependency (dsh -> dsh-web-app -> dsh-web-frontend@0.2.2-rc.5)
    const activeDshDir = join(root, 'active', 'node_modules', '@deepseek-ai', 'dsh');
    const activeWebAppDir = join(activeDshDir, 'node_modules', '@deepseek-ai', 'dsh-web-app');
    const activeFrontendDir = join(activeWebAppDir, 'node_modules', '@deepseek-ai', 'dsh-web-frontend');
    mkdirSync(join(activeDshDir, 'bin'), { recursive: true });
    mkdirSync(activeFrontendDir, { recursive: true });
    writeFileSync(join(activeDshDir, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh', version: '0.2.2-rc.5' }));
    writeFileSync(join(activeDshDir, 'bin', 'dsh.js'), '// entry');
    writeFileSync(join(activeWebAppDir, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-web-app', version: '0.2.2-rc.5' }));
    writeFileSync(join(activeFrontendDir, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-web-frontend', version: '0.2.2-rc.5' }));

    // Stale rc.1 and newer rc.9 in pnpm store
    const pnpmStore = join(root, 'home', '.local', 'share', 'pnpm', 'global', '5', '.pnpm');
    const stalePnpm = join(pnpmStore, '@deepseek-ai+dsh-web-frontend@0.2.2-rc.1', 'node_modules', '@deepseek-ai', 'dsh-web-frontend');
    const newerPnpm = join(pnpmStore, '@deepseek-ai+dsh-web-frontend@0.2.2-rc.9', 'node_modules', '@deepseek-ai', 'dsh-web-frontend');
    mkdirSync(stalePnpm, { recursive: true });
    mkdirSync(newerPnpm, { recursive: true });
    writeFileSync(join(stalePnpm, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-web-frontend', version: '0.2.2-rc.1' }));
    writeFileSync(join(newerPnpm, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-web-frontend', version: '0.2.2-rc.9' }));

    // When activeEntry points to activeDshDir, activeFrontendDir MUST come first
    const dirsFromArgv = [...resolveDshPackageDirs('@deepseek-ai/dsh-web-frontend', {
      activeEntry: join(activeDshDir, 'bin', 'dsh.js'),
      home: join(root, 'home'),
      stores: [pnpmStore],
    })];
    assert.equal(dirsFromArgv[0], realpathSync(activeFrontendDir));

    // Without activeEntry, .pnpm fallback MUST pick rc.9 before rc.1
    const dirsFallback = [...resolveDshPackageDirs('@deepseek-ai/dsh-web-frontend', {
      activeEntry: '',
      home: join(root, 'home'),
      stores: [pnpmStore],
    })];
    const idx9 = dirsFallback.indexOf(realpathSync(newerPnpm));
    const idx1 = dirsFallback.indexOf(realpathSync(stalePnpm));
    assert.ok(idx9 >= 0 && idx1 >= 0 && idx9 < idx1, 'semver fallback must rank rc.9 ahead of rc.1');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('v0.2.7: state.js bridge ownership lock, runtime.json live-PID protection, and pluginAccessMode migration', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-state-v027-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  try {
    // Migration defaults to allow_all while preserving saved allowedWebPlugins
    const migrated = migrateRemoteState({
      version: 2,
      security: { allowedWebPlugins: ['dshmarket'] },
    });
    assert.equal(migrated.security.pluginAccessMode, PLUGIN_ACCESS_MODE_ALLOW_ALL);
    assert.deepEqual(migrated.security.blockedWebPlugins, []);
    assert.deepEqual(migrated.security.allowedWebPlugins, ['dshmarket']);

    const denyMigrated = migrateRemoteState({
      version: 2,
      security: {
        pluginAccessMode: PLUGIN_ACCESS_MODE_DENY_ALL,
        blockedWebPlugins: ['ds-bot'],
        allowedWebPlugins: ['dshmarket'],
      },
    });
    assert.equal(denyMigrated.security.pluginAccessMode, PLUGIN_ACCESS_MODE_DENY_ALL);
    assert.deepEqual(denyMigrated.security.blockedWebPlugins, ['ds-bot']);
    assert.deepEqual(denyMigrated.security.allowedWebPlugins, ['dshmarket']);

    // Bridge ownership lock: acquire -> block second instance -> reclaim dead PID -> release
    const first = await claimBridgeOwnership({
      instanceId: 'inst-A',
      hostId: 'host-demo',
      origin: 'https://100.64.0.10:3080',
      advertisedOrigin: 'https://workstation.example.test:3080',
    }, statePath, { pid: process.pid });
    assert.equal(first.acquired, true);

    const second = await claimBridgeOwnership({
      instanceId: 'inst-B',
      hostId: 'host-demo',
      origin: 'http://127.0.0.1:3080',
    }, statePath, { pid: process.pid });
    assert.equal(second.acquired, false);
    assert.equal(second.owner.instanceId, 'inst-A');
    assert.equal(second.owner.advertisedOrigin, 'https://workstation.example.test:3080');

    // Non-owner release must not drop inst-A's lock
    assert.equal(await releaseBridgeOwnership('inst-B', statePath), false);
    const stillBlocked = await claimBridgeOwnership({ instanceId: 'inst-C' }, statePath, { pid: process.pid });
    assert.equal(stillBlocked.acquired, false);

    // Owner release allows inst-B to claim (simulated dead PID 99999999)
    assert.equal(await releaseBridgeOwnership('inst-A', statePath), true);
    const reclaimed = await claimBridgeOwnership({
      instanceId: 'inst-B',
      hostId: 'host-demo',
    }, statePath, { pid: 99999999 });
    assert.equal(reclaimed.acquired, true);

    // Dead PID lock is automatically reclaimed by a live instance
    const afterDead = await claimBridgeOwnership({
      instanceId: 'inst-C',
      hostId: 'host-demo',
    }, statePath, { pid: process.pid });
    assert.equal(afterDead.acquired, true);
    await releaseBridgeOwnership('inst-C', statePath);

    // writeRuntimeInfo protects another live PID's runtime.json unless overwriteLiveOther is true
    const otherLivePid = process.ppid && process.ppid !== process.pid ? process.ppid : null;
    if (otherLivePid) {
      writeFileSync(runtimePath, JSON.stringify({
        pid: otherLivePid,
        origin: 'https://100.64.0.10:3080',
        advertisedOrigin: 'https://workstation.example.test:3080',
      }));
      const res = writeRuntimeInfo({ pid: process.pid, origin: 'http://127.0.0.1:3080' }, runtimePath);
      assert.equal(res, false);
      assert.equal(readRuntimeInfo(runtimePath).pid, otherLivePid);

      const forced = writeRuntimeInfo({ pid: process.pid, origin: 'http://127.0.0.1:3080' }, runtimePath, { overwriteLiveOther: true });
      assert.equal(forced, true);
      assert.equal(readRuntimeInfo(runtimePath).pid, process.pid);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('v0.2.7: frontend-assets dual plugin policy (allow_all+blacklist, deny_all+whitelist, core protection, legacy compat)', () => {
  const ids = [
    '@deepseek-ai/dsh-workspace',
    '@deepseek-ai/dsh-client-modules',
    '@tianacloud/dsh-remote',
    'dshmarket',
    'ds-bot',
    'dsh-codex-connect',
    '@tianacloud/dsh-tiana',
  ];
  const modules = new Map(ids.map((id) => [id, { id }]));

  // Protected modules
  assert.equal(isProtectedWebPlugin('@deepseek-ai/dsh-workspace'), true);
  assert.equal(isProtectedWebPlugin('@tianacloud/dsh-remote'), true);
  assert.equal(isProtectedWebPlugin('dshmarket'), false);

  // Default policy (undefined) -> allow_all -> every plugin included
  const def = selectAllowedWebPlugins(modules);
  assert.deepEqual([...def].sort(), [...ids].sort());

  // allow_all + blacklist (cannot block core/self even if specified)
  const blacklisted = selectAllowedWebPlugins(modules, {
    mode: 'allow_all',
    blockedWebPlugins: ['dshmarket', '@deepseek-ai/dsh-workspace', '@tianacloud/dsh-remote'],
    allowedWebPlugins: ['ds-bot'],
  });
  assert.deepEqual([...blacklisted].sort(), [
    '@deepseek-ai/dsh-workspace',
    '@deepseek-ai/dsh-client-modules',
    '@tianacloud/dsh-remote',
    'ds-bot',
    'dsh-codex-connect',
    '@tianacloud/dsh-tiana',
  ].sort());

  // deny_all + whitelist
  const whitelisted = selectAllowedWebPlugins(modules, {
    mode: 'deny_all',
    blockedWebPlugins: ['dshmarket'],
    allowedWebPlugins: ['dshmarket', 'dsh-codex-connect'],
  });
  assert.deepEqual([...whitelisted].sort(), [
    '@deepseek-ai/dsh-workspace',
    '@deepseek-ai/dsh-client-modules',
    '@tianacloud/dsh-remote',
    'dshmarket',
    'dsh-codex-connect',
  ].sort());

  // Legacy compat: [] -> deny_all, ['ds-bot'] -> deny_all+ds-bot, '*' -> allow_all
  assert.equal(normalizePluginPolicy([]).mode, 'deny_all');
  assert.deepEqual([...selectAllowedWebPlugins(modules, [])].sort(), [
    '@deepseek-ai/dsh-workspace',
    '@deepseek-ai/dsh-client-modules',
    '@tianacloud/dsh-remote',
  ].sort());
  assert.deepEqual([...selectAllowedWebPlugins(modules, ['ds-bot'])].sort(), [
    '@deepseek-ai/dsh-workspace',
    '@deepseek-ai/dsh-client-modules',
    '@tianacloud/dsh-remote',
    'ds-bot',
  ].sort());
  assert.equal(normalizePluginPolicy('*').mode, 'allow_all');
  assert.deepEqual([...selectAllowedWebPlugins(modules, '*')].sort(), [...ids].sort());

  // FrontendAssets defaults to allow_all and updates policy via setPluginPolicy
  const fa = new FrontendAssets();
  assert.equal(fa.getPluginPolicy().mode, 'allow_all');
  fa.setPluginPolicy({ mode: 'deny_all', allowedWebPlugins: ['dshmarket'], blockedWebPlugins: ['ds-bot'] });
  assert.deepEqual(fa.getPluginPolicy(), {
    mode: 'deny_all',
    blockedWebPlugins: ['ds-bot'],
    allowedWebPlugins: ['dshmarket'],
  });
});

test('v0.2.7: classifyHttpRoute forwards third-party plugin HTTP APIs and /api/tiana-remote/plugin-access while blocking plugin static bundles & admin APIs', () => {
  // Plugin API routes must be forwarded
  assert.equal(classifyHttpRoute('/plugins/dsh-codex-connect/task')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/plugins/dsh-openai-codex/auth/status')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/plugins/@tianacloud/dsh-tiana/projects')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/api/tiana-remote/plugin-access')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/api/tiana-remote/public-status')?.kind, 'forward');

  // Plugin bundle / asset / event routes MUST remain blocked (null -> 404)
  assert.equal(classifyHttpRoute('/plugins'), null);
  assert.equal(classifyHttpRoute('/plugins/'), null);
  assert.equal(classifyHttpRoute('/plugins/events'), null);
  assert.equal(classifyHttpRoute('/plugins/??foo'), null);
  assert.equal(classifyHttpRoute('/plugins/dshmarket'), null);
  assert.equal(classifyHttpRoute('/plugins/dshmarket/client.js'), null);
  assert.equal(classifyHttpRoute('/plugins/dshmarket/client.abc123.js.map'), null);
  assert.equal(classifyHttpRoute('/plugins/dshmarket/assets/logo.png'), null);
  assert.equal(classifyHttpRoute('/plugins/@tianacloud/dsh-tiana'), null);
  assert.equal(classifyHttpRoute('/plugins/@tianacloud/dsh-tiana/client.js'), null);
  assert.equal(classifyHttpRoute('/plugins/@tianacloud/dsh-tiana/assets/icon.svg'), null);

  // Admin APIs MUST remain strictly forbidden
  assert.equal(classifyHttpRoute('/api/tiana-remote/admin/overview')?.kind, 'forbidden');
  assert.equal(classifyHttpRoute('/api/tiana-remote/admin/pairing-key/reveal')?.kind, 'forbidden');
});

test('v0.2.7: HostBridge conflict detection keeps backoff active on immediate kick and resets only after stability window', async () => {
  const sendWsFrame = (socket, opcode, payloadBuf) => {
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
  };

  let connectCount = 0;
  const connectTimes = [];
  const sockets = new Set();
  const server = http.createServer((_req, res) => {
    res.statusCode = 426;
    res.end();
  });
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    const accept = createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    connectCount += 1;
    const myCount = connectCount;
    connectTimes.push(Date.now());
    const frame = encodeHostFrame(0, 0, MSG_CONTROL_JSON, JSON.stringify({
      type: 'host_registered',
      hostId: 'host-demo-test',
      version: 2,
    }));
    sendWsFrame(socket, 0x02, Buffer.from(frame));
    if (myCount <= 2) {
      setTimeout(() => {
        const reasonBuf = Buffer.from('replaced by newer host connection', 'utf8');
        const closePayload = Buffer.alloc(2 + reasonBuf.length);
        closePayload.writeUInt16BE(1000, 0);
        reasonBuf.copy(closePayload, 2);
        sendWsFrame(socket, 0x08, closePayload);
        socket.end();
      }, 25);
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  let bridge = null;
  try {
    const logs = [];
    bridge = new HostBridge({
      relayUrl: `http://127.0.0.1:${port}`,
      allowInsecureLoopback: true,
      relayToken: 'tok-test',
      e2eeSecret: 'dshk1_testsecret',
      hostId: 'host-demo-test',
      hostName: 'TestHost',
      registrationKey: 'reg-1',
      ownerUserId: 'user-1',
      ownerTenantId: 'tenant-1',
      webId: 'web123456789',
      localOrigin: 'http://127.0.0.1:1',
      reconnectBaseMs: 40,
      reconnectMaxMs: 600,
      stableConnectionMs: 180,
      conflictMinBackoffMs: 220,
      log: (m) => logs.push(m),
    });

    await bridge.start();
    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 3000;
      const timer = setInterval(() => {
        if (connectCount >= 2) {
          clearInterval(timer);
          resolve();
        } else if (Date.now() > deadline) {
          clearInterval(timer);
          reject(new Error(`Timed out waiting for reconnect #2 (got ${connectCount})`));
        }
      }, 20);
    });

    const gap12 = connectTimes[1] - connectTimes[0];
    assert.ok(gap12 >= 180, `conflict reconnect gap must respect conflictMinBackoffMs, got ${gap12}ms`);
    const snapDuringConflict = bridge.getStatusSnapshot();
    assert.equal(snapDuringConflict.hostConflict, true);
    assert.equal(snapDuringConflict.lastCloseCode, 1000);
    assert.match(snapDuringConflict.lastCloseReason, /replaced by newer host connection/i);
    assert.ok(logs.some((l) => l.includes('Another DSH host process appears to be connected')));

    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 3000;
      const timer = setInterval(() => {
        const snap = bridge.getStatusSnapshot();
        if (connectCount >= 3 && snap.relayConnected && !snap.hostConflict) {
          clearInterval(timer);
          resolve();
        } else if (Date.now() > deadline) {
          clearInterval(timer);
          reject(new Error(`Timed out waiting for stable recovery (count=${connectCount}, snap=${JSON.stringify(snap)})`));
        }
      }, 20);
    });
    assert.equal(bridge.getStatusSnapshot().hostConflict, false);
  } finally {
    bridge?.stop();
    for (const s of sockets) s.destroy();
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});

test('v0.2.7: isTcpEndpointReachable detects live HTTPS/TCP listener even without valid TLS cert', async () => {
  const srv = net.createServer((sock) => sock.end());
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  try {
    assert.equal(await isTcpEndpointReachable(`https://127.0.0.1:${port}`, { timeoutMs: 500 }), true);
  } finally {
    await new Promise((r) => srv.close(r));
  }
  assert.equal(await isTcpEndpointReachable(`https://127.0.0.1:${port}`, { timeoutMs: 300 }), false);
});

test('v0.2.7: /api/tiana-remote/plugin-access works locally and over tunnel, updates HostBridge, and host-main surfaces bridgeConflict', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-api-v027-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  try {
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'host-1', hostName: 'Host One', registrationKey: 'reg' },
      owner: { userId: 'u1', tenantId: 't1', email: 'u@example.com' },
      web: { id: 'web123456789', name: 'DSH Remote', endpoint: 'https://web123456789.example.test/web/web123456789/' },
      function: { id: 'fn-1', name: 'fn', url: 'https://fn.example.test', token: 'tok', expiresAt: Math.floor(Date.now() / 1000) + 30 * 86400 },
      e2ee: { secret: 'dshk1_abc', fingerprint: '11:22:33', algorithm: 'AES-256-GCM' },
      network: { p2pEnabled: true, stunUrls: [] },
      security: { pluginAccessMode: 'allow_all', blockedWebPlugins: [], allowedWebPlugins: [] },
    }, statePath);

    const appliedPolicies = [];
    const fakeBridge = {
      registered: true,
      e2eeSecret: 'dshk1_abc',
      start() {},
      stop() {},
      updateSettings(s) {
        if (s.pluginPolicy) appliedPolicies.push(s.pluginPolicy);
      },
      getStatusSnapshot() {
        return { running: true, relayConnected: true, hostConflict: false, sessions: [] };
      },
    };
    const fakeWebServer = {
      getOrigin: () => 'http://127.0.0.1:3080',
      async collectIndexInjections() {
        return [{
          kind: 'global',
          name: '__DSH_BOOT__',
          value: {
            entries: [
              { id: '@deepseek-ai/dsh-workspace' },
              { id: '@tianacloud/dsh-remote' },
              { id: 'dshmarket' },
              { id: 'ds-bot' },
              { id: 'dsh-codex-connect' },
            ],
          },
        }];
      },
    };
    const fakeConnection = {
      browserPeer: {},
      authenticatedUrl: (u) => u,
      requestRejection: () => null,
    };

    const controller = createHostController({
      statePath,
      runtimePath,
      disableBridgeLock: true,
      createBridge: () => fakeBridge,
      getWebServer: () => fakeWebServer,
      getConnection: () => fakeConnection,
      log: () => {},
    });
    await controller.boot();

    const handler = createRemoteApiHandler(controller, fakeConnection);
    try {
      // 1. Remote tunnel GET /api/tiana-remote/plugin-access succeeds
      const getTunnel = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/plugin-access', {
          headers: { 'x-dsh-remote-tunnel': '1' },
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: true },
      );
      assert.equal(getTunnel.status, 200);
      const initial = await getTunnel.json();
      assert.equal(initial.mode, 'allow_all');
      assert.deepEqual(initial.installedWebPlugins, ['dshmarket', 'ds-bot', 'dsh-codex-connect']);
      assert.deepEqual(initial.effectiveAllowedPlugins, ['dshmarket', 'ds-bot', 'dsh-codex-connect']);

      // 2. Remote tunnel POST /api/tiana-remote/plugin-access switches to blacklist and updates bridge
      const postTunnel = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/plugin-access', {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-dsh-remote-tunnel': '1' },
          body: JSON.stringify({ mode: 'allow_all', blockedWebPlugins: ['ds-bot', '@tianacloud/dsh-remote'] }),
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: true },
      );
      assert.equal(postTunnel.status, 200);
      const afterBlacklist = await postTunnel.json();
      assert.equal(afterBlacklist.mode, 'allow_all');
      assert.deepEqual(afterBlacklist.blockedWebPlugins, ['ds-bot']);
      assert.deepEqual(afterBlacklist.effectiveAllowedPlugins, ['dshmarket', 'dsh-codex-connect']);
      assert.deepEqual(appliedPolicies.at(-1), {
        mode: 'allow_all',
        blockedWebPlugins: ['ds-bot'],
        allowedWebPlugins: [],
      });

      // 3. Local POST switches to deny_all + whitelist
      const postLocal = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/plugin-access', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ mode: 'deny_all', allowedWebPlugins: ['dshmarket'] }),
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false },
      );
      assert.equal(postLocal.status, 200);
      const afterWhitelist = await postLocal.json();
      assert.equal(afterWhitelist.mode, 'deny_all');
      assert.deepEqual(afterWhitelist.allowedWebPlugins, ['dshmarket']);
      assert.deepEqual(afterWhitelist.effectiveAllowedPlugins, ['dshmarket']);
      assert.equal(loadRemoteState(statePath).security.pluginAccessMode, 'deny_all');

      // 4. Admin API MUST still return 403 over tunnel
      const adminOverTunnel = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/admin/overview', {
          headers: { 'x-dsh-remote-tunnel': '1' },
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: true },
      );
      assert.equal(adminOverTunnel.status, 403);
    } finally {
      controller.dispose();
    }

    // 5. Bridge lock conflict skips bridge startup and surfaces bridgeConflict in admin overview
    const existingClaim = await claimBridgeOwnership({
      instanceId: 'other-proc',
      hostId: 'host-1',
      origin: 'https://100.64.0.10:3080',
      advertisedOrigin: 'https://workstation.example.test:3080',
    }, statePath, { pid: process.pid });
    assert.equal(existingClaim.acquired, true);

    let bridgeStarted = false;
    const conflictingCtrl = createHostController({
      statePath,
      runtimePath,
      bridgeConflictRetryMs: 60_000,
      createBridge: () => {
        bridgeStarted = true;
        return fakeBridge;
      },
      getWebServer: () => fakeWebServer,
      getConnection: () => fakeConnection,
      log: () => {},
    });
    await conflictingCtrl.boot();
    try {
      assert.equal(bridgeStarted, false, 'duplicate process must not start HostBridge while lock is held');
      const overview = await conflictingCtrl.getAdminOverview();
      assert.ok(overview.bridgeConflict, 'admin overview must surface bridgeConflict');
      assert.equal(overview.bridgeConflict.ownerPid, process.pid);
      assert.equal(overview.bridgeConflict.ownerOrigin, 'https://workstation.example.test:3080');
    } finally {
      conflictingCtrl.dispose();
      await releaseBridgeOwnership('other-proc', statePath);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('v0.2.7: client.js renders dual-mode plugin policy card in BOTH remote and local views plus local bridgeConflict banner', async () => {
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
  const findByProp = (node, key, val) => {
    if (!node || typeof node !== 'object') return null;
    if (node.props?.[key] === val) return node;
    for (const child of node.children || []) {
      const hit = findByProp(child, key, val);
      if (hit) return hit;
    }
    return null;
  };
  const collectText = (node) => {
    if (node === null || node === undefined || typeof node === 'boolean') return '';
    if (typeof node === 'string' || typeof node === 'number') return String(node);
    return (node.children || []).map(collectText).join(' ');
  };

  function mountPanel(forceMode, fetchHandler) {
    const states = [];
    const refs = [];
    const effects = [];
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
      fetch: (url, opts) => fetchHandler(url, opts),
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
    const render = () => { sc = 0; rc = 0; ec = 0; return mod.TianaRemotePanel({ forceMode }); };
    const flush = async () => {
      for (const eff of effects) {
        if (eff?.pending) { eff.pending = false; eff.fn(); }
      }
      await new Promise((r) => setTimeout(r, 15));
    };
    return { render, flush };
  }

  // 1. Remote mode: fetches /api/tiana-remote/plugin-access, toggles to deny_all + whitelist, saves, shows reload banner
  const remotePosts = [];
  const remoteMount = mountPanel('remote', async (url, opts) => {
    if (url === '/api/tiana-remote/public-status') {
      return new Response(JSON.stringify({ hostName: 'HostDemo', e2eeFingerprint: 'aa:bb' }), { status: 200 });
    }
    if (url === '/api/tiana-remote/plugin-access' && (!opts?.method || opts.method === 'GET')) {
      return new Response(JSON.stringify({
        ok: true,
        mode: 'allow_all',
        blockedWebPlugins: [],
        allowedWebPlugins: [],
        installedWebPlugins: ['dshmarket', 'ds-bot'],
        envOverride: false,
      }), { status: 200 });
    }
    if (url === '/api/tiana-remote/plugin-access' && opts?.method === 'POST') {
      const body = JSON.parse(opts.body);
      remotePosts.push(body);
      return new Response(JSON.stringify({
        ok: true,
        ...body,
        installedWebPlugins: ['dshmarket', 'ds-bot'],
        envOverride: false,
      }), { status: 200 });
    }
    return new Response('{}', { status: 404 });
  });

  remoteMount.render();
  await remoteMount.flush();
  let rTree = remoteMount.render();
  assert.ok(findById(rTree, 'dshr-plugin-access-card'), 'remote view must render plugin access card');
  assert.equal(findById(rTree, 'dshr-plugin-mode-allow-all').props['aria-selected'], 'true');

  findById(rTree, 'dshr-plugin-mode-deny-all').props.onClick();
  rTree = remoteMount.render();
  assert.equal(findById(rTree, 'dshr-plugin-mode-deny-all').props['aria-selected'], 'true');
  findByProp(rTree, 'data-plugin-pkg', 'dshmarket').props.onChange({ target: { checked: true } });
  rTree = remoteMount.render();

  const formNode = findById(rTree, 'dshr-plugin-access-card').children[0];
  await formNode.props.onSubmit({ preventDefault() {} });
  rTree = remoteMount.render();
  assert.equal(remotePosts.length, 1);
  assert.equal(remotePosts[0].mode, 'deny_all');
  assert.deepEqual(remotePosts[0].allowedWebPlugins, ['dshmarket']);
  assert.ok(findById(rTree, 'dshr-remote-reload-banner'), 'remote save must show reload workbench banner');
  assert.ok(findById(rTree, 'dshr-remote-reload-workbench'), 'remote save must offer reload button');

  // 2. Local mode: renders bridgeConflict banner AND plugin access card
  const localMount = mountPanel('local', async () => new Response(JSON.stringify({
    ok: true,
    configured: true,
    enabled: true,
    host: { hostId: 'host-demo', hostName: 'HostDemo' },
    web: { id: 'web123456789', endpoint: 'https://web123456789.example.test/web/web123456789/' },
    e2ee: { fingerprint: '11:22' },
    bridge: { relayConnected: false, hostConflict: true, sessions: [] },
    bridgeConflict: { ownerPid: 2495419, ownerOrigin: 'https://workstation.example.test:3080' },
    network: { p2pEnabled: true, stunUrls: [] },
    pluginAccess: {
      ok: true,
      mode: 'allow_all',
      blockedWebPlugins: ['ds-bot'],
      allowedWebPlugins: [],
      installedWebPlugins: ['dshmarket', 'ds-bot'],
      envOverride: false,
    },
  }), { status: 200 }));

  localMount.render();
  await localMount.flush();
  const lTree = localMount.render();
  const conflictBanner = findById(lTree, 'dshr-bridge-conflict-banner');
  assert.ok(conflictBanner, 'local view must render bridgeConflict alert banner');
  assert.ok(collectText(conflictBanner).includes('2495419'));
  assert.ok(findById(lTree, 'dshr-plugin-access-card'), 'local view must render plugin access card');
  assert.equal(findByProp(lTree, 'data-plugin-pkg', 'ds-bot').props.checked, true, 'blacklisted plugin checkbox must be checked in allow_all mode');
  assert.equal(findByProp(lTree, 'data-plugin-pkg', 'dshmarket').props.checked, false, 'allowed plugin checkbox must be unchecked in allow_all mode');
});
