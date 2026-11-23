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
  migrateRemoteState,
  claimBridgeOwnership,
  releaseBridgeOwnership,
  writeRuntimeInfo,
  readRuntimeInfo,
  saveRemoteState,
  loadRemoteState,
} from '../src/state.js';
import { FrontendAssets } from '../src/frontend-assets.js';
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

test('v0.2.7: state.js bridge ownership lock, runtime.json live-PID protection, and legacy plugin-policy field stripping', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-state-v027-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  try {
    // Legacy state with deprecated plugin-filter keys migrates cleanly without failing and strips deprecated fields
    const migrated = migrateRemoteState({
      version: 2,
      host: { hostId: 'host-demo', hostName: 'Demo', registrationKey: 'reg-demo' },
      pluginPolicy: { mode: 'deny_all', allowedWebPlugins: ['dshmarket'] },
      allowedWebPlugins: ['dshmarket'],
      blockedWebPlugins: ['ds-bot'],
      security: {
        pluginAccessMode: 'deny_all',
        blockedWebPlugins: ['ds-bot'],
        allowedWebPlugins: ['dshmarket'],
      },
    });
    assert.equal(migrated.host.registrationKey, 'reg-demo');
    assert.equal('pluginPolicy' in migrated, false);
    assert.equal('allowedWebPlugins' in migrated, false);
    assert.equal('blockedWebPlugins' in migrated, false);
    assert.equal('security' in migrated, false);

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
      saveRemoteState({
        pid: otherLivePid,
        origin: 'https://100.64.0.10:3080',
        advertisedOrigin: 'https://workstation.example.test:3080',
      }, runtimePath);
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

test('frontend-assets and HostBridge unconditionally allow all active third-party plugins regardless of DSH_REMOTE_WEB_PLUGINS', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-fa-all-plugins-'));
  const prevEnv = process.env.DSH_REMOTE_WEB_PLUGINS;
  try {
    process.env.DSH_REMOTE_WEB_PLUGINS = 'none';
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

    const makePkg = (id) => {
      const pkgDir = join(dir, 'pkgs', id.replace('/', '__'));
      mkdirSync(pkgDir, { recursive: true });
      writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: id, exports: { './client': './client.js' } }));
      const clientPath = join(pkgDir, 'client.js');
      writeFileSync(clientPath, `window.__ModuleLoader__.load({id:${JSON.stringify(id)},factory(){return {};}});`);
      return clientPath;
    };

    const ids = [
      '@deepseek-ai/dsh-workspace',
      '@deepseek-ai/dsh-client-modules',
      '@tianacloud/dsh-remote',
      'dshmarket',
      'ds-bot',
      'dsh-codex-connect',
      '@tianacloud/dsh-tiana',
    ];
    const clientPaths = new Map(ids.map((id) => [id, makePkg(id)]));
    const bootRows = [{
      kind: 'global',
      name: '__DSH_BOOT__',
      value: {
        entries: ids.map((id, i) => ({
          id,
          url: `plugins/??${id}/client.js&rev=r${i}`,
          rev: `r${i}`,
        })),
        batches: [],
      },
    }];

    const bridge = new HostBridge({
      relayUrl: 'https://relay.example.test',
      e2eeSecret: 'dshk1_testsecret',
      hostId: 'host-demo',
      hostName: 'HostDemo',
      registrationKey: 'reg-1',
      ownerUserId: 'u1',
      ownerTenantId: 't1',
      webId: 'web123456789',
      localOrigin: 'http://127.0.0.1:3080',
      frontendOptions: { frontend: frontendDir },
      activeClientPath: (id) => clientPaths.get(id),
      log: () => {},
    });

    const snapshot = await bridge.frontend.prepare(bootRows);
    assert.deepEqual(snapshot.manifest.boot.entries.map((e) => e.id).sort(), [...ids].sort());
    for (const id of ids) {
      assert.ok(snapshot.resources.has(`plugin:${id}/client.js`), `expected active plugin ${id} in manifest resources`);
    }
    // Removed plugin policy APIs must no longer exist on FrontendAssets
    const fa = new FrontendAssets({ frontend: frontendDir });
    assert.equal('setPluginPolicy' in fa, false);
    assert.equal('getPluginPolicy' in fa, false);
    assert.equal('setAllowlist' in fa, false);
  } finally {
    if (prevEnv === undefined) delete process.env.DSH_REMOTE_WEB_PLUGINS;
    else process.env.DSH_REMOTE_WEB_PLUGINS = prevEnv;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('v0.2.7: classifyHttpRoute forwards third-party plugin HTTP APIs while blocking plugin static bundles & admin APIs', () => {
  // Plugin API routes must be forwarded
  assert.equal(classifyHttpRoute('/plugins/dsh-codex-connect/task')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/plugins/dsh-openai-codex/auth/status')?.kind, 'forward');
  assert.equal(classifyHttpRoute('/plugins/@tianacloud/dsh-tiana/projects')?.kind, 'forward');
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

test('plugin-access endpoint is removed, legacy state.json boots cleanly and drops deprecated keys on save, admin stays 403 over tunnel, and host-main surfaces bridgeConflict', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-api-v027-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  const prevEnv = process.env.DSH_REMOTE_WEB_PLUGINS;
  try {
    process.env.DSH_REMOTE_WEB_PLUGINS = 'ds-bot';
    // Seed a legacy state.json containing deprecated pluginPolicy / allowedWebPlugins / blockedWebPlugins keys
    writeFileSync(statePath, `${JSON.stringify({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'host-1', hostName: 'Host One', registrationKey: 'reg-legacy-key' },
      owner: { userId: 'u1', tenantId: 't1', email: 'u@example.test' },
      web: { id: 'web123456789', name: 'DSH Remote', endpoint: 'https://web123456789.example.test/web/web123456789/' },
      function: { id: 'fn-1', name: 'fn', url: 'https://fn.example.test', token: 'tok', expiresAt: Math.floor(Date.now() / 1000) + 30 * 86400 },
      e2ee: { secret: 'dshk1_abc', fingerprint: '11:22:33', algorithm: 'AES-256-GCM' },
      network: { p2pEnabled: true, stunUrls: ['stun:stun.cloudflare.com:3478'] },
      pluginPolicy: { mode: 'deny_all', allowedWebPlugins: ['dshmarket'] },
      allowedWebPlugins: ['dshmarket'],
      blockedWebPlugins: ['ds-bot'],
      security: { pluginAccessMode: 'deny_all', blockedWebPlugins: ['ds-bot'], allowedWebPlugins: ['dshmarket'] },
    }, null, 2)}\n`, { mode: 0o600 });

    const bridgeConfigs = [];
    const appliedSettings = [];
    const fakeBridge = {
      registered: true,
      e2eeSecret: 'dshk1_abc',
      start() {},
      stop() {},
      updateSettings(s) {
        appliedSettings.push(s);
      },
      getStatusSnapshot() {
        return { running: true, relayConnected: true, hostConflict: false, sessions: [] };
      },
    };
    const fakeWebServer = {
      getOrigin: () => 'http://127.0.0.1:3080',
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
      createBridge: (cfg) => {
        bridgeConfigs.push(cfg);
        return fakeBridge;
      },
      getWebServer: () => fakeWebServer,
      getConnection: () => fakeConnection,
      log: () => {},
    });
    await controller.boot();

    const handler = createRemoteApiHandler(controller, fakeConnection);
    try {
      // 1. Legacy state booted cleanly with existing bindings intact and no frontendOptions.pluginPolicy
      assert.equal(bridgeConfigs.length, 1);
      assert.equal(bridgeConfigs[0].registrationKey, 'reg-legacy-key');
      assert.equal(bridgeConfigs[0].relayUrl, 'https://fn.example.test');
      assert.equal(bridgeConfigs[0].webId, 'web123456789');
      assert.equal(bridgeConfigs[0].frontendOptions, undefined);

      // 2. Removed /api/tiana-remote/plugin-access returns null (unhandled -> 404)
      const getRemoved = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/plugin-access', {
          headers: { 'x-dsh-remote-tunnel': '1' },
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: true },
      );
      assert.equal(getRemoved, null);

      const postRemoved = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/plugin-access', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ mode: 'deny_all', allowedWebPlugins: ['dshmarket'] }),
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false },
      );
      assert.equal(postRemoved, null);

      // 3. Admin overview omits pluginAccess / allowedWebPlugins / security and ignores DSH_REMOTE_WEB_PLUGINS
      const localOverviewResp = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/admin/overview'),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false },
      );
      assert.equal(localOverviewResp.status, 200);
      const localOverview = await localOverviewResp.json();
      assert.equal('pluginAccess' in localOverview, false);
      assert.equal('allowedWebPlugins' in localOverview, false);
      assert.equal('installedWebPlugins' in localOverview, false);
      assert.equal('security' in localOverview, false);
      assert.equal('allowedWebPlugins' in localOverview.envOverrides, false);

      // 4. Updating admin settings saves clean state.json omitting deprecated plugin-filter fields while preserving bindings
      const settingsResp = await handler(
        new Request('http://127.0.0.1:3080/api/tiana-remote/admin/settings', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            p2pEnabled: false,
            pluginAccessMode: 'deny_all',
            allowedWebPlugins: ['dshmarket'],
            blockedWebPlugins: ['ds-bot'],
          }),
        }),
        { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false },
      );
      assert.equal(settingsResp.status, 200);
      const settingsJson = await settingsResp.json();
      assert.equal(settingsJson.network.p2pEnabled, false);
      assert.equal('security' in settingsJson, false);
      assert.equal('pluginPolicy' in (appliedSettings.at(-1) || {}), false);

      const persisted = loadRemoteState(statePath);
      assert.equal(persisted.host.registrationKey, 'reg-legacy-key');
      assert.equal(persisted.function.url, 'https://fn.example.test');
      assert.equal(persisted.web.endpoint, 'https://web123456789.example.test/web/web123456789/');
      assert.equal(persisted.network.p2pEnabled, false);
      assert.equal('pluginPolicy' in persisted, false);
      assert.equal('pluginAccessMode' in persisted, false);
      assert.equal('allowedWebPlugins' in persisted, false);
      assert.equal('blockedWebPlugins' in persisted, false);
      assert.equal('security' in persisted, false);

      // 5. Admin API MUST still return 403 over tunnel
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

    // 6. Bridge lock conflict skips bridge startup and surfaces bridgeConflict in admin overview
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
    if (prevEnv === undefined) delete process.env.DSH_REMOTE_WEB_PLUGINS;
    else process.env.DSH_REMOTE_WEB_PLUGINS = prevEnv;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('client.js omits plugin access policy UI in both remote and local views while keeping local bridgeConflict banner', async () => {
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
  const collectText = (node) => {
    if (node === null || node === undefined || typeof node === 'boolean') return '';
    if (typeof node === 'string' || typeof node === 'number') return String(node);
    return (node.children || []).map(collectText).join(' ');
  };

  function mountPanel(forceMode, fetchHandler, { language = 'zh-CN', shell = null } = {}) {
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
      navigator: { language },
      fetch: (url, opts) => fetchHandler(url, opts),
      setInterval: () => 1,
      clearInterval: () => {},
      setTimeout: () => 0,
      clearTimeout: () => {},
      ...(shell ? { __DSH_REMOTE_SHELL__: shell } : {}),
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

  // 1. Remote mode (zh-CN): fetches ONLY /api/tiana-remote/public-status, renders NO plugin policy card,
  //    renders descriptive action rows for cache reload & device unbind, and invokes shell callbacks
  const remoteFetchedUrls = [];
  let clearCacheClicks = 0;
  let lockForgetClicks = 0;
  const remoteMount = mountPanel('remote', async (url) => {
    remoteFetchedUrls.push(url);
    if (url === '/api/tiana-remote/public-status') {
      return new Response(JSON.stringify({ hostName: 'HostDemo', e2eeFingerprint: 'aa:bb' }), { status: 200 });
    }
    return new Response('{}', { status: 404 });
  }, {
    language: 'zh-CN',
    shell: {
      clearFrontendCache() { clearCacheClicks += 1; },
      lockAndForget() { lockForgetClicks += 1; },
    },
  });

  remoteMount.render();
  await remoteMount.flush();
  const rTree = remoteMount.render();
  assert.deepEqual(remoteFetchedUrls, ['/api/tiana-remote/public-status']);
  assert.equal(findById(rTree, 'dshr-plugin-access-card'), null, 'remote view must NOT render plugin access card');

  const clearBtnZh = findById(rTree, 'dshr-remote-clear-cache');
  const clearDescZh = findById(rTree, 'dshr-remote-clear-cache-desc');
  const unbindBtnZh = findById(rTree, 'dshr-remote-lock-forget');
  const unbindDescZh = findById(rTree, 'dshr-remote-lock-forget-desc');
  assert.ok(clearBtnZh && clearDescZh, 'remote zh view must render clear-cache button and description');
  assert.ok(unbindBtnZh && unbindDescZh, 'remote zh view must render unbind-device button and description');
  assert.equal(collectText(clearBtnZh), '清除缓存并刷新');
  assert.equal(clearBtnZh.props['aria-describedby'], 'dshr-remote-clear-cache-desc');
  assert.match(collectText(clearDescZh), /升级.*DSH.*插件/u);
  assert.match(collectText(clearDescZh), /不影响本机数据/u);
  assert.equal(collectText(unbindBtnZh), '解除此设备绑定');
  assert.equal(unbindBtnZh.props['aria-describedby'], 'dshr-remote-lock-forget-desc');
  assert.match(collectText(unbindDescZh), /当前设备.*浏览器/u);
  assert.match(collectText(unbindDescZh), /关联仍然存在/u);
  assert.match(collectText(unbindDescZh), /本机电脑.*dsh-tiana-remote/u);

  clearBtnZh.props.onClick();
  unbindBtnZh.props.onClick();
  assert.equal(clearCacheClicks, 1, 'clear-cache button must invoke clearFrontendCache()');
  assert.equal(lockForgetClicks, 1, 'unbind-device button must invoke lockAndForget()');

  // 1b. Remote mode (en-US): verifies matching English labels and explanatory copy
  const remoteEnMount = mountPanel('remote', async (url) => {
    if (url === '/api/tiana-remote/public-status') {
      return new Response(JSON.stringify({ hostName: 'HostDemo', e2eeFingerprint: 'aa:bb' }), { status: 200 });
    }
    return new Response('{}', { status: 404 });
  }, { language: 'en-US' });
  remoteEnMount.render();
  await remoteEnMount.flush();
  const rTreeEn = remoteEnMount.render();
  const clearBtnEn = findById(rTreeEn, 'dshr-remote-clear-cache');
  const clearDescEn = findById(rTreeEn, 'dshr-remote-clear-cache-desc');
  const unbindBtnEn = findById(rTreeEn, 'dshr-remote-lock-forget');
  const unbindDescEn = findById(rTreeEn, 'dshr-remote-lock-forget-desc');
  assert.equal(collectText(clearBtnEn), 'Clear Cache & Reload');
  assert.match(collectText(clearDescEn), /upgrading DSH or a plugin/i);
  assert.match(collectText(clearDescEn), /not be affected/i);
  assert.equal(collectText(unbindBtnEn), 'Unbind This Device');
  assert.match(collectText(unbindDescEn), /this device\/browser only/i);
  assert.match(collectText(unbindDescEn), /remains active/i);
  assert.match(collectText(unbindDescEn), /dsh-tiana-remote.*host computer/i);

  // 2. Local mode (zh-CN): renders bridgeConflict banner, renders NO plugin policy card,
  //    renders structured sync/repair cloud page action row + cloud binding unbind section,
  //    and transitions cleanly to unbound view with lastBound quick rebind bar
  let repairResolve = null;
  let repairCalls = 0;
  let isUnbound = false;
  let unbindRequests = [];
  let provisionRequests = [];
  const localOverviewPayload = {
    ok: true,
    configured: true,
    enabled: true,
    owner: { email: 'owner@example.test', spaceName: 'Demo Space' },
    host: { hostId: 'host-demo', hostName: 'HostDemo' },
    web: { id: 'web123456789', name: 'dsh-tiana-remote', endpoint: 'https://web123456789.example.test/web/web123456789/' },
    e2ee: { fingerprint: '11:22' },
    bridge: { relayConnected: false, hostConflict: true, sessions: [] },
    bridgeConflict: { ownerPid: 2495419, ownerOrigin: 'https://workstation.example.test:3080' },
    network: { p2pEnabled: true, stunUrls: [] },
    lastBound: null,
  };
  const unboundOverviewPayload = {
    ok: true,
    configured: false,
    enabled: false,
    owner: null,
    host: { hostId: 'host-demo', hostName: 'HostDemo' },
    web: null,
    function: null,
    e2ee: null,
    bridge: { relayConnected: false, hostConflict: false, sessions: [] },
    bridgeConflict: null,
    network: { p2pEnabled: true, stunUrls: [] },
    lastBound: {
      webId: 'web123456789',
      webName: 'dsh-tiana-remote',
      endpoint: 'https://web123456789.example.test/web/web123456789/',
      unboundAt: '2026-11-23T01:00:00.000Z',
    },
  };
  const localMount = mountPanel('local', async (url, opts) => {
    if (url === '/api/tiana-remote/admin/repair' && opts?.method === 'POST') {
      repairCalls += 1;
      return new Promise((resolve) => {
        repairResolve = () => resolve(new Response(JSON.stringify({ ok: true, repaired: true }), { status: 200 }));
      });
    }
    if (url === '/api/tiana-remote/admin/unbind' && opts?.method === 'POST') {
      unbindRequests.push(JSON.parse(opts.body));
      isUnbound = true;
      return new Response(JSON.stringify({
        ok: true,
        unbound: true,
        cloudPolicyCleared: true,
        cloudPolicyWarning: '',
        lastBound: unboundOverviewPayload.lastBound,
      }), { status: 200 });
    }
    if (url === '/api/tiana-remote/admin/provision' && opts?.method === 'POST') {
      provisionRequests.push(JSON.parse(opts.body));
      return new Response(JSON.stringify({ ok: true, started: true, step: 'binding' }), { status: 202 });
    }
    if (url === '/api/tiana-remote/admin/provision-status') {
      return new Response(JSON.stringify({ ok: true, running: false, step: 'done', logs: [] }), { status: 200 });
    }
    return new Response(JSON.stringify(isUnbound ? unboundOverviewPayload : localOverviewPayload), { status: 200 });
  }, { language: 'zh-CN' });

  localMount.render();
  await localMount.flush();
  const lTree = localMount.render();
  const conflictBanner = findById(lTree, 'dshr-bridge-conflict-banner');
  assert.ok(conflictBanner, 'local view must render bridgeConflict alert banner');
  assert.ok(collectText(conflictBanner).includes('2495419'));
  assert.equal(findById(lTree, 'dshr-plugin-access-card'), null, 'local view must NOT render plugin access card');
  assert.equal(findById(lTree, 'dshr-rebind-form'), null, 'local view must NOT render legacy inline rebind form');

  const repairActionZh = findById(lTree, 'dshr-local-action-repair');
  const repairBtnZh = findById(lTree, 'dshr-repair-btn');
  const repairDescZh = findById(lTree, 'dshr-repair-desc');
  assert.ok(repairActionZh && repairBtnZh && repairDescZh, 'local zh view must render structured sync/repair action row');
  assert.equal(collectText(repairBtnZh), '同步/修复云端访问页');
  assert.equal(repairBtnZh.props['aria-describedby'], 'dshr-repair-desc');
  assert.match(collectText(repairDescZh), /升级本机插件后.*云端访问页/u);
  assert.match(collectText(repairDescZh), /不影响已有配对密钥和本机数据/u);
  assert.ok(!collectText(lTree).includes('重推静态壳层'), 'local zh view must not contain legacy static shell copy');

  const bindingMetaZh = findById(lTree, 'dshr-cloud-binding-meta');
  const unbindBtnLocalZh = findById(lTree, 'dshr-unbind-btn');
  const unbindDescLocalZh = findById(lTree, 'dshr-unbind-desc');
  const unbindDialogZh = findById(lTree, 'dshr-unbind-dialog');
  assert.ok(bindingMetaZh && unbindBtnLocalZh && unbindDescLocalZh && unbindDialogZh, 'local zh view must render cloud binding & unbind dialog');
  assert.ok(collectText(bindingMetaZh).includes('web123456789'));
  assert.ok(collectText(bindingMetaZh).includes('owner@example.test'));
  assert.ok(collectText(bindingMetaZh).includes('Demo Space'));
  assert.equal(collectText(unbindBtnLocalZh), '解除绑定');
  assert.equal(unbindBtnLocalZh.props['aria-describedby'], 'dshr-unbind-desc');
  assert.equal(findById(unbindDialogZh, 'dshr-unbind-cancel').props.autoFocus, true);

  // Verify busy & completed states when invoking handleRepair()
  repairBtnZh.props.onClick();
  const lTreeBusyZh = localMount.render();
  const repairBtnBusyZh = findById(lTreeBusyZh, 'dshr-repair-btn');
  assert.equal(repairCalls, 1, 'clicking #dshr-repair-btn must POST /api/tiana-remote/admin/repair');
  assert.equal(repairBtnBusyZh.props.disabled, true);
  assert.equal(collectText(repairBtnBusyZh), '正在同步…');
  repairResolve();
  await new Promise((r) => setTimeout(r, 15));
  const lTreeDoneZh = localMount.render();
  assert.equal(collectText(findById(lTreeDoneZh, 'dshr-repair-btn')), '同步/修复云端访问页');
  assert.ok(collectText(lTreeDoneZh).includes('云端访问页已同步'), 'local zh toast must announce cloud page synced');

  // Confirm unbind dialog -> POST /api/tiana-remote/admin/unbind { confirm: true } -> transitions to unbound card + lastBound bar
  unbindDialogZh.props.onClose({ currentTarget: { returnValue: 'confirm' } });
  await new Promise((r) => setTimeout(r, 25));
  const lTreeUnboundZh = localMount.render();
  assert.deepEqual(unbindRequests, [{ confirm: true }]);
  assert.ok(collectText(findById(lTreeUnboundZh, 'dshr-local-status-badge')).includes('尚未绑定'));
  assert.equal(findById(lTreeUnboundZh, 'dshr-enable-toggle'), null, 'unbound view must hide enable toggle');
  assert.ok(findById(lTreeUnboundZh, 'dshr-unconfigured-card'), 'unbound view must render onboarding card');
  assert.equal(findById(lTreeUnboundZh, 'dshr-bind-hostname').props.value, 'HostDemo');
  const lastBoundBarZh = findById(lTreeUnboundZh, 'dshr-last-bound-bar');
  const lastBoundRebindBtnZh = findById(lTreeUnboundZh, 'dshr-last-bound-rebind-btn');
  assert.ok(lastBoundBarZh && lastBoundRebindBtnZh, 'unbound view must render lastBound quick rebind bar');
  assert.ok(collectText(lastBoundBarZh).includes('web123456789'));
  assert.equal(collectText(lastBoundRebindBtnZh), '填入并重绑');
  lastBoundRebindBtnZh.props.onClick();
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(provisionRequests, [{ mode: 'bind', webId: 'web123456789', hostName: 'HostDemo', rebind: false }]);

  // 2b. Local mode (en-US): verifies English sync/repair, unbind, and unbound Not Bound + lastBound bar
  let repairEnResolve = null;
  let isUnboundEn = false;
  const localEnMount = mountPanel('local', async (url, opts) => {
    if (url === '/api/tiana-remote/admin/repair' && opts?.method === 'POST') {
      return new Promise((resolve) => {
        repairEnResolve = () => resolve(new Response(JSON.stringify({ ok: true, repaired: true }), { status: 200 }));
      });
    }
    if (url === '/api/tiana-remote/admin/unbind' && opts?.method === 'POST') {
      isUnboundEn = true;
      return new Response(JSON.stringify({
        ok: true,
        unbound: true,
        cloudPolicyCleared: false,
        cloudPolicyWarning: 'offline',
        lastBound: unboundOverviewPayload.lastBound,
      }), { status: 200 });
    }
    return new Response(JSON.stringify(isUnboundEn ? unboundOverviewPayload : localOverviewPayload), { status: 200 });
  }, { language: 'en-US' });

  localEnMount.render();
  await localEnMount.flush();
  const lTreeEn = localEnMount.render();
  const repairBtnEn = findById(lTreeEn, 'dshr-repair-btn');
  const repairDescEn = findById(lTreeEn, 'dshr-repair-desc');
  assert.ok(repairBtnEn && repairDescEn, 'local en view must render sync/repair button and description');
  assert.equal(collectText(repairBtnEn), 'Sync / Repair Cloud Page');
  assert.equal(repairBtnEn.props['aria-describedby'], 'dshr-repair-desc');
  assert.match(collectText(repairDescEn), /upgrading this plugin/i);
  assert.match(collectText(repairDescEn), /without changing your pairing key or local data/i);
  assert.ok(!collectText(lTreeEn).includes('Static Shell'), 'local en view must not contain legacy Static Shell copy');
  assert.equal(collectText(findById(lTreeEn, 'dshr-unbind-btn')), 'Unbind Cloud App');

  repairBtnEn.props.onClick();
  const lTreeBusyEn = localEnMount.render();
  assert.equal(collectText(findById(lTreeBusyEn, 'dshr-repair-btn')), 'Syncing…');
  repairEnResolve();
  await new Promise((r) => setTimeout(r, 15));
  const lTreeDoneEn = localEnMount.render();
  assert.equal(collectText(findById(lTreeDoneEn, 'dshr-repair-btn')), 'Sync / Repair Cloud Page');
  assert.ok(collectText(lTreeDoneEn).includes('Cloud page synced'), 'local en toast must announce cloud page synced');

  // Unbind with cloudPolicyWarning in EN shows mild warning toast and Not Bound badge
  findById(lTreeDoneEn, 'dshr-unbind-dialog').props.onClose({ currentTarget: { returnValue: 'confirm' } });
  await new Promise((r) => setTimeout(r, 25));
  const lTreeUnboundEn = localEnMount.render();
  assert.ok(collectText(findById(lTreeUnboundEn, 'dshr-local-status-badge')).includes('Not Bound'));
  assert.ok(collectText(lTreeUnboundEn).includes('cloud policy cleanup was skipped'));
  assert.equal(collectText(findById(lTreeUnboundEn, 'dshr-last-bound-rebind-btn')), 'Rebind Now');

  // 3. Static copy hygiene guard across client.js
  assert.ok(!clientCode.includes('重推静态壳层修复'), 'client.js must not retain old Chinese repair button copy');
  assert.ok(!clientCode.includes('静态壳层'), 'client.js must not retain static shell user-facing copy');
  assert.ok(!clientCode.includes('Repair / Republish Static Shell'), 'client.js must not retain old English repair button copy');
});
