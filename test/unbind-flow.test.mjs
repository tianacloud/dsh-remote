import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createHostController } from '../host-main.js';
import { createRemoteApiHandler, registerRemoteRoutes } from '../src/remote-api.js';
import {
  buildUnboundState,
  defaultBridgeLockPath,
  isRemoteConfigured,
  loadNormalizedRemoteState,
  saveRemoteState,
} from '../src/state.js';
import {
  bindTianaRemoteWeb,
  buildRemotePolicy,
  clearRemotePolicyIfOwned,
  provisionTianaRemote,
} from '../src/tiana-cli.js';
import { TunnelClient } from '../web-src/dsh-remote-entry.mjs';

const repoRoot = fileURLToPath(new URL('../', import.meta.url));

function makeMockTianaScript(dir, {
  paramsPath,
  webId = 'web123456789',
  fnId = 'fn-relay-1',
  userId = 'u-owner',
  tenantId = 't-owner',
  email = 'owner@example.test',
  failParamsGet = false,
  newWebId = 'web987654321',
  newFnId = 'fn-relay-2',
} = {}) {
  const binPath = join(dir, 'mock-tiana.mjs');
  const script = `#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const paramsPath = ${JSON.stringify(paramsPath)};
const failParamsGet = ${JSON.stringify(failParamsGet)};
const out = (data) => { process.stdout.write(JSON.stringify({ data }) + '\\n'); };

if (args[0] === 'status') {
  out({
    logged_in: true,
    user: { user_id: ${JSON.stringify(userId)}, tenant_id: ${JSON.stringify(tenantId)}, email: ${JSON.stringify(email)}, display_name: 'Owner' },
    space: { tenant_id: ${JSON.stringify(tenantId)}, display_name: 'Owner Space' },
  });
  process.exit(0);
}
if (args[0] === 'web' && args[1] === 'list') {
  out({
    items: [
      {
        id: ${JSON.stringify(webId)},
        name: 'dsh-tiana-remote',
        owner_id: ${JSON.stringify(userId)},
        tenant_id: ${JSON.stringify(tenantId)},
        endpoint: 'https://' + ${JSON.stringify(webId)} + '.tianacloud.site/web/' + ${JSON.stringify(webId)} + '/',
        enabled: true,
        deletion_pending: false,
      },
      {
        id: ${JSON.stringify(newWebId)},
        name: 'dsh-tiana-remote-new',
        owner_id: ${JSON.stringify(userId)},
        tenant_id: ${JSON.stringify(tenantId)},
        endpoint: 'https://' + ${JSON.stringify(newWebId)} + '.tianacloud.site/web/' + ${JSON.stringify(newWebId)} + '/',
        enabled: true,
        deletion_pending: false,
      },
    ],
  });
  process.exit(0);
}
if (args[0] === 'web' && args[1] === 'create') {
  out({
    project: {
      id: ${JSON.stringify(newWebId)},
      name: args[args.length - 1] || 'dsh-tiana-remote-new',
      owner_id: ${JSON.stringify(userId)},
      tenant_id: ${JSON.stringify(tenantId)},
      endpoint: 'https://' + ${JSON.stringify(newWebId)} + '.tianacloud.site/web/' + ${JSON.stringify(newWebId)} + '/',
      enabled: true,
      deletion_pending: false,
    },
  });
  process.exit(0);
}
if (args[0] === 'web' && args[1] === 'functions' && args[2] === 'get') {
  const targetWeb = args[3];
  out({
    function_instance_ids: targetWeb === ${JSON.stringify(webId)} ? [${JSON.stringify(fnId)}] : [],
    project_revision: 'rev-1',
    can_manage: true,
  });
  process.exit(0);
}
if (args[0] === 'web' && args[1] === 'functions' && args[2] === 'set') {
  out({ ok: true });
  process.exit(0);
}
if (args[0] === 'web' && args[1] === 'publish') {
  out({ revision: 'pub-1' });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'create') {
  out({ instance_id: ${JSON.stringify(newFnId)} });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'show') {
  const id = args[2];
  out({
    instance: {
      id,
      display_name: 'dsh-remote-relay',
      product_state: 'ACTIVE',
      enabled: true,
      deletion_pending: false,
      connection: { url: 'https://' + id + '.relay.invalid' },
    },
    release: { published: { id: 'bld-1', build_commit: 'bc-1' } },
  });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'source' && args[2] === 'list') {
  out({ needs_initial_source: true, commit: '' });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'source' && args[2] === 'save') {
  out({ commit: 'src-commit-1' });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'builds') {
  out({ items: [{ id: 'bld-1', source_commit: 'src-commit-1', build_commit: 'bc-1' }] });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'publish') {
  out({ ok: true });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'parameters' && args[2] === 'get') {
  if (failParamsGet) {
    process.stderr.write('403 Forbidden or offline\\n');
    process.exit(1);
  }
  const params = existsSync(paramsPath) ? JSON.parse(readFileSync(paramsPath, 'utf8')) : {};
  out({ parameters: params });
  process.exit(0);
}
if (args[0] === 'function' && args[1] === 'parameters' && args[2] === 'set') {
  const fileIdx = args.indexOf('--file');
  const raw = readFileSync(args[fileIdx + 1], 'utf8');
  writeFileSync(paramsPath, raw, { mode: 0o600 });
  out({ ok: true });
  process.exit(0);
}
if (args[0] === 'token' && args[1] === 'create') {
  out({ token: 'tok-' + Date.now(), token_id: 'tid-1' });
  process.exit(0);
}
process.stderr.write('Unhandled mock tiana args: ' + args.join(' ') + '\\n');
process.exit(1);
`;
  writeFileSync(binPath, script, { mode: 0o700 });
  chmodSync(binPath, 0o700);
  return binPath;
}

function makeBoundState({
  hostId = 'host-alpha',
  hostName = 'Alpha Workstation',
  registrationKey = 'A'.repeat(43),
  webId = 'web123456789',
  fnId = 'fn-relay-1',
} = {}) {
  return {
    version: 2,
    configVersion: 2,
    enabled: true,
    updatedAt: new Date().toISOString(),
    owner: {
      userId: 'u-owner',
      tenantId: 't-owner',
      email: 'owner@example.test',
      displayName: 'Owner',
      spaceName: 'Owner Space',
    },
    host: { hostId, hostName, registrationKey },
    e2ee: {
      algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM',
      secret: 'S'.repeat(43),
      fingerprint: 'aa:bb:cc',
      createdAt: new Date().toISOString(),
    },
    function: {
      id: fnId,
      name: 'dsh-remote-relay',
      url: `https://${fnId}.relay.invalid`,
      token: 'tok-existing',
      tokenId: 'tid-existing',
      expiresAt: Math.floor(Date.now() / 1000) + 20 * 86400,
    },
    web: {
      id: webId,
      name: 'dsh-tiana-remote',
      endpoint: `https://${webId}.tianacloud.site/web/${webId}/`,
    },
    network: {
      p2pEnabled: false,
      stunUrls: ['stun:stun.custom.test:3478'],
    },
  };
}

test('clearRemotePolicyIfOwned verifies hostId + hostDigest ownership, preserves unrelated params, and degrades offline', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-clear-policy-'));
  try {
    const paramsPath = join(dir, 'params.json');
    const state = makeBoundState();
    const ownedPolicy = buildRemotePolicy({
      hostId: state.host.hostId,
      hostName: state.host.hostName,
      registrationKey: state.host.registrationKey,
      ownerUserId: state.owner.userId,
      ownerTenantId: state.owner.tenantId,
      webId: state.web.id,
      origin: new URL(state.web.endpoint).origin,
    });
    writeFileSync(paramsPath, JSON.stringify({
      CUSTOM_VAR: { kind: 'plain', value: 'keep-me' },
      DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(ownedPolicy) },
    }, null, 2));

    const tianaBin = makeMockTianaScript(dir, { paramsPath });

    // 1. Owned policy is cleared to empty plain value while preserving CUSTOM_VAR
    const res1 = await clearRemotePolicyIfOwned(state, { bin: tianaBin, log: () => {} });
    assert.equal(res1.cleared, true);
    assert.equal(res1.warning, '');
    const afterParams = JSON.parse(readFileSync(paramsPath, 'utf8'));
    assert.deepEqual(afterParams.CUSTOM_VAR, { kind: 'plain', value: 'keep-me' });
    assert.deepEqual(afterParams.DSH_REMOTE_POLICY, { kind: 'plain', value: '' });

    // 2. Policy owned by ANOTHER host (different hostDigest) must NEVER be cleared
    const otherPolicy = buildRemotePolicy({
      hostId: state.host.hostId,
      hostName: 'Other Machine',
      registrationKey: 'B'.repeat(43),
      ownerUserId: state.owner.userId,
      ownerTenantId: state.owner.tenantId,
      webId: state.web.id,
      origin: new URL(state.web.endpoint).origin,
    });
    const otherPayload = {
      CUSTOM_VAR: { kind: 'plain', value: 'keep-me' },
      DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(otherPolicy) },
    };
    writeFileSync(paramsPath, JSON.stringify(otherPayload, null, 2));
    const res2 = await clearRemotePolicyIfOwned(state, { bin: tianaBin, log: () => {} });
    assert.equal(res2.cleared, false);
    assert.equal(res2.skipped, true);
    assert.equal(res2.reason, 'policy_not_owned');
    assert.deepEqual(JSON.parse(readFileSync(paramsPath, 'utf8')), otherPayload);

    // 3. Offline / CLI 403 error degrades gracefully without throwing
    const offlineBin = makeMockTianaScript(dir, { paramsPath, failParamsGet: true });
    const res3 = await clearRemotePolicyIfOwned(state, { bin: offlineBin, log: () => {} });
    assert.equal(res3.cleared, false);
    assert.ok(res3.warning.length > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('POST /api/tiana-remote/admin/unbind enforces guards (403 tunnel, 400 confirm, 409 busy), disconnects sessions, clears state, and supports rebind + create', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-unbind-api-'));
  const statePath = join(dir, 'state.json');
  const runtimePath = join(dir, 'runtime.json');
  const paramsPath = join(dir, 'params.json');
  try {
    const initialState = makeBoundState();
    saveRemoteState(initialState, statePath);
    const ownedPolicy = buildRemotePolicy({
      hostId: initialState.host.hostId,
      hostName: initialState.host.hostName,
      registrationKey: initialState.host.registrationKey,
      ownerUserId: initialState.owner.userId,
      ownerTenantId: initialState.owner.tenantId,
      webId: initialState.web.id,
      origin: new URL(initialState.web.endpoint).origin,
    });
    writeFileSync(paramsPath, JSON.stringify({
      DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(ownedPolicy) },
    }, null, 2));
    const tianaBin = makeMockTianaScript(dir, { paramsPath });

    let disconnectCalls = [];
    let stopCalls = 0;
    let provisionGateResolve = null;
    const fakeBridge = {
      registered: true,
      terminalState: null,
      e2eeSecret: initialState.e2ee.secret,
      async start() {},
      stop() { stopCalls += 1; },
      updateSettings() {},
      getStatusSnapshot() { return { running: true, relayConnected: true, sessions: [{ id: 's1' }] }; },
      async disconnectAllSessions(opts) { disconnectCalls.push(opts); return 2; },
    };

    const controller = createHostController({
      statePath,
      runtimePath,
      tianaBin,
      log: () => {},
      createBridge: () => fakeBridge,
      bindRemoteWeb: async () => new Promise((resolve) => { provisionGateResolve = resolve; }),
      probeRelayHealth: async () => ({ ok: true, paired: false }),
      probeRelayHostStatus: async () => ({ supported: true, ok: true, paired: false, hostConnected: false }),
    });

    // Boot controller to mount fakeBridge and hold bridge-owner.json
    await controller.boot();
    assert.ok(existsSync(defaultBridgeLockPath(statePath)), 'bridge lock should be held while running');

    // Verify registerRemoteRoutes includes /api/tiana-remote/admin/unbind
    const registeredPaths = [];
    const disposeFallback = registerRemoteRoutes({
      fetch: {
        register(route) {
          registeredPaths.push(route.path);
          return () => {};
        },
      },
    }, controller);
    assert.ok(registeredPaths.includes('/api/tiana-remote/admin/unbind'));
    disposeFallback();

    const handler = createRemoteApiHandler(controller, null);
    const localMeta = { remoteAddress: '127.0.0.1', hostHeader: '127.0.0.1:3080', hasTunnelHeader: false };

    // 1. Remote tunnel header is strictly blocked with 403
    const rTunnel = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/unbind', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-dsh-remote-tunnel': '1' },
      body: JSON.stringify({ confirm: true }),
    }), { ...localMeta, hasTunnelHeader: true });
    assert.equal(rTunnel.status, 403);

    // 2. Missing confirm: true returns 400
    const rNoConfirm = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/unbind', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    }), localMeta);
    assert.equal(rNoConfirm.status, 400);

    // 3. Running provisionTask blocks unbind with 409
    controller.startProvision({ mode: 'bind', webId: 'web123456789' });
    const rBusy = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/unbind', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    }), localMeta);
    assert.equal(rBusy.status, 409);
    provisionGateResolve?.();
    await new Promise((r) => setTimeout(r, 30));

    // 4. Valid unbind disconnects sessions with host_unbound, stops bridge, releases lock, clears cloud policy & local state
    const rUnbind = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/unbind', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    }), localMeta);
    assert.equal(rUnbind.status, 200);
    const unbindBody = await rUnbind.json();
    assert.equal(unbindBody.ok, true);
    assert.equal(unbindBody.unbound, true);
    assert.equal(unbindBody.alreadyUnbound, false);
    assert.equal(unbindBody.kickedSessions, 2);
    assert.equal(unbindBody.cloudPolicyCleared, true);
    assert.equal(unbindBody.lastBound?.webId, 'web123456789');
    assert.deepEqual(disconnectCalls, [{ code: 4002, reason: 'host_unbound' }]);
    assert.ok(stopCalls >= 1);

    // Verify persisted unbound state & overview
    const afterState = loadNormalizedRemoteState(statePath);
    assert.equal(isRemoteConfigured(afterState), false);
    assert.equal(afterState.enabled, false);
    assert.equal(afterState.host.hostName, 'Alpha Workstation');
    assert.equal('registrationKey' in afterState.host, false);
    assert.deepEqual(afterState.network, { p2pEnabled: false, stunUrls: ['stun:stun.custom.test:3478'] });
    assert.equal(afterState.lastBound.webId, 'web123456789');

    const overview = await controller.getAdminOverview();
    assert.equal(overview.configured, false);
    assert.equal(overview.enabled, false);
    assert.equal(overview.host.hostName, 'Alpha Workstation');
    assert.equal(overview.lastBound.webId, 'web123456789');
    assert.equal(overview.web, null);
    assert.equal(overview.e2ee, null);

    // 5. Repeat unbind is idempotent
    const rRepeat = await handler(new Request('http://127.0.0.1:3080/api/tiana-remote/admin/unbind', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: true }),
    }), localMeta);
    assert.equal(rRepeat.status, 200);
    const repeatBody = await rRepeat.json();
    assert.equal(repeatBody.alreadyUnbound, true);
    assert.equal(repeatBody.kickedSessions, 0);

    // 6. Configured-only admin operations fail cleanly with 400 on unbound state
    await assert.rejects(() => controller.setEnabled(true), { status: 400 });
    await assert.rejects(() => controller.rotatePairingKey(), { status: 400 });
    await assert.rejects(() => controller.updateSettings({ hostName: 'X' }), { status: 400 });
    await assert.rejects(() => controller.repairStaticShell(), { status: 400 });
    await assert.rejects(() => controller.renewHostToken(), { status: 400 });
    await assert.rejects(() => controller.reconnectBridge(), { status: 400 });

    controller.dispose();

    // 7. Re-binding the SAME web app after unbind succeeds WITHOUT --rebind and re-enables remote access
    const rebound = await bindTianaRemoteWeb({
      webId: 'web123456789',
      statePath,
      runtimePath,
      tianaBin,
      skipLocalPreflight: true,
      probeRelayHealth: async () => ({ ok: true, paired: false }),
      probeRelayHostStatus: async () => ({ supported: true, ok: true, paired: false, hostConnected: false }),
      log: () => {},
    });
    assert.equal(isRemoteConfigured(rebound), true);
    assert.equal(rebound.enabled, true, 'rebinding after unbind must re-enable remote access');
    assert.equal(rebound.web.id, 'web123456789');
    assert.equal(rebound.host.hostName, 'Alpha Workstation');
    assert.deepEqual(rebound.network, { p2pEnabled: false, stunUrls: ['stun:stun.custom.test:3478'] });
    assert.equal('lastBound' in rebound, false);
    assert.notEqual(rebound.host.registrationKey, initialState.host.registrationKey);
    const newCloudPolicy = JSON.parse(JSON.parse(readFileSync(paramsPath, 'utf8')).DSH_REMOTE_POLICY.value);
    assert.equal(
      newCloudPolicy.hostDigest,
      createHash('sha256').update(rebound.host.registrationKey).digest('hex'),
    );

    // 8. Unbind again and create a NEW cloud app under a DIFFERENT Tiana account/space
    saveRemoteState(buildUnboundState(rebound), statePath);
    const otherAcctBin = makeMockTianaScript(dir, {
      paramsPath,
      userId: 'u-second',
      tenantId: 't-second',
      email: 'second@example.test',
    });
    const created = await provisionTianaRemote({
      webName: 'New Remote App',
      statePath,
      runtimePath,
      tianaBin: otherAcctBin,
      skipLocalPreflight: true,
      probeRelayHostStatus: async () => ({ supported: true, ok: true, paired: false, hostConnected: false }),
      log: () => {},
    });
    assert.equal(isRemoteConfigured(created), true);
    assert.equal(created.enabled, true, 'creating new app after unbind must enable remote access');
    assert.equal(created.web.id, 'web987654321');
    assert.equal(created.owner.userId, 'u-second');
    assert.equal(created.owner.tenantId, 't-second');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('CLI dsh-remote unbind --local-only, status, and key handle unbound state cleanly', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-cli-unbind-'));
  try {
    const dshHome = join(dir, 'dsh-home');
    const stateFile = join(dshHome, 'tiana-remote', 'state.json');
    saveRemoteState(makeBoundState(), stateFile);

    const env = { ...process.env, DSH_HOME: dshHome };
    const unbindOut = execFileSync(process.execPath, [join(repoRoot, 'cli.js'), 'unbind', '--local-only', '--json'], {
      env,
      encoding: 'utf8',
    });
    const unbindJson = JSON.parse(unbindOut);
    assert.equal(unbindJson.ok, true);
    assert.equal(unbindJson.unbound, true);
    assert.equal(unbindJson.alreadyUnbound, false);
    assert.equal(unbindJson.cloudPolicyCleared, false);
    assert.equal(unbindJson.lastBound.webId, 'web123456789');

    // Second unbind is idempotent
    const secondOut = execFileSync(process.execPath, [join(repoRoot, 'cli.js'), 'unbind', '--local-only', '--json'], {
      env,
      encoding: 'utf8',
    });
    assert.equal(JSON.parse(secondOut).alreadyUnbound, true);

    // `dsh-remote status --json` reports configured: false and lastBound
    const statusOut = execFileSync(process.execPath, [join(repoRoot, 'cli.js'), 'status', '--json'], {
      env,
      encoding: 'utf8',
    });
    const statusJson = JSON.parse(statusOut);
    assert.equal(statusJson.configured, false);
    assert.equal(statusJson.state.lastBound.webId, 'web123456789');

    // `dsh-remote key` refuses unbound state with a clear error
    assert.throws(
      () => execFileSync(process.execPath, [join(repoRoot, 'cli.js'), 'key'], { env, encoding: 'utf8', stdio: 'pipe' }),
      /not bound yet/i,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('TunnelClient handles host_unbound control message and UNPAIRED reconnect by closing and invoking onHostUnbound', async () => {
  // 1. session_closed with reason: 'host_unbound' stops reconnects and calls onHostUnbound
  let unboundEvents = [];
  const t1 = new TunnelClient(
    async () => { throw new Error('should not reconnect'); },
    { hostId: 'h1', ownerUserId: 'u1', tenantId: 't1', webId: 'web123456789' },
    () => {},
    () => {},
    null,
    { onHostUnbound: async (err) => { unboundEvents.push(err); } },
  );
  await t1.handleControl({ type: 'session_closed', code: 4002, reason: 'host_unbound' }, {});
  assert.equal(t1.closed, true);
  assert.equal(t1.reconnectTimer ?? null, null);
  assert.equal(unboundEvents.length, 1);
  assert.equal(unboundEvents[0].code, 'HOST_UNBOUND');

  // 2. reconnect() receiving UNPAIRED closes tunnel, stops reconnect loop, and calls onHostUnbound
  let unpairedEvents = [];
  const t2 = new TunnelClient(
    async () => { throw Object.assign(new Error('应用尚未绑定主机'), { code: 'UNPAIRED' }); },
    { hostId: 'h1', ownerUserId: 'u1', tenantId: 't1', webId: 'web123456789' },
    () => {},
    () => {},
    null,
    { onHostUnbound: async (err) => { unpairedEvents.push(err); } },
  );
  t2.secret = 'S'.repeat(43);
  await t2.reconnect(false);
  assert.equal(t2.closed, true);
  assert.equal(t2.reconnectTimer ?? null, null);
  assert.equal(unpairedEvents.length, 1);
  assert.equal(unpairedEvents[0].code, 'UNPAIRED');
});
