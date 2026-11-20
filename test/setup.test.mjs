import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateE2eeSecret, loadRemoteState, saveRemoteState } from '../src/state.js';
import {
  bindTianaRemoteWeb,
  getWebFunctionBinding,
  provisionTianaRemote,
  updateRemotePolicy,
  validateRelayFunctionShown,
} from '../src/tiana-cli.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

function writeMockTiana(binary, dir, opts = {}) {
  const fnProductState = opts.fnProductState ?? 'ACTIVE';
  const fnEnabled = opts.fnEnabled ?? true;
  const fnDeletionPending = opts.fnDeletionPending ?? false;
  const webEnabled = opts.webEnabled ?? true;
  const webDeletionPending = opts.webDeletionPending ?? false;
  const failParamsGet = Boolean(opts.failParamsGet);
  const omitOwnerId = Boolean(opts.omitOwnerId);
  const hasExplicitOwnerId = Object.prototype.hasOwnProperty.call(opts, 'ownerId');
  const ownerIdValue = hasExplicitOwnerId ? opts.ownerId : 'fixture-user';
  const omitTenantId = Boolean(opts.omitTenantId);
  const hasExplicitTenantId = Object.prototype.hasOwnProperty.call(opts, 'tenantId');
  const tenantIdValue = hasExplicitTenantId ? opts.tenantId : 'fixture-tenant';
  const hasSpace = Object.prototype.hasOwnProperty.call(opts, 'spaceCanManage');
  const hasWebCanManage = Object.prototype.hasOwnProperty.call(opts, 'webCanManage');
  const webCanManageSequence = Array.isArray(opts.webCanManageSequence) ? opts.webCanManageSequence : null;
  const webFunctionIds = Array.isArray(opts.webFunctionIds) ? opts.webFunctionIds : ['fixture-function'];
  const webListEmpty = Boolean(opts.webListEmpty);
  const rotateKeyDshHomeOnTokenCreate = opts.rotateKeyDshHomeOnTokenCreate || '';
  writeFileSync(binary, `#!${process.execPath}
const cp = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const overrideFile = path.join(dir, 'mock-override.json');
const overrides = fs.existsSync(overrideFile) ? JSON.parse(fs.readFileSync(overrideFile, 'utf8')) : {};
const web = {
  id: 'fixture00001',
  ${omitOwnerId ? '' : `owner_id: ${JSON.stringify(ownerIdValue)},`}
  ${omitTenantId ? '' : `tenant_id: ${JSON.stringify(tenantIdValue)},`}
  enabled: ${JSON.stringify(webEnabled)},
  deletion_pending: ${JSON.stringify(webDeletionPending)},
  endpoint: 'https://fixture.invalid/web/fixture00001/'
};
if (Object.prototype.hasOwnProperty.call(overrides, 'ownerId')) web.owner_id = overrides.ownerId;
if (Object.prototype.hasOwnProperty.call(overrides, 'tenantId')) web.tenant_id = overrides.tenantId;
if (Object.prototype.hasOwnProperty.call(overrides, 'webEnabled')) web.enabled = overrides.webEnabled;
const save = path.join(dir, 'submitted-source.go');
const published = path.join(dir, 'published');
const fnCreatedFile = path.join(dir, 'function-created.json');
const tokenMintedFile = path.join(dir, 'token-minted.json');
const paramsFile = path.join(dir, 'function-params.json');
const webBindingFile = path.join(dir, 'web-binding-written.json');
const webPublishedFile = path.join(dir, 'web-published.json');
const getCountFile = path.join(dir, 'web-functions-get-count.txt');
let data;
if (args[0] === 'status') {
  data = {
    logged_in: true,
    user: {
      user_id: overrides.userId || 'fixture-user',
      tenant_id: overrides.statusTenantId || 'fixture-tenant',
      email: 'owner@example.test',
    },
    ${hasSpace ? `space: { tenant_id: overrides.statusTenantId || 'fixture-tenant', role: 'owner', can_manage: ${JSON.stringify(opts.spaceCanManage)} },` : ''}
  };
} else if (args[0] === 'web' && args[1] === 'list') {
  data = {items: ${JSON.stringify(webListEmpty)} ? [] : [web]};
} else if (args[0] === 'web' && args[1] === 'create') {
  data = { project: web };
} else if (args[0] === 'function' && args[1] === 'create') {
  fs.writeFileSync(fnCreatedFile, JSON.stringify({ args }));
  data = { instance_id: 'fixture-function' };
} else if (args[0] === 'function' && args[1] === 'show') {
  if (args[2] !== 'fixture-function') process.exit(5);
  data = {
    instance: {
      id: 'fixture-function',
      product_state: ${JSON.stringify(fnProductState)},
      enabled: ${JSON.stringify(fnEnabled)},
      deletion_pending: ${JSON.stringify(fnDeletionPending)},
      connection: { hostname: 'function.invalid', url: 'https://function.invalid/' }
    },
    function: {
      instance_id: 'fixture-function',
      source_dir: '.',
      git_instance_id: 'git-fixture-1'
    },
    release: {}
  };
  if (fs.existsSync(published)) data.release.published = {id:'1', build_commit:'built-commit'};
} else if (args.slice(0,3).join(' ') === 'function source list') {
  data = {commit:'old-commit'};
} else if (args.slice(0,3).join(' ') === 'function source read') {
  process.stdout.write('old source');
  process.exit(0);
} else if (args.slice(0,3).join(' ') === 'function source save') {
  const filename = args.find((part) => part.startsWith('main.go=')).slice(8);
  fs.copyFileSync(filename, save);
  data = {commit:'saved-commit'};
} else if (args.slice(0,2).join(' ') === 'function publish') {
  if (args[args.indexOf('--commit') + 1] !== 'saved-commit') process.exit(5);
  fs.writeFileSync(published, '');
  data = {};
} else if (args.slice(0,2).join(' ') === 'function builds') {
  data = {items:[{id:'1', source_commit:'saved-commit', build_commit:'built-commit'}]};
} else if (args.slice(0,3).join(' ') === 'function parameters get') {
  if (${JSON.stringify(failParamsGet)}) {
    process.stderr.write('simulated parameters get error');
    process.exit(7);
  }
  data = {parameters: fs.existsSync(paramsFile) ? JSON.parse(fs.readFileSync(paramsFile, 'utf8')) : {EXISTING_KEY: {kind:'plain', value:'keep'}}};
} else if (args.slice(0,3).join(' ') === 'function parameters set') {
  const fileArg = args[args.indexOf('--file') + 1];
  fs.copyFileSync(fileArg, paramsFile);
  data = {ok:true};
} else if (args.slice(0,2).join(' ') === 'token create') {
  if (Number(args[args.indexOf('--expires-at') + 1]) <= Date.now()/1000) process.exit(5);
  fs.writeFileSync(tokenMintedFile, JSON.stringify({ args }));
  const rotateDshHome = ${JSON.stringify(rotateKeyDshHomeOnTokenCreate)};
  if (rotateDshHome) {
    const out = cp.execFileSync(process.execPath, [${JSON.stringify(join(PROJECT_ROOT, 'cli.js'))}, 'key', '--rotate', '--json', '--print-key'], {
      env: { ...process.env, DSH_HOME: rotateDshHome },
      encoding: 'utf8',
    });
    fs.writeFileSync(path.join(dir, 'concurrent-key-rotate.json'), out);
  }
  data = {token:'fixture-new-token',token_id:'fixture-new-id'};
} else if (args.slice(0,3).join(' ') === 'web functions get') {
  const seq = ${JSON.stringify(webCanManageSequence)};
  let cm = ${hasWebCanManage ? JSON.stringify(opts.webCanManage) : 'undefined'};
  if (Array.isArray(seq)) {
    const idx = fs.existsSync(getCountFile) ? Number(fs.readFileSync(getCountFile, 'utf8')) : 0;
    fs.writeFileSync(getCountFile, String(idx + 1));
    cm = seq[Math.min(idx, seq.length - 1)];
  }
  data = { web_id: 'fixture00001', function_instance_ids: ${JSON.stringify(webFunctionIds)}, project_revision: 1 };
  if (cm !== undefined) data.can_manage = cm;
} else if (args.slice(0,3).join(' ') === 'web functions set') {
  fs.writeFileSync(webBindingFile, JSON.stringify({ args }));
  data = { ok: true };
} else if (args.slice(0,2).join(' ') === 'web publish') {
  const dist = args[args.indexOf('--dir') + 1];
  fs.copyFileSync(path.join(dist, 'remote-config.json'), path.join(__dirname, 'remote-config.json'));
  fs.writeFileSync(webPublishedFile, JSON.stringify({ status: 'verified-by-fixture' }));
  data = {status:'verified-by-fixture'};
} else {
  process.exit(5);
}
console.log(JSON.stringify({data}));
`, { mode: 0o700 });
}

test('validateRelayFunctionShown accepts exact upstream Tiana CLI v1.0.32/v1.0.34 product_state JSON and rejects disabled/deleting/non-ACTIVE', () => {
  const realCliShape = {
    instance: {
      id: 'fn-real-1',
      product_state: 'ACTIVE',
      enabled: true,
      deletion_pending: false,
      connection: { hostname: 'fn-real-1.example.test', url: 'https://fn-real-1.example.test/' },
    },
    function: {
      instance_id: 'fn-real-1',
      source_dir: '.',
      git_instance_id: 'git-123',
    },
    release: { published: { id: 'rel-1' } },
  };
  assert.equal(validateRelayFunctionShown(realCliShape), 'https://fn-real-1.example.test/');

  assert.throws(
    () => validateRelayFunctionShown({ ...realCliShape, instance: { ...realCliShape.instance, product_state: 'BUILDING' } }),
    /ACTIVE/u,
  );
  assert.throws(
    () => validateRelayFunctionShown({ ...realCliShape, instance: { ...realCliShape.instance, enabled: false } }),
    /disabled/iu,
  );
  assert.throws(
    () => validateRelayFunctionShown({ ...realCliShape, instance: { ...realCliShape.instance, deletion_pending: true } }),
    /deletion/iu,
  );
});

test('setup migrates v1 by ID, builds in temp dir without polluting repo, and publishes DSH_REMOTE_POLICY safely', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-setup-test-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  const webId = 'fixture00001';
  const oldSecret = generateE2eeSecret();
  const oldToken = generateE2eeSecret();
  const previousBinary = process.env.TIANA_BIN;
  process.env.TIANA_BIN = binary;
  try {
    saveRemoteState({
      version: 1,
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      host: { hostId: 'fixture-host', hostName: 'Fixture Host' },
      web: { id: webId, endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: oldToken },
      e2ee: { secret: oldSecret },
    }, statePath);
    writeMockTiana(binary, dir);

    const repoDistPath = join(PROJECT_ROOT, '.dist-tweb', webId);
    rmSync(repoDistPath, { recursive: true, force: true });

    const state = await provisionTianaRemote({ statePath, log: () => {} });
    assert.equal(existsSync(repoDistPath), false, 'provisionTianaRemote must not pollute repo .dist-tweb');
    assert.equal(state.version, 2);
    assert.equal(state.configVersion, 2);
    assert.notEqual(state.e2ee.secret, oldSecret);
    assert.notEqual(state.function.token, oldToken);
    assert.notEqual(state.host.registrationKey, state.e2ee.secret);
    assert.equal(loadRemoteState(statePath).pendingSetup, undefined);
    assert.equal(state.web.endpoint.includes('#rk='), false);

    const source = readFileSync(join(dir, 'submitted-source.go'), 'utf8');
    const config = readFileSync(join(dir, 'remote-config.json'), 'utf8');
    const params = JSON.parse(readFileSync(join(dir, 'function-params.json'), 'utf8'));
    for (const secret of [oldSecret, oldToken, state.e2ee.secret, state.host.registrationKey, state.function.token]) {
      assert.ok(!source.includes(secret) && !config.includes(secret) && !JSON.stringify(params).includes(secret));
    }
    assert.deepEqual(params.EXISTING_KEY, { kind: 'plain', value: 'keep' });
    const policy = JSON.parse(params.DSH_REMOTE_POLICY.value);
    assert.equal(policy.version, 1);
    assert.equal(policy.hostId, 'fixture-host');
    assert.equal(policy.hostDigest, createHash('sha256').update(state.host.registrationKey).digest('hex'));
    assert.equal(JSON.parse(config).webId, webId);

    // Zero-recompile bindTianaRemoteWeb updates DSH_REMOTE_POLICY when same hostId + same registrationKey
    const bound = await bindTianaRemoteWeb({
      webId,
      hostId: 'fixture-host',
      hostName: 'Renamed Host',
      statePath,
      probeRelayHealth: async () => ({ ok: true, paired: true }),
      log: () => {},
    });
    assert.equal(bound.host.hostName, 'Renamed Host');
    const updatedPolicy = JSON.parse(JSON.parse(readFileSync(join(dir, 'function-params.json'), 'utf8')).DSH_REMOTE_POLICY.value);
    assert.equal(updatedPolicy.hostName, 'Renamed Host');

    // Same hostId on a DIFFERENT machine (different registrationKey -> different hostDigest) MUST trigger rebind conflict!
    const otherMachineState = join(dir, 'other-machine-state.json');
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'fixture-host',
        hostName: 'Same Hostname Other Machine',
        statePath: otherMachineState,
        probeRelayHealth: async () => ({ ok: true, paired: true }),
        log: () => {},
      }),
      /already bound.*--rebind/u,
    );

    // With --rebind, same hostId from other machine succeeds and rotates registrationKey/hostDigest
    const rebound = await bindTianaRemoteWeb({
      webId,
      hostId: 'fixture-host',
      hostName: 'Other Machine Rebound',
      rebind: true,
      statePath: otherMachineState,
      probeRelayHealth: async () => ({ ok: true, paired: true }),
      log: () => {},
    });
    assert.notEqual(rebound.host.registrationKey, bound.host.registrationKey);
  } finally {
    if (previousBinary === undefined) delete process.env.TIANA_BIN;
    else process.env.TIANA_BIN = previousBinary;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bindTianaRemoteWeb recovers pendingBind after post-cloud-update local crash and merges concurrent key/token updates', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-pendingbind-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  const webId = 'fixture00001';
  try {
    writeMockTiana(binary, dir, { fnProductState: 'ACTIVE' });

    const oldRegKey = generateE2eeSecret();
    const pendingRegKey = generateE2eeSecret();
    const oldE2eeSecret = generateE2eeSecret();
    const pendingE2eeSecret = generateE2eeSecret();
    const pendingDigest = createHash('sha256').update(pendingRegKey).digest('hex');

    // Simulate cloud DSH_REMOTE_POLICY already updated with pendingRegKey before local crash
    writeFileSync(join(dir, 'function-params.json'), JSON.stringify({
      EXISTING_KEY: { kind: 'plain', value: 'keep' },
      DSH_REMOTE_POLICY: {
        kind: 'plain',
        value: JSON.stringify({
          version: 1,
          webId,
          origin: 'https://fixture.invalid',
          ownerUserId: 'fixture-user',
          ownerTenantId: 'fixture-tenant',
          hostId: 'recovered-host',
          hostName: 'Recovered Host',
          hostDigest: pendingDigest,
        }),
      },
    }), { mode: 0o600 });

    // First unbound setup crash (no committed e2ee yet): retry commits both pendingRegKey and pendingBind.e2ee
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      pendingBind: {
        webId,
        functionId: 'fixture-function',
        hostId: 'recovered-host',
        hostName: 'Recovered Host',
        registrationKey: pendingRegKey,
        e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: pendingE2eeSecret, fingerprint: 'aa11:bb22:cc33' },
        tokenInfo: { id: 'fixture-function', token: 'pending-tok', tokenId: 'pt1', expiresAt: Math.floor(Date.now() / 1000) + 15 * 86400 },
      },
    }, statePath);

    const recoveredUnbound = await bindTianaRemoteWeb({
      webId,
      hostId: 'recovered-host',
      hostName: 'Recovered Host',
      statePath,
      tianaBin: binary,
      probeRelayHealth: async () => ({ ok: true, paired: true }),
      log: () => {},
    });
    assert.equal(recoveredUnbound.host.registrationKey, pendingRegKey);
    assert.equal(recoveredUnbound.e2ee.secret, pendingE2eeSecret);
    assert.equal(loadRemoteState(statePath).pendingBind, undefined);

    // Committed host + already-rotated e2ee + stale pendingBind: retry commits pendingRegKey WITHOUT reverting committed e2ee!
    saveRemoteState({
      version: 2,
      configVersion: 2,
      enabled: true,
      host: { hostId: 'recovered-host', hostName: 'Old Host', registrationKey: oldRegKey },
      e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: oldE2eeSecret, fingerprint: '0000:1111:2222' },
      pendingBind: {
        webId,
        functionId: 'fixture-function',
        hostId: 'recovered-host',
        hostName: 'Recovered Host',
        registrationKey: pendingRegKey,
        e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: pendingE2eeSecret, fingerprint: 'aa11:bb22:cc33' },
        tokenInfo: { id: 'fixture-function', token: 'pending-tok', tokenId: 'pt1', expiresAt: Math.floor(Date.now() / 1000) + 15 * 86400 },
      },
    }, statePath);

    const recovered = await bindTianaRemoteWeb({
      webId,
      hostId: 'recovered-host',
      hostName: 'Recovered Host',
      statePath,
      tianaBin: binary,
      probeRelayHealth: async () => ({ ok: true, paired: true }),
      log: () => {},
    });
    assert.equal(recovered.host.registrationKey, pendingRegKey);
    assert.equal(recovered.e2ee.secret, oldE2eeSecret, 'committed E2EE key must not be reverted by stale pendingBind.e2ee');
    assert.equal(loadRemoteState(statePath).pendingBind, undefined);

    // Concurrent E2EE rotation & newer token renewal written during bind MUST survive final commit merge!
    const concurrentlyRotatedSecret = generateE2eeSecret();
    const newerExpiry = Math.floor(Date.now() / 1000) + 60 * 86400;
    const merged = await bindTianaRemoteWeb({
      webId,
      hostId: 'recovered-host',
      hostName: 'Recovered Host 2',
      statePath,
      tianaBin: binary,
      probeRelayHealth: async () => {
        // Simulate concurrent local panel rotating E2EE secret & renewing token while bind is mid-flight
        const cur = loadRemoteState(statePath);
        cur.e2ee = { algorithm: 'x25519-chacha20poly1305-v1', secret: concurrentlyRotatedSecret, fingerprint: 'ff00:ee11:dd22' };
        cur.function = { id: 'fixture-function', token: 'concurrent-newer-token', tokenId: 'ct2', expiresAt: newerExpiry };
        saveRemoteState(cur, statePath);
        return { ok: true, paired: true };
      },
      log: () => {},
    });
    assert.equal(merged.e2ee.secret, concurrentlyRotatedSecret, 'concurrent E2EE rotation must not be overwritten');
    assert.equal(merged.function.token, 'concurrent-newer-token', 'concurrent newer token must not be overwritten');
    assert.equal(merged.function.expiresAt, newerExpiry);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bindTianaRemoteWeb enforces strict parameter read, owner_id, ACTIVE function product_state, web enabled/deleting, and /healthz validation', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-bind-guards-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  const webId = 'fixture00001';
  try {
    // 1. Parameters GET failure MUST NOT be swallowed
    writeMockTiana(binary, dir, { failParamsGet: true });
    await assert.rejects(
      () => updateRemotePolicy('fixture-function', { version: 1 }, { bin: binary, log: () => {} }),
      /parameters get.*failed/u,
    );
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'h1',
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      }),
      /parameters get.*failed/u,
    );

    // 2. Missing owner_id on web app MUST be rejected
    writeMockTiana(binary, dir, { omitOwnerId: true });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'h1',
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      }),
      /owner/u,
    );

    // 3. Disabled or deleting web app MUST be rejected
    writeMockTiana(binary, dir, { webEnabled: false });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'h1',
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      }),
      /disabled/iu,
    );

    // 4. Non-ACTIVE Function product_state MUST be rejected
    writeMockTiana(binary, dir, { fnProductState: 'BUILDING' });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'h1',
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      }),
      /ACTIVE/u,
    );

    // 5. Invalid /healthz payload (non-Relay function) MUST be rejected before mutating cloud policy
    writeMockTiana(binary, dir, { fnProductState: 'ACTIVE' });
    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId,
        hostId: 'h1',
        statePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true }),
        log: () => {},
      }),
      /healthz/u,
    );
    assert.equal(existsSync(join(dir, 'function-params.json')), false, 'cloud policy must not be modified when /healthz fails');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Online empty webApp.owner_id uses tenant_id + can_manage proof in bindTianaRemoteWeb and provisionTianaRemote (fail-closed on negative cases)', async () => {
  const webId = 'fixture00001';

  // Positive case: Online payload (owner_id: "", matching tenant_id, space.can_manage: true, web functions get can_manage: true)
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-online-ok-'));
    const binary = join(dir, 'tiana');
    const bindStatePath = join(dir, 'bind-state.json');
    const setupStatePath = join(dir, 'setup-state.json');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManage: true,
      });

      const binding = await getWebFunctionBinding(webId, { bin: binary });
      assert.equal(binding.canManage, true);

      const bound = await bindTianaRemoteWeb({
        webId,
        hostId: 'online-host',
        hostName: 'Online Host',
        statePath: bindStatePath,
        tianaBin: binary,
        probeRelayHealth: async () => ({ ok: true, paired: false }),
        log: () => {},
      });
      assert.equal(bound.web.id, webId);
      assert.equal(bound.owner.userId, 'fixture-user');
      assert.equal(bound.owner.tenantId, 'fixture-tenant');
      assert.equal(existsSync(join(dir, 'function-params.json')), true);

      // Fresh setup (web create returning owner_id: "" + matching tenant_id + can_manage: true)
      const provisioned = await provisionTianaRemote({
        hostId: 'online-setup-host',
        hostName: 'Online Setup Host',
        statePath: setupStatePath,
        tianaBin: binary,
        log: () => {},
      });
      assert.equal(provisioned.web.id, webId);
      assert.equal(provisioned.owner.userId, 'fixture-user');
      assert.equal(provisioned.owner.tenantId, 'fixture-tenant');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // Negative cases: MUST reject fail-closed BEFORE touching Relay parameters or local state
  const negativeCases = [
    {
      name: 'empty owner_id + matching tenant_id + web can_manage: false',
      opts: { ownerId: '', tenantId: 'fixture-tenant', spaceCanManage: true, webCanManage: false },
    },
    {
      name: 'empty owner_id + matching tenant_id + missing web can_manage',
      opts: { ownerId: '', tenantId: 'fixture-tenant', spaceCanManage: true },
    },
    {
      name: 'empty owner_id + matching tenant_id + space.can_manage: false despite web can_manage: true',
      opts: { ownerId: '', tenantId: 'fixture-tenant', spaceCanManage: false, webCanManage: true },
    },
    {
      name: 'empty owner_id + missing tenant_id despite can_manage: true',
      opts: { ownerId: '', omitTenantId: true, spaceCanManage: true, webCanManage: true },
    },
    {
      name: 'empty owner_id + mismatched tenant_id despite can_manage: true',
      opts: { ownerId: '', tenantId: 'other-tenant', spaceCanManage: true, webCanManage: true },
    },
    {
      name: 'non-empty mismatched owner_id despite matching tenant_id and can_manage: true',
      opts: { ownerId: 'other-user', tenantId: 'fixture-tenant', spaceCanManage: true, webCanManage: true },
    },
  ];

  for (const tc of negativeCases) {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-online-neg-'));
    const binary = join(dir, 'tiana');
    const bindStatePath = join(dir, 'bind-state.json');
    const setupStatePath = join(dir, 'setup-state.json');
    const initialSetupState = {
      version: 2,
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      host: { hostId: 'neg-host', hostName: 'Neg Host' },
      web: { id: webId, endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: 'existing-tok' },
      e2ee: { secret: generateE2eeSecret() },
    };
    saveRemoteState(initialSetupState, setupStatePath);
    const setupBefore = readFileSync(setupStatePath, 'utf8');
    try {
      writeMockTiana(binary, dir, tc.opts);

      await assert.rejects(
        () => bindTianaRemoteWeb({
          webId,
          hostId: 'neg-host',
          statePath: bindStatePath,
          tianaBin: binary,
          probeRelayHealth: async () => ({ ok: true, paired: false }),
          log: () => {},
        }),
        /owner/iu,
        `bindTianaRemoteWeb must reject: ${tc.name}`,
      );
      assert.equal(existsSync(join(dir, 'function-params.json')), false, `bind must not touch Relay params: ${tc.name}`);
      assert.equal(existsSync(bindStatePath), false, `bind must not create local state: ${tc.name}`);

      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'neg-host',
          statePath: setupStatePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
        `provisionTianaRemote must reject: ${tc.name}`,
      );
      assert.equal(existsSync(join(dir, 'function-params.json')), false, `setup must not touch Relay params: ${tc.name}`);
      assert.equal(readFileSync(setupStatePath, 'utf8'), setupBefore, `setup must not mutate local state: ${tc.name}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // Locked re-verification: can_manage revoked between pre-check and locked bind -> reject before parameter write
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-online-revoked-'));
    const binary = join(dir, 'tiana');
    const statePath = join(dir, 'state.json');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, false],
      });
      await assert.rejects(
        () => bindTianaRemoteWeb({
          webId,
          hostId: 'revoked-host',
          statePath,
          tianaBin: binary,
          probeRelayHealth: async () => ({ ok: true, paired: false }),
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dir, 'function-params.json')), false, 'revoked can_manage under lock must block Relay params write');
      assert.equal(existsSync(statePath), false, 'revoked can_manage under lock must block local state write');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R8-2: bind (connect), webApp.owner_id initially "" then becomes explicit mismatch before locked recheck while can_manage stays true
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r8-2-owner-flip-'));
    const binary = join(dir, 'tiana');
    const statePath = join(dir, 'state.json');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManage: true,
      });
      await assert.rejects(
        () => bindTianaRemoteWeb({
          webId,
          hostId: 'owner-flip-host',
          statePath,
          tianaBin: binary,
          probeRelayHealth: async () => {
            // Simulate Web gaining an explicit mismatching owner before bind acquires its lock
            writeFileSync(join(dir, 'mock-override.json'), JSON.stringify({ ownerId: 'other-owner' }));
            return { ok: true, paired: false };
          },
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dir, 'function-params.json')), false, 'R8-2: mismatched owner under lock must block Relay params write');
      assert.equal(existsSync(statePath), false, 'R8-2: mismatched owner under lock must leave state.json absent');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R8-1a: setup NEW web, management revoked (can_manage: [true, false]) before binding/policy commit
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r8-1-setup-new-'));
    const binary = join(dir, 'tiana');
    const statePath = join(dir, 'state.json');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, false],
        webFunctionIds: [],
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'setup-new-revoked',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dir, 'published')), false, 'R10-1 new web: must not publish Relay when revoked after initial check');
      assert.equal(existsSync(join(dir, 'token-minted.json')), false, 'R10-1 new web: must not mint token when revoked after initial check');
      assert.equal(existsSync(join(dir, 'function-params.json')), false, 'R8-1 new web: must not write DSH_REMOTE_POLICY');
      assert.equal(existsSync(join(dir, 'web-binding-written.json')), false, 'R8-1 new web: must not write web binding');
      assert.equal(existsSync(join(dir, 'web-published.json')), false, 'R8-1 new web: must not publish web');
      assert.equal(existsSync(statePath), false, 'R8-1 new web: state.json must remain absent (no pendingSetup left behind)');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R8-1b & R10-1: setup REUSED web, management revoked (can_manage: [true, false]) before Relay publish / binding commit
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r8-1-setup-reused-'));
    const binary = join(dir, 'tiana');
    const statePath = join(dir, 'state.json');
    saveRemoteState({
      version: 2,
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      host: { hostId: 'setup-reused-revoked', hostName: 'Reused Host' },
      web: { id: webId, endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: 'existing-tok' },
      e2ee: { secret: generateE2eeSecret() },
    }, statePath);
    const stateBefore = readFileSync(statePath, 'utf8');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, false],
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'setup-reused-revoked',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dir, 'published')), false, 'R10-1 reused web: must not publish Relay when revoked after initial check');
      assert.equal(existsSync(join(dir, 'token-minted.json')), false, 'R10-1 reused web: must not mint token when revoked after initial check');
      assert.equal(existsSync(join(dir, 'function-params.json')), false, 'R8-1 reused web: must not write DSH_REMOTE_POLICY');
      assert.equal(existsSync(join(dir, 'web-binding-written.json')), false, 'R8-1 reused web: must not write web binding');
      assert.equal(existsSync(join(dir, 'web-published.json')), false, 'R8-1 reused web: must not publish web');
      assert.equal(readFileSync(statePath, 'utf8'), stateBefore, 'R8-1 reused web: state.json must remain byte-for-byte unchanged');
      assert.equal(loadRemoteState(statePath).pendingSetup, undefined, 'R8-1 reused web: pendingSetup must not persist');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R9-1 & R10-1: fresh setup with matching owner_id in web create, empty post-build web list, and can_manage: false -> rejects during preflight before Relay creation/publish/token
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r9-1-empty-list-'));
    const binary = join(dir, 'tiana');
    const statePath = join(dir, 'state.json');
    try {
      writeMockTiana(binary, dir, {
        ownerId: 'fixture-user',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webListEmpty: true,
        webCanManage: false,
        webFunctionIds: [],
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r9-1-host',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dir, 'function-created.json')), false, 'R10-1: must not create Function when constant can_manage: false');
      assert.equal(existsSync(join(dir, 'published')), false, 'R10-1: must not publish Relay when constant can_manage: false');
      assert.equal(existsSync(join(dir, 'token-minted.json')), false, 'R10-1: must not mint token when constant can_manage: false');
      assert.equal(existsSync(join(dir, 'function-params.json')), false, 'R9-1: must not write DSH_REMOTE_POLICY');
      assert.equal(existsSync(join(dir, 'web-binding-written.json')), false, 'R9-1: must not write web binding');
      assert.equal(existsSync(join(dir, 'web-published.json')), false, 'R9-1: must not publish web');
      assert.equal(existsSync(statePath), false, 'R9-1: state.json must remain absent');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R10-1: matching non-empty owner_id, constant can_manage: false (new Web & reused Web) -> rejects in preflight with zero Relay mutations
  {
    const dirNew = mkdtempSync(join(tmpdir(), 'dsh-remote-r10-1-const-deny-new-'));
    const binaryNew = join(dirNew, 'tiana');
    const statePathNew = join(dirNew, 'state.json');
    try {
      writeMockTiana(binaryNew, dirNew, {
        ownerId: 'fixture-user',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManage: false,
        webFunctionIds: [],
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r10-1-new',
          statePath: statePathNew,
          tianaBin: binaryNew,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dirNew, 'function-created.json')), false);
      assert.equal(existsSync(join(dirNew, 'published')), false);
      assert.equal(existsSync(join(dirNew, 'token-minted.json')), false);
      assert.equal(existsSync(join(dirNew, 'function-params.json')), false);
      assert.equal(existsSync(statePathNew), false);
    } finally {
      rmSync(dirNew, { recursive: true, force: true });
    }

    const dirReused = mkdtempSync(join(tmpdir(), 'dsh-remote-r10-1-const-deny-reused-'));
    const binaryReused = join(dirReused, 'tiana');
    const statePathReused = join(dirReused, 'state.json');
    saveRemoteState({
      version: 2,
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      host: { hostId: 'r10-1-reused', hostName: 'Reused Host' },
      web: { id: webId, endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: 'existing-tok' },
      e2ee: { secret: generateE2eeSecret() },
    }, statePathReused);
    const beforeReused = readFileSync(statePathReused, 'utf8');
    try {
      writeMockTiana(binaryReused, dirReused, {
        ownerId: 'fixture-user',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManage: false,
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r10-1-reused',
          statePath: statePathReused,
          tianaBin: binaryReused,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(existsSync(join(dirReused, 'function-created.json')), false);
      assert.equal(existsSync(join(dirReused, 'published')), false);
      assert.equal(existsSync(join(dirReused, 'token-minted.json')), false);
      assert.equal(existsSync(join(dirReused, 'function-params.json')), false);
      assert.equal(readFileSync(statePathReused, 'utf8'), beforeReused);
    } finally {
      rmSync(dirReused, { recursive: true, force: true });
    }
  }

  // R9-2a: setup denial with concurrent `cli.js key --rotate` on initially absent state.json -> rotated key preserved, pendingSetup removed
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r9-2-new-rotate-'));
    const dshHome = join(dir, 'dsh-home');
    mkdirSync(join(dshHome, 'tiana-remote'), { recursive: true, mode: 0o700 });
    const statePath = join(dshHome, 'tiana-remote', 'state.json');
    const binary = join(dir, 'tiana');
    try {
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, true, false],
        webFunctionIds: [],
        rotateKeyDshHomeOnTokenCreate: dshHome,
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r9-2-new-host',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      const rotated = JSON.parse(readFileSync(join(dir, 'concurrent-key-rotate.json'), 'utf8'));
      assert.ok(rotated.secret, 'concurrent key --rotate must have succeeded');
      assert.equal(existsSync(statePath), true, 'R9-2a: state.json must NOT be unlinked when concurrent key rotation wrote e2ee');
      const after = loadRemoteState(statePath);
      assert.equal(after.e2ee?.secret, rotated.secret, 'R9-2a: rotated E2EE secret must be preserved');
      assert.equal(after.pendingSetup, undefined, 'R9-2a: this attempt pendingSetup must be rolled back');
      assert.equal(existsSync(join(dir, 'function-params.json')), false);
      assert.equal(existsSync(join(dir, 'web-binding-written.json')), false);
      assert.equal(existsSync(join(dir, 'web-published.json')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }

  // R9-2b & R9-3: setup denial with concurrent `cli.js key --rotate` on preexisting state.json with earlier pendingSetup
  {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-r9-2-reused-rotate-'));
    const dshHome = join(dir, 'dsh-home');
    mkdirSync(join(dshHome, 'tiana-remote'), { recursive: true, mode: 0o700 });
    const statePath = join(dshHome, 'tiana-remote', 'state.json');
    const binary = join(dir, 'tiana');
    const priorPending = {
      webId,
      functionId: 'fixture-function',
      hostId: 'r9-2-reused-host',
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      note: 'preexisting-recovery-record',
    };
    const initialSecret = generateE2eeSecret();
    saveRemoteState({
      version: 2,
      owner: { userId: 'fixture-user', tenantId: 'fixture-tenant' },
      host: { hostId: 'r9-2-reused-host', hostName: 'Reused Host' },
      web: { id: webId, endpoint: 'https://fixture.invalid/web/fixture00001/' },
      function: { id: 'fixture-function', token: 'existing-tok' },
      e2ee: { secret: initialSecret },
      pendingSetup: priorPending,
    }, statePath);
    try {
      // First verify without concurrent edits: preexisting state (including preexisting pendingSetup) stays byte-identical
      const bytesBefore = readFileSync(statePath, 'utf8');
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, true, false],
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r9-2-reused-host',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      assert.equal(readFileSync(statePath, 'utf8'), bytesBefore, 'R9-3: without concurrent edits state.json must remain byte-identical via atomic restore');

      // Now verify WITH concurrent `cli.js key --rotate`: BOTH rotated key AND preexisting pendingSetup survive
      rmSync(join(dir, 'web-functions-get-count.txt'), { force: true });
      writeMockTiana(binary, dir, {
        ownerId: '',
        tenantId: 'fixture-tenant',
        spaceCanManage: true,
        webCanManageSequence: [true, true, false],
        rotateKeyDshHomeOnTokenCreate: dshHome,
      });
      await assert.rejects(
        () => provisionTianaRemote({
          hostId: 'r9-2-reused-host',
          statePath,
          tianaBin: binary,
          log: () => {},
        }),
        /owner/iu,
      );
      const rotated = JSON.parse(readFileSync(join(dir, 'concurrent-key-rotate.json'), 'utf8'));
      assert.ok(rotated.secret && rotated.secret !== initialSecret, 'concurrent key --rotate must rotate key');
      const after = loadRemoteState(statePath);
      assert.equal(after.e2ee?.secret, rotated.secret, 'R9-2b: concurrent rotated key must be preserved');
      assert.deepEqual(after.pendingSetup, priorPending, 'R9-2b: preexisting pendingSetup recovery record must be restored');
      assert.equal(existsSync(join(dir, 'function-params.json')), false);
      assert.equal(existsSync(join(dir, 'web-binding-written.json')), false);
      assert.equal(existsSync(join(dir, 'web-published.json')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
