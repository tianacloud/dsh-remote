import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateE2eeSecret, loadRemoteState, saveRemoteState } from '../src/state.js';
import {
  bindTianaRemoteWeb,
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
  writeFileSync(binary, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const dir = __dirname;
const args = process.argv.slice(2);
const web = {
  id: 'fixture00001',
  ${omitOwnerId ? '' : "owner_id: 'fixture-user',"}
  tenant_id: 'fixture-tenant',
  enabled: ${JSON.stringify(webEnabled)},
  deletion_pending: ${JSON.stringify(webDeletionPending)},
  endpoint: 'https://fixture.invalid/web/fixture00001/'
};
const save = path.join(dir, 'submitted-source.go');
const published = path.join(dir, 'published');
const paramsFile = path.join(dir, 'function-params.json');
let data;
if (args[0] === 'status') {
  data = {logged_in:true, user:{user_id:'fixture-user',tenant_id:'fixture-tenant',email:'owner@example.test'}};
} else if (args[0] === 'web' && args[1] === 'list') {
  data = {items:[web]};
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
  data = {token:'fixture-new-token',token_id:'fixture-new-id'};
} else if (args.slice(0,3).join(' ') === 'web functions get') {
  data = {function_instance_ids:['fixture-function'], project_revision: 1};
} else if (args.slice(0,2).join(' ') === 'web publish') {
  const dist = args[args.indexOf('--dir') + 1];
  fs.copyFileSync(path.join(dist, 'remote-config.json'), path.join(__dirname, 'remote-config.json'));
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
