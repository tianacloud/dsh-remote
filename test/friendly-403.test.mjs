import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  bindTianaRemoteWeb,
  ensureHostToken,
  formatTianaAccount,
  getFunctionParameters,
  isTianaForbiddenError,
  listTianaSpaces,
  parseTianaErrorMeta,
  runTiana,
  runTianaJSON,
  setFunctionParameters,
} from '../src/tiana-cli.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

function writeScenarioMockTiana(binary, config = {}) {
  writeFileSync(binary, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const cfg = ${JSON.stringify(config)};
const logFile = path.join(__dirname, 'invocations.log');
fs.appendFileSync(logFile, JSON.stringify(args) + '\\n');

function failStep(stepCfg) {
  if (stepCfg.stdout !== undefined) {
    process.stdout.write(typeof stepCfg.stdout === 'string' ? stepCfg.stdout : JSON.stringify(stepCfg.stdout) + '\\n');
  }
  if (stepCfg.stderr !== undefined) {
    process.stderr.write(String(stepCfg.stderr));
  }
  process.exit(stepCfg.exitCode ?? 1);
}

const cmd3 = args.slice(0, 3).join(' ');
const cmd2 = args.slice(0, 2).join(' ');

if (args[0] === 'status') {
  if (cfg.failStatus) failStep(cfg.failStatus);
  const data = cfg.statusData || {
    logged_in: true,
    user: {
      user_id: 'usr-water-01',
      tenant_id: 'ten-water-default',
      display_name: 'water',
      email: '',
    },
    space: {
      tenant_id: 'ten-water-default',
      display_name: 'Water Personal Space',
      role: 'tenant_owner',
      is_default: true,
      can_manage: false,
    },
  };
  console.log(JSON.stringify({ data }));
  process.exit(0);
}

if (cmd2 === 'space switch') {
  if (cfg.failSpaceSwitch) failStep(cfg.failSpaceSwitch);
  console.log(JSON.stringify({ data: { tenant_id: args[2], sync_status: 'synced' } }));
  process.exit(0);
}

if (cmd2 === 'space list') {
  if (cfg.failSpaceList) failStep(cfg.failSpaceList);
  const data = cfg.spaceListData || {
    items: [
      {
        tenant_id: 'ten-water-default',
        display_name: 'Water Personal Space',
        role: 'tenant_owner',
        is_default: true,
        is_current: true,
      },
    ],
  };
  console.log(JSON.stringify({ data }));
  process.exit(0);
}

if (cmd2 === 'web list') {
  if (cfg.failWebList) failStep(cfg.failWebList);
  const webId = cfg.webId || 'fixture00001';
  const tenantId = cfg.statusData?.user?.tenant_id || 'ten-water-default';
  const userId = cfg.statusData?.user?.user_id || 'usr-water-01';
  console.log(JSON.stringify({
    data: {
      items: [{
        id: webId,
        name: 'dsh-tiana-remote',
        owner_id: userId,
        tenant_id: tenantId,
        enabled: true,
        deletion_pending: false,
        endpoint: 'https://' + webId + '.tianacloud.site/web/' + webId + '/',
      }],
    },
  }));
  process.exit(0);
}

if (cmd3 === 'web functions get') {
  if (cfg.failWebBindingGet) failStep(cfg.failWebBindingGet);
  console.log(JSON.stringify({
    data: {
      web_id: cfg.webId || 'fixture00001',
      function_instance_ids: cfg.webFunctionIds ?? ['fn-relay-01'],
      project_revision: 3,
      can_manage: true,
    },
  }));
  process.exit(0);
}

if (cmd3 === 'web functions set') {
  if (cfg.failWebBindingSet) failStep(cfg.failWebBindingSet);
  console.log(JSON.stringify({ data: { ok: true } }));
  process.exit(0);
}

if (cmd2 === 'function create') {
  console.log(JSON.stringify({ data: { instance_id: 'fn-created-01' } }));
  process.exit(0);
}

if (cmd3 === 'function source list') {
  console.log(JSON.stringify({ data: { commit: 'abc12345', needs_initial_source: false } }));
  process.exit(0);
}

if (cmd3 === 'function source read') {
  process.stdout.write('old');
  process.exit(0);
}

if (cmd3 === 'function source save') {
  console.log(JSON.stringify({ data: { commit: 'saved1234' } }));
  process.exit(0);
}

if (cmd2 === 'function publish') {
  console.log(JSON.stringify({ data: { ok: true } }));
  process.exit(0);
}

if (cmd2 === 'function builds') {
  console.log(JSON.stringify({ data: { items: [{ id: 'rel-1', source_commit: 'saved1234', build_commit: 'bc-1' }] } }));
  process.exit(0);
}

if (cmd2 === 'function show') {
  if (cfg.failFunctionShow) failStep(cfg.failFunctionShow);
  console.log(JSON.stringify({
    data: {
      instance: {
        id: args[2],
        product_state: 'ACTIVE',
        enabled: true,
        deletion_pending: false,
        connection: { url: 'https://relay.example.invalid/' },
      },
      function: { instance_id: args[2] },
      release: { published: { id: 'rel-1', build_commit: 'bc-1' } },
    },
  }));
  process.exit(0);
}

if (cmd2 === 'token create') {
  if (cfg.failTokenCreate) failStep(cfg.failTokenCreate);
  console.log(JSON.stringify({ data: { token: 'mock-relay-token', token_id: 'tok-id-1' } }));
  process.exit(0);
}

if (cmd3 === 'function parameters get') {
  if (cfg.failParamsGet) failStep(cfg.failParamsGet);
  console.log(JSON.stringify({ data: { parameters: { EXISTING: { kind: 'plain', value: 'keep' } } } }));
  process.exit(0);
}

if (cmd3 === 'function parameters set') {
  if (cfg.failParamsSet) failStep(cfg.failParamsSet);
  console.log(JSON.stringify({ data: { ok: true } }));
  process.exit(0);
}

process.stderr.write('unexpected command: ' + args.join(' '));
process.exit(5);
`, { mode: 0o700 });
}

test('runTiana / runTianaJSON extract structured stdout JSON + stderr status/Request ID metadata', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-meta-'));
  const binary = join(dir, 'tiana');
  try {
    // Case A: non-zero exit with JSON error in stdout + stderr status/Request ID
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 1,
        stdout: {
          status: 'failed',
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'space access denied',
            http_status: 403,
            request_id: 'req-switch-001',
          },
        },
        stderr: 'Error: status 403: space access denied\nRequest ID: req-switch-001\n',
      },
    });
    await assert.rejects(
      () => runTiana(['space', 'switch', 'ten-target', '--json'], { bin: binary }),
      (err) => {
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.httpStatus, 403);
        assert.equal(err.requestId, 'req-switch-001');
        assert.equal(err.tianaMessage, 'space access denied');
        assert.equal(isTianaForbiddenError(err), true);
        return true;
      },
    );

    // Case B: non-zero exit with stderr-only status + Request ID (no JSON stdout)
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 1,
        stdout: '',
        stderr: 'Error: POST /api/v1/me/tenant returned status 403\nRequest ID: req-stderr-403\n',
      },
    });
    await assert.rejects(
      () => runTianaJSON(['space', 'switch', 'ten-target', '--json'], { bin: binary }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.requestId, 'req-stderr-403');
        assert.equal(err.tianaCode, undefined);
        assert.equal(isTianaForbiddenError(err), true);
        return true;
      },
    );

    // Case C: exit 0 JSON envelope with error object
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 0,
        stdout: {
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: 'forbidden by policy',
            http_status: 403,
            request_id: 'req-json-err-403',
          },
        },
      },
    });
    await assert.rejects(
      () => runTianaJSON(['space', 'switch', 'ten-target', '--json'], { bin: binary }),
      (err) => {
        assert.equal(err.tianaCode, 'AUTHORIZATION_DENIED');
        assert.equal(err.httpStatus, 403);
        assert.equal(err.requestId, 'req-json-err-403');
        assert.equal(err.tianaMessage, 'forbidden by policy');
        assert.equal(isTianaForbiddenError(err), true);
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('runTiana / runTianaJSON redact raw stdout/stderr on sensitive token and status commands while keeping whitelisted metadata', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-redact-'));
  const binary = join(dir, 'tiana');
  const sensitiveMarker = 'SENSITIVE_CREDENTIAL_PAYLOAD_DO_NOT_LEAK';
  try {
    writeScenarioMockTiana(binary, {
      failTokenCreate: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: `denied with ${sensitiveMarker}`,
            http_status: 403,
            request_id: 'req-tok-secret-403',
          },
          token: sensitiveMarker,
        },
        stderr: `Error: status 403: ${sensitiveMarker}\nRequest ID: req-tok-secret-403\n`,
      },
      failStatus: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: `expired ${sensitiveMarker}`,
            http_status: 401,
            request_id: 'req-status-401',
          },
        },
        stderr: `Error: status 401: ${sensitiveMarker}\nRequest ID: req-status-401\n`,
      },
    });

    await assert.rejects(
      () => runTianaJSON(['token', 'create', '--json', 'fn-1'], { bin: binary }),
      (err) => {
        assert.doesNotMatch(err.message, new RegExp(sensitiveMarker, 'u'));
        assert.match(err.message, /credential command failed/u);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.httpStatus, 403);
        assert.equal(err.requestId, 'req-tok-secret-403');
        assert.equal(err.tianaMessage, undefined);
        return true;
      },
    );

    await assert.rejects(
      () => runTianaJSON(['status', '--json'], { bin: binary }),
      (err) => {
        assert.doesNotMatch(err.message, new RegExp(sensitiveMarker, 'u'));
        assert.match(err.message, /credential command failed/u);
        assert.equal(err.tianaCode, 'AUTHORIZATION_DENIED');
        assert.equal(err.httpStatus, 401);
        assert.equal(err.requestId, 'req-status-401');
        assert.equal(err.tianaMessage, undefined);
        return true;
      },
    );

    // Also verify parseTianaErrorMeta rejects non-token / malformed code strings
    const sanitized = parseTianaErrorMeta({
      errorObj: {
        code: 'code with spaces secret',
        request_id: 'bad req id',
        http_status: 403,
        message: sensitiveMarker,
      },
      credentialCommand: true,
    });
    assert.equal(sanitized.tianaCode, undefined);
    assert.equal(sanitized.requestId, undefined);
    assert.equal(sanitized.tianaMessage, undefined);
    assert.equal(sanitized.httpStatus, 403);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('formatTianaAccount handles display_name, email, empty email (water), deduplication, and user_id fallback', () => {
  assert.equal(
    formatTianaAccount({ user: { display_name: 'water', email: '', user_id: 'usr-water' } }),
    'water / usr-water',
  );
  assert.equal(
    formatTianaAccount({ user: { display_name: 'water', email: '', user_id: 'usr-water' } }, { includeUserId: false }),
    'water',
  );
  assert.equal(
    formatTianaAccount({ display_name: 'Alice', email: 'alice@example.test', user_id: 'usr-alice' }),
    'Alice / alice@example.test / usr-alice',
  );
  assert.equal(
    formatTianaAccount({ display_name: 'Alice', email: 'alice@example.test', user_id: 'usr-alice' }, { includeUserId: false }),
    'Alice / alice@example.test',
  );
  assert.equal(
    formatTianaAccount({ display_name: 'water', email: 'water', user_id: 'usr-water' }),
    'water / usr-water',
  );
  assert.equal(
    formatTianaAccount({ display_name: '', email: '', user_id: 'usr-only' }, { includeUserId: false }),
    'usr-only',
  );
  assert.equal(formatTianaAccount(null), '(unknown)');
});

test('bindTianaRemoteWeb space switch 403 (Case 1: target space NOT in accessible spaces list) diagnoses account mismatch with actionable retry command', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-switch-403-case1-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  try {
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'not a member of target tenant',
            http_status: 403,
            request_id: 'req-switch-case1-403',
          },
        },
        stderr: 'Error: status 403: not a member\nRequest ID: req-switch-case1-403\n',
      },
      spaceListData: {
        items: [
          {
            tenant_id: 'ten-water-default',
            display_name: 'Water Personal Space',
            role: 'tenant_owner',
            is_default: true,
            is_current: true,
          },
          {
            tenant_id: 'ten-water-team',
            display_name: 'Water Team',
            role: 'tenant_member',
            is_default: false,
            is_current: false,
          },
        ],
      },
    });

    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'fixture00001',
        spaceId: 'ten-other-account-99',
        rebind: true,
        statePath,
        tianaBin: binary,
        log: () => {},
      }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-switch-case1-403');
        assert.match(err.message, /无法切换到目标 Tiana 空间 "ten-other-account-99"（HTTP 403 \/ TENANT_MANAGEMENT_FORBIDDEN）/u);
        assert.match(err.message, /当前本机 CLI 账号：water \/ usr-water-01/u);
        assert.match(err.message, /当前空间：Water Personal Space \/ ten-water-default \/ tenant_owner/u);
        assert.match(err.message, /Water Personal Space \(ten-water-default\)/u);
        assert.match(err.message, /Water Team \(ten-water-team\)/u);
        assert.match(err.message, /Request ID：req-switch-case1-403/u);
        assert.match(err.message, /不在当前登录账号的可访问列表中/u);
        assert.match(err.message, /账号不一致/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        assert.match(
          err.message,
          /npx --yes @tianacloud\/dsh-remote@latest connect --app fixture00001 --space ten-other-account-99 --rebind/u,
        );
        return true;
      },
    );
    assert.equal(existsSync(statePath), false, 'state.json must not be created on space switch 403');
    const invocations = readFileSync(join(dir, 'invocations.log'), 'utf8');
    assert.match(invocations, /\["space","list","--json"\]/u);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bindTianaRemoteWeb space switch 403 (Case 2: target space IS in accessible spaces list) guides login refresh and role check', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-switch-403-case2-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  try {
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: 'stale membership permission',
            http_status: 403,
            request_id: 'req-switch-case2-403',
          },
        },
      },
      spaceListData: {
        items: [
          {
            tenant_id: 'ten-water-default',
            display_name: 'Water Personal Space',
            role: 'tenant_owner',
            is_current: true,
          },
          {
            tenant_id: 'ten-shared-team',
            display_name: 'Shared Team Space',
            role: 'tenant_member',
            is_current: false,
          },
        ],
      },
    });

    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'fixture00001',
        spaceId: 'ten-shared-team',
        statePath,
        tianaBin: binary,
        log: () => {},
      }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'AUTHORIZATION_DENIED');
        assert.equal(err.requestId, 'req-switch-case2-403');
        assert.match(err.message, /无法切换到目标 Tiana 空间 "ten-shared-team"（HTTP 403 \/ AUTHORIZATION_DENIED）/u);
        assert.match(err.message, /当前本机 CLI 账号：water \/ usr-water-01/u);
        assert.match(err.message, /目标空间 ID：ten-shared-team \(Shared Team Space\) \[tenant_member\]/u);
        assert.match(err.message, /成员状态或当前 CLI 会话权限已变更/u);
        assert.match(err.message, /tiana login/u);
        assert.match(err.message, /Request ID：req-switch-case2-403/u);
        assert.doesNotMatch(err.message, /不在当前登录账号的可访问列表中/u);
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bindTianaRemoteWeb space switch 403 degrades safely when space list fails', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-switch-403-degrade-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  try {
    writeScenarioMockTiana(binary, {
      failSpaceSwitch: {
        exitCode: 1,
        stderr: 'Error: status 403: forbidden\nRequest ID: req-degrade-403\n',
      },
      failSpaceList: {
        exitCode: 1,
        stderr: 'network timeout while listing spaces\n',
      },
    });

    await assert.rejects(
      () => bindTianaRemoteWeb({
        webId: 'fixture00001',
        spaceId: 'ten-unreachable-space',
        statePath,
        tianaBin: binary,
        log: () => {},
      }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.requestId, 'req-degrade-403');
        assert.match(err.message, /无法切换到目标 Tiana 空间 "ten-unreachable-space"（HTTP 403 \/ FORBIDDEN）/u);
        assert.match(err.message, /自动查询 `tiana space list` 失败/u);
        assert.match(err.message, /Request ID：req-degrade-403/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        return true;
      },
    );

    // Also verify listTianaSpaces supports alternate shapes (spaces array)
    writeScenarioMockTiana(binary, {
      spaceListData: {
        spaces: [{ id: 'ten-alt-1', name: 'Alt Space', role: 'tenant_admin' }],
      },
    });
    const spaces = await listTianaSpaces({ bin: binary });
    assert.equal(spaces.length, 1);
    assert.equal(spaces[0].tenantId, 'ten-alt-1');
    assert.equal(spaces[0].displayName, 'Alt Space');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('adjacent 403 steps preserve tianaCode, Request ID, account, space, and actionable guidance (without leaking token secrets)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-adjacent-403-'));
  const binary = join(dir, 'tiana');
  const statePath = join(dir, 'state.json');
  const secretMarker = 'SECRET_TOKEN_MATERIAL_NEVER_SHOW';
  try {
    // 1. listWebAppsForOwnership (web list 403)
    writeScenarioMockTiana(binary, {
      failWebList: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'web list denied',
            http_status: 403,
            request_id: 'req-weblist-403',
          },
        },
      },
    });
    await assert.rejects(
      () => bindTianaRemoteWeb({ webId: 'fixture00001', statePath, tianaBin: binary, log: () => {} }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-weblist-403');
        assert.match(err.message, /Current Tiana CLI account: water \/ usr-water-01/u);
        assert.match(err.message, /Tiana error: HTTP 403 \/ TENANT_MANAGEMENT_FORBIDDEN/u);
        assert.match(err.message, /Request ID: req-weblist-403/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        return true;
      },
    );

    // 2. getWebBindingForOwnership (web functions get 403)
    writeScenarioMockTiana(binary, {
      failWebBindingGet: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: 'binding read denied',
            http_status: 403,
            request_id: 'req-webget-403',
          },
        },
      },
    });
    await assert.rejects(
      () => bindTianaRemoteWeb({ webId: 'fixture00001', statePath, tianaBin: binary, log: () => {} }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'AUTHORIZATION_DENIED');
        assert.equal(err.requestId, 'req-webget-403');
        assert.match(err.message, /Tiana error: HTTP 403 \/ AUTHORIZATION_DENIED/u);
        assert.match(err.message, /Request ID: req-webget-403/u);
        return true;
      },
    );

    // 3. function show 403
    writeScenarioMockTiana(binary, {
      failFunctionShow: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'cannot view function',
            http_status: 403,
            request_id: 'req-fnshow-403',
          },
        },
      },
    });
    await assert.rejects(
      () => bindTianaRemoteWeb({ webId: 'fixture00001', statePath, tianaBin: binary, log: () => {} }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-fnshow-403');
        assert.match(err.message, /tiana function show fn-relay-01/u);
        assert.match(err.message, /water \/ usr-water-01/u);
        assert.match(err.message, /Request ID：req-fnshow-403/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        return true;
      },
    );

    // 4. function parameters get & set 403
    writeScenarioMockTiana(binary, {
      failParamsGet: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'cannot read params',
            http_status: 403,
            request_id: 'req-params-get-403',
          },
        },
      },
      failParamsSet: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'cannot write params',
            http_status: 403,
            request_id: 'req-params-set-403',
          },
        },
      },
    });
    await assert.rejects(
      () => getFunctionParameters('fn-relay-01', { bin: binary }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-params-get-403');
        assert.match(err.message, /tiana function parameters get fn-relay-01/u);
        assert.match(err.message, /water \/ usr-water-01/u);
        assert.match(err.message, /Request ID：req-params-get-403/u);
        return true;
      },
    );
    await assert.rejects(
      () => setFunctionParameters('fn-relay-01', { A: { kind: 'plain', value: '1' } }, { bin: binary }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-params-set-403');
        assert.match(err.message, /tiana function parameters set fn-relay-01/u);
        assert.match(err.message, /water \/ usr-water-01/u);
        assert.match(err.message, /Request ID：req-params-set-403/u);
        return true;
      },
    );

    // 5. web functions set 403 (triggered when web has no bound function yet)
    writeScenarioMockTiana(binary, {
      webFunctionIds: [],
      failWebBindingSet: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'TENANT_MANAGEMENT_FORBIDDEN',
            message: 'cannot bind function',
            http_status: 403,
            request_id: 'req-webset-403',
          },
        },
      },
    });
    await assert.rejects(
      () => bindTianaRemoteWeb({ webId: 'fixture00001', statePath, tianaBin: binary, log: () => {} }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'TENANT_MANAGEMENT_FORBIDDEN');
        assert.equal(err.requestId, 'req-webset-403');
        assert.match(err.message, /tiana web functions set fixture00001/u);
        assert.match(err.message, /Request ID：req-webset-403/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        return true;
      },
    );

    // 6. token create 403 (preserves metadata + guidance while redacting raw secret payload!)
    writeScenarioMockTiana(binary, {
      failTokenCreate: {
        exitCode: 1,
        stdout: {
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: `denied: ${secretMarker}`,
            http_status: 403,
            request_id: 'req-token-403',
          },
        },
        stderr: `Error: status 403 ${secretMarker}\nRequest ID: req-token-403\n`,
      },
    });
    await assert.rejects(
      () => ensureHostToken({}, 'fn-relay-01', { bin: binary, log: () => {} }),
      (err) => {
        assert.equal(err.httpStatus, 403);
        assert.equal(err.tianaCode, 'AUTHORIZATION_DENIED');
        assert.equal(err.requestId, 'req-token-403');
        assert.equal(err.tianaMessage, undefined);
        assert.doesNotMatch(err.message, new RegExp(secretMarker, 'u'));
        assert.match(err.message, /tiana token create fn-relay-01/u);
        assert.match(err.message, /water \/ usr-water-01/u);
        assert.match(err.message, /Request ID：req-token-403/u);
        assert.match(err.message, /tiana logout && tiana login/u);
        return true;
      },
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cli.js status formats empty-email account (water) cleanly instead of blank', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-cli-status-empty-email-'));
  const binary = join(dir, 'tiana');
  try {
    writeScenarioMockTiana(binary, {
      statusData: {
        logged_in: true,
        user: {
          user_id: 'usr-water-01',
          tenant_id: 'ten-water-default',
          display_name: 'water',
          email: '',
        },
        space: {
          tenant_id: 'ten-water-default',
          display_name: 'Water Personal Space',
          role: 'tenant_owner',
        },
      },
    });

    const textRun = spawnSync(process.execPath, [join(PROJECT_ROOT, 'cli.js'), 'status'], {
      env: { ...process.env, HOME: dir, DSH_HOME: join(dir, '.dsh'), TIANA_BIN: binary },
      encoding: 'utf8',
    });
    assert.equal(textRun.status, 0, textRun.stderr);
    assert.match(textRun.stdout, /Tiana Login : water \(Water Personal Space\)/u);
    assert.doesNotMatch(textRun.stdout, /Tiana Login :\s+\(/u);

    const jsonRun = spawnSync(process.execPath, [join(PROJECT_ROOT, 'cli.js'), 'status', '--json'], {
      env: { ...process.env, HOME: dir, DSH_HOME: join(dir, '.dsh'), TIANA_BIN: binary },
      encoding: 'utf8',
    });
    assert.equal(jsonRun.status, 0, jsonRun.stderr);
    const parsed = JSON.parse(jsonRun.stdout);
    assert.equal(parsed.tiana.loggedIn, true);
    assert.equal(parsed.tiana.displayName, 'water');
    assert.equal(parsed.tiana.email, '');
    assert.equal(parsed.tiana.userId, 'usr-water-01');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('client.js preserves multi-line friendly 403 errors with pre-wrap and overflow-wrap', () => {
  const clientSrc = readFileSync(join(PROJECT_ROOT, 'client.js'), 'utf8');
  const errBlockMatch = /\.dshr-err\s*\{[^}]+\}/u.exec(clientSrc);
  assert.ok(errBlockMatch, '.dshr-err style block must exist');
  assert.match(errBlockMatch[0], /white-space:\s*pre-wrap/u);
  assert.match(errBlockMatch[0], /overflow-wrap:\s*anywhere/u);
  assert.match(clientSrc, /id:\s*'dshr-provision-error'/u);
});
