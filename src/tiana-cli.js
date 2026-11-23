import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { buildWebDist } from '../scripts/build-web-dist.mjs';
import {
  defaultHostIdentity,
  DEFAULT_STUN_URLS,
  detectLocalRunningHost,
  ensureE2eeConfig,
  formatLocalHostConflictError,
  generateE2eeSecret,
  isRemoteConfigured,
  loadRemoteState,
  loadRemoteStateSnapshot,
  migrateRemoteState,
  removeRemoteState,
  resolveStatePath,
  saveRemoteState,
  withStateLock,
} from './state.js';

const execFileAsync = promisify(execFile);
const PROJECT_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const RELAY_GO_DIR = join(PROJECT_ROOT, 'relay-go');

export const DEFAULT_FUNCTION_NAME = 'dsh-remote-relay';
export const DEFAULT_WEB_NAME = 'DSH Remote';
export const DEFAULT_TOKEN_NAME = 'dsh-remote-host';
const WEB_APP_OWNERSHIP_ERROR = 'Only the verified owner of this DSH Remote Web app can bind a host to it.';

export function tianaBinary(overrideBin) {
  if (typeof overrideBin === 'string' && overrideBin.trim()) return overrideBin.trim();
  return process.env.TIANA_BIN || (process.platform === 'win32' ? 'tiana.cmd' : 'tiana');
}

const TIANA_FORBIDDEN_CODES = new Set([
  'TENANT_MANAGEMENT_FORBIDDEN',
  'AUTHORIZATION_DENIED',
  'FORBIDDEN',
  'PERMISSION_DENIED',
]);

function isCredentialCommand(args) {
  return args[0] === 'token' || args[0] === 'status';
}

function sanitizeCodeToken(value, maxLen = 64) {
  const s = normalizeIdentityValue(value);
  if (!s || s.length > maxLen) return '';
  if (/^(?:dshk1_|gh[pousr]_|npm_|bearer\b)/iu.test(s)) return '';
  return /^[A-Za-z0-9_.:-]+$/u.test(s) ? s : '';
}

function parseHttpStatusValue(value) {
  const n = typeof value === 'number' ? value : Number.parseInt(String(value ?? '').trim(), 10);
  return Number.isInteger(n) && n >= 100 && n <= 599 ? n : null;
}

export function parseTianaErrorMeta({ stdout = '', stderr = '', message = '', errorObj = null, credentialCommand = false } = {}) {
  let parsedError = errorObj && typeof errorObj === 'object' ? errorObj : null;
  let parsedRoot = null;
  if (!parsedError && stdout) {
    const trimmed = String(stdout).trim();
    if (trimmed.startsWith('{')) {
      try {
        const parsed = JSON.parse(trimmed);
        if (parsed && typeof parsed === 'object') {
          parsedRoot = parsed;
          if (parsed.error && typeof parsed.error === 'object') {
            parsedError = parsed.error;
          }
        }
      } catch {
        // ignore non-JSON stdout
      }
    }
  }

  const stderrText = String(stderr || '');
  const fallbackText = stderrText || String(message || '');

  const tianaCode = sanitizeCodeToken(parsedError?.code, 64);

  let httpStatus = parseHttpStatusValue(parsedError?.http_status ?? parsedError?.status ?? parsedRoot?.http_status);
  if (!httpStatus && fallbackText) {
    const statusMatch = /\b(?:status|HTTP)\s+(\d{3})\b/iu.exec(fallbackText);
    if (statusMatch) httpStatus = parseHttpStatusValue(statusMatch[1]);
  }

  let requestId = sanitizeCodeToken(parsedError?.request_id ?? parsedRoot?.request_id, 128);
  if (!requestId && fallbackText) {
    const reqMatch = /\bRequest\s+ID\s*:\s*([A-Za-z0-9_.:-]{1,128})/iu.exec(fallbackText);
    if (reqMatch) requestId = sanitizeCodeToken(reqMatch[1], 128);
  }

  const tianaMessage = credentialCommand
    ? ''
    : normalizeIdentityValue(parsedError?.message);

  return {
    ...(tianaCode ? { tianaCode } : {}),
    ...(httpStatus ? { httpStatus } : {}),
    ...(requestId ? { requestId } : {}),
    ...(tianaMessage ? { tianaMessage } : {}),
  };
}

function attachTianaErrorMeta(err, meta, { credentialCommand = false } = {}) {
  if (!meta || typeof meta !== 'object') return err;
  if (meta.tianaCode) err.tianaCode = meta.tianaCode;
  if (meta.httpStatus) err.httpStatus = meta.httpStatus;
  if (meta.requestId) err.requestId = meta.requestId;
  if (!credentialCommand && meta.tianaMessage) err.tianaMessage = meta.tianaMessage;
  return err;
}

export function isTianaForbiddenError(err) {
  if (!err) return false;
  if (err.httpStatus === 403 || err.status === 403) return true;
  if (err.tianaCode && TIANA_FORBIDDEN_CODES.has(String(err.tianaCode).toUpperCase())) return true;
  const msg = String(err.message || err);
  return /\b(?:HTTP\s+403|status\s+403|TENANT_MANAGEMENT_FORBIDDEN|AUTHORIZATION_DENIED)\b/iu.test(msg);
}

export async function runTiana(args, options = {}) {
  const bin = tianaBinary(options.bin || options.tianaBin);
  try {
    const { stdout, stderr } = await execFileAsync(bin, args, {
      maxBuffer: 16 * 1024 * 1024,
      timeout: options.timeoutMs ?? 180_000,
      env: options.env ?? process.env,
      shell: process.platform === 'win32',
    });
    return { stdout, stderr };
  } catch (err) {
    const credentialCommand = isCredentialCommand(args);
    const meta = parseTianaErrorMeta({
      stdout: err?.stdout,
      stderr: err?.stderr,
      message: err?.message,
      credentialCommand,
    });
    let detail;
    if (credentialCommand) {
      const metaParts = [];
      if (meta.httpStatus) metaParts.push(`HTTP ${meta.httpStatus}`);
      if (meta.tianaCode) metaParts.push(meta.tianaCode);
      if (meta.requestId) metaParts.push(`Request ID: ${meta.requestId}`);
      detail = metaParts.length > 0
        ? `credential command failed (${metaParts.join(', ')})`
        : 'credential command failed';
    } else {
      const rawStderr = String(err?.stderr || '').trim();
      if (rawStderr) {
        detail = rawStderr;
      } else if (meta.tianaMessage || meta.tianaCode) {
        const metaParts = [];
        if (meta.httpStatus) metaParts.push(`HTTP ${meta.httpStatus}`);
        if (meta.tianaCode) metaParts.push(meta.tianaCode);
        if (meta.requestId) metaParts.push(`Request ID: ${meta.requestId}`);
        const base = meta.tianaMessage || meta.tianaCode;
        detail = metaParts.length > 0 ? `${base} (${metaParts.join(', ')})` : base;
      } else {
        detail = String(err?.message || err).trim();
      }
    }
    const thrown = new Error(`tiana ${args.join(' ')} failed: ${detail}`);
    throw attachTianaErrorMeta(thrown, meta, { credentialCommand });
  }
}

export async function runTianaJSON(args, options = {}) {
  const { stdout, stderr } = await runTiana(args, options);
  const trimmed = stdout.trim();
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`tiana ${args.join(' ')} returned invalid JSON`);
  }
  if (parsed?.error) {
    const credentialCommand = isCredentialCommand(args);
    const meta = parseTianaErrorMeta({
      stdout,
      stderr,
      errorObj: parsed.error,
      credentialCommand,
    });
    let msg;
    if (credentialCommand) {
      const metaParts = [];
      if (meta.httpStatus) metaParts.push(`HTTP ${meta.httpStatus}`);
      if (meta.tianaCode) metaParts.push(meta.tianaCode);
      if (meta.requestId) metaParts.push(`Request ID: ${meta.requestId}`);
      msg = metaParts.length > 0
        ? `credential command failed (${metaParts.join(', ')})`
        : 'credential command failed';
    } else {
      msg = parsed.error.message || parsed.error.code || 'unknown error';
    }
    const thrown = new Error(`tiana ${args.join(' ')} error: ${msg}`);
    throw attachTianaErrorMeta(thrown, meta, { credentialCommand });
  }
  return parsed?.data ?? parsed;
}

export async function getTianaStatus(options = {}) {
  const data = await runTianaJSON(['status', '--json'], options);
  if (!data?.logged_in || !data?.user?.user_id || !data?.user?.tenant_id) {
    throw new Error('Not logged in to Tiana. Run `tiana login` first.');
  }
  return data;
}

export async function listTianaSpaces(options = {}) {
  const data = await runTianaJSON(['space', 'list', '--json'], options);
  const rawItems = Array.isArray(data)
    ? data
    : Array.isArray(data?.items)
      ? data.items
      : Array.isArray(data?.spaces)
        ? data.spaces
        : Array.isArray(data?.tenants)
          ? data.tenants
          : [];
  return rawItems
    .map((item) => {
      if (!item || typeof item !== 'object') return null;
      const tenantId = normalizeIdentityValue(item.tenant_id ?? item.space_id ?? item.id);
      if (!tenantId) return null;
      return {
        tenantId,
        displayName: normalizeIdentityValue(item.display_name ?? item.name),
        role: normalizeIdentityValue(item.role),
        isCurrent: Boolean(item.is_current ?? item.current),
        isDefault: Boolean(item.is_default ?? item.default),
        raw: item,
      };
    })
    .filter(Boolean);
}

export async function listTianaWebApps(options = {}) {
  const data = await runTianaJSON(['web', 'list', '--json'], options);
  return Array.isArray(data?.items) ? data.items : [];
}

export async function getWebFunctionBinding(webId, options = {}) {
  const current = await runTianaJSON(['web', 'functions', 'get', webId, '--json'], options);
  const ids = Array.isArray(current?.function_instance_ids) ? current.function_instance_ids : [];
  return {
    functionInstanceIds: ids,
    projectRevision: current?.project_revision,
    canManage: current?.can_manage,
    raw: current,
  };
}

export async function getFunctionParameters(functionId, options = {}) {
  const { status = null, webId = '', ...cliOpts } = options;
  let data;
  try {
    data = await runTianaJSON(['function', 'parameters', 'get', functionId, '--json'], cliOpts);
  } catch (err) {
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana function parameters get ${functionId}`,
        resource: `Function ${functionId}`,
        webId,
        status,
        cliOpts,
      });
    }
    throw err;
  }
  const params = data?.parameters && typeof data.parameters === 'object' ? data.parameters : data;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new Error(`Unexpected function parameters response for ${functionId}`);
  }
  return params;
}

export async function setFunctionParameters(functionId, paramsObj, options = {}) {
  const { status = null, webId = '', ...cliOpts } = options;
  const temp = mkdtempSync(join(tmpdir(), 'dsh-remote-params-'));
  try {
    const paramsFile = join(temp, 'parameters.json');
    writeFileSync(paramsFile, `${JSON.stringify(paramsObj, null, 2)}\n`, { mode: 0o600 });
    try {
      return await runTianaJSON([
        'function', 'parameters', 'set',
        functionId,
        '--file', paramsFile,
        '--json',
      ], cliOpts);
    } catch (err) {
      if (isTianaForbiddenError(err)) {
        throw await buildForbiddenStepError(err, {
          command: `tiana function parameters set ${functionId}`,
          resource: `Function ${functionId}`,
          webId,
          status,
          cliOpts,
        });
      }
      throw err;
    }
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

export function buildRemotePolicy({ hostId, hostName, registrationKey, ownerUserId, ownerTenantId, webId, origin }) {
  return {
    version: 1,
    webId,
    origin,
    ownerUserId,
    ownerTenantId,
    hostId,
    hostName: hostName || hostId,
    hostDigest: createHash('sha256').update(registrationKey).digest('hex'),
    updatedAt: new Date().toISOString(),
  };
}

export function parsePolicyFromParameters(params) {
  const entry = params?.DSH_REMOTE_POLICY;
  const raw = typeof entry === 'string' ? entry : entry?.value;
  if (!raw || typeof raw !== 'string') return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Update `DSH_REMOTE_POLICY` while strictly preserving all other function parameters.
 * NEVER swallows `getFunctionParameters` errors (to prevent clobbering existing bindings or user params).
 */
export async function updateRemotePolicy(functionId, policy, { log = console.log, existingParams, ...options } = {}) {
  const existing = existingParams !== undefined
    ? existingParams
    : await getFunctionParameters(functionId, options);
  const merged = {
    ...existing,
    DSH_REMOTE_POLICY: {
      kind: 'plain',
      value: JSON.stringify(policy),
    },
  };
  log(`[dsh-remote] Updating DSH_REMOTE_POLICY on Function ${functionId} (zero recompile)...`);
  await setFunctionParameters(functionId, merged, options);
  return policy;
}

/**
 * Best-effort cleanup of cloud `DSH_REMOTE_POLICY` on unbind.
 * NEVER deletes the user's cloud Web app or Relay Function, and NEVER clears
 * a policy owned by another machine (requires exact hostId + hostDigest match).
 * Writes `{ kind: 'plain', value: '' }` for `DSH_REMOTE_POLICY` while preserving
 * all unrelated parameters so `tiana function parameters set --file` never submits
 * an empty `{}` object and `relay-go` immediately transitions to `paired: false`.
 * Swallows offline/auth/403/timeout failures and returns `{ cleared: false, warning }`.
 */
export async function clearRemotePolicyIfOwned(state, { log = console.log, ...cliOpts } = {}) {
  const functionId = state?.function?.id;
  const hostId = state?.host?.hostId;
  const registrationKey = state?.host?.registrationKey;
  if (!functionId || !hostId || !registrationKey) {
    return { cleared: false, skipped: true, reason: 'missing_local_binding', warning: '' };
  }
  const opts = { timeoutMs: 15_000, ...cliOpts };
  try {
    const existingParams = await getFunctionParameters(functionId, opts);
    const existingPolicy = parsePolicyFromParameters(existingParams);
    if (!existingPolicy) {
      return { cleared: true, alreadyCleared: true, warning: '' };
    }
    const localDigest = createHash('sha256').update(registrationKey).digest('hex');
    const webIdMismatch = Boolean(state?.web?.id && existingPolicy.webId && existingPolicy.webId !== state.web.id);
    if (existingPolicy.hostId !== hostId || existingPolicy.hostDigest !== localDigest || webIdMismatch) {
      const warning = 'Cloud Relay policy is currently owned by another host; skipped cloud policy cleanup.';
      log(`[dsh-remote] ${warning}`);
      return { cleared: false, skipped: true, reason: 'policy_not_owned', warning };
    }
    const nextParams = {
      ...existingParams,
      DSH_REMOTE_POLICY: {
        kind: 'plain',
        value: '',
      },
    };
    log(`[dsh-remote] Clearing DSH_REMOTE_POLICY on Function ${functionId} (preserving cloud Web & Function apps)...`);
    await setFunctionParameters(functionId, nextParams, opts);
    return { cleared: true, warning: '' };
  } catch (err) {
    const warning = err instanceof Error ? err.message : String(err);
    log(`[dsh-remote] Cloud policy cleanup skipped (non-fatal): ${warning}`);
    return { cleared: false, warning };
  }
}

export function validateRelayFunctionShown(fnShown) {
  const status = String(
    fnShown?.instance?.product_state ??
    fnShown?.instance?.status ??
    fnShown?.function?.status ??
    fnShown?.product_state ??
    fnShown?.status ??
    '',
  ).trim().toUpperCase();
  if (status !== 'ACTIVE') {
    throw new Error(`Relay Function must be ACTIVE (got "${status || 'unknown'}")`);
  }
  if (fnShown?.instance?.enabled === false) {
    throw new Error('Relay Function is disabled');
  }
  if (fnShown?.instance?.deletion_pending === true) {
    throw new Error('Relay Function is pending deletion');
  }
  const fnUrl = fnShown?.instance?.connection?.url || fnShown?.instance?.url || '';
  if (!fnUrl) {
    throw new Error('Relay Function requires an active HTTPS endpoint');
  }
  let parsed;
  try {
    parsed = new URL(fnUrl);
  } catch {
    throw new Error('Relay Function endpoint URL is invalid');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error('Relay Function requires an active HTTPS endpoint without credentials');
  }
  return fnUrl;
}

export async function verifyRelayHealth(fnUrl, token, options = {}) {
  if (typeof options.probeRelayHealth === 'function') {
    const res = await options.probeRelayHealth(fnUrl, token);
    if (!res || res.ok !== true || typeof res.paired !== 'boolean') {
      throw new Error('Target Function /healthz did not confirm a valid DSH Remote Relay');
    }
    return res;
  }
  const healthUrl = new URL('/healthz', fnUrl);
  if (healthUrl.protocol !== 'https:' || healthUrl.username || healthUrl.password) {
    throw new Error('Relay health probe requires HTTPS URL');
  }
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const resp = await fetch(healthUrl, {
    headers,
    redirect: 'error',
    signal: AbortSignal.timeout(options.healthTimeoutMs ?? 10_000),
  });
  if (!resp.ok) {
    throw new Error(`Target Function /healthz returned HTTP ${resp.status}; verify this is a DSH Remote Relay`);
  }
  let body;
  try {
    body = await resp.json();
  } catch {
    throw new Error('Target Function /healthz did not return JSON; verify this is a DSH Remote Relay');
  }
  if (body?.ok !== true || typeof body?.paired !== 'boolean') {
    throw new Error('Target Function /healthz payload does not match DSH Remote Relay contract');
  }
  return body;
}

export function buildActiveHostOnlineError({
  webId = '',
  functionId = '',
  hostId = '',
  hostName = '',
  updatedAt = '',
} = {}) {
  const displayName = hostName || hostId || 'unknown';
  const idPart = hostId ? ` (${hostId})` : '';
  const err = new Error(
    `检测到该云端 Relay 当前已有活跃宿主 "${displayName}${idPart}" 在线，请先停止旧宿主再重新设置。` +
    `如确认旧宿主已失联需要强制接管，请使用 --force-rebind（将强制轮换 registrationKey 使旧凭据立即失效）。\n` +
    `Active host "${displayName}"${idPart} is currently connected to this Relay. ` +
    `Stop the active host before re-initializing, or pass --force-rebind to force takeover and rotate registrationKey.`,
  );
  err.code = 'ACTIVE_HOST_ONLINE';
  err.status = 409;
  err.details = {
    code: 'ACTIVE_HOST_ONLINE',
    webId,
    functionId,
    hostConnected: true,
    hostId: hostId || '',
    hostName: displayName,
    updatedAt: updatedAt || '',
  };
  return err;
}

export async function probeRelayHostStatus(fnUrl, token, {
  existingPolicy = null,
  registrationKey = '',
  hostId = '',
  webId = '',
  fetchFn = fetch,
  probeRelayHostStatus: customProbe,
  allowInsecureLoopback = false,
  statusTimeoutMs = 10_000,
} = {}) {
  if (typeof customProbe === 'function') {
    return await customProbe(fnUrl, token, { existingPolicy, registrationKey, hostId, webId });
  }
  const statusUrl = new URL('/host-status', fnUrl);
  const isLoopbackHttp = allowInsecureLoopback && statusUrl.protocol === 'http:' &&
    ['127.0.0.1', '[::1]', 'localhost'].includes(statusUrl.hostname);
  if ((statusUrl.protocol !== 'https:' && !isLoopbackHttp) || statusUrl.username || statusUrl.password) {
    throw new Error('Relay host status probe requires HTTPS URL');
  }
  const targetHostId = existingPolicy?.hostId || hostId || '';
  if (targetHostId) {
    statusUrl.searchParams.set('host_id', targetHostId);
  }
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (existingPolicy?.hostDigest) {
    headers['Dsh-Host-Policy-Digest'] = existingPolicy.hostDigest;
  }
  if (existingPolicy?.webId || webId) {
    headers['Dsh-Host-Web-Id'] = existingPolicy?.webId || webId;
  }
  if (registrationKey) {
    headers['Dsh-Host-Registration'] = registrationKey;
  }
  const resp = await fetchFn(statusUrl, {
    method: 'GET',
    headers,
    redirect: 'error',
    signal: AbortSignal.timeout(statusTimeoutMs),
  });
  if (resp.status === 404) {
    return {
      supported: false,
      ok: false,
      paired: Boolean(existingPolicy),
      hostConnected: false,
      hostId: existingPolicy?.hostId || '',
      hostName: existingPolicy?.hostName || '',
      updatedAt: existingPolicy?.updatedAt || '',
    };
  }
  if (resp.status === 403) {
    return {
      supported: true,
      authorized: false,
      ok: false,
      status: 403,
      paired: Boolean(existingPolicy),
      hostConnected: false,
      hostId: existingPolicy?.hostId || '',
      hostName: existingPolicy?.hostName || '',
      updatedAt: existingPolicy?.updatedAt || '',
    };
  }
  if (!resp.ok) {
    return {
      supported: true,
      ok: false,
      status: resp.status,
      paired: Boolean(existingPolicy),
      hostConnected: false,
      hostId: existingPolicy?.hostId || '',
      hostName: existingPolicy?.hostName || '',
      updatedAt: existingPolicy?.updatedAt || '',
    };
  }
  const body = await resp.json().catch(() => null);
  return {
    supported: true,
    ok: body?.ok !== false,
    paired: Boolean(body?.paired),
    hostConnected: Boolean(body?.hostConnected),
    hostId: body?.hostId || existingPolicy?.hostId || '',
    hostName: body?.hostName || existingPolicy?.hostName || '',
    updatedAt: body?.updatedAt || existingPolicy?.updatedAt || '',
  };
}

async function showRelayFunction(functionId, { status = null, webId = '', ...cliOpts } = {}) {
  try {
    return await runTianaJSON(['function', 'show', functionId, '--json'], cliOpts);
  } catch (err) {
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana function show ${functionId}`,
        resource: `Function ${functionId}`,
        webId,
        status,
        cliOpts,
      });
    }
    throw err;
  }
}

async function ensureRelayFunction({ functionName, functionId, status = null, webId = '', log = console.log, ...cliOpts }) {
  if (functionId) {
    log(`[dsh-remote] Reusing configured Function ${functionId}`);
    const shown = await showRelayFunction(functionId, { status, webId, ...cliOpts });
    return { instance: shown.instance };
  }

  log(`[dsh-remote] Creating Function "${functionName}"...`);
  let created;
  try {
    created = await runTianaJSON([
      'function', 'create', '--wait',
      '-m', 'DSH Remote WebSocket rendezvous relay',
      '--json',
      functionName,
    ], { ...cliOpts, timeoutMs: 240_000 });
  } catch (err) {
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana function create ${functionName}`,
        resource: `Function "${functionName}"`,
        webId,
        status,
        cliOpts,
      });
    }
    throw err;
  }
  const createdId = created?.instance_id || created?.instance?.id || created?.id;
  if (!createdId) {
    throw new Error(`Unexpected function create response: ${JSON.stringify(created)}`);
  }
  const shown = await showRelayFunction(createdId, { status, webId, ...cliOpts });
  return { instance: shown?.instance ?? { id: createdId, display_name: functionName }, details: shown?.function ?? {}, release: shown?.release };
}

async function syncAndPublishRelayFunction(functionId, webId, { forcePublish = false, status = null, log = console.log, ...cliOpts } = {}) {
  const goModPath = join(RELAY_GO_DIR, 'go.mod');
  const desiredGoMod = readFileSync(goModPath, 'utf8');
  const template = readFileSync(join(RELAY_GO_DIR, 'main.go'), 'utf8');
  const marker = 'var defaultWebID = ""';
  const desiredMainGo = webId && template.includes(marker)
    ? template.replace(marker, () => `var defaultWebID = ${JSON.stringify(webId)}`)
    : template;

  const sourceView = await runTianaJSON(['function', 'source', 'list', functionId, '--json'], cliOpts);
  const needsInitial = Boolean(sourceView?.needs_initial_source) || !sourceView?.commit;

  let sameSource = false;
  if (!needsInitial) {
    try {
      const [curMod, curMain] = await Promise.all([
        runTiana(['function', 'source', 'read', functionId, 'go.mod'], cliOpts),
        runTiana(['function', 'source', 'read', functionId, 'main.go'], cliOpts),
      ]);
      sameSource = curMod.stdout === desiredGoMod && curMain.stdout === desiredMainGo;
    } catch {
      sameSource = false;
    }
  }

  let commit = sourceView?.commit || '';
  if (!sameSource) {
    log(`[dsh-remote] Uploading Go relay source to ${functionId}...`);
    const baseCommit = needsInitial ? 'empty' : commit;
    const temp = mkdtempSync(join(tmpdir(), 'dsh-remote-relay-'));
    try {
      const mainGoPath = join(temp, 'main.go');
      writeFileSync(mainGoPath, desiredMainGo, { mode: 0o600 });
      const saved = await runTianaJSON([
        'function', 'source', 'save',
        '--base-commit', baseCommit,
        '--file', `go.mod=${goModPath}`,
        '--file', `main.go=${mainGoPath}`,
        '--json', functionId,
      ], cliOpts);
      if (!saved?.commit) throw new Error('Function source save returned no commit');
      commit = saved.commit;
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  } else {
    log(`[dsh-remote] Function source is up to date (${commit.slice(0, 8)}).`);
  }

  async function isPublished(info) {
    const published = info?.release?.published;
    if (!published?.id) return false;
    const builds = await runTianaJSON(['function', 'builds', '--json', functionId], cliOpts);
    return Boolean(builds?.items?.some((build) => build.id === published.id &&
      build.source_commit === commit && build.build_commit === published.build_commit));
  }
  const shown = await showRelayFunction(functionId, { status, webId, ...cliOpts });
  if (!forcePublish && sameSource && await isPublished(shown)) {
    log('[dsh-remote] The configured relay source is already published');
    return shown;
  }

  log(`[dsh-remote] Building & publishing Function ${functionId}...`);
  await runTianaJSON(['function', 'publish', '--commit', commit, '--wait', '--json', functionId],
    { ...cliOpts, timeoutMs: 300_000 });
  const deployed = await showRelayFunction(functionId, { status, webId, ...cliOpts });
  if (!(await isPublished(deployed))) throw new Error('The relay release does not match the configured source');
  return deployed;
}

export async function ensureHostToken(state, functionId, { rotateToken = false, status = null, webId = '', log = console.log, ...cliOpts } = {}) {
  const now = Math.floor(Date.now() / 1000);
  if (!rotateToken && state?.function?.id === functionId && state?.function?.token &&
      state.function.expiresAt > now + 86400) {
    const { token, tokenId, expiresAt } = state.function;
    return { token, tokenId, expiresAt };
  }
  const expiresAt = now + 30 * 86400;
  const tokenName = `${DEFAULT_TOKEN_NAME}-${Date.now()}`;
  log(`[dsh-remote] Creating instance access token for ${functionId}...`);
  let receipt;
  try {
    receipt = await runTianaJSON([
      'token', 'create',
      '--name', tokenName,
      '--expires-at', String(expiresAt),
      '--json',
      functionId,
    ], cliOpts);
  } catch (err) {
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana token create ${functionId}`,
        resource: `Function ${functionId}`,
        webId,
        status,
        cliOpts,
        credentialCommand: true,
      });
    }
    throw err;
  }
  if (!receipt?.token) {
    throw new Error('Instance Token receipt was missing its credential');
  }
  return { token: receipt.token, tokenId: receipt.token_id || '', expiresAt };
}

async function ensureWebApp({ webName, webId, status, log = console.log, ...cliOpts }) {
  requireTianaSpaceMatch(status, { webId });
  if (webId) {
    const items = await listWebAppsForOwnership(webId, status, cliOpts);
    const existing = items.find((item) => item.id === webId);
    if (!existing) throw webAppNotFound(webId, status);
    return existing;
  }
  log(`[dsh-remote] Creating Web app "${webName}"...`);
  let created;
  try {
    created = await runTianaJSON([
      'web', 'create',
      '--entry', 'dsh-remote-entry.mjs',
      '--description', 'DeepSeek Harness 远程访问入口（由 @tianacloud/dsh-remote 自动编排）',
      '--json',
      webName,
    ], cliOpts);
  } catch (err) {
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana web create ${webName}`,
        resource: `Web "${webName}"`,
        status,
        cliOpts,
      });
    }
    throw err;
  }
  const createdApp = created?.project ?? created?.app ?? created;
  if (createdApp?.id && !normalizeIdentityValue(createdApp.owner_id) && !normalizeIdentityValue(createdApp.tenant_id)) {
    const items = await listWebAppsForOwnership(createdApp.id, status, cliOpts);
    const listed = items.find((item) => item.id === createdApp.id);
    if (listed) return listed;
  }
  return createdApp;
}

function normalizeIdentityValue(value) {
  return value == null ? '' : String(value).trim();
}

export function formatTianaAccount(userOrStatus, { includeUserId = true } = {}) {
  const user = userOrStatus?.user && typeof userOrStatus.user === 'object'
    ? userOrStatus.user
    : userOrStatus;
  const displayName = normalizeIdentityValue(user?.display_name ?? user?.displayName);
  const email = normalizeIdentityValue(user?.email);
  const userId = normalizeIdentityValue(user?.user_id ?? user?.userId);
  const parts = [];
  for (const item of includeUserId ? [displayName, email, userId] : [displayName, email]) {
    if (item && !parts.includes(item)) parts.push(item);
  }
  if (parts.length > 0) return parts.join(' / ');
  if (userId) return userId;
  return '(unknown)';
}

export function formatTianaSpace(statusOrSpace) {
  const user = statusOrSpace?.user && typeof statusOrSpace.user === 'object' ? statusOrSpace.user : null;
  const space = statusOrSpace?.space && typeof statusOrSpace.space === 'object'
    ? statusOrSpace.space
    : (user ? null : statusOrSpace);
  const spaceId = normalizeIdentityValue(space?.tenant_id ?? space?.space_id ?? space?.id) ||
    normalizeIdentityValue(user?.tenant_id ?? user?.tenantId);
  const parts = [];
  for (const item of [
    normalizeIdentityValue(space?.display_name ?? space?.name),
    spaceId,
    normalizeIdentityValue(space?.role),
  ]) {
    if (item && !parts.includes(item)) parts.push(item);
  }
  return parts.join(' / ') || '(unknown)';
}

function buildConnectRetryCommand({ webId = '', spaceId = '', rebind = false, forceRebind = false } = {}) {
  const parts = ['npx', '--yes', '@tianacloud/dsh-remote@latest', 'connect'];
  if (webId) parts.push('--app', webId);
  if (spaceId) parts.push('--space', spaceId);
  if (rebind) parts.push('--rebind');
  if (forceRebind) parts.push('--force-rebind');
  return parts.join(' ');
}

function formatAccessibleSpaceEntry(space, currentSpaceId = '') {
  const id = space.tenantId;
  const label = space.displayName ? `${space.displayName} (${id})` : id;
  const tags = [];
  if (space.role) tags.push(space.role);
  if (space.isCurrent || (currentSpaceId && id === currentSpaceId)) tags.push('当前');
  if (space.isDefault) tags.push('默认');
  return tags.length > 0 ? `${label} [${tags.join(', ')}]` : label;
}

async function buildSpaceSwitchForbiddenError(err, {
  spaceId,
  webId = '',
  status = null,
  rebind = false,
  forceRebind = false,
  cliOpts = {},
} = {}) {
  const httpStatus = err?.httpStatus || 403;
  const code = err?.tianaCode || 'FORBIDDEN';
  const requestId = err?.requestId || '';
  const currentSpaceId = normalizeIdentityValue(status?.space?.tenant_id) || normalizeIdentityValue(status?.user?.tenant_id);
  const accountText = formatTianaAccount(status, { includeUserId: true });
  const spaceText = formatTianaSpace(status);
  const retryCmd = buildConnectRetryCommand({ webId, spaceId, rebind, forceRebind });

  let spacesFetched = false;
  let accessibleSpaces = [];
  try {
    accessibleSpaces = await listTianaSpaces({ ...cliOpts, timeoutMs: cliOpts.timeoutMs ?? 15_000 });
    spacesFetched = true;
  } catch {
    spacesFetched = false;
    accessibleSpaces = [];
  }

  const matchedSpace = spacesFetched
    ? accessibleSpaces.find((item) => item.tenantId === spaceId) || null
    : null;

  const lines = [
    `无法切换到目标 Tiana 空间 "${spaceId}"（HTTP ${httpStatus} / ${code}）。`,
    `当前本机 CLI 账号：${accountText}`,
    `当前空间：${spaceText}`,
    `目标空间 ID：${spaceId}${matchedSpace?.displayName ? ` (${matchedSpace.displayName})` : ''}${matchedSpace?.role ? ` [${matchedSpace.role}]` : ''}`,
  ];
  if (webId) {
    lines.push(`目标 Web 应用：${webId}`);
  }
  if (!matchedSpace) {
    if (spacesFetched) {
      if (accessibleSpaces.length > 0) {
        lines.push(`当前账号可访问的空间（共 ${accessibleSpaces.length} 个）：`);
        for (const item of accessibleSpaces) {
          lines.push(`  - ${formatAccessibleSpaceEntry(item, currentSpaceId)}`);
        }
      } else {
        lines.push('当前账号可访问的空间：（无）');
      }
    } else {
      lines.push('当前账号可访问的空间：（自动查询 `tiana space list` 失败，可手动运行 `tiana space list` 核对）');
    }
  }
  if (requestId) {
    lines.push(`Request ID：${requestId}`);
  }

  lines.push('');
  if (matchedSpace) {
    lines.push('原因：目标空间在当前账号的可访问空间列表中，但切换仍返回 HTTP 403，可能是空间成员状态或当前 CLI 会话权限已变更。');
    lines.push('下一步指引：');
    lines.push(`1. 运行 \`tiana login\` 刷新当前登录会话后重试：${retryCmd}`);
    lines.push('2. 若刷新登录后仍然 403，请联系目标空间管理员确认您的成员状态与角色权限。');
  } else {
    if (spacesFetched) {
      lines.push('原因：该空间不在当前登录账号的可访问列表中，最常见原因是本机 Tiana CLI 登录的账号，与浏览器中安装该应用的账号不一致。');
    } else {
      lines.push('原因：当前登录账号无权切换到目标空间，最常见原因是本机 Tiana CLI 登录的账号，与浏览器中安装该应用的账号不一致。');
    }
    lines.push('下一步指引：');
    lines.push(`1. 若账号不一致：先运行 \`tiana logout && tiana login\` 登录安装该应用的账号，然后重新运行：${retryCmd}`);
    lines.push('2. 若确认是同一账号：请联系目标空间管理员将当前账号邀请加入空间后重试，或核对应用所在空间 ID。');
  }

  const wrapped = new Error(lines.join('\n'));
  wrapped.code = err?.tianaCode || 'TIANA_FORBIDDEN';
  if (err?.tianaCode) wrapped.tianaCode = err.tianaCode;
  wrapped.httpStatus = httpStatus;
  if (requestId) wrapped.requestId = requestId;
  wrapped.status = 403;
  return wrapped;
}

async function buildForbiddenStepError(err, {
  command,
  resource = '',
  webId = '',
  status = null,
  cliOpts = {},
  credentialCommand = false,
} = {}) {
  const httpStatus = err?.httpStatus || 403;
  const code = err?.tianaCode || 'FORBIDDEN';
  const requestId = err?.requestId || '';

  let effectiveStatus = status;
  if (!effectiveStatus) {
    try {
      effectiveStatus = await getTianaStatus({ ...cliOpts, timeoutMs: Math.min(cliOpts.timeoutMs ?? 10_000, 10_000) });
    } catch {
      effectiveStatus = null;
    }
  }

  const accountText = formatTianaAccount(effectiveStatus, { includeUserId: true });
  const spaceText = formatTianaSpace(effectiveStatus);

  const lines = [
    `执行 \`${command}\` 被拒绝（HTTP ${httpStatus} / ${code}）。`,
    `当前本机 CLI 账号：${accountText}`,
    `当前空间：${spaceText}`,
  ];
  if (resource) lines.push(`目标资源：${resource}`);
  if (webId) lines.push(`目标 Web 应用：${webId}`);
  if (requestId) lines.push(`Request ID：${requestId}`);
  lines.push(
    '',
    '原因：当前登录的 Tiana CLI 账号或空间角色无权执行此操作（常见原因：本机 CLI 登录账号与资源所属账号不一致，或在当前空间缺少管理权限）。',
    '下一步指引：',
    '1. 运行 `tiana status` 核对当前本机 CLI 账号与空间。',
    '2. 若账号不一致，请先运行 `tiana logout && tiana login` 切换为资源所属账号后重试。',
    '3. 若确认是同一账号，请联系空间管理员确认角色权限，或通过 `tiana space list` / `tiana space switch <spaceId>` 确认空间后重试。',
  );

  const wrapped = new Error(lines.join('\n'));
  wrapped.code = err?.tianaCode || 'TIANA_FORBIDDEN';
  if (err?.tianaCode) wrapped.tianaCode = err.tianaCode;
  wrapped.httpStatus = httpStatus;
  if (requestId) wrapped.requestId = requestId;
  if (!credentialCommand && err?.tianaMessage) wrapped.tianaMessage = err.tianaMessage;
  wrapped.status = 403;
  return wrapped;
}

function formatOwnershipError(baseMsg, { webId, status, webApp, binding, reason, err } = {}) {
  const accountText = formatTianaAccount(status, { includeUserId: true });
  const spaceText = formatTianaSpace(status);
  if (!reason) {
    if (binding?.canManage === false) reason = '`tiana web functions get` returned `can_manage: false`.';
    else if (binding?.canManage == null) reason = '`tiana web functions get` did not return `can_manage`.';
    else reason = '`tiana web functions get` did not return `can_manage: true`.';
  }

  const lines = [
    baseMsg,
    `Current Tiana CLI account: ${accountText}`,
    `Current Tiana space: ${spaceText}`,
    `Target Web app: ${webId || webApp?.id || '(unknown)'}`,
    `Reason: ${reason}`,
  ];
  if (err && (isTianaForbiddenError(err) || err.tianaCode || err.requestId)) {
    const statusPart = err.httpStatus ? `HTTP ${err.httpStatus}` : (isTianaForbiddenError(err) ? 'HTTP 403' : '');
    const codePart = err.tianaCode || (isTianaForbiddenError(err) ? 'FORBIDDEN' : '');
    const errSummary = [statusPart, codePart].filter(Boolean).join(' / ');
    if (errSummary) lines.push(`Tiana error: ${errSummary}`);
    if (err.requestId) lines.push(`Request ID: ${err.requestId}`);
  }
  lines.push(
    '',
    'Run `tiana status` to verify the active Tiana CLI account and space.',
    'If you are signed in with a different account, run `tiana logout && tiana login` and sign in as the Web app owner.',
    'If you are in a different space, run `tiana space list`, then `tiana space switch <spaceId>`, or pass `--space <spaceId>` to `dsh-remote connect`.',
  );
  return lines.join('\n');
}

function webAppNotFound(webId, status) {
  return new Error(formatOwnershipError(`Web app "${webId}" was not found in the current Tiana space.`, {
    webId, status, reason: '`tiana web list` did not include this Web app.',
  }));
}

async function listWebAppsForOwnership(webId, status, cliOpts) {
  try {
    return await listTianaWebApps(cliOpts);
  } catch (err) {
    const wrapped = new Error(formatOwnershipError(`Could not look up Web app "${webId}" in the current Tiana space.`, {
      webId,
      status,
      reason: '`tiana web list` failed to retrieve Web apps in the active space.',
      err,
    }));
    if (err?.httpStatus) wrapped.httpStatus = err.httpStatus;
    if (err?.tianaCode) wrapped.tianaCode = err.tianaCode;
    if (err?.requestId) wrapped.requestId = err.requestId;
    if (isTianaForbiddenError(err)) {
      wrapped.status = 403;
      wrapped.code = err?.tianaCode || 'TIANA_FORBIDDEN';
    }
    throw wrapped;
  }
}

async function getWebBindingForOwnership(webId, status, cliOpts) {
  try {
    return await getWebFunctionBinding(webId, cliOpts);
  } catch (err) {
    const wrapped = new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, {
      webId,
      status,
      reason: '`tiana web functions get` failed to retrieve the app’s management permissions.',
      err,
    }));
    if (err?.httpStatus) wrapped.httpStatus = err.httpStatus;
    if (err?.tianaCode) wrapped.tianaCode = err.tianaCode;
    if (err?.requestId) wrapped.requestId = err.requestId;
    if (isTianaForbiddenError(err)) {
      wrapped.status = 403;
      wrapped.code = err?.tianaCode || 'TIANA_FORBIDDEN';
    }
    throw wrapped;
  }
}

function requireTianaSpaceMatch(status, { webId, webApp, errorMessage } = {}) {
  const spaceTenantId = normalizeIdentityValue(status?.space?.tenant_id);
  if (spaceTenantId && spaceTenantId !== normalizeIdentityValue(status?.user?.tenant_id)) {
    throw new Error(formatOwnershipError(errorMessage || WEB_APP_OWNERSHIP_ERROR, {
      webId, webApp, status, reason: 'The space `tenant_id` in Tiana status does not match the account `tenant_id`.',
    }));
  }
}

export function verifyWebAppOwnership(webApp, status, { binding = null, requireBindingProof = false, errorMessage } = {}) {
  const reject = (reason) => {
    throw new Error(formatOwnershipError(errorMessage || WEB_APP_OWNERSHIP_ERROR, { webApp, status, binding, reason }));
  };
  const expectedUserId = normalizeIdentityValue(status?.user?.user_id);
  const expectedTenantId = normalizeIdentityValue(status?.user?.tenant_id);
  if (!expectedUserId || !expectedTenantId) {
    reject('Tiana login status is missing `user_id` or `tenant_id`.');
  }

  // Explicit management denial ALWAYS rejects fail-closed, even when webApp.owner_id matches.
  if (binding?.canManage === false) {
    reject();
  }

  requireTianaSpaceMatch(status, { webApp, errorMessage });

  const webTenantId = normalizeIdentityValue(webApp?.tenant_id);
  if (webTenantId && webTenantId !== expectedTenantId) {
    reject('The Web app `tenant_id` does not match the active Tiana account `tenant_id`.');
  }

  const webOwnerId = normalizeIdentityValue(webApp?.owner_id);
  if (webOwnerId) {
    if (webOwnerId !== expectedUserId) {
      reject('The Web app `owner_id` does not match the active Tiana account `user_id`.');
    }
    return { mode: 'owner_id', verified: true };
  }

  // Online `web list --json` can return an empty owner_id. MGR's `web functions get`
  // can_manage supplies Web app management proof. status.space.can_manage reflects
  // multi-member team management and is false in standard personal default spaces.
  if (!webTenantId) {
    reject('The Web app is missing `tenant_id` and has no `owner_id`.');
  }
  if (!requireBindingProof) return { mode: 'tenant_pending_manage_proof', verified: false };
  if (binding?.canManage !== true) reject();
  return { mode: 'tenant_can_manage', verified: true };
}

async function revalidateWebAppAuthorization(webId, {
  expectedTenantId = '',
  expectedUserId = '',
  cliOpts = {},
  fallbackWebApp = null,
  allowCreatedFallback = false,
} = {}) {
  const latestStatus = await getTianaStatus(cliOpts);
  if (expectedTenantId && latestStatus.user.tenant_id !== expectedTenantId) {
    throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, {
      webId, status: latestStatus, reason: 'The active Tiana space changed while verifying the Web app.',
    }));
  }
  if (expectedUserId && latestStatus.user.user_id !== expectedUserId) {
    throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, {
      webId, status: latestStatus, reason: 'The active Tiana CLI account changed while verifying the Web app.',
    }));
  }
  requireTianaSpaceMatch(latestStatus, { webId });

  const latestWebApps = await listWebAppsForOwnership(webId, latestStatus, cliOpts);
  const listedWebApp = latestWebApps.find((item) => item.id === webId);
  if (!listedWebApp) {
    if (!allowCreatedFallback || !fallbackWebApp || latestWebApps.length > 0) {
      throw webAppNotFound(webId, latestStatus);
    }
    // An earlier `web create` response needs fresh proof from `web functions get`
    // when `web list` is empty, including when the create response had an owner_id.
    const latestBinding = await getWebBindingForOwnership(webId, latestStatus, cliOpts);
    if (latestBinding?.canManage !== true) {
      throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, { webId, status: latestStatus, binding: latestBinding }));
    }
    verifyWebAppOwnership(fallbackWebApp, latestStatus, {
      binding: latestBinding,
      requireBindingProof: true,
    });
    if (fallbackWebApp.enabled === false) {
      throw new Error(`Web app "${webId}" is disabled.`);
    }
    if (fallbackWebApp.deletion_pending === true) {
      throw new Error(`Web app "${webId}" is pending deletion.`);
    }
    const latestWebUrl = validateWebEndpoint(fallbackWebApp, webId);
    return {
      status: latestStatus,
      webApp: fallbackWebApp,
      webUrl: latestWebUrl,
      binding: latestBinding,
      requiresManageProof: true,
    };
  }

  verifyWebAppOwnership(listedWebApp, latestStatus);
  if (listedWebApp.enabled === false) {
    throw new Error(`Web app "${webId}" is disabled.`);
  }
  if (listedWebApp.deletion_pending === true) {
    throw new Error(`Web app "${webId}" is pending deletion.`);
  }
  const latestWebUrl = validateWebEndpoint(listedWebApp, webId);

  const latestBinding = await getWebBindingForOwnership(webId, latestStatus, cliOpts);
  const verified = verifyWebAppOwnership(listedWebApp, latestStatus, {
    binding: latestBinding,
    requireBindingProof: true,
  });
  return {
    status: latestStatus,
    webApp: listedWebApp,
    webUrl: latestWebUrl,
    binding: latestBinding,
    requiresManageProof: verified.mode !== 'owner_id',
  };
}

async function ensureWebFunctionBinding(webId, functionId, {
  adoptExisting = false,
  requireManage = false,
  initialBinding = null,
  revalidate = null,
  status,
  log = console.log,
  ...cliOpts
} = {}) {
  let current = initialBinding;
  if (!current) {
    if (typeof revalidate === 'function') {
      const fresh = await revalidate();
      current = fresh.binding;
      requireManage = fresh.requiresManageProof;
      status = fresh.status;
    } else {
      current = await getWebBindingForOwnership(webId, status, cliOpts);
    }
  }
  if (current.canManage === false || (requireManage && current.canManage !== true)) {
    throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, { webId, status, binding: current }));
  }
  const bound = current.functionInstanceIds;
  if (bound.length === 1 && bound[0] === functionId) {
    return functionId;
  }
  if (adoptExisting && bound[0]) {
    log(`[dsh-remote] Adopting existing Relay Function ${bound[0]} already bound to Web ${webId}`);
    return bound[0];
  }
  const revision = current.projectRevision;
  if (!revision) {
    throw new Error(`Missing project_revision from web functions get: ${JSON.stringify(current.raw)}`);
  }
  log(`[dsh-remote] Binding Function ${functionId} -> Web ${webId} (rev ${revision})...`);
  try {
    await runTianaJSON([
      'web', 'functions', 'set',
      '--expected-revision', String(revision),
      '--function-id', functionId,
      '--json',
      webId,
    ], cliOpts);
    return functionId;
  } catch (err) {
    if (adoptExisting) {
      let rechecked;
      let recheckedRequireManage = requireManage;
      if (typeof revalidate === 'function') {
        const fresh = await revalidate();
        rechecked = fresh.binding;
        recheckedRequireManage = fresh.requiresManageProof;
        status = fresh.status;
      } else {
        rechecked = await getWebBindingForOwnership(webId, status, cliOpts);
      }
      if (rechecked.canManage === false || (recheckedRequireManage && rechecked.canManage !== true)) {
        throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, { webId, status, binding: rechecked }));
      }
      if (rechecked.functionInstanceIds[0]) {
        log(`[dsh-remote] Adopting Relay Function ${rechecked.functionInstanceIds[0]} bound concurrently to Web ${webId}`);
        return rechecked.functionInstanceIds[0];
      }
    }
    if (isTianaForbiddenError(err)) {
      throw await buildForbiddenStepError(err, {
        command: `tiana web functions set ${webId}`,
        resource: `Web ${webId} -> Function ${functionId}`,
        webId,
        status,
        cliOpts,
      });
    }
    throw err;
  }
}

function validateWebEndpoint(webApp, webId) {
  const webUrl = new URL(webApp.endpoint || `https://${webId}.tianacloud.site/web/${webId}/`);
  if (webUrl.protocol !== 'https:' || webUrl.username || webUrl.password || webUrl.search ||
      webUrl.hash || webUrl.pathname !== `/web/${webId}/`) {
    throw new Error('Invalid Web app entrypoint');
  }
  return webUrl;
}

export function hasBindingIdentityConflict(existingPolicy, { hostId, registrationKey, hostPublicKey = '' }) {
  if (!existingPolicy || typeof existingPolicy !== 'object') return false;
  if (!existingPolicy.hostId && !existingPolicy.hostDigest && !existingPolicy.hostPublicKey) return false;

  if (existingPolicy.hostId && existingPolicy.hostId !== hostId) {
    return true;
  }
  const localDigest = registrationKey
    ? createHash('sha256').update(registrationKey).digest('hex')
    : '';
  if (existingPolicy.hostDigest && existingPolicy.hostDigest !== localDigest) {
    return true;
  }
  if (existingPolicy.hostPublicKey && existingPolicy.hostPublicKey !== hostPublicKey) {
    return true;
  }
  return false;
}

/**
 * Zero-recompile binding to an existing Tiana Web app (e.g. installed from Tiana Marketplace).
 * Writes DSH_REMOTE_POLICY via `tiana function parameters set` without rebuilding Go or .tweb.
 *
 * Transactional safety:
 * 1. Validates account and space IDs and checks ownership. A non-empty `owner_id` must match the
 *    account `user_id`. An empty `owner_id` requires a matching non-empty Web app `tenant_id` and
 *    MGR's Web app `can_manage: true` from `tiana web functions get`. `status.space.can_manage`
 *    describes multi-member team management and is false in ordinary personal default spaces.
 * 2. Validates Relay Function is ACTIVE, HTTPS, and passes `/healthz` check.
 * 3. Reads existing function parameters strictly (never swallows errors).
 * 4. Checks rebind conflict across hostId + hostDigest + hostPublicKey.
 * 5. Mints/confirms token and writes local checkpoint BEFORE updating cloud `DSH_REMOTE_POLICY`.
 * 6. Commits final state under `withStateLock` while preserving concurrent local settings edits.
 */
export async function bindTianaRemoteWeb(options = {}) {
  const log = options.log ?? console.log;
  const webId = String(options.webId || '').trim();
  const statePath = options.statePath;
  const cliOpts = options.tianaBin ? { bin: options.tianaBin } : {};

  if (!/^[a-z][a-z0-9]{11}$/u.test(webId)) {
    throw new Error(`Invalid Tiana Web app ID: ${webId || '(empty)'}`);
  }

  // Local preflight: refuse initializing/binding if another live local dsh-remote host process is active
  if (!options.skipLocalPreflight && !options.forceRebind) {
    const localHost = detectLocalRunningHost({
      statePath,
      runtimePath: options.runtimePath,
      currentPid: options.currentPid ?? process.pid,
      isAlive: options.isPidAlive,
      readRuntime: options.readRuntime,
      readBridgeOwner: options.readBridgeOwner,
    });
    if (localHost.running) {
      throw formatLocalHostConflictError(localHost);
    }
  }

  let status = await getTianaStatus(cliOpts);
  if (options.spaceId && status.user.tenant_id !== options.spaceId) {
    log(`[dsh-remote] Switching Tiana space to ${options.spaceId}...`);
    try {
      await runTianaJSON(['space', 'switch', options.spaceId, '--json'], cliOpts);
    } catch (err) {
      if (isTianaForbiddenError(err)) {
        throw await buildSpaceSwitchForbiddenError(err, {
          spaceId: options.spaceId,
          webId,
          status,
          rebind: Boolean(options.rebind),
          forceRebind: Boolean(options.forceRebind),
          cliOpts,
        });
      }
      throw err;
    }
    status = await getTianaStatus(cliOpts);
  }
  if (!status?.user?.user_id || !status?.user?.tenant_id) {
    throw new Error('Tiana login status is missing user_id or tenant_id.');
  }
  if (options.spaceId && status.user.tenant_id !== options.spaceId) {
    throw new Error(`Failed to switch Tiana space to "${options.spaceId}".`);
  }

  requireTianaSpaceMatch(status, { webId });
  const targetTenantId = options.spaceId || status.user.tenant_id;
  const targetUserId = status.user.user_id;
  const webApps = await listWebAppsForOwnership(webId, status, cliOpts);
  let webApp = webApps.find((item) => item.id === webId);
  if (!webApp) {
    throw webAppNotFound(webId, status);
  }
  verifyWebAppOwnership(webApp, status);
  if (webApp.enabled === false) {
    throw new Error(`Web app "${webId}" is disabled.`);
  }
  if (webApp.deletion_pending === true) {
    throw new Error(`Web app "${webId}" is pending deletion.`);
  }
  let webUrl = validateWebEndpoint(webApp, webId);

  // Locate bound Relay Function (and verify can_manage proof when owner_id is empty) before any mutation
  const binding = await getWebBindingForOwnership(webId, status, cliOpts);
  verifyWebAppOwnership(webApp, status, {
    binding,
    requireBindingProof: true,
  });

  const revalidateBindAuth = () => revalidateWebAppAuthorization(webId, {
    expectedTenantId: targetTenantId,
    expectedUserId: targetUserId,
    cliOpts,
  });

  const initialState = await withStateLock(() => {
    const raw = loadRemoteState(statePath);
    return raw ? migrateRemoteState(raw) : {};
  }, statePath);

  const identity = defaultHostIdentity();
  const initialHostId = options.hostId || initialState.host?.hostId || identity.hostId;
  if (!/^[a-z0-9_-]{1,48}$/u.test(initialHostId)) throw new Error('Invalid host ID');

  let fnId = binding.functionInstanceIds[0] || '';
  let fnShown = null;
  if (fnId) {
    fnShown = await showRelayFunction(fnId, { status, webId, ...cliOpts });
  } else {
    log(`[dsh-remote] Web app ${webId} has no bound Relay Function; provisioning generic relay-go...`);
    const created = await ensureRelayFunction({
      functionName: options.functionName || DEFAULT_FUNCTION_NAME,
      status,
      webId,
      log,
      ...cliOpts,
    });
    fnId = created.instance.id;
    fnShown = await syncAndPublishRelayFunction(fnId, webId, { status, log, ...cliOpts });
    const boundFnId = await ensureWebFunctionBinding(webId, fnId, {
      adoptExisting: true,
      revalidate: revalidateBindAuth,
      status,
      log,
      ...cliOpts,
    });
    if (boundFnId !== fnId) {
      fnId = boundFnId;
      fnShown = await showRelayFunction(fnId, { status, webId, ...cliOpts });
    }
  }

  let fnUrl = validateRelayFunctionShown(fnShown);

  const initialPendingBind = initialState.pendingBind?.functionId === fnId && initialState.pendingBind?.webId === webId
    ? initialState.pendingBind
    : null;
  let preLockToken = initialState.function?.id === fnId ? initialState.function : null;
  const tokenSeedState = (initialState.function?.id === fnId && initialState.function?.token &&
    (!initialPendingBind?.tokenInfo?.token || Number(initialState.function.expiresAt) >= Number(initialPendingBind.tokenInfo.expiresAt)))
    ? initialState
    : (initialPendingBind?.tokenInfo ? { function: initialPendingBind.tokenInfo } : initialState);
  const seedToken = tokenSeedState?.function?.id === fnId ? tokenSeedState.function : null;

  // Step A: Mint or confirm Function Instance Token BEFORE mutating cloud policy
  let tokenInfo = await ensureHostToken(
    tokenSeedState,
    fnId,
    { rotateToken: Boolean(options.rotateToken), status, webId, log, ...cliOpts },
  );
  let mintedNewToken = tokenInfo.token !== seedToken?.token;

  // Step B: Verify target Function /healthz confirms a valid DSH Remote Relay
  let healthResult = await verifyRelayHealth(fnUrl, tokenInfo.token, options);

  // Serialize the cloud-read + conflict-check + pendingBind checkpoint + policy write + state commit
  // across local processes so concurrent binds can never produce a local/cloud hostDigest mismatch.
  const bindLockPath = `${resolveStatePath(statePath)}.bind`;
  return await withStateLock(async () => {
    const prevState = await withStateLock(() => {
      const raw = loadRemoteState(statePath);
      return raw ? migrateRemoteState(raw) : {};
    }, statePath);

    // Re-verify fresh status, Web app ownership metadata, and active Relay Function binding under lock
    const freshAuth = await revalidateBindAuth();
    status = freshAuth.status;
    webApp = freshAuth.webApp;
    webUrl = freshAuth.webUrl;
    const activeBinding = freshAuth.binding;
    let activeFnId = activeBinding.functionInstanceIds[0] || '';
    if (!activeFnId) {
      activeFnId = await ensureWebFunctionBinding(webId, fnId, {
        adoptExisting: true,
        initialBinding: activeBinding,
        requireManage: freshAuth.requiresManageProof,
        revalidate: revalidateBindAuth,
        status,
        log,
        ...cliOpts,
      });
    }
    if (activeFnId && activeFnId !== fnId) {
      fnId = activeFnId;
      fnShown = await showRelayFunction(fnId, { status, webId, ...cliOpts });
      fnUrl = validateRelayFunctionShown(fnShown);
      preLockToken = prevState.function?.id === fnId ? prevState.function : null;
      tokenInfo = await ensureHostToken(prevState, fnId, {
        rotateToken: Boolean(options.rotateToken),
        status,
        webId,
        log,
        ...cliOpts,
      });
      mintedNewToken = tokenInfo.token !== preLockToken?.token;
      healthResult = await verifyRelayHealth(fnUrl, tokenInfo.token, options);
    }

    const hostId = options.hostId || prevState.host?.hostId || identity.hostId;
    const hostName = options.hostName || prevState.host?.hostName || identity.hostName;
    if (!/^[a-z0-9_-]{1,48}$/u.test(hostId)) throw new Error('Invalid host ID');

    // Strictly read fresh existing function parameters (NEVER swallow failure!)
    const existingParams = await getFunctionParameters(fnId, { status, webId, ...cliOpts });
    const existingPolicy = parsePolicyFromParameters(existingParams);

    const pendingBind = prevState.pendingBind?.functionId === fnId && prevState.pendingBind?.webId === webId
      ? prevState.pendingBind
      : null;

    // Cloud online preflight: block binding/re-init if ANY active host is currently connected to the Relay
    let hostStatus = null;
    if (typeof options.probeRelayHostStatus === 'function') {
      hostStatus = await options.probeRelayHostStatus(fnUrl, tokenInfo.token, {
        existingPolicy,
        registrationKey: prevState.host?.registrationKey || pendingBind?.registrationKey || '',
        hostId: existingPolicy?.hostId || hostId,
        webId,
      });
    } else if (typeof options.probeRelayHealth === 'function') {
      if (typeof healthResult?.hostConnected === 'boolean') {
        hostStatus = {
          supported: true,
          ok: true,
          paired: Boolean(healthResult.paired),
          hostConnected: healthResult.hostConnected,
          hostId: healthResult.hostId || existingPolicy?.hostId || '',
          hostName: healthResult.hostName || existingPolicy?.hostName || '',
          updatedAt: healthResult.updatedAt || existingPolicy?.updatedAt || '',
        };
      }
    } else if (healthResult?.paired || existingPolicy) {
      try {
        hostStatus = await probeRelayHostStatus(fnUrl, tokenInfo.token, {
          existingPolicy,
          registrationKey: prevState.host?.registrationKey || pendingBind?.registrationKey || '',
          hostId: existingPolicy?.hostId || hostId,
          webId,
          fetchFn: options.fetchFn,
          allowInsecureLoopback: options.allowInsecureLoopback,
          statusTimeoutMs: options.statusTimeoutMs,
        });
      } catch (err) {
        log(`[dsh-remote] Warning: /host-status preflight check failed (${err instanceof Error ? err.message : String(err)}); continuing with policy verification.`);
      }
    }

    if (hostStatus?.hostConnected === true) {
      const activeHostId = hostStatus.hostId || existingPolicy?.hostId || hostId;
      const activeHostName = hostStatus.hostName || existingPolicy?.hostName || activeHostId;
      if (!options.forceRebind) {
        throw buildActiveHostOnlineError({
          webId,
          functionId: fnId,
          hostId: activeHostId,
          hostName: activeHostName,
          updatedAt: hostStatus.updatedAt || existingPolicy?.updatedAt || '',
        });
      }
      log(`[dsh-remote] --force-rebind enabled: forcing takeover from active host "${activeHostName} (${activeHostId})" and rotating registrationKey...`);
    }

    const localPubKey = prevState.host?.publicKey || prevState.hostSigningKeyPair?.publicKey || '';
    const matchesPrevHost = !hasBindingIdentityConflict(existingPolicy, {
      hostId,
      registrationKey: prevState.host?.registrationKey || '',
      hostPublicKey: localPubKey,
    });
    const matchesPendingBind = Boolean(pendingBind) && !hasBindingIdentityConflict(existingPolicy, {
      hostId: pendingBind.hostId || hostId,
      registrationKey: pendingBind.registrationKey || '',
      hostPublicKey: localPubKey,
    });
    const conflict = !matchesPrevHost && !matchesPendingBind;

    let rotatedRegistration = Boolean(options.forceRebind);
    if (conflict) {
      if (!options.rebind && !options.forceRebind) {
        if (typeof options.confirmRebind === 'function') {
          const ok = await options.confirmRebind(existingPolicy, { hostId, hostName });
          if (!ok) throw new Error('Rebind cancelled by user.');
        } else {
          throw new Error(
            `Web app ${webId} is already bound to "${existingPolicy.hostName || existingPolicy.hostId}" (${existingPolicy.hostId}). Pass --rebind to switch to this host.`,
          );
        }
      }
      rotatedRegistration = true;
    }

    const reusePending = Boolean(pendingBind) && (matchesPendingBind || !prevState.host?.registrationKey);
    let registrationKey;
    if (rotatedRegistration) {
      do {
        registrationKey = generateE2eeSecret();
      } while (registrationKey === prevState.host?.registrationKey || registrationKey === pendingBind?.registrationKey);
    } else {
      registrationKey = ((reusePending ? pendingBind?.registrationKey : prevState.host?.registrationKey) ||
        pendingBind?.registrationKey ||
        prevState.host?.registrationKey ||
        generateE2eeSecret());
    }
    const baseE2eeSource = prevState.e2ee?.secret
      ? prevState
      : (pendingBind?.e2ee?.secret ? { e2ee: pendingBind.e2ee } : prevState);
    const { e2ee } = ensureE2eeConfig(baseE2eeSource, { rotate: Boolean(options.rotateE2eeKey) });

    const bindStartToken = prevState.function?.id === fnId ? prevState.function : null;
    let activeTokenInfo = tokenInfo;
    if (!options.rotateToken &&
        prevState.function?.id === fnId &&
        prevState.function?.token &&
        (Number(prevState.function.expiresAt) > Number(tokenInfo.expiresAt) ||
          (Number(prevState.function.expiresAt) === Number(tokenInfo.expiresAt) &&
            (!mintedNewToken || prevState.function.token !== preLockToken?.token)))) {
      activeTokenInfo = {
        token: prevState.function.token,
        tokenId: prevState.function.tokenId,
        expiresAt: prevState.function.expiresAt,
      };
    } else if (!options.rotateToken &&
        pendingBind?.tokenInfo?.token &&
        Number(pendingBind.tokenInfo.expiresAt) > Number(tokenInfo.expiresAt)) {
      activeTokenInfo = {
        token: pendingBind.tokenInfo.token,
        tokenId: pendingBind.tokenInfo.tokenId,
        expiresAt: pendingBind.tokenInfo.expiresAt,
      };
    }

    // Step C: Save local recovery checkpoint under lock BEFORE mutating cloud DSH_REMOTE_POLICY
    await withStateLock(() => {
      const raw = loadRemoteState(statePath) || {};
      saveRemoteState({
        ...raw,
        pendingBind: {
          webId,
          functionId: fnId,
          hostId,
          hostName,
          registrationKey,
          e2ee,
          tokenInfo: { ...activeTokenInfo, id: fnId },
          createdAt: new Date().toISOString(),
        },
      }, statePath);
    }, statePath);

    // Step D: Write DSH_REMOTE_POLICY using verified existingParams (preserving unrelated params)
    const policy = buildRemotePolicy({
      hostId,
      hostName,
      registrationKey,
      ownerUserId: status.user.user_id,
      ownerTenantId: status.user.tenant_id,
      webId,
      origin: webUrl.origin,
    });
    await updateRemotePolicy(fnId, policy, { existingParams, status, webId, log, ...cliOpts });

    // Step E: Atomically commit final state under lock, merging concurrent settings, key rotation, and token renewals
    const committedState = await withStateLock(() => {
      const latestRaw = loadRemoteState(statePath);
      const latest = latestRaw ? migrateRemoteState(latestRaw) : prevState;
      const committedE2ee = (!options.rotateE2eeKey && latest.e2ee?.secret && latest.e2ee.secret !== prevState.e2ee?.secret)
        ? latest.e2ee
        : e2ee;
      const keepLatestToken = !options.rotateToken &&
        latest.function?.id === fnId &&
        latest.function?.token &&
        (Number(latest.function.expiresAt) > Number(activeTokenInfo.expiresAt) ||
          (Number(latest.function.expiresAt) === Number(activeTokenInfo.expiresAt) &&
            (latest.function.token !== bindStartToken?.token ||
              (!mintedNewToken && latest.function.token !== activeTokenInfo.token))));
      const committedToken = keepLatestToken
        ? { token: latest.function.token, tokenId: latest.function.tokenId, expiresAt: latest.function.expiresAt }
        : activeTokenInfo;
      const wasConfigured = isRemoteConfigured(prevState);
      const nextState = {
        version: 2,
        configVersion: 2,
        enabled: wasConfigured && latest.enabled !== undefined ? latest.enabled : true,
        updatedAt: new Date().toISOString(),
        owner: {
          userId: status.user.user_id,
          tenantId: status.user.tenant_id,
          email: status.user.email,
          displayName: status.user.display_name,
          spaceName: status.space?.display_name || '',
        },
        host: {
          hostId,
          hostName,
          registrationKey,
        },
        e2ee: committedE2ee,
        function: {
          id: fnId,
          name: fnShown?.instance?.display_name || fnShown?.instance?.name || DEFAULT_FUNCTION_NAME,
          url: fnUrl,
          token: committedToken.token,
          tokenId: committedToken.tokenId,
          expiresAt: committedToken.expiresAt,
        },
        web: {
          id: webId,
          name: webApp.name || DEFAULT_WEB_NAME,
          endpoint: webUrl.href,
        },
        network: latest.network || {
          p2pEnabled: true,
          stunUrls: [...DEFAULT_STUN_URLS],
        },
      };
      saveRemoteState(nextState, statePath);
      return nextState;
    }, statePath);

    return committedState;
  }, bindLockPath, { timeoutMs: options.bindLockTimeoutMs ?? 30_000 });
}

/**
 * Provision or reuse the Tiana Function Relay + Token + .tweb App in the logged-in user's space.
 * Uploads generic relay-go once and writes DSH_REMOTE_POLICY via function parameters (zero recompile on updates).
 */
export async function provisionTianaRemote(options = {}) {
  const log = options.log ?? console.log;
  const functionName = options.functionName || DEFAULT_FUNCTION_NAME;
  const webName = options.webName || DEFAULT_WEB_NAME;
  const statePath = options.statePath;
  const cliOpts = options.tianaBin ? { bin: options.tianaBin } : {};

  if (!options.skipLocalPreflight && !options.forceRebind) {
    const localHost = detectLocalRunningHost({
      statePath,
      runtimePath: options.runtimePath,
      currentPid: options.currentPid ?? process.pid,
      isAlive: options.isPidAlive,
      readRuntime: options.readRuntime,
      readBridgeOwner: options.readBridgeOwner,
    });
    if (localHost.running) {
      throw formatLocalHostConflictError(localHost);
    }
  }

  let status = await getTianaStatus(cliOpts);
  const resolvedStatePath = resolveStatePath(statePath);
  const bindLockPath = `${resolvedStatePath}.bind`;
  const canonicalJson = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item)).join(',')}]`;
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  };
  const hasIndependentState = (obj) => {
    if (!obj || typeof obj !== 'object') return false;
    for (const [key, val] of Object.entries(obj)) {
      if (val === undefined) continue;
      if (key === 'pendingSetup') {
        if (val && typeof val === 'object' && Object.keys(val).length > 0) return true;
        continue;
      }
      return true;
    }
    return false;
  };
  return await withStateLock(async () => {
    const { prevState, hadInitialFile, initialSnapshot, initialRawBytes, initialPendingSetup } = await withStateLock(() => {
      const snap = loadRemoteStateSnapshot(resolvedStatePath);
      return {
        prevState: snap?.state ? structuredClone(snap.state) : {},
        hadInitialFile: snap !== null,
        initialSnapshot: snap?.state ? structuredClone(snap.state) : null,
        initialRawBytes: snap?.rawBytes ?? null,
        initialPendingSetup: snap?.state?.pendingSetup !== undefined
          ? structuredClone(snap.state.pendingSetup)
          : undefined,
      };
    }, statePath);
    let lastWrittenPendingSetup = null;
    const restoreInitialState = async () => {
      if (lastWrittenPendingSetup === null) return;
      await withStateLock(() => {
        const current = loadRemoteState(resolvedStatePath);
        if (!current) return;
        if (canonicalJson(current.pendingSetup) === canonicalJson(lastWrittenPendingSetup)) {
          if (initialPendingSetup !== undefined) {
            current.pendingSetup = structuredClone(initialPendingSetup);
          } else {
            delete current.pendingSetup;
          }
        }
        if (!hadInitialFile) {
          if (!hasIndependentState(current)) {
            removeRemoteState(resolvedStatePath);
          } else {
            saveRemoteState(current, resolvedStatePath);
          }
          return;
        }
        if (canonicalJson(current) === canonicalJson(initialSnapshot)) {
          saveRemoteState(initialSnapshot, resolvedStatePath, {
            rawBytes: initialRawBytes,
            preserveUpdatedAt: true,
          });
        } else {
          saveRemoteState(current, resolvedStatePath);
        }
      }, statePath);
    };

    const pending = { ...(prevState.pendingSetup || {}) };
    const identity = defaultHostIdentity();
    const hostId = options.hostId || prevState.host?.hostId || pending.hostId || identity.hostId;
    const hostName = options.hostName || prevState.host?.hostName || identity.hostName;

    if (!/^[a-z0-9_-]{1,48}$/u.test(hostId)) throw new Error('Invalid host ID');
    const configuredWebId = prevState.web?.id || pending.webId;
    const previousOwner = prevState.owner || pending.owner;
    if ((previousOwner?.userId && previousOwner.userId !== status.user.user_id) ||
        (previousOwner?.tenantId && previousOwner.tenantId !== status.user.tenant_id)) {
      throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, {
        webId: configuredWebId, status, reason: 'Use the Tiana account and space that originally configured this DSH host.',
      }));
    }
    if ((prevState.host?.hostId || pending.hostId || hostId) !== hostId) {
      throw new Error('This installation is already bound to a different host ID');
    }
    const baseE2eeSource = prevState.e2ee?.secret
      ? prevState
      : (pending.e2ee ? { e2ee: pending.e2ee } : prevState);
    const { e2ee } = ensureE2eeConfig(baseE2eeSource, {
      rotate: (!pending.e2ee && prevState.version !== 2) || Boolean(options.rotateE2eeKey),
    });
    const registrationKey = prevState.host?.registrationKey || pending.registrationKey || generateE2eeSecret();
    const owner = { userId: status.user.user_id, tenantId: status.user.tenant_id };
    const checkpoint = async (fields) => {
      Object.assign(pending, fields);
      const snapshotPending = structuredClone(pending);
      await withStateLock(() => {
        const current = loadRemoteState(resolvedStatePath) || {};
        saveRemoteState({ ...current, pendingSetup: snapshotPending }, resolvedStatePath);
      }, statePath);
      lastWrittenPendingSetup = snapshotPending;
    };

    const hadExistingWebId = Boolean(configuredWebId);
    let webApp = await ensureWebApp({ webName, webId: configuredWebId, status, log, ...cliOpts });
    const webId = webApp?.id;
    if (!/^[a-z][a-z0-9]{11}$/u.test(webId || '')) throw new Error('Invalid Web app ID');
    verifyWebAppOwnership(webApp, status);
    if (webApp.enabled === false) {
      throw new Error(`Web app "${webId}" is disabled.`);
    }
    if (webApp.deletion_pending === true) {
      throw new Error(`Web app "${webId}" is pending deletion.`);
    }
    let webUrl = validateWebEndpoint(webApp, webId);
    let webEndpoint = webUrl.href;
    // Always query web functions binding during preflight (even when owner_id matches)
    // so an explicit can_manage: false rejects before creating/publishing a Relay Function or minting a token.
    const initialBinding = await getWebBindingForOwnership(webId, status, cliOpts);
    verifyWebAppOwnership(webApp, status, {
      binding: initialBinding,
      requireBindingProof: true,
    });
    await checkpoint({ webId, owner, hostId, registrationKey, e2ee });

    const { instance: fnInstance } = await ensureRelayFunction({
      functionName, functionId: prevState.function?.id || pending.functionId, status, webId, log, ...cliOpts,
    });
    if (!fnInstance?.id) throw new Error('Missing configured Function ID');
    await checkpoint({ functionId: fnInstance.id });

    // Build and validate the browser package in an isolated temporary directory (never pollutes repo!)
    const distTemp = mkdtempSync(join(tmpdir(), 'dsh-remote-web-dist-'));
    try {
      const built = buildWebDist({
        outDir: distTemp,
        config: {
          functionId: fnInstance.id,
          webId,
          defaultHostId: hostId,
          appTitle: `${webName} · ${hostName}`,
        },
      });
      log(`[dsh-remote] Built .tweb bundle (${built.fileCount} files, ${(built.totalBytes / 1024).toFixed(1)} KiB). Publishing to ${webId}...`);

      // Refresh Web authorization after local build work and BEFORE remote Relay upload/publish or token minting.
      let preRelayAuth;
      try {
        preRelayAuth = await revalidateWebAppAuthorization(webId, {
          expectedTenantId: owner.tenantId,
          expectedUserId: owner.userId,
          cliOpts,
          fallbackWebApp: hadExistingWebId ? null : webApp,
          allowCreatedFallback: !hadExistingWebId,
        });
      } catch (err) {
        await restoreInitialState();
        throw err;
      }
      status = preRelayAuth.status;
      webApp = preRelayAuth.webApp;
      webUrl = preRelayAuth.webUrl;
      webEndpoint = webUrl.href;

      const fnShown = await syncAndPublishRelayFunction(fnInstance.id, webId, {
        forcePublish: Boolean(options.forcePublish), status, log, ...cliOpts,
      });
      const fnUrl = fnShown?.instance?.connection?.url || fnShown?.instance?.url || fnInstance.connection?.url || fnInstance.url;
      if (!fnUrl || new URL(fnUrl).protocol !== 'https:') throw new Error('Function requires an HTTPS endpoint');

      // Mint token and checkpoint BEFORE mutating cloud policy
      const tokenSeedState = (prevState.function?.id === fnInstance.id && prevState.function?.token &&
        (!pending.tokenInfo?.token || Number(prevState.function.expiresAt) >= Number(pending.tokenInfo.expiresAt)))
        ? prevState
        : (pending.tokenInfo ? { function: pending.tokenInfo } : prevState);
      const tokenInfo = await ensureHostToken(tokenSeedState, fnInstance.id, {
        rotateToken: Boolean(options.rotateToken), status, webId, log, ...cliOpts,
      });
      await checkpoint({ tokenInfo: { ...tokenInfo, id: fnInstance.id } });

      // Revalidate fresh status, Web app ownership metadata, and management proof BEFORE writing
      // DSH_REMOTE_POLICY, binding the Function, publishing the Web app, or committing local state.
      let freshAuth;
      try {
        freshAuth = await revalidateWebAppAuthorization(webId, {
          expectedTenantId: owner.tenantId,
          expectedUserId: owner.userId,
          cliOpts,
          fallbackWebApp: hadExistingWebId ? null : webApp,
          allowCreatedFallback: !hadExistingWebId,
        });
      } catch (err) {
        await restoreInitialState();
        throw err;
      }
      status = freshAuth.status;
      webApp = freshAuth.webApp;
      webUrl = freshAuth.webUrl;
      webEndpoint = webUrl.href;

      const existingParams = await getFunctionParameters(fnInstance.id, { status, webId, ...cliOpts });
      const existingPolicy = parsePolicyFromParameters(existingParams);

      // Cloud online preflight before mutating DSH_REMOTE_POLICY
      let setupHostStatus = null;
      if (typeof options.probeRelayHostStatus === 'function') {
        setupHostStatus = await options.probeRelayHostStatus(fnUrl, tokenInfo.token, {
          existingPolicy,
          registrationKey,
          hostId: existingPolicy?.hostId || hostId,
          webId,
        });
      } else if (existingPolicy) {
        let isInvalidTestHost = false;
        try {
          isInvalidTestHost = new URL(fnUrl).hostname.endsWith('.invalid');
        } catch {
          isInvalidTestHost = true;
        }
        if (!isInvalidTestHost) {
          try {
            setupHostStatus = await probeRelayHostStatus(fnUrl, tokenInfo.token, {
              existingPolicy,
              registrationKey,
              hostId: existingPolicy.hostId || hostId,
              webId,
              fetchFn: options.fetchFn,
              allowInsecureLoopback: options.allowInsecureLoopback,
              statusTimeoutMs: options.statusTimeoutMs,
            });
          } catch (err) {
            log(`[dsh-remote] Warning: /host-status preflight check failed (${err instanceof Error ? err.message : String(err)}); continuing.`);
          }
        }
      }

      if (setupHostStatus?.hostConnected === true && !options.forceRebind) {
        await restoreInitialState();
        throw buildActiveHostOnlineError({
          webId,
          functionId: fnInstance.id,
          hostId: setupHostStatus.hostId || existingPolicy?.hostId || hostId,
          hostName: setupHostStatus.hostName || existingPolicy?.hostName || hostId,
          updatedAt: setupHostStatus.updatedAt || existingPolicy?.updatedAt || '',
        });
      }

      let effectiveRegistrationKey = registrationKey;
      if (options.forceRebind) {
        do {
          effectiveRegistrationKey = generateE2eeSecret();
        } while (effectiveRegistrationKey === registrationKey || effectiveRegistrationKey === prevState.host?.registrationKey);
        log('[dsh-remote] --force-rebind enabled: rotated registrationKey to invalidate any prior host credentials.');
      }

      const policy = buildRemotePolicy({
        hostId,
        hostName,
        registrationKey: effectiveRegistrationKey,
        ownerUserId: status.user.user_id,
        ownerTenantId: status.user.tenant_id,
        webId,
        origin: webUrl.origin,
      });

      await updateRemotePolicy(fnInstance.id, policy, { existingParams, status, webId, log, ...cliOpts });
      await ensureWebFunctionBinding(webId, fnInstance.id, {
        initialBinding: freshAuth.binding,
        requireManage: freshAuth.requiresManageProof,
        status,
        log,
        ...cliOpts,
      });

      let publishResult;
      try {
        publishResult = await runTianaJSON([
          'web', 'publish',
          '--dir', distTemp,
          '--json',
          webId,
        ], { ...cliOpts, timeoutMs: 240_000 });
      } catch (err) {
        if (isTianaForbiddenError(err)) {
          throw await buildForbiddenStepError(err, {
            command: `tiana web publish ${webId}`,
            resource: `Web ${webId}`,
            webId,
            status,
            cliOpts,
          });
        }
        throw err;
      }

      const nextState = await withStateLock(() => {
        const latestRaw = loadRemoteState(statePath) || prevState;
        const migrated = migrateRemoteState(latestRaw) || {};
        const committedE2ee = (!options.rotateE2eeKey && migrated.e2ee?.secret && migrated.e2ee.secret !== prevState.e2ee?.secret)
          ? migrated.e2ee
          : e2ee;
        const keepLatestToken = !options.rotateToken &&
          migrated.function?.id === fnInstance.id &&
          migrated.function?.token &&
          (Number(migrated.function.expiresAt) > Number(tokenInfo.expiresAt) ||
            (Number(migrated.function.expiresAt) === Number(tokenInfo.expiresAt) &&
              migrated.function.token !== prevState.function?.token));
        const committedToken = keepLatestToken
          ? { token: migrated.function.token, tokenId: migrated.function.tokenId, expiresAt: migrated.function.expiresAt }
          : tokenInfo;
        const wasConfigured = isRemoteConfigured(prevState);
        const finalState = {
          version: 2,
          configVersion: 2,
          enabled: wasConfigured && migrated.enabled !== undefined ? migrated.enabled : true,
          updatedAt: new Date().toISOString(),
          owner: {
            userId: status.user.user_id,
            tenantId: status.user.tenant_id,
            email: status.user.email,
            displayName: status.user.display_name,
            spaceName: status.space?.display_name || '',
          },
          host: {
            hostId,
            hostName,
            registrationKey: effectiveRegistrationKey,
          },
          e2ee: committedE2ee,
          function: {
            id: fnInstance.id,
            name: fnInstance.display_name || fnInstance.name || functionName,
            url: fnUrl,
            token: committedToken.token,
            tokenId: committedToken.tokenId,
            expiresAt: committedToken.expiresAt,
          },
          web: {
            id: webId,
            name: webApp.name || webName,
            endpoint: webEndpoint,
            lastPublish: publishResult,
          },
          network: migrated.network || {
            p2pEnabled: true,
            stunUrls: [...DEFAULT_STUN_URLS],
          },
        };
        saveRemoteState(finalState, statePath);
        return finalState;
      }, statePath);

      return nextState;
    } finally {
      rmSync(distTemp, { recursive: true, force: true });
    }
  }, bindLockPath, { timeoutMs: options.bindLockTimeoutMs ?? 300_000 });
}

export async function republishWebShell(state, { log = console.log, ...cliOpts } = {}) {
  if (!state?.web?.id || !state?.function?.id) {
    throw new Error('Remote web app is not configured.');
  }
  const webId = state.web.id;
  const distTemp = mkdtempSync(join(tmpdir(), 'dsh-remote-web-republish-'));
  try {
    const built = buildWebDist({
      outDir: distTemp,
      config: {
        functionId: state.function.id,
        webId,
        defaultHostId: state.host?.hostId || '',
        appTitle: `${state.web.name || DEFAULT_WEB_NAME} · ${state.host?.hostName || state.host?.hostId || 'DSH'}`,
      },
    });
    log(`[dsh-remote] Rebuilt .tweb bundle (${built.fileCount} files, ${(built.totalBytes / 1024).toFixed(1)} KiB). Publishing...`);
    try {
      return await runTianaJSON(['web', 'publish', '--dir', distTemp, '--json', webId], { ...cliOpts, timeoutMs: 240_000 });
    } catch (err) {
      if (isTianaForbiddenError(err)) {
        throw await buildForbiddenStepError(err, {
          command: `tiana web publish ${webId}`,
          resource: `Web ${webId}`,
          webId,
          cliOpts,
        });
      }
      throw err;
    }
  } finally {
    rmSync(distTemp, { recursive: true, force: true });
  }
}
