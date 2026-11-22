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
    const detail = args[0] === 'token' || args[0] === 'status'
      ? 'credential command failed'
      : String(err?.stderr || err?.message || err).trim();
    throw new Error(`tiana ${args.join(' ')} failed: ${detail}`);
  }
}

export async function runTianaJSON(args, options = {}) {
  const { stdout } = await runTiana(args, options);
  const trimmed = stdout.trim();
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`tiana ${args.join(' ')} returned invalid JSON`);
  }
  if (parsed?.error) {
    const credentialCommand = args[0] === 'token' || args[0] === 'status';
    const msg = credentialCommand ? 'credential command failed'
      : parsed.error.message || parsed.error.code || 'unknown error';
    throw new Error(`tiana ${args.join(' ')} error: ${msg}`);
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
  const data = await runTianaJSON(['function', 'parameters', 'get', functionId, '--json'], options);
  const params = data?.parameters && typeof data.parameters === 'object' ? data.parameters : data;
  if (!params || typeof params !== 'object' || Array.isArray(params)) {
    throw new Error(`Unexpected function parameters response for ${functionId}`);
  }
  return params;
}

export async function setFunctionParameters(functionId, paramsObj, options = {}) {
  const temp = mkdtempSync(join(tmpdir(), 'dsh-remote-params-'));
  try {
    const paramsFile = join(temp, 'parameters.json');
    writeFileSync(paramsFile, `${JSON.stringify(paramsObj, null, 2)}\n`, { mode: 0o600 });
    return await runTianaJSON([
      'function', 'parameters', 'set',
      functionId,
      '--file', paramsFile,
      '--json',
    ], options);
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

async function ensureRelayFunction({ functionName, functionId, log = console.log, ...cliOpts }) {
  if (functionId) {
    log(`[dsh-remote] Reusing configured Function ${functionId}`);
    const shown = await runTianaJSON(['function', 'show', functionId, '--json'], cliOpts);
    return { instance: shown.instance };
  }

  log(`[dsh-remote] Creating Function "${functionName}"...`);
  const created = await runTianaJSON([
    'function', 'create', '--wait',
    '-m', 'DSH Remote WebSocket rendezvous relay',
    '--json',
    functionName,
  ], { ...cliOpts, timeoutMs: 240_000 });
  const createdId = created?.instance_id || created?.instance?.id || created?.id;
  if (!createdId) {
    throw new Error(`Unexpected function create response: ${JSON.stringify(created)}`);
  }
  const shown = await runTianaJSON(['function', 'show', createdId, '--json'], cliOpts);
  return { instance: shown?.instance ?? { id: createdId, display_name: functionName }, details: shown?.function ?? {}, release: shown?.release };
}

async function syncAndPublishRelayFunction(functionId, webId, { forcePublish = false, log = console.log, ...cliOpts } = {}) {
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
  const shown = await runTianaJSON(['function', 'show', functionId, '--json'], cliOpts);
  if (!forcePublish && sameSource && await isPublished(shown)) {
    log('[dsh-remote] The configured relay source is already published');
    return shown;
  }

  log(`[dsh-remote] Building & publishing Function ${functionId}...`);
  await runTianaJSON(['function', 'publish', '--commit', commit, '--wait', '--json', functionId],
    { ...cliOpts, timeoutMs: 300_000 });
  const deployed = await runTianaJSON(['function', 'show', functionId, '--json'], cliOpts);
  if (!(await isPublished(deployed))) throw new Error('The relay release does not match the configured source');
  return deployed;
}

export async function ensureHostToken(state, functionId, { rotateToken = false, log = console.log, ...cliOpts } = {}) {
  const now = Math.floor(Date.now() / 1000);
  if (!rotateToken && state?.function?.id === functionId && state?.function?.token &&
      state.function.expiresAt > now + 86400) {
    const { token, tokenId, expiresAt } = state.function;
    return { token, tokenId, expiresAt };
  }
  const expiresAt = now + 30 * 86400;
  const tokenName = `${DEFAULT_TOKEN_NAME}-${Date.now()}`;
  log(`[dsh-remote] Creating instance access token for ${functionId}...`);
  const receipt = await runTianaJSON([
    'token', 'create',
    '--name', tokenName,
    '--expires-at', String(expiresAt),
    '--json',
    functionId,
  ], cliOpts);
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
  const created = await runTianaJSON([
    'web', 'create',
    '--entry', 'dsh-remote-entry.mjs',
    '--description', 'DeepSeek Harness 远程访问入口（由 @tianacloud/dsh-remote 自动编排）',
    '--json',
    webName,
  ], cliOpts);
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

function formatOwnershipError(baseMsg, { webId, status, webApp, binding, reason }) {
  const { user, space } = status ?? {};
  const account = [user?.display_name, user?.email, user?.user_id].map(normalizeIdentityValue).filter(Boolean);
  const spaceId = normalizeIdentityValue(space?.tenant_id) || normalizeIdentityValue(user?.tenant_id);
  const currentSpace = [space?.display_name, spaceId, space?.role].map(normalizeIdentityValue).filter(Boolean);
  if (!reason) {
    if (binding?.canManage === false) reason = '`tiana web functions get` returned `can_manage: false`.';
    else if (binding?.canManage == null) reason = '`tiana web functions get` did not return `can_manage`.';
    else reason = '`tiana web functions get` did not return `can_manage: true`.';
  }

  return [
    baseMsg,
    `Current Tiana CLI account: ${account.join(' / ') || '(unknown)'}`,
    `Current Tiana space: ${currentSpace.join(' / ') || '(unknown)'}`,
    `Target Web app: ${webId || webApp?.id || '(unknown)'}`,
    `Reason: ${reason}`,
    '',
    'Run `tiana status` to verify the active Tiana CLI account and space.',
    'If you are signed in with a different account, run `tiana logout && tiana login` and sign in as the Web app owner.',
    'If you are in a different space, run `tiana space list`, then `tiana space switch <spaceId>`, or pass `--space <spaceId>` to `dsh-remote connect`.',
  ].join('\n');
}

function webAppNotFound(webId, status) {
  return new Error(formatOwnershipError(`Web app "${webId}" was not found in the current Tiana space.`, {
    webId, status, reason: '`tiana web list` did not include this Web app.',
  }));
}

async function listWebAppsForOwnership(webId, status, cliOpts) {
  try {
    return await listTianaWebApps(cliOpts);
  } catch {
    throw new Error(formatOwnershipError(`Could not look up Web app "${webId}" in the current Tiana space.`, {
      webId, status, reason: '`tiana web list` failed to retrieve Web apps in the active space.',
    }));
  }
}

async function getWebBindingForOwnership(webId, status, cliOpts) {
  try {
    return await getWebFunctionBinding(webId, cliOpts);
  } catch {
    throw new Error(formatOwnershipError(WEB_APP_OWNERSHIP_ERROR, {
      webId, status, reason: '`tiana web functions get` failed to retrieve the app’s management permissions.',
    }));
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
    await runTianaJSON(['space', 'switch', options.spaceId, '--json'], cliOpts);
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
    fnShown = await runTianaJSON(['function', 'show', fnId, '--json'], cliOpts);
  } else {
    log(`[dsh-remote] Web app ${webId} has no bound Relay Function; provisioning generic relay-go...`);
    const created = await ensureRelayFunction({
      functionName: options.functionName || DEFAULT_FUNCTION_NAME,
      log,
      ...cliOpts,
    });
    fnId = created.instance.id;
    fnShown = await syncAndPublishRelayFunction(fnId, webId, { log, ...cliOpts });
    const boundFnId = await ensureWebFunctionBinding(webId, fnId, {
      adoptExisting: true,
      revalidate: revalidateBindAuth,
      status,
      log,
      ...cliOpts,
    });
    if (boundFnId !== fnId) {
      fnId = boundFnId;
      fnShown = await runTianaJSON(['function', 'show', fnId, '--json'], cliOpts);
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
    { rotateToken: Boolean(options.rotateToken), log, ...cliOpts },
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
      fnShown = await runTianaJSON(['function', 'show', fnId, '--json'], cliOpts);
      fnUrl = validateRelayFunctionShown(fnShown);
      preLockToken = prevState.function?.id === fnId ? prevState.function : null;
      tokenInfo = await ensureHostToken(prevState, fnId, {
        rotateToken: Boolean(options.rotateToken),
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
    const existingParams = await getFunctionParameters(fnId, cliOpts);
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
    await updateRemotePolicy(fnId, policy, { existingParams, log, ...cliOpts });

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
      const nextState = {
        version: 2,
        configVersion: 2,
        enabled: latest.enabled !== undefined ? latest.enabled : true,
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
      functionName, functionId: prevState.function?.id || pending.functionId, log, ...cliOpts,
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
        forcePublish: Boolean(options.forcePublish), log, ...cliOpts,
      });
      const fnUrl = fnShown?.instance?.connection?.url || fnShown?.instance?.url || fnInstance.connection?.url || fnInstance.url;
      if (!fnUrl || new URL(fnUrl).protocol !== 'https:') throw new Error('Function requires an HTTPS endpoint');

      // Mint token and checkpoint BEFORE mutating cloud policy
      const tokenSeedState = (prevState.function?.id === fnInstance.id && prevState.function?.token &&
        (!pending.tokenInfo?.token || Number(prevState.function.expiresAt) >= Number(pending.tokenInfo.expiresAt)))
        ? prevState
        : (pending.tokenInfo ? { function: pending.tokenInfo } : prevState);
      const tokenInfo = await ensureHostToken(tokenSeedState, fnInstance.id, {
        rotateToken: Boolean(options.rotateToken), log, ...cliOpts,
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

      const existingParams = await getFunctionParameters(fnInstance.id, cliOpts);
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

      await updateRemotePolicy(fnInstance.id, policy, { existingParams, log, ...cliOpts });
      await ensureWebFunctionBinding(webId, fnInstance.id, {
        initialBinding: freshAuth.binding,
        requireManage: freshAuth.requiresManageProof,
        status,
        log,
        ...cliOpts,
      });

      const publishResult = await runTianaJSON([
        'web', 'publish',
        '--dir', distTemp,
        '--json',
        webId,
      ], { ...cliOpts, timeoutMs: 240_000 });

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
        const finalState = {
          version: 2,
          configVersion: 2,
          enabled: migrated.enabled !== undefined ? migrated.enabled : true,
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
    return await runTianaJSON(['web', 'publish', '--dir', distTemp, '--json', webId], { ...cliOpts, timeoutMs: 240_000 });
  } finally {
    rmSync(distTemp, { recursive: true, force: true });
  }
}
