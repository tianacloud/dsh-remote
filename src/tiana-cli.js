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
  ensureE2eeConfig,
  generateE2eeSecret,
  loadRemoteState,
  migrateRemoteState,
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

async function ensureWebApp({ webName, webId, log = console.log, ...cliOpts }) {
  if (webId) {
    const items = await listTianaWebApps(cliOpts);
    const existing = items.find((item) => item.id === webId);
    if (!existing) throw new Error('The configured Web app is unavailable in the current Tiana space');
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
  return created?.project ?? created?.app ?? created;
}

async function ensureWebFunctionBinding(webId, functionId, { adoptExisting = false, log = console.log, ...cliOpts } = {}) {
  const current = await runTianaJSON(['web', 'functions', 'get', webId, '--json'], cliOpts);
  const bound = Array.isArray(current?.function_instance_ids) ? current.function_instance_ids : [];
  if (bound.length === 1 && bound[0] === functionId) {
    return functionId;
  }
  if (adoptExisting && bound[0]) {
    log(`[dsh-remote] Adopting existing Relay Function ${bound[0]} already bound to Web ${webId}`);
    return bound[0];
  }
  const revision = current?.project_revision;
  if (!revision) {
    throw new Error(`Missing project_revision from web functions get: ${JSON.stringify(current)}`);
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
      const rechecked = await getWebFunctionBinding(webId, cliOpts);
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
 * 1. Validates non-empty user_id/tenant_id and strict `webApp.owner_id === status.user.user_id`.
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

  let status = await getTianaStatus(cliOpts);
  if (options.spaceId && status.user.tenant_id !== options.spaceId) {
    log(`[dsh-remote] Switching Tiana space to ${options.spaceId}...`);
    await runTianaJSON(['space', 'switch', options.spaceId, '--json'], cliOpts);
    status = await getTianaStatus(cliOpts);
  }
  if (!status?.user?.user_id || !status?.user?.tenant_id) {
    throw new Error('Tiana login status is missing user_id or tenant_id.');
  }

  const webApps = await listTianaWebApps(cliOpts);
  const webApp = webApps.find((item) => item.id === webId);
  if (!webApp) {
    throw new Error(`Web app "${webId}" was not found in the current Tiana space.`);
  }
  if (!webApp.owner_id || webApp.owner_id !== status.user.user_id ||
      (webApp.tenant_id && webApp.tenant_id !== status.user.tenant_id)) {
    throw new Error('Only the verified owner of this DSH Remote Web app can bind a host to it.');
  }
  if (webApp.enabled === false) {
    throw new Error(`Web app "${webId}" is disabled.`);
  }
  if (webApp.deletion_pending === true) {
    throw new Error(`Web app "${webId}" is pending deletion.`);
  }
  const webUrl = validateWebEndpoint(webApp, webId);

  const initialState = await withStateLock(() => {
    const raw = loadRemoteState(statePath);
    return raw ? migrateRemoteState(raw) : {};
  }, statePath);

  const identity = defaultHostIdentity();
  const initialHostId = options.hostId || initialState.host?.hostId || identity.hostId;
  if (!/^[a-z0-9_-]{1,48}$/u.test(initialHostId)) throw new Error('Invalid host ID');

  // Locate bound Relay Function or provision one if empty
  const binding = await getWebFunctionBinding(webId, cliOpts);
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
    const boundFnId = await ensureWebFunctionBinding(webId, fnId, { adoptExisting: true, log, ...cliOpts });
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
  await verifyRelayHealth(fnUrl, tokenInfo.token, options);

  // Serialize the cloud-read + conflict-check + pendingBind checkpoint + policy write + state commit
  // across local processes so concurrent binds can never produce a local/cloud hostDigest mismatch.
  const bindLockPath = `${resolveStatePath(statePath)}.bind`;
  return await withStateLock(async () => {
    const prevState = await withStateLock(() => {
      const raw = loadRemoteState(statePath);
      return raw ? migrateRemoteState(raw) : {};
    }, statePath);

    // Re-verify the Web app's active Relay Function binding under lock
    const activeBinding = await getWebFunctionBinding(webId, cliOpts);
    let activeFnId = activeBinding.functionInstanceIds[0] || '';
    if (!activeFnId) {
      activeFnId = await ensureWebFunctionBinding(webId, fnId, { adoptExisting: true, log, ...cliOpts });
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
      await verifyRelayHealth(fnUrl, tokenInfo.token, options);
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

    let rotatedRegistration = false;
    if (conflict) {
      if (!options.rebind) {
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
    const registrationKey = rotatedRegistration
      ? generateE2eeSecret()
      : ((reusePending ? pendingBind?.registrationKey : prevState.host?.registrationKey) ||
          pendingBind?.registrationKey ||
          prevState.host?.registrationKey ||
          generateE2eeSecret());
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
        security: latest.security || {
          allowedWebPlugins: [],
        },
        allowedWebPlugins: latest.security?.allowedWebPlugins || latest.allowedWebPlugins || [],
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

  const status = await getTianaStatus(cliOpts);
  const bindLockPath = `${resolveStatePath(statePath)}.bind`;
  return await withStateLock(async () => {
    const prevState = await withStateLock(() => loadRemoteState(statePath) || {}, statePath);
    const pending = { ...(prevState.pendingSetup || {}) };
    const identity = defaultHostIdentity();
    const hostId = options.hostId || prevState.host?.hostId || pending.hostId || identity.hostId;
    const hostName = options.hostName || prevState.host?.hostName || identity.hostName;

    if (!/^[a-z0-9_-]{1,48}$/u.test(hostId)) throw new Error('Invalid host ID');
    const previousOwner = prevState.owner || pending.owner;
    if ((previousOwner?.userId && previousOwner.userId !== status.user.user_id) ||
        (previousOwner?.tenantId && previousOwner.tenantId !== status.user.tenant_id)) {
      throw new Error('Use the Tiana account and space that originally configured this DSH host');
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
      await withStateLock(() => {
        const current = loadRemoteState(statePath) || {};
        saveRemoteState({ ...current, pendingSetup: { ...pending } }, statePath);
      }, statePath);
    };

    const { instance: fnInstance } = await ensureRelayFunction({
      functionName, functionId: prevState.function?.id || pending.functionId, log, ...cliOpts,
    });
    if (!fnInstance?.id) throw new Error('Missing configured Function ID');
    await checkpoint({ functionId: fnInstance.id, owner, hostId, registrationKey, e2ee });
    const webApp = await ensureWebApp({ webName, webId: prevState.web?.id || pending.webId, log, ...cliOpts });
    const webId = webApp?.id;
    if (!/^[a-z][a-z0-9]{11}$/u.test(webId || '')) throw new Error('Invalid Web app ID');
    if (!webApp.owner_id || webApp.owner_id !== owner.userId ||
        (webApp.tenant_id && webApp.tenant_id !== owner.tenantId)) {
      throw new Error('The configured Web app does not belong to the DSH owner and space');
    }
    const webUrl = validateWebEndpoint(webApp, webId);
    const webEndpoint = webUrl.href;
    await checkpoint({ webId });

    const policy = buildRemotePolicy({
      hostId,
      hostName,
      registrationKey,
      ownerUserId: status.user.user_id,
      ownerTenantId: status.user.tenant_id,
      webId,
      origin: webUrl.origin,
    });

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

      await updateRemotePolicy(fnInstance.id, policy, { log, ...cliOpts });
      await ensureWebFunctionBinding(webId, fnInstance.id, { log, ...cliOpts });

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
            registrationKey,
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
          security: migrated.security || {
            allowedWebPlugins: [],
          },
          allowedWebPlugins: migrated.security?.allowedWebPlugins || [],
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
