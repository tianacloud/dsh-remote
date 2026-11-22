import { execFile, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createConnection } from 'node:net';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { promisify } from 'node:util';
import { copyToClipboard, maskPairingKey } from './clipboard.js';
import {
  detectLocalRunningHost,
  formatLocalHostConflictError,
  formatPairingKey,
  isPidAlive,
  loadNormalizedRemoteState,
  readRuntimeInfo,
  resolveDshHome,
} from './state.js';
import { bindTianaRemoteWeb, getTianaStatus, tianaBinary } from './tiana-cli.js';

const execFileAsync = promisify(execFile);

export const MIN_NODE_VERSION = '24.9.0';
export const MIN_TIANA_CLI_VERSION = '1.0.32';
const NPM_REGISTRY = 'https://registry.npmjs.org/';
const TIANA_CLI_PKG = '@tianacloud/cli@latest';
const TIANA_SKILLS_PKG = '@tianacloud/agent-skills@latest';

export function compareSemver(a, b) {
  const pa = String(a || '0.0.0').replace(/^v/u, '').split('-')[0].split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b || '0.0.0').replace(/^v/u, '').split('-')[0].split('.').map((n) => Number.parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
  }
  return 0;
}

export function extractSemver(text) {
  const match = /(\d+\.\d+\.\d+)/u.exec(String(text || ''));
  return match ? match[1] : '';
}

export function checkNodeVersion(current = process.versions.node, required = MIN_NODE_VERSION) {
  const ok = compareSemver(current, required) >= 0;
  if (ok) {
    return { ok: true, current, required, message: '' };
  }
  const message = [
    `[dsh-remote] Node.js >= ${required} is required (current: v${current}).`,
    `DeepSeek Harness (@deepseek-ai/dsh) requires Node.js >= ${required}.`,
    '',
    'Upgrade Node.js and re-run this command:',
    '  macOS / Linux (fnm):  fnm install 24 && fnm use 24',
    '  macOS / Linux (nvm):  nvm install 24 && nvm use 24',
    '  Windows (winget):     winget install OpenJS.NodeJS.LTS',
    '  Windows (fnm):        fnm install 24 && fnm use 24',
    '  Official downloads:   https://nodejs.org/',
  ].join('\n');
  return { ok: false, current, required, message };
}

export function parseAppArg(raw) {
  const input = String(raw || '').trim();
  if (!input) return '';
  if (/^[a-z][a-z0-9]{11}$/u.test(input)) return input;
  try {
    const url = new URL(input);
    const match = /^\/web\/([a-z][a-z0-9]{11})(?:\/|$)/u.exec(url.pathname);
    if (match) return match[1];
    const hostLabel = url.hostname.split('.')[0];
    if (/^[a-z][a-z0-9]{11}$/u.test(hostLabel)) return hostLabel;
  } catch {
    // not a URL
  }
  return '';
}

/**
 * Idempotently ensure plugin entries exist in ~/.dsh/cordis.patch.yml (or profile patch)
 * without overwriting or stripping existing user plugins or configuration.
 */
export function mergeCordisPatchYml(existingContent, requiredPlugins = [
  { id: 'tiana', name: '@tianacloud/dsh-tiana' },
  { id: 'tiana-remote', name: '@tianacloud/dsh-remote' },
]) {
  const raw = String(existingContent || '');
  const toAdd = requiredPlugins.filter((plugin) => !raw.includes(plugin.name));
  if (toAdd.length === 0) return raw;

  const snippet = toAdd.map((p) => `    - id: ${p.id}\n      name: '${p.name}'`).join('\n');
  if (!raw.trim()) {
    return `- insert:\n${snippet}\n`;
  }
  const insertMatch = /^([ \t]*-[ \t]+insert:\s*\n)/mu.exec(raw);
  if (insertMatch) {
    const pos = insertMatch.index + insertMatch[0].length;
    return `${raw.slice(0, pos)}${snippet}\n${raw.slice(pos)}`;
  }
  const sep = raw.endsWith('\n') ? '' : '\n';
  return `${raw}${sep}- insert:\n${snippet}\n`;
}

export function ensureCordisPatchFile({ dshHome = resolveDshHome(), profile = '' } = {}) {
  const target = profile
    ? join(dshHome, 'profiles', profile, 'cordis.patch.yml')
    : join(dshHome, 'cordis.patch.yml');
  mkdirSync(dirname(target), { recursive: true });
  const before = existsSync(target) ? readFileSync(target, 'utf8') : '';
  const after = mergeCordisPatchYml(before);
  if (after !== before) {
    writeFileSync(target, after, 'utf8');
  }
  return { path: target, changed: after !== before };
}

function platformCmd(name, platform = process.platform) {
  return platform === 'win32' ? `${name}.cmd` : name;
}

async function execQuiet(bin, args, options = {}) {
  return await execFileAsync(bin, args, {
    timeout: options.timeoutMs ?? 15_000,
    maxBuffer: 16 * 1024 * 1024,
    env: options.env ?? process.env,
    shell: process.platform === 'win32',
  });
}

async function getNpmGlobalBinCandidates(cmdName, execFn = execQuiet, platform = process.platform) {
  const out = [];
  try {
    const { stdout } = await execFn(platformCmd('npm', platform), ['prefix', '-g'], { timeoutMs: 10_000 });
    const prefix = String(stdout || '').trim();
    if (prefix) {
      const cmd = platformCmd(cmdName, platform);
      if (platform === 'win32') {
        out.push(join(prefix, cmd), join(prefix, 'bin', cmd));
      } else {
        out.push(join(prefix, 'bin', cmd));
      }
    }
  } catch {
    // ignore if npm prefix -g is unavailable
  }
  return out;
}

export async function resolveDshBinary(execFn = execQuiet, platform = process.platform) {
  const candidates = [
    process.env.DSH_BIN,
    platformCmd('dsh', platform),
    join(homedir(), '.local', 'bin', platformCmd('dsh', platform)),
  ].filter(Boolean);

  for (const bin of candidates) {
    try {
      const { stdout } = await execFn(bin, ['--version'], { timeoutMs: 15_000 });
      return { bin, version: String(stdout || '').trim() };
    } catch {
      // try next
    }
  }
  for (const bin of await getNpmGlobalBinCandidates('dsh', execFn, platform)) {
    if (candidates.includes(bin)) continue;
    try {
      const { stdout } = await execFn(bin, ['--version'], { timeoutMs: 15_000 });
      return { bin, version: String(stdout || '').trim() };
    } catch {
      // try next
    }
  }
  return null;
}

async function installNpmGlobalWithFallback(pkg, { execFn = execQuiet, log = console.error, platform = process.platform } = {}) {
  const npmBin = platformCmd('npm', platform);
  try {
    await execFn(npmBin, ['install', '-g', `--registry=${NPM_REGISTRY}`, pkg], {
      timeoutMs: 240_000,
    });
    return { userLocal: false, prefix: null };
  } catch (err) {
    const msg = String(err?.stderr || err?.message || err);
    if (platform === 'win32' || !/EACCES|EPERM|permission/iu.test(msg)) {
      throw new Error(`Failed to install ${pkg}: ${msg}`);
    }
    const prefix = join(homedir(), '.local');
    log(`[dsh-remote] Global npm prefix not writable; falling back to user prefix ${prefix} (no sudo)...`);
    await execFn(npmBin, ['install', '-g', '--prefix', prefix, `--registry=${NPM_REGISTRY}`, pkg], {
      timeoutMs: 240_000,
    });
    return { userLocal: true, prefix };
  }
}

async function installDshPackage(execFn = execQuiet, log = console.error, platform = process.platform) {
  log('[dsh-remote] DeepSeek Harness (dsh) not found. Installing @deepseek-ai/dsh@latest...');
  const { userLocal, prefix } = await installNpmGlobalWithFallback('@deepseek-ai/dsh@latest', { execFn, log, platform });
  if (userLocal && prefix) {
    const localBin = join(prefix, 'bin', platformCmd('dsh', platform));
    const { stdout } = await execFn(localBin, ['--version'], { timeoutMs: 15_000 });
    return { bin: localBin, version: String(stdout || '').trim(), userLocal: true };
  }
  const found = await resolveDshBinary(execFn, platform);
  if (found) return { ...found, userLocal: false };
  throw new Error('Installed @deepseek-ai/dsh@latest but could not locate the `dsh` executable.');
}

export async function resolveTianaBinary(execFn = execQuiet, platform = process.platform) {
  const candidates = [
    process.env.TIANA_BIN,
    platformCmd('tiana', platform),
    join(homedir(), '.local', 'bin', platformCmd('tiana', platform)),
  ].filter(Boolean);

  for (const bin of candidates) {
    try {
      const res = await execFn(bin, ['version'], { timeoutMs: 15_000 });
      const ver = extractSemver(`${res?.stdout || ''}\n${res?.stderr || ''}`);
      if (ver) return { bin, version: ver };
    } catch {
      // try next
    }
  }
  for (const bin of await getNpmGlobalBinCandidates('tiana', execFn, platform)) {
    if (candidates.includes(bin)) continue;
    try {
      const res = await execFn(bin, ['version'], { timeoutMs: 15_000 });
      const ver = extractSemver(`${res?.stdout || ''}\n${res?.stderr || ''}`);
      if (ver) return { bin, version: ver };
    } catch {
      // try next
    }
  }
  return null;
}

/**
 * Ensure `@tianacloud/cli` >= 1.0.32 and official `@tianacloud/agent-skills` in `$DSH_HOME/skills`.
 * Mirrors `dsh-tiana/install.js` and returns the verified executable path for `tiana`.
 */
export async function ensureTianaToolchain({
  execFn = execQuiet,
  log = console.error,
  dshHome = resolveDshHome(),
  platform = process.platform,
} = {}) {
  let found = await resolveTianaBinary(execFn, platform);
  let installedCli = false;
  let userLocalCli = false;

  if (!found || compareSemver(found.version, MIN_TIANA_CLI_VERSION) < 0) {
    const reason = found
      ? `Tiana CLI v${found.version} is below ${MIN_TIANA_CLI_VERSION}`
      : 'Tiana CLI not found';
    log(`[dsh-remote] ${reason}. Installing ${TIANA_CLI_PKG}...`);
    const installRes = await installNpmGlobalWithFallback(TIANA_CLI_PKG, { execFn, log, platform });
    installedCli = true;
    userLocalCli = installRes.userLocal;

    if (userLocalCli && installRes.prefix) {
      const localBin = join(installRes.prefix, 'bin', platformCmd('tiana', platform));
      const res = await execFn(localBin, ['version'], { timeoutMs: 15_000 });
      const ver = extractSemver(`${res?.stdout || ''}\n${res?.stderr || ''}`);
      found = ver ? { bin: localBin, version: ver } : null;
    } else {
      found = await resolveTianaBinary(execFn, platform);
    }
  }

  if (!found || compareSemver(found.version, MIN_TIANA_CLI_VERSION) < 0) {
    throw new Error(
      `Tiana CLI >= ${MIN_TIANA_CLI_VERSION} is required (found: ${found?.version || 'none'}).`,
    );
  }

  // Sync official Tiana skills into `$DSH_HOME/skills`
  const skillsDir = join(dshHome, 'skills');
  mkdirSync(skillsDir, { recursive: true });
  log(`[dsh-remote] Syncing ${TIANA_SKILLS_PKG} to ${skillsDir}...`);
  const npxBin = platformCmd('npx', platform);
  const pnpmBin = platformCmd('pnpm', platform);
  let skillsSynced = false;
  let lastSkillsErr = null;
  for (const [cmd, args] of [
    [npxBin, ['--yes', TIANA_SKILLS_PKG, 'install', '--dir', skillsDir]],
    [pnpmBin, ['dlx', TIANA_SKILLS_PKG, 'install', '--dir', skillsDir]],
  ]) {
    try {
      await execFn(cmd, args, { timeoutMs: 180_000 });
      skillsSynced = true;
      break;
    } catch (err) {
      lastSkillsErr = err;
    }
  }
  if (!skillsSynced) {
    throw new Error(
      `Failed to install ${TIANA_SKILLS_PKG} into ${skillsDir}: ${lastSkillsErr instanceof Error ? lastSkillsErr.message : String(lastSkillsErr)}`,
    );
  }

  return {
    bin: found.bin,
    version: found.version,
    installedCli,
    userLocalCli,
    skillsDir,
  };
}

export async function ensureDshPlugins(dshBin, { profile = 'web', execFn = execQuiet, log = console.error } = {}) {
  for (const pkg of ['@tianacloud/dsh-tiana@latest', '@tianacloud/dsh-remote@latest']) {
    log(`[dsh-remote] Ensuring plugin ${pkg} in profile "${profile}"...`);
    try {
      await execFn(dshBin, ['plugin', '--profile', profile, 'add', pkg], { timeoutMs: 180_000 });
    } catch (err) {
      const detail = String(err?.stderr || err?.message || err).trim();
      throw new Error(`Failed to install DSH plugin ${pkg} in profile "${profile}": ${detail}`);
    }
  }
  ensureCordisPatchFile({ profile: '' });
}

async function ensureTianaLoggedIn({ interactive, tianaBin, log = console.error } = {}) {
  const cliOpts = tianaBin ? { bin: tianaBin } : {};
  try {
    return await getTianaStatus(cliOpts);
  } catch {
    if (!interactive) {
      throw new Error('Not logged in to Tiana. Run `tiana login` first.');
    }
    log('[dsh-remote] Not logged in to Tiana. Launching `tiana login`...');
    await new Promise((resolve, reject) => {
      const child = spawn(tianaBinary(tianaBin), ['login'], {
        stdio: 'inherit',
        shell: process.platform === 'win32',
      });
      child.on('error', reject);
      child.on('exit', (code) => {
        if (code === 0) resolve();
        else reject(new Error(`tiana login exited with code ${code}`));
      });
    });
    return await getTianaStatus(cliOpts);
  }
}

export function openBrowserUrl(url, { platform = process.platform, spawnFn = spawn } = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Only http/https URLs may be opened');
  }
  if (parsed.hash.includes('rk=') || parsed.hash.includes('k=') || parsed.href.includes('dshk1_')) {
    throw new Error('Refusing to open URL containing pairing key material');
  }
  let cmd;
  let args;
  if (platform === 'darwin') {
    cmd = 'open';
    args = [parsed.href];
  } else if (platform === 'win32') {
    cmd = 'cmd';
    args = ['/c', 'start', '', parsed.href];
  } else {
    cmd = 'xdg-open';
    args = [parsed.href];
  }
  try {
    const child = spawnFn(cmd, args, { stdio: 'ignore', detached: true, windowsHide: true });
    child.on?.('error', () => {});
    child.unref?.();
    return true;
  } catch {
    return false;
  }
}

/**
 * Probe whether a local DSH web server with `@tianacloud/dsh-remote` mounted is responsive.
 * NEVER treats 404 or 5xx as ready: accepts ONLY 200 with valid public-status JSON (`configured` boolean)
 * or 401/403 from DSH's own local owner auth fence.
 */
export async function isLocalDshResponsive(origin, { fetchFn = fetch, timeoutMs = 1500 } = {}) {
  if (!origin) return false;
  try {
    const url = new URL('/api/tiana-remote/public-status', origin);
    const resp = await fetchFn(url, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (resp.status === 200) {
      const body = await resp.json().catch(() => null);
      return Boolean(body && typeof body === 'object' && typeof body.configured === 'boolean');
    }
    // 401/403 means DSH's connection.requestRejection fence answered on the mounted route
    if (resp.status === 401 || resp.status === 403) {
      return true;
    }
    return false;
  } catch {
    return false;
  }
}

export function isTcpEndpointReachable(origin, { timeoutMs = 1500 } = {}) {
  if (!origin) return Promise.resolve(false);
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return Promise.resolve(false);
  }
  const host = parsed.hostname.replace(/^\[|\]$/gu, '');
  const port = Number(parsed.port || (parsed.protocol === 'https:' ? 443 : 80));
  if (!host || !Number.isInteger(port) || port <= 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(ok);
    };
    const socket = createConnection({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

export function buildDshStartArgs({ profile = 'web', port = 3080 } = {}) {
  return ['--profile', String(profile || 'web'), '--port', String(port), '--no-open'];
}

export async function waitForLocalDshReady(port, timeoutMs = 15_000, { childState = null, fetchFn = fetch } = {}) {
  const deadline = Date.now() + timeoutMs;
  const origin = `http://127.0.0.1:${port}`;
  while (Date.now() < deadline) {
    if (childState?.error) {
      throw new Error(`Failed to spawn local DSH: ${childState.error.message}`);
    }
    if (childState?.exited && childState.exitCode !== 0) {
      throw new Error(`Local DSH exited prematurely with code ${childState.exitCode}`);
    }
    if (await isLocalDshResponsive(origin, { fetchFn })) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 350));
  }
  return false;
}

/**
 * Full `dsh-remote connect` orchestrator.
 * Supports dependency injection via `deps` for comprehensive offline unit tests.
 */
export async function runConnect(options = {}, deps = {}) {
  const log = options.json ? (...args) => console.error(...args) : (deps.log ?? console.log);
  const nodeCheck = checkNodeVersion(deps.nodeVersion ?? process.versions.node);
  if (!nodeCheck.ok) {
    const err = new Error(nodeCheck.message);
    err.exitCode = 2;
    throw err;
  }

  const webId = parseAppArg(options.web || options.app);
  if (!webId) {
    throw new Error('Provide --web <webIdOrUrl> (or --app <appIdOrUrl>) for the Tiana DSH Remote app.');
  }

  const profile = options.profile || 'web';
  const port = Number(options.port || process.env.DSH_PORT || 3080);
  const interactive = Boolean(!options.json && process.stdin.isTTY && process.stdout.isTTY);
  const execFn = deps.execFn ?? execQuiet;
  const fetchFn = deps.fetchFn ?? fetch;

  // Step 1: Local preflight — inspect bridge-owner.json & runtime.json before mutating cloud/local state
  const localHost = detectLocalRunningHost({
    statePath: options.statePath,
    runtimePath: options.runtimePath,
    currentPid: deps.currentPid ?? process.pid,
    isAlive: deps.isPidAlive ?? isPidAlive,
    readRuntime: deps.readRuntime,
    readBridgeOwner: deps.readBridgeOwner,
  });
  let state = null;
  let dshInfo = null;
  let installedDsh = false;
  let tianaToolchain = null;
  let reusedExistingHost = false;

  if (localHost.running) {
    let existingState = null;
    try {
      existingState = loadNormalizedRemoteState(options.statePath);
    } catch {
      existingState = null;
    }
    const canReuseSameConfig = Boolean(
      !options.forceRebind &&
      !options.rebind &&
      !options.hostId &&
      !options.hostName &&
      !options.rotateToken &&
      !options.rotateE2eeKey &&
      existingState?.web?.id === webId &&
      existingState?.e2ee?.secret &&
      existingState?.web?.endpoint &&
      (!localHost.hostId || localHost.hostId === existingState?.host?.hostId),
    );
    if (!canReuseSameConfig && !options.forceRebind) {
      throw formatLocalHostConflictError(localHost);
    }
    if (canReuseSameConfig) {
      reusedExistingHost = true;
      state = existingState;
      log(
        `[dsh-remote] Reusing already running local DSH host (PID ${localHost.pid}${localHost.origin ? `, ${localHost.origin}` : ''}) for Web app ${webId}.`,
      );
    }
  }

  if (!reusedExistingHost) {
    // Step 2: Detect or install DSH
    dshInfo = deps.resolveDsh ? await deps.resolveDsh() : await resolveDshBinary(execFn);
    if (!dshInfo) {
      dshInfo = deps.installDsh ? await deps.installDsh() : await installDshPackage(execFn, log);
      installedDsh = true;
    }

    // Step 3a: Idempotently ensure dsh-tiana + dsh-remote plugins (fail-fast on error!)
    if (deps.ensurePlugins) {
      await deps.ensurePlugins(dshInfo.bin, profile);
    } else {
      await ensureDshPlugins(dshInfo.bin, { profile, execFn, log });
    }

    // Step 3b: Ensure `@tianacloud/cli >= 1.0.32` & `@tianacloud/agent-skills` in `$DSH_HOME/skills`
    tianaToolchain = deps.ensureTianaToolchain
      ? await deps.ensureTianaToolchain()
      : await ensureTianaToolchain({ execFn, log });
    const tianaBin = tianaToolchain?.bin;

    // Step 4: Ensure Tiana CLI login using verified tiana executable
    if (deps.ensureLogin) {
      await deps.ensureLogin(tianaBin);
    } else {
      await ensureTianaLoggedIn({ interactive, tianaBin, log });
    }

    // Step 5: Zero-recompile binding (DSH_REMOTE_POLICY + Token + state.json)
    const confirmRebind = async (existingPolicy, target) => {
      if (!interactive) return false;
      const rl = createInterface({ input: process.stdin, output: process.stderr });
      try {
        const answer = await rl.question(
          `App ${webId} is currently bound to "${existingPolicy.hostName || existingPolicy.hostId}" (${existingPolicy.hostId}). Rebind to "${target.hostName}" (${target.hostId})? [y/N] `,
        );
        return /^y(?:es)?$/iu.test(answer.trim());
      } finally {
        rl.close();
      }
    };

    const bindFn = deps.bindRemoteWeb ?? bindTianaRemoteWeb;
    state = await bindFn({
      webId,
      spaceId: options.space,
      hostName: options.hostName,
      rebind: Boolean(options.rebind),
      forceRebind: Boolean(options.forceRebind),
      confirmRebind: deps.confirmRebind ?? confirmRebind,
      statePath: options.statePath,
      skipLocalPreflight: true,
      probeRelayHostStatus: deps.probeRelayHostStatus,
      tianaBin,
      log,
    });
  }

  // Step 6: Verify local DSH liveness (PID + real health probe) and start if needed
  let dshStarted = false;
  const runtime = deps.readRuntime ? deps.readRuntime() : readRuntimeInfo();
  let runtimeAlive = Boolean(reusedExistingHost || localHost.running);
  if (!runtimeAlive && runtime) {
    const probeOrigins = [...new Set([
      runtime.advertisedOrigin,
      runtime.origin,
      `http://127.0.0.1:${port}`,
    ].filter(Boolean))];
    if (deps.checkDshResponsive) {
      for (const candidate of probeOrigins) {
        if (await deps.checkDshResponsive(candidate)) {
          runtimeAlive = true;
          break;
        }
      }
    } else {
      for (const candidate of probeOrigins) {
        if (await isLocalDshResponsive(candidate, { fetchFn })) {
          runtimeAlive = true;
          break;
        }
      }
      // If HTTPS probe failed (e.g. TLS SAN mismatch on raw Tailscale/LAN IP) while runtime.pid
      // is alive and its HTTPS port accepts TCP connections, reuse the live DSH instance instead
      // of spawning a competing duplicate process.
      const checkPidAlive = deps.isPidAlive ?? isPidAlive;
      const checkTcpReachable = deps.checkTcpReachable ?? isTcpEndpointReachable;
      if (!runtimeAlive && checkPidAlive(runtime.pid) &&
          typeof runtime.origin === 'string' && runtime.origin.startsWith('https://')) {
        runtimeAlive = await checkTcpReachable(runtime.origin);
      }
    }
  }

  if (!options.noStart && !runtimeAlive) {
    if (deps.startDsh) {
      dshStarted = await deps.startDsh(dshInfo.bin, { profile, port });
    } else {
      const spawnFn = deps.spawnFn ?? spawn;
      const startArgs = buildDshStartArgs({ profile, port });
      log(`[dsh-remote] Starting local DSH (${dshInfo.bin} ${startArgs.join(' ')})...`);
      const childState = { error: null, exited: false, exitCode: null };
      const child = spawnFn(dshInfo.bin, startArgs, {
        stdio: 'ignore',
        detached: true,
        windowsHide: true,
        shell: process.platform === 'win32',
      });
      child.on('error', (err) => {
        childState.error = err;
      });
      child.on('exit', (code) => {
        childState.exited = true;
        childState.exitCode = code;
      });
      child.unref();
      dshStarted = await waitForLocalDshReady(port, 15_000, { childState, fetchFn });
    }
    if (!dshStarted) {
      throw new Error(`Local DSH web server failed to become ready on 127.0.0.1:${port}`);
    }
  }

  // Step 7: Copy pairing key to clipboard (never in URL!)
  const pairingKey = formatPairingKey(state.e2ee.secret);
  let clipboardResult = { ok: false, skipped: true };
  if (!options.noClipboard && !options.json) {
    const copyFn = deps.copyToClipboard ?? copyToClipboard;
    clipboardResult = await copyFn(pairingKey);
  }

  // Step 8: Open clean URL (no #rk= or query key!)
  const cleanUrl = state.web.endpoint;
  let browserOpened = false;
  if (!options.noOpen && !options.json) {
    const openFn = deps.openBrowser ?? openBrowserUrl;
    browserOpened = openFn(cleanUrl);
  }

  const summary = {
    ok: true,
    webId: state.web.id,
    hostId: state.host.hostId,
    hostName: state.host.hostName,
    endpoint: cleanUrl,
    fingerprint: state.e2ee.fingerprint,
    clipboardCopied: Boolean(clipboardResult.ok),
    clipboardTool: clipboardResult.tool || null,
    dshInstalled: installedDsh,
    dshStarted: Boolean(dshStarted || runtimeAlive),
    ...(reusedExistingHost ? { reusedExistingHost: true } : {}),
    browserOpened,
    ...(!options.json && options.printKey ? { pairingKey } : {}),
  };

  if (options.json) {
    console.log(JSON.stringify(summary, null, 2));
    return summary;
  }

  log('');
  log('============================================================');
  log('DSH Remote connected!');
  log(`  Host        : ${state.host.hostName} (${state.host.hostId})`);
  log(`  Remote URL  : ${cleanUrl}`);
  log(`  Fingerprint : ${state.e2ee.fingerprint}`);
  if (clipboardResult.ok) {
    log(`  Pairing Key : ${maskPairingKey(pairingKey)} (copied to clipboard via ${clipboardResult.tool})`);
  } else if (options.printKey) {
    log(`  Pairing Key : ${pairingKey}`);
  } else {
    log(`  Pairing Key : ${maskPairingKey(pairingKey)} (clipboard unavailable; run with --print-key or press Enter to reveal)`);
  }
  if (dshInfo?.userLocal || tianaToolchain?.userLocalCli) {
    log('  PATH tip    : export PATH="$HOME/.local/bin:$PATH"');
  }
  log('============================================================');

  if (!clipboardResult.ok && !options.printKey && interactive && !deps.skipInteractiveReveal) {
    const rl = createInterface({ input: process.stdin, output: process.stderr });
    try {
      await rl.question('Press Enter to reveal pairing key in this terminal (Ctrl+C to keep hidden): ');
      console.log(`  Pairing Key : ${pairingKey}`);
    } finally {
      rl.close();
    }
  }

  return summary;
}
