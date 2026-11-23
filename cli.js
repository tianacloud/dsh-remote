#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { buildWebDist } from './scripts/build-web-dist.mjs';
import { checkNodeVersion, runConnect } from './src/connect.js';
import { HostBridge } from './src/host-bridge.js';
import {
  buildUnboundState,
  claimBridgeOwnership,
  defaultStatePath,
  detectLocalRunningHost,
  ensureE2eeConfig,
  formatLocalHostConflictError,
  formatPairingKey,
  isRemoteConfigured,
  loadNormalizedRemoteState,
  loadRemoteState,
  migrateRemoteState,
  releaseBridgeOwnership,
  saveRemoteState,
  withStateLock,
} from './src/state.js';
import { clearRemotePolicyIfOwned, getTianaStatus, provisionTianaRemote } from './src/tiana-cli.js';

function parseArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }
    const eqIdx = arg.indexOf('=');
    if (eqIdx > 2) {
      flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next;
      i += 1;
    } else {
      flags[key] = true;
    }
  }
  return { command: positionals[0] || 'help', rest: positionals.slice(1), flags };
}

function printHelp() {
  console.log(`dsh-remote — Expose DeepSeek Harness via Tiana (zero platform changes, E2EE)

Usage:
  dsh-remote connect --web <webIdOrUrl> [options]
                                  Bind this machine to an installed Tiana DSH Remote app (zero recompile)
    --web <webIdOrUrl>            Tiana Web App ID or URL (alias: --app)
    --space <tenantId>            Target Tiana space ID
    --profile <name>              DSH profile name (default: web)
    --port <port>                 Local DSH port (default: 3080)
    --host-name <name>            Override display name
    --rebind                      Rebind without prompt if app is bound to another offline machine
    --force-rebind                Force takeover even if an active host is online (rotates registrationKey)
    --no-start                    Do not auto-start local DSH
    --no-open                     Do not auto-open browser
    --no-clipboard                Do not copy pairing key to clipboard
    --print-key                   Print full pairing key to stdout
    --json                        Print redacted JSON summary to stdout

  dsh-remote setup [options]      Provision/reuse Relay Function, Token, and .tweb app
    --host-id <id>                Specify the host ID for a new installation
    --host-name <name>            Override display name
    --function-name <name>        Relay Function name (default: dsh-remote-relay)
    --web-name <name>             Web App name (default: DSH Remote)
    --force-rebind                Force takeover even if an active host is online (rotates registrationKey)
    --force-publish               Force rebuild & publish Relay Function
    --rotate-token                Mint a fresh Function access token
    --rotate-e2ee-key             Rotate the local E2EE pairing key

  dsh-remote key [--rotate] [--json]
                                  Show or rotate the local E2EE pairing key
  dsh-remote unbind [--local-only] [--json]
                                  Unbind this machine from its cloud app (keeps cloud Web & Function apps)
  dsh-remote status [--json]      Show Tiana login & provisioned remote state (redacted)
  dsh-remote start --port <port>  Attach standalone HostBridge to a local DSH port
    Set DSH_LAUNCH_TOKEN in the environment to authenticate to local DSH.

  dsh-remote build-web [outDir]   Build the static .tweb bundle locally
`);
}

async function cmdConnect(flags) {
  const nodeCheck = checkNodeVersion();
  if (!nodeCheck.ok) {
    console.error(nodeCheck.message);
    process.exitCode = 2;
    return;
  }
  await runConnect({
    app: typeof flags.app === 'string' ? flags.app : undefined,
    web: typeof flags.web === 'string' ? flags.web : undefined,
    space: typeof flags.space === 'string' ? flags.space : undefined,
    profile: typeof flags.profile === 'string' ? flags.profile : undefined,
    port: typeof flags.port === 'string' ? flags.port : undefined,
    hostName: typeof flags['host-name'] === 'string' ? flags['host-name'] : undefined,
    rebind: Boolean(flags.rebind),
    forceRebind: Boolean(flags['force-rebind']),
    noStart: Boolean(flags['no-start']),
    noOpen: Boolean(flags['no-open']),
    noClipboard: Boolean(flags['no-clipboard']),
    printKey: Boolean(flags['print-key']),
    json: Boolean(flags.json),
  });
}

async function cmdSetup(flags) {
  const state = await provisionTianaRemote({
    hostId: typeof flags['host-id'] === 'string' ? flags['host-id'] : undefined,
    hostName: typeof flags['host-name'] === 'string' ? flags['host-name'] : undefined,
    functionName: typeof flags['function-name'] === 'string' ? flags['function-name'] : undefined,
    webName: typeof flags['web-name'] === 'string' ? flags['web-name'] : undefined,
    forceRebind: Boolean(flags['force-rebind']),
    forcePublish: Boolean(flags['force-publish']),
    rotateToken: Boolean(flags['rotate-token']),
    rotateE2eeKey: Boolean(flags['rotate-e2ee-key']),
  });
  console.log('');
  console.log('============================================================');
  console.log('DSH Remote provisioning complete!');
  console.log(`  Owner      : ${state.owner?.email || state.owner?.userId}`);
  console.log(`  Space      : ${state.owner?.spaceName || state.owner?.tenantId}`);
  console.log(`  Host ID    : ${state.host?.hostId} (${state.host?.hostName})`);
  console.log(`  Relay Fn   : ${state.function?.id} -> ${state.function?.url}`);
  console.log(`  Web App    : ${state.web?.id}`);
  console.log(`  E2EE       : ${state.e2ee?.algorithm} (key ${state.e2ee?.fingerprint})`);
  console.log(`  Remote URL : ${state.web?.endpoint}`);
  console.log(`  State file : ${defaultStatePath()}`);
  console.log('============================================================');
  console.log('Next: start `dsh web` (with @tianacloud/dsh-remote installed) and open the Remote URL.');
}

async function cmdStatus(flags) {
  let tianaStatus = null;
  try {
    tianaStatus = await getTianaStatus();
  } catch (err) {
    tianaStatus = { logged_in: false, error: err.message };
  }
  const rawState = loadRemoteState();
  const state = rawState ? migrateRemoteState(rawState) : null;
  const configured = isRemoteConfigured(state);
  let relayHealth = null;
  if (configured && state?.function?.url && state?.function?.token) {
    try {
      const health = new URL('/health', state.function.url);
      if (health.protocol !== 'https:' || health.username || health.password) throw new Error('HTTPS required');
      const resp = await fetch(health, {
        headers: { Authorization: `Bearer ${state.function.token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
      if (resp.ok) {
        const body = await resp.json();
        relayHealth = { ok: body?.ok === true, paired: body?.paired };
      } else {
        relayHealth = { ok: false, status: resp.status };
      }
    } catch (err) {
      relayHealth = { ok: false, error: err.message };
    }
  }

  const redactedState = state ? {
    version: state.version,
    configVersion: state.configVersion,
    configured,
    enabled: configured && state.enabled !== false,
    owner: configured && state.owner ? { userId: state.owner.userId, tenantId: state.owner.tenantId } : undefined,
    host: state.host && { hostId: state.host.hostId, hostName: state.host.hostName },
    e2ee: configured && state.e2ee?.secret ? {
      enabled: true, algorithm: state.e2ee.algorithm,
      fingerprint: state.e2ee.fingerprint, createdAt: state.e2ee.createdAt,
    } : { enabled: false },
    function: configured && state.function ? {
      id: state.function.id, url: state.function.url, name: state.function.name,
      tokenConfigured: Boolean(state.function.token),
      tokenId: state.function.tokenId, expiresAt: state.function.expiresAt,
    } : undefined,
    web: configured && state.web ? { id: state.web.id, endpoint: state.web.endpoint, name: state.web.name } : undefined,
    network: state.network,
    lastBound: state.lastBound || undefined,
  } : null;

  const summary = {
    tiana: tianaStatus?.logged_in
      ? {
          loggedIn: true,
          email: tianaStatus.user?.email,
          userId: tianaStatus.user?.user_id,
          tenantId: tianaStatus.user?.tenant_id,
          space: tianaStatus.space?.display_name,
        }
      : tianaStatus,
    statePath: defaultStatePath(),
    configured,
    state: redactedState,
    relayHealth,
  };

  if (flags.json) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  console.log('Tiana Login :', summary.tiana?.loggedIn ? `${summary.tiana.email} (${summary.tiana.space})` : 'NOT LOGGED IN');
  if (!configured) {
    console.log('Remote State: Not bound yet. Run `dsh-remote connect --app <appId>` or `dsh-remote setup`.');
    if (redactedState?.lastBound?.webId) {
      console.log('Last Bound  :', `${redactedState.lastBound.webName} (${redactedState.lastBound.webId})`);
    }
    return;
  }
  console.log('Host        :', `${redactedState.host?.hostId} (${redactedState.host?.hostName})`);
  console.log('Relay Fn    :', `${redactedState.function?.id} -> ${redactedState.function?.url}`);
  console.log('E2EE        :', redactedState.e2ee?.enabled
    ? `${redactedState.e2ee.algorithm} (key ${redactedState.e2ee.fingerprint})`
    : 'not initialized (will auto-generate on next setup/start)');
  console.log('Web Endpoint:', redactedState.web?.endpoint || 'unavailable');
  console.log('Relay Health:', relayHealth ? JSON.stringify(relayHealth) : 'unavailable');
  console.log('Tip         : Run `dsh-remote key` to view the pairing key in a private terminal.');
}

async function cmdUnbind(flags) {
  const statePath = defaultStatePath();
  const clearCloudPolicy = !Boolean(flags['local-only']);
  const log = flags.json ? (...args) => console.error(...args) : console.log;
  const prevState = loadNormalizedRemoteState(statePath);
  if (!isRemoteConfigured(prevState)) {
    const out = {
      ok: true,
      unbound: true,
      alreadyUnbound: true,
      cloudPolicyCleared: false,
      cloudPolicyWarning: '',
      lastBound: prevState?.lastBound || null,
    };
    if (flags.json) console.log(JSON.stringify(out, null, 2));
    else console.log('[dsh-remote] Already unbound (no active cloud binding found).');
    return;
  }

  let cloudPolicyCleared = false;
  let cloudPolicyWarning = '';
  if (clearCloudPolicy) {
    const res = await clearRemotePolicyIfOwned(prevState, { log });
    cloudPolicyCleared = Boolean(res?.cleared);
    cloudPolicyWarning = res?.warning || '';
  }

  const nextState = await withStateLock(() => {
    const latest = loadNormalizedRemoteState(statePath) || prevState;
    const unbound = buildUnboundState(latest);
    saveRemoteState(unbound, statePath);
    return unbound;
  }, statePath);

  const out = {
    ok: true,
    unbound: true,
    alreadyUnbound: false,
    cloudPolicyCleared,
    cloudPolicyWarning,
    lastBound: nextState.lastBound || null,
  };
  if (flags.json) {
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  console.log('[dsh-remote] Unbound this machine from its cloud app (cloud Web & Function apps were preserved).');
  if (cloudPolicyWarning) {
    console.log(`[dsh-remote] Note: ${cloudPolicyWarning}`);
  }
  if (nextState.lastBound?.webId) {
    console.log(`[dsh-remote] Rebind anytime with: dsh-remote connect --app ${nextState.lastBound.webId}`);
  }
}

async function cmdKey(flags) {
  const rotate = Boolean(flags.rotate);
  const result = await withStateLock(() => {
    const rawState = loadRemoteState();
    const state = rawState ? migrateRemoteState(rawState) : null;
    if (!state || (!isRemoteConfigured(state) && !state.e2ee?.secret && !state.pendingSetup && !state.pendingBind)) {
      throw new Error('Remote access is not bound yet. Run `dsh-remote connect` or `dsh-remote setup` first.');
    }
    const { changed, e2ee } = ensureE2eeConfig(state, { rotate });
    const hostId = state.host?.hostId || 'dsh-host';
    if (changed) {
      state.e2ee = e2ee;
      if (state.web) {
        delete state.web.shareUrl;
      }
      state.updatedAt = new Date().toISOString();
      saveRemoteState(state);
    }
    return { hostId, e2ee, endpoint: state.web?.endpoint };
  });

  const { hostId, e2ee, endpoint } = result;
  const pairingKey = formatPairingKey(e2ee.secret);
  const printKey = Boolean(flags['print-key']);
  const out = {
    hostId,
    algorithm: e2ee.algorithm,
    fingerprint: e2ee.fingerprint,
    endpoint,
    rotated: rotate,
    ...(printKey ? { pairingKey, secret: e2ee.secret } : {}),
  };
  if (flags.json) {
    console.log(JSON.stringify(out, null, 2));
    return;
  }
  if (rotate) {
    console.log('[dsh-remote] Rotated local E2EE key (running `dsh web` will hot-reload and disconnect active clients).');
  }
  console.log(`Algorithm  : ${e2ee.algorithm}`);
  console.log(`Fingerprint: ${e2ee.fingerprint}`);
  console.log(`Pairing Key: ${pairingKey}`);
  if (endpoint) console.log(`Remote URL : ${endpoint}`);
}

async function cmdStart(flags) {
  const rawState = loadRemoteState();
  if (!isRemoteConfigured(rawState) || !rawState?.function?.token) {
    throw new Error('Remote access is not bound yet. Run `dsh-remote connect` or `dsh-remote setup` first.');
  }
  const state = migrateRemoteState(rawState);
  const port = Number(flags.port || process.env.DSH_PORT || 0);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('Provide --port <port> pointing to the local dsh web port.');
  }
  if (rawState.version !== 2) throw new Error('Run setup or connect with the updated plugin first.');
  if (flags.token || flags['host-id']) throw new Error('Use DSH_LAUNCH_TOKEN and the host ID configured by setup.');
  const { hostId, registrationKey } = state.host;
  const launchToken = process.env.DSH_LAUNCH_TOKEN || '';
  const localOrigin = `http://127.0.0.1:${port}`;
  const statePath = defaultStatePath();
  const localHost = detectLocalRunningHost({ statePath });
  if (localHost.running) {
    throw formatLocalHostConflictError(localHost);
  }
  const instanceId = randomUUID();
  const claim = await claimBridgeOwnership({
    instanceId,
    hostId,
    origin: localOrigin,
  }, statePath);
  if (!claim.acquired) {
    throw formatLocalHostConflictError({
      pid: claim.owner?.pid,
      hostId: claim.owner?.hostId || hostId,
      origin: claim.owner?.advertisedOrigin || claim.owner?.origin || '',
      source: 'bridge-owner.json',
    });
  }
  const bridge = new HostBridge({
    instanceId,
    relayUrl: state.function.url,
    relayToken: state.function.token,
    e2eeSecret: state.e2ee.secret,
    hostId,
    registrationKey,
    hostName: state.host?.hostName || 'dsh-host',
    localOrigin,
    getLaunchToken: launchToken ? () => launchToken : null,
    ownerUserId: state.owner?.userId || '',
    ownerTenantId: state.owner?.tenantId,
    webId: state.web?.id,
    p2p: process.env.DSH_REMOTE_P2P ?? state.network?.p2pEnabled,
    stun: process.env.DSH_REMOTE_STUN ?? state.network?.stunUrls,
  });

  const stop = () => {
    bridge.stop();
    void releaseBridgeOwnership(instanceId, statePath).finally(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  try {
    await bridge.start();
  } catch (err) {
    await releaseBridgeOwnership(instanceId, statePath);
    throw err;
  }
  console.log(`[dsh-remote] E2EE active (${state.e2ee.algorithm}, key ${state.e2ee.fingerprint})`);
  console.log(`[dsh-remote] Bridging ${localOrigin} -> ${state.web.endpoint}`);
}

function cmdBuildWeb(rest) {
  const outDir = resolve(rest[0] || '.dist-tweb/preview');
  const res = buildWebDist({ outDir });
  console.log(`[dsh-remote] Built web dist at ${res.outDir}: ${res.fileCount} files, ${(res.totalBytes / 1024).toFixed(1)} KiB`);
}

async function main() {
  const { command, rest, flags } = parseArgs(process.argv.slice(2));
  if (flags.help || flags.h || command === 'help') {
    printHelp();
    return;
  }
  switch (command) {
    case 'connect':
      await cmdConnect(flags);
      break;
    case 'init':
      if (flags.web || flags.app) {
        await cmdConnect(flags);
      } else {
        await cmdSetup(flags);
      }
      break;
    case 'setup':
      await cmdSetup(flags);
      break;
    case 'key':
      await cmdKey(flags);
      break;
    case 'unbind':
      await cmdUnbind(flags);
      break;
    case 'status':
      await cmdStatus(flags);
      break;
    case 'start':
      await cmdStart(flags);
      break;
    case 'share':
      throw new Error('Shared viewer access is disabled. Only the configured DSH owner can connect.');
    case 'build-web':
      cmdBuildWeb(rest);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(`[dsh-remote] Error: ${err instanceof Error ? err.message : String(err)}`);
  process.exitCode = Number.isInteger(err?.exitCode) ? err.exitCode : 1;
});
