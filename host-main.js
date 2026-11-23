import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, watch } from 'node:fs';
import { dirname } from 'node:path';
import { HostBridge } from './src/host-bridge.js';
import { registerRemoteRoutes, registerWebServerRoutes } from './src/remote-api.js';
import {
  buildUnboundState,
  claimBridgeOwnership,
  defaultRuntimePath,
  defaultStatePath,
  DEFAULT_STUN_URLS,
  ensureE2eeConfig,
  isRemoteConfigured,
  loadNormalizedRemoteState,
  loadRemoteState,
  releaseBridgeOwnership,
  removeRuntimeInfo,
  saveRemoteState,
  withStateLock,
  writeRuntimeInfo,
} from './src/state.js';
import {
  bindTianaRemoteWeb,
  buildRemotePolicy,
  clearRemotePolicyIfOwned,
  ensureHostToken,
  getTianaStatus,
  provisionTianaRemote,
  republishWebShell,
  updateRemotePolicy,
} from './src/tiana-cli.js';

export const name = 'tiana-remote';
export const inject = ['webServer', 'connection'];

const TOKEN_CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000;
const TOKEN_RENEW_LEAD_SECONDS = 7 * 86400;
const BRIDGE_CONFLICT_RETRY_MS = 10_000;

export function createHostController(options = {}) {
  const statePath = options.statePath || defaultStatePath();
  const runtimePath = options.runtimePath || defaultRuntimePath();
  const log = options.log || console.log;
  const createBridge = options.createBridge || ((cfg) => new HostBridge(cfg));
  const getWebServer = options.getWebServer || (() => null);
  const getConnection = options.getConnection || (() => null);
  const getClientModules = options.getClientModules || (() => null);
  const getWebApp = options.getWebApp || (() => null);
  const instanceId = randomBytes(8).toString('hex');
  const bridgeConflictRetryMs = options.bridgeConflictRetryMs ?? BRIDGE_CONFLICT_RETRY_MS;
  const claimLock = options.claimBridgeOwnership || claimBridgeOwnership;
  const releaseLock = options.releaseBridgeOwnership || releaseBridgeOwnership;

  let bridge = null;
  let activeStateKey = '';
  let bridgeLockHeld = false;
  let bridgeConflict = null;
  let conflictRetryTimer = null;
  let disposed = false;
  let watcher = null;
  let reloadTimer = null;
  let tokenTimer = null;
  let provisionTask = {
    running: false,
    step: 'idle',
    logs: [],
    error: null,
    errorCode: null,
    errorDetails: null,
    completedAt: null,
  };

  function getEnvOverrides() {
    return {
      disabled: process.env.DSH_REMOTE_DISABLE === '1',
      p2p: process.env.DSH_REMOTE_P2P !== undefined,
      stun: process.env.DSH_REMOTE_STUN !== undefined,
    };
  }

  function effectiveConfig(state) {
    const p2p = process.env.DSH_REMOTE_P2P ?? state?.network?.p2pEnabled ?? true;
    const stun = process.env.DSH_REMOTE_STUN ?? state?.network?.stunUrls ?? DEFAULT_STUN_URLS;
    return { p2p, stun };
  }

  function stateSignature(state) {
    if (!state) return '';
    return JSON.stringify({
      enabled: state.enabled,
      hostId: state.host?.hostId,
      hostName: state.host?.hostName,
      reg: state.host?.registrationKey,
      fnUrl: state.function?.url,
      fnToken: state.function?.token,
      webId: state.web?.id,
      owner: state.owner?.userId,
      tenant: state.owner?.tenantId,
    });
  }

  function buildBridgeOptions(state) {
    const webServer = getWebServer();
    const connection = getConnection();
    const clientModules = getClientModules();
    const webApp = getWebApp();
    const eff = effectiveConfig(state);
    return {
      relayUrl: state.function.url,
      relayToken: state.function.token,
      e2eeSecret: state.e2ee.secret,
      hostId: state.host.hostId,
      hostName: state.host.hostName || state.host.hostId,
      registrationKey: state.host.registrationKey,
      localOrigin: options.localOrigin || (() => webServer.getOrigin()),
      inProcessEndpoint: options.inProcessEndpoint || (webServer ? () => ({
        listenOrigin: webServer.getOrigin(),
        boundHost: webServer?.host,
        advertisedOrigin: webApp?.getAdvertisedUrl?.(),
      }) : null),
      getLaunchToken: options.getLaunchToken || (connection ? () => {
        const url = new URL(connection.authenticatedUrl('http://127.0.0.1/'));
        return url.searchParams.get('token') || '';
      } : null),
      activeClientPath: options.activeClientPath || ((id) => clientModules?.artifactBaseline?.(id)?.path),
      collectIndexInjections: options.collectIndexInjections || (webServer && connection
        ? () => webServer.collectIndexInjections(connection.browserPeer)
        : undefined),
      ownerUserId: state.owner?.userId || '',
      ownerTenantId: state.owner?.tenantId || '',
      webId: state.web?.id || '',
      p2p: eff.p2p,
      stun: eff.stun,
      log,
    };
  }

  function stopBridge({ releaseOwnership = true } = {}) {
    clearTimeout(conflictRetryTimer);
    conflictRetryTimer = null;
    if (bridge) {
      bridge.stop();
      bridge = null;
    }
    activeStateKey = '';
    if (releaseOwnership) {
      bridgeConflict = null;
      if (bridgeLockHeld) {
        bridgeLockHeld = false;
        void releaseLock(instanceId, statePath);
      }
    }
  }

  function scheduleConflictRetry() {
    if (disposed || conflictRetryTimer) return;
    conflictRetryTimer = setTimeout(() => {
      conflictRetryTimer = null;
      void syncBridgeWithState().catch(() => {});
    }, bridgeConflictRetryMs);
    conflictRetryTimer.unref?.();
  }

  async function syncBridgeWithState({ forceRestart = false } = {}) {
    if (disposed) return;
    if (process.env.DSH_REMOTE_DISABLE === '1') {
      stopBridge();
      return;
    }
    const raw = loadRemoteState(statePath);
    if (!isRemoteConfigured(raw) || !raw?.function?.token || !raw?.e2ee?.secret) {
      stopBridge();
      return;
    }
    if (raw.version !== 2) {
      log('[dsh-remote] Legacy v1 state detected; run `dsh-remote connect` or `dsh-remote setup` to upgrade.');
      stopBridge();
      return;
    }
    const state = loadNormalizedRemoteState(statePath);
    if (!state?.enabled) {
      stopBridge();
      return;
    }

    const sig = stateSignature(state);
    if (!forceRestart && bridge && activeStateKey === sig && !bridge.terminalState) {
      // Hot-update mutable settings (secret rotation, network) without dropping Relay WS
      const eff = effectiveConfig(state);
      if (bridge.e2eeSecret !== state.e2ee.secret) {
        await bridge.rotateE2eeSecret(state.e2ee.secret);
      }
      bridge.updateSettings({
        hostName: state.host.hostName,
        p2pEnabled: eff.p2p,
        stunUrls: eff.stun,
        relayToken: state.function.token,
      });
      return;
    }

    if (!bridgeLockHeld && options.disableBridgeLock !== true) {
      const webServer = getWebServer();
      const webApp = getWebApp();
      const claim = await claimLock({
        instanceId,
        hostId: state.host.hostId,
        origin: webServer?.getOrigin?.() || '',
        advertisedOrigin: webApp?.getAdvertisedUrl?.() || '',
      }, statePath);
      if (disposed) {
        if (claim.acquired) void releaseLock(instanceId, statePath);
        return;
      }
      if (!claim.acquired) {
        const ownerPid = claim.owner?.pid || null;
        const ownerOrigin = claim.owner?.advertisedOrigin || claim.owner?.origin || '';
        const shouldLog = !bridgeConflict || bridgeConflict.ownerPid !== ownerPid;
        bridgeConflict = {
          ownerPid,
          ownerOrigin,
          hostId: claim.owner?.hostId || state.host.hostId,
          detectedAt: new Date().toISOString(),
        };
        if (shouldLog) {
          log(
            `[dsh-remote] Another live DSH process (PID ${ownerPid ?? 'unknown'}${ownerOrigin ? `, ${ownerOrigin}` : ''}) already owns the Relay bridge; skipping duplicate HostBridge startup.`,
          );
        }
        scheduleConflictRetry();
        return;
      }
      bridgeLockHeld = true;
      bridgeConflict = null;
    }

    stopBridge({ releaseOwnership: false });
    bridge = createBridge(buildBridgeOptions(state));
    activeStateKey = sig;
    try {
      await bridge.start();
    } catch (err) {
      if (err?.terminalState || bridge?.terminalState) {
        log(`[dsh-remote] HostBridge entered terminal state (${err?.terminalState || bridge?.terminalState}): ${err instanceof Error ? err.message : String(err)}`);
        return;
      }
      throw err;
    }
    if (!disposed) {
      log(`[dsh-remote] E2EE active (${state.e2ee.algorithm}, key ${state.e2ee.fingerprint})`);
      log(`[dsh-remote] Remote access ready: ${state.web?.endpoint}`);
    }
  }

  async function checkAndAutoRenewToken() {
    if (disposed) return;
    const state = loadNormalizedRemoteState(statePath);
    if (!isRemoteConfigured(state) || !state?.function?.id || !state?.function?.expiresAt) return;
    const now = Math.floor(Date.now() / 1000);
    if (state.function.expiresAt - now > TOKEN_RENEW_LEAD_SECONDS) return;
    try {
      await controller.renewHostToken();
      log('[dsh-remote] Automatically renewed Function Instance Token.');
    } catch (err) {
      log(`[dsh-remote] Auto token renew skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  function startStateWatcher() {
    try {
      const dir = dirname(statePath);
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      watcher = watch(dir, (_eventType, filename) => {
        if (disposed) return;
        if (filename && !String(filename).includes('state.json')) return;
        clearTimeout(reloadTimer);
        reloadTimer = setTimeout(() => {
          void syncBridgeWithState().catch((err) => {
            log(`[dsh-remote] Hot-reload error: ${err instanceof Error ? err.message : String(err)}`);
          });
        }, 250);
      });
      watcher.on('error', () => {});
    } catch {
      // Non-fatal if filesystem watcher unavailable
    }
  }

  const controller = {
    getBridge: () => bridge,

    async boot() {
      const webServer = getWebServer();
      const webApp = getWebApp();
      try {
        writeRuntimeInfo({
          origin: webServer?.getOrigin?.() || '',
          advertisedOrigin: webApp?.getAdvertisedUrl?.() || '',
        }, runtimePath);
      } catch { /* non-fatal */ }
      if (process.env.DSH_REMOTE_DISABLE !== '1') {
        const existing = loadRemoteState(statePath);
        if (!isRemoteConfigured(existing) && process.env.DSH_REMOTE_AUTO_SETUP === '1') {
          log('[dsh-remote] Auto-provisioning Tiana remote resources...');
          await provisionTianaRemote({ statePath, log });
        }
        await syncBridgeWithState();
      }
      startStateWatcher();
      tokenTimer = setInterval(() => void checkAndAutoRenewToken(), TOKEN_CHECK_INTERVAL_MS);
      tokenTimer.unref?.();
      void checkAndAutoRenewToken();
    },

    dispose() {
      disposed = true;
      clearTimeout(reloadTimer);
      clearTimeout(conflictRetryTimer);
      clearInterval(tokenTimer);
      try { watcher?.close(); } catch { /* ignore */ }
      watcher = null;
      stopBridge();
      removeRuntimeInfo(runtimePath);
    },

    async getPublicStatus() {
      const state = loadNormalizedRemoteState(statePath);
      const snap = bridge?.getStatusSnapshot();
      const configured = isRemoteConfigured(state);
      return {
        configured,
        enabled: configured && state.enabled !== false && process.env.DSH_REMOTE_DISABLE !== '1',
        hostName: state?.host?.hostName || null,
        hostId: state?.host?.hostId || null,
        webId: configured ? (state?.web?.id || null) : null,
        webEndpoint: configured ? (state?.web?.endpoint || null) : null,
        e2eeFingerprint: configured ? (state?.e2ee?.fingerprint || null) : null,
        p2pEnabled: snap?.p2pEnabled ?? (state?.network?.p2pEnabled !== false),
      };
    },

    async getAdminOverview() {
      const state = loadNormalizedRemoteState(statePath);
      const snap = bridge?.getStatusSnapshot() || {
        running: false,
        relayConnected: false,
        hostConflict: Boolean(bridgeConflict),
        credentialsRevoked: false,
        terminalState: null,
        terminalReason: '',
        lastHttpStatus: null,
        lastCloseCode: null,
        lastCloseReason: '',
        sessions: [],
        p2pEnabled: state?.network?.p2pEnabled !== false,
        stunUrls: state?.network?.stunUrls || DEFAULT_STUN_URLS,
      };
      let tiana = { loggedIn: false };
      try {
        const status = await getTianaStatus({ timeoutMs: 5000 });
        tiana = {
          loggedIn: true,
          email: status.user?.email || '',
          displayName: status.user?.display_name || '',
          spaceName: status.space?.display_name || '',
          tenantId: status.user?.tenant_id || '',
        };
      } catch {
        // leave loggedIn: false
      }
      const configured = isRemoteConfigured(state);
      return {
        ok: true,
        configured,
        enabled: configured ? state.enabled !== false : false,
        envOverrides: getEnvOverrides(),
        bridge: snap,
        bridgeConflict,
        tiana,
        owner: configured && state?.owner ? {
          userId: state.owner.userId,
          tenantId: state.owner.tenantId,
          email: state.owner.email,
          displayName: state.owner.displayName,
          spaceName: state.owner.spaceName,
        } : null,
        host: state?.host ? {
          hostId: state.host.hostId,
          hostName: state.host.hostName,
        } : null,
        web: configured && state?.web ? {
          id: state.web.id,
          name: state.web.name,
          endpoint: state.web.endpoint,
        } : null,
        function: configured && state?.function ? {
          id: state.function.id,
          name: state.function.name,
          url: state.function.url,
          expiresAt: state.function.expiresAt,
          autoRenew: true,
        } : null,
        e2ee: configured && state?.e2ee?.secret ? {
          algorithm: state.e2ee.algorithm,
          fingerprint: state.e2ee.fingerprint,
          createdAt: state.e2ee.createdAt,
        } : null,
        network: state?.network || { p2pEnabled: true, stunUrls: [...DEFAULT_STUN_URLS] },
        lastBound: state?.lastBound || null,
      };
    },

    async setEnabled(enabled) {
      if (process.env.DSH_REMOTE_DISABLE === '1' && enabled) {
        throw Object.assign(new Error('Remote access is disabled by DSH_REMOTE_DISABLE=1 environment variable'), { status: 409 });
      }
      const updated = await withStateLock(() => {
        const state = loadNormalizedRemoteState(statePath);
        if (!isRemoteConfigured(state)) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
        state.enabled = Boolean(enabled);
        state.updatedAt = new Date().toISOString();
        saveRemoteState(state, statePath);
        return state;
      }, statePath);
      if (!updated.enabled) {
        stopBridge();
      } else {
        await syncBridgeWithState();
      }
      return { enabled: updated.enabled, relayConnected: Boolean(bridge?.registered) };
    },

    async revealPairingKey() {
      const state = loadNormalizedRemoteState(statePath);
      if (!isRemoteConfigured(state) || !state?.e2ee?.secret) {
        throw Object.assign(new Error('Pairing key is not initialized'), { status: 404 });
      }
      return {
        secret: state.e2ee.secret,
        fingerprint: state.e2ee.fingerprint,
      };
    },

    async rotatePairingKey() {
      const rotated = await withStateLock(() => {
        const state = loadNormalizedRemoteState(statePath);
        if (!isRemoteConfigured(state)) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
        const { e2ee } = ensureE2eeConfig(state, { rotate: true });
        state.e2ee = e2ee;
        state.updatedAt = new Date().toISOString();
        saveRemoteState(state, statePath);
        return e2ee;
      }, statePath);

      let kickedSessions = 0;
      if (bridge) {
        const res = await bridge.rotateE2eeSecret(rotated.secret);
        kickedSessions = res.kicked;
      }
      return {
        secret: rotated.secret,
        fingerprint: rotated.fingerprint,
        createdAt: rotated.createdAt,
        kickedSessions,
      };
    },

    async disconnectSession(sessionId) {
      if (!bridge) return false;
      return await bridge.disconnectSession(sessionId);
    },

    async disconnectAllSessions() {
      if (!bridge) return 0;
      return await bridge.disconnectAllSessions();
    },

    async updateSettings(patch) {
      let hostNameChanged = false;
      const saved = await withStateLock(() => {
        const state = loadNormalizedRemoteState(statePath);
        if (!isRemoteConfigured(state)) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
        if (patch.hostName !== undefined && patch.hostName !== state.host?.hostName) {
          state.host = { ...state.host, hostName: patch.hostName };
          hostNameChanged = true;
        }
        if (patch.p2pEnabled !== undefined || patch.stunUrls !== undefined) {
          state.network = {
            p2pEnabled: patch.p2pEnabled !== undefined ? patch.p2pEnabled : state.network.p2pEnabled,
            stunUrls: patch.stunUrls !== undefined ? patch.stunUrls : state.network.stunUrls,
          };
        }
        state.updatedAt = new Date().toISOString();
        saveRemoteState(state, statePath);
        return state;
      }, statePath);

      if (bridge) {
        const eff = effectiveConfig(saved);
        bridge.updateSettings({
          hostName: saved.host?.hostName,
          p2pEnabled: eff.p2p,
          stunUrls: eff.stun,
        });
      }

      if (hostNameChanged && saved.function?.id && saved.web?.endpoint) {
        try {
          const policy = buildRemotePolicy({
            hostId: saved.host.hostId,
            hostName: saved.host.hostName,
            registrationKey: saved.host.registrationKey,
            ownerUserId: saved.owner.userId,
            ownerTenantId: saved.owner.tenantId,
            webId: saved.web.id,
            origin: new URL(saved.web.endpoint).origin,
          });
          await updateRemotePolicy(saved.function.id, policy, { log });
        } catch (err) {
          log(`[dsh-remote] Failed to sync updated hostName to Relay policy: ${err instanceof Error ? err.message : String(err)}`);
        }
      }

      return {
        host: { hostId: saved.host?.hostId, hostName: saved.host?.hostName },
        network: saved.network,
      };
    },

    async repairStaticShell() {
      const state = loadNormalizedRemoteState(statePath);
      if (!isRemoteConfigured(state) || !state?.function?.id) {
        throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
      }
      const policy = buildRemotePolicy({
        hostId: state.host.hostId,
        hostName: state.host.hostName,
        registrationKey: state.host.registrationKey,
        ownerUserId: state.owner.userId,
        ownerTenantId: state.owner.tenantId,
        webId: state.web.id,
        origin: new URL(state.web.endpoint).origin,
      });
      await updateRemotePolicy(state.function.id, policy, { log });
      const publishResult = await republishWebShell(state, { log });
      return { repaired: true, publishResult };
    },

    async renewHostToken() {
      const initial = await withStateLock(() => loadNormalizedRemoteState(statePath), statePath);
      const expectedFunctionId = initial?.function?.id;
      if (!isRemoteConfigured(initial) || !expectedFunctionId) {
        throw Object.assign(new Error('Relay Function is not configured yet'), { status: 400 });
      }
      const tokenInfo = await ensureHostToken(initial, expectedFunctionId, { rotateToken: true, log });
      const committed = await withStateLock(() => {
        const cur = loadNormalizedRemoteState(statePath);
        if (!cur || !isRemoteConfigured(cur) || cur.function?.id !== expectedFunctionId) {
          return null;
        }
        if (cur.function.token && Number(cur.function.expiresAt) > Number(tokenInfo.expiresAt)) {
          return {
            token: cur.function.token,
            tokenId: cur.function.tokenId,
            expiresAt: cur.function.expiresAt,
          };
        }
        cur.function = {
          ...cur.function,
          token: tokenInfo.token,
          tokenId: tokenInfo.tokenId,
          expiresAt: tokenInfo.expiresAt,
        };
        cur.updatedAt = new Date().toISOString();
        saveRemoteState(cur, statePath);
        return tokenInfo;
      }, statePath);
      if (!committed) {
        throw Object.assign(new Error('Relay Function changed during token renewal; stale token discarded'), { status: 409 });
      }
      if (bridge) {
        bridge.updateSettings({ relayToken: committed.token });
      }
      return { expiresAt: committed.expiresAt, tokenId: committed.tokenId };
    },

    async reconnectBridge() {
      if (process.env.DSH_REMOTE_DISABLE === '1') {
        throw Object.assign(new Error('Remote access is disabled by DSH_REMOTE_DISABLE=1 environment variable'), { status: 409 });
      }
      const state = loadNormalizedRemoteState(statePath);
      if (!isRemoteConfigured(state)) {
        throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
      }
      if (!state.enabled) {
        throw Object.assign(new Error('Remote access is paused; enable it before reconnecting'), { status: 409 });
      }
      stopBridge({ releaseOwnership: true });
      await syncBridgeWithState({ forceRestart: true });
      return {
        bridge: bridge?.getStatusSnapshot() || null,
        bridgeConflict,
        relayConnected: Boolean(bridge?.registered),
      };
    },

    async unbind({ clearCloudPolicy = true } = {}) {
      if (provisionTask.running) {
        throw Object.assign(
          new Error('A provision task is already running; wait for it to finish before unbinding'),
          { status: 409 },
        );
      }
      const prevState = loadNormalizedRemoteState(statePath);
      if (!isRemoteConfigured(prevState)) {
        stopBridge({ releaseOwnership: true });
        provisionTask = {
          running: false,
          step: 'idle',
          logs: [],
          error: null,
          errorCode: null,
          errorDetails: null,
          completedAt: null,
        };
        return {
          unbound: true,
          alreadyUnbound: true,
          kickedSessions: 0,
          cloudPolicyCleared: false,
          cloudPolicyWarning: '',
          lastBound: prevState?.lastBound || null,
        };
      }

      let kickedSessions = 0;
      if (bridge) {
        try {
          kickedSessions = await bridge.disconnectAllSessions({ code: 4002, reason: 'host_unbound' });
        } catch {
          kickedSessions = 0;
        }
      }
      stopBridge({ releaseOwnership: true });

      let cloudPolicyCleared = false;
      let cloudPolicyWarning = '';
      if (clearCloudPolicy) {
        const clearPolicyFn = options.clearRemotePolicy || clearRemotePolicyIfOwned;
        const clearRes = await clearPolicyFn(prevState, {
          log,
          ...(options.tianaBin ? { bin: options.tianaBin } : {}),
        });
        cloudPolicyCleared = Boolean(clearRes?.cleared);
        cloudPolicyWarning = clearRes?.warning || '';
      }

      const unboundState = await withStateLock(() => {
        const latest = loadNormalizedRemoteState(statePath) || prevState;
        const next = buildUnboundState(latest);
        saveRemoteState(next, statePath);
        return next;
      }, statePath);
      stopBridge({ releaseOwnership: true });

      provisionTask = {
        running: false,
        step: 'idle',
        logs: [],
        error: null,
        errorCode: null,
        errorDetails: null,
        completedAt: null,
      };

      return {
        unbound: true,
        alreadyUnbound: false,
        kickedSessions,
        cloudPolicyCleared,
        cloudPolicyWarning,
        lastBound: unboundState.lastBound || null,
      };
    },

    startProvision(body = {}) {
      if (provisionTask.running) return { started: false };
      provisionTask = {
        running: true,
        step: 'starting',
        logs: [],
        error: null,
        errorCode: null,
        errorDetails: null,
        completedAt: null,
      };
      const pushLog = (msg) => {
        provisionTask.logs.push(String(msg));
        if (provisionTask.logs.length > 100) provisionTask.logs.shift();
      };
      const bindFn = options.bindRemoteWeb || bindTianaRemoteWeb;
      const provisionFn = options.provisionRemote || provisionTianaRemote;
      void (async () => {
        try {
          if (body.mode === 'bind' && body.webId) {
            provisionTask.step = 'binding';
            await bindFn({
              webId: body.webId,
              hostName: body.hostName,
              rebind: Boolean(body.rebind),
              forceRebind: Boolean(body.forceRebind),
              statePath,
              runtimePath,
              probeRelayHealth: options.probeRelayHealth,
              probeRelayHostStatus: options.probeRelayHostStatus,
              tianaBin: options.tianaBin,
              log: pushLog,
            });
          } else {
            provisionTask.step = 'provisioning';
            await provisionFn({
              webName: body.webName,
              hostName: body.hostName,
              forceRebind: Boolean(body.forceRebind),
              statePath,
              runtimePath,
              probeRelayHostStatus: options.probeRelayHostStatus,
              tianaBin: options.tianaBin,
              log: pushLog,
            });
          }
          provisionTask.step = 'connecting';
          await syncBridgeWithState({ forceRestart: Boolean(body.forceRebind) });
          provisionTask.step = 'done';
        } catch (err) {
          provisionTask.step = 'error';
          provisionTask.error = err instanceof Error ? err.message : String(err);
          provisionTask.errorCode = err?.code || null;
          provisionTask.errorDetails = err?.details || null;
        } finally {
          provisionTask.running = false;
          provisionTask.completedAt = new Date().toISOString();
        }
      })();
      return { started: true, step: provisionTask.step };
    },

    getProvisionStatus() {
      return {
        ...provisionTask,
        logs: [...provisionTask.logs],
      };
    },
  };

  return controller;
}

export function apply(ctx) {
  const controller = createHostController({
    getWebServer: () => ctx.get('webServer'),
    getConnection: () => ctx.get('connection'),
    getClientModules: () => ctx.get('clientModules'),
    getWebApp: () => ctx.get('webApp'),
  });

  ctx.effect(() => () => controller.dispose(), 'tiana-remote: tunnel lifecycle');

  const mountRoutes = (routeCtx, webServer, connection) => {
    if (typeof webServer?.register === 'function') {
      routeCtx.effect(
        () => registerWebServerRoutes(webServer, connection, controller),
        'tiana-remote: http routes',
      );
      return;
    }
    if (typeof connection?.fetch?.register === 'function') {
      routeCtx.effect(
        () => registerRemoteRoutes(connection, controller),
        'tiana-remote: http routes (fetch fallback)',
      );
    }
  };

  if (typeof ctx.inject === 'function') {
    ctx.inject(['webServer', 'connection'], (routeCtx) => {
      mountRoutes(routeCtx, routeCtx.webServer, routeCtx.connection);
    });
  } else {
    mountRoutes(ctx, ctx.get('webServer'), ctx.get('connection'));
  }

  const loader = ctx.get('loader');
  const ready = loader && typeof loader.await === 'function' ? loader.await() : Promise.resolve();
  ready.then(() => controller.boot()).catch((err) => {
    console.error(`[dsh-remote] Startup failed: ${err instanceof Error ? err.message : String(err)}`);
  });
}

export default { name, inject, apply, createHostController };
