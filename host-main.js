import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, watch } from 'node:fs';
import { dirname } from 'node:path';
import { isProtectedWebPlugin, normalizePluginPolicy } from './src/frontend-assets.js';
import { HostBridge } from './src/host-bridge.js';
import { registerRemoteRoutes, registerWebServerRoutes } from './src/remote-api.js';
import {
  claimBridgeOwnership,
  defaultRuntimePath,
  defaultStatePath,
  DEFAULT_STUN_URLS,
  ensureE2eeConfig,
  loadNormalizedRemoteState,
  loadRemoteState,
  PLUGIN_ACCESS_MODE_ALLOW_ALL,
  PLUGIN_ACCESS_MODE_DENY_ALL,
  releaseBridgeOwnership,
  removeRuntimeInfo,
  saveRemoteState,
  withStateLock,
  writeRuntimeInfo,
} from './src/state.js';
import {
  bindTianaRemoteWeb,
  buildRemotePolicy,
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

function computeEffectiveAllowedPlugins(installedWebPlugins, policy) {
  const normalized = normalizePluginPolicy(policy);
  if (normalized.mode === PLUGIN_ACCESS_MODE_ALLOW_ALL) {
    const blocked = new Set(normalized.blockedWebPlugins);
    return installedWebPlugins.filter((id) => !blocked.has(id));
  }
  const allowed = new Set(normalized.allowedWebPlugins);
  return installedWebPlugins.filter((id) => allowed.has(id));
}

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
    completedAt: null,
  };

  function getEnvOverrides() {
    return {
      disabled: process.env.DSH_REMOTE_DISABLE === '1',
      p2p: process.env.DSH_REMOTE_P2P !== undefined,
      stun: process.env.DSH_REMOTE_STUN !== undefined,
      allowedWebPlugins: process.env.DSH_REMOTE_WEB_PLUGINS !== undefined,
    };
  }

  function effectiveConfig(state) {
    const p2p = process.env.DSH_REMOTE_P2P ?? state?.network?.p2pEnabled ?? true;
    const stun = process.env.DSH_REMOTE_STUN ?? state?.network?.stunUrls ?? DEFAULT_STUN_URLS;
    const envPlugins = process.env.DSH_REMOTE_WEB_PLUGINS;
    const pluginPolicy = envPlugins !== undefined
      ? normalizePluginPolicy(envPlugins)
      : normalizePluginPolicy({
          mode: state?.security?.pluginAccessMode,
          blockedWebPlugins: state?.security?.blockedWebPlugins,
          allowedWebPlugins: state?.security?.allowedWebPlugins,
        });
    return { p2p, stun, pluginPolicy };
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
      frontendOptions: { pluginPolicy: eff.pluginPolicy },
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

  async function syncBridgeWithState() {
    if (disposed) return;
    if (process.env.DSH_REMOTE_DISABLE === '1') {
      stopBridge();
      return;
    }
    const raw = loadRemoteState(statePath);
    if (!raw?.function?.url || !raw?.function?.token || !raw?.e2ee?.secret || !raw?.host?.hostId) {
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
    if (bridge && activeStateKey === sig) {
      // Hot-update mutable settings (secret rotation, network, plugins) without dropping Relay WS
      const eff = effectiveConfig(state);
      if (bridge.e2eeSecret !== state.e2ee.secret) {
        await bridge.rotateE2eeSecret(state.e2ee.secret);
      }
      bridge.updateSettings({
        hostName: state.host.hostName,
        p2pEnabled: eff.p2p,
        stunUrls: eff.stun,
        pluginPolicy: eff.pluginPolicy,
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
    await bridge.start();
    if (!disposed) {
      log(`[dsh-remote] E2EE active (${state.e2ee.algorithm}, key ${state.e2ee.fingerprint})`);
      log(`[dsh-remote] Remote access ready: ${state.web?.endpoint}`);
    }
  }

  async function checkAndAutoRenewToken() {
    if (disposed) return;
    const state = loadNormalizedRemoteState(statePath);
    if (!state?.function?.id || !state?.function?.expiresAt) return;
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

  async function listLocalWebPlugins() {
    try {
      const webServer = getWebServer();
      const connection = getConnection();
      if (!webServer || !connection) return [];
      const rows = await webServer.collectIndexInjections(connection.browserPeer);
      const graph = rows?.find((r) => r.kind === 'global' && r.name === '__DSH_BOOT__')?.value;
      if (!Array.isArray(graph?.entries)) return [];
      return graph.entries
        .map((e) => e.id)
        .filter((id) => typeof id === 'string' && !isProtectedWebPlugin(id));
    } catch {
      return [];
    }
  }

  function buildPluginAccessSnapshot(state, installedWebPlugins) {
    const mode = state?.security?.pluginAccessMode === PLUGIN_ACCESS_MODE_DENY_ALL
      ? PLUGIN_ACCESS_MODE_DENY_ALL
      : PLUGIN_ACCESS_MODE_ALLOW_ALL;
    const blockedWebPlugins = Array.isArray(state?.security?.blockedWebPlugins)
      ? state.security.blockedWebPlugins.filter((id) => !isProtectedWebPlugin(id))
      : [];
    const allowedWebPlugins = Array.isArray(state?.security?.allowedWebPlugins)
      ? state.security.allowedWebPlugins.filter((id) => !isProtectedWebPlugin(id))
      : [];
    const eff = effectiveConfig(state);
    return {
      ok: true,
      mode,
      blockedWebPlugins,
      allowedWebPlugins,
      installedWebPlugins,
      effectiveMode: eff.pluginPolicy.mode,
      effectiveAllowedPlugins: computeEffectiveAllowedPlugins(installedWebPlugins, eff.pluginPolicy),
      envOverride: process.env.DSH_REMOTE_WEB_PLUGINS !== undefined,
    };
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
        if (!existing?.function?.url && process.env.DSH_REMOTE_AUTO_SETUP === '1') {
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
      const configured = Boolean(state?.function?.url && state?.web?.id && state?.host?.hostId);
      return {
        configured,
        enabled: configured && state.enabled !== false && process.env.DSH_REMOTE_DISABLE !== '1',
        hostName: state?.host?.hostName || null,
        hostId: state?.host?.hostId || null,
        webId: state?.web?.id || null,
        webEndpoint: state?.web?.endpoint || null,
        e2eeFingerprint: state?.e2ee?.fingerprint || null,
        p2pEnabled: snap?.p2pEnabled ?? (state?.network?.p2pEnabled !== false),
      };
    },

    async getPluginAccess() {
      const state = loadNormalizedRemoteState(statePath);
      const installedWebPlugins = await listLocalWebPlugins();
      return buildPluginAccessSnapshot(state, installedWebPlugins);
    },

    async updatePluginAccess(patch = {}) {
      const saved = await withStateLock(() => {
        const state = loadNormalizedRemoteState(statePath);
        if (!state) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
        const nextSecurity = {
          ...(state.security && typeof state.security === 'object' ? state.security : {}),
        };
        if (patch.mode !== undefined) {
          nextSecurity.pluginAccessMode = patch.mode === PLUGIN_ACCESS_MODE_DENY_ALL
            ? PLUGIN_ACCESS_MODE_DENY_ALL
            : PLUGIN_ACCESS_MODE_ALLOW_ALL;
        }
        if (patch.blockedWebPlugins !== undefined) {
          nextSecurity.blockedWebPlugins = [...new Set(
            patch.blockedWebPlugins.map((p) => String(p).trim()).filter((p) => p && !isProtectedWebPlugin(p)),
          )];
        }
        if (patch.allowedWebPlugins !== undefined) {
          nextSecurity.allowedWebPlugins = [...new Set(
            patch.allowedWebPlugins.map((p) => String(p).trim()).filter((p) => p && !isProtectedWebPlugin(p)),
          )];
          state.allowedWebPlugins = nextSecurity.allowedWebPlugins;
        }
        state.security = nextSecurity;
        state.updatedAt = new Date().toISOString();
        saveRemoteState(state, statePath);
        return state;
      }, statePath);

      if (bridge) {
        const eff = effectiveConfig(saved);
        bridge.updateSettings({ pluginPolicy: eff.pluginPolicy });
      }

      const installedWebPlugins = await listLocalWebPlugins();
      return buildPluginAccessSnapshot(saved, installedWebPlugins);
    },

    async getAdminOverview() {
      const state = loadNormalizedRemoteState(statePath);
      const snap = bridge?.getStatusSnapshot() || {
        running: false,
        relayConnected: false,
        hostConflict: Boolean(bridgeConflict),
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
      const installedWebPlugins = await listLocalWebPlugins();
      const pluginAccess = buildPluginAccessSnapshot(state, installedWebPlugins);
      const configured = Boolean(state?.function?.url && state?.web?.id && state?.host?.hostId);
      return {
        ok: true,
        configured,
        enabled: configured ? state.enabled !== false : false,
        envOverrides: getEnvOverrides(),
        bridge: snap,
        bridgeConflict,
        tiana,
        owner: state?.owner ? {
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
        web: state?.web ? {
          id: state.web.id,
          name: state.web.name,
          endpoint: state.web.endpoint,
        } : null,
        function: state?.function ? {
          id: state.function.id,
          name: state.function.name,
          url: state.function.url,
          expiresAt: state.function.expiresAt,
          autoRenew: true,
        } : null,
        e2ee: state?.e2ee?.secret ? {
          algorithm: state.e2ee.algorithm,
          fingerprint: state.e2ee.fingerprint,
          createdAt: state.e2ee.createdAt,
        } : null,
        network: state?.network || { p2pEnabled: true, stunUrls: [...DEFAULT_STUN_URLS] },
        security: state?.security || {
          pluginAccessMode: PLUGIN_ACCESS_MODE_ALLOW_ALL,
          blockedWebPlugins: [],
          allowedWebPlugins: [],
        },
        pluginAccess,
        allowedWebPlugins: state?.security?.allowedWebPlugins || [],
        installedWebPlugins,
      };
    },

    async setEnabled(enabled) {
      if (process.env.DSH_REMOTE_DISABLE === '1' && enabled) {
        throw Object.assign(new Error('Remote access is disabled by DSH_REMOTE_DISABLE=1 environment variable'), { status: 409 });
      }
      const updated = await withStateLock(() => {
        const state = loadNormalizedRemoteState(statePath);
        if (!state) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
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
      if (!state?.e2ee?.secret) {
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
        if (!state) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
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
        if (!state) throw Object.assign(new Error('Remote access is not configured yet'), { status: 400 });
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
        if (patch.pluginAccessMode !== undefined || patch.blockedWebPlugins !== undefined || patch.allowedWebPlugins !== undefined) {
          const nextSecurity = {
            ...(state.security && typeof state.security === 'object' ? state.security : {}),
          };
          if (patch.pluginAccessMode !== undefined) {
            nextSecurity.pluginAccessMode = patch.pluginAccessMode === PLUGIN_ACCESS_MODE_DENY_ALL
              ? PLUGIN_ACCESS_MODE_DENY_ALL
              : PLUGIN_ACCESS_MODE_ALLOW_ALL;
          }
          if (patch.blockedWebPlugins !== undefined) {
            nextSecurity.blockedWebPlugins = [...new Set(
              patch.blockedWebPlugins.map((p) => String(p).trim()).filter((p) => p && !isProtectedWebPlugin(p)),
            )];
          }
          if (patch.allowedWebPlugins !== undefined) {
            nextSecurity.allowedWebPlugins = [...new Set(
              patch.allowedWebPlugins.map((p) => String(p).trim()).filter((p) => p && !isProtectedWebPlugin(p)),
            )];
            state.allowedWebPlugins = nextSecurity.allowedWebPlugins;
          }
          state.security = nextSecurity;
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
          pluginPolicy: eff.pluginPolicy,
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
        security: saved.security,
      };
    },

    async repairStaticShell() {
      const state = loadNormalizedRemoteState(statePath);
      if (!state?.web?.id || !state?.function?.id) {
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
      if (!expectedFunctionId) {
        throw Object.assign(new Error('Relay Function is not configured yet'), { status: 400 });
      }
      const tokenInfo = await ensureHostToken(initial, expectedFunctionId, { rotateToken: true, log });
      const committed = await withStateLock(() => {
        const cur = loadNormalizedRemoteState(statePath);
        if (!cur || cur.function?.id !== expectedFunctionId) {
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

    startProvision(body = {}) {
      if (provisionTask.running) return { started: false };
      provisionTask = {
        running: true,
        step: 'starting',
        logs: [],
        error: null,
        completedAt: null,
      };
      const pushLog = (msg) => {
        provisionTask.logs.push(String(msg));
        if (provisionTask.logs.length > 100) provisionTask.logs.shift();
      };
      void (async () => {
        try {
          if (body.mode === 'bind' && body.webId) {
            provisionTask.step = 'binding';
            await bindTianaRemoteWeb({
              webId: body.webId,
              hostName: body.hostName,
              rebind: Boolean(body.rebind),
              statePath,
              log: pushLog,
            });
          } else {
            provisionTask.step = 'provisioning';
            await provisionTianaRemote({
              webName: body.webName,
              hostName: body.hostName,
              statePath,
              log: pushLog,
            });
          }
          provisionTask.step = 'connecting';
          await syncBridgeWithState();
          provisionTask.step = 'done';
        } catch (err) {
          provisionTask.step = 'error';
          provisionTask.error = err instanceof Error ? err.message : String(err);
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
