import { RTCPeerConnection } from 'werift';
import { MultipathSession, createPath, LEASE_MS, relayPacer, RELAY_GRACE_MS } from '../web-src/multipath.js';
import { PeerPath, localAddress, normalizeP2pEnabled, normalizeStun } from '../web-src/peer-path.js';
import { FragmentReader, sendFragments } from '../web-src/ws-fragments.js';
import { base64UrlEncode, MSG_E2EE_CTRL, MULTIPATH_CAPABILITIES, respondHostHandshake } from '../web-src/e2ee.js';
import { FrontendAssets } from './frontend-assets.js';
import { openPinnedWebSocket, pinnedFetch, resolvePinnedEndpoint, resolvePinnedTarget } from './local-transport.js';
import {
  decodeClientFrame,
  decodeHostFrame,
  decodeJSON,
  decodeWindowUpdate,
  encodeClientFrame,
  encodeHostFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
  MSG_E2EE_BOX,
  MSG_E2EE_CLIENT_HELLO,
  MSG_E2EE_ERROR,
  MSG_E2EE_HOST_HELLO,
  MSG_HTTP_ABORT,
  MSG_HTTP_REQ_BODY,
  MSG_HTTP_REQ_END,
  MSG_HTTP_REQ_HEAD,
  MSG_HTTP_RES_BODY,
  MSG_HTTP_RES_END,
  MSG_HTTP_RES_HEAD,
  MSG_HTTP_RES_WINDOW,
  MSG_WS_CLOSE,
  MSG_WS_DATA_BIN,
  MSG_WS_DATA_TEXT,
  MSG_WS_OPEN,
  MSG_WS_OPENED,
} from './protocol.js';

const CHUNK_SIZE = 32 * 1024;
const MAX_REQUEST_BYTES = 16 * 1024 * 1024;
const MAX_REQUEST_CHUNKS = 1024;
const MAX_HOST_REQUEST_BYTES = 32 * 1024 * 1024;
export const MAX_STREAMS = 64;
const MIN_WINDOW_BYTES = 64 * 1024;
const MAX_WINDOW_BYTES = 8 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 5 * 60 * 1000;
const DEFAULT_SSE_KEEPALIVE_MS = 25_000;
const DEFAULT_AUTH_TIMEOUT_MS = 30_000;
const SSE_KEEPALIVE_BYTES = Buffer.from(': keepalive\n', 'utf8');

const SHARED_HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);
const REQUEST_STRIPPED_HEADERS = new Set([
  ...SHARED_HOP_BY_HOP_HEADERS,
  'host',
  'origin',
  'referer',
  'content-length',
  'cookie',
  'authorization',
  'forwarded',
  'x-real-ip',
  'x-dsh-remote-tunnel',
]);

function nominatedConnectionHeaders(headers) {
  const nominated = new Set();
  for (const part of (headers.get('connection') || '').toLowerCase().split(',')) {
    const name = part.trim();
    if (name) nominated.add(name);
  }
  return nominated;
}

const ALLOWED_HTTP_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const RESERVED_HTTP_EXACT_PATHS = new Set([
  '/',
  '/index.html',
]);
const RESERVED_HTTP_PREFIX_SEGMENTS = new Set([
  '__dsh_remote__',
  '_tiana',
  'connect',
  'plugins',
  'oauth',
  'inspector',
  'open-in-app',
]);

/**
 * Validate and classify a tunneled HTTP target.
 * - Blocks malformed/traversal paths and reserved DSH core or shell routes (returns null -> 404).
 * - Blocks `/api/tiana-remote/admin` and `/api/tiana-remote/admin/*` (returns `{ kind: 'forbidden' }` -> 403).
 * - Allows `/api/*` (including `/api/tiana-remote/status` & `/api/tiana-remote/public-status`)
 *   and third-party plugin HTTP routes.
 */
export function classifyHttpRoute(pathAndQuery) {
  if (typeof pathAndQuery !== 'string' || !pathAndQuery.startsWith('/') ||
      pathAndQuery.startsWith('//') || /[\\#\u0000-\u0020\u007f]/u.test(pathAndQuery)) {
    return null;
  }
  let parsed;
  try {
    parsed = new URL(pathAndQuery, 'http://route.invalid');
  } catch {
    return null;
  }
  const rawPathname = pathAndQuery.split('?', 1)[0];
  if (parsed.origin !== 'http://route.invalid' || parsed.username || parsed.password ||
      parsed.pathname !== rawPathname) {
    return null;
  }
  if (parsed.pathname === '/__dsh_remote__/bootstrap.json' || parsed.pathname === '/__dsh_remote__/asset') {
    return { kind: 'internal', parsed };
  }
  if (/%(?:2f|5c|2e|25)/iu.test(parsed.pathname) || parsed.pathname.includes('//')) {
    return null;
  }
  let decodedPathname;
  try {
    decodedPathname = decodeURIComponent(parsed.pathname);
  } catch {
    return null;
  }
  if (/[\u0000-\u001f\u007f\\]/u.test(decodedPathname)) {
    return null;
  }
  const segments = decodedPathname.slice(1).split('/');
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (seg === '.' || seg === '..') return null;
    if (seg === '' && decodedPathname !== '/' && i < segments.length - 1) return null;
  }
  const trimmedLower = decodedPathname === '/' ? '/' : decodedPathname.replace(/\/+$/u, '').toLowerCase() || '/';
  if (RESERVED_HTTP_EXACT_PATHS.has(trimmedLower)) {
    return null;
  }
  if (RESERVED_HTTP_PREFIX_SEGMENTS.has(segments[0].toLowerCase())) {
    return null;
  }
  if (/^\/api\/tiana-remote\/admin(?:\/|$)/iu.test(trimmedLower)) {
    return { kind: 'forbidden', parsed };
  }
  return { kind: 'forward', parsed };
}

function parseFirstCookiePair(setCookieHeader) {
  if (!setCookieHeader) return '';
  const first = Array.isArray(setCookieHeader) ? setCookieHeader[0] : setCookieHeader;
  if (!first) return '';
  return String(first).split(';', 1)[0].trim();
}

function getSetCookieHeaders(headers) {
  if (typeof headers.getSetCookie === 'function') {
    return headers.getSetCookie();
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function extractThemeFromInjections(rows) {
  const theme = {
    preference: 'system',
    cssVars: {},
  };
  for (const row of rows || []) {
    if (row?.kind !== 'script' || typeof row.text !== 'string') continue;
    if (!row.text.includes('dsThemeSource') && !row.text.includes('data-ds-dark-theme')) continue;
    const prefMatch = /const preference = ("[^"]+"|'[^']+')/.exec(row.text);
    if (prefMatch) {
      try {
        theme.preference = JSON.parse(prefMatch[1].replace(/^'|'$/g, '"'));
      } catch {
        // ignore
      }
    }
    for (const m of row.text.matchAll(/setProperty\(("[^"]+"),\s*("[^"]*")\)/g)) {
      try {
        const key = JSON.parse(m[1]);
        const val = JSON.parse(m[2]);
        theme.cssVars[key] = val;
      } catch {
        // ignore
      }
    }
  }
  return theme;
}

function isEventStreamContentType(contentType) {
  if (typeof contentType !== 'string') return false;
  return contentType.split(';', 1)[0].trim().toLowerCase() === 'text/event-stream';
}

export class HostBridge {
  constructor(options) {
    this.relayUrl = options.relayUrl;
    this.relayToken = options.relayToken || '';
    this.e2eeSecret = options.e2eeSecret || '';
    this.hostId = options.hostId;
    this.hostName = options.hostName || options.hostId;
    this.getLocalOrigin = typeof options.localOrigin === 'function'
      ? options.localOrigin
      : () => options.localOrigin;
    this.inProcessEndpoint = options.inProcessEndpoint || null;
    this.getLaunchToken = options.getLaunchToken || null;
    this.collectIndexInjections = options.collectIndexInjections || this.collectBrowserBoot.bind(this);
    this.frontend = new FrontendAssets({
      allowlist: process.env.DSH_REMOTE_WEB_PLUGINS,
      activeClientPath: options.activeClientPath,
      ...options.frontendOptions,
    });
    this.ownerUserId = options.ownerUserId || '';
    this.webId = options.webId || '';
    this.ownerTenantId = options.ownerTenantId || '';
    this.registrationKey = options.registrationKey || '';
    this.allowInsecureLoopback = options.allowInsecureLoopback === true;
    this.registered = false;
    if (!this.ownerUserId || !this.ownerTenantId || !this.webId || !this.registrationKey || !this.e2eeSecret) {
      throw new Error('Remote owner and host registration are required. Run dsh-remote setup with the updated plugin.');
    }
    this.log = options.log || console.log;

    this.ws = null;
    this.stopped = false;
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.connectedPromise = null;
    this.browserCookie = null;
    this.browserCookieGeneration = 0;

    this.sessions = new Map();
    this.relayLegs = new Map();
    this.leaseMs = options.leaseMs ?? LEASE_MS;
    this.authTimeoutMs = options.authTimeoutMs ?? DEFAULT_AUTH_TIMEOUT_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
    this.sseKeepaliveMs = options.sseKeepaliveMs ?? DEFAULT_SSE_KEEPALIVE_MS;
    this.p2pEnabled = normalizeP2pEnabled(options.p2p ?? process.env.DSH_REMOTE_P2P);
    this.iceServers = this.p2pEnabled ? normalizeStun(options.stun ?? process.env.DSH_REMOTE_STUN) : [];
    this.createPeer = options.createPeer ?? ((config) => {
      const pc = new RTCPeerConnection({
        ...config, iceUseDefaultStunServer: false, iceUseTcp: false, maxMessageSize: 65536,
      });
      if (this.iceServers.length === 0) {
        const guardIce = () => {
          const iceConn = pc.sctp?.dtlsTransport?.iceTransport?.connection ?? pc.dtlsTransports?.[0]?.iceTransport?.connection;
          if (iceConn && typeof iceConn.checkIncoming === 'function' && !iceConn.__dshPrivateOnly) {
            const orig = iceConn.checkIncoming.bind(iceConn);
            iceConn.__dshPrivateOnly = true;
            iceConn.checkIncoming = (msg, addr, proto) => {
              if (!Array.isArray(addr) || !localAddress(String(addr[0] ?? ''))) return;
              return orig(msg, addr, proto);
            };
          }
        };
        const origSetRemote = pc.setRemoteDescription.bind(pc);
        pc.setRemoteDescription = async (...args) => {
          const res = await origSetRemote(...args);
          guardIce();
          return res;
        };
        const origSetLocal = pc.setLocalDescription.bind(pc);
        pc.setLocalDescription = async (...args) => {
          const res = await origSetLocal(...args);
          guardIce();
          return res;
        };
      }
      return pc;
    });
    // `${sessionId}:${streamId}` -> HTTP stream state
    this.httpStreams = new Map();
    this.httpRequestBytes = 0;
    // `${sessionId}:${streamId}` -> WebSocket stream state
    this.wsStreams = new Map();
  }

  getStatusSnapshot() {
    const now = Date.now();
    const sessions = [];
    for (const [id, session] of this.sessions.entries()) {
      const isP2p = Boolean(session.peer?.current?.promoted);
      sessions.push({
        id,
        sessionId: `${id.slice(0, 8)}…`,
        transport: isP2p ? 'p2p' : 'relay',
        path: isP2p ? 'p2p' : 'relay',
        rttMs: session.rttMs ?? null,
        admittedAt: session.admittedAt,
        connectedDurationMs: Math.max(0, now - (session.admittedAt || now)),
        expiresAt: session.transport?.expiresAt ?? null,
      });
    }
    return {
      running: !this.stopped,
      relayConnected: this.registered,
      hostId: this.hostId,
      hostName: this.hostName,
      p2pEnabled: this.p2pEnabled,
      stunUrls: [...this.iceServers],
      activeStreams: this.httpStreams.size + this.wsStreams.size,
      sessions,
    };
  }

  async disconnectSession(sessionId, { code = 1000, reason = 'disconnected_by_host' } = {}) {
    const session = this.sessions.get(sessionId);
    if (!session) return false;
    try {
      await session.transport?.control({ type: 'session_closed', code, reason }).catch(() => {});
    } catch {
      // ignore
    }
    this.closeSessionResources(sessionId);
    return true;
  }

  async disconnectAllSessions({ code = 1000, reason = 'disconnected_by_host' } = {}) {
    const ids = [...this.sessions.keys()];
    await Promise.all(ids.map((id) => this.disconnectSession(id, { code, reason })));
    return ids.length;
  }

  async rotateE2eeSecret(newSecret) {
    if (!newSecret || typeof newSecret !== 'string') {
      throw new Error('New E2EE secret is required');
    }
    this.e2eeSecret = newSecret;
    const kicked = await this.disconnectAllSessions({ code: 4001, reason: 'key_rotated' });
    return { kicked };
  }

  updateSettings({ hostName, p2pEnabled, stunUrls, allowedWebPlugins, relayToken } = {}) {
    if (typeof hostName === 'string' && hostName.trim()) {
      this.hostName = hostName.trim().slice(0, 128);
    }
    if (p2pEnabled !== undefined) {
      this.p2pEnabled = normalizeP2pEnabled(p2pEnabled);
    }
    if (stunUrls !== undefined || p2pEnabled !== undefined) {
      this.iceServers = this.p2pEnabled ? normalizeStun(stunUrls ?? this.iceServers) : [];
    }
    if (allowedWebPlugins !== undefined) {
      this.frontend.setAllowlist(allowedWebPlugins);
    }
    if (typeof relayToken === 'string' && relayToken) {
      this.relayToken = relayToken;
    }
  }

  buildRelayHostWsUrl() {
    const url = new URL('/host', this.relayUrl);
    if (url.protocol === 'https:') url.protocol = 'wss:';
    if (this.allowInsecureLoopback && url.protocol === 'http:' &&
        ['127.0.0.1', '[::1]'].includes(url.hostname)) url.protocol = 'ws:';
    if (url.protocol !== 'wss:' && !(this.allowInsecureLoopback && url.protocol === 'ws:' &&
        ['127.0.0.1', '[::1]'].includes(url.hostname))) {
      throw new Error('A WSS relay is required');
    }
    if (url.username || url.password) throw new Error('Invalid relay origin');
    url.searchParams.set('host_id', this.hostId);
    url.searchParams.set('name', this.hostName);
    return url.href;
  }

  start() {
    this.stopped = false;
    return this.connectOnce();
  }

  stop() {
    this.stopped = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.cleanupActiveStreams();
    if (this.ws) {
      try {
        this.ws.close(1000, 'host shutdown');
      } catch {
        // ignore
      }
      this.ws = null;
    }
    this.registered = false;
  }

  cleanupActiveStreams() {
    for (const [key, req] of this.httpStreams) this.cancelHttpStream(key, req);
    for (const { socket } of this.wsStreams.values()) socket?.close(1000, 'host shutdown');
    this.wsStreams.clear();
    for (const [id] of this.sessions) this.closeSessionResources(id);
    for (const leg of this.relayLegs.values()) clearTimeout(leg.unauthTimer);
    this.relayLegs.clear();
  }

  scheduleReconnect() {
    if (this.stopped || this.reconnectTimer) return;
    const delayMs = Math.min(30_000, 1000 * Math.pow(2, Math.min(this.reconnectAttempts, 5)));
    this.reconnectAttempts += 1;
    this.log(`[dsh-remote] Relay disconnected; reconnecting in ${Math.round(delayMs / 1000)}s...`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      if (!this.stopped) {
        this.connectOnce().catch((err) => {
          this.log(`[dsh-remote] Reconnect attempt failed: ${err.message}`);
        });
      }
    }, delayMs);
  }

  connectOnce() {
    if (this.stopped) return Promise.resolve();
    const wsUrl = this.buildRelayHostWsUrl();
    const headers = { 'Dsh-Host-Registration': this.registrationKey };
    if (this.relayToken) {
      headers.Authorization = `Bearer ${this.relayToken}`;
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const ws = new WebSocket(wsUrl, { headers });
      const registrationTimeout = setTimeout(() => ws.close(), 10_000);
      this.registered = false;
      ws.binaryType = 'arraybuffer';
      this.ws = ws;
      this.paceRelay = relayPacer();

      ws.addEventListener('message', (event) => {
        if (this.ws !== ws || !(event.data instanceof ArrayBuffer)) return;
        let frame;
        try {
          frame = decodeHostFrame(event.data);
        } catch {
          return;
        }
        if (!this.registered) {
          if (frame.sessionId !== 0 || frame.msgType !== MSG_CONTROL_JSON) return;
          let reply;
          try { reply = decodeJSON(frame.payload); } catch { ws.close(); return; }
          if (reply?.type !== 'host_registered' || reply.hostId !== this.hostId || reply.version !== 2) {
            ws.close();
            return;
          }
          clearTimeout(registrationTimeout);
          this.registered = true;
          this.reconnectAttempts = 0;
          this.log(`[dsh-remote] Registered host "${this.hostId}"`);
          settled = true;
          resolve();
          return;
        }
        this.handleFrame(frame).catch((err) => {
          this.log(`[dsh-remote] Frame handler error: ${err.message}`);
        });
      });

      ws.addEventListener('close', () => {
        clearTimeout(registrationTimeout);
        if (this.ws === ws) {
          this.registered = false;
          this.ws = null;
          for (const [id] of this.relayLegs) this.detachRelay(id);
          if (!this.stopped) {
            this.scheduleReconnect();
          }
        }
        if (!settled) {
          settled = true;
          reject(new Error('Relay closed before secure host registration'));
        }
      });

      ws.addEventListener('error', () => {
        // close event will trigger reconnect / rejection
      });
    });
  }

  sendRawFrame(sessionId, streamId, msgType, payload) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN || !this.registered) return false;
    if (this.ws.bufferedAmount > MAX_BUFFERED_BYTES) {
      this.ws.close(4008);
      return false;
    }
    this.ws.send(encodeHostFrame(sessionId, streamId, msgType, payload));
    return true;
  }

  sendStreamFrame(sessionId, streamId, msgType, payload, session = this.sessions.get(sessionId), signal) {
    if (!session?.transport || this.sessions.get(sessionId) !== session) {
      return Promise.reject(new Error('DSH session is closed'));
    }
    return session.transport.send(encodeClientFrame(streamId, msgType, payload), signal);
  }

  detachRelay(id) {
    const leg = this.relayLegs.get(id);
    if (!leg) return;
    clearTimeout(leg.unauthTimer);
    leg.unauthTimer = null;
    this.relayLegs.delete(id);
    const session = leg.session;
    if (session?.leg === leg) {
      session.leg = null;
      session.transport.setRelay(null);
      this.armGrace(session);
    }
  }

  markLegAuthenticated(leg) {
    clearTimeout(leg.unauthTimer);
    leg.unauthTimer = null;
    if (!leg.relayAuthed) {
      leg.relayAuthed = true;
      this.sendRawFrame(0, 0, MSG_CONTROL_JSON, encodeJSON({ type: 'session_authenticated', sessionId: leg.id }));
    }
  }

  armGrace(session) {
    clearTimeout(session.grace);
    if (session.leg || session.peer?.current?.promoted || session.transport.closed) return;
    session.grace = setTimeout(() => this.closeSessionResources(session.id), RELAY_GRACE_MS);
  }

  async bindRelay(session, leg, challenge, renew) {
    const now = Date.now();
    if (challenge !== leg.challenge || (leg.session && leg.session !== session) ||
        !leg.path.ready() || now >= session.transport.expiresAt || now >= leg.expiresAt) return;
    let renewed = false;
    let grantedLeaseMs = Math.max(1, session.transport.expiresAt - now);
    if (renew) {
      if (leg.leaseGranted || leg.session === session) return;
      leg.leaseGranted = true;
      renewed = true;
      grantedLeaseMs = Math.max(1, Math.min(this.leaseMs, leg.expiresAt - now));
      session.transport.renewLease(grantedLeaseMs);
    }
    this.markLegAuthenticated(leg);
    leg.session = session;
    session.leg = leg;
    clearTimeout(session.grace);
    const sent = await session.transport.control({
      type: 'bound_relay_leg', challenge, renewed, leaseMs: grantedLeaseMs,
    }, leg.path);
    if (sent && session.leg === leg && leg.path.ready()) session.transport.setRelay(leg.path);
  }

  authorizeSession(msg) {
    return msg.userId === this.ownerUserId &&
      msg.tenantId === this.ownerTenantId && msg.webId === this.webId;
  }

  resolveLocalEndpoint() {
    const inProcess = typeof this.inProcessEndpoint === 'function'
      ? this.inProcessEndpoint()
      : this.inProcessEndpoint;
    return resolvePinnedEndpoint(this.getLocalOrigin(), inProcess);
  }

  async ensureBrowserCookieEntry(endpoint, forceRefresh) {
    if (!this.getLaunchToken) return null;
    const cacheKey = `${endpoint.connectHost}:${endpoint.connectPort}:${endpoint.authorityOrigin}`;
    const cached = this.browserCookie;
    if (cached?.key === cacheKey && !forceRefresh) return cached;
    const token = this.getLaunchToken();
    if (!token) return null;
    const path = '/?' + new URLSearchParams({ token }).toString();
    const resp = await pinnedFetch(endpoint, path, {
      method: 'GET',
      signal: AbortSignal.timeout(10_000),
      headers: { Origin: endpoint.authorityOrigin, 'accept-encoding': 'identity' },
    });
    const cookie = parseFirstCookiePair(getSetCookieHeaders(resp.headers));
    if (!cookie) {
      throw new Error(`Failed to obtain local DSH browser cookie (HTTP ${resp.status})`);
    }
    const entry = Object.freeze({
      key: cacheKey,
      value: cookie,
      generation: ++this.browserCookieGeneration,
    });
    this.browserCookie = entry;
    return entry;
  }

  async ensureBrowserCookie(endpoint, forceRefresh) {
    return (await this.ensureBrowserCookieEntry(endpoint, forceRefresh))?.value || '';
  }

  invalidateBrowserCookie(entryOrGeneration) {
    if (entryOrGeneration === undefined || entryOrGeneration === null) return;
    if (typeof entryOrGeneration === 'object') {
      if (this.browserCookie === entryOrGeneration) {
        this.browserCookie = null;
      }
      return;
    }
    if (this.browserCookie?.generation === entryOrGeneration) {
      this.browserCookie = null;
    }
  }

  async collectBrowserBoot() {
    const endpoint = this.resolveLocalEndpoint();
    const cookie = await this.ensureBrowserCookie(endpoint, false);
    const response = await pinnedFetch(endpoint, '/', {
      headers: { 'accept-encoding': 'identity', ...(cookie ? { cookie } : {}) },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error('DSH could not supply the active browser profile');
    const html = await response.text();
    const match = /globalThis\["__DSH_BOOT__"\]\s*=\s*([\s\S]*?)<\/script>/u.exec(html);
    return match ? [{ kind: 'global', name: '__DSH_BOOT__', value: JSON.parse(match[1]) }] : [];
  }

  async mintOperatorCookie(endpoint) {
    if (!this.getLaunchToken) return '';
    const token = this.getLaunchToken();
    if (!token) return '';
    const path = '/connect?' + new URLSearchParams({ interactions: 'answer', token }).toString();
    const resp = await pinnedFetch(endpoint, path, {
      method: 'GET',
      signal: AbortSignal.timeout(10_000),
      headers: { Origin: endpoint.authorityOrigin, 'accept-encoding': 'identity' },
    });
    const cookie = parseFirstCookiePair(getSetCookieHeaders(resp.headers));
    if (!cookie) {
      throw new Error(`Failed to obtain local DSH operator cookie (HTTP ${resp.status})`);
    }
    return cookie;
  }

  async handleE2eeClientHello(leg, payload) {
    if (!leg?.allowed || leg.session || leg.leaseGranted || leg.handshaking ||
        Date.now() >= leg.expiresAt || payload.length > 1024 || ++leg.attempts > 4) return;
    leg.handshaking = true;
    try {
      const hello = decodeJSON(payload);
      if (!/^[A-Za-z0-9_-]{22}$/u.test(hello.logicalSessionId) ||
          hello.capabilities !== MULTIPATH_CAPABILITIES || this.sessions.has(hello.logicalSessionId)) {
        const error = new Error('Unsupported DSH Remote protocol; update the app and host together');
        error.code = 'INCOMPATIBLE';
        throw error;
      }
      if (this.sessions.size >= MAX_STREAMS) throw new Error('DSH remote session limit');
      const id = hello.logicalSessionId;
      const { hostHelloPayload, cipher } = await respondHostHandshake(this.e2eeSecret, payload, {
        hostId: this.hostId, webId: this.webId, tenantId: this.ownerTenantId, ownerUserId: this.ownerUserId,
        logicalSessionId: id,
      });
      const initialLeaseMs = leg.expiresAt - Date.now();
      if (!leg.path.ready() || this.sessions.has(id) || initialLeaseMs <= 0) return;
      leg.leaseGranted = true;
      this.markLegAuthenticated(leg);
      const session = { id, userId: this.ownerUserId, allowed: true, leg, admittedAt: Date.now(), rttMs: null };
      session.transport = new MultipathSession({
        cipher,
        leaseMs: this.leaseMs,
        initialLeaseMs,
        onData: (bytes) => this.dispatchInnerFrame(id, session, decodeClientFrame(bytes)),
        onControl: (message, path) => this.handleSessionControl(session, message, path),
        onClose: () => this.closeSessionResources(id),
        onStall: (path) => path?.close(),
      });
      session.peer = this.p2pEnabled ? new PeerPath(session.transport, {
        createPeer: this.createPeer,
        sendChannel: (channel, bytes) => channel.send(Buffer.from(bytes)),
        initiator: false,
        urls: this.iceServers,
        signalPath: () => session.leg?.path,
        onPath: () => this.armGrace(session),
      }) : null;
      this.sessions.set(id, session);
      leg.session = session;
      session.transport.setRelay(leg.path);
      this.sendRawFrame(leg.id, 0, MSG_E2EE_HOST_HELLO, hostHelloPayload);
      void session.transport.control({ type: 'lease_sync', leaseMs: initialLeaseMs }, leg.path).catch(() => {});
    } catch (err) {
      this.sendRawFrame(leg.id, 0, MSG_E2EE_ERROR, encodeJSON({
        code: err.code === 'AUTH_FAILED' ? 'AUTH_FAILED' : err.code === 'INCOMPATIBLE' ? 'INCOMPATIBLE' : 'HANDSHAKE_FAILED',
        message: err.code === 'INCOMPATIBLE' ? 'Host and app versions must match' : 'E2EE handshake rejected',
      }));
    } finally {
      leg.handshaking = false;
    }
  }

  async handleSessionControl(session, message, path) {
    if (message?.type === 'bind_relay_leg') {
      const leg = path.leg;
      if (leg?.allowed) await this.bindRelay(session, leg, message.challenge, false);
    } else if (message?.type === 'lease_renew') {
      const leg = path.leg;
      if (leg?.allowed) await this.bindRelay(session, leg, message.challenge, true);
    } else if (message?.type === 'rtt_ping' && Number.isFinite(message.ts)) {
      await session.transport?.control({ type: 'rtt_pong', ts: message.ts }, path).catch(() => {});
      if (Number.isFinite(message.lastRttMs) && message.lastRttMs >= 0) {
        session.rttMs = Math.round(message.lastRttMs);
      }
    } else if (message?.type === 'close_session') {
      this.closeSessionResources(session.id);
    } else if (session.peer) {
      await session.peer.handle(message, path);
    }
  }

  async handleFrame({ sessionId, streamId, msgType, payload }) {
    if (sessionId === 0 && msgType === MSG_CONTROL_JSON) {
      const message = decodeJSON(payload);
      if (!Number.isInteger(message?.sessionId) || message.sessionId <= 0 || message.sessionId > 0xffffffff) return;
      const id = message.sessionId;
      if (message.type === 'close_session') {
        this.detachRelay(id);
        return;
      }
      if (message.type !== 'open_session' || message.hostId !== this.hostId ||
          this.relayLegs.has(id) || this.relayLegs.size >= MAX_STREAMS ||
          !/^[A-Za-z0-9_-]{22}$/u.test(message.challenge)) return;
      const now = Date.now();
      const relayRemaining = Number.isSafeInteger(message.remainingMs) && message.remainingMs >= 0
        ? Math.min(this.leaseMs, message.remainingMs)
        : this.leaseMs;
      if (relayRemaining <= 0) return;
      const socket = this.ws;
      const leg = {
        id,
        challenge: message.challenge,
        allowed: this.authorizeSession(message),
        attempts: 0,
        expiresAt: now + relayRemaining,
        leaseGranted: false,
        relayAuthed: false,
        unauthTimer: this.authTimeoutMs > 0 ? setTimeout(() => this.detachRelay(id), this.authTimeoutMs) : null,
      };
      leg.path = createPath({
        send: (type, bytes) => {
          if (!this.paceRelay(type)) return false;
          if (!this.sendRawFrame(id, 0, type, bytes)) throw new Error('Relay unavailable');
          return true;
        },
        ready: () => this.ws === socket && socket?.readyState === WebSocket.OPEN && this.relayLegs.get(id) === leg,
        bufferedAmount: () => socket?.bufferedAmount ?? 0,
        close: () => this.detachRelay(id),
      });
      leg.path.leg = leg;
      this.relayLegs.set(id, leg);
      return;
    }
    const leg = this.relayLegs.get(sessionId);
    if (!leg?.allowed) return;
    if (streamId !== 0) {
      if (msgType === MSG_HTTP_REQ_HEAD && !leg.session) {
        this.sendRawFrame(leg.id, streamId, MSG_HTTP_RES_HEAD, encodeJSON({ status: 403 }));
        this.sendRawFrame(leg.id, streamId, MSG_HTTP_RES_BODY, 'E2EE handshake required');
        this.sendRawFrame(leg.id, streamId, MSG_HTTP_RES_END);
      }
      return;
    }
    if (msgType === MSG_E2EE_CLIENT_HELLO) return this.handleE2eeClientHello(leg, payload);
    if (msgType === MSG_E2EE_CTRL && payload.length >= 40) {
      const id = base64UrlEncode(payload.subarray(0, 16));
      const session = this.sessions.get(id);
      if (!session && !leg.session) {
        this.sendRawFrame(leg.id, 0, MSG_E2EE_ERROR, encodeJSON({ code: 'GENERATION_UNKNOWN' }));
      } else {
        session?.transport.receive(msgType, payload, leg.path);
      }
    } else if (msgType === MSG_E2EE_BOX) {
      leg.session?.transport.receive(msgType, payload, leg.path);
    }
  }

  dispatchInnerFrame(sessionId, session, { streamId, msgType, payload }) {
    if (!session.allowed || streamId === 0) throw new Error('Invalid application stream');
    const key = `${sessionId}:${streamId}`;

    if (msgType === MSG_HTTP_REQ_HEAD) {
      if (this.httpStreams.has(key) || this.wsStreams.has(key)) throw new Error('Duplicate stream');
      if (this.httpStreams.size + this.wsStreams.size >= MAX_STREAMS) {
        this.sendHttpError(sessionId, streamId, 429, 'Remote stream limit reached');
        return;
      }
      let head;
      try {
        head = decodeJSON(payload);
      } catch {
        this.sendHttpError(sessionId, streamId, 400, 'Invalid HTTP head JSON');
        return;
      }
      const hasWindow = Number.isInteger(head.windowBytes) && head.windowBytes > 0;
      const initialWindow = hasWindow
        ? Math.min(MAX_WINDOW_BYTES, Math.max(MIN_WINDOW_BYTES, head.windowBytes))
        : 0;

      const entry = {
        head,
        chunks: [],
        chunkCount: 0,
        totalBytes: 0,
        executing: false,
        aborted: false,
        flowControl: hasWindow,
        initialWindowBytes: initialWindow,
        sendWindowBytes: initialWindow,
        windowPaused: false,
        windowWaiter: null,
        windowMinBytes: 1,
        sseKeepaliveTimer: null,
        abortController: new AbortController(),
        timer: null,
        refreshTimer: null,
      };
      entry.refreshTimer = () => {
        clearTimeout(entry.timer);
        if (entry.aborted) return;
        // Exempt backpressure-paused streams from idle timeout while the underlying session is alive
        if (entry.windowPaused && this.sessions.get(sessionId) === session && !session.transport?.closed) {
          return;
        }
        entry.timer = setTimeout(() => {
          const cur = this.httpStreams.get(key);
          if (cur !== entry) return;
          if (entry.windowPaused && this.sessions.get(sessionId) === session && !session.transport?.closed) {
            return;
          }
          this.cancelHttpStream(key, entry);
          if (entry.executing) {
            void this.sendStreamFrame(sessionId, streamId, MSG_HTTP_ABORT, 'DSH request timed out', session).catch(() => {});
          } else {
            this.sendHttpError(sessionId, streamId, 504, 'DSH request timed out');
          }
        }, this.requestTimeoutMs);
      };
      entry.refreshTimer();
      this.httpStreams.set(key, entry);
      return;
    }

    if (msgType === MSG_HTTP_REQ_BODY) {
      const entry = this.httpStreams.get(key);
      if (!entry) return;
      if (entry.executing) throw new Error('Body after request end');
      if (payload.byteLength === 0) return;
      entry.refreshTimer();
      const totalBytes = entry.totalBytes + payload.byteLength;
      if (++entry.chunkCount > MAX_REQUEST_CHUNKS || totalBytes > MAX_REQUEST_BYTES ||
          this.httpRequestBytes + payload.byteLength > MAX_HOST_REQUEST_BYTES) {
        this.cancelHttpStream(key, entry);
        this.sendHttpError(sessionId, streamId, 413, 'DSH request body is too large');
        return;
      }
      this.httpRequestBytes += payload.byteLength;
      entry.totalBytes = totalBytes;
      entry.chunks.push(Buffer.from(payload));
      return;
    }

    if (msgType === MSG_HTTP_REQ_END) {
      const entry = this.httpStreams.get(key);
      if (!entry || entry.aborted) return;
      if (entry.executing) throw new Error('Duplicate request end');
      entry.executing = true;
      entry.refreshTimer();
      void this.executeHttpStream(sessionId, streamId, session, entry).catch(() => {
        if (!entry.aborted) this.sendHttpError(sessionId, streamId, 502, 'Local DSH request failed');
      }).finally(() => {
        clearTimeout(entry.timer);
        clearTimeout(entry.sseKeepaliveTimer);
        if (entry.windowWaiter) {
          const w = entry.windowWaiter;
          entry.windowWaiter = null;
          w();
        }
        if (this.httpStreams.get(key) === entry) {
          this.httpStreams.delete(key);
          this.httpRequestBytes -= entry.totalBytes;
        }
      });
      return;
    }

    if (msgType === MSG_HTTP_RES_WINDOW) {
      const entry = this.httpStreams.get(key);
      if (!entry || !entry.flowControl || entry.aborted) return;
      let credit;
      try {
        credit = decodeWindowUpdate(payload);
      } catch {
        return;
      }
      if (credit <= 0) return;
      const room = Math.max(0, entry.initialWindowBytes - entry.sendWindowBytes);
      if (room > 0) {
        entry.sendWindowBytes += Math.min(credit, room);
      }
      entry.refreshTimer();
      if (entry.windowWaiter && entry.sendWindowBytes >= (entry.windowMinBytes || 1)) {
        const wake = entry.windowWaiter;
        entry.windowWaiter = null;
        wake();
      }
      return;
    }

    if (msgType === MSG_HTTP_ABORT) {
      const entry = this.httpStreams.get(key);
      if (entry) this.cancelHttpStream(key, entry);
      return;
    }

    if (msgType === MSG_WS_OPEN) {
      if (this.wsStreams.has(key) || this.httpStreams.has(key)) throw new Error('Duplicate stream');
      if (this.httpStreams.size + this.wsStreams.size >= MAX_STREAMS) {
        void this.sendStreamFrame(sessionId, streamId, MSG_WS_CLOSE, encodeJSON({ code: 1008, reason: 'Remote stream limit reached', wasClean: false }), session).catch(() => {});
        return;
      }
      let info;
      try {
        info = decodeJSON(payload);
      } catch {
        void this.sendStreamFrame(sessionId, streamId, MSG_WS_CLOSE, encodeJSON({ code: 1002, reason: 'Invalid WS open frame', wasClean: false })).catch(() => {});
        return;
      }
      const entry = { socket: null, fragments: new FragmentReader(), sendQueue: Promise.resolve() };
      this.wsStreams.set(key, entry);
      void this.openLocalWebSocket(sessionId, streamId, session, key, entry, info.path || '/api/remote.mux').catch(() => {
        if (this.wsStreams.get(key) !== entry) return;
        this.wsStreams.delete(key);
        void this.sendStreamFrame(sessionId, streamId, MSG_WS_CLOSE, encodeJSON({
          code: 1008, reason: 'Local DSH WebSocket rejected', wasClean: false,
        }), session).catch(() => {});
      });
      return;
    }

    if (msgType === MSG_WS_DATA_TEXT || msgType === MSG_WS_DATA_BIN) {
      const entry = this.wsStreams.get(key);
      const sock = entry?.socket;
      if (!sock || sock.readyState !== WebSocket.OPEN) return;
      const bytes = entry.fragments.push(msgType, payload);
      if (!bytes) return;
      if (sock.bufferedAmount + bytes.length > MAX_BUFFERED_BYTES * 4) {
        sock.close(4008, 'Remote receive queue exceeded');
        return;
      }
      sock.send(msgType === MSG_WS_DATA_TEXT ? new TextDecoder().decode(bytes) : bytes);
      return;
    }

    if (msgType === MSG_WS_CLOSE) {
      const entry = this.wsStreams.get(key);
      if (entry) {
        this.wsStreams.delete(key);
        let code = 1000;
        let reason = '';
        if (payload.byteLength > 0) {
          try {
            const parsed = decodeJSON(payload);
            if (typeof parsed.code === 'number') code = parsed.code;
            if (typeof parsed.reason === 'string') reason = parsed.reason;
          } catch {
            // ignore
          }
        }
        try { entry.socket?.close(code, reason); }
        catch { entry.socket?.close(1000); }
      }
    }
  }

  cancelHttpStream(key, entry) {
    if (this.httpStreams.get(key) !== entry) return;
    this.httpStreams.delete(key);
    this.httpRequestBytes -= entry.totalBytes;
    clearTimeout(entry.timer);
    clearTimeout(entry.sseKeepaliveTimer);
    entry.aborted = true;
    entry.abortController.abort();
    if (entry.windowWaiter) {
      const wake = entry.windowWaiter;
      entry.windowWaiter = null;
      wake();
    }
  }

  closeSessionStreamsOnly(sessionId) {
    const prefix = `${sessionId}:`;
    for (const [k, req] of this.httpStreams.entries()) {
      if (k.startsWith(prefix)) {
        this.cancelHttpStream(k, req);
      }
    }
    for (const [k, sock] of this.wsStreams.entries()) {
      if (k.startsWith(prefix)) {
        this.wsStreams.delete(k);
        sock.socket?.close(1000, 'session closed');
      }
    }
  }

  closeSessionResources(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.sessions.delete(sessionId);
    clearTimeout(session.grace);
    session.transport.close();
    if (session.peer) void session.peer.stop().catch(() => {});
    for (const [id, leg] of this.relayLegs) {
      if (leg.session === session) this.detachRelay(id);
    }
    this.closeSessionStreamsOnly(sessionId);
  }

  sendHttpError(sessionId, streamId, status, message, { forcePlaintext = false } = {}) {
    const send = forcePlaintext
      ? (msgType, payload) => this.sendRawFrame(sessionId, streamId, msgType, payload)
      : (msgType, payload) => { void this.sendStreamFrame(sessionId, streamId, msgType, payload).catch(() => {}); };
    send(MSG_HTTP_RES_HEAD, encodeJSON({
      status,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    }));
    send(MSG_HTTP_RES_BODY, message);
    send(MSG_HTTP_RES_END);
  }

  async rejectRoute(send) {
    await send(MSG_HTTP_RES_HEAD, encodeJSON({ status: 404, headers: {} }));
    await send(MSG_HTTP_RES_END);
  }

  async rejectForbiddenRoute(send) {
    await send(MSG_HTTP_RES_HEAD, encodeJSON({
      status: 403,
      headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    }));
    await send(MSG_HTTP_RES_BODY, JSON.stringify({ ok: false, error: 'Admin routes are forbidden over remote tunnel' }));
    await send(MSG_HTTP_RES_END);
  }

  async sendAsset(send, method, asset, wire, signal) {
    signal.throwIfAborted();
    await send(MSG_HTTP_RES_HEAD, encodeJSON({
      status: 200,
      headers: {
        'content-type': asset.meta.mimeType,
        'content-encoding': wire.encoding,
        'content-length': String(wire.bytes.length),
        'cache-control': 'no-store',
      },
    }), signal);
    if (method !== 'HEAD') {
      for (let offset = 0; offset < wire.bytes.length; offset += CHUNK_SIZE) {
        signal.throwIfAborted();
        await send(MSG_HTTP_RES_BODY, wire.bytes.subarray(offset, offset + CHUNK_SIZE), signal);
      }
    }
    await send(MSG_HTTP_RES_END, undefined, signal);
  }

  async executeHttpStream(sessionId, streamId, session, entry) {
    const { head, chunks, abortController } = entry;
    const method = String(head.method || 'GET').toUpperCase();
    const send = (type, payload, signal = abortController.signal) =>
      this.sendStreamFrame(sessionId, streamId, type, payload, session, signal);

    if (head.path !== undefined && typeof head.path !== 'string') {
      await this.rejectRoute(send);
      return;
    }
    const pathAndQuery = head.path ?? '/';
    const route = classifyHttpRoute(pathAndQuery);
    if (!route) {
      await this.rejectRoute(send);
      return;
    }
    if (route.kind === 'forbidden') {
      await this.rejectForbiddenRoute(send);
      return;
    }
    if (route.kind === 'internal') {
      const { parsed } = route;
      if (!['GET', 'HEAD'].includes(method)) return this.rejectRoute(send);
      const signal = AbortSignal.any([abortController.signal, AbortSignal.timeout(15_000)]);
      if (parsed.pathname.endsWith('bootstrap.json') && !parsed.search) {
        const rows = await this.collectIndexInjections();
        const snapshot = await this.frontend.prepare(rows);
        signal.throwIfAborted();
        session.assetManifest = snapshot;
        const bytes = Buffer.from(JSON.stringify({
          ...snapshot.manifest,
          p2pEnabled: this.p2pEnabled,
          iceServers: this.iceServers,
          theme: extractThemeFromInjections(rows),
          host: { hostId: this.hostId, hostName: this.hostName },
          session: { role: 'owner', userId: this.ownerUserId, tenantId: this.ownerTenantId },
        }));
        const asset = { bytes, meta: { mimeType: 'application/json' } };
        const wire = await this.frontend.representation(asset, head.headers?.['x-dsh-encoding'] === 'gzip', signal);
        return this.sendAsset(send, method, asset, wire, signal).catch(() =>
          send(MSG_HTTP_ABORT, 'Frontend transfer failed'));
      }
      if (parsed.pathname.endsWith('/asset') && parsed.searchParams.size === 2 &&
          parsed.searchParams.getAll('key').length === 1 && parsed.searchParams.getAll('rev').length === 1) {
        const asset = session.assetManifest?.resources.get(parsed.searchParams.get('key'));
        if (asset?.meta.rev === parsed.searchParams.get('rev') && session.assetManifest === this.frontend.snapshot) {
          const wire = await this.frontend.representation(asset, head.headers?.['x-dsh-encoding'] === 'gzip', signal);
          return this.sendAsset(send, method, asset, wire, signal).catch(() =>
            send(MSG_HTTP_ABORT, 'Frontend transfer failed'));
        }
      }
      return this.rejectRoute(send);
    }
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      return this.rejectRoute(send);
    }

    let endpoint;
    let targetUrl;
    try {
      endpoint = this.resolveLocalEndpoint();
      targetUrl = resolvePinnedTarget(endpoint, pathAndQuery);
    } catch {
      await send(MSG_HTTP_RES_HEAD, encodeJSON({ status: 400, headers: {} }));
      await send(MSG_HTTP_RES_END);
      return;
    }
    const reqBody = chunks.length > 0 ? Buffer.concat(chunks) : undefined;
    chunks.length = 0;
    const incoming = new Headers(head.headers || {});
    const nominated = nominatedConnectionHeaders(incoming);
    const headers = new Headers();
    for (const [name, value] of incoming) {
      if (REQUEST_STRIPPED_HEADERS.has(name) || nominated.has(name) ||
          name.startsWith('x-forwarded-') || name.startsWith('tiana-caller-') || name.startsWith('x-tiana-')) continue;
      headers.set(name, value);
    }
    headers.set('origin', targetUrl.origin);
    headers.set('x-dsh-remote-tunnel', '1');
    if (String(headers.get('accept') || '').toLowerCase().includes('text/event-stream')) {
      headers.set('accept-encoding', 'identity');
    }

    const doFetch = async (forceCookieRefresh) => {
      const cookieEntry = await this.ensureBrowserCookieEntry(endpoint, forceCookieRefresh);
      abortController.signal.throwIfAborted();
      if (cookieEntry?.value) headers.set('cookie', cookieEntry.value);
      const resp = await pinnedFetch(endpoint, pathAndQuery, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : reqBody,
        signal: abortController.signal,
      });
      return { resp, cookieEntry };
    };

    const waitForWindow = async (minBytes = 1) => {
      while (entry.flowControl && entry.sendWindowBytes < minBytes) {
        abortController.signal.throwIfAborted();
        entry.windowPaused = true;
        entry.windowMinBytes = minBytes;
        clearTimeout(entry.timer);
        await new Promise((resolve) => {
          const onAbort = () => {
            if (entry.windowWaiter === wake) entry.windowWaiter = null;
            resolve();
          };
          const wake = () => {
            abortController.signal.removeEventListener('abort', onAbort);
            resolve();
          };
          entry.windowWaiter = wake;
          abortController.signal.addEventListener('abort', onAbort, { once: true });
        });
        entry.windowPaused = false;
        entry.windowMinBytes = 1;
        entry.refreshTimer();
        abortController.signal.throwIfAborted();
      }
    };

    try {
      let { resp, cookieEntry } = await doFetch(false);
      if (resp.status === 401 && this.getLaunchToken) {
        if (method === 'GET' || method === 'HEAD') {
          await resp.body?.cancel().catch(() => {});
          ({ resp, cookieEntry } = await doFetch(true));
        } else {
          this.invalidateBrowserCookie(cookieEntry);
        }
      }

      entry.refreshTimer();

      const resNominated = nominatedConnectionHeaders(resp.headers);
      const resHeaders = {};
      resp.headers.forEach((value, key) => {
        const lower = key.toLowerCase();
        if (lower === 'set-cookie' || SHARED_HOP_BY_HOP_HEADERS.has(lower) || resNominated.has(lower)) return;
        resHeaders[lower] = value;
      });

      const isSse = resp.status === 200 && isEventStreamContentType(resHeaders['content-type']);
      if (isSse) {
        // Stripping Content-Length because keepalive comments may be injected at line boundaries
        delete resHeaders['content-length'];
      }
      let reader;
      let streamDone = false;
      let writeChain = Promise.resolve();

      // Track SSE UTF-8 multi-byte boundaries & line boundaries so keepalive NEVER splits a line or UTF-8 char
      let sseAtLineBoundary = true;
      let sseUtf8Pending = 0;
      let ssePendingKeepalive = false;

      const advanceSseBoundary = (bytes) => {
        for (let i = 0; i < bytes.byteLength; i += 1) {
          const b = bytes[i];
          if (sseUtf8Pending > 0) {
            if ((b & 0xc0) === 0x80) {
              sseUtf8Pending -= 1;
              continue;
            }
            sseUtf8Pending = 0;
          }
          if (b < 0x80) {
            sseUtf8Pending = 0;
          } else if ((b & 0xe0) === 0xc0) {
            sseUtf8Pending = 1;
          } else if ((b & 0xf0) === 0xe0) {
            sseUtf8Pending = 2;
          } else if ((b & 0xf8) === 0xf0) {
            sseUtf8Pending = 3;
          } else {
            sseUtf8Pending = 0;
          }
        }
        if (bytes.byteLength > 0) {
          sseAtLineBoundary = sseUtf8Pending === 0 && bytes[bytes.byteLength - 1] === 0x0a;
        }
      };

      const sendKeepaliveNow = async () => {
        if (streamDone || entry.aborted) return;
        await waitForWindow(SSE_KEEPALIVE_BYTES.byteLength);
        if (streamDone || entry.aborted) return;
        if (entry.flowControl) {
          entry.sendWindowBytes -= SSE_KEEPALIVE_BYTES.byteLength;
        }
        entry.refreshTimer();
        await send(MSG_HTTP_RES_BODY, SSE_KEEPALIVE_BYTES);
        sseAtLineBoundary = true;
        sseUtf8Pending = 0;
        ssePendingKeepalive = false;
      };

      const scheduleKeepalive = () => {
        clearTimeout(entry.sseKeepaliveTimer);
        if (!isSse || streamDone || entry.aborted || this.sseKeepaliveMs <= 0) return;
        entry.sseKeepaliveTimer = setTimeout(() => {
          if (streamDone || entry.aborted) return;
          writeChain = writeChain.then(async () => {
            if (streamDone || entry.aborted) return;
            if (!sseAtLineBoundary || sseUtf8Pending > 0) {
              // Defer keepalive until upstream finishes the current line / UTF-8 sequence
              ssePendingKeepalive = true;
              entry.refreshTimer();
              return;
            }
            await sendKeepaliveNow();
            scheduleKeepalive();
          }).catch(() => {});
        }, this.sseKeepaliveMs);
      };

      try {
        const resHeadObj = {
          status: resp.status,
          statusText: resp.statusText,
          headers: resHeaders,
          ...(entry.flowControl ? { flowControl: true } : {}),
        };
        await send(MSG_HTTP_RES_HEAD, encodeJSON(resHeadObj));

        if (resp.body && method !== 'HEAD') {
          reader = resp.body.getReader();
          scheduleKeepalive();
          while (true) {
            abortController.signal.throwIfAborted();
            await waitForWindow(1);
            const { done, value } = await reader.read();
            if (done) {
              streamDone = true;
              break;
            }
            scheduleKeepalive();
            let offset = 0;
            while (offset < value.byteLength) {
              await waitForWindow(1);
              abortController.signal.throwIfAborted();
              const maxChunk = entry.flowControl
                ? Math.min(CHUNK_SIZE, entry.sendWindowBytes)
                : CHUNK_SIZE;
              if (entry.flowControl && maxChunk <= 0) continue;
              const end = Math.min(value.byteLength, offset + maxChunk);
              const slice = value.subarray(offset, end);
              offset = end;
              if (entry.flowControl) {
                entry.sendWindowBytes -= slice.byteLength;
              }
              entry.refreshTimer();
              const writeOp = writeChain.then(async () => {
                if (entry.aborted) return;
                await send(MSG_HTTP_RES_BODY, slice);
                if (isSse) {
                  advanceSseBoundary(slice);
                  if (ssePendingKeepalive && sseAtLineBoundary && sseUtf8Pending === 0) {
                    await sendKeepaliveNow();
                    scheduleKeepalive();
                  }
                }
              });
              writeChain = writeOp.catch(() => {});
              await writeOp;
            }
          }
          await writeChain;
        }
      } finally {
        clearTimeout(entry.sseKeepaliveTimer);
        entry.sseKeepaliveTimer = null;
        if (reader) {
          if (!streamDone) await reader.cancel().catch(() => {});
          reader.releaseLock();
        } else if (resp.body && !resp.body.locked) {
          await resp.body.cancel().catch(() => {});
        }
      }
      await send(MSG_HTTP_RES_END);
    } catch {
      if (abortController.signal.aborted) return;
      await send(MSG_HTTP_ABORT, 'Local DSH request failed');
    }
  }

  async openLocalWebSocket(sessionId, streamId, session, key, entry, pathAndQuery) {
    const endpoint = this.resolveLocalEndpoint();
    const wsUrl = resolvePinnedTarget(endpoint, pathAndQuery);
    if (wsUrl.pathname !== '/api/remote.mux' || !pathAndQuery.match(/^\/api\/remote\.mux(?:\?|$)/u)) {
      throw new Error('Invalid DSH WebSocket route');
    }
    const origin = endpoint.authorityOrigin;

    const cookie = await this.mintOperatorCookie(endpoint);
    if (this.sessions.get(sessionId) !== session || this.wsStreams.get(key) !== entry) return;
    const headers = { Origin: origin };
    if (cookie) headers.Cookie = cookie;

    const sock = openPinnedWebSocket(endpoint, pathAndQuery, { headers });
    sock.binaryType = 'arraybuffer';
    entry.socket = sock;
    const connectTimer = setTimeout(() => sock.close(), 10_000);
    const send = (type, payload) => {
      if (this.wsStreams.get(key) !== entry) return;
      void this.sendStreamFrame(sessionId, streamId, type, payload, session).catch(() => {});
    };

    sock.addEventListener('open', () => {
      clearTimeout(connectTimer);
      send(MSG_WS_OPENED, encodeJSON({ protocol: sock.protocol || '' }));
    });

    sock.addEventListener('message', (event) => {
      const binary = typeof event.data !== 'string';
      const value = event.data;
      if (binary && !(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) return;
      const size = binary ? value.byteLength : Buffer.byteLength(value);
      entry.queued = (entry.queued ?? 0) + size;
      if (entry.queued > 16 * 1024 * 1024) {
        sock.close(4008, 'Remote WebSocket queue exceeded');
        return;
      }
      entry.sendQueue = entry.sendQueue.then(async () => {
        if (this.wsStreams.get(key) !== entry) return;
        const type = binary ? MSG_WS_DATA_BIN : MSG_WS_DATA_TEXT;
        await sendFragments(value, (part) => this.sendStreamFrame(sessionId, streamId, type, part, session));
      }).catch(() => sock.close(4008, 'Remote WebSocket send failed')).finally(() => { entry.queued -= size; });
    });

    sock.addEventListener('close', (ev) => {
      clearTimeout(connectTimer);
      void entry.sendQueue.finally(() => {
        if (this.wsStreams.get(key) !== entry) return;
        send(MSG_WS_CLOSE, encodeJSON({ code: ev.code || 1000, reason: ev.reason || '', wasClean: ev.wasClean }));
        this.wsStreams.delete(key);
      });
    });

    sock.addEventListener('error', () => {
      // close event handles cleanup
    });
  }
}
