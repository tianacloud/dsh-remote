import { isIP } from 'node:net';
import { normalizeStun } from '../web-src/peer-path.js';
import { formatPairingKey } from './state.js';

const MAX_ADMIN_BODY_BYTES = 64 * 1024;

function jsonResponse(status, body) {
  return Response.json(body, {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  });
}

function parseIpv4Bytes(ip) {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/u.test(ip)) return null;
  const parts = ip.split('.').map(Number);
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return parts;
}

function parseIpv6Words(ip) {
  if (isIP(ip) !== 6) return null;
  let normalized = ip.toLowerCase();
  const lastColon = normalized.lastIndexOf(':');
  const tail = normalized.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = parseIpv4Bytes(tail);
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }
  const words = groups.map((g) => Number.parseInt(g, 16));
  if (words.length !== 8 || words.some((w) => !Number.isInteger(w) || w < 0 || w > 0xffff)) {
    return null;
  }
  return words;
}

function parseIpAddress(addr) {
  if (!addr || typeof addr !== 'string') return null;
  if (/\s/u.test(addr)) return null;
  let bare = addr;
  const hasOpen = bare.startsWith('[');
  const hasClose = bare.endsWith(']');
  if (hasOpen || hasClose) {
    if (!hasOpen || !hasClose) return null;
    bare = bare.slice(1, -1);
    if (!bare.includes(':')) return null;
  }
  const pctIdx = bare.indexOf('%');
  if (pctIdx !== -1) {
    const zone = bare.slice(pctIdx + 1);
    bare = bare.slice(0, pctIdx);
    if (!bare.includes(':') || !zone || !/^[a-zA-Z0-9._:-]+$/u.test(zone)) {
      return null;
    }
  }
  const v4 = parseIpv4Bytes(bare);
  if (v4) return { family: 4, bytes: v4 };
  const v6 = parseIpv6Words(bare);
  if (!v6) return null;
  // Unwrap IPv4-mapped IPv6 (::ffff:0:0/96) in both dotted-quad and hex forms
  if (v6[0] === 0 && v6[1] === 0 && v6[2] === 0 && v6[3] === 0 && v6[4] === 0 && v6[5] === 0xffff) {
    return {
      family: 4,
      bytes: [(v6[6] >>> 8) & 0xff, v6[6] & 0xff, (v6[7] >>> 8) & 0xff, v6[7] & 0xff],
    };
  }
  return { family: 6, words: v6 };
}

function isLoopbackIpv4(bytes) {
  return bytes[0] === 127;
}

function isPrivateOrLocalIpv4(bytes) {
  const [a, b] = bytes;
  if (a === 127) return true; // Loopback: 127.0.0.0/8
  if (a === 10) return true; // RFC 1918: 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918: 172.16.0.0/12
  if (a === 192 && b === 168) return true; // RFC 1918: 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // RFC 6598 / Tailscale CGNAT: 100.64.0.0/10
  if (a === 169 && b === 254) return true; // RFC 3927 Link-Local: 169.254.0.0/16
  return false;
}

function isLoopbackIpv6(words) {
  return words[0] === 0 && words[1] === 0 && words[2] === 0 && words[3] === 0 &&
    words[4] === 0 && words[5] === 0 && words[6] === 0 && words[7] === 1;
}

function isPrivateOrLocalIpv6(words) {
  if (isLoopbackIpv6(words)) return true; // Loopback: ::1
  if ((words[0] & 0xffc0) === 0xfe80) return true; // Link-Local: fe80::/10
  if ((words[0] & 0xfe00) === 0xfc00) return true; // Unique Local (ULA, incl. Tailscale fd7a::): fc00::/7
  return false;
}

export function isLoopbackAddress(addr) {
  const parsed = parseIpAddress(addr);
  if (!parsed) return false;
  return parsed.family === 4 ? isLoopbackIpv4(parsed.bytes) : isLoopbackIpv6(parsed.words);
}

export function isPrivateOrLocalAddress(addr) {
  const parsed = parseIpAddress(addr);
  if (!parsed) return false;
  return parsed.family === 4 ? isPrivateOrLocalIpv4(parsed.bytes) : isPrivateOrLocalIpv6(parsed.words);
}

export function isValidHostHeader(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  if (/[\s\u0000-\u001f\u007f/@?#\\]/u.test(hostHeader) || hostHeader.endsWith(':')) return false;
  try {
    const parsed = new URL(`http://${hostHeader}`);
    if (!parsed.hostname) return false;
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function isLoopbackHostHeader(hostHeader) {
  if (!isValidHostHeader(hostHeader)) return false;
  try {
    const parsed = new URL(`http://${hostHeader}`);
    const host = parsed.hostname.toLowerCase();
    return host === 'localhost' || isLoopbackAddress(host);
  } catch {
    return false;
  }
}

async function readJsonBody(request) {
  const text = await request.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_ADMIN_BODY_BYTES) {
    throw Object.assign(new Error('Request body too large'), { status: 413 });
  }
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    throw Object.assign(new Error('Invalid JSON request body'), { status: 400 });
  }
}

function normalizeRejectionResponse(rejection, { mapAuthToForbidden = false } = {}) {
  if (rejection === undefined || rejection === null || rejection === false || rejection === 0) {
    return null;
  }
  if (typeof rejection === 'number') {
    const status = mapAuthToForbidden && (rejection === 401 || rejection === 403) ? 403 : rejection;
    return jsonResponse(status, {
      ok: false,
      error: status === 403 ? 'Local DSH owner session required' : 'Request rejected',
    });
  }
  if (rejection instanceof Response || (typeof rejection === 'object' && typeof rejection.status === 'number')) {
    if (mapAuthToForbidden && (rejection.status === 401 || rejection.status === 403)) {
      return jsonResponse(403, { ok: false, error: 'Local DSH owner session required' });
    }
    return rejection instanceof Response
      ? rejection
      : jsonResponse(rejection.status, { ok: false, error: 'Request rejected' });
  }
  return jsonResponse(403, { ok: false, error: 'Request rejected' });
}

function normalizeAuthTarget(nodeReq, request) {
  if (!nodeReq) return request;
  if (nodeReq.headers?.host === undefined && typeof nodeReq.headers?.[':authority'] === 'string') {
    return Object.create(nodeReq, {
      headers: { value: { ...nodeReq.headers, host: nodeReq.headers[':authority'] }, enumerable: true },
    });
  }
  return nodeReq;
}

/**
 * Triple-guard check for all local/LAN/Tailnet `/api/tiana-remote/admin/*` endpoints:
 * 1. Verified non-public TCP socket address (`isPrivateOrLocalAddress(remoteAddress) === true`, fail-closed when missing)
 *    AND syntactically valid `Host` header (for non-loopback peer or Host, `connection.requestRejection` is mandatory)
 * 2. Strict absence of `X-DSH-Remote-Tunnel` header (checked via presence, rejecting even empty-string values)
 * 3. Valid DSH trusted-host + owner session via `connection.requestRejection` (supports numeric status code & Response return forms)
 */
export async function guardAdminRequest(request, connection, meta = {}) {
  const { remoteAddress, hostHeader, hasTunnelHeader, nodeReq } = meta;

  // Guard 2: reject any request carrying X-DSH-Remote-Tunnel (even empty string)
  const tunnelHeaderPresent = Boolean(hasTunnelHeader) ||
    (nodeReq && 'x-dsh-remote-tunnel' in (nodeReq.headers || {})) ||
    request.headers.has('x-dsh-remote-tunnel');
  if (tunnelHeaderPresent) {
    return jsonResponse(403, { ok: false, error: 'Admin endpoints are forbidden over remote tunnel' });
  }

  // Guard 1a: require verified loopback, private LAN, Tailscale/CGNAT, link-local, or ULA peer address (fail-closed when absent)
  if (!isPrivateOrLocalAddress(remoteAddress)) {
    return jsonResponse(403, { ok: false, error: 'Admin endpoints require local or private network access' });
  }

  // Guard 1b: require syntactically valid non-empty Host header (supporting HTTP/2 :authority)
  let effectiveHost;
  if (nodeReq) {
    const hHost = nodeReq.headers?.host;
    const hAuth = nodeReq.headers?.[':authority'];
    if (hHost !== undefined && hAuth !== undefined && String(hHost).toLowerCase() !== String(hAuth).toLowerCase()) {
      return jsonResponse(403, { ok: false, error: 'Admin endpoints reject conflicting Host and :authority headers' });
    }
    effectiveHost = hHost ?? hAuth;
  } else if (hostHeader !== undefined) {
    effectiveHost = hostHeader;
  } else if (request.headers.has('host')) {
    effectiveHost = request.headers.get('host');
  } else {
    try {
      effectiveHost = new URL(request.url).host;
    } catch {
      effectiveHost = '';
    }
  }
  if (!isValidHostHeader(effectiveHost)) {
    return jsonResponse(403, { ok: false, error: 'Admin endpoints require a valid Host header' });
  }

  const isLoopback = isLoopbackAddress(remoteAddress) && isLoopbackHostHeader(effectiveHost);
  const hasRequestRejection = typeof connection?.requestRejection === 'function';
  if (!isLoopback && !hasRequestRejection) {
    return jsonResponse(403, {
      ok: false,
      error: 'Non-loopback admin access requires DSH trusted-host and owner-session verification',
    });
  }

  // Guard 3: verify DSH trusted-host + owner session
  if (hasRequestRejection) {
    const authTarget = normalizeAuthTarget(nodeReq, request);
    const rejection = await connection.requestRejection(authTarget, { allowAuthorizationHeader: false });
    const mapped = normalizeRejectionResponse(rejection, { mapAuthToForbidden: true });
    if (mapped) return mapped;
  }

  return null;
}

export async function guardPublicRequest(request, connection, meta = {}) {
  if (typeof connection?.requestRejection === 'function') {
    const authTarget = normalizeAuthTarget(meta.nodeReq, request);
    const rejection = await connection.requestRejection(authTarget, { allowAuthorizationHeader: false });
    const mapped = normalizeRejectionResponse(rejection, { mapAuthToForbidden: false });
    if (mapped) return mapped;
  }
  return null;
}

/**
 * Build a unified Fetch router for `/api/tiana-remote/*` endpoints.
 * Used by `registerWebServerRoutes` (preferred, with real TCP socket remoteAddress),
 * `registerRemoteRoutes` (Fetch fallback where admin routes fail closed), and tests.
 */
export function createRemoteApiHandler(controller, connection = null) {
  return async function handleRemoteApiRequest(request, meta = {}) {
    const url = new URL(request.url, 'http://127.0.0.1');
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // 1. Public redacted status (safe for both local & remote sidebar; strictly 8 spec fields)
    if (path === '/api/tiana-remote/status' || path === '/api/tiana-remote/public-status') {
      if (method !== 'GET' && method !== 'HEAD') {
        return jsonResponse(405, { ok: false, error: 'Method not allowed' });
      }
      const pubReject = await guardPublicRequest(request, connection, meta);
      if (pubReject) return pubReject;
      const pub = await controller.getPublicStatus();
      return method === 'HEAD'
        ? new Response(null, { status: 200, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } })
        : jsonResponse(200, pub);
    }

    // 2. Local-only Admin endpoints (triple-guarded)
    if (path === '/api/tiana-remote/admin' || path.startsWith('/api/tiana-remote/admin/')) {
      const adminReject = await guardAdminRequest(request, connection, meta);
      if (adminReject) return adminReject;

      try {
        if ((path === '/api/tiana-remote/admin/overview' || path === '/api/tiana-remote/admin/status') &&
            (method === 'GET' || method === 'HEAD')) {
          const overview = await controller.getAdminOverview();
          return method === 'HEAD' ? new Response(null, { status: 200 }) : jsonResponse(200, overview);
        }

        if (path === '/api/tiana-remote/admin/toggle' && method === 'POST') {
          const body = await readJsonBody(request);
          if (typeof body.enabled !== 'boolean') {
            return jsonResponse(400, { ok: false, error: '`enabled` boolean is required' });
          }
          const result = await controller.setEnabled(body.enabled);
          return jsonResponse(200, { ok: true, ...result });
        }

        if ((path === '/api/tiana-remote/admin/pairing-key/reveal' || path === '/api/tiana-remote/admin/key/reveal') &&
            method === 'POST') {
          const revealed = await controller.revealPairingKey();
          return jsonResponse(200, {
            ok: true,
            pairingKey: formatPairingKey(revealed.secret),
            secret: revealed.secret,
            fingerprint: revealed.fingerprint,
          });
        }

        if ((path === '/api/tiana-remote/admin/pairing-key/rotate' || path === '/api/tiana-remote/admin/key/rotate') &&
            method === 'POST') {
          const body = await readJsonBody(request);
          if (body.confirm !== true) {
            return jsonResponse(400, { ok: false, error: 'Explicit confirmation `{ confirm: true }` is required' });
          }
          const rotated = await controller.rotatePairingKey();
          return jsonResponse(200, {
            ok: true,
            pairingKey: formatPairingKey(rotated.secret),
            secret: rotated.secret,
            fingerprint: rotated.fingerprint,
            createdAt: rotated.createdAt,
            kickedSessions: rotated.kickedSessions ?? 0,
          });
        }

        if ((path === '/api/tiana-remote/admin/sessions/disconnect' || path === '/api/tiana-remote/admin/sessions/disconnect-all') &&
            method === 'POST') {
          const body = await readJsonBody(request);
          if (path.endsWith('/disconnect-all') || body.all === true || !body.sessionId) {
            const count = await controller.disconnectAllSessions();
            return jsonResponse(200, { ok: true, disconnected: count });
          }
          const removed = await controller.disconnectSession(String(body.sessionId));
          return jsonResponse(200, { ok: true, disconnected: removed ? 1 : 0 });
        }

        if (path === '/api/tiana-remote/admin/settings' && method === 'POST') {
          const body = await readJsonBody(request);
          const patch = {};
          if (body.hostName !== undefined) {
            const name = String(body.hostName).trim();
            if (!name || name.length > 128) {
              return jsonResponse(400, { ok: false, error: 'Invalid hostName (1..128 chars)' });
            }
            patch.hostName = name;
          }
          if (body.p2pEnabled !== undefined) {
            patch.p2pEnabled = Boolean(body.p2pEnabled);
          }
          if (body.stunUrls !== undefined) {
            try {
              patch.stunUrls = normalizeStun(body.stunUrls);
            } catch (err) {
              return jsonResponse(400, { ok: false, error: err.message });
            }
          }
          const updated = await controller.updateSettings(patch);
          return jsonResponse(200, { ok: true, ...updated });
        }

        if (path === '/api/tiana-remote/admin/repair' && method === 'POST') {
          const result = await controller.repairStaticShell();
          return jsonResponse(200, { ok: true, ...result });
        }

        if (path === '/api/tiana-remote/admin/token/renew' && method === 'POST') {
          const result = await controller.renewHostToken();
          return jsonResponse(200, { ok: true, ...result });
        }

        if (path === '/api/tiana-remote/admin/reconnect' && method === 'POST') {
          const result = await controller.reconnectBridge();
          return jsonResponse(200, { ok: true, ...result });
        }

        if (path === '/api/tiana-remote/admin/provision' && method === 'POST') {
          const body = await readJsonBody(request);
          const started = controller.startProvision(body);
          if (!started.started) {
            return jsonResponse(409, { ok: false, error: 'A provision task is already running' });
          }
          return jsonResponse(202, { ok: true, ...started });
        }

        if (path === '/api/tiana-remote/admin/provision-status' && (method === 'GET' || method === 'HEAD')) {
          return jsonResponse(200, { ok: true, ...controller.getProvisionStatus() });
        }

        return jsonResponse(404, { ok: false, error: 'Unknown admin route' });
      } catch (err) {
        const status = Number.isInteger(err?.status) ? err.status : 500;
        return jsonResponse(status, {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return null;
  };
}

async function readBoundedNodeBody(req, maxBytes = MAX_ADMIN_BODY_BYTES) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.byteLength;
    if (total > maxBytes) {
      req.resume();
      return null;
    }
    chunks.push(buf);
  }
  return chunks.length ? Buffer.concat(chunks, total) : Buffer.alloc(0);
}

function sendNodeJson(res, status, payload) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-content-type-options', 'nosniff');
  res.end(JSON.stringify(payload));
}

async function writeFetchResponseToNode(res, response) {
  res.statusCode = response.status;
  response.headers.forEach((value, key) => {
    res.setHeader(key, value);
  });
  if (!response.body) {
    res.end();
    return;
  }
  const buf = Buffer.from(await response.arrayBuffer());
  res.end(buf);
}

/**
 * Preferred DSH rc.5 native Node `(req, res)` registration via `webServer.register`.
 * Captures the real TCP `req.socket?.remoteAddress`, raw `req.headers.host`, exact
 * `'x-dsh-remote-tunnel' in req.headers`, and passes `req` directly to `connection.requestRejection(req)`.
 */
export function registerWebServerRoutes(webServer, connection, controller) {
  if (typeof webServer?.register !== 'function') {
    return () => {};
  }
  const handler = createRemoteApiHandler(controller, connection);

  const handleNode = async (req, res) => {
    try {
      const method = (req.method || 'GET').toUpperCase();
      let bodyBuf;
      if (method !== 'GET' && method !== 'HEAD') {
        bodyBuf = await readBoundedNodeBody(req, MAX_ADMIN_BODY_BYTES);
        if (bodyBuf === null) {
          sendNodeJson(res, 413, { ok: false, error: 'Request body too large' });
          return;
        }
      }
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers || {})) {
        if (v === undefined || k.startsWith(':')) continue;
        if (Array.isArray(v)) {
          for (const item of v) headers.append(k, String(item));
        } else {
          headers.set(k, String(v));
        }
      }
      const rawHost = req.headers?.host ?? req.headers?.[':authority'];
      const fetchReq = new Request(new URL(String(req.url || '/'), 'http://127.0.0.1').href, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : bodyBuf,
      });
      const response = await handler(fetchReq, {
        remoteAddress: req.socket?.remoteAddress ?? req.stream?.session?.socket?.remoteAddress,
        hostHeader: rawHost,
        hasTunnelHeader: 'x-dsh-remote-tunnel' in (req.headers || {}),
        nodeReq: req,
      });
      if (!response) {
        sendNodeJson(res, 404, { ok: false, error: 'Not found' });
        return;
      }
      await writeFetchResponseToNode(res, response);
    } catch (err) {
      if (!res.headersSent) {
        sendNodeJson(res, 500, { ok: false, error: err instanceof Error ? err.message : String(err) });
      } else {
        res.end();
      }
    }
  };

  const disposers = [
    webServer.register({ kind: 'exact', path: '/api/tiana-remote/public-status', handler: handleNode }),
    webServer.register({ kind: 'exact', path: '/api/tiana-remote/status', handler: handleNode }),
    webServer.register({ kind: 'prefix', path: '/api/tiana-remote/admin', handler: handleNode }),
  ];

  return () => {
    for (const dispose of disposers) {
      try { dispose?.(); } catch { /* ignore */ }
    }
  };
}

/**
 * Fallback route mounting onto `connection.fetch.register` when `webServer.register` is unavailable.
 * Because Fetch requests lack a verifiable TCP `remoteAddress`, all `/api/tiana-remote/admin/*`
 * routes fail closed with 403 while public status remains available.
 */
export function registerRemoteRoutes(connection, controller) {
  const registry = connection?.fetch;
  if (typeof registry?.register !== 'function') {
    return () => {};
  }
  const handler = createRemoteApiHandler(controller, connection);
  const routes = [
    { path: '/api/tiana-remote/status', methods: ['GET', 'HEAD'] },
    { path: '/api/tiana-remote/public-status', methods: ['GET', 'HEAD'] },
    { path: '/api/tiana-remote/admin/overview', methods: ['GET', 'HEAD'] },
    { path: '/api/tiana-remote/admin/status', methods: ['GET', 'HEAD'] },
    { path: '/api/tiana-remote/admin/toggle', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/pairing-key/reveal', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/key/reveal', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/pairing-key/rotate', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/key/rotate', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/sessions/disconnect', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/sessions/disconnect-all', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/settings', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/repair', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/token/renew', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/reconnect', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/provision', methods: ['POST'] },
    { path: '/api/tiana-remote/admin/provision-status', methods: ['GET', 'HEAD'] },
  ];

  const disposers = routes.map(({ path, methods }) => registry.register({
    path,
    methods,
    requestBody: 'buffered',
    fetch: async (request) => (await handler(request)) ?? jsonResponse(404, { ok: false, error: 'Not found' }),
  }));

  return () => {
    for (const dispose of disposers) {
      try { dispose?.(); } catch { /* ignore */ }
    }
  };
}
