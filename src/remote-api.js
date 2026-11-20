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

export function isLoopbackAddress(addr) {
  if (!addr || typeof addr !== 'string') return false;
  const bare = addr.trim().replace(/^\[|\]$/gu, '').toLowerCase();
  return bare === '127.0.0.1' || bare === '::1' || bare === '::ffff:127.0.0.1';
}

export function isLoopbackHostHeader(hostHeader) {
  if (!hostHeader || typeof hostHeader !== 'string') return false;
  const trimmed = hostHeader.trim();
  if (!trimmed || /[\s/@?#\\]/u.test(trimmed)) return false;
  try {
    const parsed = new URL(`http://${trimmed}`);
    const host = parsed.hostname.toLowerCase();
    return host === '127.0.0.1' || host === '::1' || host === '[::1]' || host === 'localhost';
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

/**
 * Triple-guard check for all local-only `/api/tiana-remote/admin/*` endpoints:
 * 1. Verified loopback TCP socket address (`isLoopbackAddress(remoteAddress) === true`, fail-closed when missing)
 *    AND verified loopback `Host` header (`isLoopbackHostHeader(hostHeader) === true`, fail-closed when missing/non-loopback)
 * 2. Strict absence of `X-DSH-Remote-Tunnel` header (checked via presence, rejecting even empty-string values)
 * 3. Valid local DSH owner session via `connection.requestRejection` (supports numeric status code & Response return forms)
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

  // Guard 1a: require verified TCP loopback peer address (fail-closed when absent)
  if (!isLoopbackAddress(remoteAddress)) {
    return jsonResponse(403, { ok: false, error: 'Admin endpoints require local loopback access' });
  }

  // Guard 1b: require verified loopback Host header (fail-closed when missing or non-loopback)
  let effectiveHost;
  if (nodeReq) {
    effectiveHost = nodeReq.headers?.host;
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
  if (!isLoopbackHostHeader(effectiveHost)) {
    return jsonResponse(403, { ok: false, error: 'Admin endpoints require a loopback Host header' });
  }

  // Guard 3: verify local DSH owner session
  if (typeof connection?.requestRejection === 'function') {
    const authTarget = nodeReq ?? request;
    const rejection = await connection.requestRejection(authTarget, { allowAuthorizationHeader: false });
    const mapped = normalizeRejectionResponse(rejection, { mapAuthToForbidden: true });
    if (mapped) return mapped;
  }

  return null;
}

export async function guardPublicRequest(request, connection, meta = {}) {
  if (typeof connection?.requestRejection === 'function') {
    const authTarget = meta.nodeReq ?? request;
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
          if (body.allowedWebPlugins !== undefined) {
            if (!Array.isArray(body.allowedWebPlugins)) {
              return jsonResponse(400, { ok: false, error: 'allowedWebPlugins must be an array' });
            }
            patch.allowedWebPlugins = body.allowedWebPlugins.map((p) => String(p).trim()).filter(Boolean);
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
        if (v === undefined) continue;
        if (Array.isArray(v)) {
          for (const item of v) headers.append(k, String(item));
        } else {
          headers.set(k, String(v));
        }
      }
      const fetchReq = new Request(new URL(String(req.url || '/'), 'http://127.0.0.1').href, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : bodyBuf,
      });
      const response = await handler(fetchReq, {
        remoteAddress: req.socket?.remoteAddress,
        hostHeader: req.headers?.host,
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
