import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';
import { networkInterfaces } from 'node:os';
import { Readable } from 'node:stream';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_LOCAL_WS_MESSAGE = 32 * 1024 * 1024;

export function isOwnedLocalAddress(host) {
  if (!host || typeof host !== 'string') return false;
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (bare === '127.0.0.1' || bare === '::1' || bare === 'localhost') return true;
  if (!isIP(bare)) return false;
  return Object.values(networkInterfaces()).flat().some((entry) => entry?.address === bare);
}

function defaultPort(protocol) {
  return protocol === 'https:' ? 443 : 80;
}

function normalizeConnectHost(hostname) {
  const bare = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  return bare === 'localhost' ? '127.0.0.1' : bare;
}

export function resolvePinnedEndpoint(origin, inProcess = null) {
  if (inProcess) {
    const { listenOrigin, boundHost, advertisedOrigin } = inProcess;
    if (!isOwnedLocalAddress(boundHost)) {
      throw new Error('DSH listener address is not owned by this host');
    }
    const listenUrl = new URL(listenOrigin);
    if (!['http:', 'https:'].includes(listenUrl.protocol) || listenUrl.username || listenUrl.password) {
      throw new Error('Invalid local DSH listener origin');
    }
    const connectHost = normalizeConnectHost(boundHost);
    if (!isIP(connectHost)) throw new Error('Pinned DSH listener host must be an IP literal');
    const connectPort = Number(listenUrl.port) || defaultPort(listenUrl.protocol);

    let authorityUrl = listenUrl;
    if (advertisedOrigin) {
      try {
        const adv = new URL(advertisedOrigin);
        const advPort = Number(adv.port) || defaultPort(adv.protocol);
        if (adv.protocol === listenUrl.protocol && advPort === connectPort &&
            !adv.username && !adv.password && adv.pathname === '/' && !adv.search && !adv.hash) {
          authorityUrl = adv;
        }
      } catch {
        // Ignore malformed advertised URL and stay on the bound listener origin.
      }
    }
    const advHostBare = normalizeConnectHost(authorityUrl.hostname);
    return {
      protocol: listenUrl.protocol,
      connectHost,
      connectPort,
      authorityOrigin: authorityUrl.origin,
      hostHeader: authorityUrl.host,
      servername: isIP(advHostBare) ? '' : advHostBare,
    };
  }

  const base = new URL(origin);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password ||
      !['127.0.0.1', '[::1]', 'localhost'].includes(base.hostname)) {
    throw new Error('DSH must use a loopback HTTP origin');
  }
  const connectHost = normalizeConnectHost(base.hostname);
  const connectPort = Number(base.port) || defaultPort(base.protocol);
  return {
    protocol: base.protocol,
    connectHost,
    connectPort,
    authorityOrigin: base.origin,
    hostHeader: base.host,
    servername: base.hostname === 'localhost' ? 'localhost' : '',
  };
}

export function resolvePinnedTarget(endpoint, pathAndQuery) {
  if (typeof pathAndQuery !== 'string' || !pathAndQuery.startsWith('/') ||
      pathAndQuery.startsWith('//') || /[\\#\u0000-\u0020\u007f]/u.test(pathAndQuery)) {
    throw new Error('Invalid DSH request path');
  }
  const target = new URL(pathAndQuery, endpoint.authorityOrigin);
  if (target.origin !== endpoint.authorityOrigin || target.username || target.password) {
    throw new Error('DSH request must stay on the local origin');
  }
  return target;
}

function pinnedLookup(connectHost) {
  const family = isIP(connectHost) || 4;
  return (_hostname, options, callback) => {
    if (typeof options === 'function') {
      options(null, connectHost, family);
      return;
    }
    if (options?.all) {
      callback(null, [{ address: connectHost, family }]);
      return;
    }
    callback(null, connectHost, family);
  };
}

export function pinnedFetch(endpoint, pathAndQuery, { method = 'GET', headers = {}, body, signal } = {}) {
  const target = resolvePinnedTarget(endpoint, pathAndQuery);
  const reqFn = endpoint.protocol === 'https:' ? httpsRequest : httpRequest;
  const outHeaders = {};
  if (headers instanceof Headers) {
    headers.forEach((value, key) => { outHeaders[key] = value; });
  } else {
    Object.assign(outHeaders, headers);
  }
  outHeaders.host = endpoint.hostHeader;
  if (body !== undefined && outHeaders['content-length'] === undefined) {
    outHeaders['content-length'] = String(Buffer.byteLength(body));
  }

  return new Promise((resolve, reject) => {
    const abortReason = () => (signal?.reason instanceof Error ? signal.reason : new Error('Aborted'));
    if (signal?.aborted) {
      reject(abortReason());
      return;
    }
    const req = reqFn({
      protocol: endpoint.protocol,
      host: endpoint.connectHost,
      port: endpoint.connectPort,
      servername: endpoint.servername || undefined,
      lookup: pinnedLookup(endpoint.connectHost),
      agent: false,
      method,
      path: target.pathname + target.search,
      headers: outHeaders,
    });
    let currentRes = null;
    let settled = false;
    const cleanupAbort = () => {
      signal?.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      const err = abortReason();
      req.destroy(err);
      if (currentRes && !currentRes.destroyed) {
        currentRes.destroy(err);
      }
    };
    signal?.addEventListener('abort', onAbort, { once: true });

    req.on('error', (err) => {
      cleanupAbort();
      if (!settled) {
        settled = true;
        reject(err);
      }
    });
    req.once('response', (res) => {
      currentRes = res;
      if (signal?.aborted) {
        cleanupAbort();
        const err = abortReason();
        req.destroy(err);
        res.destroy(err);
        if (!settled) {
          settled = true;
          reject(err);
        }
        return;
      }
      const resHeaders = new Headers();
      for (const [key, value] of Object.entries(res.headers)) {
        if (value === undefined) continue;
        if (Array.isArray(value)) {
          for (const item of value) resHeaders.append(key, item);
        } else {
          resHeaders.set(key, value);
        }
      }
      const status = res.statusCode || 502;
      const noBody = method === 'HEAD' || status === 204 || status === 205 || status === 304;
      if (noBody) {
        cleanupAbort();
        res.resume();
        settled = true;
        resolve({
          ok: status >= 200 && status < 300,
          status,
          statusText: res.statusMessage || '',
          headers: resHeaders,
          body: null,
          text: async () => '',
        });
        return;
      }
      res.once('end', cleanupAbort);
      res.once('close', cleanupAbort);
      res.once('error', cleanupAbort);
      const webBody = Readable.toWeb(res);
      settled = true;
      resolve({
        ok: status >= 200 && status < 300,
        status,
        statusText: res.statusMessage || '',
        headers: resHeaders,
        body: webBody,
        async text() {
          const chunks = [];
          for await (const chunk of res) chunks.push(Buffer.from(chunk));
          return Buffer.concat(chunks).toString('utf8');
        },
      });
    });

    if (body !== undefined && method !== 'GET' && method !== 'HEAD') {
      req.end(body);
    } else {
      req.end();
    }
  });
}

function encodeMaskedWsFrame(opcode, payload) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const len = body.length;
  let headerLen = 2;
  if (len >= 126 && len <= 65535) headerLen = 4;
  else if (len > 65535) headerLen = 10;
  const out = Buffer.allocUnsafe(headerLen + 4 + len);
  out[0] = 0x80 | (opcode & 0x0f);
  if (len < 126) {
    out[1] = 0x80 | len;
  } else if (len <= 65535) {
    out[1] = 0x80 | 126;
    out.writeUInt16BE(len, 2);
  } else {
    out[1] = 0x80 | 127;
    out.writeBigUInt64BE(BigInt(len), 2);
  }
  const mask = randomBytes(4);
  mask.copy(out, headerLen);
  const dataOffset = headerLen + 4;
  for (let i = 0; i < len; i++) {
    out[dataOffset + i] = body[i] ^ mask[i & 3];
  }
  return out;
}

export function openPinnedWebSocket(endpoint, pathAndQuery, { headers = {} } = {}) {
  const target = resolvePinnedTarget(endpoint, pathAndQuery);
  const reqFn = endpoint.protocol === 'https:' ? httpsRequest : httpRequest;
  const wsKey = randomBytes(16).toString('base64');
  const expectedAccept = createHash('sha1').update(wsKey + WS_GUID).digest('base64');

  const events = new EventTarget();
  let readyState = 0; // CONNECTING
  let netSocket = null;
  let protocol = '';
  let closeEmitted = false;

  const emitClose = (code = 1006, reason = '', wasClean = false) => {
    if (closeEmitted) return;
    closeEmitted = true;
    readyState = 3;
    const ev = new Event('close');
    Object.assign(ev, { code, reason, wasClean });
    events.dispatchEvent(ev);
  };

  let failed = false;
  const fail = () => {
    if (failed) return;
    failed = true;
    events.dispatchEvent(new Event('error'));
    netSocket?.destroy();
    req.destroy();
    emitClose(1006, '', false);
  };

  const req = reqFn({
    protocol: endpoint.protocol,
    host: endpoint.connectHost,
    port: endpoint.connectPort,
    servername: endpoint.servername || undefined,
    lookup: pinnedLookup(endpoint.connectHost),
    agent: false,
    method: 'GET',
    path: target.pathname + target.search,
    headers: {
      ...headers,
      Host: endpoint.hostHeader,
      Connection: 'Upgrade',
      Upgrade: 'websocket',
      'Sec-WebSocket-Version': '13',
      'Sec-WebSocket-Key': wsKey,
    },
  });

  req.once('response', (res) => {
    res.resume();
    fail();
  });
  req.on('error', fail);

  req.once('upgrade', (res, socket, head) => {
    const accept = String(res.headers['sec-websocket-accept'] || '').trim();
    if (res.statusCode !== 101 || accept !== expectedAccept) {
      socket.destroy();
      fail(new Error('Invalid WebSocket upgrade'));
      return;
    }
    netSocket = socket;
    socket.setNoDelay(true);
    protocol = String(res.headers['sec-websocket-protocol'] || '').trim();
    readyState = 1; // OPEN

    let buffer = head?.length ? Buffer.from(head) : Buffer.alloc(0);
    let fragOpcode = 0;
    let fragChunks = [];
    let fragBytes = 0;

    const parseLoop = () => {
      while (buffer.length >= 2 && readyState <= 2) {
        const b0 = buffer[0];
        const b1 = buffer[1];
        const fin = (b0 & 0x80) !== 0;
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        if ((b0 & 0x70) !== 0) {
          fail(new Error('Invalid WS RSV bits'));
          return;
        }
        let offset = 2;
        let len = b1 & 0x7f;
        if (len === 126) {
          if (buffer.length < 4) return;
          len = buffer.readUInt16BE(2);
          offset = 4;
        } else if (len === 127) {
          if (buffer.length < 10) return;
          const big = buffer.readBigUInt64BE(2);
          if (big > BigInt(MAX_LOCAL_WS_MESSAGE)) {
            fail(new Error('WS frame exceeds limit'));
            return;
          }
          len = Number(big);
          offset = 10;
        }
        if (len > MAX_LOCAL_WS_MESSAGE) {
          fail(new Error('WS frame exceeds limit'));
          return;
        }
        if (masked) {
          if (buffer.length < offset + 4 + len) return;
        } else if (buffer.length < offset + len) {
          return;
        }
        let payload;
        if (masked) {
          const mask = buffer.subarray(offset, offset + 4);
          offset += 4;
          payload = Buffer.from(buffer.subarray(offset, offset + len));
          for (let i = 0; i < len; i++) payload[i] ^= mask[i & 3];
        } else {
          payload = buffer.subarray(offset, offset + len);
        }
        buffer = buffer.subarray(offset + len);

        if (opcode >= 0x08) {
          if (!fin || len > 125) {
            fail(new Error('Invalid WS control frame'));
            return;
          }
          if (opcode === 0x08) {
            let code = 1000;
            let reason = '';
            if (payload.length >= 2) {
              code = payload.readUInt16BE(0);
              reason = payload.subarray(2).toString('utf8');
            }
            if (readyState === 1) {
              readyState = 2;
              const reply = Buffer.allocUnsafe(2);
              reply.writeUInt16BE(code, 0);
              socket.write(encodeMaskedWsFrame(0x08, reply));
            }
            socket.end();
            emitClose(code, reason, true);
            return;
          }
          if (opcode === 0x09 && readyState === 1) {
            socket.write(encodeMaskedWsFrame(0x0a, payload));
          }
          continue;
        }

        if (opcode === 0x00) {
          if (!fragOpcode) {
            fail(new Error('Unexpected WS continuation'));
            return;
          }
        } else if (opcode === 0x01 || opcode === 0x02) {
          if (fragOpcode) {
            fail(new Error('Interleaved WS data frame'));
            return;
          }
          fragOpcode = opcode;
        } else {
          fail(new Error('Unsupported WS opcode'));
          return;
        }

        fragBytes += payload.length;
        if (fragBytes > MAX_LOCAL_WS_MESSAGE) {
          fail(new Error('WS message exceeds limit'));
          return;
        }
        fragChunks.push(Buffer.from(payload));

        if (fin) {
          const full = fragChunks.length === 1 ? fragChunks[0] : Buffer.concat(fragChunks, fragBytes);
          const msgOp = fragOpcode;
          fragOpcode = 0;
          fragChunks = [];
          fragBytes = 0;
          const ev = new Event('message');
          if (msgOp === 0x01) {
            ev.data = full.toString('utf8');
          } else {
            ev.data = full.buffer.slice(full.byteOffset, full.byteOffset + full.byteLength);
          }
          events.dispatchEvent(ev);
        }
      }
    };

    socket.on('data', (chunk) => {
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      parseLoop();
    });
    socket.on('error', () => {
      events.dispatchEvent(new Event('error'));
    });
    socket.on('close', () => {
      emitClose(1006, '', false);
    });

    events.dispatchEvent(new Event('open'));
    if (buffer.length > 0) parseLoop();
  });

  req.end();

  return {
    binaryType: 'arraybuffer',
    get readyState() { return readyState; },
    get protocol() { return protocol; },
    get bufferedAmount() { return netSocket?.writableLength ?? 0; },
    addEventListener: events.addEventListener.bind(events),
    removeEventListener: events.removeEventListener.bind(events),
    send(data) {
      if (readyState !== 1 || !netSocket) throw new Error('WebSocket is not open');
      if (typeof data === 'string') {
        netSocket.write(encodeMaskedWsFrame(0x01, Buffer.from(data, 'utf8')));
      } else if (data instanceof ArrayBuffer) {
        netSocket.write(encodeMaskedWsFrame(0x02, Buffer.from(data)));
      } else if (ArrayBuffer.isView(data)) {
        netSocket.write(encodeMaskedWsFrame(0x02, Buffer.from(data.buffer, data.byteOffset, data.byteLength)));
      } else {
        throw new TypeError('Unsupported WebSocket payload');
      }
    },
    close(code = 1000, reason = '') {
      if (readyState === 3) return;
      if (readyState === 0) {
        readyState = 3;
        req.destroy();
        emitClose(code, reason, false);
        return;
      }
      if (readyState === 1 && netSocket) {
        readyState = 2;
        const validCode = (code === 1000 || (code >= 3000 && code <= 4999)) ? code : 1000;
        const reasonBytes = Buffer.from(String(reason || '').slice(0, 100), 'utf8');
        const payload = Buffer.allocUnsafe(2 + reasonBytes.length);
        payload.writeUInt16BE(validCode, 0);
        reasonBytes.copy(payload, 2);
        netSocket.write(encodeMaskedWsFrame(0x08, payload), () => netSocket?.end());
      }
    },
  };
}
