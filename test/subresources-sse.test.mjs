import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { HostBridge, MAX_STREAMS as HOST_MAX_STREAMS } from '../src/host-bridge.js';
import {
  decodeClientFrame,
  decodeHostFrame,
  decodeWindowUpdate,
  encodeClientFrame,
  encodeJSON,
  encodeWindowUpdate,
  MSG_CONTROL_JSON,
  MSG_HTTP_RES_WINDOW,
} from '../src/protocol.js';
import { generateE2eeSecret } from '../src/state.js';
import {
  createConcurrencySemaphore,
  createTunnelEventSource,
  MAX_STREAMS as CLIENT_MAX_STREAMS,
  TunnelClient,
} from '../web-src/dsh-remote-entry.mjs';
import { generateLogicalSessionId } from '../web-src/e2ee.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));

function createConnectedTunnel(localOrigin, extraBridgeOptions = {}, extraTargetOptions = {}) {
  const secret = generateE2eeSecret();
  const bridge = new HostBridge({
    relayUrl: 'https://relay.example.test',
    e2eeSecret: secret,
    hostId: 'host-sub',
    hostName: 'Subresource Host',
    registrationKey: 'B'.repeat(43),
    localOrigin,
    ownerUserId: 'usr-1',
    ownerTenantId: 'ten-1',
    webId: 'web000000114',
    p2p: 'off',
    log: () => {},
    ...extraBridgeOptions,
  });

  const clientListeners = new Map();
  const emitToClient = (clientBytes) => {
    const ab = clientBytes.buffer.slice(clientBytes.byteOffset, clientBytes.byteOffset + clientBytes.byteLength);
    for (const fn of clientListeners.get('message') ?? []) fn({ data: ab });
  };

  bridge.ws = {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    send(raw) {
      const hf = decodeHostFrame(raw);
      if (hf.sessionId === 1) {
        emitToClient(encodeClientFrame(hf.streamId, hf.msgType, hf.payload));
      }
    },
    close() {
      this.readyState = WebSocket.CLOSED;
    },
  };
  bridge.registered = true;
  bridge.paceRelay = () => true;

  const fakeClientWs = {
    readyState: 1,
    bufferedAmount: 0,
    binaryType: 'arraybuffer',
    addEventListener(type, fn) {
      if (!clientListeners.has(type)) clientListeners.set(type, new Set());
      clientListeners.get(type).add(fn);
    },
    removeEventListener(type, fn) {
      clientListeners.get(type)?.delete(fn);
    },
    send(raw) {
      const cf = decodeClientFrame(raw);
      void bridge.handleFrame({ sessionId: 1, streamId: cf.streamId, msgType: cf.msgType, payload: cf.payload });
    },
    close() {
      this.readyState = 3;
      for (const fn of clientListeners.get('close') ?? []) fn();
    },
  };

  const challenge = generateLogicalSessionId();
  const tunnel = new TunnelClient(
    async () => {
      await bridge.handleFrame({
        sessionId: 0,
        streamId: 0,
        msgType: MSG_CONTROL_JSON,
        payload: encodeJSON({
          type: 'open_session',
          sessionId: 1,
          hostId: 'host-sub',
          userId: 'usr-1',
          tenantId: 'ten-1',
          webId: 'web000000114',
          challenge,
          remainingMs: 60_000,
        }),
      });
      setTimeout(() => {
        emitToClient(encodeClientFrame(0, MSG_CONTROL_JSON, encodeJSON({
          type: 'welcome',
          sessionId: 1,
          paired: true,
          challenge,
          selectedHostId: 'host-sub',
          user: { userId: 'usr-1', tenantId: 'ten-1', webId: 'web000000114' },
        })));
      }, 5);
      return fakeClientWs;
    },
    { hostId: 'host-sub', webId: 'web000000114', ownerUserId: 'usr-1', tenantId: 'ten-1', ...extraTargetOptions },
    () => {},
    () => {},
  );

  return { bridge, tunnel, secret };
}

test('protocol: MSG_HTTP_RES_WINDOW (0x17) round-trip and MAX_STREAMS=64', () => {
  assert.equal(MSG_HTTP_RES_WINDOW, 0x17);
  assert.equal(HOST_MAX_STREAMS, 64);
  assert.equal(CLIENT_MAX_STREAMS, 64);
  const encoded = encodeWindowUpdate(4 * 1024 * 1024);
  assert.equal(encoded.byteLength, 4);
  assert.equal(decodeWindowUpdate(encoded), 4 * 1024 * 1024);
  assert.throws(() => encodeWindowUpdate(0), RangeError);
  assert.throws(() => decodeWindowUpdate(new Uint8Array(3)), /Invalid window update/);
});

test('client-side 3xx following (loopback origin strip, 303 POST->GET, manual, error, max hops)', async () => {
  const localServer = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/file' && !url.searchParams.has('v')) {
      // Simulate DSH 302 redirect with loopback origin
      res.writeHead(302, { location: `http://127.0.0.1:${localServer.address().port}/api/file?path=pic.png&v=123` });
      res.end();
      return;
    }
    if (url.pathname === '/api/file' && url.searchParams.get('v') === '123') {
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end(Buffer.from('PNGDATA'));
      return;
    }
    if (url.pathname === '/api/post-303') {
      res.writeHead(303, { location: '/api/after-303' });
      res.end();
      return;
    }
    if (url.pathname === '/api/after-303') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ method: req.method }));
      return;
    }
    if (url.pathname === '/api/loop') {
      res.writeHead(302, { location: '/api/loop' });
      res.end();
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin);

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // Default 'follow' strips loopback origin and returns final 200 image
    const imgResp = await tunnel.fetch('/api/file?path=pic.png');
    assert.equal(imgResp.status, 200);
    assert.equal(await imgResp.text(), 'PNGDATA');

    // 'manual' returns raw 302 untouched
    const manualResp = await tunnel.fetch('/api/file?path=pic.png', { redirect: 'manual' });
    assert.equal(manualResp.status, 302);
    assert.match(manualResp.headers.get('location'), /v=123/);

    // 'error' throws TypeError on 3xx
    await assert.rejects(() => tunnel.fetch('/api/file?path=pic.png', { redirect: 'error' }), TypeError);

    // 303 rewrites POST -> GET without body
    const post303 = await tunnel.fetch('/api/post-303', { method: 'POST', body: 'payload' });
    assert.equal(post303.status, 200);
    assert.deepEqual(await post303.json(), { method: 'GET' });

    // > 5 redirect hops rejects with Too many redirects
    await assert.rejects(() => tunnel.fetch('/api/loop'), /Too many redirects/);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('> 32 MiB Range 206 streaming with MSG_HTTP_RES_WINDOW flow control & pause zero-overflow + 40 concurrent images', { timeout: 25000 }, async () => {
  const TOTAL_SIZE = 34 * 1024 * 1024; // 34 MiB (> 16 MiB client buffer cap)
  const PATTERN_CHUNK = Buffer.alloc(64 * 1024);
  for (let i = 0; i < PATTERN_CHUNK.length; i += 1) PATTERN_CHUNK[i] = i & 0xff;

  const expectedHash = createHash('sha256');
  for (let off = 0; off < TOTAL_SIZE; off += PATTERN_CHUNK.length) {
    expectedHash.update(PATTERN_CHUNK.subarray(0, Math.min(PATTERN_CHUNK.length, TOTAL_SIZE - off)));
  }
  const expectedDigest = expectedHash.digest('hex');

  const localServer = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/big-video.mp4') {
      const range = req.headers.range || 'bytes=0-';
      const match = /^bytes=(\d+)-(\d*)$/u.exec(range);
      const start = match ? Number(match[1]) : 0;
      const end = match && match[2] ? Number(match[2]) : TOTAL_SIZE - 1;
      const length = end - start + 1;
      res.writeHead(206, {
        'content-type': 'video/mp4',
        'accept-ranges': 'bytes',
        'content-range': `bytes ${start}-${end}/${TOTAL_SIZE}`,
        'content-length': String(length),
      });
      let sent = 0;
      const writeMore = () => {
        while (sent < length && !res.destroyed) {
          const toSend = Math.min(PATTERN_CHUNK.length, length - sent);
          const ok = res.write(PATTERN_CHUNK.subarray(0, toSend));
          sent += toSend;
          if (!ok) {
            res.once('drain', writeMore);
            return;
          }
        }
        if (!res.destroyed) res.end();
      };
      writeMore();
      return;
    }
    if (url.pathname.startsWith('/api/img/')) {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'image/png' });
        res.end(Buffer.from(`img-${url.pathname}`));
      }, 15);
      return;
    }
    if (url.pathname === '/api/rpc') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ rpc: 'ok' }));
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin);

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // 1. Stream 34 MiB video with Range: bytes=0-, pause mid-stream, and verify zero buffer overflow + exact hash
    const resp = await tunnel.fetch('/api/big-video.mp4', {
      headers: { Range: 'bytes=0-' },
    });
    assert.equal(resp.status, 206);
    assert.equal(resp.headers.get('accept-ranges'), 'bytes');
    assert.equal(resp.headers.get('content-range'), `bytes 0-${TOTAL_SIZE - 1}/${TOTAL_SIZE}`);

    const reader = resp.body.getReader();
    const actualHash = createHash('sha256');
    let received = 0;
    let pausedOnce = false;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      actualHash.update(value);
      received += value.byteLength;
      if (!pausedOnce && received >= 5 * 1024 * 1024) {
        pausedOnce = true;
        // Pause consumption for 120ms while HostBridge has 29 MiB remaining — flow control must prevent 16 MiB overflow!
        await new Promise((r) => setTimeout(r, 120));
      }
    }
    assert.equal(received, TOTAL_SIZE);
    assert.equal(actualHash.digest('hex'), expectedDigest);

    // 2. Burst 40 concurrent subresource images + concurrent JSON RPC -> zero 429s!
    const imgTasks = Array.from({ length: 40 }, (_, idx) =>
      tunnel.fetch(`/api/img/${idx}.png`, { subresource: true }).then(async (r) => ({
        status: r.status,
        text: await r.text(),
      })),
    );
    const rpcTask = tunnel.fetch('/api/rpc').then(async (r) => ({ status: r.status, body: await r.json() }));
    const [imgs, rpc] = await Promise.all([Promise.all(imgTasks), rpcTask]);
    assert.equal(rpc.status, 200);
    assert.deepEqual(rpc.body, { rpc: 'ok' });
    assert.equal(imgs.length, 40);
    assert.ok(imgs.every((item) => item.status === 200));

    // 3. Verify semaphore AbortSignal removes queued waiter immediately
    const sem = createConcurrencySemaphore(1);
    const release1 = await sem.acquire();
    const ac = new AbortController();
    const queuedPromise = sem.acquire(ac.signal);
    assert.equal(sem.queuedCount, 1);
    ac.abort();
    await assert.rejects(queuedPromise, (e) => e?.name === 'AbortError');
    assert.equal(sem.queuedCount, 0);
    release1();
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('EventSource named events, Last-Event-ID reconnect, HostBridge identity+keepalive, 204 permanent close, and close() abort', { timeout: 15000 }, async () => {
  const receivedHeaders = [];
  let sseConnects = 0;
  let upstreamClosed = false;

  const localServer = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/events') {
      sseConnects += 1;
      receivedHeaders.push({
        accept: req.headers.accept,
        acceptEncoding: req.headers['accept-encoding'],
        lastEventId: req.headers['last-event-id'] || '',
      });
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache',
      });
      res.flushHeaders();
      if (sseConnects === 1) {
        // Send BOM + named event + retry + multi-line data, then drop connection to test Last-Event-ID reconnect
        res.write('\uFEFFretry: 40\r\nid: evt-1\nevent: progress\ndata: line1\ndata: line2\n\n');
        setTimeout(() => res.end(), 30);
        return;
      }
      // Second connection: stay silent past sseKeepaliveMs (60ms) AND requestTimeoutMs (180ms) to verify keepalive + sliding timeout!
      res.on('close', () => { upstreamClosed = true; });
      setTimeout(() => {
        if (!res.destroyed) {
          res.write(`id: evt-2\ndata: resumed:${req.headers['last-event-id'] || ''}\n\n`);
        }
      }, 240);
      return;
    }
    if (url.pathname === '/api/events-204') {
      res.writeHead(204).end();
      return;
    }
    if (url.pathname === '/api/events-json') {
      res.writeHead(200, { 'content-type': 'application/json' }).end('{}');
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin, {
    sseKeepaliveMs: 60,
    requestTimeoutMs: 180,
  });

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    const TunnelEventSource = createTunnelEventSource((p, init) => tunnel.fetch(p, init), {
      baseHref: 'https://web000000114.example.test/web/web000000114/',
    });

    const events = [];
    const es = new TunnelEventSource('/api/events');
    try {
      const gotSecond = new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('SSE timed out')), 4000);
        es.addEventListener('progress', (ev) => {
          events.push({ type: ev.type, data: ev.data, id: ev.lastEventId });
        });
        es.onmessage = (ev) => {
          events.push({ type: 'message', data: ev.data, id: ev.lastEventId });
          clearTimeout(t);
          resolve();
        };
      });

      await gotSecond;
      assert.deepEqual(events[0], { type: 'progress', data: 'line1\nline2', id: 'evt-1' });
      assert.deepEqual(events[1], { type: 'message', data: 'resumed:evt-1', id: 'evt-2' });
      assert.equal(receivedHeaders[0].acceptEncoding, 'identity');
      assert.equal(receivedHeaders[1].lastEventId, 'evt-1');

      // close() aborts upstream within 200ms
      const closedAt = Date.now();
      es.close();
      assert.equal(es.readyState, 2);
      for (let i = 0; i < 20 && !upstreamClosed; i += 1) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.equal(upstreamClosed, true);
      assert.ok(Date.now() - closedAt < 250);
    } finally {
      es.close();
    }

    // 204 and wrong Content-Type permanently close without reconnecting
    for (const badPath of ['/api/events-204', '/api/events-json']) {
      const badEs = new TunnelEventSource(badPath);
      await new Promise((resolve) => { badEs.onerror = resolve; });
      assert.equal(badEs.readyState, 2);
    }
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('SW hardens HTML/SVG CSP without allow-same-origin and Option A has zero MutationObserver DOM Blob hacks', () => {
  const swSource = readFileSync(join(PROJECT_ROOT, 'web-src/dsh-remote-sw.js'), 'utf8');
  const swCodeOnly = swSource.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/\/\/.*$/gmu, '');
  assert.equal(swCodeOnly.includes('caches.open'), false, 'SW must never use CacheStorage');
  assert.equal(swCodeOnly.includes('allow-same-origin'), false, 'SW CSP sandbox must never include allow-same-origin');
  assert.ok(swCodeOnly.includes("x-content-type-options', 'nosniff'") || swCodeOnly.includes('nosniff'));
  assert.ok(swCodeOnly.includes('no-store'));
  assert.ok(swCodeOnly.includes('image/svg+xml'));
  assert.ok(swCodeOnly.includes('text/html'));
  assert.ok(swCodeOnly.includes('application/xhtml+xml'));

  const entrySource = readFileSync(join(PROJECT_ROOT, 'web-src/dsh-remote-entry.mjs'), 'utf8');
  const entryCodeOnly = entrySource.replace(/\/\*[\s\S]*?\*\//gu, '').replace(/\/\/.*$/gmu, '');
  assert.equal(entryCodeOnly.includes('MutationObserver'), false, 'Option A must not inject MutationObserver DOM Blob rewrites');
  assert.ok(entryCodeOnly.includes('__DSH_FILE_UPLOAD__'));
  assert.ok(entryCodeOnly.includes('Promise.withResolvers'));
  assert.ok(entryCodeOnly.includes('AbortSignal.any'));
  assert.ok(entryCodeOnly.includes('mountNoSwBanner'));
  assert.equal(swCodeOnly.includes('mostRecentClientId'), false, 'SW must not have latestPort/mostRecentClientId fallback');
  assert.ok(swCodeOnly.includes('dsh-remote:sw-request-port'), 'SW must support idle wakeup port rebind');
  assert.ok(swCodeOnly.includes("headers.append('content-security-policy'"), 'SW must append CSP to preserve stricter upstream policies');
});

test('Round 2 #4 & #12: cross-origin redirect strips sensitive headers, HEAD 303 stays HEAD, 307 replays body/rejects stream, error rejects 302 without Location', async () => {
  const seenLocal = [];
  const localServer = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    seenLocal.push({ path: url.pathname, method: req.method, contentType: req.headers['content-type'] || '', body });

    if (url.pathname === '/api/head-303') {
      res.writeHead(303, { location: '/api/head-target' });
      res.end();
      return;
    }
    if (url.pathname === '/api/head-target') {
      res.writeHead(200, { 'x-seen-method': req.method, 'x-seen-ct': req.headers['content-type'] || '' });
      res.end(req.method === 'HEAD' ? undefined : 'body');
      return;
    }
    if (url.pathname === '/api/post-303-ct') {
      res.writeHead(303, { location: '/api/head-target' });
      res.end();
      return;
    }
    if (url.pathname === '/api/302-no-loc') {
      res.writeHead(302).end();
      return;
    }
    if (url.pathname === '/api/post-307') {
      res.writeHead(307, { location: '/api/307-target' });
      res.end();
      return;
    }
    if (url.pathname === '/api/307-target') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ method: req.method, body }));
      return;
    }
    if (url.pathname === '/api/to-external') {
      res.writeHead(302, { location: 'https://cdn.example.test/file.bin' });
      res.end();
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin);

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // 1. HEAD + 303 stays HEAD
    const headResp = await tunnel.fetch('/api/head-303', { method: 'HEAD' });
    assert.equal(headResp.status, 200);
    assert.equal(headResp.headers.get('x-seen-method'), 'HEAD');

    // 2. POST + 303 -> GET and strips Content-Type
    const post303 = await tunnel.fetch('/api/post-303-ct', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ a: 1 }),
    });
    assert.equal(post303.status, 200);
    assert.equal(post303.headers.get('x-seen-method'), 'GET');
    assert.equal(post303.headers.get('x-seen-ct'), '');

    // 3. redirect: 'error' throws TypeError on 302 EVEN WITHOUT Location header
    await assert.rejects(() => tunnel.fetch('/api/302-no-loc', { redirect: 'error' }), TypeError);

    // 4. POST + 307 replays buffered body & Request instance body faithfully
    const post307 = await tunnel.fetch('/api/post-307', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: 'replay-payload-307',
    });
    assert.deepEqual(await post307.json(), { method: 'POST', body: 'replay-payload-307' });

    const req307 = new Request('https://dsh.local/api/post-307', { method: 'POST', body: 'from-request-instance' });
    const req307Resp = await tunnel.fetch('/api/post-307', { method: 'POST', _sourceRequest: req307 });
    assert.deepEqual(await req307Resp.json(), { method: 'POST', body: 'from-request-instance' });

    // 5. POST + 307 with non-replayable ReadableStream throws TypeError
    const streamBody = new ReadableStream({
      start(c) { c.enqueue(new TextEncoder().encode('stream-once')); c.close(); },
    });
    await assert.rejects(() => tunnel.fetch('/api/post-307', { method: 'POST', body: streamBody }), TypeError);

    // 6. Cross-origin redirect strips Authorization, Cookie, Proxy-Authorization, X-Tiana-*, X-DSH-* and sets credentials: 'omit'
    let extCall = null;
    const extResp = await tunnel.fetch('/api/to-external', {
      headers: {
        Authorization: 'Bearer secret-token',
        Cookie: 'session=abc',
        'Proxy-Authorization': 'Basic xyz',
        'X-Tiana-Bootstrap': '1',
        'X-DSH-Remote-Tunnel': '1',
        Accept: 'application/octet-stream',
      },
      _externalFetch: async (url, init) => {
        extCall = { url, credentials: init.credentials, headers: Object.fromEntries(new Headers(init.headers).entries()) };
        return new Response('ext-ok', { status: 200 });
      },
    });
    assert.equal(extResp.status, 200);
    assert.equal(extCall.url, 'https://cdn.example.test/file.bin');
    assert.equal(extCall.credentials, 'omit');
    assert.equal(extCall.headers.authorization, undefined);
    assert.equal(extCall.headers.cookie, undefined);
    assert.equal(extCall.headers['proxy-authorization'], undefined);
    assert.equal(extCall.headers['x-tiana-bootstrap'], undefined);
    assert.equal(extCall.headers['x-dsh-remote-tunnel'], undefined);
    assert.equal(extCall.headers.accept, 'application/octet-stream');
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('Round 2 #10 & #11 & #12: exact window slicing never negative, paused stream survives idle timeout, seek aborts upstream, SSE line-boundary keepalive & EventSource spec edge cases', async () => {
  let seekUpstreamDestroyed = false;
  const localServer = createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/api/pausable-video') {
      res.on('close', () => { seekUpstreamDestroyed = true; });
      res.writeHead(206, {
        'content-type': 'video/mp4',
        'content-range': 'bytes 0-524287/524288',
      });
      const block = Buffer.alloc(64 * 1024, 0x41);
      let written = 0;
      const pump = () => {
        while (written < 8 && !res.destroyed) {
          written += 1;
          if (!res.write(block)) { res.once('drain', pump); return; }
        }
        if (!res.destroyed) res.end();
      };
      pump();
      return;
    }
    if (url.pathname === '/api/sse-utf8-split') {
      const fullLine = Buffer.from('data: 你好世界\n\n', 'utf8');
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'content-length': String(fullLine.byteLength), // must be stripped by HostBridge
      });
      res.flushHeaders();
      // Split a multi-byte UTF-8 char '你' (E4 BD A0) and line across two writes separated by > sseKeepaliveMs (40ms)
      const splitIdx = fullLine.indexOf(0xe4) + 1; // right inside '你'!
      res.write(fullLine.subarray(0, splitIdx));
      setTimeout(() => {
        if (!res.destroyed) {
          res.write(fullLine.subarray(splitIdx));
          setTimeout(() => res.end(), 80);
        }
      }, 90);
      return;
    }
    if (url.pathname === '/api/sse-close-mid-chunk') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end('data: first\n\ndata: second\n\n');
      return;
    }
    if (url.pathname === '/api/sse-cr-eof') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.end('data: cr-only\r\r');
      return;
    }
    if (url.pathname === '/api/sse-201') {
      res.writeHead(201, { 'content-type': 'text/event-stream' });
      res.end('data: nope\n\n');
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(
    localOrigin,
    { sseKeepaliveMs: 40, requestTimeoutMs: 120 },
    { windowBytes: 64 * 1024, responseIdleMs: 120 },
  );

  // Assert HostBridge sendWindowBytes never dips below 0
  let minObservedWindow = Infinity;
  const origSendFrame = bridge.sendStreamFrame.bind(bridge);
  bridge.sendStreamFrame = async (...args) => {
    for (const entry of bridge.httpStreams.values()) {
      if (entry.flowControl) minObservedWindow = Math.min(minObservedWindow, entry.sendWindowBytes);
    }
    return origSendFrame(...args);
  };

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // 1. Paused video stream with 64 KiB window survives > 180ms (> 120ms requestTimeoutMs), then seek/cancel aborts upstream
    const videoResp = await tunnel.fetch('/api/pausable-video', { windowBytes: 64 * 1024 });
    assert.equal(videoResp.status, 206);
    const reader = videoResp.body.getReader();
    const first = await reader.read();
    assert.ok(first.value.byteLength > 0);
    await new Promise((r) => setTimeout(r, 180)); // longer than 120ms idle timeout while paused
    const second = await reader.read();
    assert.ok(!second.done && second.value.byteLength > 0, 'paused stream must survive idle timeout');
    assert.ok(minObservedWindow >= 0, `sendWindowBytes must never go negative (observed ${minObservedWindow})`);
    await reader.cancel();
    for (let i = 0; i < 20 && !seekUpstreamDestroyed; i += 1) await new Promise((r) => setTimeout(r, 10));
    assert.equal(seekUpstreamDestroyed, true, 'cancelling/seeking stream must send MSG_HTTP_ABORT and close upstream');

    // 2. SSE split mid-UTF-8 + mid-line: Content-Length stripped & keepalive deferred until \n boundary
    const sseRaw = await tunnel.fetch('/api/sse-utf8-split');
    assert.equal(sseRaw.headers.get('content-length'), null, 'SSE response must strip Content-Length');
    const sseText = await sseRaw.text();
    assert.ok(sseText.includes('data: 你好世界\n\n'), `SSE UTF-8 event must stay intact, got: ${JSON.stringify(sseText)}`);
    assert.equal(sseText.includes('\ufffd'), false, 'must not contain UTF-8 replacement char');

    // 3. EventSource spec edge cases
    let nativeEsCalledWith = null;
    class FakeNativeES {
      constructor(url) { nativeEsCalledWith = url; }
      close() {}
    }
    const TunnelES = createTunnelEventSource((p, init) => tunnel.fetch(p, init), {
      baseHref: 'https://web000000114.example.test/web/web000000114/',
      NativeEventSource: FakeNativeES,
    });

    // 3a. /_tiana/* bypasses tunnel and delegates to native EventSource
    const platformEs = new TunnelES('/_tiana/events');
    assert.equal(platformEs instanceof FakeNativeES, true);
    assert.match(nativeEsCalledWith, /\/_tiana\/events$/);

    // 3b. Calling close() inside first event prevents second event in SAME chunk from dispatching
    const received = [];
    const esClose = new TunnelES('/api/sse-close-mid-chunk');
    await new Promise((resolve) => {
      esClose.onmessage = (ev) => {
        received.push(ev.data);
        esClose.close();
        setTimeout(resolve, 40);
      };
    });
    assert.deepEqual(received, ['first']);

    // 3c. Standalone CR blank line before EOF dispatches event cleanly
    const crEvents = [];
    const esCr = new TunnelES('/api/sse-cr-eof');
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('CR event not dispatched')), 2000);
      esCr.onmessage = (ev) => {
        crEvents.push(ev.data);
        esCr.close();
        clearTimeout(t);
        resolve();
      };
    });
    assert.deepEqual(crEvents, ['cr-only']);

    // 3d. Status 201 (non-200) fails permanently (readyState === 2)
    const es201 = new TunnelES('/api/sse-201');
    await new Promise((resolve) => { es201.onerror = resolve; });
    assert.equal(es201.readyState, 2);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('SSE keepalive comment does not split multi-line data events', async () => {
  const upstream = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.write('data: first\n');
    setTimeout(() => res.end('data: second\n\n'), 120);
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const { bridge, tunnel, secret } = createConnectedTunnel(
    `http://127.0.0.1:${upstream.address().port}`,
    { sseKeepaliveMs: 40 },
  );
  try {
    await tunnel.authenticate(await tunnel.connect(), secret);
    const ES = createTunnelEventSource((p, init) => tunnel.fetch(p, init), {
      baseHref: 'https://web000000114.example.test/',
    });
    const events = [];
    const es = new ES('/api/sse');
    es.onmessage = ({ data }) => {
      events.push(data);
      if (data.includes('second')) es.close();
    };
    await new Promise((resolve) => setTimeout(resolve, 220));
    es.close();
    assert.deepEqual(events, ['first\nsecond']);
  } finally {
    tunnel.close();
    bridge.stop();
    upstream.closeAllConnections();
    upstream.close();
  }
});

test('Flow-control credit send rejection yields to macrotasks across 1000 rejections', { timeout: 25000 }, async () => {
  const upstream = createServer((_req, res) => {
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(Buffer.alloc(512 * 1024, 0x41));
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const { bridge, tunnel, secret } = createConnectedTunnel(
    `http://127.0.0.1:${upstream.address().port}`,
    {},
    { windowBytes: 64 * 1024 },
  );
  try {
    await tunnel.authenticate(await tunnel.connect(), secret);
    const send = tunnel.sendAppFrame.bind(tunnel);
    let rejects = 0;
    let timerRanSinceFirstReject = false;
    tunnel.sendAppFrame = (sid, type, ...rest) => {
      if (type !== MSG_HTTP_RES_WINDOW) return send(sid, type, ...rest);
      rejects += 1;
      if (rejects === 1) {
        setTimeout(() => { timerRanSinceFirstReject = true; }, 0);
      }
      if (rejects >= 1000) {
        return send(sid, type, ...rest);
      }
      return Promise.reject(new Error('Fixture full send queue'));
    };
    const buf = await (await tunnel.fetch('/api/flow')).arrayBuffer();
    assert.equal(buf.byteLength, 512 * 1024);
    assert.ok(rejects >= 1000);
    assert.equal(timerRanSinceFirstReject, true, 'credit retry must yield to setTimeout macrotasks');
  } finally {
    tunnel.close();
    bridge.stop();
    upstream.closeAllConnections();
    upstream.close();
  }
});

test('External redirect opaqueredirect never double-submits non-idempotent POST 307', async () => {
  const upstream = createServer((req, res) => {
    if (req.url === '/api/post-ext-307') {
      res.writeHead(307, { location: 'https://external.example.test/upload' });
      res.end();
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve));
  const { bridge, tunnel, secret } = createConnectedTunnel(`http://127.0.0.1:${upstream.address().port}`);
  try {
    await tunnel.authenticate(await tunnel.connect(), secret);
    let extCalls = 0;
    await assert.rejects(
      () => tunnel.fetch('/api/post-ext-307', {
        method: 'POST',
        body: 'sensitive-upload',
        _externalFetch: async () => {
          extCalls += 1;
          return { type: 'opaqueredirect', status: 0, headers: new Headers() };
        },
      }),
      TypeError,
    );
    assert.equal(extCalls, 1, 'non-idempotent POST 307 opaqueredirect must invoke external fetch exactly once');
  } finally {
    tunnel.close();
    bridge.stop();
    upstream.close();
  }
});
