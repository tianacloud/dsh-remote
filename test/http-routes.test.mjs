import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { classifyHttpRoute, HostBridge } from '../src/host-bridge.js';
import { pinnedFetch, resolvePinnedEndpoint } from '../src/local-transport.js';
import {
  decodeClientFrame,
  decodeHostFrame,
  encodeClientFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
  MSG_HTTP_REQ_BODY,
  MSG_HTTP_REQ_END,
  MSG_HTTP_REQ_HEAD,
  MSG_WS_OPEN,
} from '../src/protocol.js';
import { generateE2eeSecret } from '../src/state.js';
import { TunnelClient } from '../web-src/dsh-remote-entry.mjs';
import { generateLogicalSessionId } from '../web-src/e2ee.js';

function createConnectedTunnel(localOrigin, extraBridgeOptions = {}) {
  const secret = generateE2eeSecret();
  const bridge = new HostBridge({
    relayUrl: 'https://relay.example.test',
    e2eeSecret: secret,
    hostId: 'host-routes',
    hostName: 'Routes Host',
    registrationKey: 'A'.repeat(43),
    localOrigin,
    ownerUserId: 'usr-1',
    ownerTenantId: 'ten-1',
    webId: 'web-1',
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
          hostId: 'host-routes',
          userId: 'usr-1',
          tenantId: 'ten-1',
          webId: 'web-1',
          challenge,
          remainingMs: 60_000,
        }),
      });
      setTimeout(() => {
        emitToClient(encodeClientFrame(0, MSG_CONTROL_JSON, encodeJSON({
          type: 'welcome',
          sessionId: 1,
          challenge,
          selectedHostId: 'host-routes',
          user: { userId: 'usr-1', tenantId: 'ten-1', webId: 'web-1' },
        })));
      }, 5);
      return fakeClientWs;
    },
    { hostId: 'host-routes', webId: 'web-1', ownerUserId: 'usr-1', tenantId: 'ten-1' },
    () => {},
    () => {},
  );

  return { bridge, tunnel, secret };
}

test('classifyHttpRoute allows /api and third-party plugin routes including encoded query strings while rejecting reserved DSH core routes', () => {
  // Allowed internal endpoints
  assert.equal(classifyHttpRoute('/__dsh_remote__/bootstrap.json')?.kind, 'internal');
  assert.equal(classifyHttpRoute('/__dsh_remote__/asset?key=a&rev=1')?.kind, 'internal');

  // Allowed forward routes
  for (const path of [
    '/api',
    '/api/dynamicCordisRunner/inventory',
    '/dsh-market/status',
    '/dsh-market/installed',
    '/dsh-market/changelog?name=%40tianacloud%2Fdsh-remote&target=0.2.0',
    '/dsh-market/source-repo?name=%40deepseek-ai%2Fdsh',
    '/my-plugin/items/42?url=https%3A%2F%2Fexample.com%2Fa.b%3Fx%3D100%25&q=a%2Eb',
    '/connector',
    '/plugins-market/list',
    '/oauth2/status',
    '/inspector-custom/info',
    '/open-in-app-v2/list',
  ]) {
    const res = classifyHttpRoute(path);
    assert.equal(res?.kind, 'forward', `expected forward for ${path}`);
  }

  // Reserved DSH core/internal routes, case variants, trailing slashes, and percent-encoded evasions
  for (const blocked of [
    '/',
    '/?token=launch-secret',
    '/index.html',
    '/index.html/',
    '/INDEX.HTML',
    '/index.html?token=launch-secret',
    '/%69ndex.html',
    '/__dsh_remote__',
    '/__dsh_remote__/nonexistent',
    '/__DSH_REMOTE__/bootstrap.json',
    '/_tiana',
    '/_tiana/session',
    '/_TIANA/function-connection',
    '/connect',
    '/connect/',
    '/connect?interactions=answer&token=secret',
    '/Connect',
    '/CONNECT/foo',
    '/%63onnect',
    '/plugins',
    '/plugins/',
    '/plugins/events',
    '/plugins/dshmarket/client.js',
    '/PLUGINS/events',
    '/%70lugins/events',
    '/oauth',
    '/oauth/callback',
    '/oauth/callback?code=1&state=2',
    '/OAuth/callback',
    '/inspector',
    '/inspector/devtools',
    '/inspector/devtools/cdp',
    '/INSPECTOR/devtools',
    '/open-in-app',
    '/open-in-app/apps',
    '/open-in-app/icon/vscode',
    '/open-in-app/open',
    '/OPEN-IN-APP/apps',
  ]) {
    assert.equal(classifyHttpRoute(blocked), null, `expected null for reserved path ${blocked}`);
  }

  // Traversal, control characters, malformed escapes, external targets
  for (const invalid of [
    null,
    undefined,
    123,
    '',
    'api/ping',
    '//example.invalid/foo',
    'https://example.invalid/foo',
    '///connect',
    '/dsh-market//status',
    '/dsh-market/../connect',
    '/dsh-market/./status',
    '/dsh-market/%2e%2e/connect',
    '/dsh-market/%2e/status',
    '/dsh-market/%2fstatus',
    '/dsh-market/%5cstatus',
    '/dsh-market/%252e/connect',
    '/dsh-market/status#frag',
    '/dsh-market\\status',
    '/dsh-market/status\t',
    '/dsh-market/foo%00bar',
    '/dsh-market/foo%ZZbar',
  ]) {
    assert.equal(classifyHttpRoute(invalid), null, `expected null for invalid path ${String(invalid)}`);
  }
});

test('HostBridge forwards third-party plugin HTTP routes across REST methods and encoded queries, blocks reserved routes & non-mux WS, and limits 401 retry to GET/HEAD', async () => {
  const hits = [];
  let cookieGeneration = 1;
  let force401Once = false;

  const localServer = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/' && url.searchParams.get('token') === 'launch-secret') {
      res.writeHead(303, { 'set-cookie': `dsh_web=owner-gen-${cookieGeneration}; Path=/; HttpOnly` });
      res.end();
      return;
    }
    if (url.pathname === '/connect' && url.searchParams.get('token') === 'launch-secret') {
      res.writeHead(302, { 'set-cookie': 'dsh_web=op-ok; Path=/; HttpOnly' });
      res.end();
      return;
    }

    hits.push({
      method: req.method,
      url: req.url,
      cookie: req.headers.cookie || '',
      origin: req.headers.origin || '',
    });

    if (force401Once) {
      force401Once = false;
      cookieGeneration += 1;
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'stale cookie' }));
      return;
    }

    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks).toString('utf8');

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      method: req.method,
      url: req.url,
      pathname: url.pathname,
      search: url.search,
      nameParam: url.searchParams.get('name'),
      urlParam: url.searchParams.get('url'),
      qParam: url.searchParams.get('q'),
      pctParam: url.searchParams.get('pct'),
      body: rawBody,
      cookie: req.headers.cookie || '',
      origin: req.headers.origin || '',
    }));
  });
  localServer.on('upgrade', (req, socket) => {
    hits.push({ upgrade: req.url });
    socket.destroy();
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin, {
    getLaunchToken: () => 'launch-secret',
  });

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // 1. Third-party plugin routes work across GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      const hasBody = !['GET', 'HEAD', 'OPTIONS'].includes(method);
      const resp = await tunnel.fetch('/dsh-market/item', {
        method,
        ...(hasBody ? { headers: { 'content-type': 'application/json' }, body: JSON.stringify({ op: method }) } : {}),
      });
      assert.equal(resp.status, 200);
      const data = await resp.json();
      assert.equal(data.method, method);
      assert.equal(data.pathname, '/dsh-market/item');
      assert.equal(data.cookie, 'dsh_web=owner-gen-1');
      assert.equal(data.origin, localOrigin);
      if (hasBody) {
        assert.deepEqual(JSON.parse(data.body), { op: method });
      }
    }
    const headResp = await tunnel.fetch('/dsh-market/status', { method: 'HEAD' });
    assert.equal(headResp.status, 200);

    // 2. Query string containing %2F, %2E, %25, %40 is forwarded intact
    const queryPath = '/dsh-market/changelog?name=%40tianacloud%2Fdsh-remote&url=https%3A%2F%2Fexample.com%2Fa%2Fb&q=a%2Eb&pct=100%25';
    const queryResp = await tunnel.fetch(queryPath);
    assert.equal(queryResp.status, 200);
    const queryData = await queryResp.json();
    assert.equal(queryData.url, queryPath);
    assert.equal(queryData.nameParam, '@tianacloud/dsh-remote');
    assert.equal(queryData.urlParam, 'https://example.com/a/b');
    assert.equal(queryData.qParam, 'a.b');
    assert.equal(queryData.pctParam, '100%');

    // 3. 401 retry refreshes cookie for GET, but NEVER replays POST/PUT/PATCH/DELETE
    force401Once = true;
    const retriedGet = await tunnel.fetch('/dsh-market/status');
    assert.equal(retriedGet.status, 200);
    const retriedData = await retriedGet.json();
    assert.equal(retriedData.cookie, 'dsh_web=owner-gen-2');

    force401Once = true;
    const unretriedPost = await tunnel.fetch('/dsh-market/install', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"name":"pkg"}',
    });
    assert.equal(unretriedPost.status, 401);

    // 4. Unsupported HTTP method (PROPFIND via Fetch, and TRACE via raw inner frame) is rejected before hitting localServer
    const hitsBeforeBlocked = hits.length;
    const propfindResp = await tunnel.fetch('/dsh-market/status', { method: 'PROPFIND' });
    assert.equal(propfindResp.status, 404);
    const traceRes = await new Promise((resolve) => {
      const streamId = tunnel.nextStreamId++;
      let status = null;
      tunnel.httpStreams.set(streamId, {
        resolveHead(meta) { status = meta.status; },
        pushBody() {},
        finishBody() { resolve(status); },
        fail: (err) => resolve(err),
      });
      void tunnel.sendAppFrame(streamId, MSG_HTTP_REQ_HEAD, JSON.stringify({ method: 'TRACE', path: '/dsh-market/status', headers: {} }))
        .then(() => tunnel.sendAppFrame(streamId, MSG_HTTP_REQ_END));
    });
    assert.equal(traceRes, 404);
    assert.equal(hits.length, hitsBeforeBlocked);

    // 5. All reserved routes and traversal/encoding bypasses return 404 and NEVER hit localServer
    for (const blocked of [
      '/',
      '/?token=test',
      '/index.html',
      '/INDEX.HTML',
      '/%69ndex.html',
      '/__dsh_remote__/nonexistent',
      '/__dsh_remote__/bootstrap.json?x=1',
      '/_tiana/session',
      '/connect',
      '/Connect',
      '/%63onnect',
      '/plugins/events',
      '/plugins/dshmarket/client.js',
      '/oauth/callback?code=1&state=2',
      '/inspector/devtools',
      '/inspector/devtools/cdp',
      '/open-in-app/apps',
      '/OPEN-IN-APP/open',
      '/dsh-market/../connect',
      '/dsh-market/%2e%2e/connect',
    ]) {
      const r = await tunnel.fetch(blocked);
      assert.equal(r.status, 404, `expected 404 for ${blocked}`);
    }
    assert.equal(hits.length, hitsBeforeBlocked, 'no reserved route may reach localServer');

    // 6. WebSocket strictly allows only /api/remote.mux
    const session = [...bridge.sessions.values()][0];
    const openWsViaFrame = (wsPath) => new Promise((resolve) => {
      const streamId = tunnel.nextStreamId++;
      tunnel.wsStreams.set(streamId, {
        _remoteOpen() { resolve('opened'); },
        _remoteMessage() {},
        _remoteClose(code, reason) { resolve({ closed: true, code, reason }); },
      });
      void tunnel.sendAppFrame(streamId, MSG_WS_OPEN, JSON.stringify({ path: wsPath }));
    });
    for (const wsPath of ['/inspector/devtools/cdp', '/dsh-market/ws', '/connect', '/api/other']) {
      const result = await openWsViaFrame(wsPath);
      assert.equal(result.closed, true, `expected WS reject for ${wsPath}`);
      assert.equal(result.code, 1008);
    }
    assert.equal(hits.filter((h) => h.upgrade).length, 0);

    // Sanity check: /api/remote.mux reaches localServer upgrade
    const validWsResult = await openWsViaFrame('/api/remote.mux');
    assert.equal(validWsResult.closed, true);
    assert.equal(hits.filter((h) => h.upgrade === '/api/remote.mux').length, 1);

    // Ensure session still clean on bridge
    assert.ok(session);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('TunnelClient.fetch aborts stalled ReadableStream request body upload immediately and cancels underlying stream', async () => {
  let serverHits = 0;
  const localServer = createServer((_req, res) => {
    serverHits++;
    res.writeHead(200).end('ok');
  });
  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin);

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    let streamCancelled = false;
    let cancelReason;
    const stalledStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('first-chunk'));
      },
      pull() {
        return new Promise(() => {});
      },
      cancel(reason) {
        streamCancelled = true;
        cancelReason = reason;
      },
    });

    const ac = new AbortController();
    const fetchPromise = tunnel.fetch('/dsh-market/upload', {
      method: 'PATCH',
      body: stalledStream,
      signal: ac.signal,
    });
    setTimeout(() => ac.abort(), 30);

    await assert.rejects(fetchPromise, (err) => err?.name === 'AbortError');
    assert.equal(streamCancelled, true);
    assert.equal(cancelReason?.name, 'AbortError');
    assert.equal(serverHits, 0);

    // Pre-aborted signal also cancels unconsumed ReadableStream and rejects immediately
    let preCancelled = false;
    const preAbortedStream = new ReadableStream({
      pull() { return new Promise(() => {}); },
      cancel() { preCancelled = true; },
    });
    const ac2 = new AbortController();
    ac2.abort();
    await assert.rejects(
      tunnel.fetch('/dsh-market/upload', { method: 'POST', body: preAbortedStream, signal: ac2.signal }),
      (err) => err?.name === 'AbortError',
    );
    assert.equal(preCancelled, true);
    assert.equal(serverHits, 0);

    // Non-settling cancel() promise must NEVER block pre-abort, mid-stream abort, or >16 MiB rejection
    const makeNeverCancelStream = (onPull) => new ReadableStream({
      pull: onPull,
      cancel() {
        return new Promise(() => {});
      },
    });

    const acNeverPre = new AbortController();
    acNeverPre.abort();
    await Promise.race([
      assert.rejects(
        tunnel.fetch('/dsh-market/upload', {
          method: 'POST',
          body: makeNeverCancelStream(() => new Promise(() => {})),
          signal: acNeverPre.signal,
        }),
        (err) => err?.name === 'AbortError',
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error('pre-aborted never-cancel hung')), 200)),
    ]);

    const acNeverMid = new AbortController();
    let midCancelTriggered = false;
    const neverMidStream = new ReadableStream({
      pull() { return new Promise(() => {}); },
      cancel() {
        midCancelTriggered = true;
        return new Promise(() => {});
      },
    });
    setTimeout(() => acNeverMid.abort(), 20);
    await Promise.race([
      assert.rejects(
        tunnel.fetch('/dsh-market/upload', { method: 'PUT', body: neverMidStream, signal: acNeverMid.signal }),
        (err) => err?.name === 'AbortError',
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error('mid-abort never-cancel hung')), 250)),
    ]);
    assert.equal(midCancelTriggered, true);

    let emittedBytes = 0;
    const hugeChunk = new Uint8Array(4 * 1024 * 1024);
    const neverOversizedStream = makeNeverCancelStream((controller) => {
      emittedBytes += hugeChunk.byteLength;
      controller.enqueue(hugeChunk);
    });
    await Promise.race([
      assert.rejects(
        tunnel.fetch('/dsh-market/upload', { method: 'POST', body: neverOversizedStream }),
        /too large/u,
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error('oversized never-cancel hung')), 400)),
    ]);
    assert.ok(emittedBytes > 16 * 1024 * 1024);

    // stream.tee() & Request.clone() with sibling branch kept open must reject immediately on abort
    const teeOrig = new ReadableStream({ pull() { return new Promise(() => {}); } });
    const [teeBranch1, teeBranch2] = teeOrig.tee();
    const acTee = new AbortController();
    setTimeout(() => acTee.abort(), 20);
    await Promise.race([
      assert.rejects(
        tunnel.fetch('/dsh-market/upload', { method: 'POST', body: teeBranch1, signal: acTee.signal }),
        (err) => err?.name === 'AbortError',
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error('tee branch abort hung')), 250)),
    ]);
    await teeBranch2.cancel().catch(() => {});

    const cloneReq = new Request('https://dsh.local/dsh-market/upload', {
      method: 'POST',
      body: new ReadableStream({ pull() { return new Promise(() => {}); } }),
      duplex: 'half',
    });
    const cloneOther = cloneReq.clone();
    const acClone = new AbortController();
    setTimeout(() => acClone.abort(), 20);
    await Promise.race([
      assert.rejects(
        tunnel.fetch('/dsh-market/upload', { method: 'POST', body: cloneReq.body, signal: acClone.signal }),
        (err) => err?.name === 'AbortError',
      ),
      new Promise((_, rej) => setTimeout(() => rej(new Error('Request.clone() abort hung')), 250)),
    ]);
    await cloneOther.body?.cancel().catch(() => {});
    assert.equal(serverHits, 0);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

function spyAbortSignal(controller) {
  let activeListeners = 0;
  const origAdd = controller.signal.addEventListener.bind(controller.signal);
  const origRemove = controller.signal.removeEventListener.bind(controller.signal);
  controller.signal.addEventListener = (type, listener, options) => {
    if (type === 'abort') activeListeners++;
    return origAdd(type, listener, options);
  };
  controller.signal.removeEventListener = (type, listener, options) => {
    if (type === 'abort') activeListeners = Math.max(0, activeListeners - 1);
    return origRemove(type, listener, options);
  };
  return () => activeListeners;
}

test('Aborting after response headers destroys local upstream connection (res & socket close) and cleans signal listeners', async () => {
  let resClosedCount = 0;
  let socketClosedCount = 0;
  const localServer = createServer((req, res) => {
    res.on('close', () => { resClosedCount++; });
    res.socket?.once('close', () => { socketClosedCount++; });
    if (req.url === '/dsh-market/stall-body') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('head-chunk');
      // Keep body open indefinitely until client closes.
      return;
    }
    res.writeHead(200).end('ok');
  });
  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;

  // 0. Normal completion cleans up signal listener
  const endpoint = resolvePinnedEndpoint(localOrigin);
  const normalAc = new AbortController();
  const getNormalListeners = spyAbortSignal(normalAc);
  const normalResp = await pinnedFetch(endpoint, '/dsh-market/ok', { signal: normalAc.signal });
  assert.equal(await normalResp.text(), 'ok');
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(getNormalListeners(), 0, 'signal abort listener must be removed after normal response');

  // 1. Direct pinnedFetch signal abort after headers
  const directAc = new AbortController();
  const getDirectListeners = spyAbortSignal(directAc);
  const directResp = await pinnedFetch(endpoint, '/dsh-market/stall-body', { signal: directAc.signal });
  assert.equal(directResp.status, 200);
  const directReader = directResp.body.getReader();
  const first = await directReader.read();
  assert.equal(new TextDecoder().decode(first.value), 'head-chunk');
  const stalledRead = directReader.read();
  setTimeout(() => directAc.abort(new Error('client cancelled body')), 30);
  await assert.rejects(stalledRead, /client cancelled body/);
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(resClosedCount >= 1, true, 'ServerResponse must emit close');
  assert.equal(socketClosedCount >= 1, true, 'underlying socket must emit close');
  assert.equal(getDirectListeners(), 0, 'signal abort listener must be cleaned on abort');

  // 2. End-to-end TunnelClient -> HostBridge response cancel after headers
  const beforeResCloseCount = resClosedCount;
  const beforeSocketCloseCount = socketClosedCount;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin);
  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    const tunnelAc = new AbortController();
    const getTunnelListeners = spyAbortSignal(tunnelAc);
    const tunnelResp = await tunnel.fetch('/dsh-market/stall-body', { signal: tunnelAc.signal });
    assert.equal(tunnelResp.status, 200);
    const r2 = tunnelResp.body.getReader();
    const chunk1 = await r2.read();
    assert.equal(new TextDecoder().decode(chunk1.value), 'head-chunk');

    const pendingTunnelRead = r2.read();
    setTimeout(() => tunnelAc.abort(), 30);
    await assert.rejects(pendingTunnelRead, (err) => err?.name === 'AbortError');
    await new Promise((r) => setTimeout(r, 80));
    assert.equal(resClosedCount > beforeResCloseCount, true, 'ServerResponse must emit close after tunnel abort');
    assert.equal(socketClosedCount > beforeSocketCloseCount, true, 'socket must emit close after tunnel abort');
    assert.equal(bridge.httpStreams.size, 0);
    assert.equal(getTunnelListeners(), 0);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('Write requests on 401 never replay, invalidate stale cookie generation, and clean hop-by-hop response headers + 3xx pass-through', async () => {
  let validCookie = 'dsh_web=gen-1';
  let cookieSeq = 1;
  const localHits = [];

  const localServer = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/' && url.searchParams.get('token') === 'launch-secret') {
      res.writeHead(303, { 'set-cookie': `${validCookie}; Path=/; HttpOnly` });
      res.end();
      return;
    }

    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    localHits.push({ method: req.method, path: url.pathname, cookie: req.headers.cookie || '', bodyLength: body.length });

    if (req.headers.cookie !== validCookie) {
      if (url.pathname === '/my-plugin/slow-write-401') {
        await new Promise((r) => setTimeout(r, 70));
      }
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'expired' }));
      return;
    }

    if (url.pathname === '/my-plugin/redirect') {
      res.writeHead(302, {
        location: '/my-plugin/next',
        'set-cookie': 'secret=should-strip; Path=/',
      });
      res.end();
      return;
    }

    if (url.pathname === '/my-plugin/hop-headers') {
      res.writeHead(200, {
        'content-type': 'application/json',
        connection: 'keep-alive, x-custom-hop',
        'keep-alive': 'timeout=5',
        te: 'trailers',
        trailer: 'Expires',
        'proxy-authenticate': 'Basic',
        'proxy-authorization': 'Basic abc',
        'x-custom-hop': 'strip-me',
        'set-cookie': 'leak=no; HttpOnly',
        'x-plugin-ok': 'preserved',
      });
      res.end(JSON.stringify({ ok: true, receivedBytes: body.length }));
      return;
    }

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, method: req.method, receivedBytes: body.length }));
  });

  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const localOrigin = `http://127.0.0.1:${localServer.address().port}`;
  const { bridge, tunnel, secret } = createConnectedTunnel(localOrigin, {
    getLaunchToken: () => 'launch-secret',
  });

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // Seed gen-1 cookie cache
    const seed = await tunnel.fetch('/my-plugin/seed');
    assert.equal(seed.status, 200);
    assert.equal(bridge.browserCookie.generation, 1);

    // Rotate server cookie so cached gen-1 becomes stale
    for (const method of ['PUT', 'PATCH', 'DELETE']) {
      validCookie = `dsh_web=gen-${++cookieSeq}`;
      const hitsBefore = localHits.length;
      const firstAttempt = await tunnel.fetch(`/my-plugin/write-${method}`, {
        method,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method }),
      });
      assert.equal(firstAttempt.status, 401);
      // Must NOT replay the write automatically
      assert.equal(localHits.length, hitsBefore + 1);
      // Stale cookie cache must be invalidated so the manual retry succeeds with fresh cookie
      assert.equal(bridge.browserCookie, null);

      const retryAttempt = await tunnel.fetch(`/my-plugin/write-${method}`, {
        method,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method }),
      });
      assert.equal(retryAttempt.status, 200);
      assert.equal((await retryAttempt.json()).method, method);
      assert.equal(localHits.length, hitsBefore + 2);
    }

    // Generation & concurrent interleaved race guard:
    // Rotate server cookie, fire a slow POST carrying the stale entry, then refresh via GET
    // before the slow POST receives 401. The slow POST's 401 MUST NOT clobber the fresh entry.
    const currentEntry = bridge.browserCookie;
    bridge.invalidateBrowserCookie(currentEntry.generation - 1);
    assert.equal(bridge.browserCookie, currentEntry);

    validCookie = `dsh_web=gen-${++cookieSeq}`;
    const slowWritePromise = tunnel.fetch('/my-plugin/slow-write-401', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    await new Promise((r) => setTimeout(r, 15));
    const concurrentGet = await tunnel.fetch('/my-plugin/concurrent-refresh');
    assert.equal(concurrentGet.status, 200);
    const freshEntry = bridge.browserCookie;
    assert.notEqual(freshEntry.value, currentEntry.value);

    const slowWriteResp = await slowWritePromise;
    assert.equal(slowWriteResp.status, 401);
    assert.equal(bridge.browserCookie, freshEntry, 'stale 401 must not clobber concurrently refreshed cookie entry');

    // 3xx manual pass-through AND default follow mode (HostBridge returns 302 raw; client follows on 'follow')
    const redirManual = await tunnel.fetch('/my-plugin/redirect', { redirect: 'manual' });
    assert.equal(redirManual.status, 302);
    assert.equal(redirManual.headers.get('location'), '/my-plugin/next');
    assert.equal(redirManual.headers.get('set-cookie'), null);

    const redirFollow = await tunnel.fetch('/my-plugin/redirect');
    assert.equal(redirFollow.status, 200);
    assert.equal((await redirFollow.json()).ok, true);

    // Response hop-by-hop + Connection-nominated header stripping
    const hopResp = await tunnel.fetch('/my-plugin/hop-headers');
    assert.equal(hopResp.status, 200);
    assert.equal(hopResp.headers.get('x-plugin-ok'), 'preserved');
    for (const stripped of [
      'connection',
      'keep-alive',
      'te',
      'trailer',
      'proxy-authenticate',
      'proxy-authorization',
      'x-custom-hop',
      'set-cookie',
    ]) {
      assert.equal(hopResp.headers.get(stripped), null, `expected response header ${stripped} to be stripped`);
    }

    // Empty request body on POST/PUT
    const emptyPut = await tunnel.fetch('/my-plugin/empty', { method: 'PUT' });
    assert.equal(emptyPut.status, 200);
    assert.equal((await emptyPut.json()).receivedBytes, 0);

    // Multi-chunk streaming upload (> 32 KiB CHUNK_SIZE)
    const bigPayload = new Uint8Array(80 * 1024);
    bigPayload.fill(0x42);
    const streamUpload = new ReadableStream({
      start(controller) {
        controller.enqueue(bigPayload.subarray(0, 30 * 1024));
        controller.enqueue(bigPayload.subarray(30 * 1024, 65 * 1024));
        controller.enqueue(bigPayload.subarray(65 * 1024));
        controller.close();
      },
    });
    const streamResp = await tunnel.fetch('/my-plugin/stream-up', { method: 'POST', body: streamUpload });
    assert.equal(streamResp.status, 200);
    assert.equal((await streamResp.json()).receivedBytes, 80 * 1024);

    // Oversized request body (> 16 MiB) rejected on HostBridge with 413 frame & stream cleanup
    const session = [...bridge.sessions.values()][0];
    const sid = 9001;
    const oversizedPromise = new Promise((resolve) => {
      let status = null;
      let body = '';
      tunnel.httpStreams.set(sid, {
        resolveHead(meta) { status = meta.status; },
        pushBody(chunk) { body += new TextDecoder().decode(chunk); },
        finishBody() { resolve({ status, body }); },
        fail: (err) => resolve(err),
      });
    });
    bridge.dispatchInnerFrame(session.id, session, {
      streamId: sid,
      msgType: MSG_HTTP_REQ_HEAD,
      payload: encodeJSON({ method: 'POST', path: '/my-plugin/too-big', headers: {} }),
    });
    const hugeChunk = new Uint8Array(1024 * 1024);
    for (let i = 0; i < 17; i++) {
      bridge.dispatchInnerFrame(session.id, session, {
        streamId: sid,
        msgType: MSG_HTTP_REQ_BODY,
        payload: hugeChunk,
      });
    }
    const oversizedResult = await oversizedPromise;
    assert.equal(oversizedResult.status, 413);
    assert.match(oversizedResult.body, /too large/u);
    assert.equal(bridge.httpStreams.has(`${session.id}:${sid}`), false);
    assert.equal(bridge.httpRequestBytes, 0);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});
