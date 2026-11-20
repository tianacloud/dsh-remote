import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { HostBridge } from '../src/host-bridge.js';
import { openPinnedWebSocket, pinnedFetch, resolvePinnedEndpoint } from '../src/local-transport.js';
import {
  decodeClientFrame,
  decodeHostFrame,
  decodeJSON,
  encodeClientFrame,
  encodeHostFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
  MSG_E2EE_BOX,
  MSG_E2EE_CLIENT_HELLO,
  MSG_E2EE_HOST_HELLO,
  MSG_HTTP_REQ_BODY,
  MSG_HTTP_REQ_END,
  MSG_HTTP_REQ_HEAD,
  MSG_HTTP_RES_HEAD,
} from '../src/protocol.js';
import { generateE2eeSecret } from '../src/state.js';
import { keyName, purgeWebKeys, TunnelClient } from '../web-src/dsh-remote-entry.mjs';
import { createClientHandshake, generateLogicalSessionId } from '../web-src/e2ee.js';
import { createPath, MultipathSession } from '../web-src/multipath.js';

function createInMemoryBridgeHarness(bridgeOptions = {}) {
  const secret = generateE2eeSecret();
  const hostSent = [];
  let onHostFrame = null;
  const fakeHostWs = {
    readyState: WebSocket.OPEN,
    bufferedAmount: 0,
    send(raw) {
      const frame = decodeHostFrame(raw);
      hostSent.push(frame);
      onHostFrame?.(frame);
    },
    close() {
      this.readyState = WebSocket.CLOSED;
    },
  };
  const bridge = new HostBridge({
    relayUrl: 'https://relay.example.test',
    e2eeSecret: secret,
    hostId: 'host-sec',
    hostName: 'Sec Host',
    registrationKey: 'A'.repeat(43),
    localOrigin: 'http://127.0.0.1:9',
    ownerUserId: 'usr-1',
    ownerTenantId: 'ten-1',
    webId: 'web-1',
    log: () => {},
    ...bridgeOptions,
  });
  bridge.ws = fakeHostWs;
  bridge.registered = true;
  bridge.paceRelay = () => true;
  return {
    bridge,
    secret,
    hostSent,
    setOnHostFrame(fn) { onHostFrame = fn; },
    async openLeg(sessionId, challenge, remainingMs) {
      await bridge.handleFrame({
        sessionId: 0,
        streamId: 0,
        msgType: MSG_CONTROL_JSON,
        payload: encodeJSON({
          type: 'open_session',
          sessionId,
          hostId: 'host-sec',
          userId: 'usr-1',
          tenantId: 'ten-1',
          webId: 'web-1',
          challenge,
          ...(remainingMs !== undefined ? { remainingMs } : {}),
        }),
      });
    },
  };
}

test('H-01: pre-opened Relay leg caps lease to remaining admission window, rejects double renewal, and expires idle legs', async () => {
  const { bridge, secret, hostSent, openLeg } = createInMemoryBridgeHarness({
    leaseMs: 2000,
    authTimeoutMs: 250,
    p2p: 'off',
  });
  try {
    // 1. Idle unauthenticated leg expires automatically after authTimeoutMs.
    const c1 = generateLogicalSessionId();
    await openLeg(1, c1, 2000);
    assert.equal(bridge.relayLegs.has(1), true);
    await new Promise((r) => setTimeout(r, 310));
    assert.equal(bridge.relayLegs.has(1), false);

    // 2. Leg opened with only 320ms remaining cannot grant a 2000ms lease after waiting 70ms.
    // Precompute client handshake outside the leg's auth timeout window to avoid CPU-load flakes.
    const logicalSessionId = generateLogicalSessionId();
    const hs = await createClientHandshake(secret, {
      hostId: 'host-sec', webId: 'web-1', ownerUserId: 'usr-1', tenantId: 'ten-1', logicalSessionId,
    });
    const c2 = generateLogicalSessionId();
    await openLeg(2, c2, 320);
    await new Promise((r) => setTimeout(r, 70));
    await bridge.handleFrame({
      sessionId: 2, streamId: 0, msgType: MSG_E2EE_CLIENT_HELLO, payload: hs.helloPayload,
    });
    const session = bridge.sessions.get(logicalSessionId);
    assert.ok(session, 'session established');
    const remainingAfterHandshake = session.transport.expiresAt - Date.now();
    assert.ok(remainingAfterHandshake <= 270, `expected capped lease <= 270ms, got ${remainingAfterHandshake}ms`);

    // Verify HostBridge notified Relay of session_authenticated for sid=2.
    const authedCtrl = hostSent.find((f) => f.sessionId === 0 && f.msgType === MSG_CONTROL_JSON &&
      decodeJSON(f.payload).type === 'session_authenticated');
    assert.equal(decodeJSON(authedCtrl.payload).sessionId, 2);

    const hostHello = hostSent.find((f) => f.sessionId === 2 && f.msgType === MSG_E2EE_HOST_HELLO);
    const clientCipher = await hs.finalize(hostHello.payload);
    const clientTransport = new MultipathSession({
      cipher: clientCipher,
      leaseMs: 2000,
      onData: () => {},
    });

    // 3. Attempting lease_renew on a pre-opened leg with only 90ms left caps renewal and blocks reuse.
    const c3 = generateLogicalSessionId();
    await openLeg(3, c3, 110);
    const leg3Path = createPath({
      ready: () => true,
      bufferedAmount: () => 0,
      close: () => {},
      send: (type, bytes) => {
        void bridge.handleFrame({ sessionId: 3, streamId: 0, msgType: type, payload: bytes });
        return true;
      },
    });
    await clientTransport.control({ type: 'lease_renew', challenge: c3 }, leg3Path);
    await new Promise((r) => setTimeout(r, 30));
    const renewedRemaining = session.transport.expiresAt - Date.now();
    assert.ok(renewedRemaining <= 110, `expected renewed lease capped <= 110ms, got ${renewedRemaining}ms`);
    assert.equal(bridge.relayLegs.get(3).leaseGranted, true);

    // Reusing leg 3 again for another lease_renew must not extend expiresAt.
    const beforeReuse = session.transport.expiresAt;
    await new Promise((r) => setTimeout(r, 25));
    await clientTransport.control({ type: 'lease_renew', challenge: c3 }, leg3Path);
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(session.transport.expiresAt, beforeReuse);

    clientTransport.close();
  } finally {
    bridge.stop();
  }
});

test('H-02: pinned local transport connects strictly to bound IP/port and never contacts external advertised URL or DNS', async () => {
  let trapHits = 0;
  let localRequests = [];
  const trapServer = createServer((_req, res) => {
    trapHits++;
    res.writeHead(200);
    res.end('trap');
  });
  const localServer = createServer((req, res) => {
    localRequests.push({ url: req.url, host: req.headers.host, origin: req.headers.origin });
    res.writeHead(200, { 'set-cookie': 'dsh_s=local-ok; Path=/; HttpOnly', 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  localServer.on('upgrade', (req, socket) => {
    localRequests.push({ upgrade: req.url, host: req.headers.host, origin: req.headers.origin });
    socket.destroy();
  });

  await Promise.all([
    new Promise((r) => trapServer.listen(0, '127.0.0.1', r)),
    new Promise((r) => localServer.listen(0, '127.0.0.1', r)),
  ]);
  const trapPort = trapServer.address().port;
  const localPort = localServer.address().port;

  try {
    // 1. Non-owned public IP bind host is rejected immediately.
    assert.throws(() => resolvePinnedEndpoint('http://203.0.113.9:3080', {
      listenOrigin: 'http://203.0.113.9:3080',
      boundHost: '203.0.113.9',
      advertisedOrigin: 'http://203.0.113.9:3080',
    }), /not owned by this host/);

    // 2. External reverse-proxy advertisedOrigin (different port/scheme) is ignored; traffic stays on localPort.
    const epProxy = resolvePinnedEndpoint(`http://127.0.0.1:${localPort}`, {
      listenOrigin: `http://127.0.0.1:${localPort}`,
      boundHost: '127.0.0.1',
      advertisedOrigin: `http://127.0.0.1:${trapPort}`,
    });
    assert.equal(epProxy.connectPort, localPort);
    assert.equal(epProxy.authorityOrigin, `http://127.0.0.1:${localPort}`);
    const r1 = await pinnedFetch(epProxy, '/api/ping', { headers: { Origin: epProxy.authorityOrigin } });
    assert.equal(r1.status, 200);
    assert.equal(trapHits, 0);

    // 3. Same-port DNS advertisedOrigin (.invalid cannot resolve in DNS) still connects directly to 127.0.0.1:localPort!
    const epDns = resolvePinnedEndpoint(`http://127.0.0.1:${localPort}`, {
      listenOrigin: `http://127.0.0.1:${localPort}`,
      boundHost: '127.0.0.1',
      advertisedOrigin: `http://drifted-node.invalid:${localPort}`,
    });
    assert.equal(epDns.connectHost, '127.0.0.1');
    assert.equal(epDns.connectPort, localPort);
    assert.equal(epDns.hostHeader, `drifted-node.invalid:${localPort}`);
    const r2 = await pinnedFetch(epDns, '/api/check', { headers: { Origin: epDns.authorityOrigin } });
    assert.equal(r2.status, 200);
    assert.equal(localRequests.at(-1).host, `drifted-node.invalid:${localPort}`);

    // WebSocket upgrade also uses pinned TCP without DNS lookup.
    const ws = openPinnedWebSocket(epDns, '/api/remote.mux', { headers: { Origin: epDns.authorityOrigin } });
    await new Promise((r) => ws.addEventListener('close', r, { once: true }));
    assert.equal(localRequests.at(-1).upgrade, '/api/remote.mux');
    assert.equal(localRequests.at(-1).host, `drifted-node.invalid:${localPort}`);
    assert.equal(trapHits, 0);
  } finally {
    trapServer.close();
    localServer.close();
  }
});

test('M-02: purgeWebKeys cleans stale Host/Owner scopes and TunnelClient revokes on opaque WS failure when session is 401', async () => {
  const store = new Map([
    [keyName({ webId: 'webA', ownerUserId: 'u1', hostId: 'oldHost' }), 'sec-old'],
    [keyName({ webId: 'webA', ownerUserId: 'u2', hostId: 'newHost' }), 'sec-other-owner'],
    [keyName({ webId: 'webA', ownerUserId: 'u1', hostId: 'newHost' }), 'sec-active'],
    [keyName({ webId: 'webB', ownerUserId: 'u1', hostId: 'otherWebHost' }), 'sec-webB'],
  ]);
  const mockStorage = {
    get length() { return store.size; },
    key(i) { return [...store.keys()][i] ?? null; },
    removeItem(k) { store.delete(k); },
  };

  // Switching host/owner purges sibling keys on webA while keeping active key and webB.
  const keep = keyName({ webId: 'webA', ownerUserId: 'u1', hostId: 'newHost' });
  assert.equal(purgeWebKeys('webA', keep, mockStorage), 2);
  assert.equal(store.has(keep), true);
  assert.equal(store.has(keyName({ webId: 'webB', ownerUserId: 'u1', hostId: 'otherWebHost' })), true);

  // Logout / 401 without userId purges all remaining keys for webA.
  assert.equal(purgeWebKeys('webA', null, mockStorage), 1);
  assert.equal(store.size, 1);

  // Opaque WebSocket error (no HTTP status) triggers checkSession() -> false -> immediate onRevoked().
  let revokedCount = 0;
  const tunnel = new TunnelClient(
    async () => { throw new Error('无法连接 Relay'); },
    { webId: 'webA', hostId: 'newHost', ownerUserId: 'u1', tenantId: 't1' },
    () => {},
    async () => { revokedCount++; },
    async () => false,
  );
  tunnel.secret = generateE2eeSecret();
  await tunnel.reconnect(false);
  assert.equal(revokedCount, 1);
  assert.equal(tunnel.closed, true);
});

test('M-03: stalled/unconsumed HTTP response never blocks sibling HTTP streams, aborts on buffer cap, and Host caps empty/excess request chunks', async () => {
  const localServer = createServer((req, res) => {
    if (req.url === '/api/huge') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      // Write 192 KiB (exceeding custom 96 KiB per-stream test cap).
      for (let i = 0; i < 6; i++) res.write(Buffer.alloc(32 * 1024, 0x61));
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ url: req.url, ok: true }));
  });
  await new Promise((r) => localServer.listen(0, '127.0.0.1', r));
  const port = localServer.address().port;

  const { bridge, secret, setOnHostFrame, openLeg } = createInMemoryBridgeHarness({
    localOrigin: `http://127.0.0.1:${port}`,
    p2p: 'off',
  });

  // Wire fake WebSocket client <-> in-memory HostBridge.
  const clientListeners = new Map();
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
      void bridge.handleFrame({ sessionId: 10, streamId: cf.streamId, msgType: cf.msgType, payload: cf.payload });
    },
    close() {
      this.readyState = 3;
      for (const fn of clientListeners.get('close') ?? []) fn();
    },
  };
  const emitToClient = (clientBytes) => {
    const ab = clientBytes.buffer.slice(clientBytes.byteOffset, clientBytes.byteOffset + clientBytes.byteLength);
    for (const fn of clientListeners.get('message') ?? []) fn({ data: ab });
  };
  setOnHostFrame((hf) => {
    if (hf.sessionId === 10) {
      emitToClient(encodeClientFrame(hf.streamId, hf.msgType, hf.payload));
    }
  });

  const m03Challenge = generateLogicalSessionId();
  const tunnel = new TunnelClient(
    async () => {
      await openLeg(10, m03Challenge, 60_000);
      setTimeout(() => {
        emitToClient(encodeClientFrame(0, MSG_CONTROL_JSON, encodeJSON({
          type: 'welcome',
          sessionId: 10,
          challenge: m03Challenge,
          selectedHostId: 'host-sec',
          user: { userId: 'usr-1', tenantId: 'ten-1', webId: 'web-1' },
        })));
      }, 5);
      return fakeClientWs;
    },
    {
      hostId: 'host-sec', webId: 'web-1', ownerUserId: 'usr-1', tenantId: 'ten-1',
      maxResponseBufferBytes: 96 * 1024,
    },
    () => {},
    () => {},
  );

  try {
    const leg = await tunnel.connect();
    await tunnel.authenticate(leg, secret);

    // Start /api/huge and NEVER read hugeRes.body!
    const hugeRes = await tunnel.fetch('/api/huge');
    assert.equal(hugeRes.status, 200);
    await new Promise((r) => setTimeout(r, 80));

    // Sibling /api/fast MUST still succeed without being blocked by unconsumed hugeRes!
    const fastRes = await tunnel.fetch('/api/fast');
    assert.equal(fastRes.status, 200);
    assert.deepEqual(await fastRes.json(), { url: '/api/fast', ok: true });

    // And reading hugeRes.body afterwards surfaces the per-stream buffer overflow error cleanly.
    await assert.rejects(() => hugeRes.arrayBuffer(), /buffer exceeded/);

    // Verify Host ignores 0-byte body frames and caps >1024 body fragments with 413.
    const session = [...bridge.sessions.values()][0];
    bridge.dispatchInnerFrame(session.id, session, {
      streamId: 500, msgType: MSG_HTTP_REQ_HEAD, payload: encodeJSON({ method: 'POST', path: '/api/upload' }),
    });
    bridge.dispatchInnerFrame(session.id, session, {
      streamId: 500, msgType: MSG_HTTP_REQ_BODY, payload: new Uint8Array(0),
    });
    assert.equal(bridge.httpStreams.get(`${session.id}:500`).chunkCount, 0);
    for (let i = 0; i <= 1024; i++) {
      bridge.dispatchInnerFrame(session.id, session, {
        streamId: 500, msgType: MSG_HTTP_REQ_BODY, payload: new Uint8Array([1]),
      });
    }
    assert.equal(bridge.httpStreams.has(`${session.id}:500`), false);
  } finally {
    tunnel.close();
    bridge.stop();
    localServer.close();
  }
});

test('M-04: DSH_REMOTE_P2P=off disables WebRTC and STUN=none drops non-private incoming ICE checks at werift ingress', async () => {
  const { bridge: relayOnlyBridge } = createInMemoryBridgeHarness({ p2p: 'off' });
  assert.equal(relayOnlyBridge.p2pEnabled, false);
  assert.deepEqual(relayOnlyBridge.iceServers, []);
  relayOnlyBridge.stop();

  const { bridge: lanBridge } = createInMemoryBridgeHarness({ stun: 'none' });
  const pc = lanBridge.createPeer({ iceServers: [] });
  try {
    pc.createDataChannel('dsh-remote-v2', { ordered: true });
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    const iceConn = pc.sctp?.dtlsTransport?.iceTransport?.connection ?? pc.dtlsTransports?.[0]?.iceTransport?.connection;
    assert.equal(iceConn?.__dshPrivateOnly, true);

    let forwarded = 0;
    const realProto = {};
    // Replace underlying _remoteCandidates check to observe whether checkIncoming reaches werift core.
    const beforeCount = iceConn._remoteCandidates.length;
    // Public IPv4 and IPv4-mapped IPv6 sources must be dropped before touching message attributes!
    iceConn.checkIncoming({ getAttributeValue: () => { forwarded++; return 'a:b'; } }, ['203.0.113.77', 40000], realProto);
    iceConn.checkIncoming({ getAttributeValue: () => { forwarded++; return 'a:b'; } }, ['::ffff:203.0.113.77', 40000], realProto);
    assert.equal(forwarded, 0);
    assert.equal(iceConn._remoteCandidates.length, beforeCount);
  } finally {
    await pc.close();
    lanBridge.stop();
  }
});
