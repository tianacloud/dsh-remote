import test from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { readdirSync, readlinkSync } from 'node:fs';
import { RTCPeerConnection } from 'werift';
import { createClientHandshake, respondHostHandshake, generateE2eeSecretWeb, generateLogicalSessionId, MSG_E2EE_BOX, MSG_E2EE_CTRL } from '../web-src/e2ee.js';
import { CHUNK_SIZE, createPath, MultipathSession } from '../web-src/multipath.js';
import { FragmentReader, sendFragments } from '../web-src/ws-fragments.js';
import { normalizeStun, PeerPath } from '../web-src/peer-path.js';
import { encodeClientFrame, decodeClientFrame } from '../src/protocol.js';

async function ciphers() {
  const secret = generateE2eeSecretWeb();
  const target = { hostId: 'host', webId: 'testweb', ownerUserId: 'owner', tenantId: 'tenant', logicalSessionId: generateLogicalSessionId() };
  const browser = await createClientHandshake(secret, target);
  const server = await respondHostHandshake(secret, browser.helloPayload, target);
  return [await browser.finalize(server.hostHelloPayload), server.cipher];
}

async function until(predicate, timeout = 4000) {
  const end = Date.now() + timeout;
  while (!predicate()) {
    if (Date.now() > end) throw new Error('Test condition timed out');
    await delay(4);
  }
}

function link(left, right, { latency = 0, drop = () => false, stall = () => false } = {}) {
  let up = true;
  let ordinal = 0;
  const path = (sender, receiver, remote) => createPath({
    send(kind, bytes) {
      if (drop(kind, ++ordinal)) return;
      setTimeout(() => {
        if (up) receiver.receive(kind, bytes, remote());
      }, latency);
    },
    ready: () => up,
    bufferedAmount: () => stall() ? 300000 : 0,
    close() {
      up = false;
      sender.selectPath();
      receiver.selectPath();
    },
  });
  const first = path(left, right, () => second);
  const second = path(right, left, () => first);
  return [first, second];
}

test('dual-frame and byte windows preserve order during concurrent upgrades and fallback with lost ACKs', async () => {
  const [a, b] = await ciphers();
  const receivedLeft = [];
  const receivedRight = [];
  const left = new MultipathSession({ cipher: a, onData: (bytes) => receivedLeft.push(bytes) });
  const right = new MultipathSession({ cipher: b, onData: (bytes) => receivedRight.push(bytes) });
  const relay = link(left, right, { latency: 60, drop: (kind, index) => kind === MSG_E2EE_CTRL && index % 5 === 0 });
  const p2p = link(left, right, { latency: 10, drop: (kind, index) => kind === MSG_E2EE_CTRL && index % 3 === 0 });
  try {
    left.setRelay(relay[0]);
    right.setRelay(relay[1]);
    const leftFrames = Array.from({ length: 245 }, (_, i) => new Uint8Array(8).fill(i + 1));
    const rightFrames = Array.from({ length: 245 }, (_, i) => new Uint8Array(8).fill(i + 2));
    const work = [
      ...leftFrames.map((bytes) => left.send(encodeClientFrame(1, 0x14, bytes))),
      ...rightFrames.map((bytes) => right.send(encodeClientFrame(2, 0x14, bytes))),
    ];
    await until(() => left.unacked.size === 128 && right.unacked.size === 128);
    left.setP2P(p2p[0]);
    right.setP2P(p2p[1]);
    await until(() => receivedLeft.length > 128 && receivedRight.length > 128);
    p2p[0].close();
    left.setP2P(null);
    right.setP2P(null);
    await Promise.all(work);
    await until(() => receivedLeft.length === rightFrames.length && receivedRight.length === leftFrames.length);
    assert.deepEqual(receivedLeft.map((bytes) => decodeClientFrame(bytes).payload), rightFrames);
    assert.deepEqual(receivedRight.map((bytes) => decodeClientFrame(bytes).payload), leftFrames);
    await until(() => left.unacked.size === 0 && right.unacked.size === 0);
    console.log('multipath 50 ms gap: 490 frames exact, 128 slots hit in both directions, relay fallback drained');
  } finally {
    left.close();
    right.close();
  }
});

test('WebSocket text and binary greater than 32 KiB preserve boundaries and backpressure', async () => {
  const [a, b] = await ciphers();
  const messages = [];
  const reader = new FragmentReader();
  const left = new MultipathSession({ cipher: a, onData: () => {} });
  const right = new MultipathSession({ cipher: b, onData: (bytes) => {
    const frame = decodeClientFrame(bytes);
    const result = reader.push(frame.msgType, frame.payload);
    if (result) messages.push({ kind: frame.msgType, result });
  } });
  let blocked = true;
  const relay = link(left, right, { stall: () => blocked });
  try {
    left.setRelay(relay[0]);
    right.setRelay(relay[1]);
    const text = '转发😀'.repeat(20000);
    const binary = new Uint8Array((2 << 20) + 200).map((_, i) => i & 255);
    const cancel = new AbortController();
    const skipped = left.send(encodeClientFrame(1, 0x14, Uint8Array.of(0)), cancel.signal);
    cancel.abort();
    await assert.rejects(skipped, { name: 'AbortError' });
    const forward = async (kind, value) => sendFragments(value, (part) => {
      assert.ok(part.length <= CHUNK_SIZE);
      return left.send(encodeClientFrame(3, kind, part));
    });
    const task = forward(0x22, text).then(() => forward(0x23, binary));
    await delay(40);
    assert.equal(messages.length, 0);
    blocked = false;
    await task;
    await until(() => messages.length === 2);
    assert.deepEqual(messages.map(({ kind }) => kind), [0x22, 0x23]);
    assert.equal(new TextDecoder().decode(messages[0].result), text);
    assert.deepEqual(messages[1].result, binary);
    console.log('virtual WS: multibyte UTF-8 plus', binary.length, 'binary bytes preserved');
  } finally {
    left.close();
    right.close();
  }
});

test('authenticated control replay, invalid out-of-window data, and expiry', async () => {
  const [a, b] = await ciphers();
  let count = 0;
  let stopped;
  const left = new MultipathSession({ cipher: a, onData: () => {} });
  const right = new MultipathSession({ cipher: b, onData: () => {},
    onControl: () => { count++; }, onClose: (error) => { stopped = error; }, leaseMs: 80 });
  let exactPacket;
  const path = createPath({
    send(kind, bytes) {
      exactPacket = bytes;
      right.receive(kind, bytes, path);
    },
    ready: () => true, bufferedAmount: () => 0, close() {},
  });
  left.setRelay(path);
  right.setRelay(path);
  try {
    await left.control({ type: 'fixture' });
    await until(() => count === 1);
    right.receive(MSG_E2EE_CTRL, exactPacket, path);
    const forged = new Uint8Array(40);
    new DataView(forged.buffer).setBigUint64(0, 129n);
    right.receive(MSG_E2EE_BOX, forged, path);
    assert.equal(right.verifying.size, 0);
    assert.equal(right.received.size, 0);
    right.renewLease();
    await delay(100);
    assert.equal(right.closed, true);
    assert.match(stopped.message, /租期/u);
    assert.equal(count, 1);
  } finally {
    left.close();
    right.close();
  }
});

test('20 real werift offer timeouts close UDP sockets and timers with empty STUN configuration', async () => {
  assert.deepEqual(normalizeStun('none'), []);
  const usage = () => {
    const handles = process.getActiveResourcesInfo();
    const socketFD = readdirSync('/proc/self/fd').filter((fd) => {
      try { return readlinkSync('/proc/self/fd/' + fd).startsWith('socket:'); }
      catch { return false; }
    }).length;
    return { udp: handles.filter((value) => value === 'UDPWrap').length,
      timers: handles.filter((value) => value === 'Timeout').length, socketFD };
  };
  const before = usage();
  let offers = 0;
  for (let i = 0; i < 20; i++) {
    const disposed = Promise.withResolvers();
    const peer = new PeerPath({
      async control(msg) {
        if (msg.type === 'p2p_offer') offers++;
        return true;
      },
    }, {
      createPeer(config) {
        assert.deepEqual(config.iceServers, []);
        const pc = new RTCPeerConnection({ ...config, iceUseDefaultStunServer: false, iceUseTcp: false });
        const close = pc.close.bind(pc);
        pc.close = () => close().then(disposed.resolve, disposed.reject);
        return pc;
      },
      urls: [], initiator: true, signalPath: () => ({}), probeTimeout: 100,
    });
    await peer.start();
    await disposed.promise;
    assert.equal(peer.current, null);
  }
  await delay(30);
  const after = usage();
  assert.equal(offers, 20);
  assert.deepEqual(after, before);
  console.log('werift resources:', JSON.stringify({ cycles: 20, offers, before, after, stun: 'none' }));
});
