import assert from 'node:assert/strict';
import test from 'node:test';
import {
  e2eeFingerprint,
  ensureE2eeConfig,
  generateE2eeSecret,
} from '../src/state.js';
import {
  computeKeyFingerprint,
  createClientHandshake,
  E2EE_ALGORITHM,
  generateE2eeSecretWeb,
  respondHostHandshake,
} from '../web-src/e2ee.js';

const target = { hostId: 'test-host', webId: 'testweb00001' };

test('Node and WebCrypto E2EE secret generators and fingerprints match', async () => {
  const s1 = generateE2eeSecret();
  const s2 = generateE2eeSecretWeb();
  assert.match(s1, /^[A-Za-z0-9_-]{43}$/);
  assert.match(s2, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await computeKeyFingerprint(s1), e2eeFingerprint(s1));
  assert.equal(await computeKeyFingerprint(s2), e2eeFingerprint(s2));

  const { changed, e2ee } = ensureE2eeConfig({});
  assert.equal(changed, true);
  assert.equal(e2ee.algorithm, E2EE_ALGORITHM);
  assert.equal(e2ee.fingerprint, e2eeFingerprint(e2ee.secret));


});

test('E2EE handshake + bidirectional AES-256-GCM encryption and anti-tamper/anti-replay', async () => {
  const secret = generateE2eeSecret();
  const clientHs = await createClientHandshake(secret, target);
  const { hostHelloPayload, cipher: hostCipher } = await respondHostHandshake(secret, clientHs.helloPayload, target);
  const clientCipher = await clientHs.finalize(hostHelloPayload);

  // Bidirectional round-trip
  const msg1 = new TextEncoder().encode('hello-host');
  const box1 = await clientCipher.seal(msg1);
  assert.deepEqual(await hostCipher.open(box1), msg1);

  const msg2 = new TextEncoder().encode('hello-client');
  const box2 = await hostCipher.seal(msg2);
  assert.deepEqual(await clientCipher.open(box2), msg2);

  // Replay rejected
  await assert.rejects(() => hostCipher.open(box1), /replay|out-of-order/i);

  // Tampered ciphertext rejected and does NOT advance rxSeq
  const box3 = await clientCipher.seal(new TextEncoder().encode('legit-3'));
  const tampered = new Uint8Array(box3);
  tampered[tampered.length - 1] ^= 0xff;
  await assert.rejects(() => hostCipher.open(tampered));

  // Real box3 (seq=2) must still succeed after failed tampered attempt
  assert.equal(new TextDecoder().decode(await hostCipher.open(box3)), 'legit-3');
});

test('E2EE rejects wrong key and MITM-tampered host hello', async () => {
  const hostSecret = generateE2eeSecret();
  const wrongSecret = generateE2eeSecret();

  const badClientHs = await createClientHandshake(wrongSecret, target);
  await assert.rejects(
    () => respondHostHandshake(hostSecret, badClientHs.helloPayload, target),
    (err) => err?.code === 'AUTH_FAILED',
  );

  // MITM tampers hostPub in hostHelloPayload
  const goodClientHs = await createClientHandshake(hostSecret, target);
  const { hostHelloPayload } = await respondHostHandshake(hostSecret, goodClientHs.helloPayload, target);
  const parsed = JSON.parse(new TextDecoder().decode(hostHelloPayload));
  parsed.hostNonce = Buffer.from(new Uint8Array(16).fill(7)).toString('base64url');
  const tamperedHostHello = new TextEncoder().encode(JSON.stringify(parsed));
  await assert.rejects(
    () => goodClientHs.finalize(tamperedHostHello),
    /authentication failed|MITM/i,
  );
});

test('E2EE concurrent enqueueSend and enqueueReceive preserve strict sequence ordering', async () => {
  const secret = generateE2eeSecret();
  const clientHs = await createClientHandshake(secret, target);
  const { hostHelloPayload, cipher: hostCipher } = await respondHostHandshake(secret, clientHs.helloPayload, target);
  const clientCipher = await clientHs.finalize(hostHelloPayload);

  const sentBoxes = [];
  const sends = [];
  for (let i = 0; i < 25; i += 1) {
    sends.push(
      clientCipher.enqueueSend(new TextEncoder().encode(`msg-${i}`), (box) => {
        sentBoxes.push(box);
      }),
    );
  }
  await Promise.all(sends);
  assert.equal(sentBoxes.length, 25);

  const received = [];
  await Promise.all(
    sentBoxes.map((box) =>
      hostCipher.enqueueReceive(box, (pt) => {
        received.push(new TextDecoder().decode(pt));
      }),
    ),
  );
  assert.deepEqual(
    received,
    Array.from({ length: 25 }, (_, i) => `msg-${i}`),
  );
});

test('E2EE binds the Web and host and rejects an omitted record', async () => {
  const secret = generateE2eeSecret();
  const client = await createClientHandshake(secret, target);
  for (const other of [{ ...target, hostId: 'other-host' }, { ...target, webId: 'otherweb0001' }]) {
    await assert.rejects(() => respondHostHandshake(secret, client.helloPayload, other), { code: 'AUTH_FAILED' });
  }
  const { hostHelloPayload, cipher: host } = await respondHostHandshake(secret, client.helloPayload, target);
  const cipher = await client.finalize(hostHelloPayload);
  const first = await cipher.seal(new Uint8Array([1]));
  const second = await cipher.seal(new Uint8Array([2]));
  await assert.rejects(() => host.enqueueReceive(second, () => assert.fail('Unexpected plaintext')), /missing/);
  await assert.rejects(() => host.enqueueReceive(first, () => assert.fail('Failed session accepted a frame')));
});
