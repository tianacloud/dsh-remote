import assert from 'node:assert/strict';
import test from 'node:test';
import {
  decodeClientFrame,
  decodeHostFrame,
  decodeJSON,
  encodeClientFrame,
  encodeHostFrame,
  encodeJSON,
  MSG_CONTROL_JSON,
  MSG_HTTP_REQ_HEAD,
  MSG_WS_DATA_BIN,
} from '../src/protocol.js';

test('host frame round-trip preserves sessionId, streamId, msgType, and binary payload', () => {
  const payload = new Uint8Array([0, 1, 2, 254, 255]);
  const encoded = encodeHostFrame(42, 999, MSG_WS_DATA_BIN, payload);
  const decoded = decodeHostFrame(encoded);
  assert.equal(decoded.sessionId, 42);
  assert.equal(decoded.streamId, 999);
  assert.equal(decoded.msgType, MSG_WS_DATA_BIN);
  assert.deepEqual(decoded.payload, payload);
});

test('client frame round-trip preserves streamId, msgType, and JSON payload', () => {
  const input = { method: 'POST', path: '/api/session/list' };
  const encoded = encodeClientFrame(7, MSG_HTTP_REQ_HEAD, encodeJSON(input));
  const decoded = decodeClientFrame(encoded);
  assert.equal(decoded.streamId, 7);
  assert.equal(decoded.msgType, MSG_HTTP_REQ_HEAD);
  assert.deepEqual(decodeJSON(decoded.payload), input);
});

test('control frame encodes empty and string payloads cleanly', () => {
  const encoded = encodeHostFrame(0, 0, MSG_CONTROL_JSON, '{"type":"ping"}');
  const decoded = decodeHostFrame(encoded);
  assert.equal(decoded.sessionId, 0);
  assert.equal(decoded.streamId, 0);
  assert.equal(decoded.msgType, MSG_CONTROL_JSON);
  assert.deepEqual(decodeJSON(decoded.payload), { type: 'ping' });
});
