/**
 * Shared binary frame codec for dsh-remote.
 *
 * Host <-> Relay WebSocket frames:
 *   [4B uint32BE sessionId][4B uint32BE streamId][1B uint8 msgType][payload]
 *
 * Client <-> Relay WebSocket frames:
 *   [4B uint32BE streamId][1B uint8 msgType][payload]
 */

export const MSG_CONTROL_JSON = 0x01;

export const MSG_HTTP_REQ_HEAD = 0x10;
export const MSG_HTTP_REQ_BODY = 0x11;
export const MSG_HTTP_REQ_END = 0x12;
export const MSG_HTTP_RES_HEAD = 0x13;
export const MSG_HTTP_RES_BODY = 0x14;
export const MSG_HTTP_RES_END = 0x15;
export const MSG_HTTP_ABORT = 0x16;
export const MSG_HTTP_RES_WINDOW = 0x17;

export const MSG_WS_OPEN = 0x20;
export const MSG_WS_OPENED = 0x21;
export const MSG_WS_DATA_TEXT = 0x22;
export const MSG_WS_DATA_BIN = 0x23;
export const MSG_WS_CLOSE = 0x24;

export {
  MSG_E2EE_BOX,
  MSG_E2EE_CLIENT_HELLO,
  MSG_E2EE_ERROR,
  MSG_E2EE_HOST_HELLO,
} from '../web-src/e2ee.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function encodeWindowUpdate(creditBytes) {
  if (!Number.isSafeInteger(creditBytes) || creditBytes <= 0 || creditBytes > 0xffffffff) {
    throw new RangeError(`Invalid window credit bytes: ${creditBytes}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, creditBytes >>> 0, false);
  return out;
}

export function decodeWindowUpdate(data) {
  const bytes = toBytes(data);
  if (bytes.byteLength !== 4) {
    throw new Error(`Invalid window update frame length: ${bytes.byteLength}`);
  }
  return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
}

export function encodeHostFrame(sessionId, streamId, msgType, payload) {
  const body = toBytes(payload);
  const out = new Uint8Array(9 + body.byteLength);
  const view = new DataView(out.buffer);
  view.setUint32(0, sessionId >>> 0, false);
  view.setUint32(4, streamId >>> 0, false);
  out[8] = msgType & 0xff;
  if (body.byteLength > 0) {
    out.set(body, 9);
  }
  return out;
}

export function decodeHostFrame(data) {
  const bytes = toBytes(data);
  if (bytes.byteLength < 9) {
    throw new Error(`Invalid host frame length: ${bytes.byteLength}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    sessionId: view.getUint32(0, false),
    streamId: view.getUint32(4, false),
    msgType: bytes[8],
    payload: bytes.subarray(9),
  };
}

export function encodeClientFrame(streamId, msgType, payload) {
  const body = toBytes(payload);
  const out = new Uint8Array(5 + body.byteLength);
  const view = new DataView(out.buffer);
  view.setUint32(0, streamId >>> 0, false);
  out[4] = msgType & 0xff;
  if (body.byteLength > 0) {
    out.set(body, 5);
  }
  return out;
}

export function decodeClientFrame(data) {
  const bytes = toBytes(data);
  if (bytes.byteLength < 5) {
    throw new Error(`Invalid client frame length: ${bytes.byteLength}`);
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    streamId: view.getUint32(0, false),
    msgType: bytes[4],
    payload: bytes.subarray(5),
  };
}

export function encodeJSON(value) {
  return textEncoder.encode(JSON.stringify(value));
}

export function decodeJSON(bytes) {
  return JSON.parse(textDecoder.decode(bytes));
}

export function toBytes(value) {
  if (value === undefined || value === null) return new Uint8Array(0);
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') return textEncoder.encode(value);
  throw new TypeError(`Unsupported payload type: ${typeof value}`);
}
