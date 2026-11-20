import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync,
  readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { homedir, hostname } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import {
  decodeMasterSecret,
  E2EE_ALGORITHM,
  formatPairingKey,
  normalizePairingKey,
} from '../web-src/e2ee.js';

export const STATE_CONFIG_VERSION = 2;
export const DEFAULT_STUN_URLS = ['stun:stun.cloudflare.com:3478'];

export { formatPairingKey, normalizePairingKey };

export function resolveDshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh');
}

export function defaultStateDir() {
  return join(resolveDshHome(), 'tiana-remote');
}

export function defaultStatePath() {
  return join(defaultStateDir(), 'state.json');
}

export function resolveStatePath(filePath) {
  return resolve(filePath || defaultStatePath());
}

export function defaultRuntimePath() {
  return join(defaultStateDir(), 'runtime.json');
}

function verifyPrivate(stat, type) {
  if ((type === 'directory' ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1) ||
      (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    throw new Error(`DSH remote state ${type} must be private and owned by the current user`);
  }
}

export function loadRemoteState(filePath = defaultStatePath()) {
  let fd;
  try {
    verifyPrivate(lstatSync(dirname(filePath)), 'directory');
    fd = openSync(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0) | (constants.O_NONBLOCK || 0));
  } catch (err) {
    if (err?.code === 'ENOENT') return null;
    throw err;
  }
  try {
    const info = fstatSync(fd);
    verifyPrivate(info, 'file');
    if (info.size > 256 * 1024) throw new Error('DSH remote state file is too large');
    let parsed;
    try { parsed = JSON.parse(readFileSync(fd, 'utf8')); }
    catch { throw new Error('Invalid DSH remote state file'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Invalid DSH remote state file');
    }
    return parsed;
  } finally {
    closeSync(fd);
  }
}

export function saveRemoteState(state, filePath = defaultStatePath()) {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  verifyPrivate(lstatSync(dir), 'directory');
  const tmp = `${filePath}.tmp.${randomBytes(16).toString('hex')}`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    try {
      writeFileSync(fd, `${JSON.stringify(state, null, 2)}\n`);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, filePath);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* preserve original error */ }
    throw err;
  }
}

/**
 * Lossless v1 -> v2 migration / normalization.
 * Preserves existing hostId, hostSigningKeyPair, e2ee/e2eeKeySeed, tiana/owner/function/web fields,
 * and fills v2 network & security defaults without discarding unknown fields.
 */
export function migrateRemoteState(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const stunUrls = Array.isArray(raw.network?.stunUrls)
    ? raw.network.stunUrls.map((u) => String(u).trim()).filter(Boolean)
    : [...DEFAULT_STUN_URLS];
  const p2pEnabled = raw.network?.p2pEnabled !== undefined ? Boolean(raw.network.p2pEnabled) : true;
  const rawAllowed = Array.isArray(raw.security?.allowedWebPlugins)
    ? raw.security.allowedWebPlugins
    : Array.isArray(raw.allowedWebPlugins)
      ? raw.allowedWebPlugins
      : [];
  const allowedWebPlugins = [...new Set(rawAllowed.map((item) => String(item).trim()).filter(Boolean))];

  const next = {
    ...raw,
    version: STATE_CONFIG_VERSION,
    configVersion: STATE_CONFIG_VERSION,
    enabled: raw.enabled !== undefined ? Boolean(raw.enabled) : true,
    network: {
      p2pEnabled,
      stunUrls,
    },
    security: {
      ...(raw.security && typeof raw.security === 'object' ? raw.security : {}),
      allowedWebPlugins,
    },
    allowedWebPlugins,
  };

  if (raw.hostId && !next.host) {
    next.host = {
      hostId: raw.hostId,
      hostName: raw.hostName || raw.hostId,
    };
  }
  if (raw.e2eeKeySeed && !next.e2ee?.secret) {
    try {
      const normalized = normalizePairingKey(raw.e2eeKeySeed);
      next.e2ee = {
        algorithm: E2EE_ALGORITHM,
        secret: normalized,
        fingerprint: e2eeFingerprint(normalized),
        createdAt: raw.updatedAt || new Date().toISOString(),
      };
    } catch {
      // Leave malformed legacy seed intact in e2eeKeySeed for caller to handle.
    }
  }
  return next;
}

export function loadNormalizedRemoteState(filePath = defaultStatePath()) {
  const raw = loadRemoteState(filePath);
  if (!raw) return null;
  return migrateRemoteState(raw);
}

function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM';
  }
}

const inProcessLocks = new Map();

function ensurePersistentLockFile(lockPath) {
  try {
    const fd = openSync(lockPath, constants.O_CREAT | constants.O_RDWR | (constants.O_NOFOLLOW || 0), 0o600);
    try {
      verifyPrivate(fstatSync(fd), 'file');
    } finally {
      closeSync(fd);
    }
  } catch (err) {
    if (err?.code === 'EEXIST') return;
    throw err;
  }
}

const ENTERING_RE = /^entering-(\d+)-([0-9a-f]{32})$/u;
const TICKET_RE = /^ticket-([0-9a-f]{16})-(\d+)-([0-9a-f]{32})$/u;

export async function withStateLock(fn, filePath = defaultStatePath(), { timeoutMs = 10_000 } = {}) {
  const targetPath = resolveStatePath(filePath);
  const dir = dirname(targetPath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  verifyPrivate(lstatSync(dir), 'directory');

  const lockPath = `${targetPath}.lock`;
  const claimsDir = `${lockPath}.claims`;
  ensurePersistentLockFile(lockPath);
  mkdirSync(claimsDir, { recursive: true, mode: 0o700 });
  verifyPrivate(lstatSync(claimsDir), 'directory');

  // Serialize concurrent callers within this Node.js process in FIFO order first.
  const prevTail = inProcessLocks.get(lockPath) ?? Promise.resolve();
  let releaseInProcess;
  const myTurn = new Promise((resolve) => { releaseInProcess = resolve; });
  const nextTail = prevTail.then(() => myTurn, () => myTurn);
  inProcessLocks.set(lockPath, nextTail);

  const deadline = Date.now() + timeoutMs;
  await prevTail;

  const idSuffix = `${process.pid}-${randomBytes(16).toString('hex')}`;
  const enteringPath = join(claimsDir, `entering-${idSuffix}`);
  let ticketPath = '';

  try {
    // Lamport Bakery Directory Lock: every attempt uses globally unique filenames, so
    // unlinking a dead PID's file can never affect any live owner even across arbitrary pauses.
    // Phase 1: announce entering before reading max ticket.
    closeSync(openSync(enteringPath, 'wx', 0o600));

    // Phase 2: pick strictly greater ticket number and create unique ticket file.
    let maxTicket = 0n;
    for (const name of readdirSync(claimsDir)) {
      const m = TICKET_RE.exec(name);
      if (m) {
        const ticket = BigInt(`0x${m[1]}`);
        if (ticket > maxTicket) maxTicket = ticket;
      }
    }
    const myTicket = maxTicket + 1n;
    const hex16 = myTicket.toString(16).padStart(16, '0');
    const ticketName = `ticket-${hex16}-${idSuffix}`;
    ticketPath = join(claimsDir, ticketName);
    closeSync(openSync(ticketPath, 'wx', 0o600));

    // Phase 3: clear entering marker now that our ticket is published.
    try { unlinkSync(enteringPath); } catch { /* ignore */ }

    // Phase 4: wait until no live process is entering or holds a smaller (ticket, idSuffix).
    while (true) {
      const entries = readdirSync(claimsDir);
      if (!entries.includes(ticketName)) {
        throw new Error(`DSH remote state lock ticket disappeared (${lockPath})`);
      }
      let blocked = false;
      for (const name of entries) {
        if (name === ticketName) continue;
        const em = ENTERING_RE.exec(name);
        if (em) {
          const otherPid = Number(em[1]);
          if (!isPidAlive(otherPid)) {
            try { unlinkSync(join(claimsDir, name)); } catch { /* ignore */ }
          } else {
            blocked = true;
          }
          continue;
        }
        const tm = TICKET_RE.exec(name);
        if (tm) {
          const otherTicket = BigInt(`0x${tm[1]}`);
          const otherPid = Number(tm[2]);
          const otherSuffix = `${tm[2]}-${tm[3]}`;
          if (!isPidAlive(otherPid)) {
            try { unlinkSync(join(claimsDir, name)); } catch { /* ignore */ }
          } else if (otherTicket < myTicket || (otherTicket === myTicket && otherSuffix < idSuffix)) {
            blocked = true;
          }
        }
      }
      if (!blocked) break;
      if (Date.now() >= deadline) {
        throw new Error(`Timed out waiting for DSH remote state lock (${lockPath})`);
      }
      await new Promise((r) => setTimeout(r, 8));
    }

    // Record holder metadata in persistent lock file (file itself is never deleted).
    try {
      writeFileSync(lockPath, JSON.stringify({ pid: process.pid, token: idSuffix, ticket: hex16, ts: Date.now() }) + '\n', { mode: 0o600 });
    } catch { /* non-fatal */ }

    return await fn();
  } finally {
    try { unlinkSync(enteringPath); } catch { /* ignore */ }
    if (ticketPath) {
      try { unlinkSync(ticketPath); } catch { /* ignore */ }
    }
    releaseInProcess();
    if (inProcessLocks.get(lockPath) === nextTail) {
      inProcessLocks.delete(lockPath);
    }
  }
}

export function writeRuntimeInfo(info, filePath = defaultRuntimePath()) {
  saveRemoteState({
    pid: process.pid,
    startedAt: new Date().toISOString(),
    ...info,
  }, filePath);
}

export function readRuntimeInfo(filePath = defaultRuntimePath()) {
  try {
    const info = loadRemoteState(filePath);
    if (!info || !isPidAlive(info.pid)) return null;
    return info;
  } catch {
    return null;
  }
}

export function removeRuntimeInfo(filePath = defaultRuntimePath()) {
  try {
    const info = loadRemoteState(filePath);
    if (info && info.pid === process.pid) {
      unlinkSync(filePath);
    }
  } catch {
    // ignore
  }
}

export function sanitizeHostId(raw) {
  const cleaned = String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
  return cleaned || `host-${randomBytes(3).toString('hex')}`;
}

export function defaultHostIdentity() {
  const host = hostname();
  return {
    hostId: sanitizeHostId(host),
    hostName: host || 'dsh-host',
  };
}

export function generateE2eeSecret() {
  return randomBytes(32).toString('base64url');
}

export function e2eeFingerprint(secret) {
  const bytes = decodeMasterSecret(secret);
  const digest = createHash('sha256').update(bytes).digest();
  const parts = [];
  for (let i = 0; i < 6; i += 2) {
    parts.push(digest.subarray(i, i + 2).toString('hex'));
  }
  return parts.join(':');
}

export function ensureE2eeConfig(state, { rotate = false } = {}) {
  const existing = state?.e2ee?.secret;
  if (!rotate && existing) {
    try {
      const normalized = normalizePairingKey(existing);
      const fingerprint = e2eeFingerprint(normalized);
      const needsMetaUpdate = !state.e2ee.algorithm || state.e2ee.fingerprint !== fingerprint || normalized !== existing;
      return {
        changed: needsMetaUpdate,
        e2ee: {
          algorithm: state.e2ee.algorithm || E2EE_ALGORITHM,
          secret: normalized,
          fingerprint,
          createdAt: state.e2ee.createdAt || state.updatedAt || new Date().toISOString(),
        },
      };
    } catch {
      // Regenerate if existing key is malformed.
    }
  }
  const secret = generateE2eeSecret();
  return {
    changed: true,
    e2ee: {
      algorithm: E2EE_ALGORITHM,
      secret,
      fingerprint: e2eeFingerprint(secret),
      createdAt: new Date().toISOString(),
    },
  };
}
