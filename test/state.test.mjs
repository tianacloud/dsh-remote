import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadNormalizedRemoteState, loadRemoteState, migrateRemoteState, saveRemoteState } from '../src/state.js';

test('state supports private atomic rewrites and rejects unsafe file access', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-state-test-'));
  const file = join(dir, 'fixture.json');
  const link = join(dir, 'link.json');
  try {
    assert.equal(loadRemoteState(file), null);
    saveRemoteState({ version: 1 }, file);
    saveRemoteState({ version: 2 }, file);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    assert.deepEqual(loadRemoteState(file), { version: 2 });
    chmodSync(file, 0o644);
    assert.throws(() => loadRemoteState(file), /must be private/);
    chmodSync(file, 0o600);
    symlinkSync(file, link);
    assert.throws(() => loadRemoteState(link), { code: 'ELOOP' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('legacy state.json with deprecated plugin-filter fields loads cleanly, preserves bindings, and omits deprecated keys on save', () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-remote-legacy-state-'));
  const file = join(dir, 'state.json');
  try {
    const legacy = {
      version: 2,
      configVersion: 2,
      enabled: true,
      owner: { userId: 'u-legacy', tenantId: 't-legacy', email: 'owner@example.test' },
      host: { hostId: 'legacy-host', hostName: 'Legacy Host', registrationKey: 'R'.repeat(43) },
      e2ee: { algorithm: 'ECDH-P256+HKDF-SHA256+AES-256-GCM', secret: 'S'.repeat(43), fingerprint: '11:22:33' },
      function: { id: 'fn-legacy', name: 'dsh-remote-relay', url: 'https://relay.example.test', token: 'tok-legacy', expiresAt: 1900000000 },
      web: { id: 'web123456789', name: 'DSH Remote', endpoint: 'https://web123456789.example.test/web/web123456789/' },
      network: { p2pEnabled: false, stunUrls: ['stun:stun.example.test:3478'] },
      pluginPolicy: { mode: 'deny_all', allowedWebPlugins: ['dshmarket'], blockedWebPlugins: ['ds-bot'] },
      pluginAccessMode: 'deny_all',
      allowedWebPlugins: ['dshmarket'],
      blockedWebPlugins: ['ds-bot'],
      security: {
        pluginPolicy: { mode: 'deny_all' },
        pluginAccessMode: 'deny_all',
        allowedWebPlugins: ['dshmarket'],
        blockedWebPlugins: ['ds-bot'],
      },
    };
    writeFileSync(file, `${JSON.stringify(legacy, null, 2)}\n`, { mode: 0o600 });

    const normalized = loadNormalizedRemoteState(file);
    assert.ok(normalized);
    assert.equal(normalized.host.hostId, 'legacy-host');
    assert.equal(normalized.host.hostName, 'Legacy Host');
    assert.equal(normalized.host.registrationKey, 'R'.repeat(43));
    assert.equal(normalized.function.url, 'https://relay.example.test');
    assert.equal(normalized.function.token, 'tok-legacy');
    assert.equal(normalized.web.id, 'web123456789');
    assert.equal(normalized.web.endpoint, 'https://web123456789.example.test/web/web123456789/');
    assert.equal(normalized.e2ee.secret, 'S'.repeat(43));
    assert.deepEqual(normalized.network, { p2pEnabled: false, stunUrls: ['stun:stun.example.test:3478'] });
    assert.equal('pluginPolicy' in normalized, false);
    assert.equal('pluginAccessMode' in normalized, false);
    assert.equal('allowedWebPlugins' in normalized, false);
    assert.equal('blockedWebPlugins' in normalized, false);
    assert.equal('security' in normalized, false);

    // Saving updated normalized state cleanly omits deprecated fields
    normalized.host = { ...normalized.host, hostName: 'Updated Host' };
    saveRemoteState(normalized, file);
    const savedRaw = JSON.parse(readFileSync(file, 'utf8'));
    assert.equal(savedRaw.host.hostName, 'Updated Host');
    assert.equal(savedRaw.host.registrationKey, 'R'.repeat(43));
    assert.equal(savedRaw.function.url, 'https://relay.example.test');
    assert.equal(savedRaw.web.endpoint, 'https://web123456789.example.test/web/web123456789/');
    assert.equal('pluginPolicy' in savedRaw, false);
    assert.equal('pluginAccessMode' in savedRaw, false);
    assert.equal('allowedWebPlugins' in savedRaw, false);
    assert.equal('blockedWebPlugins' in savedRaw, false);
    assert.equal('security' in savedRaw, false);

    // Non-deprecated custom fields under security (if ever present) are still preserved
    const customSec = migrateRemoteState({ version: 2, security: { customFlag: true, allowedWebPlugins: ['x'] } });
    assert.deepEqual(customSec.security, { customFlag: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
