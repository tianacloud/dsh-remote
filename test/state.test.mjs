import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadRemoteState, saveRemoteState } from '../src/state.js';

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
