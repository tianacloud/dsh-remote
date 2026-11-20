import { spawn } from 'node:child_process';

/**
 * Resolve ordered candidate clipboard commands for the given platform & environment.
 * Always writes via stdin pipe — never passes secrets as command-line arguments.
 */
export function clipboardCandidates(platform = process.platform, env = process.env) {
  if (platform === 'darwin') {
    return [{ bin: 'pbcopy', args: [] }];
  }
  if (platform === 'win32') {
    return [{ bin: 'clip.exe', args: [] }];
  }
  const list = [];
  if (env.WAYLAND_DISPLAY) {
    list.push({ bin: 'wl-copy', args: [] });
  }
  if (env.DISPLAY || !env.WAYLAND_DISPLAY) {
    list.push({ bin: 'xclip', args: ['-selection', 'clipboard'] });
    list.push({ bin: 'xsel', args: ['--clipboard', '--input'] });
  }
  if (!env.WAYLAND_DISPLAY) {
    list.push({ bin: 'wl-copy', args: [] });
  }
  return list;
}

function defaultSpawnWrite(bin, args, text, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      stdio: ['pipe', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
      reject(new Error(`${bin} timed out`));
    }, timeoutMs);

    child.stderr?.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) resolve();
      else reject(new Error(`${bin} exited with code ${code}: ${stderr.trim()}`));
    });
    child.stdin.on('error', () => {});
    child.stdin.end(text, 'utf8');
  });
}

/**
 * Copy sensitive text (such as pairing key) to system clipboard via stdin pipe.
 */
export async function copyToClipboard(text, options = {}) {
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;
  const timeoutMs = options.timeoutMs ?? 3000;
  const writeFn = options.writeFn ?? defaultSpawnWrite;
  const candidates = clipboardCandidates(platform, env);

  let lastError = 'No clipboard utility available';
  for (const { bin, args } of candidates) {
    try {
      await writeFn(bin, args, String(text), timeoutMs);
      return { ok: true, tool: bin };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
    }
  }
  return { ok: false, error: lastError };
}

export function maskPairingKey(key) {
  const str = String(key || '').trim();
  if (!str) return '••••••••••••';
  if (str.startsWith('dshk1_') && str.length > 12) {
    return `dshk1_••••••••••••${str.slice(-4)}`;
  }
  if (str.length > 8) {
    return `••••••••••••${str.slice(-4)}`;
  }
  return '••••••••••••';
}
