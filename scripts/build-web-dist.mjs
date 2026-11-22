import { cpSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('..', import.meta.url));
const webSource = join(projectRoot, 'web-src');
const MAX_BYTES = 200 * 1024;
const REQUIRED_MODULES = ['dsh-remote-entry.mjs', 'dsh-remote-sw.js', 'shell-ui.js'];

function compactModuleSource(source) {
  const out = [];
  let inBlockComment = false;
  for (const rawLine of source.split(/\r?\n/u)) {
    const trimmed = rawLine.trim();
    if (!trimmed) continue;
    if (inBlockComment) {
      const endIdx = trimmed.indexOf('*/');
      if (endIdx !== -1) {
        inBlockComment = false;
        const rest = trimmed.slice(endIdx + 2).trim();
        if (rest) out.push(rest);
      }
      continue;
    }
    if (trimmed.startsWith('/*')) {
      const endIdx = trimmed.indexOf('*/', 2);
      if (endIdx === -1) {
        inBlockComment = true;
      } else {
        const rest = trimmed.slice(endIdx + 2).trim();
        if (rest) out.push(rest);
      }
      continue;
    }
    if (trimmed.startsWith('//')) continue;
    out.push(trimmed);
  }
  return `${out.join('\n')}\n`;
}

export function buildWebDist({ outDir, config = {}, clean = true } = {}) {
  if (!outDir) throw new Error('buildWebDist requires outDir');
  const output = resolve(outDir);
  if (clean) rmSync(output, { recursive: true, force: true });
  mkdirSync(output, { recursive: true });

  const modules = readdirSync(webSource, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(mjs|js)$/u.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  for (const required of REQUIRED_MODULES) {
    if (!modules.includes(required)) {
      throw new Error(`Missing required web-src module: ${required}`);
    }
  }
  for (const file of modules) {
    const source = readFileSync(join(webSource, file), 'utf8');
    writeFileSync(join(output, file), compactModuleSource(source));
  }
  cpSync(join(projectRoot, 'icon.svg'), join(output, 'icon.svg'));
  const finalConfig = {
    functionId: config.functionId || '',
    webId: config.webId || '',
    defaultHostId: config.defaultHostId || '',
    appTitle: config.appTitle || 'dsh-tiana-remote',
    localRelayUrl: config.localRelayUrl || '',
  };
  writeFileSync(join(output, 'remote-config.json'), JSON.stringify(finalConfig) + '\n');
  const files = [...modules, 'icon.svg', 'remote-config.json'];
  const totalBytes = files.reduce((sum, file) => sum + statSync(join(output, file)).size, 0);
  if (totalBytes >= MAX_BYTES) {
    throw new Error(`The DSH Remote shell must be smaller than 200 KiB (got ${totalBytes} bytes)`);
  }
  return { outDir: output, fileCount: files.length, totalBytes, files, config: finalConfig };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = buildWebDist({ outDir: process.argv[2] || join(projectRoot, '.dist-tweb', 'preview') });
  console.log(`[dsh-remote] Built web shell at ${result.outDir}: ${result.fileCount} files, ${result.totalBytes} bytes (${(result.totalBytes / 1024).toFixed(1)} KiB)`);
}
