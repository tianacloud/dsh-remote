#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const verifyOnly = process.argv.includes('--verify');
const outArg = process.argv.slice(2).find((a) => !a.startsWith('--'));
const scratchDir = verifyOnly ? mkdtempSync(path.join(tmpdir(), 'dsh-remote-pack-verify-')) : null;
const directory = scratchDir || path.resolve(outArg ?? 'dist/npm-release');

/**
 * Exact tarball file allowlist: any missing OR unexpected extra file fails the pack gate.
 */
export const EXPECTED_TARBALL_FILES = [
  'LICENSE',
  'README.md',
  'cli.js',
  'client.js',
  'cordis.patch.yml',
  'host-main.js',
  'icon.svg',
  'locale/en-US.json',
  'locale/zh-CN.json',
  'package.json',
  'relay-go/go.mod',
  'relay-go/main.go',
  'scripts/build-web-dist.mjs',
  'src/clipboard.js',
  'src/connect.js',
  'src/dsh-packages.js',
  'src/frontend-assets.js',
  'src/host-bridge.js',
  'src/local-transport.js',
  'src/protocol.js',
  'src/remote-api.js',
  'src/state.js',
  'src/tiana-cli.js',
  'web-src/dsh-remote-entry.mjs',
  'web-src/dsh-remote-sw.js',
  'web-src/e2ee.js',
  'web-src/frontend-loader.js',
  'web-src/multipath.js',
  'web-src/peer-path.js',
  'web-src/shell-ui.js',
  'web-src/ws-fragments.js',
].sort();

const FORBIDDEN_CONTENT_PATTERNS = [
  { name: 'internal git domain', re: new RegExp('\\bgit\\.' + 'tianacloud', 'iu') },
  { name: 'internal staging domain', re: new RegExp('\\bstaging\\.' + 'tianacloud', 'iu') },
  { name: 'internal registry domain', re: new RegExp('\\bimages\\.' + 'tianacloud', 'iu') },
  { name: 'tailscale internal host', re: new RegExp('\\.ts' + '\\.net\\b', 'iu') },
  { name: 'local developer home path', re: new RegExp('/home/' + 'liam\\b', 'u') },
  { name: 'PEM private key', re: new RegExp('-----BEGIN [A-Z ]*' + 'PRIVATE KEY-----', 'u') },
  { name: 'embedded pairing key literal', re: /dshk1_[A-Za-z0-9_-]{20,}/u },
  { name: 'GitHub PAT token', re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u },
  { name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{20,}\b/u },
  { name: 'internal ticket ID', re: /\bTIA-\d+\b/u },
  { name: 'internal ticket slug', re: /\btia-?\d+\b/iu },
  {
    name: 'real personal email',
    re: /(?<![a-zA-Z0-9._%+-])(?!noreply@github\.com(?![a-zA-Z0-9.-]))[a-zA-Z0-9._%+-]+@(?!(?:example\.(?:com|org|net|test|invalid)|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:test|invalid|example|localhost)|users\.noreply\.github\.com)(?![a-zA-Z0-9.-]))[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?!(?:svg|png|jpe?g|gif|webp|ico|woff2?|ttf|otf|cjs|mjs|js|css|json|map|wasm)(?![a-zA-Z0-9._-]))[a-zA-Z]{2,24}(?![a-zA-Z0-9._-])/iu,
  },
];

const ALLOWED_COMMIT_EMAIL_RE = /^(?:(?:\d+\+)?[a-zA-Z0-9-]+@users\.noreply\.github\.com|noreply@github\.com|[a-zA-Z0-9._%+-]+@(?:example\.(?:com|org|net|test|invalid)|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:test|invalid|example|localhost)))$/iu;

const BINARY_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.wasm', '.mp4', '.tgz', '.gz', '.zip']);

export function scanText(label, content) {
  const findings = [];
  for (const rule of FORBIDDEN_CONTENT_PATTERNS) {
    if (rule.re.test(content)) {
      findings.push(`${label}: matched forbidden pattern "${rule.name}"`);
    }
  }
  return findings;
}

export function scanPackageContent(pkgRoot, filePaths) {
  const findings = [];
  for (const rel of filePaths) {
    if (BINARY_EXTS.has(path.extname(rel).toLowerCase())) continue;
    const abs = path.join(pkgRoot, rel);
    let st;
    try { st = statSync(abs); } catch { continue; }
    if (!st.isFile()) continue;
    const content = readFileSync(abs, 'utf8');
    findings.push(...scanText(rel, content));
  }
  return findings;
}

export function scanWorktreeAndGitHistory(repoRoot) {
  const findings = [];
  const lsOut = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  const worktreeFiles = lsOut.split('\0').filter(Boolean);
  for (const rel of worktreeFiles) {
    findings.push(...scanText(`path:${rel}`, rel));
  }
  findings.push(...scanPackageContent(repoRoot, worktreeFiles));

  const isShallow = execFileSync('git', ['rev-parse', '--is-shallow-repository'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).trim();
  if (isShallow === 'true') {
    findings.push('shallow git repository: fetch-depth: 0 is required for full public history scan');
    return findings;
  }

  const messages = execFileSync('git', ['log', '--format=%H%x20%an%x20<%ae>%x20%cn%x20<%ce>%n%B', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  findings.push(...scanText('git-commit-metadata(HEAD)', messages));

  const commitEmails = execFileSync('git', ['log', '--format=%ae%n%ce', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  })
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  const metadataEmailFinding = 'git-commit-metadata(HEAD): matched forbidden pattern "real personal email"';
  if (commitEmails.some((email) => !ALLOWED_COMMIT_EMAIL_RE.test(email)) && !findings.includes(metadataEmailFinding)) {
    findings.push(metadataEmailFinding);
  }

  const diff = execFileSync('git', ['log', '-p', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const addedLines = diff
    .split('\n')
    .filter((line) => line.startsWith('+') && !line.startsWith('+++ '))
    .join('\n');
  findings.push(...scanText('git-diff-added(HEAD)', addedLines));
  return findings;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    mkdirSync(directory, { recursive: true });
    const [packed] = JSON.parse(
      execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', directory], {
        cwd: root,
        encoding: 'utf8',
      }),
    );
    const tarballPath = path.join(directory, packed.filename);
    const bytes = readFileSync(tarballPath);
    const actualFiles = (packed.files || []).map((f) => f.path).sort();

    // 1. Exact allowlist set equality (neither missing nor unexpected extra files!)
    const missing = EXPECTED_TARBALL_FILES.filter((f) => !actualFiles.includes(f));
    const extra = actualFiles.filter((f) => !EXPECTED_TARBALL_FILES.includes(f));
    assert.deepEqual(missing, [], `Tarball is missing required files: ${missing.join(', ')}`);
    assert.deepEqual(extra, [], `Tarball contains unexpected extra files: ${extra.join(', ')}`);
    assert.deepEqual(actualFiles, EXPECTED_TARBALL_FILES);

    // 2. Unpack into isolated directory and scan every file + verify runtime entry points
    const unpackDir = mkdtempSync(path.join(tmpdir(), 'dsh-remote-unpack-'));
    try {
      execFileSync('tar', ['-xzf', tarballPath, '-C', unpackDir]);
      const pkgRoot = path.join(unpackDir, 'package');

      const scanFindings = scanPackageContent(pkgRoot, actualFiles);
      assert.deepEqual(scanFindings, [], `Sensitive/internal content detected in tarball:\n${scanFindings.join('\n')}`);

      const pkgJson = JSON.parse(readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
      assert.equal(pkgJson.publishConfig?.access, 'public', 'package.json must set publishConfig.access = "public"');

      // Verify syntax of browser/client modules
      execFileSync(process.execPath, ['--check', path.join(pkgRoot, 'client.js')]);
      execFileSync(process.execPath, ['--check', path.join(pkgRoot, 'web-src/dsh-remote-sw.js')]);
      execFileSync(process.execPath, ['--check', path.join(pkgRoot, 'web-src/shell-ui.js')]);

      // Verify cli.js --help runs cleanly
      const nm = path.join(root, 'node_modules');
      if (existsSync(nm)) {
        execFileSync('ln', ['-s', nm, path.join(pkgRoot, 'node_modules')]);
      }
      const helpOut = execFileSync(process.execPath, [path.join(pkgRoot, 'cli.js'), '--help'], {
        cwd: pkgRoot,
        encoding: 'utf8',
      });
      assert.match(helpOut, /dsh-remote connect/u);

      // Verify host-main.js imports cleanly
      const hostMod = await import(pathToFileURL(path.join(pkgRoot, 'host-main.js')).href);
      assert.equal(hostMod.name, 'tiana-remote');
      assert.equal(typeof hostMod.apply, 'function');

      // Verify relay-go/main.go exists and contains dynamic policy support
      const relayGo = readFileSync(path.join(pkgRoot, 'relay-go/main.go'), 'utf8');
      assert.ok(relayGo.includes('DSH_REMOTE_POLICY'));

      // Verify build-web-dist works from unpacked package and stays < 200 KiB
      const buildMod = await import(pathToFileURL(path.join(pkgRoot, 'scripts/build-web-dist.mjs')).href);
      const built = buildMod.buildWebDist({ outDir: path.join(unpackDir, 'dist-check') });
      assert.ok(built.totalBytes < 200 * 1024, `Web shell exceeds 200 KiB: ${built.totalBytes}`);
      assert.ok(built.files.includes('dsh-remote-sw.js'));
      assert.ok(built.files.includes('shell-ui.js'));
    } finally {
      rmSync(unpackDir, { recursive: true, force: true });
    }

    // 3. Scan entire worktree and full reachable git history in both --verify and release modes
    if (existsSync(path.join(root, '.git'))) {
      const repoFindings = scanWorktreeAndGitHistory(root);
      assert.deepEqual(repoFindings, [], `Sensitive/internal content detected in repo/history:\n${repoFindings.join('\n')}`);
    }

    const descriptor = {
      name: packed.name,
      version: packed.version,
      filename: packed.filename,
      fileCount: actualFiles.length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'),
      size: bytes.length,
    };
    if (!verifyOnly) {
      writeFileSync(path.join(directory, 'plugin-release.json'), JSON.stringify(descriptor, null, 2) + '\n');
    }
    console.log(JSON.stringify(descriptor));
  } finally {
    if (scratchDir) rmSync(scratchDir, { recursive: true, force: true });
  }
}
