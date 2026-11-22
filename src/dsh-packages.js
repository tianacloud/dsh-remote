import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

function parseSemverTag(raw) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/u.exec(String(raw || ''));
  if (!m) return null;
  const pre = m[4]
    ? m[4].split('.').map((part) => (/^\d+$/u.test(part) ? Number(part) : part))
    : [];
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]), pre };
}

export function comparePnpmPackageEntriesDesc(a, b, pnpmPrefix) {
  const tagA = a.slice(pnpmPrefix.length).split('_', 1)[0];
  const tagB = b.slice(pnpmPrefix.length).split('_', 1)[0];
  const sa = parseSemverTag(tagA);
  const sb = parseSemverTag(tagB);
  if (sa && sb) {
    if (sa.major !== sb.major) return sb.major - sa.major;
    if (sa.minor !== sb.minor) return sb.minor - sa.minor;
    if (sa.patch !== sb.patch) return sb.patch - sa.patch;
    // Stable release (empty pre) ranks higher than prerelease
    if (sa.pre.length === 0 && sb.pre.length > 0) return -1;
    if (sa.pre.length > 0 && sb.pre.length === 0) return 1;
    const len = Math.max(sa.pre.length, sb.pre.length);
    for (let i = 0; i < len; i += 1) {
      const pa = sa.pre[i];
      const pb = sb.pre[i];
      if (pa === undefined) return 1;
      if (pb === undefined) return -1;
      if (pa === pb) continue;
      if (typeof pa === 'number' && typeof pb === 'number') return pb - pa;
      if (typeof pa === 'number') return 1;
      if (typeof pb === 'number') return -1;
      return pb.localeCompare(pa);
    }
  } else if (sa) {
    return -1;
  } else if (sb) {
    return 1;
  }
  return b.localeCompare(a);
}

function resolveViaAnchor(anchorPath, packageName, unique) {
  const found = [];
  if (!anchorPath || !existsSync(anchorPath)) return found;
  let anchorReal = anchorPath;
  try {
    anchorReal = realpathSync(anchorPath);
  } catch {
    return found;
  }
  let req;
  try {
    req = createRequire(anchorReal);
  } catch {
    return found;
  }
  try {
    const direct = unique(dirname(req.resolve(packageName + '/package.json')));
    if (direct) found.push(direct);
  } catch {
    // Try resolving through @deepseek-ai/dsh-web-app when pnpm strict layout nests peer deps.
  }
  if (packageName !== '@deepseek-ai/dsh-web-app') {
    try {
      const webAppPkg = req.resolve('@deepseek-ai/dsh-web-app/package.json');
      const webAppReq = createRequire(webAppPkg);
      const nested = unique(dirname(webAppReq.resolve(packageName + '/package.json')));
      if (nested) found.push(nested);
    } catch {
      // ignore
    }
  }
  return found;
}

export function* resolveDshPackageDirs(packageName, options = {}) {
  const seen = new Set();
  function unique(path) {
    if (!existsSync(join(path, 'package.json'))) return undefined;
    const real = realpathSync(path);
    if (seen.has(real)) return undefined;
    seen.add(real);
    return real;
  }

  const home = options.home ?? (process.env.HOME || '');
  const activeEntry = options.activeEntry ?? process.argv[1];
  const anchors = [
    activeEntry,
    join(home, '.local/share/pnpm/global/5/node_modules/@deepseek-ai/dsh/package.json'),
  ];
  for (const anchor of anchors) {
    for (const dir of resolveViaAnchor(anchor, packageName, unique)) {
      yield dir;
    }
  }

  const require = createRequire(import.meta.url);
  try {
    const path = unique(dirname(require.resolve(packageName + '/package.json')));
    if (path) yield path;
  } catch {
    // The installed DSH profile normally owns these packages.
  }

  const stores = options.stores ?? [
    process.env.DSH_PNPM_STORE,
    join(process.env.DSH_HOME || join(home, '.dsh'), 'profiles/web/node_modules'),
    join(home, '.local/share/pnpm/global/5/.pnpm'),
  ];
  const pnpmPrefix = packageName.replace('/', '+') + '@';
  for (const base of stores) {
    if (!base || !existsSync(base)) continue;
    const direct = unique(join(base, packageName));
    if (direct) yield direct;
    const matched = readdirSync(base)
      .filter((entry) => entry.startsWith(pnpmPrefix))
      .sort((a, b) => comparePnpmPackageEntriesDesc(a, b, pnpmPrefix));
    for (const entry of matched) {
      const path = unique(join(base, entry, 'node_modules', packageName));
      if (path) yield path;
    }
  }
}

export function resolveDshPackageDir(packageName, options = {}) {
  const first = resolveDshPackageDirs(packageName, options).next();
  if (first.done) throw new Error('Unable to locate ' + packageName + '. Ensure DSH is installed.');
  return first.value;
}

