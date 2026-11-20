import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

export function* resolveDshPackageDirs(packageName) {
  const seen = new Set();
  function unique(path) {
    if (!existsSync(join(path, 'package.json'))) return undefined;
    const real = realpathSync(path);
    if (seen.has(real)) return undefined;
    seen.add(real);
    return real;
  }

  const require = createRequire(import.meta.url);
  try {
    const path = unique(dirname(require.resolve(packageName + '/package.json')));
    if (path) yield path;
  } catch {
    // The installed DSH profile normally owns these packages.
  }

  const home = process.env.HOME || '';
  const stores = [
    process.env.DSH_PNPM_STORE,
    join(process.env.DSH_HOME || join(home, '.dsh'), 'profiles/web/node_modules'),
    join(home, '.local/share/pnpm/global/5/.pnpm'),
  ];
  const pnpmPrefix = packageName.replace('/', '+') + '@';
  for (const base of stores) {
    if (!base || !existsSync(base)) continue;
    const direct = unique(join(base, packageName));
    if (direct) yield direct;
    for (const entry of readdirSync(base).sort()) {
      if (!entry.startsWith(pnpmPrefix)) continue;
      const path = unique(join(base, entry, 'node_modules', packageName));
      if (path) yield path;
    }
  }
}

export function resolveDshPackageDir(packageName) {
  const first = resolveDshPackageDirs(packageName).next();
  if (first.done) throw new Error('Unable to locate ' + packageName + '. Ensure DSH is installed.');
  return first.value;
}
