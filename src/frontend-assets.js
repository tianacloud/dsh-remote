import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, realpathSync, statSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, extname, isAbsolute, join, posix, relative, resolve, sep } from 'node:path';
import { addAbortSignal } from 'node:stream';
import { createGzip } from 'node:zlib';
import { init, parse, ImportType } from 'es-module-lexer';
import { resolveDshPackageDir, resolveDshPackageDirs } from './dsh-packages.js';

const MAX_RESOURCE = 16 << 20;
const MAX_TOTAL = 64 << 20;
const TRANSFORM = 1;
const BOOTSTRAP = '@deepseek-ai/dsh-client-modules';
// DSH 0.2.2-rc.1 passes these singleton modules from the compiled web shell.
const PLATFORM_MODULES = new Set([
  'react', 'react/jsx-runtime', 'react-dom', 'react-dom/client', '@deepseek-ai/cordis', 'zod',
  '@tanstack/react-virtual', '@deepseek-ai/dsh-client-store', '@deepseek-ai/dsh-client-ui-slots',
  '@deepseek-ai/dsh-client-ui-primitives', '@deepseek-ai/dsh-client-ui-dockkit',
]);
const PACKAGE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/u;
const CHUNK = /^client\.[A-Za-z0-9][A-Za-z0-9._-]*\.js$/u;
const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.webmanifest': 'application/manifest+json',
  '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.ttf': 'font/ttf', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.webp': 'image/webp', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.ico': 'image/x-icon', '.avif': 'image/avif',
  '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.webm': 'video/webm',
  '.pdf': 'application/pdf', '.otf': 'font/otf',
};

function confined(root, file) {
  const actual = realpathSync(file);
  const rel = relative(root, actual);
  if (!rel || rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) {
    throw new Error('DSH resource escaped its package');
  }
  return actual;
}

function readFile(file) {
  const stat = statSync(file);
  if (!stat.isFile() || stat.size > MAX_RESOURCE) throw new Error('Invalid DSH resource size or type');
  const bytes = readFileSync(file);
  if (bytes.length > MAX_RESOURCE) throw new Error('DSH resource exceeds size limit');
  return bytes;
}

function localKey(source, specifier, entries) {
  const resolved = posix.normalize(posix.join(posix.dirname(source), specifier));
  if (!specifier.startsWith('.') || !entries.has(resolved)) {
    throw new Error(`Unsupported core dependency: ${source} → ${specifier}`);
  }
  return 'core:' + resolved;
}

export function safeExpression(ctx, expression) {
  return String(expression).split('.').reduce((value, key) =>
    value != null && Object.hasOwn(value, key) ? value[key] : undefined, ctx);
}

function coreModule(file, source, entries, isEntry) {
  if (isEntry) {
    const pattern = /new Function\("ctx","expr",`[\s\S]*?return eval\(expr\)[\s\S]*?`\)/gu;
    const preloader = /(\b[$\w]+)=function\(([$\w,]+)\)\{let [$\w]+=Promise\.resolve\(\);if\([\s\S]*?new Event\("vite:preloadError"[\s\S]*?return [$\w]+\(\)\.catch\([$\w]+\)\}\)\}/gu;
    if ([...source.matchAll(pattern)].length !== 1 || [...source.matchAll(preloader)].length !== 1) {
      throw new Error('Unsupported DSH frontend transformation');
    }
    source = source.replace(pattern, '(' + safeExpression.toString() + ')')
      .replace(preloader, '$1=(load)=>load()');
  }
  const edits = [];
  const links = [];
  let dynamicImports = 0;
  for (const item of parse(source, file)[0]) {
    if (item.t === ImportType.ImportMeta && source.slice(item.e, item.e + 4) === '.url') {
      // Vite build paths only occur in the preload shim disabled above.
      edits.push([item.s, item.e + 4, JSON.stringify('https://dsh-assets.invalid/' + file)]);
    } else if (item.t === ImportType.Static) {
      const key = localKey(file, item.n, entries);
      const marker = '__DSH_CORE_LINK_' + links.length + '__';
      links.push({ marker, key });
      edits.push([item.s, item.e, marker]);
    } else if (item.t === ImportType.Dynamic && item.n?.startsWith('.')) {
      ++dynamicImports;
      edits.push([item.ss, item.se, 'globalThis.__DSH_IMPORT_CORE__(' + JSON.stringify(localKey(file, item.n, entries)) + ')']);
    }
  }
  for (const [start, end, replacement] of edits.sort((a, b) => b[0] - a[0])) {
    source = source.slice(0, start) + replacement + source.slice(end);
  }
  return { bytes: Buffer.from(source), links, dynamicImports };
}

function browserExport(root, pkg) {
  const declared = pkg.exports?.['./client'];
  const browser = typeof declared === 'string' ? declared : declared?.default;
  if (typeof browser !== 'string' || !browser.startsWith('./')) throw new Error('DSH client has no browser export');
  return confined(root, resolve(root, browser));
}

function artifactRevision(file) {
  const stat = statSync(file);
  const hash = createHash('sha1').update('plugin-artifact\0');
  for (const value of [stat.mtimeMs, stat.ctimeMs, stat.size].map(String)) {
    hash.update(String(Buffer.byteLength(value)) + ':').update(value);
  }
  return hash.digest('hex').slice(0, 12);
}

function packageFromClient(row, clientPath) {
  if (clientPath) {
    const client = realpathSync(clientPath);
    for (let root = dirname(client); dirname(root) !== root; root = dirname(root)) {
      const metadata = join(root, 'package.json');
      if (!existsSync(metadata)) continue;
      const pkg = JSON.parse(readFile(metadata));
      if (pkg.name !== row.id) continue;
      if (client !== browserExport(root, pkg)) throw new Error('Active DSH client is not its declared export');
      return { root, pkg, client };
    }
  } else {
    // Standalone bridge gets the live revision over loopback. Locate precisely that
    // export, even when the machine has multiple versions of the same package.
    for (const root of resolveDshPackageDirs(row.id)) {
      const pkg = JSON.parse(readFile(join(root, 'package.json')));
      if (pkg.name !== row.id) continue;
      const client = browserExport(root, pkg);
      if (artifactRevision(client) === row.rev) return { root, pkg, client };
    }
  }
  throw new Error('No matching export for active DSH module: ' + row.id);
}

function cleanBundle(file) {
  return Buffer.from(readFile(file).toString('utf8').replace(/\r?\n\/\/# source(?:Mapping)?URL=[^\r\n]*/gu, ''));
}

const BUILTIN_CLIENT_PREFIX = '@deepseek-ai/dsh-client-';
const SELF_CLIENT_MODULE = '@tianacloud/dsh-remote';

/**
 * Select which active DSH client modules are exposed over the remote tunnel.
 * - `allowlist: ['*']` (or `'*'`): allow all active modules.
 * - `allowlist: []` (default) or omitted: allow ONLY builtin DSH core modules
 *   (`@deepseek-ai/dsh-client-*`) plus `@tianacloud/dsh-remote` itself; third-party plugins are blocked.
 * - Explicit IDs: allow builtin core + `@tianacloud/dsh-remote` + exact allowlisted active plugins.
 */
export function selectAllowedWebPlugins(modules, allowlist) {
  const rawLimit = Array.isArray(allowlist)
    ? allowlist
    : typeof allowlist === 'string'
      ? allowlist.split(',')
      : [];
  const limit = rawLimit.map((id) => String(id).trim()).filter(Boolean);
  const allowAll = limit.includes('*');

  if (allowAll) {
    return new Set(modules.keys());
  }

  const selected = new Set();
  if (modules.has(BOOTSTRAP)) selected.add(BOOTSTRAP);
  for (const id of modules.keys()) {
    if (id.startsWith(BUILTIN_CLIENT_PREFIX) || id === SELF_CLIENT_MODULE) {
      selected.add(id);
    }
  }
  for (const id of limit) {
    if (modules.has(id)) {
      selected.add(id);
    }
  }
  return selected;
}

function compilePlugins(graph, options, add) {
  if (!graph) return undefined;
  if (!Array.isArray(graph.entries) || !Array.isArray(graph.batches)) {
    throw new Error('Unsupported DSH boot manifest');
  }
  const modules = new Map();
  for (const row of graph.entries) {
    if (!PACKAGE.test(row.id) || typeof row.rev !== 'string' || modules.has(row.id)) {
      throw new Error('Invalid DSH boot module');
    }
    modules.set(row.id, row);
  }
  const rawLimit = Array.isArray(options.allowlist)
    ? options.allowlist
    : typeof options.allowlist === 'string'
      ? options.allowlist.split(',')
      : [];
  const allowAll = rawLimit.map((id) => String(id).trim()).includes('*');
  const selected = selectAllowedWebPlugins(modules, options.allowlist);
  if (modules.size > 0 && !modules.has(BOOTSTRAP)) {
    throw new Error('A required DSH client module is absent: ' + BOOTSTRAP);
  }
  if (modules.has(BOOTSTRAP)) {
    selected.add(BOOTSTRAP);
  }
  const isBuiltinOrBootstrap = (id) => id === BOOTSTRAP || id.startsWith(BUILTIN_CLIENT_PREFIX);
  for (const id of selected) {
    const row = modules.get(id);
    if (!row) throw new Error('A required DSH client module is absent: ' + id);
    for (const dependency of row.external ?? []) {
      const name = dependency.replace(/\/client$/u, '');
      if (selected.has(name)) continue;
      if (modules.has(name)) {
        if (allowAll || isBuiltinOrBootstrap(name) || name === SELF_CLIENT_MODULE) {
          selected.add(name);
        } else if (isBuiltinOrBootstrap(id)) {
          continue;
        } else {
          throw new Error(`Required third-party DSH module is not allowlisted: ${name}`);
        }
      } else if (!PLATFORM_MODULES.has(dependency)) {
        throw new Error('Required DSH module is not active: ' + dependency);
      }
    }
  }
  const keepDep = (dep) => PLATFORM_MODULES.has(dep) || selected.has(String(dep).replace(/\/client$/u, ''));
  const entryOrder = graph.entries
    .filter((row) => selected.has(row.id))
    .map((row) => {
      const next = { ...row };
      if (Array.isArray(row.inject)) {
        next.inject = row.inject.filter(keepDep);
      }
      if (Array.isArray(row.external)) {
        next.external = row.external.filter(keepDep);
      }
      return next;
    });
  for (const row of entryOrder) {
    const id = row.id;
    const { root, pkg, client: clientFile } = packageFromClient(row, options.activeClientPath?.(id));
    const clientDir = dirname(clientFile);
    const route = 'plugins/??' + id + '/client.js&rev=' + encodeURIComponent(row.rev);
    add('plugin:' + id + '/client.js', cleanBundle(clientFile), '.js', { route, owner: id, registration: id });
    for (const item of readdirSync(clientDir, { withFileTypes: true })) {
      if (!CHUNK.test(item.name) || /^client\.(?:node|browser)(?:\.|$)/u.test(item.name)) continue;
      if (!item.isFile() && !item.isSymbolicLink()) continue;
      const file = confined(root, join(clientDir, item.name));
      add('chunk:' + id + '/' + item.name, cleanBundle(file), '.js', {
        route: 'plugins/' + id + '/' + item.name + '?rev=' + encodeURIComponent(row.rev), owner: id,
        registration: id, chunk: item.name,
      });
    }

    const exportTarget = pkg.exports?.['./assets/*'];
    if (typeof exportTarget !== 'string' || !exportTarget.endsWith('/*')) continue;
    const exportDir = confined(root, resolve(root, exportTarget.slice(0, -2)));
    const require = createRequire(join(root, 'package.json'));
    for (const entry of readdirSync(exportDir, { recursive: true, withFileTypes: true })) {
      const candidate = join(entry.parentPath, entry.name);
      const suffix = extname(entry.name);
      if (!MIME[suffix] || (!entry.isFile() && !entry.isSymbolicLink())) continue;
      const path = relative(exportDir, candidate).split(sep).join('/');
      const actual = confined(root, require.resolve(id + '/assets/' + path));
      if (actual !== confined(root, candidate)) throw new Error('DSH asset export does not match its package');
      const encoded = path.split('/').map(encodeURIComponent).join('/');
      add('asset:' + id + '/' + encoded, readFile(actual), suffix, {
        route: 'plugins/' + id + '/assets/' + encoded, owner: id,
      });
    }
  }
  return {
    ...graph,
    entries: entryOrder,
    batches: entryOrder.map((row) => ({
      phase: row.id === BOOTSTRAP ? 'bootstrap' : 'application',
      url: row.url, rev: row.rev, entries: [row.id],
    })),
  };
}

export class FrontendAssets {
  constructor(options = {}) {
    this.options = { ...options };
    this.snapshot = null;
    this.serial = 0;
    this.activeCompression = 0;
    this.waitingCompression = [];
  }

  setAllowlist(allowlist) {
    const nextKey = JSON.stringify(allowlist ?? null);
    const prevKey = JSON.stringify(this.options.allowlist ?? null);
    if (nextKey === prevKey) return false;
    this.options.allowlist = allowlist;
    this.snapshot = null;
    this.building = null;
    return true;
  }

  async prepare(rows) {
    const graph = rows.find((row) => row.kind === 'global' && row.name === '__DSH_BOOT__')?.value;
    const signature = JSON.stringify({ graph: graph ?? null, allowlist: this.options.allowlist ?? null });
    if (!this.snapshot || this.snapshot.signature !== signature) {
      const existing = this.building;
      if (existing?.signature === signature) return existing.promise;
      const promise = this.build(graph, signature);
      this.building = { signature, promise };
      try {
        const snapshot = await promise;
        if (this.building?.promise === promise) this.snapshot = snapshot;
        return snapshot;
      } finally {
        if (this.building?.promise === promise) this.building = null;
      }
    }
    return this.snapshot;
  }

  async build(graph, signature) {
    await init;
    const packageRoot = realpathSync(this.options.frontend || resolveDshPackageDir('@deepseek-ai/dsh-web-frontend'));
    const dist = confined(packageRoot, join(packageRoot, 'dist'));
    const html = readFile(confined(dist, join(dist, 'index.html'))).toString('utf8');
    const entry = /<script\s+type="module"[^>]*\bsrc="\.\/([^"]+\.js)"/u.exec(html)?.[1];
    if (!entry) throw new Error('DSH frontend has no module entry');
    const styles = [...html.matchAll(/rel="stylesheet"[^>]*href="\.\/([^"]+\.css)"/gu)].map((m) => 'core:' + m[1]);
    const paths = new Map();
    for (const item of readdirSync(dist, { withFileTypes: true, recursive: true })) {
      if (!item.isDirectory() && MIME[extname(item.name)]) {
        const actual = confined(dist, join(item.parentPath, item.name));
        paths.set(relative(dist, join(item.parentPath, item.name)).split(sep).join('/'), actual);
      }
    }
    let total = 0;
    const resources = new Map();
    function add(key, bytes, suffix, meta = {}) {
      total += bytes.length;
      if (bytes.length > MAX_RESOURCE || total > MAX_TOTAL || resources.has(key)) {
        throw new Error('Invalid, duplicate or oversized DSH frontend resource');
      }
      const digest = createHash('sha256').update(bytes).digest('hex');
      resources.set(key, { meta: { key, rev: digest, sha256: digest, byteLength: bytes.length, mimeType: MIME[suffix], ...meta }, bytes });
    }
    for (const [path, actual] of paths) {
      const suffix = extname(path);
      let bytes = readFile(actual);
      let details = {};
      if (suffix === '.js') ({ bytes, ...details } = coreModule(path, bytes.toString('utf8'), paths, path === entry));
      if (suffix === '.css') {
        const links = [];
        bytes = Buffer.from(bytes.toString('utf8').replace(/url\(["']?(\.\.?\/[^)'"]+)["']?\)/gu, (_, ref) => {
          const marker = '__DSH_STYLE_LINK_' + links.length + '__';
          links.push({ marker, key: localKey(path, ref, paths) });
          return 'url("' + marker + '")';
        }));
        details = { links };
      }
      add('core:' + path, bytes, suffix, details);
    }
    const boot = compilePlugins(graph, this.options, add);
    this.serial++;
    return {
      signature,
      resources,
      manifest: {
        transformVersion: TRANSFORM, generation: Date.now(), serial: this.serial,
        entry: 'core:' + entry, styles, boot, resources: [...resources.values()].map((row) => row.meta),
      },
    };
  }

  async representation(asset, compressed, signal) {
    signal.throwIfAborted();
    if (!compressed || asset.bytes.length < 1024 || !/^(text\/|application\/(json|wasm)|image\/svg\+xml)/u.test(asset.meta.mimeType)) {
      return { bytes: asset.bytes, encoding: 'identity' };
    }
    if (this.activeCompression >= 4) {
      await new Promise((resolve, reject) => {
        const ready = () => {
          signal.removeEventListener('abort', abort);
          resolve();
        };
        const abort = () => {
          this.waitingCompression = this.waitingCompression.filter((entry) => entry !== ready);
          reject(signal.reason);
        };
        this.waitingCompression.push(ready);
        signal.addEventListener('abort', abort, { once: true });
      });
    } else {
      this.activeCompression++;
    }
    try {
      signal.throwIfAborted();
      const stream = addAbortSignal(signal, createGzip());
      stream.end(asset.bytes);
      const parts = [];
      for await (const part of stream) parts.push(part);
      signal.throwIfAborted();
      return { bytes: Buffer.concat(parts), encoding: 'gzip' };
    } finally {
      const next = this.waitingCompression.shift();
      if (next) next();
      else this.activeCompression--;
    }
  }
}
