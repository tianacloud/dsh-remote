import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createServer as createTLS } from 'node:https';
import { createRequire } from 'node:module';
import { connect } from 'node:net';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { HostBridge } from '../src/host-bridge.js';
import { buildWebDist } from '../scripts/build-web-dist.mjs';
import { generateE2eeSecret } from '../src/state.js';

const csp = "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self' https: blob: 'wasm-unsafe-eval'; style-src 'self' https: blob: 'unsafe-inline'; connect-src 'self' https: wss:; img-src 'self' https: data: blob:; media-src 'self' https:; font-src 'self' https: data: blob:; worker-src 'self' blob:";
const project = fileURLToPath(new URL('..', import.meta.url));
const scratch = await mkdtemp(join(project, '.browser-'));
const output = resolve(process.argv[2]);
await mkdir(output, { recursive: true });
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.DSH_REMOTE_TEST_PLAYWRIGHT || 'playwright');
const target = { hostId: 'test-host', webId: 'testweb00001', ownerUserId: 'fixture-owner', ownerTenantId: 'fixture-tenant' };
const registrationKey = generateE2eeSecret();
const pairingKey = generateE2eeSecret();
const root = join(scratch, 'web');
const appBase = '/web/' + target.webId + '/';
const keyName = 'dsh-remote:v2:key:' + [target.webId, target.ownerUserId, target.hostId].join(':');
const sessions = { renewed: 0 };
let deny = 0;
let shortLease = false;
let relayPort;
let secure;
let browser;
let dsh;
let relay;
let bridge;
const sockets = new Set();
const fixturePackage = join(scratch, 'resource-fixture');
const fixtureId = 'plugin-route-browser-fixture';
let enablePlugin = false;
let truncate = false;
let acceptedWrites = 0;

await mkdir(join(fixturePackage, 'assets'), { recursive: true });
await writeFile(join(fixturePackage, 'package.json'), JSON.stringify({
  name: fixtureId, exports: { './client': './client.js', './assets/*': './assets/*' },
}));
await writeFile(join(fixturePackage, 'assets', 'hello@2x-54694.svg'),
  '<svg xmlns="http://www.w3.org/2000/svg" width="36" height="26"><rect width="36" height="26" fill="green"/></svg>');
await writeFile(join(fixturePackage, 'assets', 'probe.wasm'), Buffer.from('0061736d01000000','hex'));
await writeFile(join(fixturePackage, 'client.lazy.js'),
  'window.__ModuleLoader__.load({id:"' + fixtureId + '",chunk:"client.lazy.js",factory(){return {value:"late success"}}});');
await writeFile(join(fixturePackage, 'client.js'),
  'window.__ModuleLoader__.load({id:"' + fixtureId + '",factory(require){return {apply(){' +
  'const box=document.createElement("output");box.id="fixture-plugin";box.textContent="Plugin active";' +
  'box.style.cssText="position:fixed;top:12px;right:12px;z-index:10001;background:white;color:green;padding:14px";' +
  'const icon=document.createElement("img");icon.alt="Exported icon";icon.src=require.asset("plugins/' + fixtureId + '/assets/hello%402x-54694.svg");box.append(icon);' +
  'document.body.append(box);' +
  'window.pluginRouteFixture = {async run(){return (await require.async("./client.lazy.js")).value}};' +
  '}}}});');


const shell = buildWebDist({
  outDir: root, config: { ...target, defaultHostId: target.hostId, functionId: 'fixture-function' },
});
const http = createServer(async (request, reply) => {
  const pathname = new URL(request.url, 'http://fixture.invalid').pathname;
  const routed = pathname.startsWith(appBase) ? '/' + pathname.slice(appBase.length) : pathname;
  const path = routed.startsWith('/assets/') ? routed.slice('/assets'.length) : routed;
  if (path === '/') {
    reply.setHeader('Content-Type', 'text/html; charset=utf-8');
    reply.setHeader('Content-Security-Policy', csp);
    reply.end('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>DSH Remote</title><div id="app"></div><script type="module" src="startup.mjs"></script>');
  } else if (path === '/startup.mjs') {
    reply.setHeader('Content-Type', 'text/javascript');
    reply.end('globalThis.tiana={functions:{websocket:(_,path)=>new Promise((ok,fail)=>{const s=new WebSocket(new URL(path,location));s.onopen=()=>ok(s);s.onerror=fail})}};\n' +
      'const {mount}=await import("./assets/dsh-remote-entry.mjs"); mount(document.getElementById("app"),globalThis.tiana,' +
      JSON.stringify(shortLease ? { renewalMs: 1000, leaseMs: 6500 } : { renewalMs: 5000 }) + ');');
  } else if (path === '/_tiana/session') {
    reply.setHeader('Content-Type', 'application/json');
    reply.end(JSON.stringify({ status: 'SESSION_ACTIVE', app_tenant_id: target.ownerTenantId, is_app_owner: true, tenant_id: target.ownerTenantId, user: { user_id: target.ownerUserId } }));
  } else if (path === '/_tiana/function-connection' && request.method === 'POST') {
    sessions.renewed++;
    reply.setHeader('Content-Type', 'application/json');
    reply.writeHead(deny || 200);
    reply.end(JSON.stringify({ origin: 'https://127.0.0.1:' + secure.address().port, token: 'synthetic-fixture-transport' }));
  } else if (path === '/favicon.ico') {
    reply.writeHead(204).end();
  } else if (/^\/[A-Za-z0-9_.-]+\.(mjs|js|json|svg)$/u.test(path)) {
    const types = { js: 'text/javascript', mjs: 'text/javascript', json: 'application/json', svg: 'image/svg+xml' };
    reply.setHeader('Content-Type', types[path.split('.').at(-1)]);
    try { reply.end(await readFile(join(root, path))); } catch { reply.writeHead(404).end(); }
  } else reply.writeHead(404).end();
});
function upgrade(request, socket, head) {
  sockets.add(socket);
  socket.once('close', () => sockets.delete(socket));
  const upstream = connect(relayPort, '127.0.0.1', () => {
    const method = 'GET ' + request.url + ' HTTP/1.1\r\n';
    upstream.write(method + [
      'Host: 127.0.0.1:' + relayPort,
      'Origin: ' + base,
      'Tiana-Caller-User-Id: ' + target.ownerUserId,
      'Tiana-Caller-Tenant-Id: ' + target.ownerTenantId,
      'Tiana-Caller-Web-Id: ' + target.webId,
      ...['connection', 'upgrade', 'sec-websocket-key', 'sec-websocket-version'].map((name) => name + ': ' + request.headers[name]),
      '', '',
    ].join('\r\n'));
    if (head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
}
http.on('upgrade', upgrade);
http.listen(0, '127.0.0.1');
await once(http, 'listening');
const base = 'http://127.0.0.1:' + http.address().port;
const appURL = base + appBase;

async function freePort() {
  const server = createServer().listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  server.close();
  return port;
}

async function startDsh() {
  const home = join(scratch, 'home');
  dsh = spawn('dsh', ['web', '--host', '127.0.0.1', '--port', '0', '--no-open'], {
    cwd: scratch, env: { ...process.env, DSH_HOME: home },
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('DSH did not start')), 14000);
    let pending = '';
    dsh.stdout.on('data', (chunk) => {
      pending += chunk.toString();
      const match = /dsh web: (http:\/\/127\.0\.0\.1:[0-9]+\/\?token=[^\s]+)/u.exec(pending);
      if (match) {
        clearTimeout(timer);
        pending = '';
        resolve(new URL(match[1]));
      }
    });
    dsh.once('error', (error) => { clearTimeout(timer); reject(error); });
    dsh.once('exit', (code) => { clearTimeout(timer); reject(new Error('DSH exited: ' + code)); });
    // Drain diagnostics without logging the launch URL or credentials.
    dsh.stderr.resume();
  });
}
try {
  const cert = join(scratch, 'local-cert.pem');
  const tlsKey = join(scratch, 'local-key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', tlsKey, '-out', cert,
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  secure = createTLS({ cert: await readFile(cert), key: await readFile(tlsKey) });
  secure.on('upgrade', upgrade);
  secure.listen(0, '127.0.0.1');
  await once(secure, 'listening');
  relayPort = await freePort();
  const access = JSON.stringify({ ...target, origin: base,
    hostDigest: createHash('sha256').update(registrationKey).digest('hex') });
  const binary = join(scratch, 'relay');
  execFileSync('go', ['build', '-buildvcs=false', '-ldflags', '-X main.relayConfigJSON=' + access, '-o', binary, '.'], { cwd: join(project, 'relay-go') });
  relay = spawn(binary, [], { env: { ...process.env, PORT: String(relayPort) }, stdio: 'ignore' });
  const local = await startDsh();
  const relayUrl = 'http://127.0.0.1:' + relayPort;
  for (let i = 0; i < 30; i++) {
    if (await fetch(relayUrl + '/health').then((r) => r.ok).catch(() => false)) break;
    await delay(100);
  }
  let marks = { compressed: 0, originalCompressible: 0, resources: 0, wire: 0, relayE2EE: 0, p2pE2EE: 0, paths: [] };
  const fromHost = async (leaseMs) => {
    const host = new HostBridge({
      ...target, localOrigin: local.origin, relayUrl, registrationKey, e2eeSecret: pairingKey,
      getLaunchToken: () => local.searchParams.get('token'), allowInsecureLoopback: true, stun: 'none', leaseMs,
      frontendOptions: { allowlist: [fixtureId] },
      activeClientPath: (id) => id === fixtureId ? join(fixturePackage, 'client.js') : undefined,
    });
    const boot = host.collectIndexInjections.bind(host);
    host.collectIndexInjections = async () => {
      const rows = await boot();
      if (!enablePlugin) return rows;
      const graph = rows.find((row) => row.name === '__DSH_BOOT__').value;
      return [{ kind: 'global', name: '__DSH_BOOT__', value: {
        ...graph,
        entries: [...graph.entries, {
          id: fixtureId, url: 'plugins/??' + fixtureId + '/client.js&rev=fixture1', rev: 'fixture1', immediately: true,
        }],
      } }];
    };
    const representation = host.frontend.representation.bind(host.frontend);
    host.frontend.representation = async (asset, gzip, signal) => {
      const result = await representation(asset, gzip, signal);
      if (asset.meta.key) {
        marks.resources++;
        marks.wire += result.bytes.length;
        marks.paths.push(asset.meta.key);
        if (result.encoding === 'gzip') {
          marks.originalCompressible += asset.bytes.length;
          marks.compressed += result.bytes.length;
          if (truncate) result.bytes = result.bytes.subarray(0, -8);
        }
      }
      return result;
    };
    const originalSend = host.sendRawFrame.bind(host);
    host.sendRawFrame = (...args) => {
      if (args[2] === 0x30 || args[2] === 0x31) marks.relayE2EE += 9 + args[3].length;
      return originalSend(...args);
    };
    const auth = host.handleE2eeClientHello.bind(host);
    host.handleE2eeClientHello = async (leg, payload) => {
      await auth(leg, payload);
      if (leg.session && !leg.session.measured) {
        leg.session.measured = true;
        const transport = leg.session.transport;
        const original = transport.setP2P.bind(transport);
        transport.setP2P = (path) => {
          if (path) {
            const send = path.send;
            path.send = (type, payload) => {
              marks.p2pE2EE += 1 + payload.length;
              return send(type, payload);
            };
          }
          original(path);
        };
      }
    };
    const localAPI = host.executeHttpStream.bind(host);
    host.executeHttpStream = async (id, stream, session, entry) => {
      if (entry.head.path === '/api/plugin-route-unknown-write' && entry.head.method === 'POST') {
        acceptedWrites++;
        return new Promise((resolve) => entry.abortController.signal.addEventListener('abort', resolve, { once: true }));
      }
      return localAPI(id, stream, session, entry);
    };
    await host.start();
    return host;
  };
  bridge = await fromHost();
  browser = await chromium.launch({ channel: 'chrome', headless: true, args: ['--disable-features=WebRtcHideLocalIpsWithMdns'] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 850 }, ignoreHTTPSErrors: true });
  let page = await context.newPage();
  const errors = [];
  function observe(tab) {
    tab.on('pageerror', (error) => errors.push(error.message));
    tab.on('console', (row) => {
      if (row.type() === 'error') console.log('browser console:', row.text().slice(0, 240).replace(/blob:[^\s]+/gu, 'blob:[fixture]'));
    });
  }
  observe(page);
  await page.goto(appURL + '#k=obsolete-fixture-only');
  let input = page.locator('#dsh-remote-e2ee-key-input');
  await input.waitFor({ timeout: 10000 });
  assert.equal(new URL(page.url()).hash, '');
  await page.screenshot({ path: join(output, 'browser-pairing.png') });
  await input.fill(pairingKey);
  await page.locator('#dsh-remote-e2ee-submit').click();
  const waitForWorkbench = async (tab) => {
    await tab.waitForFunction(
      () => Boolean(globalThis.__DSH_REMOTE_SHELL__?.isRemote) && document.querySelector('#root')?.children.length > 0,
      { timeout: 40000 },
    );
  };
  const waitForTransportState = async (tab, expected, timeout = 10000) => {
    await tab.waitForFunction(
      (want) => globalThis.__DSH_REMOTE_SHELL__?.getStatusSnapshot?.()?.transportState === want,
      expected,
      { timeout },
    );
  };

  try {
    await waitForWorkbench(page);
  } catch (error) {
    console.log('Workstation startup:', (await page.locator('body').innerText()).slice(0, 600));
    throw error;
  }
  await page.screenshot({ path: join(output, 'browser-workbench.png') });
  console.log('DSH real browser mounted:', (await page.locator('body').innerText()).slice(0, 300).replaceAll('\n', ' | '));
  const localRpc = await page.evaluate(async () => {
    const response = await globalThis.__DSH_TRANSPORT__.fetch('api/dynamicCordisRunner/inventory', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}',
    });
    return response.status;
  });
  assert.equal(localRpc, 200);
  assert.equal(await page.evaluate((key) => Boolean(localStorage.getItem(key)), keyName), true);
  const core = bridge.frontend.snapshot.manifest.resources;
  const transforms = {
    dynamicImports: core.find((entry) => entry.key === bridge.frontend.snapshot.manifest.entry).dynamicImports,
    cssLinks: core.filter((entry) => entry.mimeType === 'text/css').reduce((sum, entry) => sum + entry.links.length, 0),
  };
  assert.deepEqual(transforms, { dynamicImports: 57, cssLinks: 22 });
  const cold = marks;
  marks = { compressed: 0, originalCompressible: 0, resources: 0, wire: 0, relayE2EE: 0, p2pE2EE: 0, paths: [] };
  await page.reload();
  await waitForWorkbench(page);
  assert.equal(await input.count(), 0);
  const warm = { ...marks, paths: [...marks.paths] };
  assert.equal(warm.wire, 0);
  await page.close();
  page = await context.newPage();
  observe(page);
  input = page.locator('#dsh-remote-e2ee-key-input');
  await page.goto(appURL);
  await waitForWorkbench(page);
  assert.equal(await input.count(), 0);
  assert.equal(marks.wire, 0);
  console.log('Reopened browser tab: paired without prompting and fetched zero asset bodies');
  await waitForTransportState(page, 'P2P', 10000);
  await page.screenshot({ path: join(output, 'browser-p2p.png') });
  let active = [...bridge.sessions.values()].find((session) => session.peer.current?.promoted);
  assert.ok(active);
  const initialGeneration = active.id;
  const deadline = active.transport.expiresAt;
  const originalLeg = active.leg;
  const waitUntil = async (check, timeout = 10000) => {
    const limit = Date.now() + timeout;
    while (!check()) {
      if (Date.now() >= limit) throw new Error('Host observation timed out');
      await delay(20);
    }
  };
  await waitUntil(() => sessions.renewed && active.leg !== originalLeg && active.transport.expiresAt > deadline);
  assert.equal(active.id, initialGeneration);
  assert.equal(active.peer.current.promoted, true);
  console.log('Renewal: authenticated fresh /client leg extended lease on the same live P2P generation');

  const oldRelay = bridge.ws;
  const oldLeg = active.leg;
  oldRelay.close(1000, 'fixture host leg rotation');
  await waitUntil(() => bridge.ws !== oldRelay && bridge.registered && active.leg && active.leg !== oldLeg);
  assert.equal(active.id, initialGeneration);
  assert.equal(active.peer.current.promoted, true);
  console.log('Host relay leg rotation: P2P generation stayed live and accepted a fresh authenticated leg');

  const oldBrowserLeg = active.leg;
  for (const socket of sockets) socket.destroy();
  await waitUntil(() => active.leg && active.leg !== oldBrowserLeg);
  assert.equal(active.id, initialGeneration);
  assert.equal(active.peer.current.promoted, true);
  console.log('Client relay leg rotation: P2P generation stayed live and resumed the relay leg');

  await active.peer.stop();
  await waitForTransportState(page, 'Relay', 8000);
  await page.screenshot({ path: join(output, 'browser-relay-fallback.png') });

  await page.evaluate(() => {
    window.writeResult = window.__DSH_TRANSPORT__.fetch('/api/plugin-route-unknown-write', { method: 'POST', body: 'fixture' })
      .then(() => 'completed', (error) => error.message);
  });
  await waitUntil(() => acceptedWrites === 1);
  bridge.stop();
  bridge = await fromHost();
  assert.match(await page.evaluate(() => window.writeResult), /结果未知/u);
  await waitUntil(() => [...bridge.sessions.keys()].some((generation) => generation !== initialGeneration));
  assert.equal(acceptedWrites, 1);
  console.log('New ECDH generation: accepted write count stayed at 1 after the original result was lost');

  const warmCount = warm.resources;
  const corruptedKey = await page.evaluate(() => new Promise((resolve, reject) => {
    const request = indexedDB.open('dsh-remote-assets-v1', 2);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('assets', 'readwrite');
      let key;
      tx.oncomplete = () => { db.close(); resolve(key); };
      const cursor = tx.objectStore('assets').openCursor();
      cursor.onsuccess = () => {
        const row = cursor.result;
        if (!row) return;
        if (row.primaryKey[2].startsWith('core:assets/index-') && !row.primaryKey[2].endsWith('.css')) {
          key = row.primaryKey[2];
          const changed = row.value;
          changed.bytes[0] ^= 0xff;
          row.update(changed);
        } else row.continue();
      };
    };
  }));
  assert.ok(corruptedKey);
  await page.reload();
  await waitForWorkbench(page);
  const corruptedAssetDownloads = marks.paths.filter((key) => key === corruptedKey).length;
  assert.equal(corruptedAssetDownloads, 1);
  await waitForTransportState(page, 'P2P', 10000);
  for (const denied of [401, 403]) {
    await waitForTransportState(page, 'P2P', 10000);
    deny = denied;
    await input.waitFor({ timeout: 12000 });
    assert.equal(await page.evaluate((key) => localStorage.getItem(key), keyName), null);
    await page.screenshot({ path: join(output, 'browser-revoked-' + denied + '.png') });
    deny = 0;
    await input.fill(pairingKey);
    await page.locator('#dsh-remote-e2ee-submit').click();
    await waitForWorkbench(page);
  }

  enablePlugin = true;
  await page.reload();
  await page.locator('#fixture-plugin').waitFor({ timeout: 40000 });
  assert.equal(await page.evaluate(() => window.pluginRouteFixture.run()), 'late success');
  await page.waitForFunction(() => document.querySelector('#fixture-plugin img')?.naturalWidth === 36);
  const resourceChecks = await page.evaluate(async () => {
    const fonts = Array.from(document.fonts).filter((row) => /KaTeX_Main/u.test(row.family));
    await document.fonts.load('16px KaTeX_Main');
    const wasm = globalThis.__DSH_TRANSPORT__.resolveAsset('plugins/plugin-route-browser-fixture/assets/probe.wasm');
    const response = await fetch(wasm);
    const length = Number(response.headers.get('content-length'));
    await WebAssembly.instantiateStreaming(response);
    const worker = new Worker(URL.createObjectURL(new Blob(['postMessage("worker ready")'], { type: 'text/javascript' })));
    try {
      await new Promise((resolve, reject) => {
        worker.onmessage = (event) => event.data === 'worker ready' ? resolve() : reject(event.data);
        worker.onerror = reject;
      });
    } finally {
      worker.terminate();
    }
    return { katexFonts: fonts.length, loaded: fonts.some((font) => font.status === 'loaded'), wasmBytes: length };
  });
  assert.ok(resourceChecks.katexFonts);
  assert.equal(resourceChecks.loaded, true);
  assert.equal(resourceChecks.wasmBytes, 8);
  const languages = bridge.frontend.snapshot.manifest.resources
    .filter((entry) => /^core:assets\/langs\/(ruby|vue)-/u.test(entry.key)).map((entry) => entry.key);
  const vendor = bridge.frontend.snapshot.manifest.resources.find((entry) => /^core:assets\/vendor-.*\.js$/u.test(entry.key)).key;
  const grammars = await page.evaluate(async ({ keys, vendor }) => {
    const lib = await globalThis.__DSH_IMPORT_CORE__(vendor);
    const modules = await Promise.all(keys.map((key) => globalThis.__DSH_IMPORT_CORE__(key)));
    const theme = lib.c({ name: 'css-variables', variablePrefix: '--shiki-', fontStyle: true });
    const engine = lib.a({ forgiving: true, regexConstructor: (regex) => lib.o(regex, { lazyCompileLength: Infinity }) });
    const highlighter = lib.b({ themes: [theme], langs: modules.map((item) => item.default), engine });
    const block = document.createElement('aside');
    block.setAttribute('aria-label', 'DSH render fixture');
    block.style.cssText = 'position:fixed;top:65px;right:16px;width:350px;background:#fff;color:#111;border:1px solid #888;padding:12px;z-index:10001;--shiki-foreground:#203030;--shiki-token-keyword:#a00050;--shiki-token-string:#167032;--shiki-token-constant:#264ab5';
    const examples = new Map([['ruby', ['def hello(name)', '  puts "Hello #{name}"', 'end'].join(String.fromCharCode(10))],
      ['vue', '<template><p>{{ greeting }}</p></template>']]);
    const result = [];
    for (const [lang, code] of examples) {
      const rendered = highlighter.codeToHtml(code, { lang, theme: 'css-variables' });
      const label = document.createElement('strong');
      label.textContent = lang;
      block.append(label);
      const wrapper = document.createElement('div');
      wrapper.innerHTML = rendered;
      block.append(wrapper);
      result.push(wrapper.querySelectorAll('.line span[style]').length);
    }
    const math = document.createElement('div');
    lib.k.render(String.raw`\int_0^1 x^2\,dx=\frac{1}{3}`, math);
    block.append(math);
    document.body.append(block);
    await document.fonts.ready;
    if (!math.querySelector('.katex')) throw new Error('KaTeX did not render');
    highlighter.dispose();
    return result;
  }, { keys: languages, vendor });
  assert.equal(grammars.length, 2);
  assert.ok(grammars.every((items) => items > 3));
  await page.screenshot({ path: join(output, 'browser-dynamic-resources.png') });
  enablePlugin = false;
  await page.reload();
  await waitForWorkbench(page);
  assert.equal(await page.locator('#fixture-plugin').count(), 0);

  await page.evaluate(() => globalThis.__DSH_REMOTE_SHELL__.lockAndForget());
  await input.waitFor({ timeout: 12000 });
  assert.equal(await page.evaluate((key) => localStorage.getItem(key), keyName), null);
  await page.screenshot({ path: join(output, 'browser-forgot-key.png') });

  truncate = true;
  await input.fill(pairingKey);
  await page.locator('#dsh-remote-e2ee-submit').click();
  await page.getByRole('heading', { name: 'DSH 远程工作台无法启动' }).waitFor({ timeout: 30000 });
  assert.equal(await page.locator('#fixture-plugin').count(), 0);
  assert.equal(await page.locator('#root').count(), 0);
  await page.screenshot({ path: join(output, 'browser-truncated-gzip.png') });
  truncate = false;
  const ephemeral = await browser.newContext({ viewport: { width: 1280, height: 850 }, ignoreHTTPSErrors: true });
  await ephemeral.addInitScript(() => {
    Object.defineProperty(globalThis, 'indexedDB', { value: undefined });
    Object.defineProperty(globalThis, 'DecompressionStream', { value: undefined });
  });
  const memory = await ephemeral.newPage();
  await memory.goto(appURL);
  await memory.locator('#dsh-remote-e2ee-key-input').fill(pairingKey);
  await memory.locator('#dsh-remote-e2ee-submit').click();
  await waitForWorkbench(memory);
  await memory.screenshot({ path: join(output, 'browser-memory-identity.png') });
  await ephemeral.close();
  shortLease = true;
  deny = 503;
  bridge.stop();
  bridge = await fromHost(6500);
  const expiry = await browser.newContext({ viewport: { width: 1280, height: 850 }, ignoreHTTPSErrors: true });
  const expiring = await expiry.newPage();
  await expiring.goto(appURL);
  await expiring.locator('#dsh-remote-e2ee-key-input').fill(pairingKey);
  await expiring.locator('#dsh-remote-e2ee-submit').click();
  await waitForTransportState(expiring, 'P2P', 10000);
  await waitForTransportState(expiring, '远程会话已结束', 10000);
  await waitUntil(() => bridge.sessions.size === 0);
  await expiring.screenshot({ path: join(output, 'browser-lease-expired.png') });
  await expiry.close();
  console.log('Hard lease cut-off: active P2P expired after renewal failures on browser and host');
  Object.assign(sessions, { warmResources: warmCount, unknownWrites: acceptedWrites, resourceChecks, grammars, deniedStatuses: [401, 403], memoryIdentityFallback: true, hardExpiryMs: 6500 });
  assert.deepEqual(errors, []);
  assert.ok(cold.originalCompressible > 0);
  const { paths: coldPaths, ...coldStats } = cold;
  const { paths: warmPaths, ...warmStats } = warm;
  const metrics = { shellBytes: shell.totalBytes, cold: coldStats, warm: warmStats, transforms,
    corruptedAssetDownloads,
    compressionReduction: 1 - cold.compressed / cold.originalCompressible, browser: browser.version(), sessions };
  console.log(JSON.stringify(metrics));
  await writeFile(join(output, 'browser-metrics.json'), JSON.stringify(metrics, null, 2) + '\n');
} finally {
  await browser?.close();
  bridge?.stop();
  for (const socket of sockets) socket.destroy();
  http.close();
  secure?.close();
  if (relay?.pid && relay.exitCode === null) { relay.kill(); await once(relay, 'exit'); }
  if (dsh?.pid && dsh.exitCode === null) { dsh.kill(); await once(dsh, 'exit'); }
  await rm(scratch, { force: true, recursive: true });
}
