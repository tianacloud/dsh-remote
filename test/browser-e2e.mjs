#!/usr/bin/env node
/**
 * Full real Playwright Chromium E2E acceptance suite for `@tianacloud/dsh-remote`.
 *
 * Covers:
 *  1. OnboardingWizard (`paired === false`) + `host_online` live transition to UnlockScreen (zero reload)
 *  2. UnlockScreen: default-checked remember key (`localStorage`), unchecked memory-only (no localStorage/sessionStorage),
 *     live input/paste trim & format validation
 *  3. Multi-tab synchronous lock (`BroadcastChannel` + `storage`): Tab 1 locks -> Tab 2 clears memory/storage & returns
 *     to UnlockScreen with zero reload loop
 *  4. Service Worker cross-window isolation (503 for unbound tab), CDP `ServiceWorker.stopAllWorkers` cold `<iframe>`
 *     navigation (200 + sandbox CSP) & Dedicated `new Worker(blobUrl)` (with immediate `URL.revokeObjectURL`) same-origin
 *     `fetch` (200), plus idle port-loss self-healing (`dsh-remote:sw-request-port`)
 *  5. `<img>` 302 redirect & document-relative `<img>` (`naturalWidth > 0`)
 *  6. Real `>= 34 MiB` ffmpeg-generated streamable MP4 in `<video muted playsInline>` (`play()`, `readyState >= 2`,
 *     Range 206, `currentTime` seek triggering 206 + upstream abort, `pause()`)
 *  7. Real `<a download="artifact.bin">` click via Playwright `waitForEvent('download')` + SHA-256 verification
 *  8. Malicious HTML & SVG CSP sandbox isolation (preserves stricter upstream CSP, strips `allow-same-origin`, `nosniff`, `no-store`, `SecurityError`)
 *  9. `EventSource` (named events, `Last-Event-ID`, `close()` mid-chunk) + `__DSH_FILE_UPLOAD__.fetch`
 * 10. Local sidebar panel (real scannable QR SVG, token expiry & renew, rebind UI, 4s poll draft protection) vs Remote sidebar + 403 admin block
 * 11. HostOffline screen + 800ms reconnect capsule appearance & recovery auto-hide
 * 12. Narrow mobile viewport (375x812) check
 * 13. No-SW Option A dismissible banner
 * 14. Live online page rebind (`workstation-r2` -> `workstation-r2-new`) updating `getSnapshot().hostId` & dialing new host
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { connect } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createHostController } from '../host-main.js';
import { buildWebDist } from '../scripts/build-web-dist.mjs';
import { HostBridge } from '../src/host-bridge.js';
import { registerWebServerRoutes } from '../src/remote-api.js';
import { generateE2eeSecret, saveRemoteState } from '../src/state.js';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUTPUT_DIR = resolve(process.env.OUTPUT_DIR || process.argv[2] || join(tmpdir(), 'dsh-remote-browser-e2e'));

function loadPlaywright() {
  const candidates = [
    process.env.DSH_REMOTE_TEST_PLAYWRIGHT,
    'playwright',
    join(homedir(), '.local', 'lib', 'node_modules', 'playwright'),
    '/usr/local/lib/node_modules/playwright',
  ].filter(Boolean);
  const req = createRequire(import.meta.url);
  for (const id of candidates) {
    try {
      return req(id);
    } catch {
      // try next
    }
  }
  throw new Error('Playwright module not found; set DSH_REMOTE_TEST_PLAYWRIGHT');
}

function findChromiumExecutable() {
  const cacheDir = join(homedir(), '.cache', 'ms-playwright');
  const globs = [
    join(cacheDir, 'chromium-1243', 'chrome-linux64', 'chrome'),
    join(cacheDir, 'chromium-1243', 'chrome-linux', 'chrome'),
    join(cacheDir, 'chromium-1179', 'chrome-linux', 'chrome'),
    join(cacheDir, 'chromium-1124', 'chrome-linux', 'chrome'),
    join(cacheDir, 'chromium-1091', 'chrome-linux', 'chrome'),
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
  ];
  for (const p of globs) {
    if (existsSync(p)) return p;
  }
  return undefined;
}

// 2x2 valid PNG
const VALID_PNG = Buffer.from(
  '89504e470d0a1a0a0000000d494844520000000200000002080600000072b60d240000001449444154789c6364c00f00000000ffff0300000800051f82c0170000000049454e44ae426082',
  'hex',
);

const DOWNLOAD_PAYLOAD = Buffer.alloc(256 * 1024);
for (let i = 0; i < DOWNLOAD_PAYLOAD.length; i += 1) {
  DOWNLOAD_PAYLOAD[i] = (i * 31 + 17) & 0xff;
}
const DOWNLOAD_EXPECTED_SHA256 = createHash('sha256').update(DOWNLOAD_PAYLOAD).digest('hex');

async function freePort() {
  const s = createServer().listen(0, '127.0.0.1');
  await once(s, 'listening');
  const p = s.address().port;
  s.close();
  return p;
}

const { chromium } = loadPlaywright();
// Clean output dir before writing fresh screenshots & summary
await rm(OUTPUT_DIR, { recursive: true, force: true });
await mkdir(OUTPUT_DIR, { recursive: true });
const scratch = await mkdtemp(join(tmpdir(), 'dsh-remote-e2e-'));

// Generate a real >= 34 MiB streamable H.264 MP4 via /usr/bin/ffmpeg (1 keyframe/sec, 20s @ 16Mbps -> ~40 MiB)
const videoFile = join(scratch, 'streamable-34m.mp4');
execFileSync('/usr/bin/ffmpeg', [
  '-v', 'error', '-y',
  '-f', 'lavfi', '-i', 'testsrc2=size=640x360:rate=30',
  '-t', '20',
  '-c:v', 'libx264', '-preset', 'ultrafast', '-pix_fmt', 'yuv420p',
  '-g', '30', '-keyint_min', '30', '-sc_threshold', '0',
  '-b:v', '16M', '-minrate', '16M', '-maxrate', '16M', '-bufsize', '32M',
  '-x264-params', 'nal-hrd=cbr:filler=1',
  '-movflags', '+faststart',
  videoFile,
], { stdio: 'pipe' });
const VIDEO_TOTAL_BYTES = statSync(videoFile).size;
assert.ok(VIDEO_TOTAL_BYTES >= 34 * 1024 * 1024, `Expected >= 34 MiB MP4, got ${VIDEO_TOTAL_BYTES} bytes`);

const target = {
  hostId: 'workstation-r2',
  hostName: 'Neon-Workstation-R2',
  webId: 'e2eround2001',
  ownerUserId: 'usr-e2e-owner',
  ownerTenantId: 'ten-e2e-owner',
};
const registrationKey = generateE2eeSecret();
const pairingKey = generateE2eeSecret();
const appBase = `/web/${target.webId}/`;
const storageKey = `dsh-remote:v2:key:${target.webId}:${target.ownerUserId}:${target.hostId}`;

const webRoot = join(scratch, 'web');
const fakeFrontendDir = join(scratch, 'dsh-web-frontend');
await mkdir(join(fakeFrontendDir, 'dist', 'assets'), { recursive: true });
await writeFile(
  join(fakeFrontendDir, 'dist', 'index.html'),
  '<!doctype html><link rel="stylesheet" href="./assets/app.css"><script type="module" src="./assets/index.js"></script>',
);
await writeFile(
  join(fakeFrontendDir, 'dist', 'assets', 'app.css'),
  'body { margin: 0; font-family: system-ui, sans-serif; }',
);
await writeFile(
  join(fakeFrontendDir, 'dist', 'assets', 'index.js'),
  `
const __eval = new Function("ctx","expr",\`return eval(expr)\`);
const __preload=function(load,deps){let p=Promise.resolve();if(deps){new Event("vite:preloadError")}return p.then(()=>{return load().catch(err)})};
const root = document.getElementById('root') || document.body;
root.innerHTML = \`
  <div id="e2e-workbench" style="padding:20px;font-family:system-ui,sans-serif;max-width:960px;margin:0 auto;">
    <h1 style="margin:0 0 12px;font-size:20px;">DSH Remote E2EE Workbench</h1>
    <div id="e2e-media-grid" style="display:grid;grid-template-columns:1fr 1fr;gap:14px;">
      <div style="padding:12px;border:1px solid #cbd5e1;border-radius:10px;">
        <strong>Subresources (SW Streaming)</strong>
        <div style="display:flex;gap:12px;align-items:center;margin-top:8px;">
          <img id="test-img-302" src="api/file?path=pic.png" width="32" height="32" alt="302 img" />
          <img id="test-img-rel" src="api/dsh-remotion/thumb.png" width="32" height="32" alt="rel img" />
          <a id="test-download-link" href="/api/download/artifact.bin" download="artifact.bin" style="font-size:12px;">Download artifact.bin</a>
        </div>
        <div id="e2e-video-status" style="margin-top:8px;font-size:12px;">video: pending</div>
        <video id="test-video" preload="metadata" muted playsinline style="width:100%;max-height:110px;background:#0f172a;border-radius:6px;"></video>
      </div>
      <div style="padding:12px;border:1px solid #cbd5e1;border-radius:10px;">
        <strong>SSE &amp; Upload &amp; CSP Sandbox</strong>
        <div id="e2e-sse-status" style="margin-top:6px;font-size:12px;">sse: pending</div>
        <div id="e2e-upload-status" style="margin-top:6px;font-size:12px;">upload: pending</div>
        <div id="e2e-csp-status" style="margin-top:6px;font-size:12px;">csp: pending</div>
        <iframe id="test-malicious-frame" style="width:100%;height:42px;border:1px solid #94a3b8;border-radius:6px;margin-top:6px;"></iframe>
      </div>
    </div>
    <div id="e2e-remote-sidebar-host" style="margin-top:16px;"></div>
  </div>
\`;
window.__E2E_WORKBENCH_READY__ = true;
void __eval; void __preload;
`,
);

// Build real .tweb shell (defaultHostId empty -> tests zero-recompile onboarding!)
const builtWeb = buildWebDist({
  outDir: webRoot,
  config: {
    functionId: 'fn-e2e-relay',
    webId: target.webId,
    defaultHostId: '',
    appTitle: 'DSH Remote E2E',
  },
});

const policyFile = join(scratch, 'function-config.json');
await writeFile(policyFile, '{}\n', { mode: 0o600 });

const relayBin = join(scratch, 'relay');
execFileSync('go', ['build', '-buildvcs=false', '-o', relayBin, '.'], {
  cwd: join(PROJECT_ROOT, 'relay-go'),
  stdio: 'pipe',
});
const relayPort = await freePort();
const relayProc = spawn(relayBin, [], {
  env: {
    ...process.env,
    PORT: String(relayPort),
    FUNCTION_CONFIG_FILE: policyFile,
  },
  stdio: 'ignore',
});

const statePath = join(scratch, 'state.json');
const runtimePath = join(scratch, 'runtime.json');
let tokenExpiresAt = Math.floor(Date.now() / 1000) + 14 * 86400;
let tokenRenewCount = 0;

saveRemoteState({
  version: 2,
  configVersion: 2,
  enabled: true,
  updatedAt: new Date().toISOString(),
  owner: { userId: target.ownerUserId, tenantId: target.ownerTenantId, email: 'owner@example.test', spaceName: 'E2E Space' },
  host: { hostId: target.hostId, hostName: target.hostName, registrationKey },
  e2ee: { algorithm: 'x25519-chacha20poly1305-v1', secret: pairingKey, fingerprint: 'aa11:bb22:cc33' },
  function: { id: 'fn-e2e-relay', name: 'DSH Remote Relay', url: `http://127.0.0.1:${relayPort}`, token: 'tok-e2e', expiresAt: tokenExpiresAt },
  web: { id: target.webId, name: 'DSH Remote', endpoint: `https://${target.webId}.example.test${appBase}` },
  network: { p2pEnabled: false, stunUrls: ['stun:stun.cloudflare.com:3478'] },
}, statePath);

let videoAbortedCount = 0;
let videoRangeHits = 0;
let videoRangesSeen = [];
let sseHits = 0;
let uploadedBytes = 0;

const registeredNodeRoutes = [];
const mockWebServer = {
  register(route) {
    registeredNodeRoutes.push(route);
    return () => {};
  },
};
const mockConnection = {
  requestRejection(req) {
    const cookie = String(req.headers?.cookie || '');
    if (cookie.includes('dsh_web=e2e-owner-ok')) return undefined;
    return 401;
  },
};

const hostController = createHostController({
  statePath,
  runtimePath,
  log: () => {},
});
hostController.renewHostToken = async () => {
  tokenRenewCount += 1;
  tokenExpiresAt = Math.floor(Date.now() / 1000) + 30 * 86400;
  const st = JSON.parse(await readFile(statePath, 'utf8'));
  st.function.expiresAt = tokenExpiresAt;
  saveRemoteState(st, statePath);
  return { expiresAt: tokenExpiresAt, tokenId: `tok-renewed-${tokenRenewCount}` };
};
registerWebServerRoutes(mockWebServer, mockConnection, hostController);

let localDshPort = 0;
const localDshServer = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (url.pathname === '/' && url.searchParams.get('token') === 'e2e-launch') {
    res.writeHead(303, { 'set-cookie': 'dsh_web=e2e-owner-ok; Path=/; HttpOnly' });
    res.end();
    return;
  }
  if (url.pathname === '/local-sidebar-test') {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'set-cookie': 'dsh_web=e2e-owner-ok; Path=/; HttpOnly',
    });
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>Local Sidebar Test</title></head>
      <body style="margin:0;background:#0f172a;color:#f8fafc;">
        <div id="local-panel-root"></div>
        <script src="/__test_react.js"></script>
        <script src="/__test_client.js"></script>
        <script>
          const mod = globalThis.__DSH_REMOTE_CLIENT_FACTORY__((id) => id === 'react' ? globalThis.MiniReact : {});
          globalThis.MiniReact.mount(mod.TianaRemotePanel, { forceMode: 'local' }, document.getElementById('local-panel-root'));
        </script>
      </body></html>`);
    return;
  }
  if (url.pathname === '/__test_client.js') {
    res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    res.end(await readFile(join(PROJECT_ROOT, 'client.js')));
    return;
  }
  if (url.pathname === '/__test_react.js') {
    res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    res.end(MINI_REACT_SHIM);
    return;
  }
  if (url.pathname === '/api/worker-module.mjs' || url.pathname === '/api/worker-classic.js') {
    res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    res.end("fetch(self.location.origin + '/api/dsh-remotion/thumb.png').then(r=>postMessage({status:r.status}), e=>postMessage({error:e.message}));");
    return;
  }

  const routeMatch = registeredNodeRoutes.find((r) =>
    r.kind === 'exact' ? url.pathname === r.path : (url.pathname === r.path || url.pathname.startsWith(`${r.path}/`)),
  );
  if (routeMatch) {
    await routeMatch.handler(req, res);
    return;
  }

  if (url.pathname === '/api/file' && url.searchParams.get('path') === 'pic.png') {
    if (!url.searchParams.has('v')) {
      res.writeHead(302, { location: `http://127.0.0.1:${localDshPort}/api/file?path=pic.png&v=42` });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'image/png', 'content-length': String(VALID_PNG.byteLength) });
    res.end(VALID_PNG);
    return;
  }
  if (url.pathname === '/api/dsh-remotion/thumb.png') {
    res.writeHead(200, { 'content-type': 'image/png', 'content-length': String(VALID_PNG.byteLength) });
    res.end(VALID_PNG);
    return;
  }
  if (url.pathname === '/api/download/artifact.bin') {
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment; filename="artifact.bin"',
      'content-length': String(DOWNLOAD_PAYLOAD.byteLength),
    });
    res.end(DOWNLOAD_PAYLOAD);
    return;
  }
  if (url.pathname === '/api/big-video.mp4') {
    videoRangeHits += 1;
    const range = req.headers.range || 'bytes=0-';
    videoRangesSeen.push(range);
    const m = /^bytes=(\d+)-(\d*)$/u.exec(range);
    const start = m ? Number(m[1]) : 0;
    const end = m && m[2] ? Math.min(VIDEO_TOTAL_BYTES - 1, Number(m[2])) : VIDEO_TOTAL_BYTES - 1;
    const len = end - start + 1;
    res.on('close', () => {
      if (!res.writableEnded) videoAbortedCount += 1;
    });
    res.writeHead(206, {
      'content-type': 'video/mp4',
      'accept-ranges': 'bytes',
      'content-range': `bytes ${start}-${end}/${VIDEO_TOTAL_BYTES}`,
      'content-length': String(len),
    });
    const stream = createReadStream(videoFile, { start, end, highWaterMark: 64 * 1024 });
    let streamedBytes = 0;
    let paceTimer = null;
    const burstBytes = start === 0 ? 2 * 1024 * 1024 : 3 * 1024 * 1024;
    stream.on('data', (chunk) => {
      if (res.destroyed) { stream.destroy(); return; }
      streamedBytes += chunk.byteLength;
      const ok = res.write(chunk);
      if (streamedBytes >= burstBytes) {
        stream.pause();
        paceTimer = setTimeout(() => {
          paceTimer = null;
          if (!res.destroyed) stream.resume();
        }, 80);
      } else if (!ok) {
        stream.pause();
        res.once('drain', () => { if (!res.destroyed) stream.resume(); });
      }
    });
    stream.on('end', () => { if (!res.destroyed) res.end(); });
    stream.on('error', () => { if (!res.destroyed) res.destroy(); });
    res.on('close', () => {
      clearTimeout(paceTimer);
      stream.destroy();
    });
    return;
  }
  if (url.pathname === '/api/malicious.html') {
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': "default-src 'none'; img-src 'none'; script-src 'unsafe-inline'",
    });
    res.end(`<!doctype html><html><body><script>
      try {
        localStorage.getItem('probe');
        parent.postMessage({ type: 'csp-probe', leaked: true }, '*');
      } catch (err) {
        parent.postMessage({ type: 'csp-probe', blocked: err.name || 'SecurityError', origin: location.origin }, '*');
      }
    </script></body></html>`);
    return;
  }
  if (url.pathname === '/api/malicious.svg') {
    res.writeHead(200, {
      'content-type': 'image/svg+xml',
      'content-security-policy': "default-src 'none'",
    });
    res.end('<svg xmlns="http://www.w3.org/2000/svg"><script>window.__SVG_XSS__=true</script><rect width="10" height="10"/></svg>');
    return;
  }
  if (url.pathname === '/api/sse-e2e') {
    sseHits += 1;
    res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache' });
    res.flushHeaders();
    if (sseHits === 1) {
      res.write('retry: 30\nid: e1\nevent: status\ndata: hello-sse\n\n');
      setTimeout(() => res.end(), 25);
    } else {
      res.write(`id: e2\ndata: resumed:${req.headers['last-event-id'] || ''}\n\ndata: after-close-must-not-fire\n\n`);
      setTimeout(() => res.end(), 50);
    }
    return;
  }
  if (url.pathname === '/api/session/uploadFileBinary' && req.method === 'POST') {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    uploadedBytes = Buffer.concat(chunks).byteLength;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, bytes: uploadedBytes }));
    return;
  }
  res.writeHead(404).end();
});

const MINI_REACT_SHIM = `
(function(){
  let rootComp = null, rootProps = null, rootContainer = null;
  let hooks = [], hookIdx = 0, pendingEffects = [];
  function renderNow() {
    if (!rootComp || !rootContainer) return;
    hookIdx = 0;
    pendingEffects = [];
    const active = document.activeElement;
    const activeId = active && active.id;
    const selStart = active && typeof active.selectionStart === 'number' ? active.selectionStart : null;
    const vnode = rootComp(rootProps || {});
    const frag = document.createDocumentFragment();
    mountNode(vnode, frag);
    rootContainer.replaceChildren(frag);
    if (activeId) {
      const el = document.getElementById(activeId);
      if (el && el.focus) {
        el.focus();
        if (selStart !== null && el.setSelectionRange) { try { el.setSelectionRange(selStart, selStart); } catch {} }
      }
    }
    const effs = pendingEffects.slice();
    pendingEffects = [];
    for (const fn of effs) fn();
  }
  function mountNode(vnode, parent) {
    if (vnode === null || vnode === undefined || typeof vnode === 'boolean') return;
    if (typeof vnode === 'string' || typeof vnode === 'number') {
      parent.appendChild(document.createTextNode(String(vnode)));
      return;
    }
    if (Array.isArray(vnode)) { for (const c of vnode) mountNode(c, parent); return; }
    const isSvg = vnode.type === 'svg' || parent instanceof SVGElement;
    const el = isSvg ? document.createElementNS('http://www.w3.org/2000/svg', vnode.type) : document.createElement(vnode.type);
    const props = vnode.props || {};
    for (const [k, v] of Object.entries(props)) {
      if (k === 'children' || k === 'key') continue;
      if (k === 'ref' && v && typeof v === 'object') { v.current = el; continue; }
      if (k === 'className') { el.setAttribute('class', v); continue; }
      if (k === 'style' && v && typeof v === 'object') { Object.assign(el.style, v); continue; }
      if (k === 'checked') { el.checked = Boolean(v); continue; }
      if (k === 'value') { el.value = v ?? ''; continue; }
      if (k === 'disabled') { el.disabled = Boolean(v); continue; }
      if (k.startsWith('on') && typeof v === 'function') {
        const evName = k === 'onChange' ? (vnode.type === 'input' && props.type !== 'checkbox' ? 'input' : 'change') : k.slice(2).toLowerCase();
        el.addEventListener(evName, v);
        continue;
      }
      if (v !== false && v !== undefined && v !== null) el.setAttribute(k, v === true ? '' : String(v));
    }
    const children = props.children;
    if (Array.isArray(children)) { for (const c of children) mountNode(c, el); }
    else if (children !== undefined) mountNode(children, el);
    parent.appendChild(el);
  }
  globalThis.MiniReact = {
    createElement(type, props, ...children) {
      return { type, props: { ...(props || {}), children: children.length <= 1 ? children[0] : children } };
    },
    useState(init) {
      const i = hookIdx++;
      if (!(i in hooks)) hooks[i] = typeof init === 'function' ? init() : init;
      const setState = (next) => {
        const val = typeof next === 'function' ? next(hooks[i]) : next;
        if (val !== hooks[i]) { hooks[i] = val; queueMicrotask(renderNow); }
      };
      return [hooks[i], setState];
    },
    useRef(init) {
      const i = hookIdx++;
      if (!(i in hooks)) hooks[i] = { current: init };
      return hooks[i];
    },
    useCallback(fn) { return fn; },
    useEffect(fn, deps) {
      const i = hookIdx++;
      const prev = hooks[i];
      const changed = !prev || !deps || deps.some((d, idx) => d !== prev.deps[idx]);
      if (changed) {
        hooks[i] = { deps: deps ? deps.slice() : null, cleanup: prev?.cleanup };
        pendingEffects.push(() => {
          try { prev?.cleanup?.(); } catch {}
          const c = fn();
          if (typeof c === 'function') hooks[i].cleanup = c;
        });
      }
    },
    mount(comp, props, container) {
      hooks = [];
      rootComp = comp;
      rootProps = props;
      rootContainer = container;
      renderNow();
    },
  };
})();
`;

await new Promise((r) => localDshServer.listen(0, '127.0.0.1', r));
localDshPort = localDshServer.address().port;

const sockets = new Set();
const appServer = createServer(async (req, res) => {
  const parsed = new URL(req.url, 'http://127.0.0.1');
  const pathname = parsed.pathname;
  const routed = pathname.startsWith(appBase) ? '/' + pathname.slice(appBase.length) : pathname;
  const assetPath = routed.startsWith('/assets/') ? routed.slice('/assets'.length) : routed;

  if (routed === '/' || routed === '') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DSH Remote E2E</title><div id="app"></div><script type="module" src="assets/startup.mjs"></script>`);
    return;
  }
  if (routed === '/assets/startup.mjs') {
    res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
    res.end(`
      globalThis.tiana = {
        appId: ${JSON.stringify(target.webId)},
        functions: {
          websocket: (_, path) => new Promise((ok, fail) => {
            const s = new WebSocket(new URL(path, location));
            s.onopen = () => ok(s);
            s.onerror = fail;
          }),
          fetch: (_, path, init) => fetch('/__relay_proxy' + path, init),
        },
      };
      const { mount } = await import('./dsh-remote-entry.mjs');
      mount(document.getElementById('app'), globalThis.tiana);
    `);
    return;
  }
  if (pathname === '/favicon.ico') {
    res.writeHead(204).end();
    return;
  }
  if (routed === '/_tiana/session') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      status: 'SESSION_ACTIVE',
      web_id: target.webId,
      app_tenant_id: target.ownerTenantId,
      tenant_id: target.ownerTenantId,
      is_app_owner: true,
      user: { user_id: target.ownerUserId },
    }));
    return;
  }
  if (pathname.startsWith('/__relay_proxy/')) {
    const relayPath = pathname.slice('/__relay_proxy'.length) + parsed.search;
    const resp = await fetch(`http://127.0.0.1:${relayPort}${relayPath}`, {
      headers: {
        'Tiana-Caller-User-Id': target.ownerUserId,
        'Tiana-Caller-Tenant-Id': target.ownerTenantId,
        'Tiana-Caller-App-Owner-Id': target.ownerUserId,
        'Tiana-Caller-Web-Id': target.webId,
      },
    });
    res.writeHead(resp.status, { 'content-type': resp.headers.get('content-type') || 'application/json' });
    res.end(Buffer.from(await resp.arrayBuffer()));
    return;
  }
  if (/^\/[A-Za-z0-9_.-]+\.(mjs|js|json|svg)$/u.test(assetPath)) {
    const ext = assetPath.split('.').at(-1);
    const mime = { js: 'text/javascript', mjs: 'text/javascript', json: 'application/json', svg: 'image/svg+xml' }[ext];
    const headers = { 'content-type': mime, 'cache-control': 'no-store' };
    if (assetPath === '/dsh-remote-sw.js') {
      headers['service-worker-allowed'] = appBase;
    }
    try {
      const content = await readFile(join(webRoot, assetPath));
      res.writeHead(200, headers);
      res.end(content);
    } catch {
      res.writeHead(404).end();
    }
    return;
  }
  res.writeHead(404).end();
});

let appOrigin = '';
appServer.on('upgrade', (request, socket, head) => {
  sockets.add(socket);
  socket.once('close', () => sockets.delete(socket));
  const upstream = connect(relayPort, '127.0.0.1', () => {
    upstream.write(`GET ${request.url} HTTP/1.1\r\n` + [
      `Host: 127.0.0.1:${relayPort}`,
      `Origin: ${appOrigin}`,
      `Tiana-Caller-User-Id: ${target.ownerUserId}`,
      `Tiana-Caller-Tenant-Id: ${target.ownerTenantId}`,
      `Tiana-Caller-App-Owner-Id: ${target.ownerUserId}`,
      `Tiana-Caller-Web-Id: ${target.webId}`,
      ...['connection', 'upgrade', 'sec-websocket-key', 'sec-websocket-version'].map((k) => `${k}: ${request.headers[k]}`),
      '', '',
    ].join('\r\n'));
    if (head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.on('close', () => upstream.destroy());
});

await new Promise((r) => appServer.listen(0, '127.0.0.1', r));
appOrigin = `http://127.0.0.1:${appServer.address().port}`;
const appUrl = `${appOrigin}${appBase}`;

for (let i = 0; i < 40; i += 1) {
  if (await fetch(`http://127.0.0.1:${relayPort}/health`).then((r) => r.ok).catch(() => false)) break;
  await delay(50);
}

let bridge = null;
let browser = null;
const results = {};

async function startHostBridge() {
  const b = new HostBridge({
    relayUrl: `http://127.0.0.1:${relayPort}`,
    e2eeSecret: pairingKey,
    hostId: target.hostId,
    hostName: target.hostName,
    registrationKey,
    localOrigin: `http://127.0.0.1:${localDshPort}`,
    getLaunchToken: () => 'e2e-launch',
    allowInsecureLoopback: true,
    ownerUserId: target.ownerUserId,
    ownerTenantId: target.ownerTenantId,
    webId: target.webId,
    p2p: 'off',
    frontendOptions: { frontend: fakeFrontendDir },
    collectIndexInjections: async () => [
      { kind: 'global', name: '__DSH_BOOT__', value: { entries: [], batches: [], release: { version: 'e2e' }, rev: 'e2e' } },
    ],
    log: () => {},
  });
  await b.start();
  return b;
}

try {
  const executablePath = findChromiumExecutable();
  browser = await chromium.launch({
    headless: true,
    ...(executablePath ? { executablePath } : {}),
  });

  const context = await browser.newContext({ viewport: { width: 1280, height: 860 }, acceptDownloads: true });
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('[browser console error]', m.text());
  });

  // ---- 1. OnboardingWizard (`paired === false`) + live `host_online` transition ----
  await page.goto(appUrl);
  await page.locator('#dsh-remote-shell[data-state="onboarding"]').waitFor({ timeout: 10000 });
  const onboardCmd = await page.locator('#dsh-remote-onboarding-cmd').textContent();
  assert.match(onboardCmd, new RegExp(`--app ${target.webId}`));
  await page.screenshot({ path: join(OUTPUT_DIR, '01-onboarding-wizard.png') });
  results.onboardingWizard = { ok: true, command: onboardCmd };

  const policyObj = {
    version: 1,
    webId: target.webId,
    origin: appOrigin,
    ownerUserId: target.ownerUserId,
    ownerTenantId: target.ownerTenantId,
    hostId: target.hostId,
    hostName: target.hostName,
    hostDigest: createHash('sha256').update(registrationKey).digest('hex'),
    updatedAt: new Date().toISOString(),
  };
  await delay(20);
  await writeFile(policyFile, JSON.stringify({
    DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(policyObj) },
  }), { mode: 0o600 });

  bridge = await startHostBridge();

  // ---- 2. UnlockScreen: default-checked remember, live validation, unchecked memory-only ----
  await page.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 10000 });
  const defaultChecked = await page.locator('#dsh-remote-remember-key').isChecked();
  assert.equal(defaultChecked, true, 'UnlockScreen remember checkbox must be checked by default');

  await page.locator('#dsh-remote-e2ee-key-input').fill('short-key');
  assert.equal(await page.locator('#dsh-remote-key-validation').getAttribute('data-valid'), 'false');
  await page.locator('#dsh-remote-e2ee-key-input').fill(`  dshk1_${pairingKey}  `);
  assert.equal(await page.locator('#dsh-remote-key-validation').getAttribute('data-valid'), 'true');
  assert.equal(await page.locator('#dsh-remote-e2ee-key-input').inputValue(), `dshk1_${pairingKey}`);
  await page.screenshot({ path: join(OUTPUT_DIR, '02-unlock-screen.png') });

  await page.locator('#dsh-remote-remember-key').uncheck();
  await page.locator('#dsh-remote-e2ee-submit').click();
  await page.waitForFunction(() => Boolean(window.__E2E_WORKBENCH_READY__), undefined, { timeout: 15000 });
  const memStorageCheck = await page.evaluate((k) => ({
    local: localStorage.getItem(k),
    session: sessionStorage.getItem(k),
    remembered: globalThis.__DSH_REMOTE_SHELL__.getStatusSnapshot().remembered,
  }), storageKey);
  assert.equal(memStorageCheck.local, null);
  assert.equal(memStorageCheck.session, null);
  assert.equal(memStorageCheck.remembered, false);
  results.unlockMemoryOnly = { ok: true, defaultRememberChecked: defaultChecked, ...memStorageCheck };

  // ---- 3. Multi-tab synchronous lock (BroadcastChannel + storage) & cross-window SW isolation ----
  const tab2 = await context.newPage();
  await tab2.goto(appUrl);
  await tab2.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 10000 });
  await tab2.locator('#dsh-remote-e2ee-key-input').fill(`dshk1_${pairingKey}`);
  await tab2.locator('#dsh-remote-e2ee-submit').click();
  await tab2.waitForFunction(() => Boolean(window.__E2E_WORKBENCH_READY__), undefined, { timeout: 15000 });
  assert.equal(await tab2.evaluate((k) => Boolean(localStorage.getItem(k)), storageKey), true);

  const tab3 = await context.newPage();
  await tab3.goto(appUrl);
  await page.evaluate(() => globalThis.__DSH_REMOTE_SHELL__.lockAndForget());
  await page.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 8000 });
  await tab2.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 8000 });
  const tab2Cleared = await tab2.evaluate((k) => ({
    local: localStorage.getItem(k),
    session: sessionStorage.getItem(k),
    state: document.querySelector('#dsh-remote-shell')?.dataset.state,
  }), storageKey);
  assert.equal(tab2Cleared.local, null);
  assert.equal(tab2Cleared.session, null);
  assert.equal(tab2Cleared.state, 'unlock');
  await tab2.close();
  results.multiTabSyncLock = { ok: true };

  await tab3.reload();
  await tab3.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 8000 });
  await page.locator('#dsh-remote-e2ee-key-input').fill(`dshk1_${pairingKey}`);
  await page.locator('#dsh-remote-e2ee-submit').click();
  await page.waitForFunction(() => Boolean(document.querySelector('#e2e-workbench')), undefined, { timeout: 15000 });
  assert.equal(await page.evaluate((k) => Boolean(localStorage.getItem(k)), storageKey), true);
  assert.equal(await page.evaluate((k) => sessionStorage.getItem(k), storageKey), null);

  const unboundFetchStatus = await tab3.evaluate(async (base) => {
    const r = await fetch(`${base}api/file?path=pic.png`);
    return r.status;
  }, appBase);
  assert.equal(unboundFetchStatus, 503, 'unbound tab must receive 503 and never borrow another tab SW port');
  await tab3.close();
  results.swCrossWindowIsolation = { ok: true, unboundTabStatus: unboundFetchStatus };

  // ---- 4. CDP ServiceWorker.stopAllWorkers: cold <iframe> (200 + sandbox CSP) & Dedicated Worker fetch (200) ----
  const cdp = await context.newCDPSession(page);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  const coldFramePromise = page.waitForResponse((res) => res.url().includes('probe=cold-iframe'), { timeout: 10000 });
  await page.evaluate((base) => {
    document.getElementById('test-malicious-frame').src = `${base}api/malicious.html?probe=cold-iframe`;
  }, appBase);
  const coldFrame = await coldFramePromise;
  const coldFrameCsp = (await coldFrame.allHeaders())['content-security-policy'] || '';
  assert.equal(coldFrame.status(), 200, 'cold iframe navigation after ServiceWorker.stopAllWorkers must return 200');
  assert.equal(coldFrame.fromServiceWorker(), true, 'cold iframe must be served via Service Worker');
  assert.ok(coldFrameCsp.includes('sandbox') && !coldFrameCsp.includes('allow-same-origin'), `cold iframe must have sandbox CSP: ${coldFrameCsp}`);

  // Also test Dedicated Worker right after another cold SW stop AND immediate URL.revokeObjectURL
  await cdp.send('ServiceWorker.stopAllWorkers');
  const workerFetchStatus = await page.evaluate(async (base) => {
    const workerUrl = URL.createObjectURL(new Blob([
      'onmessage = async ({data}) => { try { postMessage((await fetch(data)).status); } catch (err) { postMessage(err.message); } };',
    ], { type: 'text/javascript' }));
    const worker = new Worker(workerUrl);
    // Revoke caller blob URL immediately BEFORE worker fetches to verify synchronous wrapper safety
    URL.revokeObjectURL(workerUrl);
    try {
      return await new Promise((resolve) => {
        const timer = setTimeout(() => resolve('timed out'), 8000);
        worker.onmessage = ({ data }) => { clearTimeout(timer); resolve(data); };
        worker.onerror = (e) => { clearTimeout(timer); resolve(`worker-error:${e.message}`); };
        worker.postMessage(new URL(`${base}api/dsh-remotion/thumb.png?probe=dedicated-worker`, location.origin).href);
      });
    } finally {
      worker.terminate();
    }
  }, appBase);
  assert.equal(workerFetchStatus, 200, `Dedicated Worker same-origin fetch after cold SW stop must return 200, got ${workerFetchStatus}`);

  // 3-attempt x 8-parallel cold <iframe> navigations after CDP ServiceWorker.stopAllWorkers
  const parallelColdNav = [];
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await cdp.send('ServiceWorker.stopAllWorkers');
    const pending = Array.from({ length: 8 }, (_, i) =>
      page.waitForResponse((r) => r.url().includes(`cold-parallel=${attempt}-${i}&`), { timeout: 10000 }),
    );
    await page.evaluate(({ base, attempt: att }) => {
      for (let i = 0; i < 8; i += 1) {
        const f = document.createElement('iframe');
        f.className = 'cold-parallel-fixture';
        f.src = `${base}api/malicious.html?cold-parallel=${att}-${i}`;
        document.body.appendChild(f);
      }
    }, { base: appBase, attempt });
    const statuses = (await Promise.all(pending)).map((r) => r.status());
    assert.deepEqual(
      statuses,
      [200, 200, 200, 200, 200, 200, 200, 200],
      `Cold SW 8-parallel iframe attempt ${attempt} must return all 200s, got ${JSON.stringify(statuses)}`,
    );
    parallelColdNav.push(statuses);
    await page.evaluate(() => document.querySelectorAll('.cold-parallel-fixture').forEach((f) => f.remove()));
  }

  // Cold-SW classic and module URL `new Worker(...)` same-origin fetch checks
  const urlWorkers = {};
  for (const type of ['module', 'classic']) {
    await cdp.send('ServiceWorker.stopAllWorkers');
    urlWorkers[type] = await page.evaluate(({ base, type: workerType }) => new Promise((resolve) => {
      const worker = new Worker(`${base}api/worker-${workerType}${workerType === 'module' ? '.mjs' : '.js'}`, { type: workerType });
      const timer = setTimeout(() => { worker.terminate(); resolve({ error: 'timeout' }); }, 8000);
      const done = (result) => { clearTimeout(timer); worker.terminate(); resolve(result); };
      worker.onmessage = ({ data }) => done(data);
      worker.onerror = (e) => { e.preventDefault(); done({ workerError: e.message }); };
    }), { base: appBase, type });
    assert.equal(urlWorkers[type]?.status, 200, `Cold SW ${type} URL Worker must fetch 200, got ${JSON.stringify(urlWorkers[type])}`);
  }

  await cdp.detach();
  results.coldSwIframeAndDedicatedWorker = {
    ok: true,
    iframeStatus: coldFrame.status(),
    iframeViaServiceWorker: coldFrame.fromServiceWorker(),
    iframeCsp: coldFrameCsp,
    workerFetchStatus,
    parallelColdNav,
    urlWorkers,
  };

  // ---- 4b. SW Idle Port Loss -> Self-Healing Rebind Recovery (`dsh-remote:sw-request-port`) ----
  const swRebindOk = await page.evaluate(async (base) => {
    const ctrl = navigator.serviceWorker.controller;
    if (!ctrl) return { ok: false, reason: 'no-controller' };
    ctrl.postMessage({ type: 'dsh-remote:sw-unbind' });
    await new Promise((r) => setTimeout(r, 80));
    return await new Promise((resolve) => {
      const xhr = new XMLHttpRequest();
      xhr.open('GET', `${base}api/dsh-remotion/thumb.png?rebind=1`);
      xhr.responseType = 'arraybuffer';
      xhr.timeout = 8000;
      xhr.onload = () => resolve({ ok: xhr.status === 200 && xhr.response.byteLength > 0, status: xhr.status, bytes: xhr.response.byteLength });
      xhr.onerror = () => resolve({ ok: false, status: xhr.status });
      xhr.ontimeout = () => resolve({ ok: false, reason: 'timeout' });
      xhr.send();
    });
  }, appBase);
  assert.equal(swRebindOk.ok, true, `SW idle rebind failed: ${JSON.stringify(swRebindOk)}`);
  results.swIdleRebindRecovery = swRebindOk;

  // ---- 5. `<img>` 302 redirect & document-relative `<img>` ----
  await page.waitForFunction(() => {
    const i1 = document.getElementById('test-img-302');
    const i2 = document.getElementById('test-img-rel');
    return i1 && i2 && i1.complete && i1.naturalWidth > 0 && i2.complete && i2.naturalWidth > 0;
  }, undefined, { timeout: 10000 });
  results.subresourceImages = {
    ok: true,
    img302Width: await page.evaluate(() => document.getElementById('test-img-302').naturalWidth),
    imgRelWidth: await page.evaluate(() => document.getElementById('test-img-rel').naturalWidth),
  };

  // ---- 6. Real `>= 34 MiB` streamable MP4 in `<video muted playsInline>`: play, 206 Range, seek + abort, pause ----
  const videoResponses = [];
  const onVideoResp = (res) => {
    if (res.url().includes('/api/big-video.mp4')) {
      videoResponses.push({ status: res.status(), fromSw: res.fromServiceWorker(), range: res.headers()['content-range'] || '' });
    }
  };
  page.on('response', onVideoResp);

  const videoCheck = await page.evaluate(async (base) => {
    const v = document.getElementById('test-video');
    v.src = `${base}api/big-video.mp4`;
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('video loadeddata timed out')), 15000);
      const done = () => {
        if (v.readyState >= 2) { clearTimeout(t); resolve(); }
      };
      v.addEventListener('loadeddata', done, { once: true });
      v.addEventListener('canplay', done, { once: true });
      v.addEventListener('error', () => { clearTimeout(t); reject(new Error(`video error code=${v.error?.code}`)); }, { once: true });
      if (v.readyState >= 2) done();
    });
    await v.play();
    const playedReadyState = v.readyState;
    const duration = v.duration;
    const playingBeforeSeek = !v.paused;

    // Seek far ahead (~16s, ~32 MiB offset) to force a new 206 Range request & abort prior stream
    const seekTarget = Math.min(16, Math.max(1, duration - 2));
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('video seeked timed out')), 15000);
      v.addEventListener('seeked', () => { clearTimeout(t); resolve(); }, { once: true });
      v.currentTime = seekTarget;
    });
    const timeAfterSeek = v.currentTime;
    v.pause();
    const pausedAfter = v.paused;
    document.getElementById('e2e-video-status').textContent =
      `video: MP4 readyState=${playedReadyState} dur=${duration.toFixed(1)}s seek=${timeAfterSeek.toFixed(1)}s paused=${pausedAfter}`;
    return { playedReadyState, duration, playingBeforeSeek, timeAfterSeek, pausedAfter };
  }, appBase);

  page.off('response', onVideoResp);
  await delay(100);
  assert.ok(videoCheck.playedReadyState >= 2, `expected video readyState >= 2, got ${videoCheck.playedReadyState}`);
  assert.equal(videoCheck.playingBeforeSeek, true, 'video must play cleanly');
  assert.ok(videoCheck.timeAfterSeek >= 5, `expected seeked currentTime >= 5, got ${videoCheck.timeAfterSeek}`);
  assert.equal(videoCheck.pausedAfter, true, 'video.pause() must pause playback');
  assert.ok(videoResponses.some((r) => r.status === 206 && r.fromSw), `expected 206 Range via SW: ${JSON.stringify(videoResponses)}`);
  assert.ok(videoRangeHits >= 2, `expected >= 2 Range requests (initial + seek), got ${videoRangeHits}`);
  assert.ok(videoAbortedCount >= 1, `expected seek/pause to abort prior upstream stream, got videoAbortedCount=${videoAbortedCount}`);
  results.videoRange206AndSeekAbort = {
    ok: true,
    videoBytes: VIDEO_TOTAL_BYTES,
    ...videoCheck,
    videoRangeHits,
    videoAbortedCount,
    video206Responses: videoResponses.length,
  };

  // ---- 7. Real `<a download="artifact.bin">` click + SHA-256 verification ----
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 10000 }),
    page.locator('#test-download-link').click(),
  ]);
  assert.equal(download.suggestedFilename(), 'artifact.bin');
  const dlPath = await download.path();
  assert.ok(dlPath, 'download.path() must resolve to downloaded file');
  const dlBytes = await readFile(dlPath);
  const dlSha256 = createHash('sha256').update(dlBytes).digest('hex');
  assert.equal(dlBytes.byteLength, DOWNLOAD_PAYLOAD.byteLength);
  assert.equal(dlSha256, DOWNLOAD_EXPECTED_SHA256);
  results.nativeDownload = {
    ok: true,
    filename: download.suggestedFilename(),
    bytes: dlBytes.byteLength,
    sha256: dlSha256,
  };

  // ---- 8. Malicious HTML & SVG CSP sandbox isolation + preserving stricter upstream CSP ----
  const cspCheck = await page.evaluate(async (base) => {
    const swGetHeaders = (url) => new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('GET', url);
      xhr.timeout = 8000;
      xhr.onload = () => resolve({
        status: xhr.status,
        csp: xhr.getResponseHeader('content-security-policy') || '',
        nosniff: xhr.getResponseHeader('x-content-type-options') || '',
        cache: xhr.getResponseHeader('cache-control') || '',
      });
      xhr.onerror = () => reject(new Error('xhr error'));
      xhr.ontimeout = () => reject(new Error('xhr timeout'));
      xhr.send();
    });
    const htmlInfo = await swGetHeaders(`${base}api/malicious.html`);
    const svgInfo = await swGetHeaders(`${base}api/malicious.svg`);

    const frameProbe = await new Promise((resolve, reject) => {
      let leaked = false;
      let settled = false;
      const onMsg = (ev) => {
        if (ev.data?.type === 'csp-probe' && ev.data.leaked) leaked = true;
      };
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        window.removeEventListener('message', onMsg);
        reject(new Error('frameProbe timed out after 5000ms'));
      }, 5000);
      window.addEventListener('message', onMsg);
      const frame = document.getElementById('test-malicious-frame');
      frame.onload = () => {
        setTimeout(() => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          window.removeEventListener('message', onMsg);
          let blocked = '';
          try {
            void frame.contentWindow.localStorage;
          } catch (err) {
            blocked = err.name || 'SecurityError';
          }
          resolve({
            loaded: true,
            leaked,
            blocked,
            contentDocumentNull: frame.contentDocument === null,
          });
        }, 120);
      };
      frame.src = `${base}api/malicious.html`;
    });
    document.getElementById('e2e-csp-status').textContent = `csp: iframe ${frameProbe.blocked} | docNull=${frameProbe.contentDocumentNull} | nosniff=${htmlInfo.nosniff}`;
    return {
      htmlCsp: htmlInfo.csp,
      htmlNosniff: htmlInfo.nosniff,
      htmlCache: htmlInfo.cache,
      svgCsp: svgInfo.csp,
      frameProbe,
    };
  }, appBase);
  assert.equal(cspCheck.htmlNosniff, 'nosniff');
  assert.equal(cspCheck.htmlCache, 'no-store');
  assert.equal(cspCheck.htmlCsp.includes('allow-same-origin'), false);
  assert.ok(cspCheck.htmlCsp.includes('sandbox'));
  assert.ok(cspCheck.htmlCsp.includes("img-src 'none'"), 'must preserve stricter upstream CSP');
  assert.equal(cspCheck.svgCsp.includes('allow-same-origin'), false);
  assert.ok(cspCheck.svgCsp.includes('sandbox'));
  assert.equal(cspCheck.frameProbe.loaded, true);
  assert.equal(cspCheck.frameProbe.leaked, false);
  assert.equal(cspCheck.frameProbe.blocked, 'SecurityError');
  assert.equal(cspCheck.frameProbe.contentDocumentNull, true);
  results.cspSandboxIsolation = { ok: true, ...cspCheck };

  // ---- 9. EventSource (SSE) + File Upload hook ----
  const sseAndUpload = await page.evaluate(async () => {
    const events = [];
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('SSE timeout')), 5000);
      const es = new EventSource('/api/sse-e2e');
      es.addEventListener('status', (ev) => events.push({ type: ev.type, data: ev.data, id: ev.lastEventId }));
      es.onmessage = (ev) => {
        events.push({ type: 'message', data: ev.data, id: ev.lastEventId });
        es.close();
        clearTimeout(t);
        setTimeout(resolve, 60);
      };
    });
    document.getElementById('e2e-sse-status').textContent = `sse: ${events.map((e) => e.data).join(' -> ')}`;

    const payload = new Uint8Array(4096);
    payload.fill(7);
    const upResp = await globalThis.__DSH_FILE_UPLOAD__.fetch('/api/session/uploadFileBinary', {
      method: 'POST',
      body: payload,
    });
    const upJson = await upResp.json();
    document.getElementById('e2e-upload-status').textContent = `upload: ${upJson.bytes} bytes OK`;
    return { events, upJson };
  });
  assert.deepEqual(sseAndUpload.events, [
    { type: 'status', data: 'hello-sse', id: 'e1' },
    { type: 'message', data: 'resumed:e1', id: 'e2' },
  ]);
  assert.equal(sseAndUpload.upJson.bytes, 4096);
  await page.screenshot({ path: join(OUTPUT_DIR, '03-connected-media-and-sse.png') });
  results.sseAndUpload = { ok: true, ...sseAndUpload };

  // ---- 10. Remote tunnel 403 admin block + Local Sidebar Panel (QR, Token Renew, Rebind, Draft Protection) ----
  const remoteAdminBlock = await page.evaluate(async () => {
    const r1 = await fetch('/api/tiana-remote/admin/status');
    const r2 = await fetch('/api/tiana-remote/admin/pairing-key/reveal', { method: 'POST', body: '{}' });
    const pub = await fetch('/api/tiana-remote/public-status');
    return { adminStatus: r1.status, revealStatus: r2.status, pubStatus: pub.status, pubBody: await pub.json() };
  });
  assert.equal(remoteAdminBlock.adminStatus, 403);
  assert.equal(remoteAdminBlock.revealStatus, 403);
  assert.equal(remoteAdminBlock.pubStatus, 200);
  assert.equal(Object.keys(remoteAdminBlock.pubBody).length, 8);

  const localPanelPage = await context.newPage();
  await localPanelPage.goto(`http://127.0.0.1:${localDshPort}/local-sidebar-test`);
  await localPanelPage.locator('#dshr-qr-btn').waitFor({ timeout: 8000 });
  await localPanelPage.locator('#dshr-hostname-input').fill('My-Unsaved-Draft-Name');
  await delay(4300);
  assert.equal(await localPanelPage.locator('#dshr-hostname-input').inputValue(), 'My-Unsaved-Draft-Name');
  await localPanelPage.locator('#dshr-renew-token-btn').click();
  await localPanelPage.waitForFunction(() => document.querySelector('#dshr-token-expiry')?.textContent?.includes('30'), undefined, { timeout: 5000 });
  assert.equal(tokenRenewCount, 1);
  assert.equal(await localPanelPage.locator('#dshr-rebind-form').count(), 1);
  await localPanelPage.locator('#dshr-qr-btn').click();
  const qrMeta = await localPanelPage.evaluate(() => {
    const svg = document.querySelector('#dshr-qr-dialog svg');
    return {
      version: Number(svg?.getAttribute('data-qr-version') || 0),
      size: Number(svg?.getAttribute('data-qr-size') || 0),
      ec: svg?.getAttribute('data-qr-ec'),
      hasPath: Boolean(svg?.querySelector('path')?.getAttribute('d')?.length > 100),
    };
  });
  assert.ok(qrMeta.version >= 2 && qrMeta.size >= 25 && qrMeta.ec === 'M' && qrMeta.hasPath);
  await localPanelPage.screenshot({ path: join(OUTPUT_DIR, '04-sidebar-local-panel-qr.png') });
  await localPanelPage.close();
  results.localAndRemoteSidebar = { ok: true, remoteAdminBlock, tokenRenewCount, draftPreservedAcross4sPoll: true, qrMeta };

  // ---- 11. 800ms Reconnect Capsule & HostOffline screen ----
  const dropAt = Date.now();
  bridge.stop();
  await page.waitForFunction(
    () => getComputedStyle(document.getElementById('dsh-remote-reconnect-banner')).display === 'flex',
    undefined,
    { timeout: 3000 },
  );
  const bannerElapsedMs = Date.now() - dropAt;
  assert.ok(bannerElapsedMs >= 700 && bannerElapsedMs < 2500, `reconnect banner expected around 800ms, got ${bannerElapsedMs}ms`);
  await page.screenshot({ path: join(OUTPUT_DIR, '05-reconnect-capsule-800ms.png') });

  const offlinePage = await context.newPage();
  await offlinePage.goto(appUrl);
  await offlinePage.locator('#dsh-remote-shell[data-state="offline"]').waitFor({ timeout: 10000 });
  await offlinePage.screenshot({ path: join(OUTPUT_DIR, '06-host-offline.png') });
  await offlinePage.close();

  bridge = await startHostBridge();
  await page.waitForFunction(
    () => getComputedStyle(document.getElementById('dsh-remote-reconnect-banner')).display === 'none',
    undefined,
    { timeout: 10000 },
  );
  results.reconnectAndOffline = { ok: true, bannerElapsedMs };

  // ---- 12. Narrow mobile viewport (375x812) ----
  const mobileCtx = await browser.newContext({ viewport: { width: 375, height: 812 } });
  const mobilePage = await mobileCtx.newPage();
  await mobilePage.goto(appUrl);
  await mobilePage.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 10000 });
  const mobileOverflow = await mobilePage.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
  assert.ok(mobileOverflow.scrollWidth <= mobileOverflow.clientWidth + 2, `mobile overflow: ${JSON.stringify(mobileOverflow)}`);
  await mobilePage.screenshot({ path: join(OUTPUT_DIR, '07-mobile-narrow-viewport.png') });
  await mobileCtx.close();
  results.mobileViewport = { ok: true, ...mobileOverflow };

  // ---- 13. No-SW Option A dismissible banner ----
  const noSwCtx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await noSwCtx.addInitScript(() => {
    Object.defineProperty(navigator, 'serviceWorker', { value: undefined, configurable: true });
  });
  const noSwPage = await noSwCtx.newPage();
  await noSwPage.goto(appUrl);
  await noSwPage.locator('#dsh-remote-e2ee-key-input').fill(`dshk1_${pairingKey}`);
  await noSwPage.locator('#dsh-remote-e2ee-submit').click();
  await noSwPage.locator('#dsh-remote-no-sw-banner').waitFor({ state: 'visible', timeout: 15000 });
  await noSwPage.screenshot({ path: join(OUTPUT_DIR, '08-no-sw-option-a-banner.png') });
  await noSwPage.locator('#dsh-remote-no-sw-dismiss').click();
  assert.equal(await noSwPage.locator('#dsh-remote-no-sw-banner').count(), 0);
  await noSwCtx.close();
  results.noSwOptionABanner = { ok: true };

  // ---- 14. Live online page rebind (`workstation-r2` -> `workstation-r2-new`) ----
  const rebindDials = [];
  page.on('websocket', (socket) => {
    const u = new URL(socket.url());
    if (u.pathname.endsWith('/client')) rebindDials.push(u.searchParams.get('host_id'));
  });
  target.hostId = 'workstation-r2-new';
  target.hostName = 'Rebound Workstation';
  const reboundPolicy = {
    ...policyObj,
    hostId: target.hostId,
    hostName: target.hostName,
    updatedAt: new Date().toISOString(),
  };
  await delay(20);
  await writeFile(policyFile, JSON.stringify({
    DSH_REMOTE_POLICY: { kind: 'plain', value: JSON.stringify(reboundPolicy) },
  }), { mode: 0o600 });
  bridge.stop();
  bridge = await startHostBridge();

  const fresh = await context.newPage();
  await fresh.goto(appUrl);
  await fresh.locator('#dsh-remote-shell[data-state="unlock"]').waitFor({ timeout: 14000 });
  const freshHostMatched = (await fresh.locator('#dsh-remote-shell').innerText()).includes(target.hostName);
  assert.equal(freshHostMatched, true, 'fresh tab must recognize rebound hostName');

  await page.waitForFunction(
    (expectedId) => {
      const snap = globalThis.__DSH_REMOTE_SHELL__?.getSnapshot?.();
      return snap?.hostId === expectedId && (snap?.transportState === 'Relay' || snap?.transportState === 'P2P');
    },
    target.hostId,
    { timeout: 12000 },
  );
  const oldPageHost = await page.evaluate(() => globalThis.__DSH_REMOTE_SHELL__?.getSnapshot().hostId);
  assert.equal(oldPageHost, target.hostId, 'already-online tab must update snapshot hostId after rebind');
  assert.ok(rebindDials.includes(target.hostId), `expected online tab to dial ${target.hostId}, dials=${JSON.stringify(rebindDials)}`);
  await page.screenshot({ path: join(OUTPUT_DIR, '09-online-page-after-rebind.png') });
  await fresh.close();
  results.liveOnlinePageRebind = { ok: true, expected: target.hostId, freshHostMatched, oldPageHost, rebindDials };

  assert.deepEqual(pageErrors, [], `Unexpected page errors: ${pageErrors.join('; ')}`);

  // Write SHA256SUMS for all generated PNGs
  const pngFiles = (await readdir(OUTPUT_DIR)).filter((f) => f.endsWith('.png')).sort();
  const sumLines = [];
  for (const name of pngFiles) {
    const hash = createHash('sha256').update(await readFile(join(OUTPUT_DIR, name))).digest('hex');
    sumLines.push(`${hash}  ${name}`);
  }
  await writeFile(join(OUTPUT_DIR, 'SHA256SUMS'), `${sumLines.join('\n')}\n`);

  let gitCommit = '';
  let gitStatusClean = false;
  try {
    gitCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: PROJECT_ROOT, encoding: 'utf8' }).trim();
    gitStatusClean = execFileSync('git', ['status', '--short'], { cwd: PROJECT_ROOT, encoding: 'utf8' }).trim() === '';
  } catch {
    // ignore outside git repo
  }

  const summary = {
    verifiedAt: new Date().toISOString(),
    gitCommit,
    gitStatusClean,
    browserVersion: browser.version(),
    shellBytes: builtWeb.totalBytes,
    screenshots: pngFiles,
    outputDir: OUTPUT_DIR,
    results,
  };
  await writeFile(join(OUTPUT_DIR, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
  console.log(JSON.stringify(summary, null, 2));
} finally {
  await browser?.close();
  bridge?.stop();
  hostController.dispose();
  for (const s of sockets) s.destroy();
  appServer.close();
  localDshServer.close();
  if (relayProc.pid && relayProc.exitCode === null) {
    relayProc.kill();
    await once(relayProc, 'exit').catch(() => {});
  }
  await rm(scratch, { recursive: true, force: true });
}
