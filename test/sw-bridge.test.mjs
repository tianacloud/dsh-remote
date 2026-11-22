import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

const PROJECT_ROOT = fileURLToPath(new URL('..', import.meta.url));
const SW_SOURCE = readFileSync(join(PROJECT_ROOT, 'web-src/dsh-remote-sw.js'), 'utf8');

function createSwHarness({
  origin = 'https://wcnw5aiuh2bx.tianacloud.site',
  scopePath = '/web/wcnw5aiuh2bx/',
} = {}) {
  const listeners = new Map();
  const windowClients = new Map();

  const selfObj = {
    location: new URL(`${origin}${scopePath}dsh-remote-sw.js`),
    registration: { scope: `${origin}${scopePath}` },
    crypto: webcrypto,
    clients: {
      async claim() {},
      async get(id) {
        return windowClients.get(id) ?? null;
      },
      async matchAll(opts = {}) {
        const list = [...windowClients.values()];
        if (opts.type) return list.filter((c) => c.type === opts.type);
        return list;
      },
    },
    skipWaiting() {},
    addEventListener(type, fn) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(fn);
    },
  };

  const sandbox = {
    self: selfObj,
    globalThis: selfObj,
    crypto: webcrypto,
    URL,
    URLSearchParams,
    Headers,
    Response,
    ReadableStream,
    MessageChannel,
    Uint8Array,
    DOMException,
    setTimeout,
    clearTimeout,
    console,
  };
  vm.runInNewContext(SW_SOURCE, sandbox, { filename: 'web-src/dsh-remote-sw.js' });

  function addWindowClient(id, url) {
    const client = { id, type: 'window', url, postMessage() {} };
    windowClients.set(id, client);
    return client;
  }

  async function bindWindow(clientId, url, navToken, responder) {
    const client = addWindowClient(clientId, url);
    const channel = new MessageChannel();
    const bound = new Promise((resolve) => {
      channel.port1.onmessage = (ev) => {
        const msg = ev.data;
        if (msg?.type === 'dsh-remote:sw-bound') {
          resolve(msg);
          return;
        }
        if (msg?.type === 'fetch' && ev.ports?.[0]) {
          const reqPort = ev.ports[0];
          const reply = responder(msg) || {
            status: 200,
            headers: { 'content-type': 'text/plain; charset=utf-8' },
            body: new TextEncoder().encode('ok'),
          };
          reqPort.onmessage = (rev) => {
            if (rev.data?.type === 'pull') {
              if (reply.body && reply.body.byteLength > 0) {
                const chunk = reply.body;
                reply.body = null;
                reqPort.postMessage({ type: 'chunk', data: chunk }, [chunk.buffer]);
              }
              reqPort.postMessage({ type: 'end' });
            }
          };
          reqPort.start?.();
          reqPort.postMessage({
            type: 'head',
            status: reply.status,
            statusText: reply.statusText || 'OK',
            headers: reply.headers || {},
          });
        }
      };
    });
    channel.port1.start?.();
    for (const fn of listeners.get('message') || []) {
      fn({
        source: client,
        data: { type: 'dsh-remote:sw-bind', clientId, navToken },
        ports: [channel.port2],
      });
    }
    const ack = await bound;
    return {
      ack,
      close() {
        try { channel.port1.close(); } catch { /* ignore */ }
      },
    };
  }

  async function dispatchFetch({
    url,
    destination = 'iframe',
    referrer = '',
    headers = {},
    clientId = '',
    resultingClientId = '',
    method = 'GET',
    mode = 'navigate',
  }) {
    const reqHeaders = new Headers(headers);
    const request = {
      url,
      method,
      destination,
      referrer,
      mode,
      redirect: 'follow',
      headers: reqHeaders,
      signal: new AbortController().signal,
      async arrayBuffer() {
        return new ArrayBuffer(0);
      },
    };
    let responsePromise = null;
    const event = {
      request,
      clientId,
      resultingClientId,
      respondWith(p) {
        responsePromise = Promise.resolve(p);
      },
    };
    for (const fn of listeners.get('fetch') || []) {
      fn(event);
    }
    return responsePromise ? await responsePromise : null;
  }

  return { addWindowClient, bindWindow, dispatchFetch };
}

test('dsh-remote-sw.js enforces strict iframe isolation under Referrer-Policy: no-referrer while allowing trusted same-origin embeds', async () => {
  const origin = 'https://wcnw5aiuh2bx.tianacloud.site';
  const appBase = `${origin}/web/wcnw5aiuh2bx/`;
  const navToken = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4';
  const harness = createSwHarness({ origin, scopePath: '/web/wcnw5aiuh2bx/' });

  const bound = await harness.bindWindow('win-owner-1', appBase, navToken, (req) => {
    if (req.path.startsWith('/api/download/artifact.bin')) {
      return {
        status: 200,
        headers: { 'content-type': 'application/octet-stream' },
        body: new TextEncoder().encode('binary-payload-v023'),
      };
    }
    return {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: new TextEncoder().encode('<h1>preview</h1>'),
    };
  });
  harness.addWindowClient('win-sibling-other', `${origin}/other-app/`);

  const iframeUrl = `${appBase}api/preview.html?__dsh_nav=${navToken}`;
  const downloadUrl = `${appBase}api/download/artifact.bin?__dsh_nav=${navToken}&__dsh_dl=artifact.bin`;

  try {
    // (a) Empty referrer + sec-fetch-site: same-origin + trusted parent client -> ALLOWED (200)
    const allowedSameOrigin = await harness.dispatchFetch({
      url: iframeUrl,
      destination: 'iframe',
      referrer: '',
      headers: { 'sec-fetch-site': 'same-origin' },
      clientId: 'win-owner-1',
    });
    assert.equal(allowedSameOrigin.status, 200);
    assert.equal(await allowedSameOrigin.text(), '<h1>preview</h1>');
    assert.match(allowedSameOrigin.headers.get('content-security-policy') || '', /sandbox allow-scripts/u);
    assert.equal((allowedSameOrigin.headers.get('content-security-policy') || '').includes('allow-same-origin'), false);

    // (b) Empty referrer + sec-fetch-site: same-site (cross-tenant *.tianacloud.site!) -> REJECTED (503)
    for (const cid of ['', 'win-owner-1']) {
      const deniedSameSite = await harness.dispatchFetch({
        url: iframeUrl,
        destination: 'iframe',
        referrer: '',
        headers: { 'sec-fetch-site': 'same-site' },
        clientId: cid,
      });
      assert.equal(deniedSameSite.status, 503, `same-site iframe must be rejected (clientId=${cid})`);
    }

    // (c) Empty referrer + sec-fetch-site: cross-site -> REJECTED (503)
    const deniedCrossSite = await harness.dispatchFetch({
      url: iframeUrl,
      destination: 'iframe',
      referrer: '',
      headers: { 'sec-fetch-site': 'cross-site' },
      clientId: 'win-owner-1',
    });
    assert.equal(deniedCrossSite.status, 503);

    // (c2) Empty referrer + missing / none sec-fetch-site -> REJECTED (503)
    for (const headers of [{}, { 'sec-fetch-site': 'none' }]) {
      const deniedMissing = await harness.dispatchFetch({
        url: iframeUrl,
        destination: 'iframe',
        referrer: '',
        headers,
        clientId: 'win-owner-1',
      });
      assert.equal(deniedMissing.status, 503);
    }

    // (c3) Empty referrer + sec-fetch-site: same-origin + missing or sibling-path parent client -> REJECTED (503)
    for (const cid of ['', 'win-sibling-other', 'win-nonexistent']) {
      const deniedUntrustedClient = await harness.dispatchFetch({
        url: iframeUrl,
        destination: 'iframe',
        referrer: '',
        headers: { 'sec-fetch-site': 'same-origin' },
        clientId: cid,
      });
      assert.equal(deniedUntrustedClient.status, 503, `untrusted/missing parent client must be rejected (clientId=${cid})`);
    }

    // (d) Non-empty untrusted referrer (cross-tenant, sibling path, or external) -> REJECTED (503)
    for (const badRef of [
      'https://otherweb.tianacloud.site/web/otherweb/',
      `${origin}/other-app/`,
      'https://evil.example/embed',
    ]) {
      const deniedBadRef = await harness.dispatchFetch({
        url: iframeUrl,
        destination: 'iframe',
        referrer: badRef,
        headers: { 'sec-fetch-site': 'same-origin' },
        clientId: 'win-owner-1',
      });
      assert.equal(deniedBadRef.status, 503, `untrusted referrer ${badRef} must be rejected`);
    }

    // (e) Trusted same-origin referrer (emitted by <iframe referrerpolicy="same-origin"> on no-referrer pages) with empty clientId -> ALLOWED (200)
    const allowedPreview = await harness.dispatchFetch({
      url: iframeUrl,
      destination: 'iframe',
      referrer: appBase,
      clientId: '',
    });
    assert.equal(allowedPreview.status, 200);
    assert.equal(await allowedPreview.text(), '<h1>preview</h1>');

    const allowedDownload = await harness.dispatchFetch({
      url: downloadUrl,
      destination: 'iframe',
      referrer: appBase,
      clientId: '',
    });
    assert.equal(allowedDownload.status, 200);
    assert.equal(allowedDownload.headers.get('content-disposition'), 'attachment; filename="artifact.bin"');
    assert.equal(await allowedDownload.text(), 'binary-payload-v023');

    // (f) Entry script sets referrerPolicy = 'same-origin' for hidden download & rewritten preview iframes
    const entrySource = readFileSync(join(PROJECT_ROOT, 'web-src/dsh-remote-entry.mjs'), 'utf8');
    assert.match(entrySource, /f\.referrerPolicy\s*=\s*'same-origin'/u);
    assert.match(entrySource, /el\.referrerPolicy\s*=\s*'same-origin'/u);
  } finally {
    bound.close();
  }
});

test('dsh-remote-sw.js tunnels custom plugin root paths under /web/<id>/ while passing through platform, static shell, cross-origin, navigation, and sibling /web/ apps', async () => {
  const origin = 'https://wcnw5aiuh2bx.tianacloud.site';
  const scopePath = '/web/wcnw5aiuh2bx/';
  const appBase = `${origin}${scopePath}`;
  const navToken = 'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5';
  const harness = createSwHarness({ origin, scopePath });
  const tunneledPaths = [];

  const bound = await harness.bindWindow('win-owner-2', appBase, navToken, (req) => {
    tunneledPaths.push(req.path);
    return {
      status: 200,
      headers: { 'content-type': 'image/png' },
      body: new TextEncoder().encode(`ok:${req.path}`),
    };
  });

  try {
    // 1. Custom plugin root paths (and appBase-prefixed variants) MUST be tunneled with intact query strings
    const customPaths = [
      { url: `${origin}/tiana/api/template-cover?name=foo`, expected: '/tiana/api/template-cover?name=foo' },
      { url: `${origin}/tiana/api/site-icon?id=bar`, expected: '/tiana/api/site-icon?id=bar' },
      { url: `${origin}/my-plugin/img.png?size=64`, expected: '/my-plugin/img.png?size=64' },
      { url: `${appBase}tiana/api/template-cover?name=baz`, expected: '/tiana/api/template-cover?name=baz' },
      { url: `${origin}/api/file?path=a.png`, expected: '/api/file?path=a.png' },
      { url: `${origin}/plugins/dshmarket/badge.svg`, expected: '/plugins/dshmarket/badge.svg' },
    ];
    for (const { url, expected } of customPaths) {
      const resp = await harness.dispatchFetch({
        url,
        destination: 'image',
        mode: 'no-cors',
        clientId: 'win-owner-2',
      });
      assert.ok(resp, `expected SW to intercept and tunnel ${url}`);
      assert.equal(resp.status, 200);
      assert.equal(await resp.text(), `ok:${expected}`);
    }
    assert.deepEqual(tunneledPaths, customPaths.map((p) => p.expected));

    // 2. Platform, static shell, external origin, top-level navigation, and sibling /web/<other>/ apps MUST passthrough (return null -> event.respondWith not called)
    const passthroughCases = [
      { url: 'https://cdn.example.test/cover.png', destination: 'image', mode: 'no-cors' },
      { url: `${origin}/_tiana/session`, destination: '', mode: 'cors' },
      { url: `${origin}/_tiana`, destination: '', mode: 'cors' },
      { url: `${appBase}_tiana/session`, destination: '', mode: 'cors' },
      { url: `${origin}/web/wcnw5aiuh2bx/_tiana`, destination: '', mode: 'cors' },
      { url: `${appBase}assets/dsh-remote-entry.mjs`, destination: 'script', mode: 'cors' },
      { url: `${origin}/brand/logo.svg`, destination: 'image', mode: 'no-cors' },
      { url: `${origin}/favicon.ico`, destination: 'image', mode: 'no-cors' },
      { url: appBase, destination: 'document', mode: 'navigate' },
      { url: `${origin}/web/wcnw5aiuh2bx`, destination: 'document', mode: 'navigate' },
      { url: `${origin}/`, destination: 'document', mode: 'navigate' },
      { url: `${origin}/index.html`, destination: 'document', mode: 'navigate' },
      { url: `${origin}/web/otherapp9999/`, destination: 'document', mode: 'navigate' },
      { url: `${origin}/web/otherapp9999/api/status`, destination: '', mode: 'cors' },
      { url: `${origin}/web/otherapp9999/tiana/api/site-icon`, destination: 'image', mode: 'no-cors' },
    ];
    const countBefore = tunneledPaths.length;
    for (const tc of passthroughCases) {
      const resp = await harness.dispatchFetch({
        ...tc,
        clientId: 'win-owner-2',
      });
      assert.equal(resp, null, `expected passthrough (null) for ${tc.url} (mode=${tc.mode})`);
    }
    assert.equal(tunneledPaths.length, countBefore, 'passthrough URLs must never hit the tunnel');
  } finally {
    bound.close();
  }
});
