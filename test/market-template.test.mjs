import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { packMarketTemplate, parseZip, verifyInstallZip } from '../scripts/pack-market-template.mjs';

const repoRoot = fileURLToPath(new URL('../', import.meta.url));

test('packMarketTemplate builds a valid unified install.zip without mutating relay-go/main.go', () => {
  const relayMainPath = path.join(repoRoot, 'relay-go', 'main.go');
  const relayBefore = readFileSync(relayMainPath, 'utf8');
  const workDir = mkdtempSync(path.join(tmpdir(), 'dsh-remote-market-test-'));

  try {
    const outZip = path.join(workDir, 'dsh-remote-test.install.zip');
    const result = packMarketTemplate({ repoRoot, outPath: outZip });

    // Source tree relay-go/main.go must remain untouched
    const relayAfter = readFileSync(relayMainPath, 'utf8');
    assert.equal(relayAfter, relayBefore);
    assert.ok(relayAfter.includes('var defaultWebID = ""'));

    // Top-level verification summary
    assert.equal(result.name, 'dsh-remote');
    assert.equal(result.display_name, 'dsh-tiana-remote');
    assert.equal(result.entry, 'dsh-remote-entry.mjs');
    assert.equal(result.database_required, false);
    assert.equal(result.has_source, true);
    assert.equal(result.icon.width, 256);
    assert.equal(result.icon.height, 256);
    assert.equal(result.icon.colorType, 6);
    assert.ok(result.cover.pixels > 0 && result.cover.pixels <= 2_097_152);
    assert.ok(result.site_tweb_bytes <= 16 * 1024 * 1024);

    // Re-verify bytes from disk
    const rawZip = readFileSync(outZip);
    const verified = verifyInstallZip(rawZip);
    assert.equal(verified.sha256, result.sha256);

    // Inspect inner source.zip and site.tweb layers
    const outer = parseZip(rawZip, 'install.zip');
    const source = parseZip(outer.files['source.zip'], 'source.zip');
    const site = parseZip(outer.files['site.tweb'], 'site.tweb');

    // Placeholder injected in source.zip relay main.go and remote-config.json
    const stagedRelay = source.files['repositories/app/functions/relay/main.go'].toString('utf8');
    assert.ok(stagedRelay.includes('var defaultWebID = "__TIANA_WEB_ID_5f3b9d02__"'));
    assert.ok(!stagedRelay.includes('var defaultWebID = ""'));

    const siteConfig = JSON.parse(site.files['data/remote-config.json'].toString('utf8'));
    assert.equal(siteConfig.functionId, '__TIANA_FUNCTION_RELAY_8c4e2a19__');
    assert.equal(siteConfig.webId, '__TIANA_WEB_ID_5f3b9d02__');

    // Showcase preview must use the updated user-facing sync/repair cloud page copy & explanation
    const previewHtml = outer.files['showcase/preview.html'].toString('utf8');
    assert.ok(previewHtml.includes('同步/修复云端访问页'), 'preview.html must display updated sync/repair cloud page button copy');
    assert.ok(previewHtml.includes('id="desc-repair-shell"'), 'preview.html must include structured explanation for sync/repair cloud page');
    assert.ok(previewHtml.includes('云端应用绑定'), 'preview.html must display local cloud app binding section');
    assert.ok(previewHtml.includes('id="desc-local-unbind"'), 'preview.html must include structured explanation for local unbind');
    assert.ok(!previewHtml.includes('重推静态壳层'), 'preview.html must not contain legacy static shell button copy');
    assert.ok(!previewHtml.includes('静态壳层'), 'preview.html must not contain legacy static shell copy');

    // Extracted repositories/app from source.zip builds cleanly via build.mjs
    const extractRoot = path.join(workDir, 'extracted');
    for (const [rel, bytes] of Object.entries(source.files)) {
      const target = path.join(extractRoot, rel);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, bytes);
    }
    const buildOut = execFileSync(process.execPath, ['build.mjs'], {
      cwd: path.join(extractRoot, 'repositories', 'app'),
      encoding: 'utf8',
    });
    assert.ok(buildOut.includes('TIANA_PROJECT_PARAMS {"entry":"dsh-remote-entry.mjs"}'));
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
});
