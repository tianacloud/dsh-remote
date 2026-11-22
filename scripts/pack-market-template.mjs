#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { crc32, deflateRawSync, inflateRawSync } from 'node:zlib';
import { buildWebDist } from './build-web-dist.mjs';
import { scanText } from './pack-plugin.mjs';

const projectRoot = fileURLToPath(new URL('../', import.meta.url));

const MIB = 1 << 20;
const MAX_INSTALL_ZIP_BYTES = 32 * MIB;
const MAX_FILE_BYTES = 16 * MIB;
const MAX_SITE_BYTES = 16 * MIB;
const MAX_SITE_ENTRIES = 4097;
const MAX_INSTALL_JSON_BYTES = MIB;
const MAX_EXPANDED_BYTES = 128 * MIB;
const MAX_CUMULATIVE_ENTRIES = 5000;
const MAX_PREVIEW_BYTES = 500_000;
const MAX_COVER_PIXELS = 2_097_152;
const REQUIRED_ICON_SIZE = 256;
const FIXED_ENTRY = 'dsh-remote-entry.mjs';
const WEB_ID_PLACEHOLDER = '__TIANA_WEB_ID_5f3b9d02__';
const PLACEHOLDER_RE = /^__TIANA_[A-Z0-9_]+_[a-f0-9]+__$/;
const PLACEHOLDER_GLOBAL_RE = /__TIANA_[A-Z0-9_]+_[a-f0-9]+__/g;

const BINARY_EXTS = new Set(['.png', '.webp', '.jpg', '.jpeg', '.gif', '.ico', '.wasm', '.zip', '.tweb', '.gz']);

const EXTRA_FORBIDDEN_PATTERNS = [
  { name: 'internal test account name', re: new RegExp('\\bwat' + 'er\\b', 'iu') },
  { name: 'internal test workspace slug', re: new RegExp('sr-' + 'ws', 'iu') },
  { name: 'internal test app id', re: new RegExp('l9o1db' + 'ftsxqj', 'iu') },
  { name: 'deprecated plugin policy env var', re: new RegExp('DSH_REMOTE_' + 'WEB_PLUGINS', 'u') },
  { name: 'deprecated template repo reference', re: new RegExp('tianacloud/' + 'template-apps', 'iu') },
];

const EXTERNAL_HTML_PATTERNS = [
  { name: 'external http(s) URL', re: /https?:\/\//iu },
  { name: 'protocol-relative URL', re: /(?:src|href|action|poster)\s*=\s*["']\s*\/\//iu },
  { name: 'CSS @import', re: /@import\b/iu },
  { name: 'CSS external url()', re: /url\(\s*["']?\s*(?:https?:|\/\/)/iu },
  { name: 'external script src', re: /<script\b[^>]*\bsrc\s*=/iu },
  { name: 'external stylesheet link', re: /<link\b[^>]*\bhref\s*=/iu },
];

// Deterministic DOS timestamp: 1980-01-01 00:00:00
const DOS_TIME = 0x0000;
const DOS_DATE = 0x0021;
const UTF8_FLAG = 0x0800;

export function createZip(entries) {
  const names = Object.keys(entries).sort();
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const name of names) {
    const raw = Buffer.isBuffer(entries[name]) ? entries[name] : Buffer.from(entries[name]);
    const nameBuf = Buffer.from(name, 'utf8');
    const crc = crc32(raw) >>> 0;
    const compressed = raw.length === 0 ? raw : deflateRawSync(raw, { level: 9 });
    const method = raw.length === 0 ? 0 : 8;

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // local file header signature
    localHeader.writeUInt16LE(20, 4); // version needed to extract (2.0)
    localHeader.writeUInt16LE(UTF8_FLAG, 6);
    localHeader.writeUInt16LE(method, 8);
    localHeader.writeUInt16LE(DOS_TIME, 10);
    localHeader.writeUInt16LE(DOS_DATE, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(compressed.length, 18);
    localHeader.writeUInt32LE(raw.length, 22);
    localHeader.writeUInt16LE(nameBuf.length, 26);
    localHeader.writeUInt16LE(0, 28); // extra length

    localParts.push(localHeader, nameBuf, compressed);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // central file header signature
    centralHeader.writeUInt16LE(0x0314, 4); // version made by (Unix, 2.0)
    centralHeader.writeUInt16LE(20, 6); // version needed
    centralHeader.writeUInt16LE(UTF8_FLAG, 8);
    centralHeader.writeUInt16LE(method, 10);
    centralHeader.writeUInt16LE(DOS_TIME, 12);
    centralHeader.writeUInt16LE(DOS_DATE, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(compressed.length, 20);
    centralHeader.writeUInt32LE(raw.length, 24);
    centralHeader.writeUInt16LE(nameBuf.length, 28);
    centralHeader.writeUInt16LE(0, 30); // extra length
    centralHeader.writeUInt16LE(0, 32); // comment length
    centralHeader.writeUInt16LE(0, 34); // disk number start
    centralHeader.writeUInt16LE(0, 36); // internal attrs
    centralHeader.writeUInt32LE((0o100644 << 16) >>> 0, 38); // external attrs (regular file)
    centralHeader.writeUInt32LE(offset, 42);

    centralParts.push(centralHeader, nameBuf);
    offset += localHeader.length + nameBuf.length + compressed.length;
  }

  const centralDir = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // central directory disk
  eocd.writeUInt16LE(names.length, 8); // entries on this disk
  eocd.writeUInt16LE(names.length, 10); // total entries
  eocd.writeUInt32LE(centralDir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localParts, centralDir, eocd]);
}

export function parseZip(data, label = 'archive') {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
  let eocdOffset = -1;
  const minOffset = Math.max(0, buf.length - 65558);
  for (let pos = buf.length - 22; pos >= minOffset; pos--) {
    if (
      buf.readUInt32LE(pos) === 0x06054b50 &&
      pos + 22 + buf.readUInt16LE(pos + 20) === buf.length
    ) {
      eocdOffset = pos;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error(`${label}: invalid ZIP end-of-central-directory`);
  }
  const disk = buf.readUInt16LE(eocdOffset + 4);
  const cdDisk = buf.readUInt16LE(eocdOffset + 6);
  const localCount = buf.readUInt16LE(eocdOffset + 8);
  const count = buf.readUInt16LE(eocdOffset + 10);
  const cdSize = buf.readUInt32LE(eocdOffset + 12);
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);
  if (
    disk !== 0 ||
    cdDisk !== 0 ||
    localCount !== count ||
    count > MAX_CUMULATIVE_ENTRIES ||
    cdOffset + cdSize !== eocdOffset
  ) {
    throw new Error(`${label}: invalid ZIP central directory or entry budget exceeded`);
  }

  const files = {};
  const directories = new Set();
  const seen = new Set();
  let totalExpanded = 0;
  let pos = cdOffset;
  let actualCount = 0;

  while (pos < eocdOffset) {
    if (pos + 46 > eocdOffset || buf.readUInt32LE(pos) !== 0x02014b50) {
      throw new Error(`${label}: corrupt central directory entry`);
    }
    actualCount += 1;
    if (actualCount > MAX_CUMULATIVE_ENTRIES) {
      throw new Error(`${label}: exceeds ${MAX_CUMULATIVE_ENTRIES} entries`);
    }
    const method = buf.readUInt16LE(pos + 10);
    const expectedCrc = buf.readUInt32LE(pos + 16);
    const compSize = buf.readUInt32LE(pos + 20);
    const uncompSize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const extAttr = buf.readUInt32LE(pos + 38);
    const localOffset = buf.readUInt32LE(pos + 42);
    const rawName = buf.subarray(pos + 46, pos + 46 + nameLen).toString('utf8');
    pos += 46 + nameLen + extraLen + commentLen;

    const isDir = rawName.endsWith('/');
    const name = isDir ? rawName.slice(0, -1) : rawName;
    const parts = name.split('/');
    const mode = (extAttr >>> 16) & 0o170000;
    if (
      !name ||
      name.includes('\\') ||
      name.includes('\0') ||
      name.includes(':') ||
      name.startsWith('/') ||
      parts.some((p) => !p || p === '.' || p === '..' || p.toLowerCase() === '.git') ||
      seen.has(name) ||
      ![0, 0o100000, 0o040000].includes(mode) ||
      (isDir && mode === 0o100000) ||
      (!isDir && mode === 0o040000) ||
      (directories.has(name) && !isDir)
    ) {
      throw new Error(`${label}: unsafe ZIP path or entry mode: ${rawName}`);
    }
    for (let i = 1; i < parts.length; i++) {
      const parent = parts.slice(0, i).join('/');
      if (Object.hasOwn(files, parent)) {
        throw new Error(`${label}: file/directory collision at ${name}`);
      }
      directories.add(parent);
    }
    if (isDir) directories.add(name);
    seen.add(name);

    if (uncompSize > MAX_FILE_BYTES || totalExpanded + uncompSize > MAX_EXPANDED_BYTES) {
      throw new Error(`${label}: expanded size exceeds budget at ${name}`);
    }
    if (localOffset + 30 > cdOffset || buf.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new Error(`${label}: invalid local file header for ${name}`);
    }
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compSize;
    if (dataEnd > cdOffset) {
      throw new Error(`${label}: truncated entry payload for ${name}`);
    }
    const payload = buf.subarray(dataStart, dataEnd);
    let content;
    if (method === 0) {
      content = Buffer.from(payload);
    } else if (method === 8) {
      content = inflateRawSync(payload);
    } else {
      throw new Error(`${label}: unsupported ZIP compression method ${method} for ${name}`);
    }
    if (content.length !== uncompSize || content.length > MAX_FILE_BYTES) {
      throw new Error(`${label}: uncompressed size mismatch for ${name}`);
    }
    if ((crc32(content) >>> 0) !== expectedCrc) {
      throw new Error(`${label}: CRC32 mismatch for ${name}`);
    }
    totalExpanded += content.length;
    if (totalExpanded > MAX_EXPANDED_BYTES) {
      throw new Error(`${label}: actual expanded size exceeds budget`);
    }
    if (isDir && content.length > 0) {
      throw new Error(`${label}: directory entry contains bytes: ${name}`);
    }
    if (!isDir) {
      files[name] = content;
    }
  }

  if (actualCount !== count || pos !== eocdOffset) {
    throw new Error(`${label}: ZIP central directory entry count mismatch`);
  }
  return { files, totalExpanded, count: actualCount };
}

export function inspectPng(buf) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (buf.length < 33 || !buf.subarray(0, 8).equals(sig)) {
    throw new Error('icon.png: invalid PNG signature');
  }
  const ihdrLen = buf.readUInt32BE(8);
  const ihdrType = buf.subarray(12, 16).toString('ascii');
  if (ihdrLen !== 13 || ihdrType !== 'IHDR') {
    throw new Error('icon.png: missing or invalid IHDR chunk');
  }
  const width = buf.readUInt32BE(16);
  const height = buf.readUInt32BE(20);
  const bitDepth = buf[24];
  const colorType = buf[25];

  // Walk chunks to confirm structural validity and IEND terminator
  let pos = 8;
  let sawIend = false;
  while (pos + 12 <= buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.subarray(pos + 4, pos + 8).toString('ascii');
    const next = pos + 12 + len;
    if (next > buf.length) {
      throw new Error(`icon.png: truncated PNG chunk ${type}`);
    }
    if (type === 'IEND') {
      sawIend = true;
      break;
    }
    pos = next;
  }
  if (!sawIend) {
    throw new Error('icon.png: missing IEND chunk');
  }
  return { width, height, bitDepth, colorType };
}

export function inspectWebp(buf) {
  if (
    buf.length < 30 ||
    buf.subarray(0, 4).toString('ascii') !== 'RIFF' ||
    buf.subarray(8, 12).toString('ascii') !== 'WEBP'
  ) {
    throw new Error('showcase/cover.webp: invalid RIFF/WEBP header');
  }
  const declaredRiffSize = buf.readUInt32LE(4);
  if (declaredRiffSize + 8 > buf.length) {
    throw new Error('showcase/cover.webp: truncated RIFF payload');
  }
  const chunkType = buf.subarray(12, 16).toString('ascii');
  const chunkSize = buf.readUInt32LE(16);
  const payload = buf.subarray(20, 20 + chunkSize);
  if (payload.length < 10) {
    throw new Error(`showcase/cover.webp: truncated ${chunkType} chunk`);
  }

  let width = 0;
  let height = 0;
  if (chunkType === 'VP8 ') {
    if (payload[3] !== 0x9d || payload[4] !== 0x01 || payload[5] !== 0x2a) {
      throw new Error('showcase/cover.webp: invalid VP8 keyframe start code');
    }
    width = payload.readUInt16LE(6) & 0x3fff;
    height = payload.readUInt16LE(8) & 0x3fff;
  } else if (chunkType === 'VP8L') {
    if (payload[0] !== 0x2f) {
      throw new Error('showcase/cover.webp: invalid VP8L signature');
    }
    const bits = payload.readUInt32LE(1);
    width = (bits & 0x3fff) + 1;
    height = ((bits >>> 14) & 0x3fff) + 1;
  } else if (chunkType === 'VP8X') {
    width = (payload[4] | (payload[5] << 8) | (payload[6] << 16)) + 1;
    height = (payload[7] | (payload[8] << 8) | (payload[9] << 16)) + 1;
  } else {
    throw new Error(`showcase/cover.webp: unsupported WebP chunk ${chunkType}`);
  }
  if (width <= 0 || height <= 0) {
    throw new Error(`showcase/cover.webp: invalid dimensions ${width}x${height}`);
  }
  return { width, height, pixels: width * height, format: chunkType.trim() };
}

function validWebEntry(entry) {
  if (typeof entry !== 'string' || !entry || Buffer.byteLength(entry, 'utf8') > 512) return false;
  if (entry === '.' || entry === '..' || entry.startsWith('/') || /[\\\x00\r\n?#%:]/.test(entry)) return false;
  const parts = entry.split('/');
  if (parts.some((p) => !p || p === '.' || p === '..' || p.startsWith('.'))) return false;
  return entry.endsWith('.js') || entry.endsWith('.mjs');
}

function scanTemplateText(label, text) {
  const findings = [...scanText(label, text)];
  for (const rule of EXTRA_FORBIDDEN_PATTERNS) {
    if (rule.re.test(text)) {
      findings.push(`${label}: matched forbidden pattern "${rule.name}"`);
    }
  }
  return findings;
}

function validatePreviewHtml(bytes) {
  if (bytes.length === 0) {
    throw new Error('showcase/preview.html: empty file');
  }
  if (bytes.length > MAX_PREVIEW_BYTES) {
    throw new Error(`showcase/preview.html: exceeds ${MAX_PREVIEW_BYTES} bytes (${bytes.length})`);
  }
  const html = bytes.toString('utf8');
  if (!/<!doctype html>/iu.test(html) || !/<\/html>/iu.test(html)) {
    throw new Error('showcase/preview.html: missing <!doctype html> or </html>');
  }
  for (const rule of EXTERNAL_HTML_PATTERNS) {
    if (rule.re.test(html)) {
      throw new Error(`showcase/preview.html: not self-contained (matched "${rule.name}")`);
    }
  }
}

export function verifyInstallZip(zipBytes) {
  const rawZip = Buffer.isBuffer(zipBytes) ? zipBytes : Buffer.from(zipBytes);
  if (rawZip.length > MAX_INSTALL_ZIP_BYTES) {
    throw new Error(`install.zip exceeds 32 MiB (${rawZip.length} bytes)`);
  }

  const outer = parseZip(rawZip, 'install.zip');
  const requiredTop = [
    'install.json',
    'site.tweb',
    'source.zip',
    'icon.png',
    'showcase/cover.webp',
    'showcase/preview.html',
    'showcase/prompt.md',
  ];
  for (const name of requiredTop) {
    if (!Object.hasOwn(outer.files, name)) {
      throw new Error(`install.zip: missing required entry ${name}`);
    }
    if (outer.files[name].length > MAX_FILE_BYTES) {
      throw new Error(`install.zip: entry ${name} exceeds 16 MiB`);
    }
  }
  if (outer.files['install.json'].length > MAX_INSTALL_JSON_BYTES) {
    throw new Error('install.json exceeds 1 MiB');
  }

  const manifest = JSON.parse(outer.files['install.json'].toString('utf8'));
  const metadata = manifest.metadata;
  if (!metadata || typeof metadata !== 'object') {
    throw new Error('install.json: missing metadata object');
  }
  for (const field of ['name', 'display_name', 'description']) {
    if (typeof metadata[field] !== 'string' || !metadata[field].trim()) {
      throw new Error(`metadata.${field}: requires a non-empty string`);
    }
  }
  if (typeof metadata.database_required !== 'boolean' || manifest.database_required !== metadata.database_required) {
    throw new Error('database_required must be a matching boolean in install.json and metadata');
  }
  if (!validWebEntry(manifest.entry)) {
    throw new Error(`install.json: invalid entry "${manifest.entry}"`);
  }

  // Validate site.tweb
  const siteBytes = outer.files['site.tweb'];
  if (siteBytes.length > MAX_SITE_BYTES) {
    throw new Error(`site.tweb exceeds 16 MiB (${siteBytes.length} bytes)`);
  }
  const site = parseZip(siteBytes, 'site.tweb');
  if (site.totalExpanded > MAX_SITE_BYTES || site.count > MAX_SITE_ENTRIES) {
    throw new Error('site.tweb exceeds Web archive resource budget');
  }
  for (const requiredSiteFile of ['web.yaml', `data/${manifest.entry}`, 'data/icon.png', 'data/remote-config.json']) {
    if (!Object.hasOwn(site.files, requiredSiteFile)) {
      throw new Error(`site.tweb: missing required entry ${requiredSiteFile}`);
    }
  }

  // Validate source.zip
  const source = parseZip(outer.files['source.zip'], 'source.zip');
  if (!Object.hasOwn(source.files, 'metadata.json')) {
    throw new Error('source.zip: missing metadata.json');
  }
  const sourceMetadata = JSON.parse(source.files['metadata.json'].toString('utf8'));
  if (JSON.stringify(sourceMetadata) !== JSON.stringify(metadata)) {
    throw new Error('source.zip metadata.json does not match install.json metadata');
  }

  // Validate cumulative archive budget (exact parity with MGR / pack-template.py)
  const cumulativeExpanded = outer.totalExpanded + site.totalExpanded + source.totalExpanded;
  const cumulativeEntries = outer.count + site.count + source.count;
  if (cumulativeExpanded > MAX_EXPANDED_BYTES || cumulativeEntries > MAX_CUMULATIVE_ENTRIES) {
    throw new Error(
      `install.zip exceeds cumulative extraction budget (${cumulativeExpanded} bytes, ${cumulativeEntries} entries)`,
    );
  }

  // Validate repositories, functions & placeholders
  const repositories = new Map();
  for (const repo of metadata.repositories ?? []) {
    if (!repo.key || repositories.has(repo.key) || !repo.path) {
      throw new Error('metadata.repositories: requires unique keys and valid paths');
    }
    const prefix = repo.path === '.' ? '' : `${repo.path}/`;
    if (!Object.keys(source.files).some((name) => name.startsWith(prefix))) {
      throw new Error(`source.zip: repository "${repo.key}" has no files under ${repo.path}`);
    }
    repositories.set(repo.key, prefix);
  }
  if (metadata.web_repository && !repositories.has(metadata.web_repository)) {
    throw new Error(`metadata.web_repository references undeclared repo "${metadata.web_repository}"`);
  }
  const fnKeys = new Set();
  for (const fn of metadata.functions ?? []) {
    if (!fn.key || fnKeys.has(fn.key) || !fn.name?.trim() || !repositories.has(fn.repository)) {
      throw new Error(`metadata.functions: invalid function declaration "${fn.key}"`);
    }
    fnKeys.add(fn.key);
    const dir = (fn.source_dir || '').replace(/\/+$/u, '');
    if (fn.source_dir !== '/' && (!dir.startsWith('/') || dir.includes('..'))) {
      throw new Error(`metadata.functions[${fn.key}]: invalid source_dir "${fn.source_dir}"`);
    }
    const fnPrefix = repositories.get(fn.repository) + (dir ? `${dir.slice(1)}/` : '');
    const goFiles = Object.keys(source.files).filter(
      (name) => name.startsWith(fnPrefix) && !name.slice(fnPrefix.length).includes('/') && name.endsWith('.go'),
    );
    if (!goFiles.length) {
      throw new Error(`source.zip: function "${fn.key}" missing Go entry source in ${fnPrefix}`);
    }
    if (!Object.hasOwn(source.files, `${fnPrefix}go.mod`)) {
      throw new Error(`source.zip: function "${fn.key}" missing go.mod in ${fnPrefix}`);
    }
    const mainGo = source.files[`${fnPrefix}main.go`]?.toString('utf8') ?? '';
    if (!mainGo.includes('package main') || !mainGo.includes('DSH_REMOTE_POLICY')) {
      throw new Error(`source.zip: function "${fn.key}" main.go missing expected Relay entry symbols`);
    }
  }

  // Check declared variables in source.zip
  const allVars = [...(metadata.variables ?? [])];
  for (const repo of metadata.repositories ?? []) {
    const prefix = repo.path === '.' ? '' : `${repo.path}/`;
    for (const v of repo.variables ?? []) {
      allVars.push({ ...v, files: (v.files ?? []).map((f) => `${prefix}${f}`) });
    }
  }
  const declaredLocations = new Map();
  for (const variable of allVars) {
    if (!variable.name || !variable.description?.trim() || !PLACEHOLDER_RE.test(variable.placeholder ?? '') || !variable.files?.length) {
      throw new Error(`metadata variable "${variable.name ?? ''}": invalid declaration`);
    }
    const locs = declaredLocations.get(variable.placeholder) ?? new Set();
    for (const file of variable.files) {
      if (!Object.hasOwn(source.files, file)) {
        throw new Error(`source.zip: variable "${variable.name}" references missing file ${file}`);
      }
      if (!source.files[file].includes(variable.placeholder)) {
        throw new Error(`source.zip: variable "${variable.name}" placeholder missing in ${file}`);
      }
      locs.add(file);
    }
    declaredLocations.set(variable.placeholder, locs);
  }
  for (const [name, bytes] of Object.entries(source.files)) {
    if (name === 'metadata.json' || BINARY_EXTS.has(path.posix.extname(name).toLowerCase())) continue;
    const text = bytes.toString('utf8');
    for (const found of text.match(PLACEHOLDER_GLOBAL_RE) ?? []) {
      const locs = declaredLocations.get(found);
      if (!locs) {
        throw new Error(`source.zip: undeclared placeholder ${found} in ${name}`);
      }
      if (!locs.has(name)) {
        throw new Error(`source.zip: unrecorded occurrence of ${found} in ${name}`);
      }
    }
  }

  // Check site_variables in site.tweb
  for (const variable of metadata.site_variables ?? []) {
    if (!PLACEHOLDER_RE.test(variable.placeholder ?? '') || !variable.files?.length) {
      throw new Error(`site_variables "${variable.name ?? ''}": invalid declaration`);
    }
    for (const file of variable.files) {
      const sitePath = `data/${file}`;
      if (!Object.hasOwn(site.files, sitePath) || !site.files[sitePath].includes(variable.placeholder)) {
        throw new Error(`site.tweb: placeholder ${variable.placeholder} missing in ${sitePath}`);
      }
    }
  }

  // Validate icon.png (256x256 RGBA PNG) and byte equality across all 3 layers
  const iconPng = outer.files['icon.png'];
  const iconInfo = inspectPng(iconPng);
  if (
    iconInfo.width !== REQUIRED_ICON_SIZE ||
    iconInfo.height !== REQUIRED_ICON_SIZE ||
    iconInfo.colorType !== 6 ||
    iconInfo.bitDepth !== 8
  ) {
    throw new Error(
      `icon.png must be ${REQUIRED_ICON_SIZE}x${REQUIRED_ICON_SIZE} 8-bit RGBA PNG (got ${iconInfo.width}x${iconInfo.height}, colorType=${iconInfo.colorType}, bitDepth=${iconInfo.bitDepth})`,
    );
  }
  if (!iconPng.equals(site.files['data/icon.png'])) {
    throw new Error('icon.png in install.zip differs from site.tweb data/icon.png');
  }
  if (!iconPng.equals(source.files['repositories/app/icon.png'])) {
    throw new Error('icon.png in install.zip differs from source.zip repositories/app/icon.png');
  }

  // Validate showcase/cover.webp (pixels <= 2,097,152) and parity with source.zip
  const coverWebp = outer.files['showcase/cover.webp'];
  const coverInfo = inspectWebp(coverWebp);
  if (coverInfo.pixels > MAX_COVER_PIXELS) {
    throw new Error(
      `showcase/cover.webp decoded pixels (${coverInfo.pixels}) exceed limit ${MAX_COVER_PIXELS}`,
    );
  }
  if (!coverWebp.equals(source.files['showcase/cover.webp'])) {
    throw new Error('showcase/cover.webp in install.zip differs from source.zip');
  }

  // Validate showcase/preview.html and showcase/prompt.md
  validatePreviewHtml(outer.files['showcase/preview.html']);
  if (!outer.files['showcase/preview.html'].equals(source.files['showcase/preview.html'])) {
    throw new Error('showcase/preview.html in install.zip differs from source.zip');
  }
  const promptText = outer.files['showcase/prompt.md'].toString('utf8');
  if (!promptText.trim()) {
    throw new Error('showcase/prompt.md must not be empty');
  }
  if (!outer.files['showcase/prompt.md'].equals(source.files['showcase/prompt.md'])) {
    throw new Error('showcase/prompt.md in install.zip differs from source.zip');
  }

  // Scan ALL text entries across all 3 layers for personal/sensitive leakage
  const scanFindings = [];
  const scanLayer = (prefix, map) => {
    for (const [name, bytes] of Object.entries(map)) {
      if (BINARY_EXTS.has(path.posix.extname(name).toLowerCase())) continue;
      scanFindings.push(...scanTemplateText(`${prefix}:${name}`, bytes.toString('utf8')));
    }
  };
  scanLayer('install.zip', outer.files);
  scanLayer('site.tweb', site.files);
  scanLayer('source.zip', source.files);
  if (scanFindings.length > 0) {
    throw new Error(`Sensitive/forbidden content detected in template package:\n${scanFindings.join('\n')}`);
  }

  return {
    name: metadata.name,
    display_name: metadata.display_name,
    description: metadata.description,
    entry: manifest.entry,
    database_required: manifest.database_required,
    has_source: true,
    size: rawZip.length,
    sha256: createHash('sha256').update(rawZip).digest('hex'),
    site_tweb_bytes: siteBytes.length,
    source_zip_bytes: outer.files['source.zip'].length,
    preview_html_bytes: outer.files['showcase/preview.html'].length,
    expanded_bytes: cumulativeExpanded,
    entries: cumulativeEntries,
    cover: coverInfo,
    icon: iconInfo,
    top_level_files: Object.keys(outer.files).sort(),
    site_files: Object.keys(site.files).sort(),
    source_files: Object.keys(source.files).sort(),
  };
}

function readGitCommit(repoRoot) {
  try {
    const out = execFileSync('git', ['rev-parse', '--verify', 'HEAD^{commit}'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return /^[0-9a-f]{40}$/u.test(out) ? out : null;
  } catch {
    return null;
  }
}

function prepareTemplateRelayMainGo(rawMainGo) {
  const target = 'var defaultWebID = ""';
  const replacement = `var defaultWebID = "${WEB_ID_PLACEHOLDER}"`;
  const parts = rawMainGo.split(target);
  if (parts.length !== 2) {
    throw new Error(
      `relay-go/main.go must contain exactly one "${target}" declaration (found ${parts.length - 1})`,
    );
  }
  const transformed = parts.join(replacement);
  if (transformed.split(replacement).length !== 2) {
    throw new Error('Failed to inject template WEB_ID placeholder cleanly into relay-go/main.go');
  }
  return Buffer.from(transformed, 'utf8');
}

export function packMarketTemplate({ repoRoot = projectRoot, outPath } = {}) {
  const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
  const templateDir = path.join(repoRoot, 'template');
  const templateAppDir = path.join(templateDir, 'app');
  const webSrcDir = path.join(repoRoot, 'web-src');
  const relayGoDir = path.join(repoRoot, 'relay-go');

  const metadata = JSON.parse(readFileSync(path.join(templateDir, 'metadata.json'), 'utf8'));
  const commit = readGitCommit(repoRoot);
  if (commit) {
    metadata.source = {
      repository: 'https://github.com/tianacloud/dsh-remote',
      commit,
    };
  }

  const iconBytes = readFileSync(path.join(templateDir, 'icon.png'));
  const coverBytes = readFileSync(path.join(templateDir, 'showcase', 'cover.webp'));
  const previewBytes = readFileSync(path.join(templateDir, 'showcase', 'preview.html'));
  const promptBytes = readFileSync(path.join(templateDir, 'showcase', 'prompt.md'));
  const templateReadmeBytes = readFileSync(path.join(templateDir, 'README.md'));
  const remoteConfigRaw = readFileSync(path.join(templateAppDir, 'remote-config.json'), 'utf8');
  const remoteConfig = JSON.parse(remoteConfigRaw);

  // Assemble source.zip directly from single-source-of-truth repo directories (zero copy drift)
  const sourceEntries = {
    'metadata.json': Buffer.from(`${JSON.stringify(metadata, null, 2)}\n`, 'utf8'),
    'README.md': templateReadmeBytes,
    'showcase/cover.webp': coverBytes,
    'showcase/preview.html': previewBytes,
    'showcase/prompt.md': promptBytes,
    'repositories/app/.gitignore': readFileSync(path.join(templateAppDir, '.gitignore')),
    'repositories/app/README.md': readFileSync(path.join(templateAppDir, 'README.md')),
    'repositories/app/build.mjs': readFileSync(path.join(templateAppDir, 'build.mjs')),
    'repositories/app/package.json': readFileSync(path.join(templateAppDir, 'package.json')),
    'repositories/app/package-lock.json': readFileSync(path.join(templateAppDir, 'package-lock.json')),
    'repositories/app/icon.png': iconBytes,
    'repositories/app/remote-config.json': Buffer.from(remoteConfigRaw, 'utf8'),
    'repositories/app/functions/relay/go.mod': readFileSync(path.join(relayGoDir, 'go.mod')),
    'repositories/app/functions/relay/main.go': prepareTemplateRelayMainGo(
      readFileSync(path.join(relayGoDir, 'main.go'), 'utf8'),
    ),
  };

  const webModules = readdirSync(webSrcDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && /\.(mjs|js)$/u.test(entry.name))
    .map((entry) => entry.name)
    .sort();
  if (!webModules.includes(FIXED_ENTRY)) {
    throw new Error(`Missing web-src/${FIXED_ENTRY}`);
  }
  for (const mod of webModules) {
    sourceEntries[`repositories/app/web-src/${mod}`] = readFileSync(path.join(webSrcDir, mod));
  }

  const sourceZipBytes = createZip(sourceEntries);

  // Build site.tweb using the canonical buildWebDist() helper + template icon.png in a temporary directory
  const scratchDir = mkdtempSync(path.join(tmpdir(), 'dsh-remote-market-dist-'));
  let siteTwebBytes;
  let siteIconBytes;
  try {
    buildWebDist({
      outDir: scratchDir,
      config: {
        functionId: remoteConfig.functionId,
        webId: remoteConfig.webId,
        defaultHostId: remoteConfig.defaultHostId || '',
        appTitle: remoteConfig.appTitle || 'dsh-tiana-remote',
        localRelayUrl: '',
      },
      clean: true,
    });
    cpSync(path.join(templateDir, 'icon.png'), path.join(scratchDir, 'icon.png'));

    const siteEntries = { 'web.yaml': Buffer.alloc(0) };
    const walkDist = (rel = '') => {
      const dir = rel ? path.join(scratchDir, rel) : scratchDir;
      for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
        const nextRel = rel ? `${rel}/${entry.name}` : entry.name;
        const abs = path.join(scratchDir, nextRel);
        if (entry.isDirectory()) {
          walkDist(nextRel);
        } else if (entry.isFile()) {
          siteEntries[`data/${nextRel}`] = readFileSync(abs);
        } else {
          throw new Error(`Non-regular file in dist: ${nextRel}`);
        }
      }
    };
    walkDist();
    siteIconBytes = siteEntries['data/icon.png'];
    siteTwebBytes = createZip(siteEntries);
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }

  const installManifest = {
    metadata,
    entry: FIXED_ENTRY,
    database_required: metadata.database_required,
    variables: [],
  };
  for (const key of ['private_database', 'web_repository', 'repositories', 'functions', 'site_variables']) {
    if (metadata[key] !== undefined) {
      installManifest[key] = metadata[key];
    }
  }

  const installEntries = {
    'install.json': Buffer.from(`${JSON.stringify(installManifest, null, 2)}\n`, 'utf8'),
    'site.tweb': siteTwebBytes,
    'source.zip': sourceZipBytes,
    'icon.png': siteIconBytes,
    'showcase/cover.webp': coverBytes,
    'showcase/preview.html': previewBytes,
    'showcase/prompt.md': promptBytes,
  };

  const installZipBytes = createZip(installEntries);
  // Fail-closed: run full MGR verification BEFORE writing output artifact
  const verification = verifyInstallZip(installZipBytes);

  const resolvedOut = path.resolve(
    outPath || path.join(repoRoot, 'dist', 'market-template', `${metadata.name}-${pkg.version}.install.zip`),
  );
  mkdirSync(path.dirname(resolvedOut), { recursive: true });
  const tempOut = `${resolvedOut}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tempOut, installZipBytes);
  renameSync(tempOut, resolvedOut);

  const stat = statSync(resolvedOut);
  return {
    ...verification,
    version: pkg.version,
    file: resolvedOut,
    size: stat.size,
  };
}

function parseCliArgs(argv) {
  let outPath = null;
  let verifyPath = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--out' || arg === '--output' || arg === '-o') {
      outPath = argv[++i];
      if (!outPath) throw new Error(`${arg} requires a file path`);
    } else if (arg.startsWith('--out=')) {
      outPath = arg.slice('--out='.length);
    } else if (arg.startsWith('--output=')) {
      outPath = arg.slice('--output='.length);
    } else if (arg === '--verify-only') {
      verifyPath = argv[++i];
      if (!verifyPath) throw new Error('--verify-only requires a file path');
    } else if (arg === '--help' || arg === '-h') {
      console.log(
        [
          'Usage: node scripts/pack-market-template.mjs [--out <path>] [--verify-only <zip>]',
          '',
          'Packages the self-contained DSH Remote unified market template (.install.zip)',
          'directly from web-src/, relay-go/, and template/ with full MGR verification.',
        ].join('\n'),
      );
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return { outPath, verifyPath };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { outPath, verifyPath } = parseCliArgs(process.argv.slice(2));
    if (verifyPath) {
      const resolved = path.resolve(verifyPath);
      if (!existsSync(resolved)) throw new Error(`File not found: ${resolved}`);
      const report = verifyInstallZip(readFileSync(resolved));
      console.log(JSON.stringify({ file: resolved, valid: true, ...report }, null, 2));
    } else {
      const result = packMarketTemplate({ outPath });
      console.log(JSON.stringify(result, null, 2));
    }
  } catch (error) {
    console.error(`[pack-market-template] ${error.message}`);
    process.exitCode = 1;
  }
}
