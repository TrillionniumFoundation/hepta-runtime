#!/usr/bin/env node
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Produce authored inert fixtures with the actual pinned @electron/asar writer,
// then compare its independent consumer against the authored byte inventory.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const [packageRoot, output] = process.argv.slice(2);
assert(packageRoot && output && path.isAbsolute(packageRoot) && path.isAbsolute(output),
  'usage: node rea-asar-reference.mjs ABSOLUTE_ASAR_PACKAGE ABSOLUTE_NEW_OUTPUT');
const metadata = JSON.parse(await fs.readFile(path.join(packageRoot, 'package.json'), 'utf8'));
assert.equal(metadata.name, '@electron/asar');
assert.equal(metadata.version, '4.2.0', 'reference version is frozen, never silently upgraded');
const asar = await import(pathToFileURL(path.join(packageRoot, 'lib/asar.js')).href);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
await fs.mkdir(output, {mode: 0o700});
const sourceRoot = path.join(output, 'authored');
await fs.mkdir(sourceRoot, {mode: 0o700});
for (const name of ['assets', 'src']) await fs.mkdir(path.join(sourceRoot, name), {mode: 0o700});
const marker = path.join(output, 'must-never-execute');
const block = 4 * 1024 * 1024;
const exact = Buffer.alloc(block);
const plus = Buffer.alloc(block + 37);
for (let i = 0; i < exact.length; i++) exact[i] = i % 251;
for (let i = 0; i < plus.length; i++) plus[i] = (i * 7) % 256;
const authored = new Map([
  ['package.json', Buffer.from('{"name":"hepta-owned-asar-fixture","version":"1.0.0","type":"module","main":"src/main.js"}\n')],
  ['src/main.js', Buffer.from(`import {value} from './util.js';\nimport {ipcMain} from 'electron';\nipcMain.handle('fixture:get', () => value);\nexport const answer = value;\nrequire('node:fs').writeFileSync(${JSON.stringify(marker)}, 'MUST NOT EXECUTE');\n`)],
  ['src/util.js', Buffer.from('export const value = 7;\n')],
  ['src/preload.cjs', Buffer.from("const {ipcRenderer} = require('electron');\nipcRenderer.invoke('fixture:get');\n")],
  ['src/λ.js', Buffer.from('export const label = "雪";\n')],
  ['empty.txt', Buffer.alloc(0)],
  ['assets/binary.bin', Buffer.from([0, 255, 1, 10, 128, 254])],
  ['assets/external.bin', Buffer.from([9, 8, 7, 6])],
  ['assets/block-exact.bin', exact],
  ['assets/block-plus.bin', plus],
]);
for (const [name, bytes] of authored) await fs.writeFile(path.join(sourceRoot, name), bytes, {mode: 0o600, flag: 'wx'});
await fs.symlink('src/main.js', path.join(sourceRoot, 'alias.js'));
await fs.symlink('src', path.join(sourceRoot, 'alias-dir'));
const names = ['assets', 'src', 'alias.js', 'alias-dir', ...authored.keys()]
  .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
const archive = path.join(output, 'app.asar');
await asar.createPackageFromFiles(sourceRoot, archive, names.map(n => path.join(sourceRoot, n)), {}, {unpack: '**/external.bin'});
asar.uncacheAll();
const raw = asar.getRawHeader(archive);
const archiveBytes = await fs.readFile(archive);
const listed = asar.listPackage(archive).map(n => n.replace(/^\//, ''));
assert.deepEqual([...listed].sort(), [...names].sort(), 'producer inventory must match authored names');
const entries = [];
for (const name of listed) {
  const info = asar.statFile(archive, name, false);
  const kind = 'files' in info ? 'directory' : 'link' in info ? 'link' : info.unpacked ? 'unpacked_file' : 'packed_file';
  const row = {
    path: name, kind, size_bytes: info.size ?? null,
    relative_data_offset: info.offset === undefined ? null : Number(info.offset),
    unpacked: !!info.unpacked, executable_declaration: !!info.executable,
    link_target: info.link ?? null, integrity: info.integrity ?? null,
  };
  if (kind === 'packed_file' || kind === 'unpacked_file') {
    const expected = authored.get(name);
    assert(expected, `missing independently authored bytes for ${name}`);
    const observed = asar.extractFile(archive, name, false);
    assert.deepEqual(observed, expected, `upstream consumer differs from authored bytes: ${name}`);
    row.sha256 = sha(expected);
    row.ranges = [...new Set([0, Math.max(0, expected.length - 9), Math.max(0, Math.min(block - 2, expected.length))])]
      .map(offset => ({offset, length: 17, bytes_hex: expected.subarray(offset, offset + 17).toString('hex')}));
  }
  entries.push(row);
}
entries.sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
const sourceIdentities = {};
for (const name of ['package.json','lib/asar.js','lib/disk.js','lib/pickle.js','lib/filesystem.js','lib/integrity.js']) {
  const bytes = await fs.readFile(path.join(packageRoot, name));
  sourceIdentities[name] = {sha256:sha(bytes), bytes:bytes.length};
}
const report = {
  schema:'hepta.asar-reference.v1', producer_consumer:'@electron/asar@4.2.0', node:process.version,
  package_root:packageRoot, package_sources:sourceIdentities,
  generator_sha256:sha(await fs.readFile(fileURLToPath(import.meta.url))),
  archive:{path:archive, sha256:sha(archiveBytes), bytes:archiveBytes.length,
    header_bytes:8 + raw.headerSize, header_sha256:sha(archiveBytes.subarray(0, 8 + raw.headerSize)),
    header_sha256_scope:'complete_pickle_header',
    electron_json_header_sha256:sha(Buffer.from(raw.headerString, 'utf8'))},
  authored_root:sourceRoot, execution_marker:marker, entries,
  graph_sources:[
    {id:'src/main.js', member:'src/main.js', syntax:'javascript', module_kind:'module'},
    {id:'src/preload.cjs', member:'src/preload.cjs', syntax:'javascript', module_kind:'commonjs'},
    {id:'src/util.js', member:'src/util.js', syntax:'javascript', module_kind:'module'},
  ],
  source_bytes_unchanged:true, target_code_executed:false,
};
await fs.writeFile(path.join(output,'upstream-header.json'), JSON.stringify(raw.header, null, 2)+'\n', {flag:'wx',mode:0o600});
await fs.writeFile(path.join(output,'reference.json'), JSON.stringify(report, null, 2)+'\n', {flag:'wx',mode:0o600});
console.log(JSON.stringify({reference:path.join(output,'reference.json'), archive_sha256:report.archive.sha256,
  entries:entries.length, packed:entries.filter(x=>x.kind==='packed_file').length}));
