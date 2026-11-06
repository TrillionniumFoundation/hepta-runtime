#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Capture original Service failures through the original public error projector.

Existing refused APK corpus members are reused and a few owned framing failures
cover producer boundaries not present in that corpus. All ordinary fixtures are
small; the file-size refusal uses an explicitly owned sparse file. The native
runtime must compare these complete projected errors in its own qualification.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import time
import zipfile


FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
NODE = r'''
import {readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const request=JSON.parse(readFileSync(0,'utf8'));
const get=path=>import(pathToFileURL(request.root+'/'+path).href);
const {ApkSignatureProvider}=await get('dist/apkSignature/ApkSignatureProvider.js');
const {ApkSignatureService}=await get('dist/application/apkSignature/ApkSignatureService.js');
const {projectAnalysisError}=await get('dist/domain/analysisErrorProjection.js');
const provider=new ApkSignatureProvider();
let calls=0;
const service=new ApkSignatureService({inspect:(input,options)=>{calls++;return provider.inspect(input,options);},close:()=>provider.close()});
const rows=[];
try {
 for(const entry of request.cases){
  const before=calls,input={path:entry.path,detail:'complete'};
  let records=0;
  const result=await service.inspect(input,undefined,{recordEvidence:()=>{records++;return {ok:true,value:undefined};},evidenceById:()=>undefined});
  assert.equal(result.ok,false,entry.name+' must be an original producer refusal');
  assert.equal(calls-before,1);assert.equal(records,0);
  if(entry.expected_tag!==null)assert.equal(result.error._tag,entry.expected_tag,entry.name);
  const projected=projectAnalysisError(result.error);
  const row={name:entry.name,input,fixture:entry.path,fixture_sha256:entry.sha256,fixture_bytes:entry.bytes,
   source:entry.source,typed_error:Object.fromEntries(Object.entries(result.error).filter(([key])=>key!=='cause')),
   expected:projected,provider_calls:1,record_calls:0};
  writeFileSync(request.out+'/cases/'+entry.name+'.json',JSON.stringify(row,null,2)+'\n');
  rows.push(row);
 }
}finally{await service.close();}
writeFileSync(request.out+'/errors.json',JSON.stringify(rows,null,2)+'\n');
process.stdout.write(JSON.stringify({node:process.version,openssl:process.versions.openssl,cases:rows.length,
 rows:rows.map(row=>({name:row.name,tag:row.typed_error._tag,code:row.expected.code,resource:row.expected.details?.resource??null}))})+'\n');
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def additions(repo):
    seed = (repo / 'tests/fixtures/rea_apk_signature/custom-0103-rsa.apk').read_bytes()
    end = seed.rindex(b'PK\x05\x06')
    central = struct.unpack_from('<I', seed, end + 16)[0]
    assert seed[central - 16:central] == b'APK Sig Block 42'
    start = central - struct.unpack_from('<Q', seed, central - 24)[0] - 8
    result = {'owned-empty': b'', 'owned-nonzip-without-eocd': b'owned non-ZIP bytes'.ljust(40, b'x')}

    def member(archive, name, data):
        entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_STORED
        archive.writestr(entry, data)

    def changed(name, position, data):
        value = bytearray(seed)
        value[position:position + len(data)] = data
        result[name] = bytes(value)

    changed('owned-block-size-mismatch', start, struct.pack('<Q', 24))
    changed('owned-block-pair-too-short', start + 8, struct.pack('<Q', 3))
    changed('owned-central-signature-damage', central, b'BAD!')
    changed('owned-central-name-overrun', central + 28, struct.pack('<H', 65535))
    changed('owned-eocd-extent-overlap', end + 12, struct.pack('<I', end - central + 1))
    entries = io.BytesIO()
    with zipfile.ZipFile(entries, 'w', compression=zipfile.ZIP_STORED) as archive:
        member(archive, 'META-INF/MANIFEST.MF', b'')
        for index in range(33):
            member(archive, f'META-INF/KEY{index}.SF', b'')
            member(archive, f'META-INF/KEY{index}.RSA', b'')
    result['owned-v1-33-paired-signers'] = entries.getvalue()
    simple = io.BytesIO()
    with zipfile.ZipFile(simple, 'w', compression=zipfile.ZIP_STORED) as archive:
        member(archive, 'payload', b'public fixture')
    value = simple.getvalue()
    eocd = value.rindex(b'PK\x05\x06')
    count, size, offset = struct.unpack_from('<HII', value, eocd + 10)
    record = struct.pack('<4sQHHIIQQQQ', b'PK\x06\x06', 44, 45, 45, 0, 0, count, count, size, offset)
    ending = bytearray(value[eocd:])
    struct.pack_into('<HHII', ending, 8, 65535, 65535, 0xffffffff, 0xffffffff)
    for disks, name in [(0, 'owned-zip64-zero-disks'), (2, 'owned-zip64-multiple-disks')]:
        locator = struct.pack('<4sIQI', b'PK\x06\x07', 0, eocd, disks)
        result[name] = value[:eocd] + record + locator + ending
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--rea-install', type=Path, required=True)
    parser.add_argument('--rea-tarball', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    package = args.rea_tarball.read_bytes()
    assert sha(package) == FROZEN_PACKAGE
    checked = 0
    with tarfile.open(fileobj=io.BytesIO(package), mode='r:gz') as archive:
        for member in archive:
            if member.isfile():
                assert member.name.startswith('package/') and '..' not in Path(member.name).parts
                assert (args.rea_install / member.name.removeprefix('package/')).read_bytes() == archive.extractfile(member).read()
                checked += 1
    fixtures = args.out / 'fixtures'
    fixtures.mkdir()
    (args.out / 'cases').mkdir()
    manifest = {row['name']:row for row in json.loads((args.corpus / 'cases.json').read_text())}
    reference = json.loads((args.corpus / 'rea.stdout.json').read_text())
    cases = []
    for row in reference:
        if row['ok']:
            continue
        previous = manifest[row['name']]
        path = fixtures / (row['name'] + '.apk')
        shutil.copyfile(previous['path'], path)
        assert path.stat().st_size == previous['bytes'] and file_sha(path) == previous['sha256']
        cases.append(dict(name=row['name'], path=str(path), bytes=previous['bytes'], sha256=previous['sha256'],
                          source=previous['path'], expected_tag=row['error']['_tag']))
    reused = len(cases)
    assert reused == 14
    extra = additions(args.repo)
    for name, data in extra.items():
        path = fixtures / (name + '.apk')
        path.write_bytes(data)
        cases.append(dict(name=name, path=str(path), bytes=len(data), sha256=sha(data),
                          source='owned framing mutation or ZIP constructor in this script', expected_tag=None))
    sparse = fixtures / 'owned-file-size-512mib-plus-one.apk'
    with sparse.open('xb') as stream:
        stream.truncate(512 * 1024 * 1024 + 1)
    cases.append(dict(name=sparse.stem, path=str(sparse), bytes=sparse.stat().st_size, sha256=file_sha(sparse),
                      source='owned sparse all-zero file; size checked by real provider',
                      expected_tag='AnalysisResourceConstraintError'))
    for row in cases:
        Path(row['path']).chmod(0o400)
    request = dict(root=str(args.rea_install), out=str(args.out), cases=cases)
    data = json.dumps(request, separators=(',', ':')).encode()
    (args.out / 'request.json').write_bytes(data)
    (args.out / 'runner.mjs').write_text(NODE)
    argv = ['node', str(args.out / 'runner.mjs')]
    started = time.monotonic()
    result = subprocess.run(argv, input=data, capture_output=True, timeout=90, cwd='/', env={})
    (args.out / 'reference.stdout.json').write_bytes(result.stdout)
    (args.out / 'reference.stderr.log').write_bytes(result.stderr)
    receipt = dict(argv=argv, timeout_seconds=90, exit_code=result.returncode, seconds=time.monotonic() - started,
                   stdin_sha256=sha(data), stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
    (args.out / 'reference.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    output = json.loads(result.stdout)
    assert output['cases'] == len(cases)
    sources = ['dist/application/apkSignature/ApkSignatureService.js', 'dist/apkSignature/ApkSignatureProvider.js',
               'dist/apkSignature/apkSignatureFailures.js', 'dist/domain/analysisErrorProjection.js',
               'dist/domain/analysisErrorPresentation.js']
    summary = dict(format='hepta.apk-service-projected-errors.v1', passed=True, cases=len(cases),
                   reused_corpus_failures=reused, additional_owned_cases=len(extra) + 1,
                   frozen_npm_tarball_sha256=FROZEN_PACKAGE, frozen_install_files_checked=checked,
                   oracle_node=output['node'], oracle_openssl=output['openssl'], receipt=receipt,
                   upstream_sources={name:sha((args.rea_install / name).read_bytes()) for name in sources},
                   golden_sha256=file_sha(args.out / 'errors.json'), golden_bytes=(args.out / 'errors.json').stat().st_size,
                   fixture_identities=cases, sparse_file_allocated_bytes=sparse.stat().st_blocks * 512,
                   runtime_release_qualified=False,
                   comparison='Every field produced by the actual projectAnalysisError after the actual APK Service/provider refusal; no tag-only/resource-only projection.',
                   scope='Finite original reference only. Native parent mapping, file-read admission policy and actual worker lifecycle require independent native gates.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key:summary[key] for key in ['passed','cases','reused_corpus_failures','additional_owned_cases','golden_sha256','golden_bytes','sparse_file_allocated_bytes']}), flush=True)


if __name__ == '__main__':
    main()
