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

"""Real-path, exact-wire APK output boundary against frozen npm REA 6.8.0.

All paths and archives are generated below one new owned output directory. The
native mini mode calls production parser/binder functions, while runtime mode
uses the actual framed static worker. Neither mode installs or executes an APK.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import time


LIMIT = 8 * 1024 * 1024
FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
NODE = r'''
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(readFileSync(0,'utf8'));
const {ApkSignatureProvider}=await import(pathToFileURL(input.root+'/dist/apkSignature/ApkSignatureProvider.js').href);
const provider=new ApkSignatureProvider(),rows=[];
try {for(const path of input.paths){
 const result=await provider.inspect({path});
 if(result.ok){const value={result:result.value.result,limitations:result.value.limitations};
  rows.push({path,ok:true,value,serialized_bytes:Buffer.byteLength(JSON.stringify(value)),
   empty_path_bytes:Buffer.byteLength(JSON.stringify({...value,result:{...value.result,artifact:{...value.result.artifact,path:''}}}))});
 }else{const e=result.error;rows.push({path,ok:false,error:{_tag:e._tag,operation:e.operation,resource:e.resource,reason:e.reason,reportedLimits:e.reportedLimits}});}
}}finally{await provider.close();}
process.stdout.write(JSON.stringify(rows));
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


def invoke(out, name, argv, stdin):
    started = time.monotonic()
    result = subprocess.run(argv, input=stdin, capture_output=True, timeout=90, cwd='/', env={})
    (out / (name + '.stdout.json')).write_bytes(result.stdout)
    (out / (name + '.stderr.log')).write_bytes(result.stderr)
    receipt = dict(argv=argv, exit_code=result.returncode, timeout_seconds=90,
                   seconds=time.monotonic() - started, stdin_sha256=sha(stdin),
                   stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
    (out / (name + '.receipt.json')).write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return json.loads(result.stdout)


def boundary_path(root, escaped_bytes):
    """Use real quoted filenames to reach JSON size without exceeding PATH_MAX."""
    root.mkdir(parents=True, exist_ok=True)
    while True:
        prefix = len(json_bytes(str(root) + '/')) - 2
        remaining = escaped_bytes - prefix - len('.apk')
        assert remaining >= 0
        if remaining <= 400:
            name = '"' * (remaining // 2) + ('a' if remaining % 2 else '') + '.apk'
            result = root / name
            assert len(result.name.encode()) <= 255 and len(str(result).encode()) < 4096
            assert len(json_bytes(str(result))) - 2 == escaped_bytes
            return result
        root = root / ('"' * 200)
        root.mkdir(exist_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mode', choices=['minimal-crate', 'runtime'], required=True)
    parser.add_argument('--repo', type=Path, required=True)
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
    generator_path = args.repo / 'scripts/qualify_apk_observations.py'
    spec = importlib.util.spec_from_file_location('apk_owned_fixture_generator', generator_path)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    seed = (args.repo / 'tests/fixtures/rea_apk_signature/custom-0103-rsa.apk').read_bytes()
    cert = generator.first_certificate(seed)
    pair = next(value for ident, value in generator.block_pairs(seed) if ident == generator.V2)
    signer = generator.raw_signer(generator.elements(generator.take(pair)[0])[0], False)
    fixed = 4096 + 256 + 512 + 256 + 4 * len(cert) + 160 + 160 * len(signer['signatures'])
    digest = struct.pack('<I', 0xffffffff) + generator.lp(b'\0' * ((LIMIT - fixed) // 2))
    data = generator.change_signers(seed, generator.V2, lambda signers: signers[0].update(digests=[digest]))
    short = args.out / 'short.apk'
    short.write_bytes(data)
    probe = invoke(args.out, 'probe', ['node', '--input-type=module', '-e', NODE],
                   json_bytes(dict(root=str(args.rea_install), paths=[str(short)])))[0]
    assert probe['ok'] and probe['serialized_bytes'] < LIMIT
    empty_bytes = probe['empty_path_bytes']
    records = [dict(name='short', path=short, expected_bytes=probe['serialized_bytes'])]
    for name, delta, prefix in [('minus-one', -1, 'quoted'), ('exact', 0, 'quoted'),
                                ('plus-one', 1, 'quoted'), ('utf8-exact', 0, 'utf8-\U00010000'),
                                ('utf8-plus-one', 1, 'utf8-\U00010000')]:
        path = boundary_path(args.out / prefix, LIMIT + delta - empty_bytes)
        with path.open('xb') as stream:
            stream.write(data)
        records.append(dict(name=name, path=path, expected_bytes=LIMIT + delta))
    manifest = [dict(name=row['name'], path=str(row['path']), raw_path_utf8_bytes=len(str(row['path']).encode()),
                     encoded_path_json_bytes=len(json_bytes(str(row['path']))), expected_bytes=row['expected_bytes'],
                     sha256=sha(data), bytes=len(data)) for row in records]
    (args.out / 'cases.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    oracle = invoke(args.out, 'reference', ['node', '--input-type=module', '-e', NODE],
                    json_bytes(dict(root=str(args.rea_install), paths=[row['path'] for row in manifest])))
    results, failures = [], []
    for row, expected in zip(manifest, oracle):
        assert row['path'] == expected['path']
        if args.mode == 'runtime':
            argv = [str(args.binary), 'rea-apk-static-worker']
            header = json_bytes(dict(input=dict(path=row['path']), sha256=row['sha256'], bytes=row['bytes']))
            stdin = struct.pack('<I', len(header)) + header + data
        else:
            argv, stdin = [str(args.binary), '--bind-static', row['path']], data
        actual = invoke(args.out, row['name'] + '.native', argv, stdin)
        if args.mode == 'runtime':
            actual = (dict(ok=False, error=actual['failure']) if 'failure' in actual else
                      dict(ok=True, value=dict(result=actual['report'], limitations=actual['limitations'])))
        if expected['ok']:
            assert expected['serialized_bytes'] == row['expected_bytes'] <= LIMIT
            matched = actual == dict(ok=True, value=expected['value'])
        else:
            assert row['expected_bytes'] == LIMIT + 1
            error = actual.get('error', {})
            normalized = dict(_tag=error.get('_tag'), operation=error.get('operation'), resource=error.get('resource'),
                              reason=error.get('reason'), reportedLimits=error.get('reported_limits'))
            matched = actual['ok'] is False and normalized == expected['error']
        results.append(dict(name=row['name'], passed=matched, native_outcome=actual['ok'], reference_outcome=expected['ok'],
                            expected_serialized_bytes=row['expected_bytes']))
        if not matched:
            failures.append(row['name'])
            print('DIFFERENCE', row['name'], 'native', actual.get('error', actual['ok']), 'reference', expected.get('error', expected['ok']), flush=True)
    sources = ['rea_apk_signature.rs', 'rea_apk_signature_observation.rs', 'rea_apk_signature_observation_tests.rs']
    summary = dict(format='hepta.apk-bound-path-budget-qualification.v1', mode=args.mode,
                   binary_sha256=sha(args.binary.read_bytes()), frozen_npm_tarball_sha256=FROZEN_PACKAGE,
                   frozen_install_files_checked=checked, generator_sha256=sha(generator_path.read_bytes()),
                   source_sha256={name:sha((args.repo / 'src/mcp' / name).read_bytes()) for name in sources},
                   corpus_cases=len(records), matched=len(records) - len(failures), failures=failures, results=results,
                   runtime_release_qualified=args.mode == 'runtime' and not failures,
                   comparison='Complete report/limitations on success; exact output-budget tag, operation, reason, resource and fixed limits on failure.',
                   scope='Actual filesystem paths and original provider, including UTF-8 and escaped names at 8MiB-1, 8MiB and 8MiB+1. No Android installability claim.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({key:summary[key] for key in ('mode','corpus_cases','matched','failures','binary_sha256')}), flush=True)
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
