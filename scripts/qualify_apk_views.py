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

"""Actual frozen producer/projection differential for the pure Rust APK view.

The binary is a small harness importing the unchanged production Rust modules.
This gate proves selected projection behavior, not MCP Evidence authentication,
retention, publication, acquisition, or worker lifecycle. No APK is executed.
"""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import time


FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
PARENT_ID = 'ev_' + 'a' * 64
FIELDS = {
    'signers': ['id', 'scheme', 'index', 'certificate', 'certificate_sha256', 'signatures',
                'public_key_bytes', 'uninterpreted_signed_data_bytes', 'uninterpreted_signer_bytes',
                'min_sdk', 'max_sdk', 'signature_file', 'block_file', 'signer_infos', 'decode_error'],
    'digests': ['uninterpreted_bytes', 'signature_algorithm_id', 'algorithm', 'declared_digest_hex',
                'matches_apk', 'id', 'scheme', 'index', 'signer_id', 'signer_index'],
    'lineage': ['certificate', 'flags', 'capabilities', 'id', 'scheme', 'index', 'signer_id',
                'signer_index', 'previous_id', 'certificate_sha256'],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


PRODUCER = r'''
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(readFileSync(0,'utf8'));
const {ApkSignatureProvider}=await import(pathToFileURL(input.root+'/dist/apkSignature/ApkSignatureProvider.js').href);
const provider=new ApkSignatureProvider(),reports=[];
try {for(const path of input.paths){const one=await provider.inspect({path});reports.push(one.ok?
 {path,ok:true,report:one.value.result,limitations:one.value.limitations}:
 {path,ok:false,error:{_tag:one.error._tag,reason:one.error.reason??null}});}}
finally {await provider.close();}
process.stdout.write(JSON.stringify({node:process.version,openssl:process.versions.openssl,reports}));
'''


PROJECTOR = r'''
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(readFileSync(0,'utf8'));
const {projectAnalysisView,analysisViewRequestSchema}=await import(pathToFileURL(input.root+'/dist/domain/analysisView/analysisView.js').href);
const {analysisInputErrorFromIssues}=await import(pathToFileURL(input.root+'/dist/domain/inputIssueProjection.js').href);
const out=[];
for(const row of input.cases){
 const parsed=analysisViewRequestSchema.safeParse(row.view);
 const result=parsed.success?projectAnalysisView({evidenceId:row.parent_id,operation:'inspect_apk_signature',normalizedResult:row.report,subject:row.subject,limitations:row.limitations},parsed.data):
 {ok:false,error:analysisInputErrorFromIssues('inspect_analysis_view',parsed.error.issues.map(issue=>({...issue,path:['view',...issue.path]})),{view:row.view})};
 out.push(result.ok?{name:row.name,ok:true,value:result.value}:{name:row.name,ok:false,error:{_tag:result.error._tag,operation:result.error.operation,issues:result.error.issues}});
}
process.stdout.write(JSON.stringify(out));
'''


def invoke(out, name, argv, request, timeout=90):
    started = time.monotonic()
    data = json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode()
    (out / (name + '.input.json')).write_bytes(data)
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, cwd='/', env={})
    (out / (name + '.stdout.json')).write_bytes(result.stdout)
    (out / (name + '.stderr.log')).write_bytes(result.stderr)
    receipt = dict(argv=argv, timeout_seconds=timeout, exit_code=result.returncode,
                   seconds=time.monotonic() - started, stdin_sha256=sha(data),
                   stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
    (out / (name + '.receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return json.loads(result.stdout)


def cases_from(reports):
    cases = []

    def add(name, report, view, *, limitations=None, subject='match', parent_id=PARENT_ID):
        if subject == 'match':
            subject = dict(local_path=report['artifact']['path'], digest=dict(sha256=report['artifact']['sha256']))
        cases.append(dict(name=name, report=copy.deepcopy(report), view=view, subject=subject,
                          parent_id=parent_id, limitations=limitations or []))

    for entry in reports:
        if not entry['ok']:
            continue
        report = entry['report']
        name = Path(entry['path']).stem
        add(name + '/summary', report, dict(kind='summary'), limitations=entry['limitations'])
        for collection, fields in FIELDS.items():
            selections = [({}, 'default'), ({'limit': 1}, 'first'), ({'offset': 1, 'limit': 1}, 'second'),
                          ({'offset': 9007199254740991}, 'past-end'), ({'ids': []}, 'empty-ids'),
                          ({'signer_ids': []}, 'empty-signers'), ({'schemes': []}, 'empty-schemes'),
                          ({'schemes': ['v3.1', 'v1', 'v3', 'v2', 'v1']}, 'scheme-order'),
                          ({'ids': ['missing', 'missing']}, 'unknown-id'), ({'fields': []}, 'identity-only'),
                          ({'fields': fields + fields[:1]}, 'all-fields')]
            for field in fields:
                selections.append(({'fields': [field]}, 'field-' + field))
            for options, suffix in selections:
                add(name + '/' + collection + '/' + suffix, report,
                    dict(kind='apk-signature', collection=collection, **options))
            for scheme, data in report['schemes'].items():
                for index, signer in enumerate(data['signers']):
                    identity = f"apk:{report['artifact']['sha256']}:{scheme}:signer:{index}"
                    add(name + '/' + collection + '/signer-' + scheme + '-' + str(index), report,
                        dict(kind='apk-signature', collection=collection, signer_ids=[identity, identity]))
                    children = ([signer] if collection == 'signers' else signer.get('digests', [])
                                if collection == 'digests' else signer.get('rotation', {}).get('lineage', []))
                    if children:
                        row_id = identity if collection == 'signers' else identity + ':' + collection + ':0'
                        add(name + '/' + collection + '/id-' + scheme + '-' + str(index), report,
                            dict(kind='apk-signature', collection=collection, ids=[row_id, row_id], signer_ids=[identity]))
    seed = next(entry['report'] for entry in reports if entry['ok'] and entry['report']['schemes']['v3.1']['signers'])
    add('parent/no-subject', seed, dict(kind='summary'), subject=None)
    add('parent/wrong-path', seed, dict(kind='summary'), subject=dict(local_path='/other.apk', digest=dict(sha256=seed['artifact']['sha256'])))
    add('parent/wrong-digest', seed, dict(kind='summary'), subject=dict(local_path=seed['artifact']['path'], digest=dict(sha256='f' * 64)))
    add('parent/invalid-id', seed, dict(kind='summary'), parent_id='ev_not-a-digest')
    for options, name in [({'limit': 0}, 'zero-limit'), ({'offset': -1}, 'negative-offset'),
                          ({'offset': 1.5}, 'fraction-offset'), ({'limit': None}, 'null-limit'),
                          ({'fields': ['not-a-field']}, 'unknown-field'), ({'schemes': ['v4']}, 'unknown-scheme'),
                          ({'ids': [None]}, 'null-id'), ({'extra': 'secret-value'}, 'extra-field'),
                          ({'limit': 9007199254740992}, 'unsafe-limit')]:
        add('invalid-view/' + name, seed, dict(kind='apk-signature', collection='signers', **options))
    add('invalid-view/summary-extra', seed, dict(kind='summary', fields=[]))
    add('invalid-view/absent-collection', seed, dict(kind='apk-signature'))
    add('invalid-view/unknown-collection', seed, dict(kind='apk-signature', collection='signatures'))
    for path, replacement, name in [
        (['artifact', 'path'], '', 'empty-path'), (['artifact', 'sha256'], 'F' * 64, 'uppercase-digest'),
        (['artifact', 'bytes'], 1.5, 'fraction-bytes'), (['artifact', 'bytes'], -1, 'negative-bytes'),
        (['artifact', 'bytes'], 9007199254740992, 'unsafe-bytes'),
        (['schemes', 'v3.1', 'signers', 0, 'certificate', 'unexpected'], 'secret-value', 'certificate-extra'),
        (['schemes', 'v3.1', 'signers', 0, 'rotation', 'lineage', 0, 'flags'], -1, 'negative-flags'),
        (['schemes', 'v3.1', 'signers', 0, 'digests', 0, 'declared_digest_hex'], 'f', 'odd-hex'),
        (['schemes', 'v3.1', 'signers', 0, 'digests', 0, 'signature_algorithm_id'], 4294967296, 'algorithm-over-u32'),
        (['runtime_execution'], 'performed', 'execution-literal'),
        (['posture', 'unknown'], True, 'posture-extra'),
        (['source_stamp', 'certificate'], {}, 'incomplete-certificate'),
    ]:
        report = copy.deepcopy(seed)
        at = report
        for part in path[:-1]:
            at = at[part]
        at[path[-1]] = replacement
        add('invalid-report/' + name, report, dict(kind='summary'))
    report = copy.deepcopy(seed)
    del report['schemes']['v2']['uninterpreted_bytes']
    add('invalid-report/missing-field', report, dict(kind='summary'))
    report = copy.deepcopy(seed)
    report['artifact']['bytes'] = 1.0
    signer = report['schemes']['v3.1']['signers'][0]
    signer['min_sdk'], signer['max_sdk'] = -9007199254740991, 9007199254740991
    signer['rotation']['lineage'][0]['flags'] = 9007199254740991
    signer['rotation']['lineage'] *= 2
    for collection in ('signers', 'lineage'):
        add('external-schema/wide-' + collection, report, dict(kind='apk-signature', collection=collection))
    report = copy.deepcopy(seed)
    report['schemes']['v3.1']['signers'][0]['certificate'] = None
    report['schemes']['v3.1']['signers'][0]['rotation']['decode_error'] = 'bad lineage: \U00010000\ue000'
    report['source_stamp']['decode_error'] = 'unread stamp'
    add('unknowns/missing-identity-and-lineage', report, dict(kind='summary'))
    report = copy.deepcopy(seed)
    for scheme in ('v2', 'v3', 'v3.1'):
        block = report['schemes'][scheme]
        block['uninterpreted_bytes'] = 1
        for signer in block['signers']:
            signer['uninterpreted_signed_data_bytes'], signer['uninterpreted_signer_bytes'] = 2, 3
            for record in signer['digests'] + signer['signatures']:
                record['uninterpreted_bytes'] = 4
    add('coverage/uninterpreted-suffixes', report, dict(kind='summary'))
    for name, messages in [
        ('codepoints', ['\U00010000', '\ue000', 'A', 'A', '\U0010ffff', '\uffff']),
        ('one-too-large', ['x' * 10000, 'small', 'small']),
        ('many-small', [f'message-{i:05}' for i in range(3000)]),
        ('astral-bound', ['\U00010000' * 2426, 'small']),
    ]:
        add('messages/' + name, seed, dict(kind='summary'), limitations=messages)
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
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
    paths = sorted((args.repo / 'tests/fixtures/rea_apk_signature').glob('*.apk'))
    assert paths
    producer = invoke(args.out, 'producer', ['node', '--input-type=module', '-e', PRODUCER],
                      dict(root=str(args.rea_install), paths=[str(path) for path in paths]))
    cases = cases_from(producer['reports'])
    oracle = invoke(args.out, 'reference-views', ['node', '--input-type=module', '-e', PROJECTOR],
                    dict(root=str(args.rea_install), cases=cases))
    native = invoke(args.out, 'native-views', [str(args.binary), '--project-views'], cases)
    assert len(cases) == len(oracle) == len(native)
    results, failures = [], []
    for case, expected, actual in zip(cases, oracle, native):
        assert case['name'] == expected.pop('name')
        if expected['ok']:
            digest = expected['value'].pop('view_digest')
        else:
            digest = None
        matched = actual == expected
        results.append(dict(name=case['name'], passed=matched, native_outcome=actual['ok'],
                            reference_outcome=expected['ok'], expected_view_digest=digest))
        if not matched:
            failures.append(case['name'])
            print('DIFFERENCE', case['name'], json.dumps(dict(native=actual, reference=expected), ensure_ascii=False), flush=True)
    sources = ['rea_apk_signature_view.rs', 'rea_apk_signature_view_schema.rs', 'rea_apk_signature_view_tests.rs']
    summary = dict(format='hepta.apk-view-projection-qualification.v1', binary_sha256=sha(args.binary.read_bytes()),
                   frozen_npm_tarball_sha256=FROZEN_PACKAGE, frozen_install_files_checked=checked,
                   oracle_node=producer['node'], oracle_openssl=producer['openssl'],
                   source_sha256={name:sha((args.repo / 'src/mcp' / name).read_bytes()) for name in sources},
                   fixture_sha256={path.name:sha(path.read_bytes()) for path in paths},
                   report_inputs=len(producer['reports']), report_successes=sum(row['ok'] for row in producer['reports']),
                   corpus_cases=len(cases), matched=len(cases) - len(failures), failures=failures, results=results,
                   runtime_release_qualified=False,
                   comparison='Every unsealed projection field and typed input issue; original sealed view_digest retained for shared canonical integration.',
                   scope='Finite pure production-function differential. Evidence authentication, retention, cancellation/publication, MCP and isolated-worker qualification are separate.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({key:summary[key] for key in ('corpus_cases','matched','failures','binary_sha256')}), flush=True)
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
