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

"""Capture actual frozen APK Service Evidence for full native-entry comparison.

The original provider reads owned public fixtures. The original Service creates
and seals Evidence and calls real supplied retention callbacks. This script does
not emulate a server, execute an APK, qualify a native binary, alter an upstream
clock or timer, or substitute synthetic provider observations.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import time


FROZEN_PACKAGE = '8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb'
NODE = r'''
import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import assert from 'node:assert/strict';
const request=JSON.parse(readFileSync(0,'utf8'));
const get=path=>import(pathToFileURL(request.root+'/'+path).href);
const {ApkSignatureProvider}=await get('dist/apkSignature/ApkSignatureProvider.js');
const {ApkSignatureService}=await get('dist/application/apkSignature/ApkSignatureService.js');
const {inspectApkSignatureInputSchema}=await get('dist/domain/apkSignature/apkSignatureQuery.js');
const {safeParseEvidence}=await get('dist/domain/evidenceValidation.js');
const provider=new ApkSignatureProvider(),sessions=new Map(),outputs=[];
let activeCalls=[];
// This adapter only observes arguments; every execution comes from the original provider.
const service=new ApkSignatureService({
 inspect:(input,options)=>{activeCalls.push(structuredClone(input));return provider.inspect(input,options);},
 close:()=>provider.close(),
});
const errorView=error=>Object.fromEntries(Object.entries(error).filter(([key])=>key!=='cause'));
try {
 for(const row of request.cases){
  const input=JSON.parse(row.input_json),normalized=inspectApkSignatureInputSchema.safeParse(input);
  const session=sessions.get(row.session)??new Map();sessions.set(row.session,session);
  const retainedBefore=[...session.keys()],events=[];activeCalls=[];
  const retention=row.retention?{
   recordEvidence:record=>{
    assert.equal(safeParseEvidence(record).ok,true);
    const duplicate=session.has(record.evidence_id);
    events.push({duplicate,record});
    if(!duplicate)session.set(record.evidence_id,record);
    return {ok:true,value:undefined};
   },
   evidenceById:id=>session.get(id),
  }:undefined;
  let options;
  if(row.cancelled){const controller=new AbortController();controller.abort('owned pre-dispatch cancellation');options={signal:controller.signal};}
  const result=await service.inspect(input,options,retention);
  assert.equal(result.ok,row.expected_ok,row.name);
  assert.equal(activeCalls.length,row.expected_provider_calls,row.name+' provider dispatch');
  for(const call of activeCalls)assert.deepEqual(call,{path:input.path});
  assert.equal(events.length,row.expected_record_calls,row.name+' retention dispatch');
  if(result.ok){
   assert.equal(safeParseEvidence(result.value).ok,true,row.name+' Evidence authentication');
   if(result.value.operation==='inspect_analysis_view'){
    const parent=result.value.normalized_result.parent_evidence_id;
    assert.equal(session.has(parent),true);
    assert.deepEqual(result.value.evidence_links,[parent]);
    assert.equal(result.value.confidence,'derived');
    assert.equal(result.value.normalized_result.view_digest.length,64);
    const view=normalized.data.view===undefined?{kind:'summary'}:{kind:'apk-signature',...normalized.data.view};
    assert.deepEqual(result.value.parameters,{parent_evidence_id:parent,view});
   }else{
    assert.equal(result.value.operation,'inspect_apk_signature');
    assert.deepEqual(result.value.parameters,{path:input.path});
    assert.equal(result.value.confidence,'observed');
   }
  }else assert.equal(result.error._tag,row.expected_tag);
  const outcome={name:row.name,input_json:row.input_json,
   input_numbers:Object.fromEntries(['offset','limit'].filter(key=>typeof input.view?.[key]==='number').map(key=>[key,{value:input.view[key],negative_zero:Object.is(input.view[key],-0)}])),
   parsed_input:normalized.success?normalized.data:null,
   service_result:result.ok?{ok:true,value:result.value}:{ok:false,error:errorView(result.error)},
   provider_calls:activeCalls,retention_enabled:row.retention,session:row.session,
   retained_before_ids:retainedBefore,record_events:events,retained_after_ids:[...session.keys()]};
  writeFileSync(request.out+'/cases/'+row.name+'.json',JSON.stringify(outcome,null,2)+'\n');
  outputs.push({name:row.name,ok:result.ok,evidence_id:result.ok?result.value.evidence_id:null,
   parent_evidence_id:result.ok?result.value.normalized_result.parent_evidence_id??null:null,
   provider_calls:activeCalls.length,record_calls:events.length});
 }
}finally{await service.close();}
for(const [name,session] of sessions)writeFileSync(request.out+'/retained/'+name+'.json',JSON.stringify([...session.values()],null,2)+'\n');
const named=name=>JSON.parse(readFileSync(request.out+'/cases/'+name+'.json','utf8'));
assert.deepEqual(named('rotation-default-summary').service_result,named('rotation-explicit-summary').service_result);
assert.equal(named('rotation-explicit-summary').record_events[0].duplicate,true);
assert.equal(named('rotation-digests-numeric').input_numbers.offset.negative_zero,true);
assert.equal(named('rotation-digests-numeric').service_result.value.parameters.view.offset,0);
assert.equal(named('rotation-digests-numeric').service_result.value.parameters.view.limit,2);
assert.deepEqual(named('rotation-signers-empty-ids').service_result.value.normalized_result.items,[]);
assert.equal(named('rotation-signers-empty-ids').service_result.value.normalized_result.coverage.total,0);
process.stdout.write(JSON.stringify({node:process.version,openssl:process.versions.openssl,outputs})+'\n');
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def make_cases(fixtures):
    rotation = str(fixtures / 'rotation-v31.apk')
    v1 = str(fixtures / 'v1-v2-v3.apk')
    digest = sha((fixtures / 'rotation-v31.apk').read_bytes())
    signer = f'apk:{digest}:v3.1:signer:0'
    cases = []

    def add(name, path=rotation, *, detail=None, view=None, retention=True,
            numeric=False, expected_tag=None, cancelled=False):
        value = dict(path=path)
        if detail is not None:
            value['detail'] = detail
        if view is not None:
            value['view'] = view
        encoded = encode(value)
        if numeric:
            encoded = encoded.replace('"offset":0', '"offset":-0').replace('"limit":2', '"limit":2e0')
        success = expected_tag is None
        cases.append(dict(name=name, input_json=encoded, session='v1' if path == v1 else 'rotation',
                          retention=retention, cancelled=cancelled, expected_ok=success,
                          expected_provider_calls=int(success), expected_tag=expected_tag,
                          expected_record_calls=int(success and detail != 'complete')))

    add('rotation-complete', detail='complete', retention=False)
    add('v1-complete', v1, detail='complete')
    add('rotation-default-summary')
    add('rotation-explicit-summary', detail='summary')
    add('rotation-signers-default', view=dict(collection='signers'))
    add('rotation-signers-fields', view=dict(collection='signers', fields=['public_key_bytes', 'max_sdk']))
    add('rotation-signers-identity-only', view=dict(collection='signers', fields=[]))
    add('rotation-digests-numeric', view=dict(collection='digests', offset=0, limit=2,
                                           fields=['algorithm', 'matches_apk']), numeric=True)
    add('rotation-lineage-numeric', view=dict(collection='lineage', offset=1.0, limit=1.0,
                                           fields=['flags', 'capabilities']))
    add('rotation-lineage-signer-filter', view=dict(collection='lineage', signer_ids=[signer]))
    add('rotation-signers-duplicate-filter-fields', view=dict(collection='signers', schemes=['v3.1', 'v3.1'],
                                                            fields=['certificate', 'certificate']))
    add('rotation-signers-empty-ids', view=dict(collection='signers', ids=[]))
    add('rotation-signers-past-end', view=dict(collection='signers', offset=9007199254740991))
    add('rotation-lineage-explicit-id', view=dict(collection='lineage', ids=[signer + ':lineage:0']))
    add('v1-default-summary', v1)
    add('v1-signers-fields', v1, view=dict(collection='signers', schemes=['v1'],
                                        fields=['certificate', 'signature_file', 'block_file', 'signer_infos']))
    add('summary-needs-retention', retention=False, expected_tag='AnalysisCapabilityUnavailableError')
    add('complete-refuses-view', detail='complete', view=dict(collection='signers'),
        expected_tag='AnalysisInputError')
    add('cancelled-before-provider', detail='complete', cancelled=True, expected_tag='AnalysisCancelledError')
    return cases


def main():
    parser = argparse.ArgumentParser()
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
                relative = member.name.removeprefix('package/')
                assert (args.rea_install / relative).read_bytes() == archive.extractfile(member).read()
                checked += 1
    fixtures = args.out / 'fixtures'
    fixtures.mkdir()
    for name in ['rotation-v31.apk', 'v1-v2-v3.apk']:
        path = fixtures / name
        shutil.copyfile(args.repo / 'tests/fixtures/rea_apk_signature' / name, path)
        path.chmod(0o400)
    (args.out / 'cases').mkdir()
    (args.out / 'retained').mkdir()
    cases = make_cases(fixtures)
    request = dict(root=str(args.rea_install), out=str(args.out), cases=cases)
    data = encode(request).encode()
    (args.out / 'runner.mjs').write_text(NODE)
    (args.out / 'request.json').write_bytes(data)
    argv = ['node', str(args.out / 'runner.mjs')]
    started = time.monotonic()
    result = subprocess.run(argv, input=data, capture_output=True, timeout=90, cwd='/', env={})
    (args.out / 'reference.stdout.json').write_bytes(result.stdout)
    (args.out / 'reference.stderr.log').write_bytes(result.stderr)
    receipt = dict(argv=argv, timeout_seconds=90, exit_code=result.returncode,
                   seconds=time.monotonic() - started, stdin_sha256=sha(data),
                   stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr))
    (args.out / 'reference.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    output = json.loads(result.stdout)
    assert len(output['outputs']) == len(cases) == 19
    identities = {}
    for path in sorted(args.out.rglob('*')):
        if path.is_file():
            identities[str(path.relative_to(args.out))] = dict(bytes=path.stat().st_size, sha256=sha(path.read_bytes()))
    sources = ['dist/apkSignature/ApkSignatureProvider.js',
               'dist/application/apkSignature/ApkSignatureService.js',
               'dist/domain/apkSignature/apkSignatureQuery.js',
               'dist/application/analysisView/AnalysisViewService.js',
               'dist/domain/analysisView/apkSignatureView.js',
               'dist/domain/evidence.js', 'dist/domain/evidenceValidation.js']
    summary = dict(format='hepta.apk-service-reference.v1', passed=True,
                   cases=19, successful_evidence=16, typed_predispatch_refusals=3,
                   frozen_npm_tarball_sha256=FROZEN_PACKAGE, frozen_install_files_checked=checked,
                   oracle_node=output['node'], oracle_openssl=output['openssl'],
                   upstream_sources={path:sha((args.rea_install / path).read_bytes()) for path in sources},
                   frozen_install_verified_before_execution=True, receipt=receipt, artifacts=identities,
                   golden_comparison='Complete original Service Evidence with no ignored fields; Evidence contains no wall-clock timestamp.',
                   runtime_release_qualified=False,
                   retention_scope='Actual Service callback calls and supplied in-memory session. Service retains complete parent for views; final reply publication by the MCP handler is a separate gate.',
                   scope='Finite original provider/Service reference capture, not a native comparison, server authentication, cancellation-during-work, or worker lifecycle qualification.')
    (args.out / 'qualification.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key:summary[key] for key in ['passed', 'cases', 'successful_evidence', 'typed_predispatch_refusals', 'frozen_install_files_checked']}), flush=True)


if __name__ == '__main__':
    main()
