#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual pinned Node and public original MCP controls; no candidate binary."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
HELPERS = Path('/home/qian-qi/work/hepta-rea-p0p5-679ccf-20261105/scripts')
PACKAGE = Path('/home/qian-qi/work/hepta-rea-reference-recovery-ca464-20261105-r1/install/node_modules/rea-agents')
TARBALL = Path('/home/qian-qi/work/hepta-rea-reference-20261103/pack/rea-agents-6.8.0.tgz')
NODE = Path('/usr/bin/node')
OUT = Path('/home/qian-qi/work/hepta-rea-p0p5-679ccf-20261105-p1-checkpoint-evidence/root-string-reference-r2')
sys.path.insert(0, str(HELPERS))
import rea_operation_qualification as q
import rea_apk_export_qualification as a
from rea_frame_mcp_qualification import CompressedMcp

CASES = [
    ('lone-high', b'"\\uD800"', 'witness'),
    ('lone-low', b'"\\uDC00"', 'witness'),
    ('double-high', b'"\\uD800\\uD800"', 'witness'),
    ('double-low', b'"\\uDC00\\uDFFF"', 'witness'),
    ('reversed-pair', b'"\\uDC00\\uD800"', 'witness'),
    ('valid-pair', b'"\\uD800\\uDC00"', 'value'),
    ('whitespace-surrounded', b' \r\n\t"\\uD800" \t\r\n', 'witness'),
    ('literal-backslash', b'"\\\\uD800"', 'value'),
    ('plain-string', b'"plain"', 'value'),
    ('empty-string', b'""', 'value'),
    ('malformed-suffix', b'"\\uD800"x', 'invalid-json'),
    ('second-root', b'"\\uD800" "second"', 'invalid-json'),
    ('unterminated-string', b'"\\uD800', 'invalid-json'),
    ('bad-following-escape', b'"\\uD800\\q"', 'invalid-json'),
    ('bad-following-unicode', b'"\\uD800\\uQ"', 'invalid-json'),
    ('invalid-utf8-tail', b'"\\uD800" ' + bytes([0xff]), 'invalid-utf8'),
    ('nested-object', b'{"x":"\\uD800"}', 'gap'),
    ('nested-array', b'["\\uD800"]', 'gap'),
    ('non-finite-root', b'1e400', 'gap'),
    ('boolean-root', b'true', 'value'),
    ('invalid-surrogate-utf8', b'"' + bytes([0xed, 0xa0, 0x80]) + b'"', 'invalid-utf8'),
]

NODE_PROBE = r'''
const fs=require('node:fs');
const cases=JSON.parse(fs.readFileSync(0,'utf8'));
const output=cases.map(c=>{
 const raw=Buffer.from(c.input_hex,'hex');
 let source;
 try { source=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw); }
 catch(error) { return {id:c.id,utf8:false,json_parse:false,error_name:error.name,message:error.message}; }
 try {
  const value=JSON.parse(source);
  const kind=value===null?'null':Array.isArray(value)?'array':typeof value;
  const row={id:c.id,utf8:true,json_parse:true,root_kind:kind};
  if(kind==='string') row.utf16_units=Array.from({length:value.length},(_,i)=>value.charCodeAt(i));
  if(kind==='number') {row.number_finite=Number.isFinite(value);row.number_spelling=String(value);}
  return row;
 } catch(error) {return {id:c.id,utf8:true,json_parse:false,error_name:error.name,message:error.message};}
});
process.stdout.write(JSON.stringify({node:process.version,executable:process.execPath,cases:output})+'\n');
'''

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def main():
    OUT.mkdir(mode=0o700)
    workspace = OUT/'workspace'; workspace.mkdir(mode=0o700)
    before = q.reference_package(PACKAGE, TARBALL)
    assert before['file_count'] == 2398
    # reference_package already requires every installed own file to equal the
    # fixed-tarball member map; its serialized map digest has its own profile.
    q.write_json(OUT/'package-before.json',before)
    node = q.identity(NODE)
    assert node['sha256'] == '94efd062ed066c1a0b332e18249859c905e920eeada5df55d24c99b919629a90'
    helpers = [q.identity(Path(module.__file__)) for module in tuple(sys.modules.values())
               if getattr(module, '__file__', None) and Path(module.__file__).parent == HELPERS]
    helpers.sort(key=lambda item:item['path'])
    raw_inputs = [{'id':name,'input_hex':raw.hex()} for name,raw,_ in CASES]
    write(OUT/'node-probe.js',NODE_PROBE.encode())
    write(OUT/'node-probe.inputs.json',json.dumps(raw_inputs,separators=(',',':')).encode())
    completed = subprocess.run([str(NODE),str(OUT/'node-probe.js')],
        input=(OUT/'node-probe.inputs.json').read_bytes(),env={},capture_output=True,timeout=30)
    write(OUT/'node-probe.stdout',completed.stdout)
    write(OUT/'node-probe.stderr',completed.stderr)
    assert completed.returncode == 0
    node_report=json.loads(completed.stdout)
    assert node_report['node']=='v22.23.4'
    node_cases={row['id']:row for row in node_report['cases']}
    environment={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
        'REA_MCP_INPUT_SCHEMA_PROFILE':'full','REA_MCP_OUTPUT_SCHEMA_PROFILE':'full'}
    client=None
    report={'schema':'hepta.rea.complete-root-string-original-controls.v1',
        'reference_before':before,'node':node,'node_probe':node_report,
        'producer':q.identity(Path(__file__)),'helpers_before':helpers,
        'cases':[],'candidate_executed':False,'production_qualified':False,
        'automatic_retry':False,'prior_preflight_job':'1a1ae85cad3-fc05-600d','prior_preflight_failed_before_any_node_or_mcp':True,'passed':False}
    try:
        client=CompressedMcp([str(NODE),str(PACKAGE/'scripts/rea.mjs'),'mcp'],workspace,environment,OUT/'original-mcp')
        report['initialize']=client.initialize()
        baseline=client.call('get_evidence_bundle',{})
        baseline_value=q.tool_value(baseline)
        assert not baseline_value.get('isError')
        for name,raw,expected_native in CASES:
            path=workspace/(name+'.json');write(path,raw)
            start=len(client.entries)
            response=client.call('import_evidence_bundle',{'path':str(path)})
            assert response.get('result',{}).get('isError') is True,response
            request_raw=response_raw=None
            for entry in client.entries[start:]:
                observed=client.original(entry);value=json.loads(observed)
                if value.get('method')=='tools/call' and value.get('id')==response['id']:
                    request_raw=observed
                if ('result' in value or 'error' in value) and value.get('id')==response['id']:
                    assert value==response;response_raw=observed
            assert request_raw is not None and response_raw is not None
            after=client.call('get_evidence_bundle',{})
            assert q.tool_value(after)==baseline_value,'failed import changed original session: '+name
            report['cases'].append({'id':name,'input_hex':raw.hex(),'input_bytes':len(raw),
                'input_sha256':sha(raw),'expected_native':expected_native,'node':node_cases[name],
                'original_request':json.loads(request_raw),'original_response':response,
                'original_request_raw':request_raw.decode(),'original_response_raw':response_raw.decode(),
                'original_request_sha256':sha(request_raw),'original_response_sha256':sha(response_raw),
                'original_session_unchanged':True})
        report['passed']=True
    finally:
        if client is not None:
            report['original_close']=client.close()
            report['wire_entries']=client.entries
            report['passed']=report['passed'] and a.closed_normally(report['original_close'])
        report['reference_after']=q.reference_package(PACKAGE,TARBALL)
        report['node_after']=q.identity(NODE)
        report['helpers_after']=[q.identity(Path(row['path'])) for row in helpers]
        report['producer_after']=q.identity(Path(__file__))
        report['passed']=report['passed'] and report['reference_after']==before and report['node_after']==node and report['helpers_after']==helpers and report['producer_after']==report['producer']
        q.write_json(OUT/'reference.json',report)
        for path in (OUT/'original-mcp').iterdir():
            if path.is_file():
                with path.open('rb') as stream:os.fsync(stream.fileno())
    assert report['passed'] and len(report['cases'])==len(CASES)
    portable={key:report[key] for key in ('schema','reference_before','reference_after','node','node_after',
        'producer','producer_after','helpers_before','helpers_after','original_close','passed','candidate_executed','automatic_retry')}
    portable['source_reference']=q.identity(OUT/'reference.json')
    portable['node_probe_stdout']=q.identity(OUT/'node-probe.stdout')
    portable['cases']=[{key:value for key,value in case.items() if key not in ('original_request','original_response')}
        for case in report['cases']]
    write(OUT/'portable.json',(json.dumps(portable,ensure_ascii=True,separators=(',',':'))+'\n').encode())
    print(json.dumps({'reference':q.identity(OUT/'reference.json'),'cases':len(CASES),
        'portable':q.identity(OUT/'portable.json'),
        'node_probe_returncode':completed.returncode,'original_close':report['original_close'],
        'reference_files_sha256':before['files_sha256'],'passed':True,'candidate_executed':False},sort_keys=True),flush=True)

if __name__=='__main__':
    main()
