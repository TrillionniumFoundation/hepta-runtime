#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Exact frozen-byte legacy/fixed native protocol comparison; no real SSH dispatch.

The PATH adapter recognizes only the pre-reviewed network inspection source and
returns a captured fixture. It cannot execute arbitrary commands. Controllers
and credentials are private direct children. Original production state is not
opened or changed. Reports contain sizes/hashes, never captured network content.
"""
import argparse, hashlib, importlib.util, json, os, pathlib, re, secrets, subprocess, sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('native_fixture',ROOT/'tests/dc_functional_v10_operation_explicit_state_acceptance.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
LIMIT=1048576

def digest(raw):return hashlib.sha256(raw).hexdigest()
def write(path,data,mode=0o600):
    raw=data.encode() if isinstance(data,str) else data
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())

def case(binary,raw,parent,label,expect):
    root=parent/label;root.mkdir(mode=0o700)
    for name in ('state','workspace','bin'):(root/name).mkdir(mode=0o700)
    write(root/'input.json',raw)
    token=secrets.token_hex(32);write(root/'token',token)
    config={'state_dir':str(root/'state'),'controller_workspace_roots':[str(root/'workspace')],
            'hosts':{'fixture':{'ssh_target':'network-boundary-fixture','platform':'linux',
            'execution_mode':'operator','remote_state_dir':str(root/'unused-host-state'),
            'allow_execute':False,'allow_pty':False,'allow_write':False}}}
    write(root/'runtime.json',json.dumps(config))
    source=(ROOT/'src/mcp/runtime/inspect.rs').read_text()
    helper=re.search(r'const NETWORK_CODE: &str = r#"(.*?)"#;',source,re.S).group(1)
    assert digest(helper.encode())=='42823baa447bae2db9d8b5dfcc14de50e33d3dc2b7dac6d0e1e2689d516a8c64'
    prefix=['-T','-o','BatchMode=yes','-o','ConnectTimeout=8','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','network-boundary-fixture']
    command='python3 -c '+M.shell_quote(helper)
    wrapper=("#!/usr/bin/python3\nimport os,sys,pathlib\n"
             +f"root=pathlib.Path({str(root)!r})\nprefix={prefix!r}\ncommand={command!r}\n"
             +"if sys.argv[1:-1]!=prefix or sys.argv[-1]!=command:raise SystemExit(91)\n"
             +"if sys.stdin.buffer.read(129).strip()!=b'{}':raise SystemExit(92)\n"
             +"fd=os.open(root/'dispatch-count',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)\n"
             +"os.write(fd,b'1\\n');os.fsync(fd);os.close(fd)\n"
             +"raw=(root/'input.json').read_bytes()\n"
             +"if len(raw)>4*1024*1024:raise SystemExit(93)\n"
             +"sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()\n")
    write(root/'bin/ssh',wrapper,0o700)
    env=dict(os.environ,PATH=str(root/'bin')+':'+os.environ.get('PATH',''))
    controller=M.Controller(binary,root/'workspace',root/'runtime.json',root/'token',env)
    def dispatches():return len((root/'dispatch-count').read_text().splitlines())
    result={'case':label,'input_bytes':len(raw),'input_sha256':digest(raw),'expected':expect,'complete':False}
    try:
        client=controller.start()
        tools=client.rpc('tools/list',{})['tools']
        frozen=json.loads((ROOT/'deploy/contracts/hepta-runtime-full-operator-v10.json').read_text())['tools']
        assert {x['name']:x for x in tools}=={x['name']:x for x in frozen}
        result['catalog_exact']=True
        direct=client.raw_call('network_inspect',{'host':'fixture'})
        inner=direct['content'][0]['text']
        result.update(direct_text_bytes=len(inner.encode()),direct_text_sha256=digest(inner.encode()),direct_error=direct.get('isError',False))
        start=M.start_operation(client,'network_inspect',{'host':'fixture'},'frozen-'+label)
        status=M.settled(client,start['operation_id'])
        result.update(operation_id=start['operation_id'],async_state=status['async_state'],payload_available=status['payload_available'])
        assert dispatches()==2
        if expect=='unknown':
            assert status['async_state']=='unknown' and not status['payload_available']
            assert direct.get('isError') is not True
            assert json.loads(inner)==json.loads(raw)
            reply=client.raw_call('operation_result',{'operation_id':start['operation_id']})
            assert reply.get('isError') is True
            result['legacy_missing_result_reproduced']=True
        else:
            assert status['async_state']==('failed' if expect=='explicit_error' else 'completed')
            assert status['payload_available']
            recovered,meta=M.reconstructed(client,start['operation_id'],direct)
            result['retained_payload']=meta
            assert meta['bytes']<=LIMIT
            if expect=='explicit_error':
                assert direct.get('isError') is True
                assert 'no fields were truncated' in inner and 'PRIVATE_OVERSIZE' not in inner
            else:
                assert direct.get('isError') is not True and json.loads(inner)==json.loads(raw)
            controller.stop();client=controller.start()
            _,again=M.reconstructed(client,start['operation_id'],direct)
            assert again['sha256']==meta['sha256']
            result['restart_exact_result_preserved']=True
        before=dispatches()
        repeat=M.start_operation(client,'network_inspect',{'host':'fixture'},'frozen-'+label)
        assert repeat['reused'] and repeat['operation_id']==start['operation_id'] and dispatches()==before
        result.update(same_key_no_redispatch=True,total_adapter_dispatches=dispatches(),real_ssh_dispatches=0,complete=True)
    finally:
        controller.cleanup();controller.close_logs()
        result['owned_controllers_exited']=all(p.poll() is not None for p in controller.children)
        write(root/'case-summary.json',json.dumps(result,indent=2))
    return result

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--role',choices=['legacy','fixed'],required=True)
    ap.add_argument('--sample',required=True);ap.add_argument('--root',required=True);a=ap.parse_args()
    root=pathlib.Path(a.root);root.mkdir(mode=0o700)
    binary=pathlib.Path(a.binary).resolve(strict=True)
    raw=pathlib.Path(a.sample).read_bytes();json.loads(raw)
    write(root/'harness.py',pathlib.Path(__file__).read_bytes())
    report={'schema':'hepta-frozen-network-boundary-causal-v1','role':a.role,'binary_sha256':M.digest(binary),
            'harness_source':M.source_identity(),'checks':[],'complete':False,'production_state_changed':False,'original_operation_replayed':False}
    try:
        small=json.dumps({'links':{'exit_code':0,'data':[]},'listeners':{'data':'中文🙂\n','exit_code':0},'routes':{'exit_code':0,'data':[]}},ensure_ascii=False).encode()
        report['checks'].append(case(binary,small,root,'small','complete'))
        report['checks'].append(case(binary,raw,root,'captured','unknown' if a.role=='legacy' else 'complete'))
        if a.role=='fixed':
            large=json.dumps({'listeners':{'exit_code':0,'data':'PRIVATE_OVERSIZE'*100000}}).encode()
            report['checks'].append(case(binary,large,root,'oversized','explicit_error'))
        report['complete']=True
    finally:
        write(root/'summary.json',json.dumps(report,indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='source'},indent=2))
if __name__=='__main__':main()
