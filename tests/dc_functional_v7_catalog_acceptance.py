#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify reviewed v7 native/facade catalog and strict successor refusal; no target probes."""
import argparse,copy,datetime,hashlib,json,os,pathlib,secrets,select,socket,subprocess,sys,tempfile,time
from runtime_http_acceptance import Client
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract,make_contract
from dc_successor_contract import ADDITIONS as V5_ADDITIONS, AUDIT_CONFIG_ADDITIONS, V7_SHA256, V5_SHA256, V6_SHA256, verify_successor
ADDITIONS=V5_ADDITIONS|AUDIT_CONFIG_ADDITIONS

def negative_successor_checks(reviewed,path):
    checks=[]
    for version,digest in [(5,V5_SHA256),(6,V6_SHA256)]:
        oldpath=ROOT/f'deploy/contracts/hepta-runtime-full-operator-v{version}.json'
        previous=ToolContract.load(oldpath,digest)
        assert len(verify_successor(previous.tools,oldpath))==50
    checks.append('historical reviewed v5/v6 successors retain their original exact-definition checks')
    tampered=copy.deepcopy(reviewed.tools)
    tampered[0]['description']+=' unreviewed wire change'
    try:verify_successor(tampered,path)
    except (ValueError,AssertionError):pass
    else:raise AssertionError('reviewed digest accepted changed native definitions')
    checks.append('reviewed v7 file rejects changed native tool definitions before projection')
    with tempfile.TemporaryDirectory(prefix='hepta-v7-contract-negative-') as td:
        for name,tools in [('v4-drift',copy.deepcopy(reviewed.tools)),
                           ('ownership-drift',copy.deepcopy(reviewed.tools)),
                           ('extra-tool',copy.deepcopy(reviewed.tools))]:
            selected='shell_start' if name=='v4-drift' else 'request_history'
            if name=='extra-tool':
                extra=copy.deepcopy(tools[0]);extra['name']='unreviewed_fixture_tool';tools.append(extra)
            else:
                next(tool for tool in tools if tool['name']==selected)['description']+=' unreviewed recomputed contract'
            unknown=pathlib.Path(td)/(name+'.json')
            unknown.write_text(json.dumps(make_contract(tools),indent=2)+'\n');unknown.chmod(0o600)
            try:verify_successor(tools,unknown)
            except (ValueError,AssertionError):pass
            else:raise AssertionError('self-consistent unknown successor digest was accepted')
    checks.append('recomputed unknown v4 drift, ownership drift and extra-tool catalogs all refused')
    return checks

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--contract',required=True)
    a=ap.parse_args();binary=pathlib.Path(a.binary).resolve(strict=True);checks=[]
    reviewed=ToolContract.load(pathlib.Path(a.contract),V7_SHA256)
    checks.extend(negative_successor_checks(reviewed,a.contract))
    with tempfile.TemporaryDirectory(prefix='hepta-dc-v7-catalog-') as td:
        root=pathlib.Path(td);workspace=root/'workspace';workspace.mkdir(mode=0o700)
        token=root/'token';token.write_text(secrets.token_hex(32));token.chmod(0o600)
        cfg=root/'runtime.json'
        host={'ssh_target':'localhost','platform':'linux','remote_state_dir':str(root/'unused'),
              'allow_execute':False,'allow_pty':False,'allow_write':False,
              'allowed_read_path_prefixes':[str(workspace)],'allowed_write_path_prefixes':[]}
        cfg.write_text(json.dumps({'state_dir':str(root/'state'),
            'controller_workspace_roots':[str(workspace)],'hosts':{'disabled-fixture':host}}))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        with (root/'native.log').open('wb') as log:
            proc=subprocess.Popen([str(binary),'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}',
                '--runtime-config',str(cfg),'--auth-token-file',str(token)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if proc.poll() is not None:raise RuntimeError('candidate exited before ready')
                    try:client=Client(f'http://127.0.0.1:{port}/mcp',token.read_text());break
                    except (OSError,RuntimeError):time.sleep(.1)
                else:raise TimeoutError('candidate never ready')
                tools=client.rpc('tools/list',{})['tools'];byname={t['name']:t for t in tools}
                v4file=ROOT/'deploy/contracts/hepta-runtime-full-operator-v4.json'
                v4=ToolContract.load(v4file,'d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1')
                assert len(tools)==len(byname)==58 and set(byname)-set(v4.by_name)==ADDITIONS
                assert all(byname[n]==t for n,t in v4.by_name.items())
                verify_successor(tools,a.contract)
                checks.append('all original 50 definitions exact; five ownership definitions reviewed by exact v7 digest; all other v6 definitions exact')
                readonly={'host_health','read_multiple_files','search_list','search_results','effective_config','request_history'}
                for name in ADDITIONS:
                    hints=byname[name]['annotations']
                    assert hints=={'readOnlyHint':name in readonly,'destructiveHint':False,
                        'idempotentHint':name!='search_start','openWorldHint':False},(name,hints)
                    schema=byname[name]['inputSchema']
                    assert schema.get('additionalProperties') is False and 'owner' not in schema.get('properties',{})
                checks.append('strict schemas; accurate read-only and search-state annotations; owner never caller input')
                path=pathlib.Path(a.contract)
                frozen=ToolContract.load(path,V7_SHA256);frozen.verify(tools)
                checks.append('exact reviewed v7 native contract verified')
                metadata={'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities':{},
                    'io.modelcontextprotocol/clientInfo':{'name':'dc-v7-candidate-verifier','version':'1'}}
                requests=[{'jsonrpc':'2.0','id':i+1,'method':method,'params':{'_meta':metadata,**params}}
                    for i,(method,params) in enumerate([
                        ('server/discover',{}),('tools/list',{}),
                        ('tools/call',{'name':'host_list','arguments':{}}),
                        ('tools/call',{'name':'request_history','arguments':{}}),
                        ('tools/call',{'name':'request_history','arguments':{'owner':'a'*64}}),
                        ('tools/call',{'name':'search_start','arguments':{'host':'disabled-fixture',
                            'root':str(workspace),'query':'fixture','kind':'files','owner':'a'*64}})])]
                command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio',
                    '--upstream',f'http://127.0.0.1:{port}/mcp','--token-file',str(token),
                    '--contract',str(path.resolve()),'--contract-sha256',hashlib.sha256(path.read_bytes()).hexdigest(),
                    '--acknowledge-full-operator']
                facade_log=pathlib.Path(a.out).with_suffix('.facade.stderr.log')
                facade_stream=facade_log.open('xb')
                wire=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=facade_stream,bufsize=0)
                rows=[];buffer=b''
                try:
                    for request in requests:
                        wire.stdin.write((json.dumps(request)+'\n').encode());wire.stdin.flush()
                        deadline=time.monotonic()+45
                        while b'\n' not in buffer:
                            remaining=deadline-time.monotonic()
                            if remaining<=0 or not select.select([wire.stdout],[],[],remaining)[0]:
                                raise TimeoutError('facade request/reply deadline')
                            part=os.read(wire.stdout.fileno(),65536)
                            if not part:raise RuntimeError('facade ended before expected reply')
                            buffer+=part
                            if len(buffer)>1024*1024:raise RuntimeError('facade reply exceeded bounded fixture')
                        line,buffer=buffer.split(b'\n',1)
                        rows.append(json.loads(line))
                    wire.stdin.close()
                    assert wire.wait(timeout=15)==0,wire.returncode
                    assert not buffer
                finally:
                    if wire.poll() is None:wire.terminate()
                    wire.wait(timeout=15)
                    facade_stream.close()
                    raw=facade_log.read_bytes()
                    facade_log.write_bytes(raw.replace(token.read_text().encode(),b'[redacted-test-token]'))
                    facade_log.chmod(0o600)
                assert len(rows)==len(requests)
                for request,row in zip(requests[:4],rows[:4]):
                    assert row.get('id')==request['id'] and 'error' not in row
                    assert row['result']['resultType']=='complete'
                    if request['method'] in ('server/discover','tools/list'):assert row['result']['cacheScope']=='private'
                frozen.verify(rows[1]['result']['tools'])
                assert not rows[2]['result'].get('isError')
                scoped=json.loads(rows[3]['result']['content'][0]['text'])
                assert scoped['ownership_scope']=='authenticated_private_operator_credential'
                assert scoped['authenticated_chatgpt_caller_isolation'] is False
                assert scoped['cross_session_resume'] is True
                assert token.read_text() not in json.dumps(scoped)
                for request,row in zip(requests[4:],rows[4:]):
                    assert row.get('id')==request['id']
                    assert 'error' in row or row.get('result',{}).get('isError') is True
                checks.append('modern native/facade discover, exact catalog and credential history scope')
                checks.append('history/search owner arguments refused before any configured-host operation')
                receipt={'schema':'hepta-dc-functional-v7-catalog-native-v1',
                    'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'contract_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'catalog_sha256':frozen.catalog_sha256,'tool_count':58,'checks':checks,'complete':True,
                    'facade_stderr_sha256':hashlib.sha256(facade_log.read_bytes()).hexdigest(),
                    'facade_stderr_path':str(facade_log),
                    'origin':'isolated local native controller and facade',
                    'qualification_scope':'local_native_and_facade_contract_protocol_only','target_health_probed':False,
                    'chatgpt_originated':False,'installed_runtime_changed':False,'desktop_commander_changed':False,
                    'full_dc_replacement_qualified':False}
                with pathlib.Path(a.out).open('x') as stream:json.dump(receipt,stream,indent=2);stream.write('\n')
                print(json.dumps({'complete':True,'passed':len(checks),'contract_sha256':receipt['contract_sha256']}))
            finally:
                if proc.poll() is None:proc.terminate()
                proc.wait(timeout=12)
if __name__=='__main__':main()
