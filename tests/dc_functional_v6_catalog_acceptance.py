#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Freeze or verify an additive native candidate; no installed service changes."""
import argparse,datetime,hashlib,json,pathlib,secrets,socket,subprocess,sys,tempfile,time
from runtime_http_acceptance import Client
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract,make_contract
from dc_successor_contract import ADDITIONS as V5_ADDITIONS, AUDIT_CONFIG_ADDITIONS
ADDITIONS=V5_ADDITIONS|AUDIT_CONFIG_ADDITIONS

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--contract',required=True)
    ap.add_argument('--freeze',action='store_true')
    a=ap.parse_args();binary=pathlib.Path(a.binary).resolve(strict=True);checks=[]
    with tempfile.TemporaryDirectory(prefix='hepta-dc-v6-catalog-') as td:
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
                v5file=ROOT/'deploy/contracts/hepta-runtime-full-operator-v5.json'
                v5=ToolContract.load(v5file,'f3fd365ae69e1189c550c4314c4fdfb12f4c80d8cc86d1bc0aca6bd1bf7c4cba')
                assert all(byname[n]==t for n,t in v5.by_name.items())
                checks.append('all original 50 definitions exact; only eight reviewed native additions; original v5 definitions exact')
                readonly={'host_health','read_multiple_files','search_list','search_results','effective_config','request_history'}
                for name in ADDITIONS:
                    hints=byname[name]['annotations']
                    assert hints=={'readOnlyHint':name in readonly,'destructiveHint':False,
                        'idempotentHint':name!='search_start','openWorldHint':False},(name,hints)
                    schema=byname[name]['inputSchema']
                    assert schema.get('additionalProperties') is False and 'owner' not in schema.get('properties',{})
                checks.append('strict schemas; accurate read-only and search-state annotations; owner never caller input')
                value=make_contract(tools);path=pathlib.Path(a.contract)
                data=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
                if a.freeze:
                    with path.open('xb') as stream:stream.write(data)
                    path.chmod(0o600)
                frozen=ToolContract.load(path,hashlib.sha256(path.read_bytes()).hexdigest());frozen.verify(tools)
                checks.append('exact frozen v6 native contract verified')
                metadata={'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                    'io.modelcontextprotocol/clientCapabilities':{},
                    'io.modelcontextprotocol/clientInfo':{'name':'dc-v6-candidate-verifier','version':'1'}}
                requests=[{'jsonrpc':'2.0','id':i+1,'method':method,'params':{'_meta':metadata,**params}}
                    for i,(method,params) in enumerate([
                        ('server/discover',{}),('tools/list',{}),
                        ('tools/call',{'name':'host_list','arguments':{}})])]
                command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),'--stdio',
                    '--upstream',f'http://127.0.0.1:{port}/mcp','--token-file',str(token),
                    '--contract',str(path.resolve()),'--contract-sha256',hashlib.sha256(path.read_bytes()).hexdigest(),
                    '--acknowledge-full-operator']
                wire=subprocess.run(command,input=''.join(json.dumps(q)+'\n' for q in requests),
                    text=True,capture_output=True,timeout=45)
                assert wire.returncode==0,wire.returncode
                rows=[json.loads(line) for line in wire.stdout.splitlines()]
                assert len(rows)==3
                for request,row in zip(requests,rows):
                    assert row.get('id')==request['id'] and 'error' not in row
                    assert row['result']['resultType']=='complete'
                    if request['method'] in ('server/discover','tools/list'):assert row['result']['cacheScope']=='private'
                frozen.verify(rows[1]['result']['tools'])
                assert not rows[2]['result'].get('isError')
                checks.append('modern MCP discover/list/read-only call through exact full-operator facade')
                receipt={'schema':'hepta-dc-functional-v6-catalog-native-v1',
                    'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'contract_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                    'catalog_sha256':frozen.catalog_sha256,'tool_count':58,'checks':checks,'complete':True,
                    'origin':'isolated local native controller and facade',
                    'chatgpt_originated':False,'installed_runtime_changed':False,'desktop_commander_changed':False,
                    'full_dc_replacement_qualified':False}
                with pathlib.Path(a.out).open('x') as stream:json.dump(receipt,stream,indent=2);stream.write('\n')
                print(json.dumps({'complete':True,'passed':len(checks),'contract_sha256':receipt['contract_sha256']}))
            finally:
                if proc.poll() is None:proc.terminate()
                proc.wait(timeout=12)
if __name__=='__main__':main()
