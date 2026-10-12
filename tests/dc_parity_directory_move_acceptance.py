#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real isolated MCP qualification of v4's non-overwriting directory move.

Only a disposable controller, private temporary workspace and test token are
used. The existing v3 contract, installed runtime and ChatGPT tunnel are not
changed; this is NOT ChatGPT-originated execution or product action approval.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from runtime_http_acceptance import Client

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy'))
from mcp_tool_contract import ToolContract,make_contract


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--v3-contract',default=str(ROOT/'deploy/contracts/hepta-runtime-full-operator-v3.json'))
    parser.add_argument('--v4-contract')
    parser.add_argument('--official-schema',help='Optional locally supplied published MCP 2026-07-28 JSON Schema')
    parser.add_argument('--freeze-v4-contract')
    args=parser.parse_args()
    checks=[]
    def passed(label):
        checks.append(label)
        print('PASS',label,flush=True)

    with tempfile.TemporaryDirectory(prefix='hepta-dir-move-v4-') as directory:
        base=pathlib.Path(directory)
        workspace=base/'workspace';workspace.mkdir(mode=0o700)
        tokenfile=base/'token';tokenfile.write_text(secrets.token_hex(32));tokenfile.chmod(0o600)
        isolated_host={
            'ssh_target':'localhost','platform':'linux',
            'remote_state_dir':str(base/'unused-state'),
            'execution_mode':'isolated','allow_execute':False,'allow_pty':False,
            'allow_write':False,'allowed_read_path_prefixes':[str(workspace)],
            'allowed_write_path_prefixes':[str(workspace)]
        }
        config=base/'runtime.json'
        config.write_text(json.dumps({
            'state_dir':str(base/'state'),'controller_workspace_roots':[str(workspace)],
            'hosts':{'disabled-fixture':isolated_host}
        }))
        with socket.socket() as s:
            s.bind(('127.0.0.1',0))
            port=s.getsockname()[1]
        cmd=[str(pathlib.Path(args.binary).resolve(strict=True)),'mcp','--path',str(workspace),
             '--bind',f'127.0.0.1:{port}','--runtime-config',str(config),
             '--auth-token-file',str(tokenfile)]
        with (base/'controller.log').open('wb') as logfile:
            process=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=logfile,stderr=logfile)
            try:
                for _ in range(90):
                    if process.poll() is not None:
                        raise RuntimeError('isolated fixture terminated: '+
                            (base/'controller.log').read_text(errors='replace')[-1200:])
                    try:
                        client=Client(f'http://127.0.0.1:{port}/mcp',tokenfile.read_text())
                        break
                    except (OSError,RuntimeError):
                        time.sleep(.1)
                else:
                    raise TimeoutError('isolated MCP did not start')

                catalog=client.rpc('tools/list',{})['tools']
                by_name={t['name']:t for t in catalog}
                assert len(catalog)==len(by_name)==50
                v3_file=pathlib.Path(args.v3_contract)
                v3=ToolContract.load(v3_file,hashlib.sha256(v3_file.read_bytes()).hexdigest())
                assert len(v3.tools)==49
                assert set(by_name)-set(v3.by_name)=={'directory_move'}
                for name,prior in v3.by_name.items():
                    assert by_name[name]==prior,('v3 tool drift',name)
                hints=by_name['directory_move']['annotations']
                assert hints=={'readOnlyHint':False,'destructiveHint':True,
                              'idempotentHint':False,'openWorldHint':False},hints
                passed('50 tools discovered, v3 49 unchanged, directory move truthful risk')

                if args.v4_contract:
                    p=pathlib.Path(args.v4_contract)
                    pinned=ToolContract.load(p,hashlib.sha256(p.read_bytes()).hexdigest())
                    pinned.verify(catalog)
                    passed('v4 frozen exact catalog verified')
                if args.v4_contract:
                    pinned_path=pathlib.Path(args.v4_contract)
                    token_sha=hashlib.sha256(pinned_path.read_bytes()).hexdigest()
                    command=[sys.executable,str(ROOT/'deploy/chatgpt_full_operator.py'),
                        '--stdio','--upstream',f'http://127.0.0.1:{port}/mcp',
                        '--token-file',str(tokenfile),'--contract',str(pinned_path.resolve()),
                        '--contract-sha256',token_sha,'--acknowledge-full-operator']
                    metadata={
                        'io.modelcontextprotocol/protocolVersion':'2026-07-28',
                        'io.modelcontextprotocol/clientCapabilities':{},
                        'io.modelcontextprotocol/clientInfo':{'name':'parity-v4-local-verifier','version':'1'}
                    }
                    methods=['server/discover','tools/list']
                    sent=[{'jsonrpc':'2.0','id':idx+1,'method':method,
                           'params':{'_meta':metadata}} for idx,method in enumerate(methods)]
                    wire=subprocess.run(command,input=b''.join(
                        (json.dumps(item)+'\n').encode() for item in sent),
                        capture_output=True,timeout=45)
                    assert wire.returncode==0 and len(wire.stdout.splitlines())==2
                    parsed=[json.loads(line) for line in wire.stdout.splitlines()]
                    for req,response in zip(sent,parsed):
                        assert response.get('id')==req['id'] and 'error' not in response
                        assert response['result']['resultType']=='complete'
                        assert response['result']['cacheScope']=='private'
                        assert response['result']['_meta']['io.modelcontextprotocol/serverInfo']['name']=='hepta-runtime-full-operator'
                    assert parsed[0]['result']['supportedVersions']==['2026-07-28']
                    scanned=parsed[1]['result']['tools']
                    assert len(scanned)==50 and {t['name']:t for t in scanned}==by_name
                    passed('independent stdio modern MCP discover/tools-list preserves all 50 definitions')
                    if args.official_schema:
                        import jsonschema
                        spec=json.loads(pathlib.Path(args.official_schema).read_text())
                        for response,definition in zip(parsed,(
                            'DiscoverResultResponse','ListToolsResultResponse')):
                            validator=jsonschema.Draft202012Validator(
                                {**spec,'$ref':'#/$defs/'+definition})
                            errors=list(validator.iter_errors(response))
                            assert not errors,[e.message for e in errors]
                        passed('both actual modern MCP responses satisfy published official schema')
                if args.freeze_v4_contract:
                    target=pathlib.Path(args.freeze_v4_contract)
                    payload=(json.dumps(make_contract(catalog),ensure_ascii=False,indent=2)+'\n').encode()
                    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    with os.fdopen(fd,'wb') as output:output.write(payload)
                    passed('new v4 contract frozen without overwriting prior contract')

                old=workspace/'original';(old/'inner/deep').mkdir(parents=True)
                content=old/'inner/deep/keep.txt';content.write_text('中文 file tree\n')
                outer_inode=old.stat().st_ino;child_inode=(old/'inner').stat().st_ino
                new=workspace/'renamed'
                # Prime cached views at BOTH old and future destination names.
                # The future destination then disappears before the move, as it
                # would after an external filesystem cleanup, but its cached
                # content must not survive a real directory relocation.
                cached_old=client.call('view',{'path':str(content)})
                assert '中文 file tree' in str(cached_old)
                (new/'inner/deep').mkdir(parents=True)
                replacement_preview=new/'inner/deep/keep.txt'
                replacement_preview.write_text('中文 file tree\n')
                cached_new=client.call('view',{'path':str(replacement_preview)})
                assert '中文 file tree' in str(cached_new)
                shutil.rmtree(new)
                result=client.call('directory_move',{'source':str(old),'destination':str(new)})
                assert result['moved'] and new.is_dir() and not old.exists()
                assert new.stat().st_ino==outer_inode
                assert (new/'inner').stat().st_ino==child_inode
                assert (new/'inner/deep/keep.txt').read_text()=='中文 file tree\n'
                passed('nonempty directory move retains tree, content and inode identities')
                # Equal content is intentional: without subtree invalidation,
                # view returns an incorrect 'unchanged since last viewed' marker.
                after_view=client.call('view',{'path':str(new/'inner/deep/keep.txt')})
                assert '中文 file tree' in str(after_view),str(after_view)
                assert 'unchanged since' not in str(after_view),str(after_view)
                (old/'inner/deep').mkdir(parents=True)
                content.write_text('中文 file tree\n')
                recreated_view=client.call('view',{'path':str(content)})
                assert '中文 file tree' in str(recreated_view),str(recreated_view)
                assert 'unchanged since' not in str(recreated_view),str(recreated_view)
                passed('whole-subtree old/destination view caches invalidated after move')

                second=workspace/'second';second.mkdir()
                client.call('directory_move',{'source':str(second),'destination':str(new)},denied=True)
                assert second.is_dir() and new.is_dir()
                passed('existing nonempty destination never overwritten')

                source=workspace/'source';source.mkdir()
                destination=workspace/'existing-empty';destination.mkdir()
                client.call('directory_move',{'source':str(source),'destination':str(destination)},denied=True)
                assert source.is_dir() and destination.is_dir()
                passed('existing empty destination never replaced')

                regular=workspace/'file.txt';regular.write_text('not directory')
                client.call('directory_move',{'source':str(regular),'destination':str(workspace/'file-renamed')},denied=True)
                assert regular.is_file()
                passed('ordinary file source refused')

                link=workspace/'source-link';link.symlink_to(source,target_is_directory=True)
                client.call('directory_move',{'source':str(link),'destination':str(workspace/'bad-link')},denied=True)
                assert link.is_symlink()
                passed('symlink source refused')

                ancestor=workspace/'source-parent-link';ancestor.symlink_to(workspace,target_is_directory=True)
                client.call('directory_move',{'source':str(source),'destination':str(ancestor/'bad')},denied=True)
                assert source.is_dir() and not (workspace/'bad').exists()
                passed('symlinked target parent refused')

                client.call('directory_move',{'source':str(source),'destination':str(workspace/'absent-parent/child')},denied=True)
                assert source.is_dir()
                passed('missing target parent refused')

                inside=source/'child';inside.mkdir()
                client.call('directory_move',{'source':str(source),'destination':str(inside/'loop')},denied=True)
                assert inside.is_dir()
                passed('moving directory inside itself rejected')

                external=base/'outside'
                client.call('directory_move',{'source':str(source),'destination':str(external)},denied=True)
                client.call('directory_move',{'source':str(external),'destination':str(workspace/'inside')},denied=True)
                assert source.is_dir() and not external.exists()
                passed('both path endpoints must stay inside authorized workspace')

                client.call('directory_move',{'source':str(source),'destination':str(source)},denied=True)
                assert source.is_dir()
                passed('self-move rejected')

                protected=workspace/'untouched';protected.write_text('DO_NOT_CHANGE\n')
                nested_symlink=source/'nested-link';nested_symlink.symlink_to(protected)
                final=workspace/'tree-moved'
                client.call('directory_move',{'source':str(source),'destination':str(final)})
                assert (final/'nested-link').is_symlink() and protected.read_text()=='DO_NOT_CHANGE\n'
                passed('internal symlink retained without following or touching target')

                result={'schema':'hepta-v4-dc-directory-move-isolated-mcp-v1','complete':True,
                        'tools':len(catalog),'checks':checks,'passed':len(checks),
                        'v3_contract_sha256':hashlib.sha256(v3_file.read_bytes()).hexdigest(),
                        'model_origin':False,'runtime_or_DC_restarted':False,'public_gateway_started':False}
                out=pathlib.Path(args.out)
                if out.exists():raise FileExistsError('do not overwrite prior acceptance')
                out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
                print('ALL_PASS',len(checks),flush=True)
            finally:
                if process.poll() is None:process.terminate()
                process.wait(timeout=10)

if __name__=='__main__':main()
