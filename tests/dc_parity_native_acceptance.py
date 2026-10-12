#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent temporary-controller MCP acceptance for genuine DC file parity.

These operations are not sent from ChatGPT and are NOT proof of platform write
approval. Only one private temp workspace, service and token are created. The
installed 46-tool native runtime, tunnel and Desktop Commander are unchanged.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import time

from runtime_http_acceptance import Client
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"deploy"))
from mcp_tool_contract import make_contract, ToolContract, canonical

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--catalog-out', help='Freeze reviewed candidate MCP schema; requires absent path')
    ap.add_argument('--verify-contract', help='Require exact candidate schema to match this frozen catalog')
    args=ap.parse_args()
    binary=str(pathlib.Path(args.binary).resolve(strict=True))
    checks=[]
    def passed(name):
        checks.append(name)
        print('PASS',name,flush=True)
    with tempfile.TemporaryDirectory(prefix='hepta-dc-parity-native-') as d:
        root=pathlib.Path(d)
        workspace=root/'workspace';workspace.mkdir(mode=0o700)
        state=root/'state';tokenfile=root/'token'
        token=secrets.token_hex(32)
        tokenfile.write_text(token);tokenfile.chmod(0o600)
        config=root/'runtime.json'
        host={'ssh_target':'localhost','platform':'linux',
              'remote_state_dir':str(root/'remote'),
              'execution_mode':'isolated','allow_execute':False,
              'allow_pty':False,'allow_write':False,
              'allowed_read_path_prefixes':[str(workspace)],
              'allowed_write_path_prefixes':[str(workspace)]}
        config.write_text(json.dumps({'state_dir':str(state),
            'controller_workspace_roots':[str(workspace)],
            'hosts':{'disabled-test-host':host}}))
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port=sock.getsockname()[1]
        with (root/'controller.log').open('wb') as log:
            cmd=[binary,'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}',
                 '--runtime-config',str(config),'--auth-token-file',str(tokenfile)]
            proc=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            try:
                endpoint=f'http://127.0.0.1:{port}/mcp'
                for _ in range(100):
                    if proc.poll() is not None:
                        raise RuntimeError('isolated MCP candidate exited before readiness: ' +
                            (root/'controller.log').read_text(errors='replace')[-1200:])
                    try:
                        client=Client(endpoint,token)
                        break
                    except (OSError,RuntimeError):
                        time.sleep(.1)
                else:
                    raise TimeoutError('isolated MCP candidate never became ready')
                actual={x['name']:x for x in client.rpc('tools/list',{})['tools']}
                assert len(actual)==49,len(actual)
                source=pathlib.Path(__file__).resolve().parents[1]
                original=json.loads((source/'deploy/contracts/hepta-runtime-full-operator-v1.json').read_text())
                old_tools={t['name']:t for t in original['tools']}
                assert len(old_tools)==46
                assert set(actual)-set(old_tools)=={'directory_create','file_move','text_file_write'}
                for name,old in old_tools.items():
                    assert actual[name]==old, ('old tool contract changed',name)
                candidate=make_contract(list(actual.values()))
                assert candidate['tool_count']==49
                frozen_v2=json.loads((source/'deploy/contracts/hepta-runtime-full-operator-v2.json').read_text())
                v2_tools={t['name']:t for t in frozen_v2['tools']}
                assert len(v2_tools)==48
                assert set(actual)-set(v2_tools)=={'text_file_write'}
                assert all(actual[name]==tool for name,tool in v2_tools.items())
                if args.verify_contract:
                    pinned=pathlib.Path(args.verify_contract)
                    contract=ToolContract.load(pinned,hashlib.sha256(pinned.read_bytes()).hexdigest())
                    contract.verify(list(actual.values()))
                if args.catalog_out:
                    output=pathlib.Path(args.catalog_out)
                    assert not output.exists(), 'do not overwrite an existing contract'
                    output.write_text(json.dumps(candidate,ensure_ascii=False,indent=2)+'\n')
                    output.chmod(0o600)
                passed('old 46 and v2 48 definitions unchanged; one additive bounded text operation')
                hints=actual['directory_create']['annotations']
                assert hints['readOnlyHint'] is False and hints['destructiveHint'] is False and hints['idempotentHint'] is True and hints['openWorldHint'] is False
                hints=actual['file_move']['annotations']
                assert hints['readOnlyHint'] is False and hints['destructiveHint'] is True and hints['idempotentHint'] is False and hints['openWorldHint'] is False
                hints=actual['text_file_write']['annotations']
                assert hints['readOnlyHint'] is False and hints['destructiveHint'] is True and hints['idempotentHint'] is False and hints['openWorldHint'] is False
                passed('49 native tools discovered; directory/move/text-write annotations truthful')
                target=workspace/'nested/inside'
                value=client.call('directory_create',{'path':str(target)})
                assert value['created'] is True and target.is_dir()
                value=client.call('directory_create',{'path':str(target)})
                assert value['created'] is False
                passed('real MCP directory create and idempotent existing directory')
                client.call('directory_create',{'path':str(root/'outside')},denied=True)
                assert not (root/'outside').exists()
                passed('controller workspace isolation enforced before mkdir')
                (workspace/'real').mkdir()
                (workspace/'alias').symlink_to(workspace/'real',target_is_directory=True)
                client.call('directory_create',{'path':str(workspace/'alias/blocked')},denied=True)
                assert not (workspace/'real/blocked').exists()
                passed('symlink parent refused without side effects')
                source=target/'source.txt'
                client.call('text_editor',{'command':'create','path':str(source),'content':'parity-line\n'})
                destination=target/'renamed.txt'
                moved=client.call('file_move',{'source':str(source),'destination':str(destination)})
                assert moved['moved'] and not source.exists() and destination.read_text()=='parity-line\n'
                passed('same private runtime creates and then atomically moves a regular file')
                source.write_text('keep original')
                client.call('file_move',{'source':str(source),'destination':str(destination)},denied=True)
                assert source.read_text()=='keep original' and destination.read_text()=='parity-line\n'
                passed('existing destination not overwritten')
                link=target/'link.txt';link.symlink_to(source)
                client.call('file_move',{'source':str(link),'destination':str(target/'should-not-exist')},denied=True)
                assert source.exists() and link.is_symlink()
                passed('file move refuses symlink source')
                client.call('file_move',{'source':str(source),'destination':str(root/'outside.txt')},denied=True)
                assert not (root/'outside.txt').exists()
                passed('both file move endpoints constrained to controller roots')
                plaintext=target/'managed-text.txt'
                created=client.call('text_file_write',{'path':str(plaintext),'mode':'create',
                    'expected_sha256':'absent','content':'First 中文\n'})
                assert created['was_new_file'] and plaintext.read_text()=='First 中文\n'
                appended=client.call('text_file_write',{'path':str(plaintext),'mode':'append',
                    'expected_sha256':created['sha256'],'content':'Next 🦀\n'})
                assert plaintext.read_text()=='First 中文\nNext 🦀\n'
                assert appended['sha256']==hashlib.sha256(plaintext.read_bytes()).hexdigest()
                replaced=client.call('text_file_write',{'path':str(plaintext),'mode':'replace',
                    'expected_sha256':appended['sha256'],'content':'Final\n'})
                assert plaintext.read_text()=='Final\n'
                passed('native bounded UTF-8 create/append/replace with pinned prior hashes')
                client.call('text_file_write',{'path':str(plaintext),'mode':'append',
                    'expected_sha256':created['sha256'],'content':'STALE'},denied=True)
                client.call('text_file_write',{'path':str(plaintext),'mode':'create',
                    'expected_sha256':'absent','content':'DUPLICATE'},denied=True)
                assert plaintext.read_text()=='Final\n'
                client.call('text_file_write',{'path':str(root/'outside.txt'),'mode':'create',
                    'expected_sha256':'absent','content':'OUTSIDE'},denied=True)
                assert not (root/'outside.txt').exists()
                passed('stale/duplicate publication and external workspace writes refused')
                symlinked=target/'forbidden.txt';symlinked.symlink_to(plaintext)
                client.call('text_file_write',{'path':str(symlinked),'mode':'replace',
                    'expected_sha256':replaced['sha256'],'content':'NEW'},denied=True)
                assert plaintext.read_text()=='Final\n'
                passed('plain text publication refuses symlinked target')
                data={'schema':'hepta-dc-parity-independent-mcp-v1','complete':True,'checks':checks,
                      'tool_count':len(actual),'chatgpt_origin':False,'runtime_install_changed':False,
                      'desktop_commander_changed':False,'public_gateway_started':False}
                pathlib.Path(args.out).write_text(json.dumps(data,indent=2)+'\n')
                print('ALL_PASS',len(checks),flush=True)
            finally:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=12)

if __name__=='__main__': main()
