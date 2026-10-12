#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent temporary-controller MCP acceptance for genuine DC file parity.

These operations are not sent from ChatGPT and are NOT proof of platform write
approval. Only one private temp workspace, service and token are created. The
installed 46-tool native runtime, tunnel and Desktop Commander are unchanged.
"""
import argparse
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

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--out',required=True)
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
                assert len(actual)==48,len(actual)
                hints=actual['directory_create']['annotations']
                assert hints['readOnlyHint'] is False and hints['destructiveHint'] is False and hints['idempotentHint'] is True and hints['openWorldHint'] is False
                hints=actual['file_move']['annotations']
                assert hints['readOnlyHint'] is False and hints['destructiveHint'] is True and hints['idempotentHint'] is False and hints['openWorldHint'] is False
                passed('48 native tools discovered; both new tool annotations truthful')
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
