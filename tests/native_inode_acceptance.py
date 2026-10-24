#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real SSH and authenticated MCP tests for inode-preserving native patching.
Only unique fixture files; held-open descriptor proves more than pathname equality.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True);ap.add_argument('--url');ap.add_argument('--token-file');ap.add_argument('--host',default='operator');a=ap.parse_args()
    with open(a.binary,'rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
    report={'complete':False,'checks':[],'binary_sha256':sha,'ssh_target':a.ssh_target,'installed_endpoint':bool(a.url)}
    def passed(label):
        report['checks'].append(label);pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('PASS '+label,flush=True)
    root='/tmp/hepta-inode-native-'+secrets.token_hex(12)
    code="import pathlib,os,sys,json;r=pathlib.Path("+repr(root)+");r.mkdir(mode=0o700);r=r.resolve();p=r/'data.bin';p.write_bytes(b'original hardlink payload\\n');os.link(p,r/'alias.bin');p.chmod(0o6750 if sys.platform=='linux' else 0o640);print(json.dumps({'root':str(r),'platform':'linux' if sys.platform=='linux' else 'macos','inode':p.stat().st_ino}))"
    proc=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=20)
    if proc.returncode:raise RuntimeError(proc.stderr)
    fixture=json.loads(proc.stdout);root=fixture['root'];report['fixture']=fixture
    with tempfile.TemporaryDirectory(prefix='hepta-inode-controller-') as directory:
        d=pathlib.Path(directory);workspace=d/'workspace';workspace.mkdir();token=secrets.token_hex(32);(d/'token').write_text(token);(d/'token').chmod(0o600)
        host={'ssh_target':a.ssh_target,'platform':fixture['platform'],'execution_mode':'operator','remote_state_dir':root+'/jobs','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[root],'allowed_write_path_prefixes':[root]}
        config={'state_dir':str(d/'state'),'controller_workspace_roots':[str(workspace)],'hosts':{a.host:host}};(d/'config.json').write_text(json.dumps(config))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        controller=None;job=None;c=None
        if not a.url:
            with (d/'runtime.log').open('w') as log:controller=subprocess.Popen([a.binary,'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}','--runtime-config',str(d/'config.json'),'--auth-token-file',str(d/'token')],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if controller and controller.poll() is not None:raise RuntimeError((d/'runtime.log').read_text()[-2000:])
                try:c=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
                except (OSError,RuntimeError):time.sleep(.1)
            if c is None:raise RuntimeError('MCP unavailable')
            tool=next(t for t in c.rpc('tools/list',{})['tools'] if t['name']=='binary_patch_inode');assert not {'sudo','executable','root'}&tool['inputSchema']['properties'].keys()
            passed('native inode tool discovered without privilege override fields')
            path=root+'/data.bin';original=c.call('file_info',{'host':a.host,'path':path})
            patch={'host':a.host,'path':path,'action':'apply','transaction_id':'native-inode-01','acknowledge_non_atomic':True,'preserve_special_bits':True,'offset':0,'data_base64':base64.b64encode(b'UPDATED!').decode(),'expected_sha256':original['sha256'],'expected_version':original['version']}
            if fixture['platform']!='linux':
                c.call('binary_patch_inode',patch,denied=True)
                assert c.call('file_info',{'host':a.host,'path':path})['sha256']==original['sha256']
                passed('unsupported platform is refused with original linked file unchanged')
            else:
                for override in ({'acknowledge_non_atomic':False},{'expected_version':'STALE'},{'preserve_special_bits':False}):c.call('binary_patch_inode',{**patch,**override},denied=True)
                assert c.call('file_info',{'host':a.host,'path':path})['sha256']==original['sha256']
                passed('stale source, omitted special-bit permission and atomicity acknowledgement rejected before mutation')
                code="import pathlib,json,os,time;r=pathlib.Path("+repr(root)+");f=(r/'alias.bin').open('rb');print('FD_READY',flush=True);end=time.monotonic()+90\nwhile not(r/'readnow').exists() and time.monotonic()<end:time.sleep(.05)\nprint(json.dumps({'inode':os.fstat(f.fileno()).st_ino,'mode':os.fstat(f.fileno()).st_mode&0o7777,'text':f.read().decode()}),flush=True)"
                job=c.call('process_start',{'host':a.host,'executable':'/usr/bin/python3','args':['-u','-c',code],'timeout_seconds':100})['job']['id']
                for _ in range(60):
                    page=c.call('process_read',{'host':a.host,'job_id':job})
                    if 'FD_READY' in page['stdout']['text']:break
                    time.sleep(.1)
                else:raise RuntimeError('held descriptor fixture not ready')
                result=c.call('binary_patch_inode',patch);assert result['state']=='committed' and result['inode_preserved'] and not result['atomic_visibility']
                for name in ('data.bin','alias.bin'):
                    info=c.call('file_info',{'host':a.host,'path':root+'/'+name});assert info['sha256']==result['sha256'] and info['metadata']['mode']==0o6750 and info['metadata']['link_count']==2
                c.call('binary_write',{'host':a.host,'path':root+'/readnow','data_base64':'MQ==','expected_version':'absent'})
                state=c.call('process_wait',{'host':a.host,'job_id':job,'timeout_seconds':15});assert state['state']=='succeeded'
                out=c.call('process_read',{'host':a.host,'job_id':job});value=json.loads(next(line for line in out['stdout']['text'].splitlines() if line.startswith('{')))
                assert value=={'inode':fixture['inode'],'mode':0o6750,'text':'UPDATED! hardlink payload\n'}
                report['held_descriptor']=value
                passed('hard-link aliases and already-open descriptor retain inode, patched bytes and special mode bits')
                replay=c.call('binary_patch_inode',patch);assert replay['reused'] and replay['sha256']==result['sha256']
                status=c.call('binary_patch_inode',{'host':a.host,'path':path,'action':'status','transaction_id':'native-inode-01','acknowledge_non_atomic':True})
                assert status['state']=='committed' and status['current_sha256']==result['sha256']
                c.call('binary_patch_inode',{**patch,'data_base64':'QkFERk9STSE='},denied=True)
                passed('exact transaction retry and status reconcile without repeating or accepting changed data')
                recovered=c.call('binary_patch_inode',{'host':a.host,'path':path,'action':'recover','transaction_id':'native-inode-01','acknowledge_non_atomic':True})
                assert recovered['state']=='committed' and recovered['sha256']==result['sha256']
                passed('explicit committed-state recovery preserves verified bytes and permissions')
            report.update(complete=True,passed=len(report['checks']));pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('NATIVE_INODE_PASS '+str(report['passed']))
        finally:
            if job and c:
                try:c.call('process_cancel',{'host':a.host,'job_id':job})
                except Exception:pass
            if controller:controller.terminate();controller.wait(timeout=20)


if __name__=='__main__':main()
