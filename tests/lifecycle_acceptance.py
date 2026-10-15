#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real SSH/MCP archive and terminal-recovery tests; no production service restart."""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True)
    a=ap.parse_args();key=secrets.token_hex(16);target='/tmp/hepta-lifecycle-'+key
    report={'ssh_target':a.ssh_target,'checks':[],'complete':False,'password_prompt_tested':False,'physical_target_reboot_tested':False,'chatgpt_tested':False}
    controller=None;client=None;sessions=[]
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2))
    def passed(name,detail=None):
        report['checks'].append({'check':name,'detail':detail});save();print('PASS',name,flush=True)
    def ssh(code):
        p=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=8',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=30)
        if p.returncode:raise RuntimeError(p.stderr)
        return json.loads(p.stdout)
    meta=ssh("import pathlib,sys,os,json,shutil;p=pathlib.Path("+repr(target)+");p.mkdir(mode=0o700);print(json.dumps({'uid':os.getuid(),'platform':'linux' if sys.platform=='linux' else 'macos','path':str(p.resolve()),'free':shutil.disk_usage(p).free}))")
    target=meta['path'];report['target_test_directory']=target
    if meta['free']<128*1024*1024:raise RuntimeError('target lacks space for disposable archive test')
    passed('actual SSH account and disposable workspace',meta)
    with tempfile.TemporaryDirectory(prefix='hepta-lifecycle-controller-') as work:
        work=pathlib.Path(work);(work/'workspace').mkdir();token=secrets.token_hex(32);(work/'token').write_text(token);os.chmod(work/'token',0o600)
        host={'ssh_target':a.ssh_target,'platform':meta['platform'],'execution_mode':'operator','remote_state_dir':target,'allow_execute':True,'allow_pty':True,'allow_job_network':True,'allow_detached_fallback':True,'allow_write':True,'allowed_read_path_prefixes':[target],'allowed_write_path_prefixes':[target]}
        config={'state_dir':str(work/'state'),'controller_workspace_roots':[str(work/'workspace')],'hosts':{'operator':host,'other':host}}
        (work/'config.json').write_text(json.dumps(config))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        url=f'http://127.0.0.1:{port}/mcp'
        def start():
            nonlocal controller,client
            with (work/'controller.log').open('ab') as log:
                controller=subprocess.Popen([a.binary,'mcp','--path',str(work/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(work/'config.json'),'--auth-token-file',str(work/'token')],stdout=log,stderr=log,stdin=subprocess.DEVNULL)
            for _ in range(100):
                if controller.poll() is not None:raise RuntimeError((work/'controller.log').read_text()[-3000:])
                try:client=Client(url,token);return
                except (OSError,RuntimeError):time.sleep(.1)
            raise RuntimeError('test endpoint unavailable')
        def read(sid,**params):return client.call('pty_read',{'host':'operator','session_id':sid,**params})
        def until(sid,marker):
            for _ in range(100):
                value=read(sid)
                if marker in value['text']:return value
                time.sleep(.05)
            raise AssertionError('missing terminal marker '+marker)
        def terminal(code,idem=None):
            p={'host':'operator','executable':'/usr/bin/python3','args':['-c',code],'cwd':target}
            if idem:p['idempotency_key']=idem
            value=client.call('pty_start',p);sid=value['session_id'];sessions.append(sid)
            assert value['persistent_across_runtime_restart']
            return sid,p,value
        def finish(sid):
            for _ in range(100):
                part=read(sid)
                if part['status']['state']!='running':return part
                time.sleep(.05)
            raise AssertionError('terminal did not exit')
        try:
            start()
            tools={x['name']:x for x in client.rpc('tools/list',{})['tools']}
            assert 'idempotency_key' in tools['pty_start']['inputSchema']['properties']
            assert 'request_id' in tools['pty_write']['inputSchema']['properties']
            passed('persistent terminal discovery and input idempotency schemas')
            count=20*1024*1024+13
            job=client.call('process_start',{'host':'operator','executable':'/usr/bin/python3','args':['-c',f"import sys;sys.stdout.buffer.write(b'x'*{count});sys.stderr.write('END_ERR')"],'cwd':target,'timeout_seconds':30})['job']
            status=client.call('process_wait',{'host':'operator','job_id':job['id'],'timeout_seconds':30})
            assert status['state']=='succeeded' and status['output_complete'],status
            part=client.call('process_read',{'host':'operator','job_id':job['id'],'stdout_offset':count-13})
            assert part['stdout']['text']=='x'*13 and part['stdout']['size']==count and part['stderr']['text']=='END_ERR'
            archive=job['remote_job_dir']+'/stdout.log'
            digest=ssh("import hashlib,json;print(json.dumps({'sha256':hashlib.file_digest(open("+repr(archive)+",'rb'),'sha256').hexdigest()}))") if meta['platform']=='linux' else ssh("import hashlib,json;print(json.dumps({'sha256':hashlib.sha256(open("+repr(archive)+",'rb').read()).hexdigest()}))")
            assert digest['sha256']==hashlib.sha256(b'x'*count).hexdigest()
            passed('full durable archive above 16 MiB verified by SHA256',{'bytes':count,**digest})
            count=6*1024*1024+17
            sid,_,_=terminal(f"import os;os.write(1,b'z'*{count})")
            part=finish(sid);assert part['output_complete'] and part['available_end']==count,part
            assert read(sid,offset=count-17)['text']=='z'*17
            path=part['archive_path'];digest=ssh("import hashlib,json;print(json.dumps({'sha256':hashlib.sha256(open("+repr(path)+",'rb').read()).hexdigest()}))")
            assert digest['sha256']==hashlib.sha256(b'z'*count).hexdigest()
            assert read(sid,offset=0,limit=1)['text']=='z'
            passed('full PTY archive above 4 MiB without prefix eviction',{'bytes':count,**digest})
            code="import os,time;print('OWNER_PID='+str(os.getpid()),flush=True);time.sleep(2);print('WHILE_OFFLINE',flush=True);v=input();print('AFTER_'+v,flush=True);v=input();print('FINAL_'+v,flush=True)"
            sid,params,started=terminal(code,key+'-restart');text=until(sid,'OWNER_PID=')['text'];pid=int(re.search(r'OWNER_PID=(\d+)',text).group(1))
            controller.terminate();controller.wait(timeout=15);time.sleep(2.1);start()
            same=client.call('pty_start',params);assert same['session_id']==sid and same['reused'] and same['status']['pid']==pid
            assert any(x['session_id']==sid for x in client.call('pty_list',{})['sessions'])
            until(sid,'WHILE_OFFLINE')
            client.call('pty_read',{'host':'other','session_id':sid},denied=True)
            passed('graceful controller restart preserves same live target PTY and offline output',{'pid':pid,'session_id':sid})
            write={'host':'operator','session_id':sid,'data':'FIRST\n','request_id':key+'-input'}
            assert client.call('pty_write',write)['complete'];until(sid,'AFTER_FIRST')
            controller.kill();controller.wait(timeout=10);start()
            again=client.call('pty_write',write);assert again['reused']
            client.call('pty_write',{**write,'data':'DIFFERENT\n'},denied=True)
            assert read(sid)['status']['pid']==pid
            client.call('pty_write',{'host':'operator','session_id':sid,'data':'SECOND\n','request_id':key+'-second'})
            part=finish(sid);assert part['output_complete'] and 'FINAL_SECOND' in part['text']
            assert part['text'].count('AFTER_FIRST')==1 and part['text'].count('FINAL_SECOND')==1
            passed('SIGKILL controller recovery and once-only input across reconnect',{'pid':pid})
            sid=client.call('sudo_start',{'host':'operator','executable':'/usr/bin/id','args':['-u'],'non_interactive':True})['session_id'];sessions.append(sid)
            part=finish(sid);assert part['output_complete'] and part['text'].strip()=='0',part
            passed('persistent sudo PTY retains existing root authorization without policy change')
            report['complete']=True;report['passed']=len(report['checks']);save();print('ALL_PASS',report['passed'],flush=True)
        finally:
            if controller is not None and controller.poll() is None and client is not None:
                for sid in sessions:
                    try:client.call('pty_close',{'host':'operator','session_id':sid})
                    except Exception:pass
                controller.terminate();controller.wait(timeout=15)


if __name__=='__main__':main()
