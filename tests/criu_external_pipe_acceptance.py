#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Transparent state restore with explicit replacement of external stdin/stdout pipes.
Only a disposable ordinary Python application is checkpointed. The application
has no checkpoint API. Parent-owned stream buffers are drained before handoff.
This does not adopt Desktop Commander's unknown live descriptors or GUI state.
"""
import argparse
import hashlib
import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import time

APPLICATION=r'''
import hashlib,json,os,sys
memory=os.urandom(40);count=0
print(json.dumps({'event':'READY','pid':os.getpid(),'uid':os.getuid(),'hash':hashlib.sha256(memory).hexdigest(),'count':count}),flush=True)
for line in sys.stdin:
 if line.strip()=='EXIT':break
 count+=int(line)
 print(json.dumps({'event':'VALUE','pid':os.getpid(),'uid':os.getuid(),'hash':hashlib.sha256(memory).hexdigest(),'count':count}),flush=True)
'''


def read_line(fd,timeout=10):
    result=bytearray();deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        ready,_,_=select.select([fd],[],[],max(0,deadline-time.monotonic()))
        if not ready:break
        data=os.read(fd,1)
        if not data:raise RuntimeError('unexpected stream EOF')
        result+=data
        if data==b'\n':return json.loads(result)
        if len(result)>4096:raise RuntimeError('fixture output exceeded bound')
    raise TimeoutError('no expected fixture line')


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--criu',required=True);ap.add_argument('--expected-criu-sha256',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    binary=pathlib.Path(a.criu).resolve(strict=True)
    with binary.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
    if sha!=a.expected_criu_sha256:raise ValueError('CRIU artifact mismatch')
    root=pathlib.Path(tempfile.mkdtemp(prefix='hepta-criu-external-pipes-',dir=str(pathlib.Path.home())));root.chmod(0o700);images=root/'images';images.mkdir(mode=0o700)
    report={'complete':False,'fixture_root':str(root),'criu_sha256':sha,'application_checkpoint_code':False,'business_processes_modified':False,'dc_external_pipes_claimed':False}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    log=(root/'error.log').open('wb');app=subprocess.Popen([sys.executable,'-u','-c',APPLICATION],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,start_new_session=True)
    new_r,new_w=os.pipe();out_r,out_w=os.pipe();restored=False
    try:
        first=read_line(app.stdout.fileno());assert first['event']=='READY' and first['uid']==os.getuid();report['ready']=first
        app.stdin.write(b'17\n');app.stdin.flush();before=read_line(app.stdout.fileno());assert before['count']==17;report['before']=before
        resources={}
        for fd in (0,1):
            link=os.readlink('/proc/'+str(app.pid)+'/fd/'+str(fd))
            if not link.startswith('pipe:['):raise ValueError('fixture fd is not a pipe')
            resources[str(fd)]=link
        report['original_resources']=resources
        dumped=subprocess.run(['sudo','-n',str(binary),'dump','--tree',str(app.pid),'--images-dir',str(images),'--work-dir',str(images),'--log-file','dump.log','--shell-job','-v4'],capture_output=True,text=True,timeout=50)
        report['dump']={'exit_code':dumped.returncode,'stderr':dumped.stderr[-2000:]};save()
        if dumped.returncode:raise RuntimeError('external-pipe dump failed; inspect private dump.log')
        app.wait(timeout=10);app.stdin.close();app.stdout.close()
        # Only fd 0 and 1 are inherited through sudo, avoiding closefrom changes.
        command=[str(binary),'restore','--images-dir',str(images),'--work-dir',str(images),'--log-file','restore.log','--shell-job','--restore-detached','--pidfile',str(root/'restored.pid'),'--inherit-fd','fd[INHERIT_INPUT]:'+resources['0'],'--inherit-fd','fd[INHERIT_OUTPUT]:'+resources['1'],'-v4']
        bridge="import os,sys;a=os.dup(0);b=os.dup(1);os.set_inheritable(a,True);os.set_inheritable(b,True);args=[v.replace('INHERIT_INPUT',str(a)).replace('INHERIT_OUTPUT',str(b)) for v in sys.argv[1:]];os.execv(args[0],args)"
        proc=subprocess.Popen(['sudo','-n','/usr/bin/python3','-c',bridge,*command],stdin=new_r,stdout=out_w,stderr=log);code=proc.wait(timeout=50)
        report['restore']={'exit_code':code};save()
        if code:raise RuntimeError('external-pipe restore failed; inspect private restore.log')
        restored=True
        actual_pid=int(subprocess.check_output(['sudo','-n','/bin/cat',str(root/'restored.pid')],text=True))
        assert actual_pid==before['pid']
        os.write(new_w,b'5\n');after=read_line(out_r);report['after']=after
        assert after['count']==22 and after['pid']==before['pid'] and after['uid']==before['uid'] and after['hash']==before['hash']
        os.write(new_w,b'EXIT\n')
        report.update(complete=True,same_pid=True,same_random_memory=True,previously_consumed_input_state_preserved=True,new_external_stdin_stdout_operational=True,parent_buffers_drained_before_handoff=True,old_input_not_replayed=True,new_stream_endpoint_mapping_explicit=True,host_policy_changed=False)
        save();print('CRIU_EXTERNAL_PIPE_PASS '+json.dumps({'pid':actual_pid,'before':17,'after':22,'memory_hash_equal':True,'same_pid':True}),flush=True)
    finally:
        if app.poll() is None:app.terminate();app.wait(timeout=10)
        if restored:
            try:os.write(new_w,b'EXIT\n')
            except (OSError,BrokenPipeError):pass
        for fd in (new_r,new_w,out_r,out_w):os.close(fd)
        log.close();save()


if __name__=='__main__':main()
