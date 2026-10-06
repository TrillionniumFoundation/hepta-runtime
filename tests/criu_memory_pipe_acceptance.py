#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real CRIU memory/anonymous-pipe restore of a disposable ordinary Python process.
The application has NO checkpoint/resume implementation. Only its own PID is
checkpointed. Existing sudo authority is used; no kernel/PAM/sysctl policy edit.
Run on a dedicated Linux test host, not against a business process.
"""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

APPLICATION=r'''
import hashlib,json,os,pathlib,sys,time
root=pathlib.Path(sys.argv[1]);(root/'started-once').open('x').close()
nonce=os.urandom(64);pipe_payload=os.urandom(96);reader,writer=os.pipe()
os.write(writer,pipe_payload);os.close(writer)
memory_value=sum(nonce)*7919
ready={'pid':os.getpid(),'uid':os.getuid(),'nonce_sha256':hashlib.sha256(nonce).hexdigest(),'pipe_sha256':hashlib.sha256(pipe_payload).hexdigest(),'memory_value':memory_value}
(root/'ready.json').write_text(json.dumps(ready));print('READY '+json.dumps(ready),flush=True)
while not (root/'resume-now').exists():time.sleep(.1)
restored={**ready,'pid':os.getpid(),'uid':os.getuid(),'nonce_sha256':hashlib.sha256(nonce).hexdigest(),'pipe_sha256':hashlib.sha256(os.read(reader,96)).hexdigest(),'memory_value':memory_value}
(root/'restored.json').write_text(json.dumps(restored));print('RESTORED '+json.dumps(restored),flush=True)
'''


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--criu',required=True);ap.add_argument('--expected-criu-sha256',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    binary=pathlib.Path(a.criu).resolve(strict=True)
    with binary.open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=a.expected_criu_sha256:raise ValueError('CRIU binary identity differs')
    root=pathlib.Path(tempfile.mkdtemp(prefix='hepta-criu-memory-pipe-',dir=str(pathlib.Path.home())));root.chmod(0o700);images=root/'images';images.mkdir(mode=0o700)
    report={'complete':False,'fixture_root':str(root),'criu_binary_sha256':actual,'criu_binary':str(binary),'real_process_memory_dumped':False,'application_checkpoint_code':False,'host_policy_changed':False,'cloud_tested':False,'started_uid':os.getuid()}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def criu(args):
        p=subprocess.run(['sudo','-n',str(binary),*args],capture_output=True,text=True,timeout=50)
        return {'exit_code':p.returncode,'stdout':p.stdout[-2000:],'stderr':p.stderr[-3000:]}
    output=(root/'application.log').open('wb');app=subprocess.Popen([sys.executable,'-u','-c',APPLICATION,str(root)],stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
    restored_pid=None
    try:
        for _ in range(100):
            if (root/'ready.json').exists():break
            if app.poll() is not None:raise RuntimeError('fixture exited before ready')
            time.sleep(.05)
        report['before']=json.loads((root/'ready.json').read_text());assert report['before']['pid']==app.pid and report['before']['uid']==os.getuid()
        prefix=(root/'application.log').read_bytes();report['log_prefix_sha256']=hashlib.sha256(prefix).hexdigest()
        result=criu(['dump','--tree',str(app.pid),'--images-dir',str(images),'--work-dir',str(images),'--log-file','dump.log','--shell-job','-v4'])
        report['dump']=result;save()
        if result['exit_code']:raise RuntimeError('CRIU dump failed; inspect private fixture dump.log')
        app.wait(timeout=10);report['real_process_memory_dumped']=True;report['original_process_terminal_returncode']=app.returncode;save()
        result=criu(['restore','--images-dir',str(images),'--work-dir',str(images),'--log-file','restore.log','--shell-job','--restore-detached','--pidfile',str(root/'restored.pid'),'-v4'])
        report['restore']=result;save()
        if result['exit_code']:raise RuntimeError('CRIU restore failed; inspect private fixture restore.log')
        restored_pid=int(subprocess.check_output(['sudo','-n','/bin/cat',str(root/'restored.pid')],text=True));assert restored_pid==report['before']['pid']
        (root/'resume-now').touch(exist_ok=False)
        for _ in range(100):
            if (root/'restored.json').exists():break
            time.sleep(.05)
        after=json.loads((root/'restored.json').read_text());assert after==report['before'],after
        log=(root/'application.log').read_bytes();assert log.startswith(prefix) and log.count(b'READY ')==1 and log.count(b'RESTORED ')==1
        report.update({'complete':True,'after':after,'same_pid':True,'random_memory_identity_preserved':True,'unread_anonymous_pipe_preserved':True,'existing_stdout_file_offset_preserved':True,'application_started_once':True,'no_business_process_touched':True,'restore_was_same_host':True,'dc_live_external_pipes_tested':False})
        save();print('CRIU_MEMORY_PIPE_PASS '+json.dumps({'pid':restored_pid,'uid':after['uid'],'same_memory_and_pipe':True,'fixture_root':str(root)}),flush=True)
    finally:
        if app.poll() is None:app.terminate();app.wait(timeout=10)
        # A successfully restored fixture terminates itself after the resume flag.
        # On failure, do not blindly signal a reused numerical PID.
        output.close();save()


if __name__=='__main__':main()
