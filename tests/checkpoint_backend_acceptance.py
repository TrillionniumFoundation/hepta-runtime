#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real two-phase backend test on a disposable X230 process, independent of MCP.
No application checkpoint code or business process. Never counts as native router
qualification; the authenticated-MCP acceptance is a separate required test.
"""
import argparse
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import sys
import tempfile
import time

APPLICATION='''import os,pathlib,json,hashlib,time,sys
root=pathlib.Path(sys.argv[1]);memory=os.urandom(128);r,w=os.pipe();payload=os.urandom(97);os.write(w,payload);value=8273641
before={'pid':os.getpid(),'uid':os.getuid(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(payload).hexdigest(),'value':value}
(root/'before.json').write_text(json.dumps(before));print('START_ONCE',flush=True)
while not (root/'go').exists():time.sleep(.05)
after={'pid':os.getpid(),'uid':os.getuid(),'memory_sha256':hashlib.sha256(memory).hexdigest(),'pipe_sha256':hashlib.sha256(os.read(r,97)).hexdigest(),'value':value}
(root/'after.json').write_text(json.dumps(after));print('RESTORED_MEMORY',flush=True)
'''


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--helper',required=True);ap.add_argument('--helper-sha256',required=True);ap.add_argument('--criu',required=True);ap.add_argument('--criu-sha256',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    helper=pathlib.Path(a.helper).resolve(strict=True)
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=a.helper_sha256:raise ValueError('fixed helper fingerprint differs')
    root=pathlib.Path(tempfile.mkdtemp(prefix='hepta-checkpoint-backend-',dir=str(pathlib.Path.home())));root.chmod(0o700)
    checkpoint='backend-'+secrets.token_hex(12);report={'complete':False,'native_mcp_tested':False,'application_checkpoint_code':False,'helper_sha256':a.helper_sha256,'fixture_root':str(root),'checkpoint_id':checkpoint}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def call(action,denied=False,**fields):
        q={'action':action,'checkpoint_id':checkpoint,'configured_binary':a.criu,'configured_sha256':a.criu_sha256,**fields}
        p=subprocess.run(['sudo','-n','/usr/bin/python3','-I',str(helper)],input=json.dumps(q),capture_output=True,text=True,timeout=70)
        if denied:
            assert p.returncode!=0,p.stdout;return p.stderr
        if p.returncode:raise RuntimeError(p.stderr[:1500])
        return json.loads(p.stdout)
    output=(root/'stdout.log').open('wb');app=subprocess.Popen([sys.executable,'-u','-c',APPLICATION,str(root)],stdin=subprocess.DEVNULL,stdout=output,stderr=output,start_new_session=True)
    restored=None
    try:
        for _ in range(80):
            if (root/'before.json').exists():break
            if app.poll() is not None:raise ValueError('fixture exited')
            time.sleep(.05)
        before=json.loads((root/'before.json').read_text());report['before']=before
        inspected=call('inspect',pid=app.pid);assert inspected['ready'],inspected
        report['inspect']=inspected;save()
        request={'pid':app.pid,'expected_identity':inspected['identity'],'acknowledge_process_stop':True}
        call('dump',denied=True,**{**request,'expected_identity':{**inspected['identity'],'start_ticks':0}})
        assert app.poll() is None
        report['dump']=call('dump',**request);save();assert report['dump']['state']=='dumped'
        app.wait(timeout=10)
        restored=call('restore',acknowledge_process_stop=True);report['restore']=restored;save()
        assert restored['state']=='restored_stopped' and restored['restored_kernel_state']=='T' and restored['restored_identity']['pid']==app.pid
        (root/'go').touch();time.sleep(.2);assert not (root/'after.json').exists()
        request={'expected_identity':restored['restored_identity'],'acknowledge_resume':True}
        call('resume',denied=True,**{**request,'expected_identity':{**request['expected_identity'],'start_ticks':0}})
        assert call('status')['restored_kernel_state']=='T'
        report['resume']=call('resume',**request);assert report['resume']['state']=='resumed'
        assert call('resume',**request)['reused']
        for _ in range(80):
            if (root/'after.json').exists():break
            time.sleep(.05)
        after=json.loads((root/'after.json').read_text());assert after==before,(before,after)
        assert (root/'stdout.log').read_text()=='START_ONCE\nRESTORED_MEMORY\n'
        report.update(complete=True,after=after,explicit_resume_passed=True,same_memory_and_unread_pipe=True,startup_not_repeated=True,only_disposable_fixture_touched=True);save();print('CHECKPOINT_BACKEND_TWO_PHASE_PASS',flush=True)
    finally:
        if app.poll() is None:app.terminate();app.wait(timeout=10)
        if restored:
            try:
                (root/'go').touch();s=call('status')
                if s['state']=='restored_stopped':call('resume',expected_identity=s['restored_identity'],acknowledge_resume=True)
            except Exception as e:report['cleanup_error']=str(e)[:300]
        output.close();save()


if __name__=='__main__':main()
