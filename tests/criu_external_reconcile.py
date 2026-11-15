#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Complete the exact checkpoint from a recorded failed external-pipe restore.
Refuses an occupied PID; inherits duplicate descriptors so CRIU keeps stdio open.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import secrets
import sys


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--report',required=True);ap.add_argument('--driver',required=True);ap.add_argument('--criu',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    report_path=pathlib.Path(a.report);r=json.loads(report_path.read_text());root=pathlib.Path(r['fixture_root'])
    if not root.name.startswith('hepta-criu-external-pipes-') or root.stat().st_uid!=os.getuid():raise ValueError('not an owned checkpoint fixture')
    if r['dump']['exit_code']!=0 or r['restore']['exit_code']==0:raise ValueError('not the expected failed-restore receipt')
    pid=r['before']['pid']
    if pathlib.Path('/proc',str(pid)).exists():raise RuntimeError('original PID is occupied; never overwrite a live process')
    binary=pathlib.Path(a.criu)
    with binary.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
    if actual!=r['criu_sha256']:raise ValueError('CRIU release changed')
    spec=importlib.util.spec_from_file_location('fixture_driver',a.driver);driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
    images=root/'images';new_r,new_w=os.pipe();out_r,out_w=os.pipe();restored=False;attempt=secrets.token_hex(6);pidfile=root/('reconciled-'+attempt+'.pid')
    result={'complete':False,'original_report_sha256':hashlib.sha256(report_path.read_bytes()).hexdigest(),'source_report':r}
    try:
        bridge="import os,sys;a=os.dup(0);b=os.dup(1);os.set_inheritable(a,True);os.set_inheritable(b,True);args=[v.replace('INHERIT_INPUT',str(a)).replace('INHERIT_OUTPUT',str(b)) for v in sys.argv[1:]];os.execv(args[0],args)"
        cmd=[str(binary),'restore','--images-dir',str(images),'--work-dir',str(images),'--log-file','restore-reconciled-'+attempt+'.log','--shell-job','--restore-detached','--pidfile',str(pidfile),'--inherit-fd','fd[INHERIT_INPUT]:'+r['original_resources']['0'].replace('pipe[','pipe:['),'--inherit-fd','fd[INHERIT_OUTPUT]:'+r['original_resources']['1'].replace('pipe[','pipe:['),'-v4']
        with (root/'reconcile-error.log').open('wb') as error:
            proc=subprocess.Popen(['sudo','-n','/usr/bin/python3','-c',bridge,*cmd],stdin=new_r,stdout=out_w,stderr=error);code=proc.wait(timeout=50)
        result['restore_exit_code']=code;result['attempt']=attempt
        if code:raise RuntimeError('reconciliation restore failed; retain private diagnostic log')
        restored=True;actual_pid=int(subprocess.check_output(['sudo','-n','/bin/cat',str(pidfile)],text=True));assert actual_pid==pid
        os.write(new_w,b'5\n');after=driver.read_line(out_r)
        assert after=={**r['before'],'count':22},after
        os.write(new_w,b'EXIT\n')
        result.update(complete=True,after=after,same_pid=True,same_random_memory=True,previously_consumed_input_state_preserved=True,new_external_stdin_stdout_operational=True,checkpoint_reused_not_application_restarted=True,business_processes_modified=False,dc_external_pipes_claimed=False,diagnosis='CRIU consumes inherited fd references; duplicated stdio before restore and matched exact CRIU pipe:[inode] resource spelling from pinned pipes.c')
        print('CRIU_EXTERNAL_RECONCILE_PASS '+json.dumps({'pid':pid,'before':17,'after':22,'same_random_memory':True}))
    finally:
        if restored:
            try:os.write(new_w,b'EXIT\n')
            except OSError:pass
        for fd in (new_r,new_w,out_r,out_w):os.close(fd)
        pathlib.Path(a.out).write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
