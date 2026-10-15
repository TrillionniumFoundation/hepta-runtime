#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real owned Linux unit reuse against source-pinned helpers, not installed/model-origin evidence."""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'src/mcp/runtime/jobs.rs').read_text()
CODES={name:re.search(r'const '+name+r': &str = r#"(.*?)"#;',SOURCE,re.S).group(1)
       for name in ('START_CODE','STATUS_CODE','CANCEL_CODE','READ_CODE')}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def identity(pid):
    ticks=pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19]
    return {'kind':'proc_start_ticks','value':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+ticks}
def helper(name,q,log):
    p=subprocess.run([sys.executable,'-c',CODES[name]],input=json.dumps(q),capture_output=True,text=True,timeout=45)
    log.write(json.dumps({'helper':name,'request':q,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})+'\n');log.flush();os.fsync(log.fileno())
    return p, json.loads(p.stdout) if p.returncode==0 else None
def wait_file(path,timeout=15):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if path.exists():return json.loads(path.read_text())
        time.sleep(.05)
    raise TimeoutError('owned fixture marker did not appear')
def owner_alive(pid,expected):
    try:return identity(pid)==expected
    except (ProcessLookupError,FileNotFoundError):return False
def unit_props(unit):
    p=subprocess.run(['systemctl','--user','show',unit,'--no-pager','--property=LoadState,InvocationID,Description,ExecMainPID'],
        capture_output=True,text=True,timeout=5)
    return dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
CHILD="""import fcntl,json,os,pathlib,signal,time
base=pathlib.Path(__import__('sys').argv[1]);base.mkdir(exist_ok=True)
with (base/'launch-count.lock').open('a') as lock:
 fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
 p=base/'launch-counter.json'
 launches=json.loads(p.read_text())['launches'] if p.exists() else 0
 p.write_text(json.dumps({'launches':launches+1}))
count=0
def term(*args):
 global count
 count+=1
 (base/'counter.json').write_text(json.dumps({'count':count,'pid':os.getpid()}))
signal.signal(signal.SIGTERM,term)
(base/'counter.json').write_text(json.dumps({'count':count,'pid':os.getpid()}))
(base/'ready.json').write_text(json.dumps({'pid':os.getpid(),'uid':os.geteuid()}))
print('OWNED_READY',flush=True)
deadline=time.monotonic()+120
while not (base/'release').exists() and time.monotonic()<deadline:time.sleep(.05)
print('OWNED_RELEASED',flush=True)
"""
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--receipt-dir',required=True);args=ap.parse_args()
    if sys.platform!='linux':raise RuntimeError('real unit-reuse fixture requires Linux')
    destination=pathlib.Path(args.receipt_dir).resolve();destination.mkdir(parents=True,exist_ok=False,mode=0o700)
    fixture=pathlib.Path(tempfile.mkdtemp(prefix='hepta-owned-unit-reuse-')).resolve()
    unit='hepta-job-owner-'+uuid.uuid4().hex;job=fixture/'original-job';original=fixture/'original';replacement=fixture/'replacement'
    original.mkdir(mode=0o700);replacement.mkdir(mode=0o700)
    q={'job_id':'owned-original-'+uuid.uuid4().hex,'job_dir':str(job),'unit':unit,
       'request_fingerprint':uuid.uuid4().hex,'platform':'linux','execution_mode':'operator',
       'executable':sys.executable,'args':['-u','-c',CHILD,str(original)],'cwd':str(fixture),
       'env':{},'stdin':None,'timeout_seconds':60,'nice':0,'cpu_quota_percent':None,
       'memory_max_bytes':None,'allow_job_network':True,'allow_detached_fallback':False}
    ref={key:q[key] for key in ('job_id','job_dir','unit')}
    report={'schema':'hepta-operator-unit-reuse-helper-v1','origin':'local_source_pinned_helpers_real_owned_systemd_units',
       'chatgpt_originated':False,'native_mcp_envelope_tested':False,'installed_service_changed':False,
       'DC_changed':False,'full_dc_replacement_qualified':False,
       'recorded_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'source_head':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
       'jobs_source_sha256':sha(ROOT/'src/mcp/runtime/jobs.rs'),'script_sha256':sha(pathlib.Path(__file__)),
       'checks':[],'cleanup':{},'complete':False}
    replacement_pid=None;replacement_identity=None;failure=None
    cancel_ref=None;cancel_workload=None;restart_ref=None;restart_workload=None
    with (destination/'helper-dispatch.jsonl').open('x',encoding='utf-8') as log:
        try:
            p,launch=helper('START_CODE',q,log);assert p.returncode==0 and launch['backend']=='systemd'
            ready=wait_file(original/'ready.json');started=wait_file(job/'started.json')
            assert started['job_id']==q['job_id'] and started['supervisor_uid']==os.geteuid()
            assert started['launch_nonce'] and started['invocation_id'] and started['supervisor_identity']
            report['original_start']=started;report['original_ready']=ready;report['original_unit']=unit_props(unit)
            assert report['original_unit']['InvocationID']==started['invocation_id']
            report['checks'].append('real runner freezes launch nonce, UID, start identity and systemd invocation')
            frozen_bytes=(job/'started.json').read_bytes()
            owner_intent_bytes=(job/'owner-intent.json').read_bytes()
            def replay(label):
                p=subprocess.run([sys.executable,str(job/'runner.py')],capture_output=True,text=True,timeout=5)
                log.write(json.dumps({'fixture_phase':label,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})+'\n');log.flush()
                assert p.returncode!=0
                assert (job/'started.json').read_bytes()==frozen_bytes
                assert (job/'owner-intent.json').read_bytes()==owner_intent_bytes
                assert json.loads((original/'launch-counter.json').read_text())['launches']==1
            replay('direct_runner_replay_while_live')
            original_request=(job/'request.json').read_bytes()
            for corrupted in (b'PARTIAL_JSON',b'null'):
                try:
                    (job/'request.json').write_bytes(corrupted)
                    p,value=helper('START_CODE',q,log);assert p.returncode!=0 and value is None
                    assert (job/'request.json').read_bytes()==corrupted
                    assert (job/'started.json').read_bytes()==frozen_bytes
                    assert json.loads((original/'launch-counter.json').read_text())['launches']==1
                finally:(job/'request.json').write_bytes(original_request)
            (job/'request.json').rename(job/'preserved-request.json')
            try:
                p,value=helper('START_CODE',q,log)
                assert p.returncode!=0 and value is None and not (job/'request.json').exists()
                assert (job/'started.json').read_bytes()==frozen_bytes
            finally:(job/'preserved-request.json').rename(job/'request.json')
            report['checks'].append('live runner replay and corrupt/null/missing request cannot rebind or launch a second child')
            (original/'release').write_text('owned release')
            exit_data=wait_file(job/'exit.json',20);assert exit_data['exit_code']==0
            shutil.copyfile(job/'exit.json',destination/'original-exit.json')
            replay('direct_runner_replay_after_original_exit')
            (job/'owner-intent.json').write_bytes(b'PARTIAL_OWNER_INTENT')
            try:
                p=subprocess.run([sys.executable,str(job/'runner.py')],capture_output=True,text=True,timeout=5)
                assert p.returncode!=0 and (job/'owner-intent.json').read_bytes()==b'PARTIAL_OWNER_INTENT'
                assert (job/'started.json').read_bytes()==frozen_bytes
                assert json.loads((original/'launch-counter.json').read_text())['launches']==1
            finally:(job/'owner-intent.json').write_bytes(owner_intent_bytes)
            report['checks'].append('completed or uncertain supervisor intent is never automatically replayed')
            deadline=time.monotonic()+10
            while unit_props(unit).get('LoadState')!='not-found' and time.monotonic()<deadline:time.sleep(.05)
            assert unit_props(unit).get('LoadState')=='not-found'
            (job/'exit.json').rename(job/'preserved-original-exit.json')
            subprocess.run(['systemd-run','--user','--quiet','--collect','--unit',unit,
                '--property=Description=Owned replacement fixture','--',sys.executable,'-u','-c',CHILD,str(replacement)],
                capture_output=True,text=True,timeout=10,check=True)
            replacement_ready=wait_file(replacement/'ready.json');replacement_pid=replacement_ready['pid']
            replacement_identity=identity(replacement_pid);props=unit_props(unit)
            assert props['InvocationID'] and props['InvocationID']!=started['invocation_id']
            assert int(props['ExecMainPID'])==replacement_pid
            report['replacement_start']={'pid':replacement_pid,'identity':replacement_identity,'unit_properties':props}
            for phase in ('old_owner_gone','missing_frozen_binding'):
                original_started=(job/'started.json').read_text()
                try:
                    if phase=='missing_frozen_binding':
                        changed=json.loads(original_started);changed.pop('launch_nonce')
                        (job/'started.json').write_text(json.dumps(changed))
                    p,result=helper('CANCEL_CODE',{**ref,'grace_seconds':0},log)
                    assert p.returncode!=0 and result is None
                    p,status=helper('STATUS_CODE',{**ref,'wait_seconds':0},log)
                    assert p.returncode==0 and status['state']=='owner_unknown' and status['status_authoritative'] is False
                    assert owner_alive(replacement_pid,replacement_identity)
                    assert json.loads((replacement/'counter.json').read_text())['count']==0
                    assert unit_props(unit)['InvocationID']==props['InvocationID']
                    report['checks'].append(phase+' refuses cancellation/new-unit status without touching replacement')
                finally:(job/'started.json').write_text(original_started)
            p,output=helper('READ_CODE',{**ref,'stdout_offset':0,'stderr_offset':0,'limit':16384},log)
            assert p.returncode==0 and bytes.fromhex(output['stdout']['bytes_hex'])==b'OWNED_READY\nOWNED_RELEASED\n'
            (job/'preserved-original-exit.json').rename(job/'exit.json')
            p,status=helper('STATUS_CODE',{**ref,'wait_seconds':0},log)
            assert status['state']=='succeeded' and status['exit_code']==0 and status['output_complete'] is True
            report['checks'].append('original output cursors and final result remain available after same-name reuse')
            cancel_workload=fixture/'live-cancel';cancel_workload.mkdir(mode=0o700)
            cancel_q={**q,'job_id':'owned-cancel-'+uuid.uuid4().hex,
                'job_dir':str(fixture/'cancel-job'),'unit':unit+'-cancel',
                'request_fingerprint':uuid.uuid4().hex,'args':['-u','-c',CHILD,str(cancel_workload)]}
            cancel_ref={key:cancel_q[key] for key in ('job_id','job_dir','unit')}
            p,cancel_launch=helper('START_CODE',cancel_q,log)
            assert p.returncode==0 and cancel_launch['backend']=='systemd'
            wait_file(cancel_workload/'ready.json')
            cancel_started=wait_file(pathlib.Path(cancel_q['job_dir'])/'started.json')
            # Each helper below is a new process. It must use only the original
            # persisted binding, without obtaining a replacement owner's grant.
            p,cancel_ack=helper('CANCEL_CODE',{**cancel_ref,'grace_seconds':10},log)
            assert p.returncode==0 and cancel_ack['result']=='stop_requested'
            assert cancel_ack['atomic_identity'] is True and cancel_ack['supervisor_pid']==cancel_started['supervisor_pid']
            final=wait_file(pathlib.Path(cancel_q['job_dir'])/'exit.json',15)
            assert final['cancelled'] is True and final['timed_out'] is False and final['output_complete'] is True
            report['live_cancel']={'launch':cancel_launch,'start':cancel_started,'ack':cancel_ack,'final':final}
            report['checks'].append('fresh helper process cancels the original frozen supervisor; runner escalates owned workload and captures complete output')
            restart_workload=fixture/'restart';restart_workload.mkdir(mode=0o700)
            restart_q={**q,'job_id':'owned-restart-'+uuid.uuid4().hex,
                'job_dir':str(fixture/'restart-job'),'unit':unit+'-restart',
                'request_fingerprint':uuid.uuid4().hex,'args':['-u','-c',CHILD,str(restart_workload)]}
            restart_ref={key:restart_q[key] for key in ('job_id','job_dir','unit')}
            p,restart_launch=helper('START_CODE',restart_q,log);assert p.returncode==0
            wait_file(restart_workload/'ready.json')
            restart_job=pathlib.Path(restart_q['job_dir'])
            restart_binding=wait_file(restart_job/'started.json')
            restart_bytes=(restart_job/'started.json').read_bytes()
            before_props=unit_props(restart_ref['unit']);assert before_props['InvocationID']==restart_binding['invocation_id']
            p=subprocess.run(['systemctl','--user','restart',restart_ref['unit']],capture_output=True,text=True,timeout=25)
            log.write(json.dumps({'fixture_phase':'real_owned_systemd_restart','unit':restart_ref['unit'],'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})+'\n');log.flush()
            wait_file(restart_job/'exit.json',15)
            assert (restart_job/'started.json').read_bytes()==restart_bytes
            assert json.loads((restart_workload/'launch-counter.json').read_text())['launches']==1
            report['restart_fixture']={'original_binding':restart_binding,'restart_command_exit_code':p.returncode,
                'binding_bytes_unchanged':True,'workload_launch_counter':1,'after_unit':unit_props(restart_ref['unit'])}
            report['checks'].append('actual systemd restart cannot replace original binding or launch workload twice')
            report['source_stable']=sha(ROOT/'src/mcp/runtime/jobs.rs')==report['jobs_source_sha256']
            assert report['source_stable']
        except Exception as exc:
            failure=exc;report['error_type']=type(exc).__name__;report['error']=str(exc)[:3000]
        finally:
            (original/'release').write_text('owned cleanup release')
            (replacement/'release').write_text('owned cleanup release')
            if cancel_workload is not None:(cancel_workload/'release').write_text('owned cleanup release')
            cancel_terminal=True;restart_terminal=True
            if cancel_ref is not None:
                try:wait_file(pathlib.Path(cancel_ref['job_dir'])/'exit.json',15)
                except TimeoutError:cancel_terminal=False
            if restart_workload is not None:(restart_workload/'release').write_text('owned cleanup release')
            if restart_ref is not None:
                try:wait_file(pathlib.Path(restart_ref['job_dir'])/'exit.json',15)
                except TimeoutError:restart_terminal=False
            deadline=time.monotonic()+15
            while replacement_pid and owner_alive(replacement_pid,replacement_identity) and time.monotonic()<deadline:time.sleep(.1)
            if (job/'preserved-original-exit.json').exists() and not (job/'exit.json').exists():
                (job/'preserved-original-exit.json').rename(job/'exit.json')
            old_terminal=(job/'exit.json').exists()
            new_terminal=not replacement_pid or not owner_alive(replacement_pid,replacement_identity)
            report['cleanup']={'original_terminal_confirmed':old_terminal,'replacement_terminal_confirmed':new_terminal,
                'same_unit_collected':unit_props(unit).get('LoadState')=='not-found',
                'live_cancel_terminal_confirmed':cancel_terminal,
                'restart_terminal_confirmed':restart_terminal}
            if old_terminal and new_terminal and cancel_terminal and restart_terminal and report['cleanup']['same_unit_collected']:
                shutil.rmtree(fixture);report['cleanup']['fixture_removed']=True
            else:report['cleanup']['fixture_removed']=False;report['cleanup']['retained_owned_fixture']=str(fixture)
    report['logs']={'helper-dispatch.jsonl':{'sha256':sha(destination/'helper-dispatch.jsonl'),
       'bytes':(destination/'helper-dispatch.jsonl').stat().st_size}}
    report['complete']=failure is None and report['cleanup']['fixture_removed'] and report.get('source_stable') is True
    (destination/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
    print('OWNED_UNIT_REUSE_COMPLETE',report['complete'],len(report['checks']),flush=True)
    if not report['complete']:raise SystemExit(1)
if __name__=='__main__':main()
