#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Explicit maintenance-window X230 reboot with actual before/after evidence.
Only run when authorized. Refuse active business processes/containers. Pause the
idle runner briefly, restore it on abort; do not reboot the controller or DC host.
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import secrets
import shlex
import subprocess
import sys
import time
from runtime_http_acceptance import Client

RUNNER='actions.runner.TrillionniumFoundation-Trillionnium-Chain.p4-x230.service'


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);ap.add_argument('--execute-reboot',action='store_true');a=ap.parse_args()
    if not a.execute_reboot:raise SystemExit('physical reboot requires explicit --execute-reboot')
    os.environ.setdefault('XDG_RUNTIME_DIR',f'/run/user/{os.getuid()}')
    os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS',f'unix:path=/run/user/{os.getuid()}/bus')
    report={'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':'x230-ts','performed':False,'complete':False,'checks':[]}
    out=pathlib.Path(a.out)
    def save():out.write_text(json.dumps(report,indent=2)+'\n')
    def passed(name):report['checks'].append(name);save();print('PASS',name,flush=True)
    def ssh(command,timeout=20,check=True):
        p=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=5','x230-ts',command],text=True,capture_output=True,timeout=timeout)
        if check and p.returncode:raise RuntimeError(p.stderr[-1000:] or p.stdout[-1000:])
        return p
    before=ssh("hostname; cat /proc/sys/kernel/random/boot_id; systemctl is-enabled "+RUNNER+"; systemctl is-active wired-fallback-guard.service").stdout.strip().splitlines()
    if before[0]!='qian-ThinkPad-X230':raise RuntimeError('refusing unexpected physical host')
    report['boot_before']=before[1];report['baseline_services']=before[2:]
    if before[2]!='enabled':raise RuntimeError('runner is not configured to return after reboot')
    sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
    conf=pathlib.Path.home()/'.config/hepta-runtime-operator'
    c=Client('http://127.0.0.1:8790/mcp',(conf/'token').read_text().strip())
    report['controller_manifest_sha256']=json.loads((conf/'manifest.json').read_text())['binary_sha256']
    dc_before=subprocess.check_output(['systemctl','--user','show','desktop-commander-remote.service','-p','MainPID','--value'],text=True).strip()
    report['dc_pid_before']=dc_before
    # The only Python daemon exempted from workload refusal is the known,
    # already-enabled network recovery service, identified by cgroup as well.
    guard=r'''
import pathlib,json,subprocess,os,sys
allowed=set(map(int,json.loads(sys.argv[1])))
allowed.add(os.getpid());allowed.add(os.getppid())
blocking=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit() or int(p.name) in allowed:continue
 try:
  name=(p/'comm').read_text().strip();group=(p/'cgroup').read_text()
  if name.startswith(('cargo','rustc','cc1','make','ninja','Runner.Worker','codex','llama','ffmpeg','qemu')):blocking.append({'pid':int(p.name),'name':name})
  elif name.startswith('python') and '/wired-fallback-guard.service' not in group:
   blocking.append({'pid':int(p.name),'name':name})
 except (FileNotFoundError,PermissionError):pass
containers=subprocess.run(['/usr/bin/docker','ps','-q'],text=True,capture_output=True,timeout=8)
if containers.returncode or containers.stdout.strip():blocking.append({'containers':'not proven empty'})
if blocking:print(json.dumps({'blocked':blocking}));raise SystemExit(2)
print(json.dumps({'safe':True}))
'''
    def check_guard(allowed):
        return ssh('sudo -n /usr/bin/python3 -c '+shlex.quote(guard)+' '+shlex.quote(json.dumps(allowed))).stdout
    try:check_guard([])
    except Exception as error:
        report['preflight_refused']=str(error);save();raise
    passed('physical host identity, enabled recovery services and no business workloads/containers')
    paused=False;sid=None;job=None
    try:
        ssh('sudo -n systemctl stop '+RUNNER);paused=True
        check_guard([]);passed('idle Actions listener paused; no job interrupted')
        marker='hepta-physical-'+secrets.token_hex(12)
        code="import os,time,pathlib; p=pathlib.Path.home()/'.local/state/hepta-reboot-canaries'/"+repr(marker)+";p.mkdir(parents=True,exist_ok=False);(p/'once').write_text('1');print('PRE_REBOOT '+str(os.getpid()),flush=True);time.sleep(600)"
        params={'host':'x230','executable':'/usr/bin/python3','args':['-c',code],'timeout_seconds':900,'idempotency_key':marker}
        job=c.call('process_start',params)['job'];report['job_id']=job['id'];report['job_request']=params
        report['remote_job_dir']=job['remote_job_dir']
        for _ in range(30):
            r=c.call('process_read',{'host':'x230','job_id':job['id']})
            if 'PRE_REBOOT' in r['stdout']['text']:break
            time.sleep(.1)
        else:raise RuntimeError('durable pre-reboot output missing')
        report['job_prefix']=r['stdout']['text']
        report['job_before']=c.call('process_status',{'host':'x230','job_id':job['id']})
        sid=c.call('pty_start',{'host':'x230','executable':'/usr/bin/python3','args':['-c',"import os,time;print('PTY_PRE_REBOOT '+str(os.getpid()),flush=True);time.sleep(600)"],'idempotency_key':marker+'-pty'})['session_id']
        report['pty_id']=sid
        for _ in range(30):
            r=c.call('pty_read',{'host':'x230','session_id':sid})
            if 'PTY_PRE_REBOOT' in r['text']:break
            time.sleep(.1)
        else:raise RuntimeError('PTY pre-reboot output missing')
        report['pty_before']=r;report['archive_sha256_before']=r['chunk_sha256']
        allowed=[report['job_before'].get('pid'),r['status'].get('pid'),r['status'].get('owner_pid')]
        # Include only supervisors from this exact fixture job directory.
        identify="import pathlib,json;root="+repr(job['remote_job_dir'])+";print(json.dumps([int(p.name) for p in pathlib.Path('/proc').iterdir() if p.name.isdigit() and (lambda x: root in x)(p.joinpath('cmdline').read_text(errors='ignore'))]))"
        # Use a resilient descriptor read because unrelated tasks may exit.
        identify="import pathlib,json;root="+repr(job['remote_job_dir'])+";a=[]\nfor p in pathlib.Path('/proc').iterdir():\n if p.name.isdigit():\n  try:\n   if root in (p/'cmdline').read_text(errors='ignore'):a.append(int(p.name))\n  except (FileNotFoundError,PermissionError):pass\nprint(json.dumps(a))"
        allowed.extend(json.loads(ssh('sudo -n /usr/bin/python3 -c '+shlex.quote(identify)).stdout))
        import re
        allowed.extend(map(int,re.findall(r'PRE_REBOOT (\d+)',report['job_prefix'])))
        allowed=[p for p in allowed if isinstance(p,int)];report['allowed_fixture_pids']=allowed
        check_guard(allowed);passed('only owned durable-job/PTY fixtures present at final shutdown check')
        ssh('sync; sudo -n systemctl reboot',check=False);report['performed']=True;save()
        passed('real physical reboot requested through systemd')
        new=None;seen_unreachable=False
        for _ in range(90):
            time.sleep(2)
            try:
                p=ssh('cat /proc/sys/kernel/random/boot_id',timeout=8,check=False)
                if p.returncode:seen_unreachable=True;continue
                boot=p.stdout.strip()
                if boot and boot!=report['boot_before']:new=boot;break
            except subprocess.TimeoutExpired:seen_unreachable=True
        if new is None:raise RuntimeError('physical target did not return with a changed boot identity')
        report['boot_after']=new;report['observed_unreachable']=seen_unreachable;passed('SSH returned with a different kernel boot ID')
        state=c.call('process_status',{'host':'x230','job_id':job['id']});report['job_after']=state
        pty=c.call('pty_read',{'host':'x230','session_id':sid});report['pty_after']=pty
        assert pty['status']['state']=='lost' and pty['status']['reason']=='target_reboot',pty
        assert pty['text']==report['pty_before']['text'] and pty['chunk_sha256']==report['archive_sha256_before']
        assert state['state'] not in ('running','succeeded'),state
        same=c.call('process_start',params)['job'];assert same['id']==job['id']
        check="import pathlib,json;p=pathlib.Path.home()/'.local/state/hepta-reboot-canaries'/"+repr(marker)+";print(json.dumps({'once':(p/'once').read_text()}))"
        assert json.loads(ssh('/usr/bin/python3 -c '+shlex.quote(check)).stdout)['once']=='1'
        passed('prior job/session report interruption, archives persist and original command is not duplicated')
        fresh=c.call('process_start',{'host':'x230','executable':'/usr/bin/id','args':['-u'],'timeout_seconds':15})['job']['id']
        fresh_state=c.call('process_wait',{'host':'x230','job_id':fresh,'timeout_seconds':20})
        assert fresh_state['state']=='succeeded',fresh_state
        passed('new post-boot native MCP execution succeeds with original SSH identity')
        services=ssh('systemctl is-active '+RUNNER+'; systemctl is-active wired-fallback-guard.service').stdout.strip().splitlines()
        assert services==['active','active'],services;paused=False;report['postboot_services']=services
        dc_after=subprocess.check_output(['systemctl','--user','show','desktop-commander-remote.service','-p','MainPID','--value'],text=True).strip()
        assert dc_before==dc_after;report['dc_pid_after']=dc_after
        passed('runner and network recovery service restart automatically; controller DC PID unchanged')
        report['complete']=True;report['completed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();save();print('PHYSICAL_REBOOT_PASSED',new,flush=True)
    finally:
        if paused:
            try:ssh('sudo -n systemctl start '+RUNNER)
            except Exception as error:report['runner_restore_error']=str(error)
        if not report['performed']:
            if sid:
                try:c.call('pty_close',{'host':'x230','session_id':sid})
                except Exception:pass
            if job:
                try:c.call('process_cancel',{'host':'x230','job_id':job['id']})
                except Exception:pass
        save()


if __name__=='__main__':main()
