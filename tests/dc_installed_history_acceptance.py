#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adopt an already-running DC-launched handoff owner into the installed broker.

This program does not start or signal the old owner/application. The caller starts
deploy/dc_handoff_owner.py through Desktop Commander and sends pre-handoff input.
This acceptance then verifies finalized owner history, asks that owner to hand off,
restarts only the hepta-runtime user service, and continues the same child process.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
OWNER=ROOT/'deploy/dc_handoff_owner.py'
sys.path.insert(0,str(ROOT/'tests'))
from runtime_http_acceptance import Client


def sha(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def owner_call(state,op,**values):
    command=[sys.executable,str(OWNER),op,'--socket',str(state/'control.sock')]
    if op=='handoff':
        command += ['--handoff-socket',values['handoff_socket'],'--session-id',values['session_id'],
                    '--application-pids',json.dumps(values['application_pids'])]
    raw=subprocess.check_output(command,text=True,timeout=20)
    return json.loads(raw)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--state-dir',required=True)
    ap.add_argument('--binary',required=True)
    ap.add_argument('--token-file',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--service',default='hepta-runtime-operator.service')
    ap.add_argument('--no-runtime-restart',action='store_true',help='qualify owner integration without changing the installed service')
    args=ap.parse_args()
    os.environ.setdefault('XDG_RUNTIME_DIR',f'/run/user/{os.getuid()}')
    os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS',f'unix:path=/run/user/{os.getuid()}/bus')
    state=pathlib.Path(args.state_dir).resolve(strict=True)
    binary=pathlib.Path(args.binary).resolve(strict=True);expected_sha=sha(binary)
    token=pathlib.Path(args.token_file).read_text().strip()
    report={'complete':False,'checks':[],'binary_sha256':expected_sha,'actual_DC_launched_owner_required':True,
            'application_checkpoint_code':False,'privileged_operation':False,'cloud_binding_used':False}
    def save():pathlib.Path(args.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(label,detail=None):report['checks'].append({'check':label,'detail':detail});save();print('PASS',label,flush=True)
    def connect():
        for _ in range(100):
            try:return Client('http://127.0.0.1:8790/mcp',token)
            except Exception:time.sleep(.08)
        raise RuntimeError('installed endpoint unavailable')
    def service_pid(unit):
        return int(subprocess.check_output(['systemctl','--user','show',unit,'-p','MainPID','--value'],text=True))
    before=owner_call(state,'status')
    if before['state']!='running' or before['stdin_pending_bytes']!=0:raise RuntimeError('old owner not at a quiescent input boundary')
    stdout_history=(state/'stdout.history').read_bytes();stderr_history=(state/'stderr.history').read_bytes()
    events=[json.loads(line) for line in stdout_history.splitlines() if line.startswith(b'{')]
    ready=next(v for v in events if v.get('event')=='READY')
    prior=events[-1]
    if prior.get('event')!='VALUE' or prior.get('total')!=17:raise RuntimeError('expected DC-side state 17 before handoff')
    assert ready['pid']==before['child_identity']['pid']==prior['pid'] and ready['hash']==prior['hash']
    passed('actual DC owner has durable raw pre-handoff history and zero unread raw stdin',
           {'owner_pid':before['owner_pid'],'application_pids':before['application_pids'],'stdout_history_bytes':len(stdout_history)})
    runtime_before=service_pid(args.service);dc_before=service_pid('desktop-commander-remote.service')
    if sha('/proc/'+str(runtime_before)+'/exe')!=expected_sha:raise RuntimeError('running installed release differs')
    c=connect();key='dc-real-history-'+hashlib.sha256((str(state)+str(before['owner_pid'])).encode()).hexdigest()[:32]
    prepared=c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':before['application_pids']})
    sid=prepared['session_id']
    receipt=owner_call(state,'handoff',handoff_socket=prepared['handoff_socket'],session_id=sid,application_pids=before['application_pids'])
    assert receipt['accepted'] and receipt['userspace_read_ahead_bytes_unaccounted']==0
    passed('DC owner exported live pipes plus finalized histories and exited its ownership path',
           {'session_id':sid,'history_receipt':receipt['receipt_sha256']})
    deadline=time.monotonic()+8;page=None
    while time.monotonic()<deadline:
        page=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
        data=base64.b64decode(page['data_base64'])
        if len(data)>=len(stdout_history):break
        time.sleep(.05)
    assert data[:len(stdout_history)]==stdout_history
    broker_state=json.loads((pathlib.Path.home()/'.config/hepta-runtime-operator/runtime.json').read_text())['state_dir']
    handoff=json.loads((pathlib.Path(broker_state)/'stream_handoffs'/sid/'handoff_receipt.json').read_text())
    assert handoff['history_seed']['stdout']['sha256']==hashlib.sha256(stdout_history).hexdigest()
    assert handoff['history_seed']['stderr']['sha256']==hashlib.sha256(stderr_history).hexdigest()
    passed('native durable archive starts with the exact bytes already consumed and forwarded by DC owner')
    if not args.no_runtime_restart:
        subprocess.run(['systemctl','--user','restart',args.service],check=True,timeout=30)
    c=connect();runtime_after=service_pid(args.service)
    assert (runtime_after==runtime_before if args.no_runtime_restart else runtime_after!=runtime_before)
    assert sha('/proc/'+str(runtime_after)+'/exe')==expected_sha
    assert service_pid('desktop-commander-remote.service')==dc_before
    status=c.call('stream_handoff_status',{'session_id':sid})
    assert status['owner_accepted'] and status['all_applications_alive']
    passed('same app/history/broker ownership is accessible from a fresh native client' if args.no_runtime_restart else
           'same app/history/broker ownership survives installed MCP service restart',
           {'runtime_before':runtime_before,'runtime_after':runtime_after,'DC_pid':dc_before,
            'runtime_service_restarted':not args.no_runtime_restart})
    request={'session_id':sid,'request_id':'dc-real-history-write-01','data_base64':base64.b64encode(b'5\n').decode()}
    first=c.call('stream_handoff_write',request);second=c.call('stream_handoff_write',request)
    assert first['state']=='confirmed' and second['reused']
    deadline=time.monotonic()+8;full=b''
    while time.monotonic()<deadline:
        page=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
        full=base64.b64decode(page['data_base64'])
        if b'"total": 22' in full:break
        time.sleep(.05)
    assert full.startswith(stdout_history)
    output=[json.loads(line) for line in full.splitlines() if line.startswith(b'{')]
    after=output[-1]
    assert after['total']==22 and after['pid']==ready['pid'] and after['hash']==ready['hash']
    passed('native once-only input continues the exact DC-launched process state',{'pid':after['pid'],'total':22})
    c.call('stream_handoff_close',{'session_id':sid})
    for _ in range(100):
        final=c.call('stream_handoff_status',{'session_id':sid})
        if final['state']=='exited':break
        time.sleep(.05)
    assert final['state']=='exited' and final['output_complete']
    archive=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
    assert archive['eof'] and base64.b64decode(archive['data_base64']).startswith(stdout_history)
    input_receipts=(pathlib.Path(broker_state)/'stream_handoffs'/sid/'input_receipts.jsonl').read_text()
    assert base64.b64encode(b'5\n').decode() not in input_receipts and '5\\n' not in input_receipts
    passed('EOF completes archive and native receipts contain no raw post-handoff input')
    report.update(complete=True,passed=len(report['checks']),session_id=sid,old_owner_pid=before['owner_pid'],
                  application_pid=ready['pid'],application_memory_hash=ready['hash'],
                  stdout_history_sha256=hashlib.sha256(stdout_history).hexdigest(),
                  userspace_read_ahead_bytes_unaccounted=0,runtime_pid_before=runtime_before,
                  runtime_pid_after=runtime_after,desktop_commander_pid=dc_before,application_process_stopped_for_handoff=False)
    report['runtime_service_restarted']=not args.no_runtime_restart
    save();print('DC_INSTALLED_HISTORY_PASS',report['passed'],flush=True)


if __name__=='__main__':main()
