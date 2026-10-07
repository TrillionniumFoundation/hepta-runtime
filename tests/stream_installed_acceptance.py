#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Installed endpoint stream ownership acceptance.

Uses only disposable ordinary-user application/child processes. The installed MCP
service is restarted through the user's own systemd manager; Desktop Commander,
business processes and host privilege policy are not changed.
"""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import termios
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from runtime_http_acceptance import Client
spec=importlib.util.spec_from_file_location('stream_export',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)

WORKER=r"""import hashlib,json,os,sys
memory=os.urandom(32);total=0
print(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
for line in sys.stdin:
    if line.strip()=='EXIT':break
    total+=int(line);print(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
"""

APP=r"""import hashlib,json,os,subprocess,sys,threading,time
memory=os.urandom(32);total=0
worker=subprocess.Popen([sys.executable,'-u','-c',%r],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
child=json.loads(worker.stdout.readline())
print(json.dumps({'event':'READY','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total,'worker':child}),flush=True)
def offline():
    time.sleep(2.0);print(json.dumps({'event':'SERVICE_RESTART_MARK','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest()}),flush=True)
threading.Thread(target=offline,daemon=True).start()
for line in sys.stdin:
    amount=int(line);total+=amount;worker.stdin.write(str(amount).encode()+b'\n');child=json.loads(worker.stdout.readline())
    print(json.dumps({'event':'VALUE','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total,'worker':child}),flush=True)
worker.stdin.write(b'EXIT\n');worker.stdin.close();worker.stdout.close();worker.wait(timeout=5)
""" % WORKER

def descendants(pid):
    out=[];queue=[pid]
    while queue:
        parent=queue.pop(0)
        try: children=list(map(int,(pathlib.Path('/proc')/str(parent)/'task'/str(parent)/'children').read_text().split()))
        except FileNotFoundError: children=[]
        for child in children:
            if child not in out: out.append(child);queue.append(child)
    return out

def sha(path):
    with pathlib.Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--binary',required=True)
    ap.add_argument('--url',default='http://127.0.0.1:8790/mcp')
    ap.add_argument('--token-file',required=True)
    ap.add_argument('--out',required=True)
    ap.add_argument('--service',default='hepta-runtime-operator.service')
    a=ap.parse_args()
    os.environ.setdefault('XDG_RUNTIME_DIR',f'/run/user/{os.getuid()}')
    os.environ.setdefault('DBUS_SESSION_BUS_ADDRESS',f'unix:path=/run/user/{os.getuid()}/bus')
    binary=pathlib.Path(a.binary).resolve(strict=True);expected_sha=sha(binary)
    token=pathlib.Path(a.token_file).read_text().strip()
    report={'complete':False,'binary_sha256':expected_sha,'checks':[],'service_restart_performed':False,
            'desktop_commander_modified':False,'privileged_operation':False,'cloud_binding_used':False}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(label,detail=None):report['checks'].append({'check':label,'detail':detail});save();print('PASS',label,flush=True)
    def system_pid(unit):
        return int(subprocess.check_output(['systemctl','--user','show',unit,'-p','MainPID','--value'],text=True))
    def connect():
        for _ in range(100):
            try:return Client(a.url,token)
            except Exception:time.sleep(.08)
        raise RuntimeError('installed endpoint did not return')
    runtime_before=system_pid(a.service);dc_before=system_pid('desktop-commander-remote.service')
    if sha('/proc/'+str(runtime_before)+'/exe')!=expected_sha:raise RuntimeError('running installed artifact differs')
    app=None
    try:
        c=connect();tools={v['name'] for v in c.rpc('tools/list',{})['tools']}
        required={'stream_handoff_prepare','stream_handoff_status','stream_handoff_read','stream_handoff_write','stream_handoff_close','stream_handoff_list'}
        if not required<=tools:raise AssertionError(required-tools)
        passed('installed endpoint exposes all six stream ownership tools',len(tools))
        app=subprocess.Popen([sys.executable,'-u','-c',APP],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
        deadline=time.monotonic()+3;children=[]
        while time.monotonic()<deadline:
            children=descendants(app.pid)
            if len(children)==1:break
            time.sleep(.02)
        assert len(children)==1,children
        app.stdin.write(b'17\n');app.stdin.flush()
        pending=bytearray(4)
        for _ in range(100):
            fcntl.ioctl(app.stdout.fileno(),termios.FIONREAD,pending,True)
            if int.from_bytes(pending,sys.byteorder)>0:break
            time.sleep(.02)
        queued=int.from_bytes(pending,sys.byteorder);assert queued>0
        key='installed-stream-'+os.urandom(12).hex()
        prepared=c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':[app.pid,*children]})
        sid=prepared['session_id'];assert prepared['status']['state']=='waiting_for_owner'
        ack=EXPORT.transfer(prepared['handoff_socket'],sid,
            {'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno(),'stderr_reader':app.stderr.fileno()},
            [app.pid,*children],acknowledge_quiesced_io=True)
        assert ack['accepted'];app.stdin.close();app.stdout.close();app.stderr.close()
        passed('old ordinary-user owner transferred the exact live pipes to installed broker',{'queued_before':queued,'application_pids':[app.pid,*children]})
        cursor=0
        def read_until(needle,timeout=8):
            nonlocal cursor
            text='';deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                page=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':cursor,'limit':4096})
                block=base64.b64decode(page['data_base64']);cursor=page['next_offset'];text+=block.decode()
                if needle in text:return text,page
                time.sleep(.05)
            raise AssertionError('missing '+needle)
        text,_=read_until('"total": 17')
        events=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
        ready=next(v for v in events if v['event']=='READY');seventeen=next(v for v in events if v['event']=='VALUE')
        assert seventeen['total']==17 and seventeen['hash']==ready['hash'] and seventeen['worker']['hash']==ready['worker']['hash']
        passed('pre-handoff queued output archived without replay and memory identities retained')
        subprocess.run(['systemctl','--user','restart',a.service],check=True,timeout=30)
        report['service_restart_performed']=True
        c=connect();runtime_after=system_pid(a.service)
        assert runtime_after!=runtime_before and sha('/proc/'+str(runtime_after)+'/exe')==expected_sha
        assert system_pid('desktop-commander-remote.service')==dc_before
        listing=c.call('stream_handoff_list',{'limit':20});assert any(v['session_id']==sid for v in listing['sessions'])
        status=c.call('stream_handoff_status',{'session_id':sid});assert status['owner_accepted'] and status['all_applications_alive']
        offline,_=read_until('SERVICE_RESTART_MARK',timeout=8);assert 'SERVICE_RESTART_MARK' in offline
        passed('broker, app identity and queued output survive actual installed service restart',{'runtime_before':runtime_before,'runtime_after':runtime_after})
        write={'session_id':sid,'request_id':'installed-write-0001','data_base64':base64.b64encode(b'5\n').decode()}
        first=c.call('stream_handoff_write',write);second=c.call('stream_handoff_write',write)
        assert first['state']=='confirmed' and not first['reused'] and second['reused']
        c.call('stream_handoff_write',{**write,'data_base64':base64.b64encode(b'6\n').decode()},denied=True)
        value,_=read_until('"total": 22')
        event=next(v for v in map(json.loads,[line for line in value.splitlines() if line.startswith('{')]) if v.get('event')=='VALUE')
        assert event['total']==22 and event['hash']==ready['hash'] and event['worker']['hash']==ready['worker']['hash']
        passed('installed native input receipt prevents duplicate effect and preserves app/child memory')
        c.call('stream_handoff_close',{'session_id':sid});app.wait(timeout=8)
        for _ in range(100):
            status=c.call('stream_handoff_status',{'session_id':sid})
            if status['state']=='exited':break
            time.sleep(.05)
        assert status['state']=='exited' and status['output_complete']
        final=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
        assert final['eof'] and final['output_complete']
        state_dir=json.loads((pathlib.Path.home()/'.config/hepta-runtime-operator/runtime.json').read_text())['state_dir']
        receipts=(pathlib.Path(state_dir)/'stream_handoffs'/sid/'input_receipts.jsonl').read_text()
        assert base64.b64encode(b'5\n').decode() not in receipts and '5\\n' not in receipts
        passed('input EOF completes archive and receipts contain no raw input')
        report.update(complete=True,passed=len(report['checks']),session_id=sid,application_pid=ready['pid'],child_pid=ready['worker']['pid'],
                      runtime_pid_before=runtime_before,runtime_pid_after=runtime_after,desktop_commander_pid=dc_before,
                      native_receiver_persistent_across_installed_restart=True,application_checkpoint_code=False,application_processes_stopped_for_handoff=False)
        save();print('STREAM_INSTALLED_PASS',report['passed'],flush=True)
    finally:
        if app is not None and app.poll() is None:
            os.killpg(app.pid,signal.SIGTERM);app.wait(timeout=5)
        save()

if __name__=='__main__':main()
