#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native MCP cooperative stream receiver; real app/child survive controller SIGKILL."""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import termios
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
from runtime_http_acceptance import Client
spec=importlib.util.spec_from_file_location('stream_export',ROOT/'deploy/stream_handoff.py')
EXPORT=importlib.util.module_from_spec(spec);spec.loader.exec_module(EXPORT)

WORKER=r'''
import hashlib,json,os,sys
memory=os.urandom(32);total=0
print(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
for line in sys.stdin:
    if line.strip()=='EXIT':break
    total+=int(line);print(json.dumps({'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
'''

APP=r'''
import hashlib,json,os,subprocess,sys,threading,time
memory=os.urandom(32);total=0
worker=subprocess.Popen([sys.executable,'-u','-c',%r],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
child=json.loads(worker.stdout.readline())
print(json.dumps({'event':'READY','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total,'worker':child}),flush=True)
def offline():
    time.sleep(2.0);print(json.dumps({'event':'OFFLINE_MARK','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest()}),flush=True)
threading.Thread(target=offline,daemon=True).start()
for line in sys.stdin:
    amount=int(line);total+=amount;worker.stdin.write(str(amount).encode()+b'\n');child=json.loads(worker.stdout.readline())
    print(json.dumps({'event':'VALUE','pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total,'worker':child}),flush=True)
worker.stdin.write(b'EXIT\n');worker.stdin.close();worker.stdout.close();worker.wait(timeout=5)
''' % WORKER


def descendants(pid):
    result=[];queue=[pid]
    while queue:
        parent=queue.pop(0)
        try:children=list(map(int,(pathlib.Path('/proc')/str(parent)/'task'/str(parent)/'children').read_text().split()))
        except FileNotFoundError:children=[]
        for child in children:
            if child not in result:
                result.append(child);queue.append(child)
    return result


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    binary=pathlib.Path(a.binary).resolve(strict=True)
    with binary.open('rb') as file:binary_sha=hashlib.file_digest(file,'sha256').hexdigest()
    report={'complete':False,'binary_sha256':binary_sha,'checks':[],'privileged_operation':False,'DC_session_modified':False,'cloud_binding_used':False}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(name,detail=None):report['checks'].append({'check':name,'detail':detail});save();print('PASS',name,flush=True)
    controller=None;app=None
    with tempfile.TemporaryDirectory(prefix='hepta-stream-native-controller-') as temp:
        root=pathlib.Path(temp);workspace=root/'workspace';workspace.mkdir(mode=0o700);state=root/'state';state.mkdir(mode=0o700)
        remote=root/'remote';remote.mkdir(mode=0o700);token='native-'+os.urandom(24).hex();token_file=root/'token';token_file.write_text(token);token_file.chmod(0o600)
        host={'ssh_target':'localhost','platform':'linux','remote_state_dir':str(remote),'execution_mode':'operator','allow_execute':True,'allow_pty':True,'allow_write':True,
              'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[str(remote)],'allowed_write_path_prefixes':[str(remote)]}
        config={'state_dir':str(state),'controller_workspace_roots':[str(workspace)],'hosts':{'operator':host}}
        config_file=root/'runtime.json';config_file.write_text(json.dumps(config))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        url=f'http://127.0.0.1:{port}/mcp';log_file=root/'controller.log'
        def start():
            nonlocal controller
            log=open(log_file,'ab')
            controller=subprocess.Popen([str(binary),'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}','--runtime-config',str(config_file),'--auth-token-file',str(token_file)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
            for _ in range(100):
                if controller.poll() is not None:raise RuntimeError(log_file.read_text()[-3000:])
                try:return Client(url,token)
                except Exception:time.sleep(.08)
            raise RuntimeError('stream canary controller unavailable')
        try:
            c=start();names={tool['name'] for tool in c.rpc('tools/list',{})['tools']}
            required={'stream_handoff_prepare','stream_handoff_status','stream_handoff_read','stream_handoff_write','stream_handoff_close','stream_handoff_list'}
            assert required<=names;passed('six native stream handoff tools discovered',len(names))
            app=subprocess.Popen([sys.executable,'-u','-c',APP],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,bufsize=0)
            deadline=time.monotonic()+3;child_pids=[]
            while time.monotonic()<deadline:
                child_pids=descendants(app.pid)
                if child_pids:break
                time.sleep(.02)
            assert len(child_pids)==1,child_pids
            app.stdin.write(b'17\n');app.stdin.flush()
            pending=bytearray(4)
            for _ in range(100):
                fcntl.ioctl(app.stdout.fileno(),termios.FIONREAD,pending,True)
                if int.from_bytes(pending,sys.byteorder)>0:break
                time.sleep(.02)
            queued=int.from_bytes(pending,sys.byteorder);assert queued>0
            key='native-stream-'+os.urandom(12).hex()
            prepared=c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':[app.pid,*child_pids]})
            sid=prepared['session_id'];assert prepared['status']['state']=='waiting_for_owner'
            ack=EXPORT.transfer(prepared['handoff_socket'],sid,{'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno(),'stderr_reader':app.stderr.fileno()},
                                [app.pid,*child_pids],acknowledge_quiesced_io=True)
            assert ack['accepted'];app.stdin.close();app.stdout.close();app.stderr.close()
            passed('cooperating old owner exports exact queued pipes to native receiver',{'queued_before':queued,'application_pids':[app.pid,*child_pids]})
            def read_all(offset=0,needle=None):
                text='';deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    page=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':offset,'limit':4096})
                    block=base64.b64decode(page['data_base64']);text+=block.decode();offset=page['next_offset']
                    if needle is None or needle in text:return text,offset,page
                    time.sleep(.05)
                raise AssertionError('missing native stream output '+str(needle))
            text,cursor,page=read_all(0,'"total": 17')
            lines=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
            ready=next(v for v in lines if v['event']=='READY');seventeen=next(v for v in lines if v['event']=='VALUE')
            assert seventeen['total']==17 and ready['hash']==seventeen['hash'] and seventeen['worker']['total']==17
            passed('queued pre-handoff application and child state captured without replay')
            controller.kill();controller.wait(timeout=10);time.sleep(2.3)
            c=start();listing=c.call('stream_handoff_list',{'limit':20})
            assert any(v['session_id']==sid for v in listing['sessions'])
            status=c.call('stream_handoff_status',{'session_id':sid});assert status['owner_accepted'] and status['all_applications_alive']
            offline,cursor,page=read_all(cursor,'OFFLINE_MARK');assert 'OFFLINE_MARK' in offline
            again=c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':[app.pid,*child_pids]})
            assert again['reused'] and again['session_id']==sid
            c.call('stream_handoff_prepare',{'idempotency_key':key,'application_pids':[app.pid]},denied=True)
            passed('receiver and queued output survive MCP controller SIGKILL/restart with same identity')
            write={'session_id':sid,'request_id':'native-write-0001','data_base64':base64.b64encode(b'5\n').decode()}
            first=c.call('stream_handoff_write',write);second=c.call('stream_handoff_write',write)
            assert first['state']=='confirmed' and not first['reused'] and second['reused']
            changed={**write,'data_base64':base64.b64encode(b'6\n').decode()};c.call('stream_handoff_write',changed,denied=True)
            value,cursor,page=read_all(cursor,'"total": 22');result=next(v for v in map(json.loads,[line for line in value.splitlines() if line.startswith('{')]) if v.get('event')=='VALUE')
            assert result['total']==22 and result['hash']==ready['hash'] and result['worker']['hash']==ready['worker']['hash']
            passed('native input request identity prevents duplicate effects and preserves app/child memory')
            c.call('stream_handoff_close',{'session_id':sid});app.wait(timeout=8)
            for _ in range(100):
                status=c.call('stream_handoff_status',{'session_id':sid})
                if status['state']=='exited':break
                time.sleep(.05)
            assert status['state']=='exited' and status['output_complete']
            final=c.call('stream_handoff_read',{'session_id':sid,'stream':'stdout','offset':0,'limit':16384})
            assert final['output_complete'] and final['eof']
            c.call('stream_handoff_write',{**write,'request_id':'after-exit-01'},denied=True)
            receipts=(state/'stream_handoffs'/sid/'input_receipts.jsonl').read_text()
            assert base64.b64encode(b'5\n').decode() not in receipts and '5\\n' not in receipts
            passed('input close is EOF not signal; final archive complete; raw input absent from receipts')
            report.update(complete=True,passed=len(report['checks']),session_id=sid,application_pid=ready['pid'],child_pid=ready['worker']['pid'],
                          controller_restart_used_sigkill=True,application_checkpoint_code=False,application_processes_stopped_for_handoff=False,
                          native_receiver_persistent_across_runtime_restart=True)
            save();print('STREAM_NATIVE_PASS',report['passed'],flush=True)
        finally:
            if controller is not None and controller.poll() is None:
                controller.terminate();controller.wait(timeout=10)
            if app is not None and app.poll() is None:
                os.killpg(app.pid,signal.SIGTERM);app.wait(timeout=5)
            save()


if __name__=='__main__':main()
