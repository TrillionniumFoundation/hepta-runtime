#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real old-owner output-history boundary into the native persistent broker.

The owner reads and forwards child output before handoff, finalizes that exact
history, transfers the same live pipes + read-only history, exits, and the broker
continues from the next unread kernel byte. No child checkpoint/restart is used.
"""
import base64
import hashlib
import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
BROKER=ROOT/'src/mcp/runtime/stream_broker.py'
OWNER=ROOT/'deploy/dc_handoff_owner.py'
APP=r"""
import hashlib,json,os,sys
memory=os.urandom(32);total=0
def emit(event):
 print(json.dumps({'event':event,'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'total':total}),flush=True)
emit('READY')
for line in sys.stdin:
 total+=int(line);emit('VALUE')
"""


def rpc(q,fail=False):
    p=subprocess.run([sys.executable,str(BROKER)],input=json.dumps(q),text=True,capture_output=True,timeout=30)
    if fail:
        assert p.returncode!=0,p.stdout
        return p.stderr
    if p.returncode:raise RuntimeError(p.stderr)
    return json.loads(p.stdout)


def read_line(fd,timeout=8):
    data=b'';deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if not select.select([fd],[],[],max(0,deadline-time.monotonic()))[0]:break
        block=os.read(fd,1)
        if not block:raise RuntimeError('owner output EOF')
        data+=block
        if data.endswith(b'\n'):return data
        if len(data)>16384:raise ValueError('owner line too large')
    raise TimeoutError('owner output line missing')


def main():
    with tempfile.TemporaryDirectory(prefix='hepta-dc-owner-history-') as temp:
        root=pathlib.Path(temp);state=root/'runtime';state.mkdir(mode=0o700);owner_state=root/'owner'
        owner=subprocess.Popen([sys.executable,'-u',str(OWNER),'run','--state-dir',str(owner_state),'--',
                                sys.executable,'-u','-c',APP],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        assert owner.stdin and owner.stdout and owner.stderr
        marker=json.loads(read_line(owner.stdout.fileno()).decode().split(' ',1)[1])
        ready=json.loads(read_line(owner.stdout.fileno()))
        assert ready['event']=='READY' and ready['pid']==marker['child_identity']['pid']
        owner.stdin.write(b'17\n');owner.stdin.flush()
        first=json.loads(read_line(owner.stdout.fileno()))
        assert first['event']=='VALUE' and first['total']==17 and first['hash']==ready['hash']
        status=json.loads(subprocess.check_output([sys.executable,str(OWNER),'status','--socket',marker['control_socket']],text=True))
        assert status['application_pids'][0]==ready['pid'] and status['stdin_pending_bytes']==0
        history_before=(owner_state/'stdout.history').read_bytes()
        assert history_before==json.dumps(ready).encode()+b'\n'+json.dumps(first).encode()+b'\n'
        session='stream-'+hashlib.sha256(b'dc-history-fixture').hexdigest()
        prepared=rpc({'op':'prepare','state_dir':str(state),'session_id':session,'application_pids':status['application_pids']})
        handoff=json.loads(subprocess.check_output([sys.executable,str(OWNER),'handoff',
            '--socket',marker['control_socket'],'--handoff-socket',prepared['handoff_socket'],
            '--session-id',session,'--application-pids',json.dumps(status['application_pids'])],text=True))
        assert handoff['accepted'] and handoff['userspace_read_ahead_bytes_unaccounted']==0
        owner.stdin.close()
        assert owner.wait(timeout=10)==0
        # Broker must expose exactly what the old owner had already consumed first.
        page=rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':16384})
        prefix=base64.b64decode(page['data_base64'])
        assert prefix==history_before
        receipt=json.loads((state/'stream_handoffs'/session/'handoff_receipt.json').read_text())
        assert receipt['history_seed']['stdout']['sha256']==hashlib.sha256(history_before).hexdigest()
        assert receipt['history_seed']['stdout']['size']==len(history_before)
        # Continue through native broker only; child PID/memory identity must stay.
        rpc({'op':'write','state_dir':str(state),'session_id':session,'request_id':'history-continuation-01',
             'data_base64':base64.b64encode(b'5\n').decode()})
        deadline=time.monotonic()+8;full=prefix
        while time.monotonic()<deadline:
            page=rpc({'op':'read','state_dir':str(state),'session_id':session,'stream':'stdout','offset':0,'limit':16384})
            full=base64.b64decode(page['data_base64'])
            if b'"total": 22' in full:break
            time.sleep(.05)
        assert full.startswith(history_before)
        lines=[json.loads(v) for v in full.splitlines() if v.startswith(b'{')]
        after=lines[-1]
        assert after['total']==22 and after['pid']==ready['pid'] and after['hash']==ready['hash']
        rpc({'op':'close','state_dir':str(state),'session_id':session})
        # Closing input yields EOF and normal child exit; archive remains readable.
        deadline=time.monotonic()+8;status2=None;last_status_error=None
        while time.monotonic()<deadline:
            try:
                status2=rpc({'op':'status','state_dir':str(state),'session_id':session})
                last_status_error=None
            except RuntimeError as error:
                # The broker closes its control socket just before publishing final.json.
                # A status probe that lands in that tiny transition can see ECONNRESET;
                # retry the same durable session identity instead of treating it as loss.
                last_status_error=error;time.sleep(.05);continue
            if status2['state']=='exited':break
            time.sleep(.05)
        if status2 is None and last_status_error is not None:raise last_status_error
        assert status2['state']=='exited' and status2['output_complete']
        assert owner.stderr.read()==b''
        report={'complete':True,'old_owner_started_child':True,'old_owner_exited':True,
                'application_pid_before_after':ready['pid'],'application_random_memory_hash':ready['hash'],
                'pre_handoff_history_bytes':len(history_before),'pre_handoff_history_sha256':hashlib.sha256(history_before).hexdigest(),
                'history_is_exact_broker_prefix':True,'userspace_read_ahead_unaccounted_bytes':0,
                'post_handoff_total':22,'application_checkpoint_code':False,'application_stopped_for_handoff':False,
                'privileged_operation':False,'arbitrary_existing_DC_session_adoption':False}
        pathlib.Path('dc-owner-history-acceptance.json').write_text(json.dumps(report,indent=2)+'\n')
        print('DC_OWNER_HISTORY_HANDOFF_PASS '+json.dumps(report))


if __name__=='__main__':main()
