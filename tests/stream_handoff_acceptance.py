#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real non-root handoff of a cooperating launcher's pipes while its app tree lives.
Application and worker have random memory but no save/reload/checkpoint interface.
A queued output record crosses the ownership change without consuming it first.
"""
import array
import fcntl
import hashlib
import importlib.util
import json
import os
import pathlib
import select
import subprocess
import sys
import tempfile
import termios
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('handoff',ROOT/'deploy/stream_handoff.py');H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)


def line(fd,timeout=10):
    data=b'';deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if not select.select([fd],[],[],max(0,deadline-time.monotonic()))[0]:break
        block=os.read(fd,1)
        if not block:raise RuntimeError('unexpected application EOF')
        data+=block
        if data.endswith(b'\n'):return json.loads(data)
        if len(data)>4096:raise ValueError('fixture response too large')
    raise TimeoutError('fixture line missing')


def save(path,value):
    with path.open('x') as f:json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def worker():
    memory=os.urandom(32);total=0
    def value():return {'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'count':total}
    print(json.dumps(value()),flush=True)
    for command in sys.stdin:
        if command.strip()=='EXIT':return
        total+=int(command);print(json.dumps(value()),flush=True)


def application(root):
    memory=os.urandom(32);total=0
    child=subprocess.Popen([sys.executable,__file__,'worker',str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,bufsize=0)
    def report(event,other):
        print(json.dumps({'event':event,'pid':os.getpid(),'hash':hashlib.sha256(memory).hexdigest(),'count':total,'worker':other}),flush=True)
    report('READY',line(child.stdout.fileno()))
    try:
        for command in sys.stdin:
            if command.strip()=='EXIT':child.stdin.write(b'EXIT\n');child.wait(timeout=5);return
            amount=int(command);total+=amount;child.stdin.write(str(amount).encode()+b'\n');report('VALUE',line(child.stdout.fileno()))
    finally:
        child.stdin.close();child.stdout.close()
        if child.poll() is None:child.wait(timeout=5)


def owner(root):
    handoff_id=root.name;error=(root/'application-error.log').open('wb')
    app=subprocess.Popen([sys.executable,__file__,'application',str(root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=error,start_new_session=True,bufsize=0)
    ready=line(app.stdout.fileno());assert ready['event']=='READY'
    app.stdin.write(b'17\n');before=line(app.stdout.fileno());assert before['count']==17 and before['worker']['count']==17
    identities=[H.identity(before['pid']),H.identity(before['worker']['pid'])]
    app.stdin.write(b'5\n')
    pending=array.array('i',[0])
    for _ in range(100):
        fcntl.ioctl(app.stdout.fileno(),termios.FIONREAD,pending,True)
        if pending[0]>0:break
        time.sleep(.02)
    assert pending[0]>0,'queued output must exist without being read by old owner'
    inventory_spec=importlib.util.spec_from_file_location('live_inventory',ROOT/'deploy/maintenance_inventory.py')
    inspector=importlib.util.module_from_spec(inventory_spec);inventory_spec.loader.exec_module(inspector)
    inventory=inspector.resource_report(app.pid)
    assert inventory['process_count']==2 and inventory['observation_stable'] and inventory['descriptor_bindings_stable']
    external=inventory['external_descriptor_owners']
    assert any(v['identity']['pid']==os.getpid() and v['kind']=='pipe' for v in external)
    assert not inventory['migration_authorized'] and not inventory['processes_signalled']
    save(root/'resource-inventory.json',inventory)
    metadata={'before':before,'ready':ready,'application_identities':identities,'queued_output_bytes_before_transfer':pending[0],
              'resource_inventory_sha256':hashlib.sha256((root/'resource-inventory.json').read_bytes()).hexdigest(),
              'resource_inventory_summary':{'process_count':inventory['process_count'],'external_owner_count':len(external),
                'old_owner_explicitly_identified':True,'ownership_scan_complete':inventory['ownership_scan_complete'],
                'unavailable_count':inventory['unavailable_count'],'no_migration_authorized_by_inventory':True}}
    ack=H.transfer(root/'handoff.sock',handoff_id,{'stdin_writer':app.stdin.fileno(),'stdout_reader':app.stdout.fileno()},[v['pid'] for v in identities],acknowledge_quiesced_io=True)
    receipt=(root/'descriptor-receipt.json').read_bytes();assert hashlib.sha256(receipt).hexdigest()==ack['receipt_sha256']
    app.stdin.close();app.stdout.close();error.close()
    save(root/'owner-report.json',{**metadata,'ack':ack,'old_owned_descriptors_closed':True,'old_owner_pid':os.getpid()})
    # No terminate/wait on the still-running application: only this owner exits.


def receiver(root):
    server=H.listener(root/'handoff.sock');server.settimeout(15)
    try:
        conn,_=server.accept()
        with conn:
            conn.settimeout(10);receipt,fds=H.receive(conn,root/'descriptor-receipt.json',root.name)
        sender=receipt['sender']
        for _ in range(200):
            try:H.identity(sender['pid'])
            except (FileNotFoundError,PermissionError):break
            time.sleep(.025)
        else:raise RuntimeError('old owner has not exited')
        queued=line(fds['stdout_reader']);assert queued['event']=='VALUE' and queued['count']==22 and queued['worker']['count']==22
        os.write(fds['stdin_writer'],b'7\n');after=line(fds['stdout_reader']);assert after['count']==29 and after['worker']['count']==29
        identities=[H.identity(after['pid']),H.identity(after['worker']['pid'])]
        assert identities==receipt['application_identities']
        worker_stat=pathlib.Path('/proc',str(after['worker']['pid']),'stat').read_text()
        assert int(worker_stat[worker_stat.rfind(')')+2:].split()[1])==after['pid']
        os.write(fds['stdin_writer'],b'EXIT\n')
        for fd in fds.values():os.close(fd)
        save(root/'receiver-report.json',{'complete':True,'queued':queued,'after':after,'application_identities_after':identities,'receiver_pid':os.getpid(),'old_owner_exited_before_new_io':True})
    finally:server.close();(root/'handoff.sock').unlink(missing_ok=True)


def acceptance(out):
    if os.geteuid()==0:raise RuntimeError('this test specifically requires the normal non-root account')
    root=pathlib.Path(tempfile.mkdtemp(prefix='hepta-stream-handoff-'));root.chmod(0o700)
    report={'complete':False,'fixture_root':str(root),'privileged_operation':False,'real_DC_sessions_modified':False,
            'native_runtime_adoption_claimed':False,'cross_host_memory_migration_claimed':False}
    with (root/'receiver.log').open('wb') as rlog,(root/'owner.log').open('wb') as olog:
        recv=subprocess.Popen([sys.executable,__file__,'receiver',str(root)],stdout=rlog,stderr=rlog)
        for _ in range(100):
            if (root/'handoff.sock').exists():break
            if recv.poll() is not None:raise RuntimeError('receiver setup failed')
            time.sleep(.02)
        own=subprocess.Popen([sys.executable,__file__,'owner',str(root)],stdout=olog,stderr=olog)
        rc=own.wait(timeout=25);rr=recv.wait(timeout=25)
        report.update(owner_exit_code=rc,receiver_exit_code=rr)
        if rc or rr:
            save(pathlib.Path(out),report);raise RuntimeError('fixture failed; retained '+str(root))
    source=json.loads((root/'owner-report.json').read_text());dest=json.loads((root/'receiver-report.json').read_text())
    before,queued,after=source['before'],dest['queued'],dest['after']
    for record in (queued,after):
        assert record['pid']==before['pid'] and record['hash']==before['hash']
        assert record['worker']['pid']==before['worker']['pid'] and record['worker']['hash']==before['worker']['hash']
    assert source['queued_output_bytes_before_transfer']>0 and source['application_identities']==dest['application_identities_after']
    report.update(complete=True,source=source,destination=dest,application_and_worker_numeric_identity_unchanged=True,
                  random_memory_hashes_unchanged=True,original_pipe_objects_transferred=True,pending_output_preserved=True,
                  sequence_counts=[17,22,29],old_input_replayed=False,application_checkpoint_code=False,
                  application_processes_stopped=False,old_owner_cooperation_required=True,
                  scope='same-host same-login cooperative live descriptor ownership transfer; not arbitrary DC adoption or CRIU tree capture')
    save(pathlib.Path(out),report);print('LIVE_STREAM_HANDOFF_PASS '+json.dumps({'processes':2,'counts':[17,22,29],'pending_output_preserved':True,'root_required':False,'native_runtime_adoption':False}))


if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='worker':worker()
    elif mode=='application':application(pathlib.Path(sys.argv[2]))
    elif mode=='owner':owner(pathlib.Path(sys.argv[2]))
    elif mode=='receiver':receiver(pathlib.Path(sys.argv[2]))
    elif mode=='test':acceptance(sys.argv[2])
    else:raise ValueError('unknown fixture mode')
