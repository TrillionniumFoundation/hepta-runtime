# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Ordinary owned flock Pending/cancel/EOF captures. No interception or qualification by capture alone."""
from pathlib import Path
import fcntl,json,os,selectors,stat,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import lifecycle_inputs as inputs
import lifecycle_success as base
q=base.q;J=base.J

def lock_witness(child,lock):
    expected=lock.stat();root=Path('/proc')/str(child.pid);tids=[];fds=[]
    for path in sorted((root/'task').iterdir()):
        try:
            wchan=(path/'wchan').read_text().strip()
            if 'locks_lock_inode_wait'in wchan or 'flock'in wchan:tids.append(dict(tid=int(path.name),wchan=wchan))
        except FileNotFoundError:continue
    for path in sorted((root/'fd').iterdir()):
        try:
            found=path.stat()
            if (found.st_dev,found.st_ino)==(expected.st_dev,expected.st_ino):
                fds.append(dict(fd=int(path.name),device=found.st_dev,inode=found.st_ino,mode=stat.S_IMODE(found.st_mode),target=os.readlink(path)))
        except FileNotFoundError:continue
    return dict(pid=child.pid,monotonic_ns=time.monotonic_ns(),wall_ns=time.time_ns(),
        lock_device=expected.st_dev,lock_inode=expected.st_ino,blocked_threads=tids,matching_open_descriptors=fds,
        actual_flock_wait=bool(tids and fds))

def run_case(case,folder,binary,side,update,*,retained_common=None):
    target=folder/side;target.mkdir(mode=0o700)
    common=folder/'common' if retained_common is None else Path(retained_common)
    state=common/'state';state.mkdir(mode=0o700)
    confpath=common/'config.json';conf=q.SORTED(base.config(case,state))
    if confpath.exists():assert confpath.read_bytes()==conf
    else:base.create(confpath,conf)
    fence_env,roots=base.setup_fence(case,common,state)
    fence_before={p.name:q.capture_tree(p,True)for p in roots};base.create(target/'fence-before.json',J(fence_before))
    env=dict(PATH='',LC_ALL='C',HEPTA_REQUEST_AUDIT_TRACE='0',**fence_env)
    command=[str(binary),'--runtime-config',str(confpath)]
    row=dict(side=side,case=case,status='RUNNING',pid=None,command=command,environment=env,
        sends=[],responses=[],successful_starts=0,qualification=False,full_capture=False)
    child=None;guard=None;buffer=b'';received={};next_index=0;started=time.monotonic_ns();update(row)
    try:
        with(target/'input.bin').open('xb')as sin,(target/'stdout.bin').open('xb')as sout,(target/'stderr').open('xb')as serr:
            child=subprocess.Popen(command,cwd=target,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=serr,bufsize=0,close_fds=True)
            row['pid']=child.pid;update(row)
            def send(method,params,identifier,label):
                nonlocal next_index
                request=dict(jsonrpc='2.0')
                if identifier is not None:request['id']=identifier
                request.update(method=method,params=params);raw=q.C(request)+b'\n'
                event=dict(index=next_index,label=label,request=request,raw_input_hex=raw.hex(),
                    wall_before=time.time_ns(),mono_before=time.monotonic_ns(),sent_bytes=0)
                next_index+=1;row['sends'].append(event);update(row)
                while event['sent_bytes']<len(raw):
                    at=event['sent_bytes'];n=os.write(child.stdin.fileno(),raw[at:]);assert n>0
                    sin.write(raw[at:at+n]);sin.flush();event['sent_bytes']+=n
                event.update(wall_after=time.time_ns(),mono_after=time.monotonic_ns())
                base.create(target/('send-'+str(event['index'])+'.json'),J(event));update(row);return event
            def tool(identifier,name,args,label):
                return send('tools/call',dict(name=name,arguments=args),identifier,label)
            def drain(timeout):
                nonlocal buffer
                with selectors.DefaultSelector()as sel:
                    sel.register(child.stdout,selectors.EVENT_READ);events=sel.select(timeout)
                if not events:return False
                data=os.read(child.stdout.fileno(),65536);sout.write(data);sout.flush()
                if not data:return True
                buffer+=data;assert len(buffer)<=134217728
                while b'\n'in buffer:
                    pos=buffer.index(b'\n')+1;wire=buffer[:pos];buffer=buffer[pos:]
                    response=q.checked_json(wire[:-1]);identifier=response.get('id')
                    assert type(identifier)is int and identifier not in received
                    event=dict(order=len(row['responses']),id=identifier,response=response,raw_output_hex=wire.hex(),
                        wall_after=time.time_ns(),mono_after=time.monotonic_ns())
                    received[identifier]=event;row['responses'].append(event)
                    base.create(target/('response-'+str(identifier)+'.json'),J(event));update(row)
                return False
            def await_response(identifier):
                deadline=time.monotonic()+30
                while identifier not in received:
                    left=deadline-time.monotonic();assert left>0
                    eof=drain(left);assert not eof or identifier in received,'unexpected EOF while waiting response'
                response=received[identifier]['response']
                if identifier!=0:assert response['result']['isError']is False,(identifier,response)
                return response
            send('initialize',dict(protocolVersion=case['protocol'],capabilities={},clientInfo=dict(name='ordinary-public-fence-pending',version='1')),0,'initialize')
            await_response(0);tool(1,'host_list',{},'baseline');await_response(1)
            row['baseline_snapshot']=base.snapshot(target/'baseline-filesystem.json',state,True)
            lock=common/'fence/.owner.lock';guard=lock.open('r+b');fcntl.flock(guard.fileno(),fcntl.LOCK_EX)
            row['guard_acquired_mono']=time.monotonic_ns()
            args=dict(operation=dict(tool='host_list',arguments={}),idempotency_key=case['key'])
            tool(2,'request_start',args,'blocked-start')
            deadline=time.monotonic()+10;witnesses=[]
            while True:
                assert child.poll()is None and time.monotonic()<deadline,'owned child did not enter actual flock wait'
                witness=lock_witness(child,lock);witnesses.append(witness);drain(0)
                assert 2 not in received,'Start completed while the private authority lock was exclusively held'
                if witness['actual_flock_wait']:break
                time.sleep(0.005)
            base.create(target/'blocked-observations.json',J(witnesses));row['blocked_witness']=witness
            row['while_blocked_snapshot']=base.snapshot(target/'blocked-filesystem.json',state,True)
            assert not list((state/'request-async-v9/.intents').glob('*.json')),'producer began before fence acquisition'
            if case['action']=='cancel':
                send('notifications/cancelled',dict(requestId=2,reason='ordinary owned fence wait'),None,'cancel-notification')
            tool(3,'host_list',{},'sibling-during-wait');await_response(3);assert 2 not in received
            row['sibling_before_guard_release']=True
            base.create(target/'sibling-before-release.json',J(dict(response=received[3],witness=lock_witness(child,lock))))
            if case['action']=='eof':
                child.stdin.close();row['eof_sent_monotonic_ns']=time.monotonic_ns();deadline=time.monotonic()+5.5
                while time.monotonic()<deadline:
                    assert child.poll()is None,'runtime exited while the real fence worker was still blocked'
                    drain(min(0.05,max(0,deadline-time.monotonic())));assert 2 not in received
                row['drain_wait_witness']=lock_witness(child,lock);assert row['drain_wait_witness']['actual_flock_wait']
                row['guard_released_mono']=time.monotonic_ns()
                assert row['guard_released_mono']-row['eof_sent_monotonic_ns']>=5_500_000_000
                fcntl.flock(guard.fileno(),fcntl.LOCK_UN);guard.close();guard=None
            else:
                row['guard_released_mono']=time.monotonic_ns()
                fcntl.flock(guard.fileno(),fcntl.LOCK_UN);guard.close();guard=None
                if case['action']=='normal':await_response(2)
                deadline=time.monotonic()+30;completion=[]
                while True:
                    assert child.poll()is None and time.monotonic()<deadline,'producer completion observation deadline'
                    drain(0)
                    if case['action']=='cancel':assert 2 not in received,'SDK cancelled request produced a response'
                    found=list((state/'request-async-v9/.outcomes').glob('*.json'));assert len(found)<=1
                    stamp=dict(monotonic_ns=time.monotonic_ns(),wall_ns=time.time_ns())
                    if found:
                        raw=found[0].read_bytes();value=q.checked_json(raw)
                        stamp.update(path=str(found[0]),hex=raw.hex(),sha256=q.H(raw));completion.append(stamp)
                        assert value['state']=='completed';identifier=value['request_id'];break
                    stamp['absent']=True;completion.append(stamp);time.sleep(0.005)
                base.create(target/'completion-observations.json',J(completion))
                row['successful_starts']=1;row['inner_request_id']=identifier
                row['completion_snapshot']=base.snapshot(target/'completed-filesystem.json',state,True)
                if case['action']=='normal':
                    receipt=q.checked_json(received[2]['response']['result']['content'][0]['text'].encode())
                    assert receipt['request_id']==identifier and receipt['reused']is False
                tool(4,'request_status',dict(request_id=identifier),'completed-status');response=await_response(4)
                body=q.checked_json(response['result']['content'][0]['text'].encode())
                assert body['async_state']=='completed'and body['owned_future_active']is False
                tool(5,'request_cancel',dict(request_id=identifier),'completed-cancel');response=await_response(5)
                body=q.checked_json(response['result']['content'][0]['text'].encode())
                assert body['cancel_requested']is False and body['observation']=='no_owned_future_present_no_replay'
                if case['action']=='cancel':assert 2 not in received
                child.stdin.close();row['eof_sent_monotonic_ns']=time.monotonic_ns()
            deadline=time.monotonic()+30
            while child.poll()is None:
                left=deadline-time.monotonic();assert left>0,'EOF drain deadline';drain(min(left,0.05))
            child.wait()
            while not drain(0):pass
            assert not buffer and child.returncode==0 and(target/'stderr').read_bytes()==b''
            expected={0,1,3}if case['action']=='eof'else({0,1,2,3,4,5}if case['action']=='normal'else{0,1,3,4,5})
            assert set(received)==expected
            assert(target/'input.bin').read_bytes()==b''.join(bytes.fromhex(x['raw_input_hex'])for x in row['sends'])
            assert(target/'stdout.bin').read_bytes()==b''.join(bytes.fromhex(x['raw_output_hex'])for x in row['responses'])
            row.update(exit_code=0,reaped=True,full_capture=True,eof_completed_monotonic_ns=time.monotonic_ns())
        row['final']=base.snapshot(target/'eof-filesystem.json',state,True)
        row['fence_after']={p.name:q.capture_tree(p,True)for p in roots};base.create(target/'fence-after.json',J(row['fence_after']))
        assert row['fence_after']==fence_before
        if case['action']=='eof':
            assert not list((state/'request-async-v9/.intents').glob('*.json'));row['successful_starts']=0
        row['status']='CAPTURED_NOT_QUALIFIED'
        os.rename(state,target/'final-state')
        for p in roots:os.rename(p,target/('final-'+p.name))
    except BaseException as error:
        row.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        if guard is not None:fcntl.flock(guard.fileno(),fcntl.LOCK_UN);guard.close()
        if child is not None:
            if child.poll()is None:child.kill();child.wait(timeout=3)
            row['exit_code']=child.returncode
            if child.stdout is not None:
                try:
                    raw=child.stdout.read()
                    if raw:
                        with(target/'stdout.bin').open('ab')as f:f.write(raw)
                except(OSError,ValueError):pass
        row['elapsed_seconds']=(time.monotonic_ns()-started)/1e9
        for name in ('input.bin','stdout.bin','stderr'):
            p=target/name
            if p.exists():row[name]=inputs.pin(p)
        base.create(target/'result.json',J(row));update(row)
    return row
