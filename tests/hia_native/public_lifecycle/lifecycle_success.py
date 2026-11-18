# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual ordinary nine-tool Start/Cancel pairs with full source and capture admission."""
from pathlib import Path
import argparse,fcntl,hashlib,json,os,selectors,stat,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import lifecycle_inputs as inputs
import lifecycle_success_cases as cases
import lifecycle_success_projection as q
J=lambda value:(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def create(path,raw):
    with path.open('xb')as f:f.write(raw)
    path.chmod(0o600)

def atomic(path,raw):
    temp=path.with_name(path.name+'.updating')
    with temp.open('wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    temp.chmod(0o600);os.replace(temp,path)

def config(case,state):
    hosts={}
    for i in range(case['hosts']):
        hosts['fixture'+format(i,'03d')]=dict(ssh_target='unused-local-fixture-'+str(i),
            remote_state_dir='/unused-private-'+str(i),allow_write=False)
    return dict(state_dir=str(state),hosts=hosts)

def setup_fence(case,common,state):
    kind=case['fence'];env={};paths=[]
    if kind is None:return env,paths
    root=common/'fence';root.mkdir(mode=0o700);paths.append(root)
    predecessor=common/'predecessor';other=common/'other-state'
    document=dict(schema='hepta-effect-owner-fence-v1',owner='v4',epoch=1,phase='admitting',state_root=str(state))
    env=dict(HEPTA_EFFECT_OWNER_FENCE_DIR=str(root),HEPTA_EFFECT_OWNER_SELF='v4',HEPTA_EFFECT_OWNER_FENCE_REQUIRED='1')
    if kind=='v11':
        predecessor.mkdir(mode=0o700);paths.append(predecessor)
        document.update(owner='v11',predecessor_state_root=str(predecessor))
        env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='frozen':document['phase']='frozen'
    elif kind=='wrong_owner':env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='wrong_state':
        other.mkdir(mode=0o700);paths.append(other);document['state_root']=str(other)
    elif kind=='missing_predecessor':
        document['owner']='v11';env['HEPTA_EFFECT_OWNER_SELF']='v11'
    elif kind=='zero_epoch':document['epoch']=0
    elif kind=='partial':env.pop('HEPTA_EFFECT_OWNER_SELF')
    elif kind=='invalid_required':env['HEPTA_EFFECT_OWNER_FENCE_REQUIRED']='0'
    else:assert kind=='v4'
    create(root/'.owner.lock',b'');create(root/'.owner.json',q.SORTED(document))
    return env,paths

def receive(child,buffer,complete):
    deadline=time.monotonic()+30
    with selectors.DefaultSelector()as selector:
        selector.register(child.stdout,selectors.EVENT_READ)
        while b'\n'not in buffer:
            remaining=deadline-time.monotonic()
            assert remaining>0 and selector.select(remaining),'30 second public response deadline'
            raw=os.read(child.stdout.fileno(),65536)
            complete.write(raw);complete.flush()
            assert raw,'unexpected public EOF'
            buffer+=raw
            assert len(buffer)<=134217728
    end=buffer.index(b'\n')+1
    return buffer[:end],buffer[end:]

def snapshot(path,root,strict):
    result=dict(wall_before=time.time_ns(),mono_before=time.monotonic_ns())
    result['filesystem']=q.capture_tree(root,strict)
    result.update(wall_after=time.time_ns(),mono_after=time.monotonic_ns())
    create(path,J(result));return result

def run_side(case,folder,binary,side,update,*,retained_common=None):
    target=folder/side;target.mkdir(mode=0o700)
    common=folder/'common' if retained_common is None else Path(retained_common)
    state=common/'state';state.mkdir(mode=0o700)
    configuration=common/'config.json';conf=q.SORTED(config(case,state))
    if configuration.exists():assert configuration.read_bytes()==conf
    else:create(configuration,conf)
    env=dict(PATH='',LC_ALL='C',HEPTA_REQUEST_AUDIT_TRACE='0')
    additional,fence_paths=setup_fence(case,common,state);env.update(additional)
    before_fences={p.name:q.capture_tree(p,True)for p in fence_paths}
    create(target/'fence-before.json',J(before_fences))
    row=dict(side=side,case=case['name'],status='RUNNING',pid=None,command=[str(binary),'--runtime-config',str(configuration)],
        environment=env,requests_entered=0,responses_received=0,responses_validated=0,
        successful_starts=0,full_capture=False,frames=[],boundaries={})
    child=None;buffer=b'';started=time.monotonic_ns();streams={}
    update(row)
    try:
        with(target/'input.bin').open('xb')as sin,(target/'stdout.bin').open('xb')as sout,(target/'stderr').open('xb')as serr:
            streams=dict(input=sin,output=sout)
            child=subprocess.Popen(row['command'],cwd=target,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=serr,bufsize=0,close_fds=True)
            row['pid']=child.pid;update(row)
            def call(tool,args,label,success=True):
                nonlocal buffer
                index=len(row['frames'])
                if tool is None:
                    request=dict(jsonrpc='2.0',id=index,method='initialize',params=dict(protocolVersion=case['protocol'],
                        capabilities={},clientInfo=dict(name='public-start-normal-pairs',version='1')))
                else:request=dict(jsonrpc='2.0',id=index,method='tools/call',params=dict(name=tool,arguments=args))
                raw=q.C(request)+b'\n';row['requests_entered']+=1
                wall_before=time.time_ns();mono_before=time.monotonic_ns();sent=0
                while sent<len(raw):
                    n=os.write(child.stdin.fileno(),raw[sent:]);assert n>0
                    sin.write(raw[sent:sent+n]);sin.flush();sent+=n
                wire,buffer=receive(child,buffer,sout)
                frame=dict(index=index,label=label,request=request,response=q.checked_json(wire[:-1]),
                    raw_input_hex=raw.hex(),raw_output_hex=wire.hex(),wall_before=wall_before,mono_before=mono_before,
                    wall_after=time.time_ns(),mono_after=time.monotonic_ns())
                row['responses_received']+=1;row['frames'].append(frame)
                create(target/('frame-'+str(index)+'.json'),J(frame))
                snapshot(target/('frame-'+str(index)+'-filesystem.json'),state,False)
                update(row)
                assert frame['response']['id']==index
                if tool is not None:
                    result=frame['response']['result']
                    assert result['isError']is (not success),(label,frame['response'])
                row['responses_validated']+=1;update(row)
                return frame['response']
            def boundary(label):
                value=snapshot(target/('boundary-'+label+'.json'),state,True)
                row['boundaries'][label]=value;update(row)
                return value
            call(None,None,'initialize')
            call(case['operation']['tool'],case['operation']['arguments'],'baseline')
            boundary('baseline')
            arguments=dict(operation=case['operation'],idempotency_key=case['key'])
            response=call('request_start',arguments,'start',case['success'])
            if case['fence']is not None:
                lock=common/'fence/.owner.lock'
                with lock.open('r+b')as held:
                    fcntl.flock(held.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
                    fcntl.flock(held.fileno(),fcntl.LOCK_UN)
                create(target/'fence-release-observed.json',J(dict(actual_nonblocking_exclusive_lock=True,
                    lock=str(lock),after_response_index=len(row['frames'])-1,monotonic_ns=time.monotonic_ns())))
            if case['success']:
                body=q.checked_json(response['result']['content'][0]['text'].encode())
                identifier=body['request_id'];assert q.valid_id(identifier)and body['reused']is False
                row['successful_starts']+=1
                deadline=time.monotonic()+30;witness=[]
                outcome=state/'request-async-v9/.outcomes'/(identifier+'.json')
                while True:
                    assert time.monotonic()<deadline,'producer completion observation deadline'
                    assert child.poll()is None,'producer process exited during observation'
                    stamp=dict(monotonic_ns=time.monotonic_ns(),path=str(outcome))
                    try:
                        raw=outcome.read_bytes();info=outcome.stat()
                        stamp.update(hex=raw.hex(),sha256=q.H(raw),device=info.st_dev,inode=info.st_ino,
                                     mode=stat.S_IMODE(info.st_mode),bytes=len(raw))
                        value=q.checked_json(raw)
                        assert value['request_id']==identifier
                        witness.append(stamp)
                        if value['state']=='completed':break
                        raise AssertionError(('unexpected producer outcome',value))
                    except FileNotFoundError:stamp['absent']=True;witness.append(stamp)
                    time.sleep(0.005)
                create(target/'completion-observations.json',J(witness))
                boundary('producer-completed')
                response=call('request_start',arguments,'reuse')
                reuse=q.checked_json(response['result']['content'][0]['text'].encode())
                assert reuse['request_id']==identifier and reuse['reused']is True and reuse['async_state']=='completed'
                boundary('reuse')
                different=dict(tool='effective_config'if case['operation']['tool']=='host_list'else'host_list',arguments={})
                call('request_start',dict(operation=different,idempotency_key=case['key']),'key-conflict',False)
                boundary('key-conflict')
                response=call('request_status',dict(request_id=identifier),'status')
                status=q.checked_json(response['result']['content'][0]['text'].encode())
                assert status['async_state']=='completed'and status['owned_future_active']is False
                assert status['result_state']==case['expected_result']
                boundary('status')
                call('request_result',dict(request_id=identifier),'result',case['expected_result']=='stored')
                boundary('result')
                call('request_cancel',dict(request_id=identifier),'cancel')
                boundary('cancel')
            else:
                boundary('refused')
                call('request_cancel',dict(request_id='f'*64),'cancel-missing-binding',False)
                boundary('cancel-missing-binding')
            call('host_list',{},'recovery')
            boundary('recovery')
            child.stdin.close();row['eof_sent_monotonic_ns']=time.monotonic_ns()
            child.wait(timeout=30)
            while True:
                extra=os.read(child.stdout.fileno(),65536)
                if not extra:break
                sout.write(extra);sout.flush();buffer+=extra
            assert child.returncode==0 and not buffer,('EOF result',child.returncode,buffer.hex())
            assert(target/'stderr').read_bytes()==b''
            row.update(exit_code=0,reaped=True,full_capture=True,eof_completed_monotonic_ns=time.monotonic_ns())
        assert (target/'input.bin').read_bytes()==b''.join(bytes.fromhex(f['raw_input_hex'])for f in row['frames'])
        assert (target/'stdout.bin').read_bytes()==b''.join(bytes.fromhex(f['raw_output_hex'])for f in row['frames'])
        for f in row['frames']:assert json.loads((target/('frame-'+str(f['index'])+'.json')).read_bytes())==f
        after_fences={p.name:q.capture_tree(p,True)for p in fence_paths}
        create(target/'fence-after.json',J(after_fences))
        assert before_fences==after_fences,'configured authority files/identities changed'
        row['final']=snapshot(target/'eof-filesystem.json',state,True)
        projected,observations=q.project_case(case,row['frames'],row['boundaries'],row['final'])
        create(target/'projection.json',J(projected));create(target/'scheduling-observations.json',J(observations))
        row['projection']=inputs.pin(target/'projection.json')
        row['scheduling_observations']=inputs.pin(target/'scheduling-observations.json')
        row['status']='PASS'
        os.rename(state,target/'final-state')
        for p in fence_paths:os.rename(p,target/('final-'+p.name))
        return projected,observations
    except BaseException as error:
        row.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        if child is not None:
            if child.poll()is None:child.kill();child.wait(timeout=3)
            row['exit_code']=child.returncode
            if child.stdout is not None and not child.stdout.closed:
                try:
                    remaining=child.stdout.read()
                    if remaining:
                        with(target/'stdout.bin').open('ab')as f:f.write(remaining)
                except (OSError,ValueError):pass
        for name in ('input.bin','stdout.bin','stderr'):
            p=target/name
            if p.exists():row[name]=inputs.pin(p)
        row['elapsed_seconds']=(time.monotonic_ns()-started)/1e9
        create(target/'result.json',J(row));update(row)
