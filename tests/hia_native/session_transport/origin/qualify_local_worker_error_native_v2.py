#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual LocalSessionWorkerError and WorkerResult Err ownership over typed HIA children."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,os,stat,struct,subprocess,sys,threading,time
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=D/'local-worker-error-native-v2'
BUILD_SHA='903900344b8840fd017dd09b51e288297081395bf1f614a6f921db7fc7ac41b9'
MACHINE_SHA='70e41e2b3a4f4ce42f91412c73e99bcc3c2abc9e78cc1e5923051bb57227ab2b'
CASES_SHA='ca169cb75b8283b9507680f4de838366f1a9ef554ad371e6c2df0c2ea353daf0'
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
Q=ctypes.c_uint64
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
word=lambda p,n=0:Q.from_address(p+n).value
PINS={}
def pin(path,digest=None):
    p=Path(path);s=p.lstat();assert stat.S_ISREG(s.st_mode)and not p.is_symlink()and s.st_nlink==1
    raw=p.read_bytes();row=dict(bytes=len(raw),sha256=SHA(raw),mode=stat.S_IMODE(s.st_mode))
    if digest is not None:assert row['sha256']==digest,(str(p),row)
    key=str(p.resolve());assert key not in PINS or PINS[key]==row;PINS[key]=row;return raw
def module(path,digest,name):
    pin(path,digest);spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def mapped(address):
    for line in Path('/proc/self/maps').read_text().splitlines():
        span,flags,*_=line.split();a,b=(int(x,16)for x in span.split('-'))
        if a<=address<b:return flags
    return None
def guard_maps():
    return [line.split()[:2]for line in Path('/proc/self/maps').read_text().splitlines()if line.split()[1].startswith('---')]
def child(mode):
    assert mode in(1,2);os.umask(0o077);folder=OUT/('mode-'+str(mode));folder.mkdir(mode=0o700)
    report=dict(schema='hepta.local-worker-error.native-child.v2',status='RUNNING',mode=mode,pid=os.getpid(),tid=threading.get_native_id(),
        actual_cases=0,actual_poll_task_selections=0,actual_error_factories=0,actual_error_owner_hia_entries=0,actual_error_child_views=0,actual_error_value_creates=0,
        actual_client_message_factories=0,actual_client_message_hia_entries=0,actual_session_error_factories=0,
        actual_explicit_value_creates=0,actual_explicit_value_drops=0,actual_oneshot_channels=0,actual_oneshot_calls=0,
        actual_owned_reply_sends=0,actual_worker_result_takes=0,actual_typed_callbacks=0,actual_typed_hia_entries=0,actual_typed_effects=0,
        actual_waker_clones=0,actual_waker_drops=0,actual_consuming_wakes=0,actual_wakes_by_ref=0,historical_address_reuses=0,
        capacity_refusals=0,wrong_type_refusals=0,actual_original_executions=0,actual_probe_creations=0,
        original_compared=False,full_worker=False,full_error_formatting=False,actual_join_error=False,production_activated=False)
    tm=module(D/'local_worker_error_machine_v1.py',MACHINE_SHA,'worker_transport_machine')
    corpus=module(D/'session_error_corpus_v1.py','9e769bcb9422f2613c2cab6ba088a11d6f9c6298640ba0fc71477d99efc611cc','error_corpus')
    decoder=module(D/'qualify_session_error_project_pairs_v2.py','1b7a5bb22d7b4a28d349ea925f512c89789ab89880a047e7583a3eb5e788633b','error_decoder')
    checked_shapes=set()
    machine=tm.Machine(folder,report,BUILD_SHA);journal=(folder/'resources.jsonl').open('xb',buffering=0);canonical=[];started=time.monotonic()
    cases=json.loads(pin(D/'local-worker-error-cases-v1.json',CASES_SHA))
    def log(row):journal.write((json.dumps(row,sort_keys=True,ensure_ascii=False)+'\n').encode())
    try:
        for cid,case in enumerate(cases,1):
            report['phase']=cid;report['frames']=cid;fd_before=set(os.listdir('/proc/self/fd'));guards_before=guard_maps()
            sc=machine.call('cooperative_scheduler_create',cid,mode);assert sc
            typed_data=(Q*(6*1024))();typed=(Q*4)(int.from_bytes(b'HRTDO001','little'),ctypes.addressof(typed_data),1024,0)
            waker_data=(Q*(2*1024))();observer=(Q*4)(int.from_bytes(b'HROBS001','little'),ctypes.addressof(waker_data),1024,0)
            assert machine.call('typed_drop_observer_attach',sc,ctypes.addressof(typed))==0
            assert machine.call('batch_observer_attach',sc,ctypes.addressof(observer))==0
            cookies=[(Q*1)(cid*4+i)for i in range(2)];cells=[machine.call('cooperative_scheduler_register',sc,ctypes.addressof(x),0)for x in cookies]
            assert all(cells)and cells[0]!=cells[1]
            active=0
            for _ in range(8):
                active=machine.call('cooperative_scheduler_next',sc)
                if active:assert active in cells;break
                assert word(sc,200)==2
            else:raise AssertionError('no scheduler task')
            serial=0;leases=[];contexts=[];rows=[];seen=0
            def gen():
                nonlocal serial
                serial+=1;assert serial<256;return cid*256+serial
            def record(address,role,payload=None,entry=None):
                span=machine.call('value_lease_span',address);actual=ctypes.string_at(span.pointer,span.size)
                if payload is not None:assert actual==payload
                if entry is not None:assert word(address,32)==machine.base+machine.exports[entry]
                assert word(address,40)==sc and 'w'not in mapped(address)and'w'not in mapped(span.pointer)
                row=dict(address=address,payload=span.pointer,size=span.size,role=role,descriptor_hex=ctypes.string_at(address,80).hex(),payload_hex=actual.hex())
                leases.append(row);log(dict(case=cid,event='LEASE_OBSERVED',**row));return actual
            def lease(payload,entry,role):
                source=ctypes.create_string_buffer(payload,len(payload));g=gen()
                address=machine.call('value_lease_create',ctypes.addressof(source),len(payload),g,machine.base+machine.exports[entry],sc);assert address
                assert source.raw==payload;record(address,role,payload,entry);report['actual_explicit_value_creates']+=1;return address
            def drop(address):
                log(dict(case=cid,event='DROP_ENTER',address=address));assert machine.call('value_lease_drop',address)==0
                report['actual_explicit_value_drops']+=1;log(dict(case=cid,event='DROP_RETURN',address=address))
            def row(step,result=None):
                nonlocal seen
                n=int(observer[3]);events=[]
                for index in range(seen,n):
                    kind=int(waker_data[index*2]);cell=int(waker_data[index*2+1]);assert cell in cells
                    label={1:'clone',2:'drop',3:'wake_by_ref',4:'wake'}[kind]
                    events.append(dict(kind=label,waker=cells.index(cell)))
                    counter={1:'actual_waker_clones',2:'actual_waker_drops',3:'actual_wakes_by_ref',4:'actual_consuming_wakes'}[kind]
                    report[counter]+=1
                seen=n;rows.append(dict(step=step,result=result,events=events));log(dict(case=cid,event='CANONICAL_STEP',**rows[-1]))
            event_rx=0;event_tx=0;message=0;child_value=0;reply_rx=0
            def pair(label):
                generation=gen();context=machine.call('oneshot_create',sc,generation,ctypes.addressof(observer));assert context
                contexts.append(dict(context=context,workspace=word(context,16),kind=label));report['actual_oneshot_channels']+=1
                sender=lease(b'HROHL001'+struct.pack('<3Q',1,context,generation),'owned_oneshot_handle_drop_entry',label+'.tx')
                receiver=lease(b'HROHL001'+struct.pack('<3Q',2,context,generation),'owned_oneshot_handle_drop_entry',label+'.rx')
                return context,generation,sender,receiver
            def select_poll_task(waker):
                # A real poll is bound to the real current SC task. The fixture
                # explicitly schedules its logical poll target; no state writes
                # or substitute Waker callbacks are used to bypass this binding.
                nonlocal active
                target=cells[waker];assert word(sc,96)==active
                if active!=target:
                    assert machine.call('cooperative_scheduler_finish',sc,active,0)==0
                    active=0
                    assert machine.call('cooperative_scheduler_notify',target,0,1)==0
                    for _ in range(64):
                        selected=machine.call('cooperative_scheduler_next',sc)
                        if selected:
                            assert selected in cells
                            if selected==target:
                                active=selected;break
                            assert machine.call('cooperative_scheduler_finish',sc,selected,0)==0
                        else:assert word(sc,200)==2
                    else:raise AssertionError('poll task was not selected')
                    report['actual_poll_task_selections']+=1
                assert active==target and word(sc,96)==target
                log(dict(case=cid,event='SELECT_POLL_TASK',waker=waker,cell=target,current=word(sc,96)))
            def opoll(context,generation,waker):
                select_poll_task(waker)
                frame=b'HRONQ001'+struct.pack('<9Q',4,generation,0,cells[waker],0,0,0,0,0)
                source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*80)()
                code=machine.call('oneshot_call',context,ctypes.addressof(source),80,ctypes.addressof(answer),80);out=bytes(answer)
                assert code==80 and out[:8]==b'HRONR001'and U(out,16)==generation and source.raw==frame
                report['actual_oneshot_calls']+=1;log(dict(case=cid,event='ONESHOT_CALL',context=context,waker=waker,input_hex=frame.hex(),output_hex=out.hex(),code=code));return out
            def client_wire(address):
                payload=record(address,'client_message_view',entry='client_message_drop_entry');assert payload[:8]==b'HRCMV001'
                projection=payload[32:];assert projection[:8]==b'HRCMO001'and U(payload,16)==len(projection)
                at=U(projection,224);size=U(projection,232);assert at>=256 and at+size<=len(projection)
                return projection[at:at+size].decode()
            def make_client(raw):
                raw=raw.encode();g=gen();frame=b'HRCMQ001'+struct.pack('<7Q',2,len(raw),sc,g,0,0,0)+raw
                source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*64)();counts=(Q*4)()
                code=machine.call('client_message_call',ctypes.addressof(source),len(frame),ctypes.addressof(answer),64,ctypes.addressof(counts));out=bytes(answer)
                assert code==64 and out[:8]==b'HRCMR001'and source.raw==frame
                report['actual_client_message_factories']+=1;report['actual_client_message_hia_entries']+=sum(counts[:3])
                log(dict(case=cid,event='CLIENT_MESSAGE_FACTORY',input_hex=frame.hex(),output_hex=out.hex(),counts=list(counts)))
                address=U(out,16);client_wire(address);return address
            def child_shape(address):
                if not address:return None
                payload=record(address,'local_error_child_view')
                if payload[:8]==b'HRSERV01':
                    assert word(address,32)==machine.base+machine.exports['session_error_drop_entry']and U(payload,24)==1
                    projection=decoder.decode(payload[32:],corpus.KIND_NAMES)
                    return dict(type='session_error',display=projection['display'])
                assert payload[:8]==b'HRSVE001'and len(payload)==128 and word(address,32)==machine.base+machine.exports['session_event_drop_entry']
                return dict(type='session_event',tag=U(payload,8),http_request_id=U(payload,40)if U(payload,32)else None,index=U(payload,48),
                    retry=dict(seconds=U(payload,64),nanos=U(payload,72))if U(payload,56)else None,
                    wire=client_wire(U(payload,16))if U(payload,16)else None,responder_present=bool(U(payload,24)))
            spec=case['child']
            if spec is not None:
                if spec['kind']=='session_error':
                    raw=corpus.frame(spec['value']);g=gen();frame=b'HRSEMQ01'+struct.pack('<7Q',2,len(raw),sc,g,0,0,0)+raw
                    source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*64)();counts=(Q*4)()
                    code=machine.call('session_error_call',ctypes.addressof(source),len(frame),ctypes.addressof(answer),64,ctypes.addressof(counts));out=bytes(answer)
                    assert code==64 and out[:8]==b'HRSEMR01'and source.raw==frame
                    child_value=U(out,8);record(child_value,'session_error_child',entry='session_error_drop_entry');report['actual_session_error_factories']+=1
                    log(dict(case=cid,event='SESSION_ERROR_FACTORY',input_hex=frame.hex(),output_hex=out.hex(),counts=list(counts)))
                else:
                    assert spec['kind']=='session_event';tag=spec['tag']
                    if spec['message_json']is not None:message=make_client(spec['message_json'])
                    if tag not in(1,6):event_context,event_generation,event_tx,event_rx=pair('event.reply')
                    http=spec['http_request_id'];retry=spec['retry']
                    payload=b'HRSVE001'+struct.pack('<15Q',tag,message,event_tx,int(http is not None),http or 0,spec['index'],
                        int(retry is not None),retry['seconds']if retry else 0,retry['nanos']if retry else 0,0,0,0,0,0,0)
                    child_value=lease(payload,'session_event_drop_entry','event_child')
            observed_child=child_shape(child_value);row('construct_child',observed_child)
            if event_rx:
                out=opoll(event_context,event_generation,1);assert U(out,8)==3;row('poll_event_reply_before','pending')
            generation=gen();frame=b'HRLWQ001'+struct.pack('<7Q',case['variant'],sc,generation,child_value,case['seconds'],case['nanos'],0)
            source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*80)();counts=(Q*3)()
            def create_error(raw,capacity=64):
                source=ctypes.create_string_buffer(raw,len(raw));ctypes.memset(answer,169,80);ctypes.memset(counts,0,24)
                code=machine.call('local_worker_error_create',ctypes.addressof(source),len(raw),ctypes.addressof(answer),capacity,ctypes.addressof(counts))
                out=bytes(answer);assert source.raw==raw
                report['actual_error_owner_hia_entries']+=counts[0];report['actual_error_child_views']+=counts[1];report['actual_error_value_creates']+=counts[2]
                log(dict(case=cid,event='LOCAL_ERROR_FACTORY',input_hex=raw.hex(),output_hex=out.hex(),capacity=capacity,code=code,counts=list(counts)))
                return code,out
            shape=0 if spec is None else 1 if spec['kind']=='session_event'else 2
            if shape not in checked_shapes:
                for capacity in(0,63):
                    code,out=create_error(frame,capacity);assert code==0xfffffffe and out==b'\xa9'*80 and list(counts)==[1,0,0]
                    report['capacity_refusals']+=1
                if shape:
                    bad=bytearray(frame);struct.pack_into('<Q',bad,8,3 if shape==1 else 2)
                    code,out=create_error(bytes(bad));assert code==0xffffffff and out==b'\xa9'*80 and list(counts)==[2,1,0]
                    assert child_shape(child_value)==observed_child;report['wrong_type_refusals']+=1
                checked_shapes.add(shape)
            code,out=create_error(frame)
            assert code==64 and out[:8]==b'HRLWR001'and out[64:]==b'\xa9'*16 and list(counts)==([3,1,1]if child_value else[2,0,1])
            error=U(out,8);expected=b'HRLWE001'+struct.pack('<5Q',case['variant'],child_value,case['seconds'],case['nanos'],0)
            error_payload=record(error,'local_worker_error',expected,'local_worker_error_drop_entry');report['actual_error_factories']+=1
            assert U(out,16)==case['variant']and U(out,24)==child_value and U(out,32)==case['seconds']and U(out,40)==case['nanos']and U(out,48)==generation and U(out,56)==0
            log(dict(case=cid,event='LOCAL_ERROR_DROP_INPUT',input_hex=(b'HRTDQ001'+struct.pack('<7Q',error,word(error,8),sc,48,0,0,0)+error_payload).hex()))
            def error_shape(address):
                payload=record(address,'local_worker_error_view',entry='local_worker_error_drop_entry');assert len(payload)==48 and payload[:8]==b'HRLWE001'and U(payload,40)==0
                return dict(variant=U(payload,8),seconds=U(payload,24),nanos=U(payload,32),child=child_shape(U(payload,16)))
            observed_error=error_shape(error);row('construct_error',observed_error);route=case['route'];worker_result=0
            if route=='direct_drop':drop(error);row('drop_error')
            else:
                reply_context,reply_generation,reply_tx,reply_rx=pair('worker.reply')
                out=opoll(reply_context,reply_generation,0);assert U(out,8)==3;row('poll_result_before','pending')
                if route=='closed_send':drop(reply_rx);reply_rx=0;row('drop_result_rx_before')
                result_payload=b'HRWRV001'+struct.pack('<3Q',1,1,error)
                worker_result=lease(result_payload,'worker_result_drop_entry','worker_result.error');row('construct_result',dict(status='error'))
                sent=(ctypes.c_ubyte*80)();assert machine.call('owned_oneshot_send',reply_tx,worker_result,ctypes.addressof(sent),80)==80
                out=bytes(sent);assert out[:8]==b'HROSNR01'and U(out,8)in(1,2);report['actual_owned_reply_sends']+=1
                log(dict(case=cid,event='REPLY_SEND',result=worker_result,output_hex=out.hex()));delivery='sent'if U(out,8)==1 else'closed';row('send_result',delivery)
                if route=='closed_send':assert delivery=='closed'and U(out,24)==worker_result;drop(worker_result);row('drop_rejected_result')
                else:
                    assert delivery=='sent'and U(out,24)==0
                    if route=='buffered_cancel':drop(reply_rx);reply_rx=0;row('drop_buffered_result_rx')
                    else:
                        out=opoll(reply_context,reply_generation,0);assert U(out,8)==4 and U(out,24)==worker_result
                        received=record(worker_result,'received_worker_result',result_payload,'worker_result_drop_entry');assert U(received,16)==1
                        actual_error=U(received,24);shape_after=error_shape(actual_error);assert actual_error==error and shape_after==observed_error
                        row('poll_result_after',dict(status='error',error=shape_after))
                        if route=='reply_drop':drop(worker_result);row('drop_result')
                        else:
                            assert route=='reply_take';taken=(ctypes.c_ubyte*80)();ctypes.memset(taken,169,80)
                            assert machine.call('worker_result_take',worker_result,ctypes.addressof(taken),64)==64
                            out=bytes(taken);assert out[:8]==b'HRWRFR01'and U(out,16)==worker_result and U(out,24)==32 and out[32:64]==result_payload and out[64:]==b'\xa9'*16
                            report['actual_worker_result_takes']+=1;log(dict(case=cid,event='WORKER_RESULT_TAKE',output_hex=out[:64].hex()))
                            moved=U(out,56);shape_after=error_shape(moved);assert moved==error and shape_after==observed_error
                            row('take_result',dict(error=shape_after));drop(moved);row('drop_error')
                        drop(reply_rx);reply_rx=0;row('drop_result_rx_after')
            if event_rx:
                out=opoll(event_context,event_generation,1);assert U(out,8)==5;row('poll_event_reply_after','closed')
                drop(event_rx);event_rx=0;row('drop_event_reply_after')
            assert seen==int(observer[3])
            # Tasks that the fixture left Pending must be scheduled once more
            # to retire them through the actual completed-task path.
            for cell in cells:
                if cell!=active:assert machine.call('cooperative_scheduler_notify',cell,0,1)==0
            assert machine.call('cooperative_scheduler_finish',sc,active,1)==0
            for _ in range(64):
                selected=machine.call('cooperative_scheduler_next',sc)
                if selected:assert selected in cells;assert machine.call('cooperative_scheduler_finish',sc,selected,1)==0
                elif word(sc,200)==1:break
                else:assert word(sc,200)==2
            else:raise AssertionError('scheduler failed to quiesce')
            for cell in cells:assert word(cell,32)==1 and machine.call('cooperative_scheduler_retire',cell)==0 and not mapped(cell)
            # Every native arena has guard pages. Check their exact baseline after
            # SC retirement; Python may reuse already-unmapped historical addresses.
            def retired(address,role):
                flags=mapped(address)
                if flags is not None:
                    assert 'w'in flags,(cid,role,address,flags,Path('/proc/self/maps').read_text())
                    report['historical_address_reuses']+=1
                    log(dict(case=cid,event='RETIRED_ADDRESS_REUSED',address=address,role=role,new_flags=flags))
            typed_raw=ctypes.string_at(ctypes.addressof(typed_data),int(typed[3])*48)
            (folder/('case-'+str(cid)+'.typed.bin')).write_bytes(typed_raw);stack=[];local_drops=[];result_terminals=[];child_drops=[];message_drops=[]
            for stage,tag,descriptor,arena,hias,effects in struct.iter_unpack('<6Q',typed_raw):
                if stage==1:
                    assert hias==effects==0;stack.append((tag,descriptor,arena));report['actual_typed_callbacks']+=1
                    if tag==16:local_drops.append(descriptor)
                    if tag in(14,15):result_terminals.append((tag,descriptor))
                    if tag in(2,8)and descriptor==child_value:child_drops.append(descriptor)
                    if tag==10:message_drops.append(descriptor)
                else:
                    assert stage==2 and stack.pop()==(tag,descriptor,arena)and hias==effects+1
                    retired(arena,'typed_callback_arena')
                    if tag==16:assert effects==int(bool(child_value))
                    if tag==14 or tag==15:assert hias==2 and effects==1
                    report['actual_typed_hia_entries']+=hias;report['actual_typed_effects']+=effects
            assert not stack and local_drops==[error]and child_drops==([child_value]if child_value else[])and message_drops==([message]if message else[])
            assert result_terminals==([(15 if route=='reply_take'else 14,worker_result)]if worker_result else[])
            waker_raw=ctypes.string_at(ctypes.addressof(waker_data),int(observer[3])*16);(folder/('case-'+str(cid)+'.wakers.bin')).write_bytes(waker_raw)
            assert machine.call('typed_drop_observer_attach',sc,0)==0 and machine.call('batch_observer_attach',sc,0)==0
            assert machine.call('cooperative_scheduler_destroy',sc)==0 and not mapped(sc)
            assert guard_maps()==guards_before,(cid,guards_before,guard_maps())
            for item in leases:
                retired(item['address'],item['role']+'.descriptor');retired(item['payload'],item['role']+'.payload')
            for item in contexts:
                retired(item['context'],item['kind']+'.context');retired(item['workspace'],item['kind']+'.initial_workspace')
                if 'semaphore'in item:retired(item['semaphore'],'semaphore.context')
            assert set(os.listdir('/proc/self/fd'))==fd_before
            log(dict(case=cid,event='ALL_RELEASED',fd_sets_balanced=True,all_native_guarded_allocations_retired=True))
            canonical.append(dict(name=case['name'],rows=rows));report['actual_cases']+=1
        assert checked_shapes=={0,1,2}
        report.update(status='PASS_FINITE_NATIVE_LOCAL_WORKER_ERROR_OWNERS',all_native_guarded_allocations_retired=True,all_fd_sets_balanced=True,all_inputs_unchanged=True,owned_variants=[1,2,3,4,5,6])
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        journal.flush();os.fsync(journal.fileno());journal.close();machine.close();report['elapsed_seconds']=time.monotonic()-started
        (folder/'canonical.json').write_bytes(J(canonical));(folder/'result.json').write_bytes(J(report));print(json.dumps(report,sort_keys=True))
def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',type=int);a=p.parse_args()
    if a.mode is not None:return child(a.mode)
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);started=time.monotonic();processes=[]
    report=dict(schema='hepta.local-worker-error.native.v2',status='RUNNING',actual_native_processes=0,actual_original_executions=0,
        original_compared=False,full_worker=False,local_worker_error_owned=True,full_error_formatting=False,actual_join_error=False,registration_some=False,production_activated=False,whole_runtime_replaced=False)
    try:
        before=pin(__file__);pin(D/'local_worker_error_machine_v1.py',MACHINE_SHA)
        pin(D/'session_error_corpus_v1.py','9e769bcb9422f2613c2cab6ba088a11d6f9c6298640ba0fc71477d99efc611cc')
        pin(D/'qualify_session_error_project_pairs_v2.py','1b7a5bb22d7b4a28d349ea925f512c89789ab89880a047e7583a3eb5e788633b')
        source=pin(D/'local-worker-error-cases-v1.json',CASES_SHA);assert len(json.loads(source))==140;(OUT/'cases.json').write_bytes(source)
        pin(D/'LOCAL-WORKER-ERROR-PAIR-PROTOCOL-v1.md','920c34397676b4f6ec5a0ed4003b0bed23aed1c27097aeacf34612ee58923900')
        build=json.loads(pin(D/'local-worker-error-callable-build-v1/result.json',BUILD_SHA));assert build['semantic_images']==38 and build['unchanged_parent_semantic_images']==36
        assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'
        for path,row in build['source_pins'].items():pin(path,row['sha256'])
        pin(build['artifact']['path'],build['artifact']['sha256'])
        e=json.loads(pin(D/'local-worker-error-callable-build-v1.external.json','312a647f6c28f3f878a60b997c0e0731630deff25d28ed1e61802c6d3ffdcbb4'))
        st=e['status'];assert st['job_id']=='1a1eb7fa82d-392-432b'and st['state']=='succeeded'and st['exit_code']==0
        assert st['output_complete']and st['output_durable']and st['terminal_publication_confirmed']and not st['timed_out']and not st['cancelled']and not st['automatic_retry']
        assert e['read']['stdout']['eof']and e['read']['stderr']['eof']and not e['read']['stderr']['text']
        children=[];canonical=[]
        for mode in(1,2):
            command=['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--mode',str(mode)]
            process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'','LANG':'C'},cwd=OUT)
            report['actual_native_processes']+=1;begun=time.monotonic();timed=False
            try:out,err=process.communicate(timeout=60)
            except subprocess.TimeoutExpired:timed=True;process.kill();out,err=process.communicate(timeout=10)
            (OUT/('mode-'+str(mode)+'.stdout')).write_bytes(out);(OUT/('mode-'+str(mode)+'.stderr')).write_bytes(err)
            row=dict(mode=mode,pid=process.pid,command=command,exit_code=process.returncode,timed_out=timed,elapsed_seconds=time.monotonic()-begun,
                stdout_bytes=len(out),stdout_sha256=SHA(out),stderr_bytes=len(err),stderr_sha256=SHA(err))
            processes.append(row);(OUT/'processes.json').write_bytes(J(processes));assert process.returncode==0 and not timed and not err,row
            observed=json.loads((OUT/('mode-'+str(mode))/'result.json').read_bytes());assert observed==json.loads(out)
            assert observed['status']=='PASS_FINITE_NATIVE_LOCAL_WORKER_ERROR_OWNERS'and observed['actual_cases']==140 and observed['pid']==process.pid
            children.append(observed);canonical.append((OUT/('mode-'+str(mode))/'canonical.json').read_bytes())
        assert canonical[0]==canonical[1]and pin(__file__)==before
        for path,row in list(PINS.items()):pin(path,row['sha256'])
        report.update(status='PASS_FINITE_NATIVE_LOCAL_WORKER_ERROR_OWNERS',actual_cases_per_mode=140,native_modes_equal=True,
            native_per_mode={k:v for k,v in children[0].items()if k.startswith('actual_')or k.endswith('_refusals')},creator_thread_only=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started;report['processes']=processes;report['source_pins']=PINS
        report['retained_files']={str(p.relative_to(OUT)):dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes()))for p in sorted(OUT.rglob('*'))if p.is_file()}
        (OUT/'result.json').write_bytes(J(report));print(json.dumps({k:v for k,v in report.items()if k not in('processes','source_pins','retained_files')},sort_keys=True))
if __name__=='__main__':main()
