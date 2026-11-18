#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual typed Worker request/result ownership over HIA ServerMessage and channels."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,os,stat,struct,subprocess,sys,threading,time
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=D/'worker-transport-owners-native-v2'
BUILD_SHA='8d40289b3693f243c4ddc5b5513e8aada36f89859360c0c76f653a1cf791b9fe'
MACHINE_SHA='f35cc2f1efb0fe8772f63d935e9691600f4f20315247fa65797d379ae69aef0f'
CASES_SHA='906e67f5cf10feee565ede0846f8af7c0618ab331fd37e9999236144068d6f0d'
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
    report=dict(schema='hepta.worker-transport-owners.native-child.v1',status='RUNNING',mode=mode,pid=os.getpid(),tid=threading.get_native_id(),
        actual_cases=0,actual_server_message_factories=0,actual_server_message_hia_entries=0,
        actual_explicit_value_creates=0,actual_explicit_value_drops=0,actual_oneshot_channels=0,actual_oneshot_calls=0,
        actual_mpsc_channels=0,actual_mpsc_calls=0,actual_owned_reply_sends=0,actual_request_takes=0,actual_result_takes=0,
        actual_typed_callbacks=0,actual_typed_hia_entries=0,actual_typed_effects=0,actual_waker_clones=0,actual_waker_drops=0,
        actual_consuming_wakes=0,actual_wakes_by_ref=0,historical_address_reuses=0,capacity_refusals=0,wrong_type_refusals=0,
        actual_original_executions=0,actual_probe_creations=0,original_compared=False,full_worker=False,production_activated=False)
    tm=module(D/'worker_transport_owners_machine_v2.py',MACHINE_SHA,'worker_transport_machine')
    machine=tm.Machine(folder,report,BUILD_SHA);journal=(folder/'resources.jsonl').open('xb',buffering=0);canonical=[];started=time.monotonic()
    cases=json.loads(pin(D/'worker-owner-cases-v1.json',CASES_SHA))
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
            serial=0;leases=[];contexts=[];rows=[];seen=0;reply_rx=0;queue=None;queue_rx_live=False;recv_future=0
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
            raw=case['message_json'].encode();g=gen()
            frame=b'HSSMQ001'+struct.pack('<11Q',1,2,0,0,len(raw),0,0,sc,g,0,0)+raw
            source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*64)();counts=(Q*6)()
            code=machine.call('server_message_call',ctypes.addressof(source),len(frame),ctypes.addressof(answer),64,ctypes.addressof(counts))
            response=bytes(answer);assert code==64 and response[:8]==b'HSSMR001'and source.raw==frame and counts[4]==1 and counts[5]==0
            message=U(response,24);payload=record(message,'server_message',entry='server_message_drop_entry');assert payload[:8]==b'HSSMV001'
            projection=payload[32:];assert projection[:8]==b'HSSMP001'and len(projection)==U(payload,8)
            assert U(projection,32)==128 and len(projection)==128+U(projection,24)
            wire=projection[128:].decode();report['actual_server_message_factories']+=1;report['actual_server_message_hia_entries']+=sum(counts[:4])
            log(dict(case=cid,event='SERVER_MESSAGE_FACTORY',input_hex=frame.hex(),output_hex=response.hex(),counts=list(counts)))
            og=gen();oc=machine.call('oneshot_create',sc,og,ctypes.addressof(observer));assert oc;contexts.append(dict(context=oc,workspace=word(oc,16),kind='oneshot'))
            report['actual_oneshot_channels']+=1
            reply_tx=lease(b'HROHL001'+struct.pack('<3Q',1,oc,og),'owned_oneshot_handle_drop_entry','reply.tx')
            reply_rx=lease(b'HROHL001'+struct.pack('<3Q',2,oc,og),'owned_oneshot_handle_drop_entry','reply.rx')
            request_payload=b'HRSWR001'+struct.pack('<5Q',message,reply_tx,0,case['control_generation'],0)
            request=lease(request_payload,'worker_send_request_drop_entry','worker_request')
            log(dict(case=cid,event='WORKER_POLICY_INPUT',policy='drop_or_take',descriptor=request,
                input_hex=(b'HRTDQ001'+struct.pack('<7Q',request,word(request,8),sc,48,0,0,0)+request_payload).hex()))
            observed_fields=dict(control_generation=U(request_payload,32),cancellation_none=U(request_payload,24)==0,wire=wire)
            row('construct',observed_fields)
            def opoll():
                frame=b'HRONQ001'+struct.pack('<9Q',4,og,0,cells[0],0,0,0,0,0)
                source=ctypes.create_string_buffer(frame,len(frame));out=(ctypes.c_ubyte*80)()
                code=machine.call('oneshot_call',oc,ctypes.addressof(source),80,ctypes.addressof(out),80);got=bytes(out)
                assert code==80 and got[:8]==b'HRONR001'and U(got,16)==og and source.raw==frame
                report['actual_oneshot_calls']+=1;log(dict(case=cid,event='ONESHOT_CALL',input_hex=frame.hex(),output_hex=got.hex(),code=code));return got
            if case['receiver']=='closed':drop(reply_rx);reply_rx=0;row('reply_drop_before')
            elif case['poll_receiver']:
                got=opoll();assert U(got,8)==3;row('reply_poll_before','pending')
            def mcall(op,token=0,value=0):
                frame=b'HRCMUQ01'+struct.pack('<11Q',op,queue['generation'],token,value,cells[1]if op in(5,8)else 0,0,0,0,0,0,0)
                source=ctypes.create_string_buffer(frame,len(frame));out=(ctypes.c_ubyte*128)()
                code=machine.call('bounded_mpsc_call',queue['context'],ctypes.addressof(source),96,ctypes.addressof(out),128);got=bytes(out)
                assert code==128 and got[:8]==b'HRCMUR01'and U(got,16)==queue['generation']and U(got,24)==op and source.raw==frame
                report['actual_mpsc_calls']+=1;log(dict(case=cid,event='MPSC_CALL',input_hex=frame.hex(),output_hex=got.hex(),code=code));return got
            route=case['route']
            if route!='direct':
                mg=gen();mc=machine.call('bounded_mpsc_create',sc,mg,case['channel_capacity'],machine.call('channel_waker_observer_table'),sc);assert mc
                initial=ctypes.string_at(mc+256,128);assert initial[:8]==b'HRCMUR01'and U(initial,8)==0
                token=U(initial,32);qtx=lease(b'HROMH001'+struct.pack('<4Q',1,mc,mg,token),'owned_mpsc_handle_drop_entry','queue.tx')
                qrx=lease(b'HROMH001'+struct.pack('<4Q',2,mc,mg,0),'owned_mpsc_handle_drop_entry','queue.rx')
                queue=dict(context=mc,generation=mg,token=token,tx=qtx,rx=qrx);queue_rx_live=True
                contexts.append(dict(context=mc,workspace=word(mc,16),kind='mpsc',semaphore=word(mc,80)));report['actual_mpsc_channels']+=1
                log(dict(case=cid,event='MPSC_CREATE',initial_hex=initial.hex(),**queue))
                if route=='mpsc_closed':drop(qrx);queue_rx_live=False;row('queue_close_before')
                elif route=='mpsc'and case['poll_queue']:
                    recv_future=U(mcall(7),32);got=mcall(8,recv_future);assert U(got,8)==1;row('queue_poll_before','pending')
                send_future=U(mcall(4,token,request),32);got=mcall(5,send_future);status=U(got,8)
                assert status in(0,2);mcall(6,send_future)
                if status==2:assert U(got,40)==request
                else:assert U(got,40)==0
                row('send_queue','sent'if status==0 else'closed')
                if route=='mpsc':
                    assert status==0
                    if not recv_future:recv_future=U(mcall(7),32)
                    got=mcall(8,recv_future);assert U(got,8)==0 and U(got,40)==request;mcall(9,recv_future);recv_future=0
                    row('take_queue','request')
                elif route=='mpsc_drain':
                    assert status==0;drop(qrx);queue_rx_live=False;request=0;row('drop_queue_rx')
                else:assert status==2
            if request:
                if case['finish']=='drop':drop(request);request=0;row('drop_request')
                else:
                    assert case['finish']=='take_ok';out=(ctypes.c_ubyte*96)();ctypes.memset(out,169,96)
                    assert machine.call('worker_send_request_take',request,ctypes.addressof(out),79)==0xfffffffe and bytes(out)==b'\xa9'*96
                    report['capacity_refusals']+=1
                    assert machine.call('worker_result_take',request,ctypes.addressof(out),64)==0xffffffff and bytes(out)==b'\xa9'*96
                    report['wrong_type_refusals']+=1
                    assert machine.call('worker_send_request_take',request,ctypes.addressof(out),80)==80
                    got=bytes(out);assert got[:8]==b'HRSWFR01'and U(got,16)==request and U(got,24)==48 and got[32:80]==request_payload and got[80:]==b'\xa9'*16
                    assert not mapped(request);request=0;report['actual_request_takes']+=1
                    log(dict(case=cid,event='REQUEST_TAKE',output_hex=got[:80].hex()))
                    row('take_request',dict(control_generation=U(got,64),cancellation_none=U(got,56)==0,wire=wire))
                    drop(message);row('drop_message')
                    unit_payload=b'HRWRV001'+struct.pack('<3Q',1,0,0)
                    result=lease(unit_payload,'worker_result_drop_entry','worker_result.unit')
                    log(dict(case=cid,event='WORKER_POLICY_INPUT',policy='result_drop_or_take',descriptor=result,
                        input_hex=(b'HRTDQ001'+struct.pack('<7Q',result,word(result,8),sc,32,0,0,0)+unit_payload).hex()))
                    sent=(ctypes.c_ubyte*80)();assert machine.call('owned_oneshot_send',reply_tx,result,ctypes.addressof(sent),80)==80
                    got=bytes(sent);assert got[:8]==b'HROSNR01'and U(got,8)in(1,2);report['actual_owned_reply_sends']+=1
                    log(dict(case=cid,event='REPLY_SEND',result=result,output_hex=got.hex()))
                    if U(got,8)==2:assert U(got,24)==result;drop(result)
                    else:assert U(got,24)==0
                    row('send_reply','sent'if U(got,8)==1 else'closed')
            if reply_rx:
                got=opoll();assert U(got,8)in(4,5)
                row('reply_poll_after','ok'if U(got,8)==4 else'closed')
                if U(got,8)==4:
                    result=U(got,24);unit=record(result,'received_worker_result',entry='worker_result_drop_entry')
                    assert unit==b'HRWRV001'+struct.pack('<3Q',1,0,0)
                    if case['result_finish']=='take':
                        out=(ctypes.c_ubyte*80)();ctypes.memset(out,169,80)
                        assert machine.call('worker_result_take',result,ctypes.addressof(out),63)==0xfffffffe and bytes(out)==b'\xa9'*80
                        report['capacity_refusals']+=1
                        assert machine.call('worker_send_request_take',result,ctypes.addressof(out),80)==0xffffffff and bytes(out)==b'\xa9'*80
                        report['wrong_type_refusals']+=1
                        assert machine.call('worker_result_take',result,ctypes.addressof(out),64)==64
                        taken=bytes(out);assert taken[:8]==b'HRWRFR01'and U(taken,16)==result and U(taken,24)==32 and taken[32:64]==unit and taken[64:]==b'\xa9'*16
                        assert not mapped(result);report['actual_result_takes']+=1;log(dict(case=cid,event='RESULT_TAKE',output_hex=taken[:64].hex()));row('take_reply_value')
                    else:drop(result);row('drop_reply_value')
                drop(reply_rx);reply_rx=0;row('reply_drop_after')
            if queue:
                drop(queue['tx'])
                if queue_rx_live:drop(queue['rx']);queue_rx_live=False
                row('queue_cleanup')
            assert seen==int(observer[3])
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
            (folder/('case-'+str(cid)+'.typed.bin')).write_bytes(typed_raw);stack=[];seen_request=[];seen_result=[];message_drops=[]
            for stage,tag,descriptor,arena,hias,effects in struct.iter_unpack('<6Q',typed_raw):
                if stage==1:
                    assert hias==effects==0;stack.append((tag,descriptor,arena));report['actual_typed_callbacks']+=1
                    if tag in(11,13):seen_request.append(tag)
                    if tag in(14,15):seen_result.append(tag)
                    if tag==12:message_drops.append(descriptor)
                else:
                    assert stage==2 and stack.pop()==(tag,descriptor,arena)and hias==effects+1
                    retired(arena,'typed_callback_arena')
                    if tag==11:assert hias==3 and effects==2
                    if tag==13 or tag==15:assert hias==2 and effects==1
                    if tag==14 or tag==12:assert hias==1 and effects==0
                    report['actual_typed_hia_entries']+=hias;report['actual_typed_effects']+=effects
            assert not stack and len(seen_request)==1 and message_drops==[message]
            assert seen_request[0]==(13 if case['finish']=='take_ok'else 11)
            assert len(seen_result)==int(case['finish']=='take_ok')
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
        report.update(status='PASS_FINITE_NATIVE_WORKER_OWNERS',all_native_guarded_allocations_retired=True,all_fd_sets_balanced=True,all_inputs_unchanged=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        journal.flush();os.fsync(journal.fileno());journal.close();machine.close();report['elapsed_seconds']=time.monotonic()-started
        (folder/'canonical.json').write_bytes(J(canonical));(folder/'result.json').write_bytes(J(report));print(json.dumps(report,sort_keys=True))
def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',type=int);a=p.parse_args()
    if a.mode is not None:return child(a.mode)
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);started=time.monotonic();processes=[]
    report=dict(schema='hepta.worker-transport-owners.native.v1',status='RUNNING',actual_native_processes=0,actual_original_executions=0,
        original_compared=False,full_worker=False,local_worker_error=False,registration_some=False,production_activated=False,whole_runtime_replaced=False)
    try:
        before=pin(__file__);pin(D/'worker_transport_owners_machine_v2.py',MACHINE_SHA)
        source=pin(D/'worker-owner-cases-v1.json',CASES_SHA);assert len(json.loads(source))==72;(OUT/'cases.json').write_bytes(source)
        pin(D/'WORKER-OWNERS-PAIR-PROTOCOL-v1.md','22657952b76cf39dbe4eaffd364fc967efb8b0356d85458979427fb12b1b299f')
        build=json.loads(pin(D/'worker-transport-owners-callable-build-v3/result.json',BUILD_SHA));assert build['semantic_images']==32 and build['unchanged_parent_semantic_images']==23
        assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'
        for path,row in build['source_pins'].items():pin(path,row['sha256'])
        pin(build['artifact']['path'],build['artifact']['sha256'])
        e=json.loads(pin(D/'worker-transport-owners-callable-build-v3.external.json','0574573e6017ba940c967f44fb03876fa69c49ca1ba0472f0dca6abcfe670586'))
        st=e['status'];assert st['job_id']=='1a1eb5dc64e-392-4311'and st['state']=='succeeded'and st['exit_code']==0
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
            assert observed['status']=='PASS_FINITE_NATIVE_WORKER_OWNERS'and observed['actual_cases']==72 and observed['pid']==process.pid
            children.append(observed);canonical.append((OUT/('mode-'+str(mode))/'canonical.json').read_bytes())
        assert canonical[0]==canonical[1]and pin(__file__)==before
        for path,row in list(PINS.items()):pin(path,row['sha256'])
        report.update(status='PASS_FINITE_NATIVE_WORKER_OWNERS',actual_cases_per_mode=72,native_modes_equal=True,
            native_per_mode={k:v for k,v in children[0].items()if k.startswith('actual_')or k.endswith('_refusals')},creator_thread_only=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started;report['processes']=processes;report['source_pins']=PINS
        report['retained_files']={str(p.relative_to(OUT)):dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes()))for p in sorted(OUT.rglob('*'))if p.is_file()}
        (OUT/'result.json').write_bytes(J(report));print(json.dumps({k:v for k,v in report.items()if k not in('processes','source_pins','retained_files')},sort_keys=True))
if __name__=='__main__':main()
