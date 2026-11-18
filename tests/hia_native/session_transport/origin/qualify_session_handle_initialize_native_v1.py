#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual initialize Future with actual typed Client/Server messages in one ELF."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,os,stat,struct,subprocess,threading,time
D=Path('/home/qq/hepta-http-transport-bd947-v1');OUT=D/'session-handle-initialize-native-v1'
BUILD_SHA='b8b1573cb0fc27cafe050134b13a070f0631aa4223ce529f3975c03bf5b4e94a'
MACHINE_SHA='6434fec17163a287c3a7912a734c98b59419566d0e55ddb813dff9355105868c'
CASES_SHA='340eb989c8212c4c76f2d5880a03e40694242513c82bc125ad4f8b4969a54c6d'
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
Q=ctypes.c_uint64;U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
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
    report=dict(schema='hepta.session-handle-initialize.native-child.v1',status='RUNNING',mode=mode,pid=os.getpid(),tid=threading.get_native_id(),
        actual_cases=0,actual_client_message_factories=0,actual_client_message_hia_entries=0,actual_server_message_factories=0,actual_server_message_hia_entries=0,
        actual_future_creates=0,actual_future_calls=0,actual_future_hia_entries=0,actual_future_effects=0,actual_pending_polls=0,actual_ready_polls=0,
        actual_explicit_value_creates=0,actual_explicit_value_drops=0,actual_mpsc_channels=0,actual_mpsc_calls=0,actual_event_takes=0,actual_owned_reply_sends=0,actual_result_takes=0,
        actual_typed_callbacks=0,actual_typed_hia_entries=0,actual_typed_effects=0,actual_waker_clones=0,actual_waker_drops=0,actual_consuming_wakes=0,actual_wakes_by_ref=0,
        actual_future_trace_rows=0,historical_address_reuses=0,capacity_refusals=0,actual_original_executions=0,actual_probe_creations=0,
        original_compared=False,worker_integrated=False,production_activated=False,whole_runtime_replaced=False)
    tm=module(D/'session_message_machine_v1.py',MACHINE_SHA,'session_message_machine');machine=tm.Machine(folder,report,BUILD_SHA)
    journal=(folder/'resources.jsonl').open('xb',buffering=0);canonical=[];started=time.monotonic()
    cases=json.loads(pin(D/'session-handle-initialize-cases-v1.json',CASES_SHA))
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
            assert all(cells)and cells[0]!=cells[1];active=0
            for _ in range(8):
                active=machine.call('cooperative_scheduler_next',sc)
                if active:assert active in cells;break
                assert word(sc,200)==2
            else:raise AssertionError('no scheduler task')
            serial=0;leases=[];contexts=[];rows=[];seen=0;future=0;trace_seen=0
            trace_data=(ctypes.c_ubyte*(2048*128))();trace=(Q*4)(int.from_bytes(b'HRSHT001','little'),ctypes.addressof(trace_data),128,0)
            def gen():
                nonlocal serial
                serial+=1;assert serial<128;return cid*256+serial
            def record(address,role,payload=None,entry=None):
                span=machine.call('value_lease_span',address);actual=ctypes.string_at(span.pointer,span.size)
                if payload is not None:assert actual==payload
                if entry is not None:assert word(address,32)==machine.base+machine.exports[entry]
                assert word(address,40)==sc and 'w'not in mapped(address)and'w'not in mapped(span.pointer)
                item=dict(address=address,payload=span.pointer,size=span.size,role=role,descriptor_hex=ctypes.string_at(address,80).hex(),payload_hex=actual.hex())
                leases.append(item);log(dict(case=cid,event='LEASE_OBSERVED',**item));return actual
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
                    events.append(dict(kind={1:'clone',2:'drop',3:'wake_by_ref',4:'wake'}[kind],waker=cells.index(cell)))
                    report[{1:'actual_waker_clones',2:'actual_waker_drops',3:'actual_wakes_by_ref',4:'actual_consuming_wakes'}[kind]]+=1
                seen=n;rows.append(dict(step=step,result=result,events=events));log(dict(case=cid,event='CANONICAL_STEP',**rows[-1]))
            def message_wire(address,server):
                payload=record(address,'server_message_view'if server else'client_message_view',entry='server_message_drop_entry'if server else'client_message_drop_entry')
                assert payload[:8]==(b'HSSMV001'if server else b'HRCMV001')
                projection=payload[32:]
                if server:
                    assert projection[:8]==b'HSSMP001'and len(projection)==U(payload,8)
                    at=U(projection,32);length=U(projection,24);assert at==128
                else:
                    assert projection[:8]==b'HRCMO001'and len(projection)==U(payload,16)and U(payload,8)==0 and U(payload,24)==0
                    at=U(projection,224);length=U(projection,232);assert at>=256
                assert at+length<=len(projection);return projection[at:at+length].decode()
            def make_message(raw,server):
                g=gen();raw=raw.encode()
                frame=(b'HSSMQ001'+struct.pack('<11Q',1,2,0,0,len(raw),0,0,sc,g,0,0)if server else b'HRCMQ001'+struct.pack('<7Q',2,len(raw),sc,g,0,0,0))+raw
                source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*64)();counts=(Q*(6 if server else 5))()
                code=machine.call('server_message_call'if server else'client_message_call',ctypes.addressof(source),len(frame),ctypes.addressof(answer),64,ctypes.addressof(counts))
                response=bytes(answer);assert code==64 and response[:8]==(b'HSSMR001'if server else b'HRCMR001')and source.raw==frame
                address=U(response,24 if server else 16);wire=message_wire(address,server)
                report['actual_server_message_factories'if server else'actual_client_message_factories']+=1
                report['actual_server_message_hia_entries'if server else'actual_client_message_hia_entries']+=sum(counts[:4]if server else counts[:3])
                log(dict(case=cid,event='SERVER_MESSAGE_FACTORY'if server else'CLIENT_MESSAGE_FACTORY',input_hex=frame.hex(),output_hex=response.hex(),counts=list(counts)))
                return address,wire
            client,client_wire=make_message(case['client_json'],False);row('construct_client',dict(wire=client_wire))
            mg=gen();mc=machine.call('bounded_mpsc_create',sc,mg,case['channel_capacity'],machine.call('channel_waker_observer_table'),sc);assert mc
            initial=ctypes.string_at(mc+256,128);assert initial[:8]==b'HRCMUR01'and U(initial,8)==0
            tx_token=U(initial,32);tx=lease(b'HROMH001'+struct.pack('<4Q',1,mc,mg,tx_token),'owned_mpsc_handle_drop_entry','events.tx')
            rx=lease(b'HROMH001'+struct.pack('<4Q',2,mc,mg,0),'owned_mpsc_handle_drop_entry','events.rx')
            contexts.append(dict(context=mc,workspace=word(mc,16),semaphore=word(mc,80),kind='mpsc'));report['actual_mpsc_channels']+=1
            log(dict(case=cid,event='MPSC_CREATE',context=mc,generation=mg,token=tx_token,tx=tx,rx=rx,initial_hex=initial.hex()))
            def mcall(op,token=0,value=0):
                frame=b'HRCMUQ01'+struct.pack('<11Q',op,mg,token,value,cells[1]if op in(5,8)else 0,0,0,0,0,0,0)
                source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*128)()
                code=machine.call('bounded_mpsc_call',mc,ctypes.addressof(source),96,ctypes.addressof(answer),128);out=bytes(answer)
                assert code==128 and out[:8]==b'HRCMUR01'and U(out,16)==mg and U(out,24)==op and source.raw==frame
                report['actual_mpsc_calls']+=1;log(dict(case=cid,event='MPSC_CALL',input_hex=frame.hex(),output_hex=out.hex(),code=code));return out
            def receive_event():
                rf=U(mcall(7),32);out=mcall(8,rf);assert U(out,8)==0 and U(out,40);mcall(9,rf);return U(out,40)
            fgen=cid*256+128;frame=b'HRSHQ001'+struct.pack('<15Q',1,fgen,5,sc,tx,client,0,0,0,0,0,0,0,0,0)
            source=ctypes.create_string_buffer(frame,len(frame));answer=(ctypes.c_ubyte*80)();counts=(Q*8)();ctypes.memset(answer,169,80)
            future=machine.call('session_handle_future_create',ctypes.addressof(source),128,ctypes.addressof(answer),64,ctypes.addressof(counts),ctypes.addressof(trace))
            initial=bytes(answer);assert future and source.raw==frame and initial[64:]==b'\xa9'*16 and list(counts)==[1,0,0,0,0,0,0,0]
            assert initial[:8]==b'HRSHR001'and U(initial,8)==0 and U(initial,32)==0 and U(initial,40)==3
            workspace=word(future,8);contexts.append(dict(context=future,workspace=workspace,kind='handle_future'))
            report['actual_future_creates']+=1;report['actual_future_hia_entries']+=1
            log(dict(case=cid,event='FUTURE_CREATE',input_hex=frame.hex(),output_hex=initial[:64].hex(),future=future,workspace=workspace,counts=list(counts)));row('create_future')
            def read_trace():
                nonlocal trace_seen
                n=int(trace[3]);raw=ctypes.string_at(ctypes.addressof(trace_data),n*2048)
                while trace_seen<n:
                    entry=raw[trace_seen*2048:(trace_seen+1)*2048];stage,effect,seq,phase,code,size=struct.unpack_from('<6Q',entry)
                    assert stage in(1,2)and 1<=effect<=7 and entry[1408:]==bytes(640)
                    if stage==2 and effect==3:
                        address=U(entry,704);desc=entry[1216:1296];length=U(desc,24);payload=entry[192:192+length]
                        assert U(desc,16)and length in(32,128)and U(desc,40)==sc and U(desc,8)==U(entry,136)
                        leases.append(dict(address=address,payload=U(desc,16),size=length,role='future:'+str(phase),descriptor_hex=desc.hex(),payload_hex=payload.hex()))
                    if stage==2 and effect==2:
                        ctx=U(entry,704);header=entry[1216:1344];assert U(header,104)==ctypes.addressof(observer)
                        contexts.append(dict(context=ctx,workspace=U(header,16),kind='future.oneshot'))
                    trace_seen+=1
                (folder/('case-'+str(cid)+'.future-trace.bin')).write_bytes(raw)
            def future_call(op,capacity=64):
                nonlocal future
                ctypes.memset(answer,169,80);ctypes.memset(counts,0,64);address=future;before=ctypes.string_at(workspace,16384)
                code=machine.call('session_handle_future_call',future,op,cells[0]if op==2 else 0,ctypes.addressof(answer),capacity,ctypes.addressof(counts))
                out=bytes(answer);report['actual_future_calls']+=1;report['actual_future_hia_entries']+=counts[0];report['actual_future_effects']+=sum(counts[1:])
                log(dict(case=cid,event='FUTURE_CALL',future=address,op=op,capacity=capacity,code=code,output_hex=out.hex(),counts=list(counts)))
                if capacity<64:
                    assert code==0xfffffffe and out==b'\xa9'*80 and list(counts)==[1,0,0,0,0,0,0,0]and ctypes.string_at(workspace,16384)==before
                    report['capacity_refusals']+=1;return None
                read_trace();assert code==64 and out[:8]==b'HRSHR001'and out[64:]==b'\xa9'*16
                assert U(out,16)==fgen and U(out,24)==5 and U(out,40)==3 and U(out,56)==0
                if op==3:assert U(out,8)==3;future=0;return None
                if U(out,8)==1:assert U(out,32)==0;report['actual_pending_polls']+=1;return None
                assert U(out,8)==2 and U(out,32);report['actual_ready_polls']+=1;return U(out,32)
            if cid==1:future_call(2,0);future_call(2,63)
            scenario=case['scenario'];pending=scenario=='pending_send_resume_ok_take'
            if pending:
                filler=lease(b'HRSVE001'+struct.pack('<15Q',6,*([0]*14)),'session_event_drop_entry','filler.close')
                sf=U(mcall(4,tx_token,filler),32);out=mcall(5,sf);assert U(out,8)==0;mcall(6,sf);row('fill_queue')
            result=future_call(2);assert result is None;row('poll_initial','pending')
            if pending:
                filler_received=receive_event();assert filler_received==filler;drop(filler_received);row('drain_filler')
                result=future_call(2);assert result is None;row('poll_after_capacity','pending')
            event=receive_event();payload=record(event,'received_initialize_event',entry='session_event_drop_entry')
            assert payload[:8]==b'HRSVE001'and len(payload)==128 and U(payload,8)==5 and U(payload,16)==client and U(payload,24)and payload[32:]==bytes(96)
            taken=(ctypes.c_ubyte*160)();assert machine.call('session_event_take',event,ctypes.addressof(taken),160)==160
            out=bytes(taken);assert out[:8]==b'HRSVFR01'and U(out,16)==event and U(out,24)==128 and out[32:]==payload
            report['actual_event_takes']+=1;log(dict(case=cid,event='EVENT_TAKE',descriptor=event,output_hex=out.hex()))
            responder=U(out,56);assert message_wire(U(out,48),False)==client_wire;row('take_initialize_event',dict(wire=client_wire))
            drop(client);row('drop_client_message')
            server,server_wire=make_message(case['server_json'],True)
            result_payload=b'HRSRS001'+struct.pack('<3Q',3,0,server)
            reply_result=lease(result_payload,'session_result_drop_entry','reply.result.ok.server');row('construct_reply',dict(wire=server_wire))
            if scenario=='cancel_before_reply':future_call(3);row('drop_future',dict(when='before_reply'))
            sent=(ctypes.c_ubyte*80)();assert machine.call('owned_oneshot_send',responder,reply_result,ctypes.addressof(sent),80)==80
            out=bytes(sent);assert out[:8]==b'HROSNR01'and U(out,8)in(1,2);report['actual_owned_reply_sends']+=1
            log(dict(case=cid,event='REPLY_SEND',responder=responder,result=reply_result,output_hex=out.hex()))
            delivery='sent'if U(out,8)==1 else'closed';row('send_reply',delivery)
            if scenario=='cancel_before_reply':
                assert delivery=='closed'and U(out,24)==reply_result;drop(reply_result);row('drop_rejected_reply')
            else:
                assert delivery=='sent'and U(out,24)==0
                if scenario=='cancel_buffered_reply':future_call(3);row('drop_future',dict(when='buffered_reply'))
                else:
                    result=future_call(2);assert result==reply_result
                    observed=record(result,'returned_initialize_result',result_payload,'session_result_drop_entry')
                    observed_wire=message_wire(U(observed,24),True);assert observed_wire==server_wire
                    row('poll_reply',dict(status='ok',wire=observed_wire))
                    future_call(3);row('drop_future',dict(when='ready'))
                    # The result remains a live caller-owned lease after Future Drop.
                    record(result,'result_after_future_drop',result_payload,'session_result_drop_entry')
                    if scenario=='reply_ok_drop':drop(result);row('drop_reply_result')
                    else:
                        assert scenario in('reply_ok_take','pending_send_resume_ok_take')
                        taken_result=(ctypes.c_ubyte*80)();ctypes.memset(taken_result,169,80)
                        if cid==1:
                            assert machine.call('session_result_take',result,ctypes.addressof(taken_result),63)==0xfffffffe and bytes(taken_result)==b'\xa9'*80
                            report['capacity_refusals']+=1
                        assert machine.call('session_result_take',result,ctypes.addressof(taken_result),64)==64
                        out=bytes(taken_result);assert out[:8]==b'HRSRFR01'and U(out,16)==result and U(out,24)==32 and out[32:64]==result_payload and out[64:]==b'\xa9'*16
                        report['actual_result_takes']+=1;log(dict(case=cid,event='RESULT_TAKE',descriptor=result,output_hex=out[:64].hex()))
                        assert U(out,56)==server and message_wire(U(out,56),True)==server_wire
                        row('take_reply_result',dict(wire=server_wire));drop(server);row('drop_server_message')
            assert future==0;drop(tx);drop(rx);row('channel_cleanup');assert seen==int(observer[3])
            assert machine.call('cooperative_scheduler_finish',sc,active,1)==0
            for _ in range(64):
                selected=machine.call('cooperative_scheduler_next',sc)
                if selected:assert selected in cells;assert machine.call('cooperative_scheduler_finish',sc,selected,1)==0
                elif word(sc,200)==1:break
                else:assert word(sc,200)==2
            else:raise AssertionError('scheduler failed to quiesce')
            for cell in cells:assert word(cell,32)==1 and machine.call('cooperative_scheduler_retire',cell)==0 and not mapped(cell)
            def retired(address,role):
                flags=mapped(address)
                if flags is not None:
                    assert 'w'in flags,(cid,role,address,flags,Path('/proc/self/maps').read_text())
                    report['historical_address_reuses']+=1;log(dict(case=cid,event='RETIRED_ADDRESS_REUSED',address=address,role=role,new_flags=flags))
            typed_raw=ctypes.string_at(ctypes.addressof(typed_data),int(typed[3])*48)
            (folder/('case-'+str(cid)+'.typed.bin')).write_bytes(typed_raw);stack=[];client_drops=[];server_drops=[];result_terminals=[];event_takes=[]
            for stage,tag,descriptor,arena,hias,effects in struct.iter_unpack('<6Q',typed_raw):
                if stage==1:
                    assert hias==effects==0;stack.append((tag,descriptor,arena));report['actual_typed_callbacks']+=1
                    if tag==10:client_drops.append(descriptor)
                    if tag==12:server_drops.append(descriptor)
                    if tag in(7,9):result_terminals.append((tag,descriptor))
                    if tag==4:event_takes.append(descriptor)
                else:
                    assert stage==2 and stack.pop()==(tag,descriptor,arena)and hias==effects+1
                    retired(arena,'typed_callback_arena')
                    if tag==12:assert hias==1 and effects==0
                    report['actual_typed_hia_entries']+=hias;report['actual_typed_effects']+=effects
            assert not stack and client_drops==[client]and server_drops==[server]and event_takes==[event]
            assert result_terminals==[(9 if scenario in('reply_ok_take','pending_send_resume_ok_take')else 7,reply_result)]
            report['actual_future_trace_rows']+=int(trace[3]);assert int(trace[3])%2==0 and trace_seen==int(trace[3])
            waker_raw=ctypes.string_at(ctypes.addressof(waker_data),int(observer[3])*16);(folder/('case-'+str(cid)+'.wakers.bin')).write_bytes(waker_raw)
            assert machine.call('typed_drop_observer_attach',sc,0)==0 and machine.call('batch_observer_attach',sc,0)==0
            assert machine.call('cooperative_scheduler_destroy',sc)==0 and not mapped(sc)
            assert guard_maps()==guards_before,(cid,guards_before,guard_maps())
            for item in leases:retired(item['address'],item['role']+'.descriptor');retired(item['payload'],item['role']+'.payload')
            for item in contexts:
                retired(item['context'],item['kind']+'.context');retired(item['workspace'],item['kind']+'.initial_workspace')
                if 'semaphore'in item:retired(item['semaphore'],'semaphore.context')
            assert set(os.listdir('/proc/self/fd'))==fd_before
            log(dict(case=cid,event='ALL_RELEASED',fd_sets_balanced=True,all_native_guarded_allocations_retired=True,
                actual_client_drop_count=len(client_drops),actual_server_drop_count=len(server_drops),actual_result_terminal=result_terminals))
            canonical.append(dict(name=case['name'],rows=rows));report['actual_cases']+=1
        report.update(status='PASS_FINITE_NATIVE_HANDLE_INITIALIZE',all_native_guarded_allocations_retired=True,all_fd_sets_balanced=True,
            all_inputs_unchanged=True,all_messages_actual_typed_owners=True,actual_server_child_dropped_exactly_once_per_case=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        journal.flush();os.fsync(journal.fileno());journal.close();machine.close();report['elapsed_seconds']=time.monotonic()-started
        (folder/'canonical.json').write_bytes(J(canonical));(folder/'result.json').write_bytes(J(report));print(json.dumps(report,sort_keys=True))
def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',type=int);a=p.parse_args()
    if a.mode is not None:return child(a.mode)
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);started=time.monotonic();processes=[]
    report=dict(schema='hepta.session-handle-initialize.native.v1',status='RUNNING',actual_native_processes=0,actual_original_executions=0,
        original_compared=False,worker_integrated=False,production_activated=False,whole_runtime_replaced=False)
    try:
        before=pin(__file__);pin(D/'session_message_machine_v1.py',MACHINE_SHA)
        source=pin(D/'session-handle-initialize-cases-v1.json',CASES_SHA);assert len(json.loads(source))==40;(OUT/'cases.json').write_bytes(source)
        pin(D/'SESSION-HANDLE-INITIALIZE-PAIR-PROTOCOL-v1.md','6ba6cd02e847fcbc4a797ae680effb35e64b8f29e22b800ce013d57f78d86549')
        build=json.loads(pin(D/'session-message-callable-build-v1/result.json',BUILD_SHA))
        assert build['status']=='BUILT_NOT_SEMANTICALLY_QUALIFIED'and build['semantic_images']==36 and build['unchanged_parent_semantic_images']==32
        assert build['parent_export_offsets_unchanged']and build['fixed_observer_patch']['bytes']==7 and build['fixed_observer_patch']['all_other_parent_adapter_bytes_equal']
        for path,row in build['source_pins'].items():pin(path,row['sha256'])
        pin(build['artifact']['path'],build['artifact']['sha256'])
        external=json.loads(pin(D/'session-message-callable-build-v1.external.json','4898d1f5775b556a144b9ced5a946261191b9697eb755cc16a38fc3f8a8e9017'))
        st=external['status'];assert st['job_id']=='1a1eb703229-392-4318'and st['state']=='succeeded'and st['exit_code']==0
        assert st['output_complete']and st['output_durable']and st['terminal_publication_confirmed']and st['timed_out']is st['cancelled']is st['automatic_retry']is False
        assert external['read']['stdout']['eof']and external['read']['stderr']['eof']and not external['read']['stderr']['text']
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
            assert observed['status']=='PASS_FINITE_NATIVE_HANDLE_INITIALIZE'and observed['actual_cases']==40 and observed['pid']==process.pid
            children.append(observed);canonical.append((OUT/('mode-'+str(mode))/'canonical.json').read_bytes())
        assert canonical[0]==canonical[1]and pin(__file__)==before
        for path,row in list(PINS.items()):pin(path,row['sha256'])
        report.update(status='PASS_FINITE_NATIVE_HANDLE_INITIALIZE',actual_cases_per_mode=40,native_modes_equal=True,
            native_per_mode={k:v for k,v in children[0].items()if k.startswith('actual_')or k.endswith('_refusals')},
            creator_thread_only=True,single_native_elf=True,missing_initialize_success_owner=False)
    except BaseException as error:report.update(status='FAIL',error=repr(error));raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started;report['processes']=processes;report['source_pins']=PINS
        report['retained_files']={str(p.relative_to(OUT)):dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes()))for p in sorted(OUT.rglob('*'))if p.is_file()}
        (OUT/'result.json').write_bytes(J(report));print(json.dumps({k:v for k,v in report.items()if k not in('processes','source_pins','retained_files')},sort_keys=True))
if __name__=='__main__':main()
