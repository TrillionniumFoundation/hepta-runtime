#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct Initialize40 from complete actual Native and Original captures."""
from pathlib import Path
import json,struct
D=Path('/home/qq/hepta-http-transport-bd947-v1')
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
def native_captures(cases,base):
    pin=base.pin;durable=base.durable
    root=D/'session-handle-initialize-native-v1'
    handoff=json.loads(pin(D/'session-handle-initialize-core-handoff-v1.json','cc74ed8e21d7a492e6fd8bf482e7d2ff3f93db44c363d561dc4db936dbc7cc1c'))
    for path,want in handoff['final_inputs_and_outputs'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    build=base.admit_callable(D/'session-message-callable-build-v1',
        'b8b1573cb0fc27cafe050134b13a070f0631aa4223ce529f3975c03bf5b4e94a',
        D/'session-message-callable-build-v1.external.json',
        '4898d1f5775b556a144b9ced5a946261191b9697eb755cc16a38fc3f8a8e9017','1a1eb703229-392-4318')
    result=json.loads(pin(root/'result.json','151192ae4c834e38878414cedbd590755a0f1c20e57858540701fd3847227348'))
    ext=json.loads(pin(D/'session-handle-initialize-native-v1.external.json','80c5026d1048419d70d68739ab31be5dc2418ba3dba5408e388e34df93e35e17'))
    out,err=durable(ext,'1a1eb75a764-392-431e');assert not err
    assert json.loads(out)=={k:v for k,v in result.items()if k not in('processes','source_pins','retained_files')}
    assert result['status']=='PASS_FINITE_NATIVE_HANDLE_INITIALIZE'and result['actual_native_processes']==2 and result['actual_original_executions']==0
    for path,want in result['source_pins'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    for rel,want in result['retained_files'].items():
        raw=pin(root/rel,want['sha256']);assert len(raw)==want['bytes']
    assert json.loads(pin(root/'cases.json'))==cases
    canonical=[];metrics=[]
    for mode,process in zip((1,2),result['processes'],strict=True):
        assert process['mode']==mode and process['exit_code']==0 and not process['timed_out']
        folder=root/('mode-'+str(mode));child=json.loads(pin(folder/'result.json'))
        out=pin(root/('mode-'+str(mode)+'.stdout'),process['stdout_sha256'])
        err=pin(root/('mode-'+str(mode)+'.stderr'),process['stderr_sha256'])
        assert not err and len(out)==process['stdout_bytes']and child==json.loads(out)and child['pid']==process['pid']
        assert child['status']=='PASS_FINITE_NATIVE_HANDLE_INITIALIZE'and child['actual_cases']==40
        physical=[json.loads(line)for line in pin(folder/'physical.calls.jsonl').splitlines()]
        assert len(physical)==2*child['exports_returned']==2*child['exports_attempted']
        per_case={i:[]for i in range(1,41)}
        for index in range(0,len(physical),2):
            enter,returned=physical[index:index+2]
            assert enter['event']=='ENTER'and returned['event']=='RETURN'
            assert enter['ordinal']==returned['ordinal']==index//2
            assert {k:v for k,v in enter.items()if k!='event'}=={k:v for k,v in returned.items()if k not in('event','result')}
            assert enter['phase']==enter['frame']and enter['phase']in per_case
            per_case[enter['phase']].append(returned)
        resources=[json.loads(line)for line in pin(folder/'resources.jsonl').splitlines()]
        groups={i:[]for i in range(1,41)}
        for row in resources:groups[row['case']].append(row)
        wanted=json.loads(pin(folder/'canonical.json','abf16ea94996658ac3283b6ace1e6af88e273b35343faaf1ce78eb41ba3c1683'))
        reconstructed=[];totals=dict(physical=len(physical)//2,typed_callbacks=0,typed_hia=0,typed_effects=0,
            wakers=0,future_calls=0,future_hia=0,future_effects=0,future_trace_rows=0,
            client_factories=0,server_factories=0,mpsc_calls=0,event_takes=0,result_takes=0,reply_sends=0,
            pending_polls=0,ready_polls=0,capacity_refusals=0)
        for cid,case in enumerate(cases,1):
            rows=groups[cid];calls=per_case[cid]
            cells=[x['result']for x in calls if x['name']=='cooperative_scheduler_register']
            scs=[x['result']for x in calls if x['name']=='cooperative_scheduler_create']
            assert len(cells)==len(set(cells))==2 and len(scs)==1;sc=scs[0]
            leases=[r for r in rows if r['event']=='LEASE_OBSERVED']
            def role(name):
                found=[r for r in leases if r['role']==name];assert found,(cid,name)
                assert all({k:v for k,v in r.items()if k not in('case','event')}==
                    {k:v for k,v in found[0].items()if k not in('case','event')}for r in found)
                return found[0]
            for r in leases:
                d=bytes.fromhex(r['descriptor_hex']);p=bytes.fromhex(r['payload_hex'])
                assert len(d)==80 and len(p)==r['size']and U(d,16)==r['payload']and U(d,24)==r['size']
                assert U(d,40)==sc and r['address']>0 and r['payload']>0
            client=role('client_message_view');server=role('server_message_view')
            def wire(message,is_server):
                p=bytes.fromhex(message['payload_hex']);assert p[:8]==(b'HSSMV001'if is_server else b'HRCMV001')
                q=p[32:]
                if is_server:
                    assert q[:8]==b'HSSMP001'and U(p,8)==len(q)and U(q,32)==128
                    off,size=U(q,32),U(q,24)
                else:
                    assert q[:8]==b'HRCMO001'and U(p,16)==len(q)and U(p,8)==U(p,24)==0
                    off,size=U(q,224),U(q,232);assert off>=256
                assert off+size<=len(q);return q[off:off+size].decode()
            client_wire=wire(client,False);server_wire=wire(server,True)
            for is_server,message,key in((False,client,'client_json'),(True,server,'server_json')):
                kind='SERVER_MESSAGE_FACTORY'if is_server else'CLIENT_MESSAGE_FACTORY'
                found=[r for r in rows if r['event']==kind];assert len(found)==1;p=found[0]
                frame=bytes.fromhex(p['input_hex']);reply=bytes.fromhex(p['output_hex'])
                if is_server:
                    assert frame[:8]==b'HSSMQ001'and U(frame,8)==1 and U(frame,16)==2 and frame[96:]==case[key].encode()
                    assert U(frame,40)==len(frame)-96 and U(frame,64)==sc and U(frame,72)==U(bytes.fromhex(message['descriptor_hex']),8)
                    assert reply[:8]==b'HSSMR001'and U(reply,24)==message['address']and p['counts'][4:]==[1,0]
                    totals['server_factories']+=1
                else:
                    assert frame[:8]==b'HRCMQ001'and U(frame,8)==2 and frame[64:]==case[key].encode()
                    assert U(frame,16)==len(frame)-64 and U(frame,24)==sc and U(frame,32)==U(bytes.fromhex(message['descriptor_hex']),8)
                    assert reply[:8]==b'HRCMR001'and U(reply,16)==message['address']
                    totals['client_factories']+=1
                assert len(reply)==64
                physical_factory=[x for x in calls if x['name']==('server_message_call'if is_server else'client_message_call')]
                assert len(physical_factory)==1 and physical_factory[0]['result']==64 and physical_factory[0]['args'][1]==len(frame)and physical_factory[0]['args'][3]==64
            tx=role('events.tx');rx=role('events.rx');event=role('received_initialize_event');reply_result=role('reply.result.ok.server')
            ep=bytes.fromhex(event['payload_hex']);rp=bytes.fromhex(reply_result['payload_hex'])
            assert len(ep)==128 and ep[:8]==b'HRSVE001'and U(ep,8)==5 and U(ep,16)==client['address']and U(ep,24)>0 and ep[32:]==bytes(96)
            responder=U(ep,24);assert rp==b'HRSRS001'+struct.pack('<3Q',3,0,server['address'])
            created=[r for r in rows if r['event']=='FUTURE_CREATE'];assert len(created)==1;fc=created[0]
            fi=bytes.fromhex(fc['input_hex']);fo=bytes.fromhex(fc['output_hex']);future=fc['future'];fgen=cid*256+128
            assert len(fi)==128 and fi[:8]==b'HRSHQ001'and list(struct.unpack_from('<6Q',fi,8))==[1,fgen,5,sc,tx['address'],client['address']]and fi[56:]==bytes(72)
            assert len(fo)==64 and fo[:8]==b'HRSHR001'and U(fo,8)==U(fo,32)==0 and U(fo,40)==3 and fc['counts']==[1,0,0,0,0,0,0,0]
            create_calls=[x for x in calls if x['name']=='session_handle_future_create'];assert len(create_calls)==1 and create_calls[0]['result']==future
            totals['future_hia']+=1
            recorded_calls=[r for r in rows if r['event']=='FUTURE_CALL']
            actual_calls=[r for r in calls if r['name']=='session_handle_future_call'];assert len(recorded_calls)==len(actual_calls)
            for record,actual in zip(recorded_calls,actual_calls,strict=True):
                assert actual['args'][0]==record['future']==future and actual['args'][1]==record['op']
                assert actual['args'][4]==record['capacity']and actual['result']==record['code']
                out=bytes.fromhex(record['output_hex']);counts=record['counts'];assert len(out)==80 and len(counts)==8
                totals['future_calls']+=1;totals['future_hia']+=counts[0];totals['future_effects']+=sum(counts[1:])
                if record['capacity']<64:
                    assert record['code']==0xfffffffe and out==b'\xa9'*80 and counts==[1,0,0,0,0,0,0,0];totals['capacity_refusals']+=1
                else:
                    assert record['code']==64 and out[:8]==b'HRSHR001'and out[64:]==b'\xa9'*16
                    assert U(out,16)==fgen and U(out,24)==5 and U(out,40)==3 and U(out,56)==0
                    if record['op']==3:assert U(out,8)==3
                    else:
                        assert record['op']==2 and U(out,8)in(1,2)
                        if U(out,8)==1:assert U(out,32)==0;totals['pending_polls']+=1
                        else:assert U(out,32)==reply_result['address'];totals['ready_polls']+=1
            mcs=[r for r in rows if r['event']=='MPSC_CALL'];mphys=[r for r in calls if r['name']=='bounded_mpsc_call']
            assert len(mcs)==len(mphys)
            for rec,physical_call in zip(mcs,mphys,strict=True):
                i=bytes.fromhex(rec['input_hex']);o=bytes.fromhex(rec['output_hex'])
                assert rec['code']==physical_call['result']==128 and i[:8]==b'HRCMUQ01'and o[:8]==b'HRCMUR01'
                assert len(i)==96 and len(o)==128 and U(i,16)==U(o,16)and U(i,8)==U(o,24)
                assert U(i,40)==(cells[1]if U(i,8)in(5,8)else 0)
                assert physical_call['args'][2]==96 and physical_call['args'][4]==128
            totals['mpsc_calls']+=len(mcs)
            steps=[];block=[];all_events=[]
            def one(kind):
                found=[x for x in block if x['event']==kind];assert len(found)==1,(cid,kind,found);return found[0]
            def drop_role(name):
                address=role(name)['address'];en=[x['address']for x in block if x['event']=='DROP_ENTER'];re=[x['address']for x in block if x['event']=='DROP_RETURN']
                assert address in en and en==re
            def one_future(op):
                found=[x for x in block if x['event']=='FUTURE_CALL'and x['capacity']==64]
                assert len(found)==1 and found[0]['op']==op;return bytes.fromhex(found[0]['output_hex'])
            for r in rows:
                if r['event']!='CANONICAL_STEP':block.append(r);continue
                step=r['step'];value=None
                if step=='construct_client':assert one('CLIENT_MESSAGE_FACTORY');value=dict(wire=client_wire)
                elif step=='create_future':assert one('FUTURE_CREATE')==fc
                elif step in('fill_queue','drain_filler'):
                    op=5 if step=='fill_queue'else 8
                    selected=[x for x in block if x['event']=='MPSC_CALL'and U(bytes.fromhex(x['input_hex']),8)==op]
                    assert len(selected)==1 and U(bytes.fromhex(selected[0]['output_hex']),8)==0
                    if step=='drain_filler':
                        assert U(bytes.fromhex(selected[0]['output_hex']),40)==role('filler.close')['address'];drop_role('filler.close')
                elif step in('poll_initial','poll_after_capacity'):assert U(one_future(2),8)==1;value='pending'
                elif step=='take_initialize_event':
                    o=bytes.fromhex(one('EVENT_TAKE')['output_hex'])
                    assert len(o)==160 and o[:8]==b'HRSVFR01'and U(o,16)==event['address']and U(o,24)==128 and o[32:]==ep
                    totals['event_takes']+=1;value=dict(wire=client_wire)
                elif step=='drop_client_message':drop_role('client_message_view')
                elif step=='construct_reply':assert one('SERVER_MESSAGE_FACTORY');value=dict(wire=server_wire)
                elif step=='drop_future':
                    assert U(one_future(3),8)==3
                    when={'cancel_before_reply':'before_reply','cancel_buffered_reply':'buffered_reply'}.get(case['scenario'],'ready')
                    value=dict(when=when)
                    if when=='ready':
                        kept=role('result_after_future_drop');assert kept['address']==reply_result['address']and kept['payload_hex']==reply_result['payload_hex']
                elif step=='send_reply':
                    record=one('REPLY_SEND');o=bytes.fromhex(record['output_hex'])
                    assert len(o)==80 and o[:8]==b'HROSNR01'and record['responder']==responder and record['result']==reply_result['address']
                    assert U(o,8)in(1,2)and U(o,24)==(reply_result['address']if U(o,8)==2 else 0)
                    value={1:'sent',2:'closed'}[U(o,8)];totals['reply_sends']+=1
                elif step=='drop_rejected_reply':drop_role('reply.result.ok.server')
                elif step=='poll_reply':
                    o=one_future(2);assert U(o,8)==2 and U(o,32)==reply_result['address']
                    returned=role('returned_initialize_result');assert returned['payload_hex']==reply_result['payload_hex']and returned['address']==reply_result['address']
                    value=dict(status='ok',wire=server_wire)
                elif step=='take_reply_result':
                    o=bytes.fromhex(one('RESULT_TAKE')['output_hex'])
                    assert len(o)==64 and o[:8]==b'HRSRFR01'and U(o,16)==reply_result['address']and U(o,24)==32 and o[32:]==rp
                    value=dict(wire=server_wire);totals['result_takes']+=1
                elif step=='drop_reply_result':drop_role('reply.result.ok.server')
                elif step=='drop_server_message':drop_role('server_message_view')
                elif step=='channel_cleanup':drop_role('events.tx');drop_role('events.rx')
                else:raise AssertionError((cid,step))
                assert value==r['result'],(cid,step,value,r)
                all_events.extend(r['events']);steps.append(dict(step=step,result=value,events=r['events']));block=[]
            wakers=pin(folder/('case-'+str(cid)+'.wakers.bin'));observed=[]
            for kind,cell in struct.iter_unpack('<2Q',wakers):
                assert cell in cells;observed.append(dict(kind={1:'clone',2:'drop',3:'wake_by_ref',4:'wake'}[kind],waker=cells.index(cell)))
            assert observed==all_events;totals['wakers']+=len(observed)
            typed=pin(folder/('case-'+str(cid)+'.typed.bin'));stack=[];cd=[];sd=[];rt=[];et=[]
            for stage,tag,desc,arena,hias,effects in struct.iter_unpack('<6Q',typed):
                if stage==1:
                    assert hias==effects==0;stack.append((tag,desc,arena));totals['typed_callbacks']+=1
                    if tag==10:cd.append(desc)
                    if tag==12:sd.append(desc)
                    if tag in(7,9):rt.append((tag,desc))
                    if tag==4:et.append(desc)
                else:
                    assert stage==2 and stack.pop()==(tag,desc,arena)and hias==effects+1
                    if tag==12:assert(hias,effects)==(1,0)
                    totals['typed_hia']+=hias;totals['typed_effects']+=effects
            assert not stack and cd==[client['address']]and sd==[server['address']]and et==[event['address']]
            take=case['scenario']in('reply_ok_take','pending_send_resume_ok_take')
            assert rt==[(9 if take else 7,reply_result['address'])]
            trace=pin(folder/('case-'+str(cid)+'.future-trace.bin'));assert len(trace)%4096==0
            totals['future_trace_rows']+=len(trace)//2048
            for at in range(0,len(trace),4096):
                request=trace[at:at+2048];response=trace[at+2048:at+4096]
                a=struct.unpack_from('<6Q',request);b=struct.unpack_from('<6Q',response)
                assert a[0]==1 and b[0]==2 and a[1:4]==b[1:4]and a[4:]==(0,0)
                assert 1<=a[1]<=7 and request[48:704]==response[48:704]
                assert request[1408:]==response[1408:]==bytes(640)
                if a[1]==3:
                    desc=response[1216:1296];size=U(desc,24)
                    assert size in(32,128)and U(desc,40)==sc and U(desc,8)==U(response,136)
                    assert U(response,704)>0 and U(desc,16)>0
                if a[1]==2:
                    assert U(response,704)>0 and U(response,1320)>0
            assert len(trace)//4096==sum(sum(r['counts'][1:])for r in recorded_calls)
            released=[r for r in rows if r['event']=='ALL_RELEASED'];assert len(released)==1
            assert released[0]['fd_sets_balanced']and released[0]['all_native_guarded_allocations_retired']
            assert released[0]['actual_client_drop_count']==released[0]['actual_server_drop_count']==1
            reconstructed.append(dict(name=case['name'],rows=steps))
        assert reconstructed==wanted
        expected=dict(typed_callbacks=328,typed_hia=768,typed_effects=440,
            future_calls=114,future_hia=610,future_effects=456,future_trace_rows=912,
            client_factories=40,server_factories=40,mpsc_calls=168,event_takes=40,
            result_takes=16,reply_sends=40,pending_polls=48,ready_polls=24)
        for key,n in expected.items():assert totals[key]==n,(mode,key,totals)
        assert totals['typed_callbacks']==child['actual_typed_callbacks']and totals['typed_hia']==child['actual_typed_hia_entries']
        assert totals['typed_effects']==child['actual_typed_effects']and totals['future_trace_rows']==child['actual_future_trace_rows']
        # Two Future capacity controls plus the independently retained ResultTake control.
        small=[c for calls in per_case.values()for c in calls if c['name']=='session_result_take'and c['args'][2]<64]
        assert len(small)==1 and small[0]['args'][2]==63 and small[0]['result']==0xfffffffe
        assert totals['capacity_refusals']+len(small)==child['capacity_refusals']==3
        canonical.append(reconstructed);metrics.append(totals)
    assert canonical[0]==canonical[1];return canonical[0],metrics

def original_capture(raw,cases):
    traces={};answers=[];current=None;completed=set();metrics=dict(trace_records=0,channel_polls=0,outer_polls=0,clones=0,drops=0,wake_by_ref=0,consuming_wakes=0,base_drops=0)
    records=[json.loads(line)for line in raw.splitlines()]
    for row in records:
        name=row['case']
        if row['event']=='trace':
            assert name not in completed
            if current is None:current=name
            assert current==name
            trail=traces.setdefault(name,[]);record=row['record'];assert record['seq']==len(trail);trail.append(record)
        else:
            assert row['event']=='result'and current==name and name not in completed
            index=len(answers);case=cases[index];assert name==case['name'];value=row['value'];trace=traces[name]
            assert value['trace']==trace and value['status']=='PASS_FINITE_ACTUAL_HANDLE_INITIALIZE'
            assert value['real_runtime']=='current_thread'and value['real_spawned_task']and value['actual_public_initialize']and value['actual_session_event_channel']
            assert not value['actual_typed_destructor_callbacks_observed']and not value['whole_worker_qualified']and not value['production_activated']
            result_rows=[];step=None;events=[];refs=[0,0];addresses={};polls=0;outer=0;base_drops=0;thread=None;active_poll=None;per=dict(clones=[0,0],drops=[0,0],consuming_wakes=[0,0],wake_by_ref=[0,0])
            for r in trace:
                if thread is None:thread=r['thread']
                assert r['thread']==thread
                e=r['event'];detail=r['details'];metrics['trace_records']+=1
                if e=='base_create':
                    i=detail['waker'];assert i in(0,1)and i not in addresses;addresses[i]=detail['raw_address'];refs[i]+=1
                elif e=='waker':
                    i=detail['waker'];kind=detail['kind'];assert detail['raw_address']==addresses[i]
                    if kind=='clone':refs[i]+=1;metrics['clones']+=1;per['clones'][i]+=1
                    elif kind in('drop','wake'):
                        refs[i]-=1;metrics['drops'if kind=='drop'else'consuming_wakes']+=1;per['drops'if kind=='drop'else'consuming_wakes'][i]+=1
                    else:assert kind=='wake_by_ref';metrics['wake_by_ref']+=1;per['wake_by_ref'][i]+=1
                    assert refs[i]>=0
                    if r['phase']=='base_cleanup':assert kind=='drop';base_drops+=1;metrics['base_drops']+=1
                    else:assert step==r['step'];events.append(dict(kind=kind,waker=i))
                elif e=='operation_begin':assert step is None;step=r['step'];events=[]
                elif e=='operation_end':
                    assert step==r['step'];result_rows.append(dict(step=step,result=detail,events=events));step=None;events=[]
                elif e=='channel_poll_begin':
                    assert active_poll is None and step==r['step']and detail['operation']in('initialize','mpsc_send','mpsc_recv')
                    active_poll=detail['operation'];polls+=1
                    assert detail['real_context_present']is True and detail['observer_is_context']is False
                elif e=='channel_poll_end':
                    assert active_poll==detail['operation']and isinstance(detail['ready'],bool);active_poll=None
                elif e=='outer_poll_begin':outer+=1
                elif e=='outer_poll_end':assert detail==dict(ready=True)
                else:assert e in('base_cleanup_begin','base_cleanup_end')
            assert active_poll is None and step is None and refs==[0,0]and base_drops==2 and outer==1 and len(addresses)==2
            canonical=dict(name=name,rows=result_rows);assert canonical==value['canonical']
            assert polls==value['actual_channel_polls']and outer==value['actual_outer_task_polls']
            assert value['base_creates']==[1,1]
            assert value['clones']==per['clones']and value['drops_including_base']==per['drops']
            assert value['consuming_wakes']==per['consuming_wakes']and value['wake_by_ref']==per['wake_by_ref']
            metrics['channel_polls']+=polls;metrics['outer_polls']+=outer;answers.append(canonical);completed.add(name);current=None
    assert current is None and len(answers)==len(cases)==40 and len(completed)==40
    return answers,metrics
