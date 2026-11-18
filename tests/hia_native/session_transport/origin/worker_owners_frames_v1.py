#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct Worker72 canonical rows from complete retained physical evidence."""
from pathlib import Path
import json,struct
D=Path('/home/qq/hepta-http-transport-bd947-v1')
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
def native_captures(cases,base):
    pin=base.pin;durable=base.durable;admit_callable=base.admit_callable
    root=D/'worker-transport-owners-native-v2'
    handoff=json.loads(pin(D/'worker-transport-owners-core-handoff-v1.json','f279936b45b4bc0d4fc8e240dac3e1ec6de74337e7545b88167c1bf87a057c75'))
    for path,want in handoff['final_inputs_and_outputs'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    build=admit_callable(D/'worker-transport-owners-callable-build-v3',
        '8d40289b3693f243c4ddc5b5513e8aada36f89859360c0c76f653a1cf791b9fe',
        D/'worker-transport-owners-callable-build-v3.external.json',
        '0574573e6017ba940c967f44fb03876fa69c49ca1ba0472f0dca6abcfe670586','1a1eb5dc64e-392-4311')
    result=json.loads(pin(root/'result.json','bf96b9373ce944a8184355d52db91caa5331af44a39cdd38dbdd2fca4d62dd19'))
    ext=json.loads(pin(D/'worker-transport-owners-native-v2.external.json','f08750265f1485922fec1be52dc1f2eb8877666790e27418424e82627e506411'))
    out,err=durable(ext,'1a1eb5f7ec0-392-4312');assert not err
    assert json.loads(out)=={k:v for k,v in result.items()if k not in('processes','source_pins','retained_files')}
    assert result['status']=='PASS_FINITE_NATIVE_WORKER_OWNERS'and result['actual_native_processes']==2 and result['actual_original_executions']==0
    for path,want in result['source_pins'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    for rel,want in result['retained_files'].items():
        raw=pin(root/rel,want['sha256']);assert len(raw)==want['bytes']
    assert json.loads(pin(root/'cases.json'))==cases
    canonical=[];metrics=[]
    for mode,process in zip((1,2),result['processes'],strict=True):
        assert process['mode']==mode and process['exit_code']==0 and not process['timed_out']
        folder=root/('mode-'+str(mode));child=json.loads(pin(folder/'result.json'))
        out=pin(root/('mode-'+str(mode)+'.stdout'),process['stdout_sha256']);err=pin(root/('mode-'+str(mode)+'.stderr'),process['stderr_sha256'])
        assert not err and len(out)==process['stdout_bytes']and child==json.loads(out)and child['pid']==process['pid']
        assert child['status']=='PASS_FINITE_NATIVE_WORKER_OWNERS'and child['actual_cases']==72
        physical=[json.loads(line)for line in pin(folder/'physical.calls.jsonl').splitlines()]
        assert len(physical)==2*child['exports_returned']==2*child['exports_attempted']
        per_case={i:[]for i in range(1,73)}
        for index in range(0,len(physical),2):
            enter,returned=physical[index:index+2]
            assert enter['event']=='ENTER'and returned['event']=='RETURN'
            assert enter['ordinal']==returned['ordinal']==index//2
            assert {k:v for k,v in enter.items()if k!='event'}=={k:v for k,v in returned.items()if k not in('event','result')}
            per_case[enter['phase']].append(returned)
        resources=[json.loads(line)for line in pin(folder/'resources.jsonl').splitlines()]
        groups={i:[]for i in range(1,73)}
        for row in resources:groups[row['case']].append(row)
        wanted=json.loads(pin(folder/'canonical.json','072ac4695499dd4304b921de03b482f347706c0a53c6f1cd3c68b5661e56bed9'))
        reconstructed=[];totals=dict(typed_callbacks=0,typed_hia=0,typed_effects=0,wakers=0,physical=len(physical)//2)
        for cid,case in enumerate(cases,1):
            rows=groups[cid];calls=per_case[cid]
            cells=[x['result']for x in calls if x['name']=='cooperative_scheduler_register'];assert len(cells)==2 and len(set(cells))==2
            scs=[x['result']for x in calls if x['name']=='cooperative_scheduler_create'];assert len(scs)==1
            leases=[r for r in rows if r['event']=='LEASE_OBSERVED']
            by_role={r['role']:r for r in leases}
            message=by_role['server_message'];payload=bytes.fromhex(message['payload_hex'])
            descriptor=bytes.fromhex(message['descriptor_hex']);assert len(descriptor)==80 and U(descriptor,40)==scs[0]
            assert payload[:8]==b'HSSMV001'and U(payload,8)==len(payload)-32
            projection=payload[32:];assert projection[:8]==b'HSSMP001'and U(projection,32)==128 and U(projection,24)==len(projection)-128
            wire=projection[128:].decode()
            factory=[r for r in rows if r['event']=='SERVER_MESSAGE_FACTORY'];assert len(factory)==1
            frame=bytes.fromhex(factory[0]['input_hex']);reply=bytes.fromhex(factory[0]['output_hex'])
            assert frame[:8]==b'HSSMQ001'and U(frame,8)==1 and U(frame,16)==2 and frame[96:]==case['message_json'].encode()
            assert U(frame,40)==len(frame)-96 and U(frame,64)==scs[0]and U(frame,72)==U(descriptor,8)
            assert reply[:8]==b'HSSMR001'and U(reply,24)==message['address']and factory[0]['counts'][4:]==[1,0]
            request=by_role['worker_request'];rq=bytes.fromhex(request['payload_hex'])
            assert rq[:8]==b'HRSWR001'and len(rq)==48 and U(rq,8)==message['address']and U(rq,16)==by_role['reply.tx']['address']
            assert U(rq,24)==0 and U(rq,32)==case['control_generation']and U(rq,40)==0
            fields=dict(control_generation=U(rq,32),cancellation_none=U(rq,24)==0,wire=wire)
            for r in leases:
                d=bytes.fromhex(r['descriptor_hex']);p=bytes.fromhex(r['payload_hex'])
                assert len(d)==80 and len(p)==r['size']and U(d,40)==scs[0]and r['address']>0 and r['payload']>0
            steps=[];block=[];all_events=[]
            def one(event):
                found=[x for x in block if x['event']==event];assert len(found)==1,(cid,event,found);return found[0]
            def dropped(role):
                address=by_role[role]['address'];entered=[r['address']for r in block if r['event']=='DROP_ENTER'];done=[r['address']for r in block if r['event']=='DROP_RETURN']
                assert address in entered and entered==done
            for row in rows:
                if row['event']!='CANONICAL_STEP':block.append(row);continue
                step=row['step'];actual=None
                if step=='construct':actual=fields
                elif step in('reply_poll_before','reply_poll_after'):
                    p=one('ONESHOT_CALL');i=bytes.fromhex(p['input_hex']);o=bytes.fromhex(p['output_hex'])
                    assert i[:8]==b'HRONQ001'and U(i,8)==4 and U(i,32)==cells[0]
                    assert p['code']==len(o)==80 and o[:8]==b'HRONR001'
                    actual={3:'pending',4:'ok',5:'closed'}[U(o,8)]
                elif step in('queue_poll_before','send_queue','take_queue'):
                    op=5 if step=='send_queue'else 8
                    found=[x for x in block if x['event']=='MPSC_CALL'and U(bytes.fromhex(x['input_hex']),8)==op]
                    assert len(found)==1
                    p=found[0];i=bytes.fromhex(p['input_hex']);o=bytes.fromhex(p['output_hex'])
                    assert p['code']==len(o)==128 and i[:8]==b'HRCMUQ01'and o[:8]==b'HRCMUR01'and U(i,40)==cells[1]
                    if step=='send_queue':actual={0:'sent',2:'closed'}[U(o,8)]
                    elif step=='queue_poll_before':assert U(o,8)==1;actual='pending'
                    else:assert U(o,8)==0 and U(o,40)==request['address'];actual='request'
                elif step=='take_request':
                    p=bytes.fromhex(one('REQUEST_TAKE')['output_hex'])
                    assert len(p)==80 and p[:8]==b'HRSWFR01'and p[32:]==rq and U(p,16)==request['address']
                    actual=dict(control_generation=U(p,64),cancellation_none=U(p,56)==0,wire=wire)
                elif step=='send_reply':
                    p=one('REPLY_SEND');o=bytes.fromhex(p['output_hex'])
                    assert o[:8]==b'HROSNR01'and len(o)==80
                    actual={1:'sent',2:'closed'}[U(o,8)]
                    if U(o,8)==2:assert U(o,24)==p['result'];dropped('worker_result.unit')
                elif step=='take_reply_value':
                    o=bytes.fromhex(one('RESULT_TAKE')['output_hex']);assert len(o)==64 and o[:8]==b'HRWRFR01'
                    assert o[32:]==b'HRWRV001'+struct.pack('<3Q',1,0,0)
                elif step in('reply_drop_before','reply_drop_after'):dropped('reply.rx')
                elif step in('queue_close_before','drop_queue_rx'):dropped('queue.rx')
                elif step=='drop_request':dropped('worker_request')
                elif step=='drop_message':dropped('server_message')
                elif step=='drop_reply_value':dropped('worker_result.unit')
                elif step=='queue_cleanup':dropped('queue.tx')
                else:raise AssertionError((cid,'unknown step',step))
                assert actual==row['result'],(cid,step,actual,row)
                events=row['events'];assert all(e['kind']in('clone','drop','wake','wake_by_ref')and e['waker']in(0,1)for e in events)
                all_events.extend(events);steps.append(dict(step=step,result=actual,events=events));block=[]
            wakers=pin(folder/('case-'+str(cid)+'.wakers.bin'));observed=[]
            for kind,cell in struct.iter_unpack('<2Q',wakers):
                assert cell in cells;observed.append(dict(kind={1:'clone',2:'drop',3:'wake_by_ref',4:'wake'}[kind],waker=cells.index(cell)))
            assert all_events==observed;totals['wakers']+=len(observed)
            typed=pin(folder/('case-'+str(cid)+'.typed.bin'));stack=[];msg=[];req=[];unit=[]
            for stage,tag,desc,arena,hias,effects in struct.iter_unpack('<6Q',typed):
                if stage==1:
                    assert hias==effects==0;stack.append((tag,desc,arena));totals['typed_callbacks']+=1
                    if tag==12:msg.append(desc)
                    if tag in(11,13):req.append(tag)
                    if tag in(14,15):unit.append(tag)
                else:
                    assert stage==2 and stack.pop()==(tag,desc,arena)and hias==effects+1
                    if tag==11:assert(hias,effects)==(3,2)
                    if tag in(13,15):assert(hias,effects)==(2,1)
                    if tag in(12,14):assert(hias,effects)==(1,0)
                    totals['typed_hia']+=hias;totals['typed_effects']+=effects
            assert not stack and msg==[message['address']]
            assert req==[13 if case['finish']=='take_ok'else 11]and len(unit)==int(case['finish']=='take_ok')
            released=[r for r in rows if r['event']=='ALL_RELEASED'];assert len(released)==1 and released[0]['fd_sets_balanced']and released[0]['all_native_guarded_allocations_retired']
            reconstructed.append(dict(name=case['name'],rows=steps))
        assert reconstructed==wanted
        assert totals['typed_callbacks']==child['actual_typed_callbacks']==392
        assert totals['typed_hia']==child['actual_typed_hia_entries']==992 and totals['typed_effects']==600
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
            assert value['trace']==trace and value['status']=='PASS_FINITE_ACTUAL_WORKER_OWNERS'
            assert value['real_runtime']=='current_thread'and value['real_spawned_task']and not value['registration_some_qualified']and not value['complete_worker_qualified']
            result_rows=[];step=None;events=[];refs=[0,0];addresses={};polls=0;outer=0;base_drops=0;thread=None
            for r in trace:
                if thread is None:thread=r['thread']
                assert r['thread']==thread
                e=r['event'];detail=r['details'];metrics['trace_records']+=1
                if e=='base_create':
                    i=detail['waker'];assert i in(0,1)and i not in addresses;addresses[i]=detail['raw_address'];refs[i]+=1
                elif e=='waker':
                    i=detail['waker'];kind=detail['kind'];assert detail['raw_address']==addresses[i]
                    if kind=='clone':refs[i]+=1;metrics['clones']+=1
                    elif kind in('drop','wake'):
                        refs[i]-=1;metrics['drops'if kind=='drop'else'consuming_wakes']+=1
                    else:assert kind=='wake_by_ref';metrics['wake_by_ref']+=1
                    assert refs[i]>=0
                    if r['phase']=='base_cleanup':assert kind=='drop';base_drops+=1;metrics['base_drops']+=1
                    else:assert step==r['step'];events.append(dict(kind=kind,waker=i))
                elif e=='operation_begin':assert step is None;step=r['step'];events=[]
                elif e=='operation_end':
                    assert step==r['step'];result_rows.append(dict(step=step,result=detail,events=events));step=None;events=[]
                elif e=='channel_poll_begin':polls+=1;assert detail['real_context_present']is True and detail['observer_is_context']is False
                elif e=='channel_poll_end':assert isinstance(detail['ready'],bool)
                elif e=='outer_poll_begin':outer+=1
                elif e=='outer_poll_end':assert detail==dict(ready=True)
                else:assert e in('base_cleanup_begin','base_cleanup_end')
            assert step is None and refs==[0,0]and base_drops==2 and outer==1 and len(addresses)==2
            canonical=dict(name=name,rows=result_rows);assert canonical==value['canonical']
            assert polls==value['actual_channel_polls']and outer==value['actual_outer_task_polls']
            assert value['base_creates']==[1,1]
            metrics['channel_polls']+=polls;metrics['outer_polls']+=outer;answers.append(canonical);completed.add(name);current=None
    assert current is None and len(answers)==len(cases)==72 and len(completed)==72
    return answers,metrics
