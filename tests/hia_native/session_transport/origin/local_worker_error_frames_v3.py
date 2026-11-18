#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reconstruct LocalWorkerError140 from complete actual Native and Original captures."""
from pathlib import Path
import collections,json,struct
D=Path('/home/qq/hepta-http-transport-bd947-v1')
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
def native_captures(cases,base):
    pin=base.pin
    build=base.admit_callable(D/'local-worker-error-callable-build-v1',
        '903900344b8840fd017dd09b51e288297081395bf1f614a6f921db7fc7ac41b9',
        D/'local-worker-error-callable-build-v1.external.json',
        '312a647f6c28f3f878a60b997c0e0731630deff25d28ed1e61802c6d3ffdcbb4','1a1eb7fa82d-392-432b')
    root=D/'local-worker-error-native-v2'
    result=json.loads(pin(root/'result.json','1d9bd9a7c973fe43dbfae5403d1ec14379e68084988f45c0ada8ff4db8671409'))
    ext=json.loads(pin(D/'local-worker-error-native-v2.external.json','46e6b8628dab649f67456092620cff397d56671ca0c2f92cd0ec3ba3e094ab4b'))
    out,err=base.durable(ext,'1a1eb8e7ea4-392-433e');assert not err
    assert json.loads(out)=={k:v for k,v in result.items()if k not in('processes','source_pins','retained_files')}
    assert result['status']=='PASS_FINITE_NATIVE_LOCAL_WORKER_ERROR_OWNERS'
    assert result['actual_native_processes']==2 and result['actual_original_executions']==0
    assert not result['full_worker']and not result['actual_join_error']and not result['production_activated']
    for path,want in result['source_pins'].items():
        raw=pin(path,want['sha256']);assert len(raw)==want['bytes']
    for rel,want in result['retained_files'].items():
        raw=pin(root/rel,want['sha256']);assert len(raw)==want['bytes']
    assert json.loads(pin(root/'cases.json'))==cases and len(cases)==140
    corpus=base.module(D/'session_error_corpus_v1.py','9e769bcb9422f2613c2cab6ba088a11d6f9c6298640ba0fc71477d99efc611cc','local_error_child_corpus')
    decoder=base.module(D/'qualify_session_error_project_pairs_v2.py','1b7a5bb22d7b4a28d349ea925f512c89789ab89880a047e7583a3eb5e788633b','local_error_child_decoder')
    canonical=[];metrics=[]
    for mode,process in zip((1,2),result['processes'],strict=True):
        assert process['mode']==mode and process['exit_code']==0 and not process['timed_out']
        folder=root/('mode-'+str(mode));child=json.loads(pin(folder/'result.json'))
        raw=pin(root/('mode-'+str(mode)+'.stdout'),process['stdout_sha256'])
        err=pin(root/('mode-'+str(mode)+'.stderr'),process['stderr_sha256'])
        assert len(raw)==process['stdout_bytes']and len(err)==process['stderr_bytes']==0
        assert json.loads(raw)==child and child['pid']==child['tid']==process['pid']and child['actual_cases']==140
        assert child['status']==result['status']and child['sealed_rx_image']['sha256']==build['artifact']['sha256']
        assert not child['sealed_rx_image']['writable_executable']and child['image_unmapped']
        assert child['actual_original_executions']==child['actual_probe_creations']==0
        physical=[json.loads(line)for line in pin(folder/'physical.calls.jsonl').splitlines()]
        assert len(physical)==2*child['exports_returned']==2*child['exports_attempted']
        groups={i:[]for i in range(1,141)};per_case={i:[]for i in range(1,141)}
        for index in range(0,len(physical),2):
            a,b=physical[index:index+2]
            assert a['event']=='ENTER'and b['event']=='RETURN'and a['ordinal']==b['ordinal']==index//2
            assert {k:v for k,v in a.items()if k!='event'}=={k:v for k,v in b.items()if k not in('event','result')}
            assert a['phase']==a['frame']and a['phase']in per_case;per_case[a['phase']].append(b)
        for row in (json.loads(line)for line in pin(folder/'resources.jsonl').splitlines()):
            assert row['case']in groups;groups[row['case']].append(row)
        wanted=json.loads(pin(folder/'canonical.json','edb766220b4e3354a50329b7b3e2ba094d8c32e6803175ec7400e35f6c167225'))
        totals=collections.Counter();reconstructed=[]
        for cid,case in enumerate(cases,1):
            rows=groups[cid];calls=per_case[cid]
            cells=[x['result']for x in calls if x['name']=='cooperative_scheduler_register']
            scs=[x['result']for x in calls if x['name']=='cooperative_scheduler_create']
            assert len(cells)==len(set(cells))==2 and len(scs)==1;sc=scs[0]
            leases=[r for r in rows if r['event']=='LEASE_OBSERVED'];by_address={};by_identity={}
            creation_by_ordinal={};span_by_ordinal={};poll_by_ordinal={};send_by_ordinal={}
            def role(name):
                found=[r for r in leases if r['role']==name];assert found,(cid,name)
                assert all({k:v for k,v in r.items()if k not in('role','case','event')}==
                    {k:v for k,v in found[0].items()if k not in('role','case','event')}for r in found)
                return found[0]
            error=role('local_worker_error');error_address=error['address']
            native_base=U(bytes.fromhex(error['descriptor_hex']),32)-build['exports']['local_worker_error_drop_entry']
            assert native_base>0 and native_base%4096==0
            spans=[x for x in calls if x['name']=='value_lease_span']
            assert len(spans)==len(leases)
            for r,physical_span in zip(leases,spans,strict=True):
                d=bytes.fromhex(r['descriptor_hex']);p=bytes.fromhex(r['payload_hex'])
                assert len(d)==80 and d[:8]==b'HRVLS001'and len(p)==r['size']==U(d,24)==U(d,48)
                assert U(d,16)==r['payload']and U(d,40)==sc and U(d,56)==child['tid']and U(d,72)==0
                assert U(d,8)//256==cid and r['address']>0 and r['payload']>0
                assert physical_span['args']==[r['address']]and physical_span['result']==[r['payload'],r['size']]
                key=(r['address'],U(d,8));old=by_identity.setdefault(key,(d,p));assert old==(d,p)
                by_address.setdefault(r['address'],set()).add(key);span_by_ordinal[physical_span['ordinal']]=key
            def identity(address,entry=None):
                candidates=list(by_address[address])
                if entry is not None:
                    candidates=[key for key in candidates if U(by_identity[key][0],32)==native_base+build['exports'][entry]]
                assert len(candidates)==1,(cid,address,entry,candidates)
                return candidates[0]
            def payload(address,entry=None):
                return by_identity[identity(address,entry)][1]
            def client_wire(address):
                p=payload(address,'client_message_drop_entry');q=p[32:]
                assert p[:8]==b'HRCMV001'and U(p,16)==len(q)and p[8:16]==p[24:32]==bytes(8)
                assert q[:8]==b'HRCMO001';off,size=U(q,224),U(q,232)
                assert off>=256 and off+size<=len(q);return q[off:off+size].decode()
            def child_shape(address):
                if not address:return None
                p=payload(address)
                if p[:8]==b'HRSERV01':
                    payload(address,'session_error_drop_entry');assert U(p,24)==1
                    value=decoder.decode(p[32:],corpus.KIND_NAMES)
                    return dict(type='session_error',display=value['display'])
                payload(address,'session_event_drop_entry');assert p[:8]==b'HRSVE001'and len(p)==128 and p[80:]==bytes(48)
                assert U(p,32)in(0,1)and U(p,56)in(0,1)
                return dict(type='session_event',tag=U(p,8),http_request_id=U(p,40)if U(p,32)else None,index=U(p,48),
                    retry=dict(seconds=U(p,64),nanos=U(p,72))if U(p,56)else None,
                    wire=client_wire(U(p,16))if U(p,16)else None,responder_present=bool(U(p,24)))
            ep=payload(error_address,'local_worker_error_drop_entry')
            assert ep[:8]==b'HRLWE001'and len(ep)==48 and U(ep,40)==0
            assert (U(ep,8),U(ep,24),U(ep,32))==(case['variant'],case['seconds'],case['nanos'])
            child_address=U(ep,16);spec=case['child'];message=0;event_rx=0
            if spec is None:assert child_address==0
            elif spec['kind']=='session_error':
                assert role('session_error_child')['address']==child_address
                recs=[x for x in rows if x['event']=='SESSION_ERROR_FACTORY'];assert len(recs)==1
                rec=recs[0];i=bytes.fromhex(rec['input_hex']);o=bytes.fromhex(rec['output_hex'])
                assert i[:8]==b'HRSEMQ01'and U(i,8)==2 and U(i,16)==len(i)-64 and U(i,24)==sc
                assert i[64:]==corpus.frame(spec['value'])
                assert o[:8]==b'HRSEMR01'and len(o)==64 and U(o,8)==child_address
                cs=[x for x in calls if x['name']=='session_error_call'];assert len(cs)==1 and cs[0]['result']==64
                assert cs[0]['args'][1]==len(i)and cs[0]['args'][3]==64;totals['session_error_factories']+=1
                creation_by_ordinal[cs[0]['ordinal']]=(child_address,U(i,32))
            else:
                assert spec['kind']=='session_event'and role('event_child')['address']==child_address
                p=payload(child_address,'session_event_drop_entry')
                if spec['message_json']is not None:
                    message=role('client_message_view')['address'];assert U(p,16)==message
                    recs=[x for x in rows if x['event']=='CLIENT_MESSAGE_FACTORY'];assert len(recs)==1
                    rec=recs[0];i=bytes.fromhex(rec['input_hex']);o=bytes.fromhex(rec['output_hex'])
                    assert i[:8]==b'HRCMQ001'and U(i,8)==2 and U(i,16)==len(i)-64 and U(i,24)==sc
                    assert i[64:]==spec['message_json'].encode()and o[:8]==b'HRCMR001'and len(o)==64 and U(o,16)==message
                    cs=[x for x in calls if x['name']=='client_message_call'];assert len(cs)==1 and cs[0]['result']==64
                    assert cs[0]['args'][1]==len(i)and cs[0]['args'][3]==64
                    totals['client_message_factories']+=1;totals['client_hia']+=sum(rec['counts'][:3])
                    creation_by_ordinal[cs[0]['ordinal']]=(message,U(i,32))
                else:assert U(p,16)==0
                if spec['tag']not in(1,6):
                    tx=role('event.reply.tx')['address'];event_rx=role('event.reply.rx')['address'];assert U(p,24)==tx
                else:assert U(p,24)==0
                retry=spec['retry'];http=spec['http_request_id']
                expected=b'HRSVE001'+struct.pack('<15Q',spec['tag'],message,U(p,24),int(http is not None),http or 0,spec['index'],
                    int(retry is not None),retry['seconds']if retry else 0,retry['nanos']if retry else 0,0,0,0,0,0,0)
                assert p==expected
            shape=dict(variant=U(ep,8),seconds=U(ep,24),nanos=U(ep,32),child=child_shape(child_address))
            owner_rows=[r for r in rows if r['event']=='LOCAL_ERROR_FACTORY']
            owner_calls=[r for r in calls if r['name']=='local_worker_error_create']
            assert len(owner_rows)==len(owner_calls)
            good=[]
            for r,c in zip(owner_rows,owner_calls,strict=True):
                i=bytes.fromhex(r['input_hex']);o=bytes.fromhex(r['output_hex']);counts=r['counts'];cap=r['capacity']
                assert len(i)==64 and i[:8]==b'HRLWQ001'and U(i,16)==sc and U(i,24)==U(bytes.fromhex(error['descriptor_hex']),8)
                assert U(i,32)==child_address and U(i,40)==case['seconds']and U(i,48)==case['nanos']and U(i,56)==0
                assert c['args'][1]==64 and c['args'][3]==cap and c['result']==r['code']and len(o)==80 and len(counts)==3
                totals['error_owner_hia']+=counts[0];totals['error_child_views']+=counts[1];totals['error_value_creates']+=counts[2]
                if cap<64:
                    assert cap in(0,63)and r['code']==0xfffffffe and o==b'\xa9'*80 and counts==[1,0,0]
                    totals['capacity_refusals']+=1
                elif r['code']==0xffffffff:
                    assert child_address and U(i,8)==(3 if spec['kind']=='session_event'else 2)
                    assert o==b'\xa9'*80 and counts==[2,1,0];totals['wrong_type_refusals']+=1
                else:
                    assert cap==r['code']==64 and U(i,8)==case['variant']and o[:8]==b'HRLWR001'and o[64:]==b'\xa9'*16
                    assert list(struct.unpack_from('<7Q',o,8))==[error_address,case['variant'],child_address,case['seconds'],case['nanos'],U(i,24),0]
                    assert counts==([3,1,1]if child_address else[2,0,1]);good.append(r)
                    creation_by_ordinal[c['ordinal']]=(error_address,U(i,24))
            assert len(good)==1;totals['error_factories']+=1
            drops=[r for r in rows if r['event']=='LOCAL_ERROR_DROP_INPUT'];assert len(drops)==1
            assert bytes.fromhex(drops[0]['input_hex'])==b'HRTDQ001'+struct.pack('<7Q',error_address,U(bytes.fromhex(error['descriptor_hex']),8),sc,48,0,0,0)+ep
            oneshot_contexts={}
            for r in leases:
                p=bytes.fromhex(r['payload_hex'])
                if p[:8]==b'HROHL001':
                    assert len(p)==32 and U(p,8)in(1,2);payload(r['address'],'owned_oneshot_handle_drop_entry')
                    key=(U(p,16),U(p,24));roles=oneshot_contexts.setdefault(key,{})
                    assert U(p,8)not in roles or roles[U(p,8)]==r['address'];roles[U(p,8)]=r['address']
            creates=[x for x in calls if x['name']=='oneshot_create']
            assert len(creates)==len(oneshot_contexts)==(int(bool(event_rx))+int(case['route']!='direct_drop'))
            for c in creates:
                assert c['args'][0]==sc and (c['result'],c['args'][1])in oneshot_contexts
                assert set(oneshot_contexts[(c['result'],c['args'][1])])=={1,2}
            totals['oneshot_channels']+=len(creates)
            poll_rows=[r for r in rows if r['event']=='ONESHOT_CALL']
            poll_calls=[r for r in calls if r['name']=='oneshot_call']
            selects=[r for r in rows if r['event']=='SELECT_POLL_TASK']
            assert len(poll_rows)==len(poll_calls)==len(selects)
            current=0;poll_index=0
            for c in calls:
                name=c['name']
                if name=='cooperative_scheduler_next':
                    if c['result']:assert c['result']in cells;current=c['result']
                elif name=='cooperative_scheduler_finish':
                    assert c['args'][:2]==[sc,current]and c['result']==0
                    if c['args'][2]==0:totals['poll_task_selections']+=1
                    else:assert c['args'][2]==1
                    current=0
                elif name=='oneshot_call':
                    r=poll_rows[poll_index];sel=selects[poll_index];poll_index+=1
                    i=bytes.fromhex(r['input_hex']);o=bytes.fromhex(r['output_hex'])
                    assert len(i)==len(o)==80 and i[:8]==b'HRONQ001'and o[:8]==b'HRONR001'
                    assert U(i,8)==4 and U(i,16)==U(o,16)and i[40:]==bytes(40)and U(i,24)==0
                    assert U(i,32)==cells[r['waker']]==current==sel['cell']==sel['current']
                    assert sel['waker']==r['waker']and c['args'][0]==r['context']
                    assert (r['context'],U(i,16))in oneshot_contexts
                    assert c['args'][2]==c['args'][4]==c['result']==r['code']==80
                    assert U(o,8)in(3,4,5);poll_by_ordinal[c['ordinal']]=r
            assert poll_index==len(poll_rows);totals['oneshot_calls']+=poll_index
            physical_drops=[x['args'][0]for x in calls if x['name']=='value_lease_drop']
            en=[x['address']for x in rows if x['event']=='DROP_ENTER'];ex=[x['address']for x in rows if x['event']=='DROP_RETURN']
            assert physical_drops==en==ex and all(x['result']==0 for x in calls if x['name']=='value_lease_drop')
            totals['explicit_drops']+=len(en)
            creates=[x for x in calls if x['name']=='value_lease_create'];totals['explicit_creates']+=len(creates)
            for c in creates:
                key=(c['result'],c['args'][2]);d,p=by_identity[key]
                assert c['args'][1:]==[len(p),U(d,8),U(d,32),sc]
                creation_by_ordinal[c['ordinal']]=key
            worker_result=0
            if case['route']!='direct_drop':
                worker_result=role('worker_result.error')['address']
                rp=payload(worker_result,'worker_result_drop_entry')
                assert rp==b'HRWRV001'+struct.pack('<3Q',1,1,error_address)
            replies=[r for r in rows if r['event']=='REPLY_SEND'];send_calls=[x for x in calls if x['name']=='owned_oneshot_send']
            assert len(replies)==len(send_calls)==int(bool(worker_result))
            for r,c in zip(replies,send_calls,strict=True):
                o=bytes.fromhex(r['output_hex']);assert len(o)==80 and o[:8]==b'HROSNR01'and U(o,8)in(1,2)
                assert c['args'][0]==role('worker.reply.tx')['address']and c['args'][1]==r['result']==worker_result
                assert c['result']==c['args'][3]==80 and U(o,24)==(worker_result if U(o,8)==2 else 0)
                send_by_ordinal[c['ordinal']]=r
            totals['reply_sends']+=len(replies)
            takes=[r for r in rows if r['event']=='WORKER_RESULT_TAKE'];take_calls=[x for x in calls if x['name']=='worker_result_take']
            assert len(takes)==len(take_calls)==int(case['route']=='reply_take')
            for r,c in zip(takes,take_calls,strict=True):
                o=bytes.fromhex(r['output_hex']);assert len(o)==64 and o[:8]==b'HRWRFR01'and U(o,16)==worker_result and U(o,24)==32
                assert o[32:]==payload(worker_result,'worker_result_drop_entry')and c['args'][0]==worker_result and c['args'][2]==c['result']==64
            totals['result_takes']+=len(takes)
            # Bind each descriptor to address AND generation. Every creation is
            # tied to its actual physical call, and every subsequent span must
            # name the currently live identity. Reuse requires actual prior Drop
            # or consuming Take/Send; no mutable descriptor bytes are accepted.
            live={};created=[];retired=[];buffered={};closed=set()
            def current(address):
                assert address in live,(cid,'not live',address)
                return live[address]
            def retire(address,take=False):
                key=current(address);d,p=by_identity[key]
                retired.append(key)
                if p[:8]==b'HRLWE001':
                    if U(p,16):retire(U(p,16))
                elif p[:8]==b'HRWRV001':
                    assert U(p,8)==U(p,16)==1
                    if not take:retire(U(p,24))
                elif p[:8]==b'HRSVE001':
                    if U(p,16):retire(U(p,16))
                    if U(p,24):retire(U(p,24))
                elif p[:8]==b'HROHL001':
                    context=U(p,16)
                    if U(p,8)==2:
                        closed.add(context)
                        value=buffered.get(context);buffered[context]=None
                        if value is not None:retire(value)
                else:assert p[:8]in(b'HRSERV01',b'HRCMV001'),(cid,p[:8])
                assert live.pop(address)==key
            for c in calls:
                ordinal=c['ordinal'];name=c['name']
                if ordinal in creation_by_ordinal:
                    key=creation_by_ordinal[ordinal];address,generation=key
                    assert key in by_identity and key not in created and address not in live,(cid,'creation overlaps live',key)
                    if any(old[0]==address for old in created):totals['descriptor_address_reuses']+=1
                    live[address]=key;created.append(key)
                if ordinal in span_by_ordinal:
                    key=span_by_ordinal[ordinal];assert current(key[0])==key,(cid,'span stale',key)
                if name=='oneshot_create':
                    assert c['result']not in buffered;buffered[c['result']]=None
                elif name=='oneshot_call':
                    record=poll_by_ordinal[ordinal];o=bytes.fromhex(record['output_hex']);context=record['context']
                    assert context in buffered
                    if U(o,8)==4:
                        assert buffered[context]==U(o,24)and U(o,24)in live;buffered[context]=None
                    else:assert buffered[context]is None
                elif name=='owned_oneshot_send':
                    record=send_by_ordinal[ordinal];o=bytes.fromhex(record['output_hex'])
                    sender,value=c['args'][:2];sender_key=current(sender);p=by_identity[sender_key][1]
                    assert p[:8]==b'HROHL001'and U(p,8)==1;current(value);context=U(p,16)
                    assert context in buffered and buffered[context]is None
                    if U(o,8)==1:
                        assert context not in closed;buffered[context]=value
                    else:assert U(o,8)==2 and context in closed
                    retire(sender)
                elif name=='value_lease_drop':retire(c['args'][0])
                elif name=='worker_result_take':retire(c['args'][0],take=True)
            assert not live and set(created)==set(by_identity)and collections.Counter(retired)==collections.Counter(created)
            assert all(value is None for value in buffered.values())
            steps=[];block=[];all_events=[]
            def one(kind):
                found=[x for x in block if x['event']==kind];assert len(found)==1,(cid,kind,len(found));return found[0]
            def dropped(address):
                a=[x['address']for x in block if x['event']=='DROP_ENTER'];b=[x['address']for x in block if x['event']=='DROP_RETURN']
                assert a==b==[address],(cid,address,a,b)
            for r in rows:
                if r['event']!='CANONICAL_STEP':block.append(r);continue
                step=r['step'];value=None
                if step=='construct_child':
                    value=child_shape(child_address)
                    if spec is not None:
                        assert any(x['event']==('SESSION_ERROR_FACTORY'if spec['kind']=='session_error'else'LEASE_OBSERVED')for x in block)
                elif step=='construct_error':assert any(x is good[0]for x in block);value=shape
                elif step in('poll_event_reply_before','poll_event_reply_after','poll_result_before','poll_result_after'):
                    rec=one('ONESHOT_CALL');o=bytes.fromhex(rec['output_hex'])
                    if step.startswith('poll_event'):assert rec['waker']==1 and rec['context']==U(payload(event_rx,'owned_oneshot_handle_drop_entry'),16)
                    else:assert rec['waker']==0 and rec['context']==U(payload(role('worker.reply.rx')['address'],'owned_oneshot_handle_drop_entry'),16)
                    if step.endswith('before'):assert U(o,8)==3;value='pending'
                    elif step=='poll_event_reply_after':assert U(o,8)==5;value='closed'
                    else:
                        assert U(o,8)==4 and U(o,24)==worker_result
                        assert role('received_worker_result')['address']==worker_result
                        value=dict(status='error',error=shape)
                elif step=='construct_result':assert role('worker_result.error')in block;value=dict(status='error')
                elif step=='send_result':
                    o=bytes.fromhex(one('REPLY_SEND')['output_hex']);value={1:'sent',2:'closed'}[U(o,8)]
                elif step=='take_result':
                    o=bytes.fromhex(one('WORKER_RESULT_TAKE')['output_hex']);assert U(o,56)==error_address;value=dict(error=shape)
                elif step=='drop_error':dropped(error_address)
                elif step in('drop_result','drop_rejected_result'):dropped(worker_result)
                elif step in('drop_result_rx_before','drop_result_rx_after','drop_buffered_result_rx'):dropped(role('worker.reply.rx')['address'])
                elif step=='drop_event_reply_after':dropped(event_rx)
                else:raise AssertionError((cid,step))
                assert r['result']==value,(cid,step,r['result'],value)
                all_events.extend(r['events']);steps.append(dict(step=step,result=value,events=r['events']));block=[]
            actual_steps=[r['step']for r in steps]
            expected=['construct_child']+(['poll_event_reply_before']if event_rx else[])+['construct_error']
            route=case['route']
            if route=='direct_drop':expected+=['drop_error']
            else:
                expected+=['poll_result_before']+(['drop_result_rx_before']if route=='closed_send'else[])+['construct_result','send_result']
                if route=='closed_send':expected+=['drop_rejected_result']
                elif route=='buffered_cancel':expected+=['drop_buffered_result_rx']
                else:expected+=['poll_result_after']+(['take_result','drop_error']if route=='reply_take'else['drop_result'])+['drop_result_rx_after']
            if event_rx:expected+=['poll_event_reply_after','drop_event_reply_after']
            assert actual_steps==expected,(cid,actual_steps,expected)
            wakers=pin(folder/('case-'+str(cid)+'.wakers.bin'));observed=[]
            for kind,cell in struct.iter_unpack('<2Q',wakers):
                assert cell in cells and kind in(1,2,3,4)
                name={1:'clone',2:'drop',3:'wake_by_ref',4:'wake'}[kind]
                observed.append(dict(kind=name,waker=cells.index(cell)));totals['waker_'+name]+=1
            assert observed==all_events
            typed=pin(folder/('case-'+str(cid)+'.typed.bin'));stack=[];starts=[];local=[];results=[];children=[];messages=[]
            for stage,tag,desc,arena,hias,effects in struct.iter_unpack('<6Q',typed):
                assert desc in by_address
                if stage==1:
                    assert hias==effects==0 and len(starts)<len(retired)and retired[len(starts)][0]==desc
                    key=retired[len(starts)];stack.append((tag,desc,arena));starts.append(key);totals['typed_callbacks']+=1
                    if tag==16:local.append(desc)
                    if tag in(14,15):results.append((tag,desc))
                    if tag in(2,8)and desc==child_address:children.append(desc)
                    if tag==10:messages.append(desc)
                else:
                    assert stage==2 and stack.pop()==(tag,desc,arena)and hias==effects+1
                    if tag==16:assert effects==int(bool(child_address))
                    if tag in(14,15):assert(hias,effects)==(2,1)
                    totals['typed_hia']+=hias;totals['typed_effects']+=effects
            assert not stack and starts==retired and collections.Counter(starts)==collections.Counter(by_identity.keys())
            assert local==[error_address]and children==([child_address]if child_address else[])and messages==([message]if message else[])
            assert results==([(15 if route=='reply_take'else 14,worker_result)]if worker_result else[])
            released=[r for r in rows if r['event']=='ALL_RELEASED'];assert len(released)==1
            assert released[0]['fd_sets_balanced']and released[0]['all_native_guarded_allocations_retired']
            assert [x['args']for x in calls if x['name']=='cooperative_scheduler_retire']==[[c]for c in cells]
            assert calls[-1]['name']=='cooperative_scheduler_destroy'and calls[-1]['args']==[sc]and calls[-1]['result']==0
            reconstructed.append(dict(name=case['name'],rows=steps))
        assert reconstructed==wanted
        expected=dict(error_factories=140,error_owner_hia=400,error_child_views=112,error_value_creates=140,
            session_error_factories=70,client_message_factories=10,client_hia=40,
            explicit_creates=436,explicit_drops=254,oneshot_channels=142,oneshot_calls=228,
            reply_sends=112,result_takes=28,typed_callbacks=656,typed_hia=1598,typed_effects=942,
            waker_clone=142,waker_drop=142,waker_wake_by_ref=114,waker_wake=0,
            capacity_refusals=6,wrong_type_refusals=2,poll_task_selections=78)
        for key,want in expected.items():assert totals[key]==want,(mode,key,totals[key],want)
        mapping=dict(error_factories='actual_error_factories',error_owner_hia='actual_error_owner_hia_entries',
            error_child_views='actual_error_child_views',error_value_creates='actual_error_value_creates',
            session_error_factories='actual_session_error_factories',client_message_factories='actual_client_message_factories',
            client_hia='actual_client_message_hia_entries',explicit_creates='actual_explicit_value_creates',
            explicit_drops='actual_explicit_value_drops',oneshot_channels='actual_oneshot_channels',oneshot_calls='actual_oneshot_calls',
            reply_sends='actual_owned_reply_sends',result_takes='actual_worker_result_takes',typed_callbacks='actual_typed_callbacks',
            typed_hia='actual_typed_hia_entries',typed_effects='actual_typed_effects',
            waker_clone='actual_waker_clones',waker_drop='actual_waker_drops',waker_wake_by_ref='actual_wakes_by_ref',
            waker_wake='actual_consuming_wakes',capacity_refusals='capacity_refusals',wrong_type_refusals='wrong_type_refusals',
            poll_task_selections='actual_poll_task_selections')
        for key,field in mapping.items():assert totals[key]==child[field]
        totals['physical_calls']=len(physical)//2;canonical.append(reconstructed);metrics.append(dict(totals))
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
            assert value['trace']==trace and value['status']=='PASS_FINITE_ACTUAL_LOCAL_WORKER_ERROR'
            assert value['real_runtime']=='current_thread'and value['real_spawned_task']
            assert not value['actual_typed_destructor_callbacks_observed']and not value['whole_worker_qualified']and not value['production_activated']
            assert not value['local_worker_error_formatting_qualified']and not value['join_error_qualified']
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
                    assert active_poll is None and step==r['step']and detail['operation']in('event_oneshot_rx','result_oneshot_rx')
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
    assert current is None and len(answers)==len(cases)==140 and len(completed)==140
    return answers,metrics
