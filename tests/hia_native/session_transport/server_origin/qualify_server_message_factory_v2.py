#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual ServerMessage factories, immutable ValueLease and owned oneshot custody."""
from pathlib import Path
import argparse,ctypes,hashlib,importlib.util,json,os,stat,struct,subprocess,threading,time,traceback
M=Path('/home/qq/hepta-server-message-codec-bd947-v1')
OUT=M/'message-factory-pairs-v2'
BUILD=M/'server-message-callable-build-v3'
BUILD_SHA='5ad5308481a4214484c1f1ea63cae26edbaaa7e245d505a56f8a4eed6e06f846'
EXTERNAL_SHA='5a450c303dc7cdfd50e16b1b1518a77485e3f4119cbc07751c64c9e8205cd931'
MACHINE_SHA='a8eab79bdd39eef870e86be5a2d4853b24e0e00b1c69f8083a83f9ca7600aa6a'
INPUTS_SHA='14a5975dbef33429f656635cf2ba79b516af8c6dd6b5b75f9bac35319e22bad8'
Q=ctypes.c_uint64
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
U=lambda b,at=0:struct.unpack_from('<Q',b,at)[0]
word=lambda p,at=0:Q.from_address(p+at).value
KIND={'Request':1,'Response':2,'Notification':3,'Error':4}
KINDS={v:k for k,v in KIND.items()}
VARIANTS={
1:('PingRequest','CreateMessageRequest','ListRootsRequest','ElicitRequest','CustomRequest'),
2:('DiscoverResult','InitializeResult','CompleteResult','GetPromptResult','ListPromptsResult','ListResourcesResult','ListResourceTemplatesResult','ReadResourceResult','SubscriptionsListenResult','ListToolsResult','ElicitResult','CreateTaskResult','GetTaskResult','CallToolResult','InputRequiredResult','TaskAckResult','EmptyResult','CustomResult'),
3:('CancelledNotification','ProgressNotification','LoggingMessageNotification','ResourceUpdatedNotification','ResourceListChangedNotification','ToolListChangedNotification','PromptListChangedNotification','SubscriptionsAcknowledgedNotification','TaskStatusNotification','CustomNotification'),
4:('ErrorData',)}
def module(path,digest,name):
    raw=Path(path).read_bytes();assert SHA(raw)==digest,(str(path),SHA(raw))
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def mapped(address):
    for line in Path('/proc/self/maps').read_text().splitlines():
        low,high=[int(x,16)for x in line.split()[0].split('-')]
        if low<=address<high:return line.split()[1]
    return None
def make_cases(admit):
    folder=M/'message-pairs-v4'
    report=json.loads(admit.pin(folder/'result.json','6f775fae8fcf6a2920ffee72fdf4d32afd0a15290461707a028bfecd5a347216'))
    assert report['status']=='PASS' and report['paired_requests']==report['matching_pairs']==6441 and not report['mismatches']
    records=[json.loads(line)for line in admit.pin(folder/'cases.jsonl').splitlines()]
    answers=[json.loads(line)for line in admit.pin(folder/'original.stdout',report['original_process']['stdout_sha256']).splitlines()]
    assert len(records)==len(answers)==6441
    selected={};decoded={};cases=[]
    for row,answer in zip(records,answers,strict=True):
        if answer['status']!='OK':continue
        if row['op']==2:
            sel=row['selected'];kind=1 if sel<=5 else 3 if sel<=15 else 2
            variant=sel if kind==1 else sel-5 if kind==3 else sel-15
            assert answer['variant']==VARIANTS[kind][variant-1]
            selected.setdefault((kind,variant),row)
        elif row['op']==1:
            kind=KIND[answer['kind']];variant=VARIANTS[kind].index(answer['variant'])+1
            decoded.setdefault((kind,variant),row)
    assert set(selected)=={(k,v)for k in (1,2,3)for v in range(1,len(VARIANTS[k])+1)}
    def add(label,operation,kind,variant,body,id_raw=None,legacy=False,positive=True):
        if isinstance(body,str):body=body.encode()
        cases.append(dict(label=label,operation=operation,kind=kind,variant=variant,body_hex=body.hex(),
            id_hex=b''.hex()if id_raw is None else id_raw.encode().hex(),legacy=legacy,positive=positive))
    for (kind,variant),row in sorted(selected.items()):
        add('construct/'+str(kind)+'/'+str(variant),2,kind,variant,bytes.fromhex(row['hex']),None if kind==3 else '0',row['legacy'])
    for (kind,variant),row in sorted(decoded.items()):
        add('decode/'+str(kind)+'/'+str(variant),1,0,0,bytes.fromhex(row['hex']))
    for id_raw in (None,'null','0','"error-id"'):
        add('construct/error/'+str(id_raw),2,4,1,b'{"code":-32603,"message":"m","data":{"x":1}}',id_raw)
    for i,id_raw in enumerate(('""','"id\\u0000"','-9223372036854775808','9223372036854775807',
        '{"$serde_json::private::RawValue":"1"}','0.0','null','9223372036854775808','{}')):
        add('id/request/'+str(i),2,1,1,b'{"method":"ping"}',id_raw,positive=i<5)
        add('id/response/'+str(i),2,2,18,b'null',id_raw,positive=i<5)
    add('decode/required-null-result',1,0,0,b'{"jsonrpc":"2.0","id":0,"result":null}')
    for i,raw in enumerate((b'',b'null',b'{}',b'{"jsonrpc":"2.0","id":null,"result":{}}',b'\xff')):
        add('decode/invalid/'+str(i),1,0,0,raw,positive=False)
    assert len({x['label']for x in cases})==len(cases)
    return cases
def oracle_request(case):
    q=dict(hex=case['body_hex'])
    if case['operation']==1:q['op']='server_message_normalize'
    else:
        q.update(op='server_message_encode',kind=KINDS[case['kind']],variant=VARIANTS[case['kind']][case['variant']-1],legacy=case['legacy'])
        if case['id_hex']:q['id_hex']=case['id_hex']
    return q
def input_frame(case,mode,sc=0,generation=0):
    raw=bytes.fromhex(case['body_hex']);ident=bytes.fromhex(case['id_hex'])
    return b'HSSMQ001'+struct.pack('<11Q',case['operation'],mode,case['kind'],case['variant'],len(raw),len(ident),case['legacy'],sc,generation,0,0)+raw+ident
def expected_spans(raw):
    text=raw.decode();decoder=json.JSONDecoder();assert text[0]=='{'and text[-1]=='}'
    at=1;spans={}
    while at<len(text)-1:
        key,end=decoder.raw_decode(text,at);assert isinstance(key,str)and text[end]==':'
        start=end+1;value,end=decoder.raw_decode(text,start)
        assert key not in spans
        spans[key]=(128+len(text[:start].encode()),len(text[start:end].encode()))
        if end==len(text)-1:at=end
        else:assert text[end]==',';at=end+1
    return spans
def check_projection(raw,case,expected):
    assert raw[:8]==b'HSSMP001'and len(raw)>=130 and U(raw,24)==len(raw)-128 and U(raw,32)==128
    kind=KIND[expected['kind']];variant=VARIANTS[kind].index(expected['variant'])+1
    assert U(raw,8)==kind and U(raw,16)==variant
    assert U(raw,88)==case['operation']and U(raw,96)==case['legacy']and raw[104:128]==bytes(24)
    wire=expected['wire'].encode();assert raw[128:]==wire
    spans=expected_spans(wire)
    for key,at in (('id',40),('method',56),('params'if kind in (1,3)else'result'if kind==2 else'error',72)):
        assert (U(raw,at),U(raw,at+8))==spans.get(key,(0,0)),(case['label'],key)
    return kind,variant
def run_original(binary,cases,report):
    requests=[oracle_request(case)for case in cases]
    wire=b''.join((json.dumps(q,separators=(',',':'))+'\n').encode()for q in requests)
    (OUT/'original.stdin').write_bytes(wire);process=None;timed=False;started=time.monotonic()
    with (OUT/'original.stdin').open('rb',buffering=0)as inp,(OUT/'original.stdout').open('xb',buffering=0)as out,(OUT/'original.stderr').open('xb',buffering=0)as err:
        try:
            process=subprocess.Popen([binary],cwd=OUT,stdin=inp,stdout=out,stderr=err)
            row=dict(pid=process.pid,pgid=os.getpgid(process.pid),command=[binary],started=True)
            report['actual_original_processes']+=1;report['original']=row
            (OUT/'original-process-start.json').write_bytes(J(row))
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:timed=True;process.kill();process.wait();raise
        finally:
            if process:
                if process.poll()is None:process.kill();process.wait()
                row.update(exit_code=process.returncode,reaped=True,timed_out=timed,elapsed_seconds=time.monotonic()-started,input_offset=inp.tell())
                (OUT/'original-process-finish.json').write_bytes(J(row))
    out=(OUT/'original.stdout').read_bytes();err=(OUT/'original.stderr').read_bytes()
    row.update(stdin_bytes=len(wire),stdin_sha256=SHA(wire),stdout_bytes=len(out),stdout_sha256=SHA(out),stderr_bytes=len(err),stderr_sha256=SHA(err))
    assert not timed and process.returncode==0 and not err and row['input_offset']==len(wire)
    actual=[json.loads(line)for line in out.splitlines()];assert len(actual)==len(cases)
    for case,answer in zip(cases,actual,strict=True):
        assert answer['status']in('OK','ERROR'),(case['label'],answer)
        if case['positive']:assert answer['status']=='OK',(case['label'],answer)
    row['complete_capture']=True;return actual,row
def run_child(mode,manifest_sha):
    os.umask(0o077);assert mode in(1,2);folder=OUT/('mode-'+str(mode));folder.mkdir(mode=0o700)
    manifest_raw=(OUT/'fixture.json').read_bytes();assert SHA(manifest_raw)==manifest_sha
    manifest=json.loads(manifest_raw);assert manifest['build_sha256']==BUILD_SHA
    cases=manifest['cases'];answers=manifest['answers']
    assert SHA((OUT/'original.stdout').read_bytes())==manifest['original_stdout_sha256']
    report=dict(schema='hepta.server-message.factory-child.v2',status='RUNNING',mode=mode,pid=os.getpid(),tid=threading.get_native_id(),
        projection_calls=0,matching_projections=0,owned_cases=0,actual_message_creations=0,capacity_refusals=0,
        owner_entries=0,controller_entries=0,parser_entries=0,emitter_entries=0,lease_creates=0,
        typed_callbacks=0,typed_hia_entries=0,typed_effects=0,waker_callbacks=0,owned_sends=0,closed_returns=0,
        channel_calls=0,channel_creates=0,automatic_channel_retirements=0,original_ownership_paired=False,
        real_wire_original_paired=True,production_activated=False,whole_runtime_replaced=False)
    mod=module(M/'server_message_machine_v1.py',MACHINE_SHA,'sm_machine')
    machine=mod.Machine(folder,report,BUILD_SHA);journal=(folder/'resources.jsonl').open('xb',buffering=0)
    started=time.monotonic();canonical=[]
    def log(value):journal.write((json.dumps(value,sort_keys=True,ensure_ascii=True)+'\n').encode())
    def invoke(case,mode_value,capacity,sc=0,generation=0,output_size=65552):
        wire=input_frame(case,mode_value,sc,generation);source=ctypes.create_string_buffer(wire,len(wire))
        out=ctypes.create_string_buffer(output_size);counts=ctypes.create_string_buffer(48);ctypes.memset(out,169,output_size)
        log(dict(event='MESSAGE_ENTER',label=case['label'],mode=mode_value,capacity=capacity,input_hex=wire.hex()))
        code=machine.call('server_message_call',ctypes.addressof(source),len(wire),ctypes.addressof(out),capacity,ctypes.addressof(counts))
        numbers=struct.unpack('<6Q',counts.raw)
        log(dict(event='MESSAGE_RETURN',label=case['label'],code=code,output_hex=out.raw.hex(),counts=list(numbers)))
        assert source.raw==wire and numbers[-1]==0
        for key,value in zip(('owner_entries','controller_entries','parser_entries','emitter_entries','lease_creates'),numbers[:5]):report[key]+=value
        return code,out.raw,numbers
    try:
        for ordinal,(case,answer)in enumerate(zip(cases,answers,strict=True),1):
            report['phase']=ordinal;report['frames']=ordinal
            code,out,counts=invoke(case,1,65536)
            report['projection_calls']+=1
            if answer['status']=='ERROR':assert code==0xffffffff and out==b'\xa9'*len(out)
            else:
                assert code<=65536 and out[code:]==b'\xa9'*(len(out)-code)
                check_projection(out[:code],case,answer)
                for capacity in (127,code-1):
                    rejected,unchanged,ref_counts=invoke(case,1,capacity)
                    assert rejected==0xfffffffe and unchanged==b'\xa9'*len(unchanged)
                    if capacity==127:assert ref_counts==(1,0,0,0,0,0)
                    report['capacity_refusals']+=1
            report['matching_projections']+=1
        good=[(case,answer)for case,answer in zip(cases,answers,strict=True)if answer['status']=='OK']
        for case_id,(case,answer,scenario)in enumerate(((c,a,s)for c,a in good for s in range(4)),1):
            report['phase']=10000+case_id;report['frames']=case_id;fd_before=set(os.listdir('/proc/self/fd'))
            sc=machine.call('cooperative_scheduler_create',case_id,mode);assert sc
            pub_data=(Q*(2*128))();pub=(Q*4)(int.from_bytes(b'HROBS001','little'),ctypes.addressof(pub_data),128,0)
            td_data=(Q*(6*128))();td=(Q*4)(int.from_bytes(b'HRTDO001','little'),ctypes.addressof(td_data),128,0)
            assert machine.call('batch_observer_attach',sc,ctypes.addressof(pub))==0
            assert machine.call('typed_drop_observer_attach',sc,ctypes.addressof(td))==0
            leases={};channels=[];cell=0;logical=[]
            def record(address,role,generation):
                span=machine.call('value_lease_span',address);payload=ctypes.string_at(span.pointer,span.size)
                assert word(address,8)==generation and word(address,40)==sc
                assert mapped(address)and'w'not in mapped(address)and mapped(span.pointer)and'w'not in mapped(span.pointer)
                assert address not in leases
                leases[address]=dict(role=role,payload=span.pointer,generation=generation,bytes=span.size)
                log(dict(event='LEASE_CREATE',case=case_id,role=role,descriptor=address,descriptor_hex=ctypes.string_at(address,80).hex(),payload_pointer=span.pointer,payload_hex=payload.hex()))
                return payload
            generation=case_id*32+31
            code,out,counts=invoke(case,2,63,sc,generation,80)
            assert code==0xfffffffe and out==b'\xa9'*80 and counts==(1,0,0,0,0,0)and td[3]==0
            report['capacity_refusals']+=1
            code,out,counts=invoke(case,2,64,sc,generation,80)
            assert code==64 and out[64:]==b'\xa9'*16 and out[:8]==b'HSSMR001'and counts[4]==1
            address=U(out,24);assert address
            payload=record(address,'message',generation)
            assert word(address,32)==machine.base+machine.exports['server_message_drop_entry']
            assert payload[:8]==b'HSSMV001'and U(payload,8)==len(payload)-32
            kind,variant=check_projection(payload[32:],case,answer)
            assert (U(payload,16),U(payload,24))==(kind,variant)
            assert (U(out,8),U(out,16),U(out,32),U(out,40),U(out,48),U(out,56))==(kind,variant,len(payload)-32,case['operation'],case['legacy'],0)
            assert counts[0]==counts[1]//3+2 and counts[1]==counts[2]*3 and counts[3]==counts[2]
            report['actual_message_creations']+=1
            def drop(value):
                log(dict(event='DROP_ENTER',case=case_id,descriptor=value,role=leases[value]['role']))
                assert machine.call('value_lease_drop',value)==0
                log(dict(event='DROP_RETURN',case=case_id,descriptor=value,role=leases[value]['role']))
                logical.append(dict(action='drop',role=leases[value]['role']))
            def on(context,gen,op,waker=0):
                wire=b'HRONQ001'+struct.pack('<9Q',op,gen,0,waker,0,0,0,0,0)
                source=ctypes.create_string_buffer(wire,len(wire));reply=ctypes.create_string_buffer(80)
                log(dict(event='CHANNEL_ENTER',case=case_id,context=context,input_hex=wire.hex()))
                ret=machine.call('oneshot_call',context,ctypes.addressof(source),80,ctypes.addressof(reply),80)
                assert ret==80 and reply.raw[:8]==b'HRONR001'and U(reply.raw,16)==gen
                log(dict(event='CHANNEL_RETURN',case=case_id,context=context,output_hex=reply.raw.hex()))
                report['channel_calls']+=1;logical.append(dict(action='channel',op=op,status=U(reply.raw,8)))
                return reply.raw
            if scenario:
                context=machine.call('oneshot_create',sc,case_id,ctypes.addressof(pub));assert context
                channels.append((context,word(context,16)));report['channel_creates']+=1
                handles=[]
                for side in (1,2):
                    body=b'HROHL001'+struct.pack('<3Q',side,context,case_id);raw=ctypes.create_string_buffer(body,len(body))
                    desc=machine.call('value_lease_create',ctypes.addressof(raw),len(body),case_id*32+side,machine.base+machine.exports['owned_oneshot_handle_drop_entry'],sc)
                    assert desc and record(desc,'sender'if side==1 else'receiver',case_id*32+side)==body
                    handles.append(desc)
                tx,rx=handles
                if scenario==1:
                    cookie=(Q*1)(case_id);cell=machine.call('cooperative_scheduler_register',sc,ctypes.addressof(cookie),0);assert cell
                    for _ in range(4):
                        selected=machine.call('cooperative_scheduler_next',sc)
                        if selected:assert selected==cell;break
                        assert word(sc,200)==2
                    else:raise AssertionError('first task selection')
                    assert U(on(context,case_id,4,cell),8)==3
                    assert machine.call('cooperative_scheduler_finish',sc,cell,0)==0
                if scenario==2:drop(rx)
                reply=ctypes.create_string_buffer(80);log(dict(event='OWNED_SEND_ENTER',case=case_id,sender=tx,value=address))
                assert machine.call('owned_oneshot_send',tx,address,ctypes.addressof(reply),80)==80
                log(dict(event='OWNED_SEND_RETURN',case=case_id,output_hex=reply.raw.hex()))
                assert reply.raw[:8]==b'HROSNR01'and not mapped(tx)and not mapped(leases[tx]['payload'])
                report['owned_sends']+=1
                if scenario==2:
                    assert U(reply.raw,8)==2 and U(reply.raw,24)==address
                    report['closed_returns']+=1;drop(address)
                elif scenario==3:
                    assert U(reply.raw,8)==1 and U(reply.raw,24)==0;drop(rx)
                else:
                    assert U(reply.raw,8)==1 and U(reply.raw,24)==0
                    for _ in range(4):
                        selected=machine.call('cooperative_scheduler_next',sc)
                        if selected:assert selected==cell;break
                        assert word(sc,200)==2
                    else:raise AssertionError('woken task selection')
                    value=on(context,case_id,4,cell);assert U(value,8)==4 and U(value,24)==address
                    assert machine.call('cooperative_scheduler_finish',sc,cell,1)==0
                    drop(rx);drop(address)
            else:drop(address)
            if cell:
                for _ in range(4):
                    assert machine.call('cooperative_scheduler_next',sc)==0
                    if word(sc,200)==1:break
                    assert word(sc,200)==2
                else:raise AssertionError('scheduler did not idle')
                assert word(cell,32)==1 and machine.call('cooperative_scheduler_retire',cell)==0 and not mapped(cell)
            for context,workspace in channels:
                assert not mapped(context)and not mapped(workspace)
                report['automatic_channel_retirements']+=1
            for desc,info in leases.items():assert not mapped(desc)and not mapped(info['payload']),(case_id,info)
            typed=ctypes.string_at(ctypes.addressof(td_data),td[3]*48);wakers=ctypes.string_at(ctypes.addressof(pub_data),pub[3]*16)
            log(dict(event='OBSERVERS',case=case_id,typed_hex=typed.hex(),wakers_hex=wakers.hex()))
            stack=[];seen=[];arenas=set()
            for stage,tag,desc,arena,hias,effects in struct.iter_unpack('<6Q',typed):
                role=leases[desc]['role'];assert tag==(12 if role=='message'else 3 if role=='sender'else 1)
                if stage==1:
                    assert arena not in arenas and hias==effects==0
                    stack.append((tag,desc,arena));arenas.add(arena);seen.append(role);report['typed_callbacks']+=1
                else:
                    assert stage==2 and stack.pop()==(tag,desc,arena);arenas.remove(arena)
                    assert hias==effects+1
                    if tag==12:assert (hias,effects)==(1,0)
                    report['typed_hia_entries']+=hias;report['typed_effects']+=effects
                logical.append(dict(action='typed',stage=stage,type=tag,role=role,entries=hias,effects=effects))
            assert not stack and not arenas and sorted(seen)==sorted(x['role']for x in leases.values())
            kinds=[]
            for event,token in struct.iter_unpack('<2Q',wakers):
                assert cell and token==cell;kinds.append(event);logical.append(dict(action='waker',kind=event))
            assert kinds==([1,3,2]if scenario==1 else [])
            report['waker_callbacks']+=len(kinds)
            assert machine.call('typed_drop_observer_attach',sc,0)==0 and machine.call('batch_observer_attach',sc,0)==0
            assert machine.call('cooperative_scheduler_destroy',sc)==0 and not mapped(sc)
            assert set(os.listdir('/proc/self/fd'))==fd_before
            canonical.append(dict(label=case['label'],scenario=scenario,kind=kind,variant=variant,logical=logical))
            report['owned_cases']+=1
        report.update(status='PASS_FINITE_SERVER_FACTORY',all_owned_wire_matches_actual_original=True,
            all_owned_storage_retired=True,all_channel_retirement_actual=True,all_file_descriptors_balanced=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        journal.close();machine.close();report['elapsed_seconds']=time.monotonic()-started
        (folder/'canonical.json').write_bytes(J(canonical));(folder/'result.json').write_bytes(J(report))
        print(json.dumps(report,sort_keys=True))
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mode',type=int);parser.add_argument('--fixture-sha');args=parser.parse_args()
    if args.mode is not None:return run_child(args.mode,args.fixture_sha)
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700)
    started=time.monotonic();report=dict(schema='hepta.server-message.factory-pairs.v2',status='RUNNING',
        actual_native_processes=0,actual_original_processes=0,new_compiles=0,
        original_ownership_paired=False,production_activated=False,whole_runtime_replaced=False)
    processes=[];admit=None
    try:
        admit=module(M/'admit_server_message_inputs_v2.py',INPUTS_SHA,'sm_admit')
        admit.pin(__file__);admit.pin(M/'server_message_machine_v1.py',MACHINE_SHA)
        handoff,original,recheck_original=admit.admit_reference()
        build=admit.admit_callable(BUILD,BUILD_SHA,M/'server-message-callable-build-v3.external.json',EXTERNAL_SHA,'1a1eb4113c6-392-4301')
        cases=make_cases(admit);answers,process=run_original(handoff['binary']['path'],cases,report)
        assert report['actual_original_processes']==1;report['original']=process
        report['original_requests']=len(cases);report['original_successes']=sum(x['status']=='OK'for x in answers)
        fixture=dict(build_sha256=BUILD_SHA,original_stdout_sha256=process['stdout_sha256'],cases=cases,answers=answers)
        raw=J(fixture);(OUT/'fixture.json').write_bytes(raw);fixture_sha=SHA(raw);report['fixture_sha256']=fixture_sha
        children=[];canonical=[]
        for mode in (1,2):
            command=['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--mode',str(mode),'--fixture-sha',fixture_sha]
            child=None;timed=False;begin=time.monotonic()
            with (OUT/('mode-'+str(mode)+'.stdout')).open('xb',buffering=0)as stdout,(OUT/('mode-'+str(mode)+'.stderr')).open('xb',buffering=0)as stderr:
                try:
                    child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,cwd=OUT,env={'PATH':'','LANG':'C'})
                    report['actual_native_processes']+=1
                    row=dict(mode=mode,command=command,pid=child.pid,pgid=os.getpgid(child.pid),started=True)
                    processes.append(row);(OUT/'processes.json').write_bytes(J(processes))
                    try:child.wait(timeout=60)
                    except subprocess.TimeoutExpired:timed=True;child.kill();child.wait();raise
                finally:
                    if child:
                        if child.poll()is None:child.kill();child.wait()
                        row.update(exit_code=child.returncode,reaped=True,timed_out=timed,elapsed_seconds=time.monotonic()-begin)
                        (OUT/'processes.json').write_bytes(J(processes))
            out=(OUT/('mode-'+str(mode)+'.stdout')).read_bytes();err=(OUT/('mode-'+str(mode)+'.stderr')).read_bytes()
            row.update(stdout_bytes=len(out),stdout_sha256=SHA(out),stderr_bytes=len(err),stderr_sha256=SHA(err))
            assert child.returncode==0 and not timed and not err,row
            observed=json.loads((OUT/('mode-'+str(mode))/'result.json').read_bytes());assert json.loads(out)==observed and observed['pid']==child.pid
            assert observed['status']=='PASS_FINITE_SERVER_FACTORY'and observed['matching_projections']==len(cases)
            assert observed['actual_message_creations']==observed['owned_cases']==report['original_successes']*4
            children.append(observed);canonical.append((OUT/('mode-'+str(mode))/'canonical.json').read_bytes())
        assert canonical[0]==canonical[1]
        recheck_original();admit.recheck_all()
        report.update(status='PASS_FINITE_SERVER_FACTORY',native_modes_equal=True,projection_calls_per_mode=len(cases),
            owned_cases_per_mode=children[0]['owned_cases'],typed_callbacks_per_mode=children[0]['typed_callbacks'],
            actual_hia_entries_per_mode=sum(children[0][k]for k in('owner_entries','controller_entries','parser_entries','emitter_entries','typed_hia_entries')),
            initializer_factory_actual=True,all_sources_rechecked=True)
    except BaseException as error:report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        report['elapsed_seconds']=time.monotonic()-started;report['processes']=processes
        if admit:report['source_pins']=admit.PINS
        report['retained_files']={p.relative_to(OUT).as_posix():dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes()))for p in sorted(OUT.rglob('*'))if p.is_file()}
        (OUT/'result.json').write_bytes(J(report))
        print(json.dumps({k:v for k,v in report.items()if k not in('source_pins','retained_files','traceback')},sort_keys=True))
if __name__=='__main__':main()
