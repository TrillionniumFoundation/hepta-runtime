#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Rebuild actual ServerMessage factory and exact-input evidence without execution."""
from pathlib import Path
import collections,gzip,json,struct
M=Path('/home/qq/hepta-server-message-codec-bd947-v1')
BUILD_SHA='5ad5308481a4214484c1f1ea63cae26edbaaa7e245d505a56f8a4eed6e06f846'
FIXTURE_SHA='91e44d387db2aba8633b900a2c77fca44ef983d3ec6e7b8c827217ea32e18989'
INPUTS_SHA='14a5975dbef33429f656635cf2ba79b516af8c6dd6b5b75f9bac35319e22bad8'
MACHINE_SHA='a8eab79bdd39eef870e86be5a2d4853b24e0e00b1c69f8083a83f9ca7600aa6a'
U=lambda b,n=0:struct.unpack_from('<Q',b,n)[0]
def public(report):
    return {k:v for k,v in report.items()if k not in('source_pins','retained_files','traceback')}
def completed(C,path,sha,report,job,source):
    envelope=C.js(path,sha)
    assert set(envelope)=={'schema','request','raw_start','raw_status','raw_read','result'}
    normalized=dict(envelope,status=envelope['raw_status'],read=envelope['raw_read'])
    info=C.durable_object(normalized,public(report),job,source)
    C.COMPLETIONS[job]=dict(path=str(path),sha256=sha,**info)
def inputs(C):
    admit=C.module(M/'admit_server_message_inputs_v2.py',INPUTS_SHA,'factory_retained_admission')
    C.pin(M/'server_message_machine_v1.py',MACHINE_SHA)
    handoff,original,recheck=admit.admit_reference()
    build=admit.admit_callable(M/'server-message-callable-build-v3',BUILD_SHA,
        M/'server-message-callable-build-v3.external.json',
        '5a450c303dc7cdfd50e16b1b1518a77485e3f4119cbc07751c64c9e8205cd931','1a1eb4113c6-392-4301')
    C.mergepins(admit);C.build_compiles(build)
    assert original['registry_before']==original['registry_after']and len(original['registry_before'])==139
    for project in(M/'source-v1/project',M/'original-build-v1/project'):
        for path in sorted(project.rglob('*')):
            if path.is_file():C.pin(path)
    for name,row in original['registry_before'].items():
        C.pin(M/'original-build-v1/registry'/(name+'.crate'),row['archive']['sha256'],row['archive']['bytes'])
        for rel,want in row['members'].items():C.pin(Path(row['actual_source'])/rel,want['sha256'],want['bytes'])
    fixture=C.module(M/'qualify_server_message_factory_v2.py',FIXTURE_SHA,'factory_retained_assertions')
    return admit,handoff,original,recheck,build,fixture
def process(C,root,name,row,command,stdin=None,start_name=None,finish_name=None):
    assert row['command']==command and row['started']is True
    assert type(row['pid'])is int and type(row['pgid'])is int and row['pid']>0 and row['pgid']>0
    assert row['exit_code']==0 and row['reaped']is True and row['timed_out']is False
    for channel in('stdout','stderr'):
        raw=C.pin(root/(name+'.'+channel),row[channel+'_sha256'],row[channel+'_bytes'])
        if channel=='stderr':assert raw==b''
    if stdin is not None:
        assert C.pin(root/(name+'.stdin'))==stdin
        for key in('input_offset','actual_input_offset'):
            if key in row:assert row[key]==len(stdin)
        if 'stdin_bytes'in row:assert row['stdin_bytes']==len(stdin)and row['stdin_sha256']==C.SHA(stdin)
    if start_name:
        start=C.js(root/start_name)
        assert start=={k:row[k]for k in('command','pid','pgid','started')}
    if finish_name:
        finish=C.js(root/finish_name)
        assert all(row[k]==v for k,v in finish.items())
        assert all(k in finish for k in('command','pid','pgid','started','exit_code','reaped','timed_out','elapsed_seconds'))
class Physical:
    def __init__(self,C,path,build,report):
        rows=[json.loads(x)for x in C.pin(path).splitlines()]
        assert len(rows)%2==0;self.rows=[];self.at=0;self.phase=0;self.frame=0;self.report=report
        for ordinal,(entry,done)in enumerate(zip(rows[::2],rows[1::2],strict=True)):
            assert set(entry)=={'ordinal','phase','frame','name','args','event'}
            assert set(done)==set(entry)|{'result'} and entry['event']=='ENTER'and done['event']=='RETURN'
            assert entry['ordinal']==ordinal and all(entry[k]==done[k]for k in entry if k!='event')
            assert entry['name']in build['exports']
            assert all(type(x)is int and 0<=x<1<<64 for x in entry['args'])
            self.rows.append((entry,done))
        assert len(self.rows)==report['exports_attempted']==report['exports_returned']
        assert report['image_unmapped']is True
        assert report['sealed_rx_image']==dict(bytes=build['artifact']['bytes'],sha256=build['artifact']['sha256'],writable_executable=False)
    def call(self,name,args,expected=None):
        assert self.at<len(self.rows),(name,'missing')
        entry,done=self.rows[self.at];self.at+=1
        assert (entry['name'],entry['phase'],entry['frame'])==(name,self.phase,self.frame),(entry,name,self.phase,self.frame)
        assert len(entry['args'])==len(args)
        for actual,want in zip(entry['args'],args,strict=True):
            if want is None:assert actual>0
            else:assert actual==want,(name,entry['args'],args)
        if expected is not None:assert done['result']==expected,(name,done['result'],expected)
        return done['result'],entry['args']
    def done(self):assert self.at==len(self.rows)
class Resources:
    def __init__(self,C,path):
        self.rows=[json.loads(x)for x in C.pin(path).splitlines()];self.at=0
    def take(self,event,**values):
        assert self.at<len(self.rows),(event,'missing')
        row=self.rows[self.at];self.at+=1
        assert row['event']==event,(row,event)
        assert all(row.get(k)==v for k,v in values.items()),(row,values)
        return row
    def done(self):assert self.at==len(self.rows)
def factory(C):
    root=M/'message-factory-pairs-v2'
    report=C.js(root/'result.json','7060bbffd0974d35e06cfb978061fc6d3cb32dd0be479fb6f75a2613e794ea52')
    assert report['status']=='PASS_FINITE_SERVER_FACTORY'
    completed(C,M/'message-factory-pairs-v2.external.json','12bf50a9bdaa24f8d72dc18910c05d7cafa038040df051e66daacc8f40708cb7',
        report,'1a1eb463e1e-392-4306',M/'qualify_server_message_factory_v2.py')
    C.allpins(report['source_pins']);C.directory(root,report['retained_files'])
    admit,handoff,original,recheck,build,f=inputs(C)
    cases=f.make_cases(admit);assert len(cases)==90
    requests=[f.oracle_request(case)for case in cases]
    stdin=b''.join((json.dumps(q,separators=(',',':'))+'\n').encode()for q in requests)
    process(C,root,'original',report['original'],[handoff['binary']['path']],stdin,
        'original-process-start.json','original-process-finish.json')
    answers=[json.loads(x)for x in C.pin(root/'original.stdout').splitlines()]
    assert len(answers)==len(cases)
    for case,answer in zip(cases,answers,strict=True):
        assert answer['status']in('OK','ERROR')
        if answer.get('target')=='id':
            assert answer['status']=='ERROR'and case['operation']==2 and case['kind']in(1,2,4)and case['id_hex']
            assert answer['input_bytes']==len(bytes.fromhex(case['id_hex']))
        else:
            assert 'target'not in answer and answer['input_bytes']==len(bytes.fromhex(case['body_hex']))
        if case['positive']:assert answer['status']=='OK'
    manifest=dict(build_sha256=BUILD_SHA,original_stdout_sha256=C.SHA(C.pin(root/'original.stdout')),cases=cases,answers=answers)
    assert C.pin(root/'fixture.json',report['fixture_sha256'])==f.J(manifest)
    assert report['actual_original_processes']==1 and report['actual_native_processes']==2
    assert report['original_requests']==90 and report['original_successes']==sum(a['status']=='OK'for a in answers)==77
    processes=C.js(root/'processes.json')
    assert len(processes)==len(report['processes'])==2
    children=[];canonical=[]
    for mode,row in enumerate(report['processes'],1):
        command=['/usr/bin/python3','-I','-B',str(M/'qualify_server_message_factory_v2.py'),'--mode',str(mode),'--fixture-sha',report['fixture_sha256']]
        process(C,root,'mode-'+str(mode),row,command)
        assert all(row[k]==v for k,v in processes[mode-1].items())
        child=C.js(root/('mode-'+str(mode))/'result.json')
        assert json.loads(C.pin(root/('mode-'+str(mode)+'.stdout')))==child
        assert child['pid']==row['pid']and child['tid']==row['pid']and child['mode']==mode
        value=factory_child(C,root/('mode-'+str(mode)),build,child,f,cases,answers,mode)
        children.append(value);canonical.append(C.pin(root/('mode-'+str(mode))/'canonical.json'))
    assert canonical[0]==canonical[1]and children[0]==children[1]
    for row in(children[0],):
        assert report['projection_calls_per_mode']==row['projection_calls']==90
        assert report['owned_cases_per_mode']==row['owned_cases']==308
        assert report['typed_callbacks_per_mode']==row['typed_callbacks']==770
        assert report['actual_hia_entries_per_mode']==sum(row[k]for k in('owner_entries','controller_entries','parser_entries','emitter_entries','typed_hia_entries'))==7225
    assert report['original_ownership_paired']is False and report['native_modes_equal']is True
    recheck();admit.recheck_all();C.mergepins(admit)
    return dict(historical_original_requests=90,historical_native_modes=2,historical_owned_cases_per_mode=308,
        actual_wire_and_owned_payloads_reconstructed=True,complete_physical_sequences_reconstructed=True,
        historical_original_ownership_paired=False,per_mode=children[0],
        mapping_and_fd_retirement='Bound to completed immutable fixture assertions; no raw maps or fd snapshots were captured.',
        new_semantic_executions=0,new_original_processes=0,new_native_image_entries=0)

def factory_child(C,folder,build,child,f,cases,answers,mode):
    assert child['status']=='PASS_FINITE_SERVER_FACTORY'and child['original_ownership_paired']is False
    P=Physical(C,folder/'physical.calls.jsonl',build,child);R=Resources(C,folder/'resources.jsonl')
    names=('projection_calls','matching_projections','owned_cases','actual_message_creations','capacity_refusals',
        'owner_entries','controller_entries','parser_entries','emitter_entries','lease_creates','typed_callbacks',
        'typed_hia_entries','typed_effects','waker_callbacks','owned_sends','closed_returns','channel_calls',
        'channel_creates','automatic_channel_retirements')
    metrics={name:0 for name in names};canonical=[];base=None;identities={}
    def invoke(case,mode_value,capacity,sc=0,generation=0,output_size=65552):
        wire=f.input_frame(case,mode_value,sc,generation)
        entry=R.take('MESSAGE_ENTER',label=case['label'],mode=mode_value,capacity=capacity,input_hex=wire.hex())
        assert set(entry)=={'event','label','mode','capacity','input_hex'}
        ret,args=P.call('server_message_call',[None,len(wire),None,capacity,None])
        assert len(set((args[0],args[2],args[4])))==3
        done=R.take('MESSAGE_RETURN',label=case['label'],code=ret)
        assert set(done)=={'event','label','code','output_hex','counts'}
        out=bytes.fromhex(done['output_hex']);counts=done['counts']
        assert len(out)==output_size and len(counts)==6 and all(type(v)is int and 0<=v<1<<64 for v in counts)and counts[-1]==0
        for key,value in zip(names[5:10],counts[:5],strict=True):metrics[key]+=value
        return ret,out,counts
    for ordinal,(case,answer)in enumerate(zip(cases,answers,strict=True),1):
        P.phase=P.frame=ordinal
        code,out,counts=invoke(case,1,65536);metrics['projection_calls']+=1
        if answer['status']=='ERROR':
            assert code==0xffffffff and out==b'\xa9'*len(out)
        else:
            assert code<=65536 and out[code:]==b'\xa9'*(len(out)-code)
            f.check_projection(out[:code],case,answer)
            for capacity in(127,code-1):
                denied,unchanged,small=invoke(case,1,capacity)
                assert denied==0xfffffffe and unchanged==b'\xa9'*len(unchanged)
                if capacity==127:assert small==[1,0,0,0,0,0]
                metrics['capacity_refusals']+=1
        metrics['matching_projections']+=1
    good=[(case,answer)for case,answer in zip(cases,answers,strict=True)if answer['status']=='OK']
    for cid,(case,answer,scenario)in enumerate(((c,a,s)for c,a in good for s in range(4)),1):
        P.phase=10000+cid;P.frame=cid
        sc,_=P.call('cooperative_scheduler_create',[cid,mode]);assert type(sc)is int and sc>0
        _,pubargs=P.call('batch_observer_attach',[sc,None],0)
        P.call('typed_drop_observer_attach',[sc,None],0)
        leases={};retired=set();channels=[];logical=[];cell=0
        def record(address,role,generation):
            nonlocal base
            span,_=P.call('value_lease_span',[address])
            assert isinstance(span,list)and len(span)==2 and all(type(n)is int and n>0 for n in span)
            row=R.take('LEASE_CREATE',case=cid,role=role,descriptor=address,payload_pointer=span[0])
            assert set(row)=={'event','case','role','descriptor','descriptor_hex','payload_pointer','payload_hex'}
            desc=bytes.fromhex(row['descriptor_hex']);payload=bytes.fromhex(row['payload_hex'])
            assert len(desc)==80 and desc[:8]==b'HRVLS001'
            assert U(desc,8)==generation and U(desc,16)==span[0]and U(desc,24)==span[1]==len(payload)==U(desc,48)
            assert U(desc,40)==sc and U(desc,56)==child['tid']and U(desc,64)==4096 and U(desc,72)==0
            symbol='server_message_drop_entry'if role=='message'else'owned_oneshot_handle_drop_entry'
            origin=U(desc,32)-build['exports'][symbol]
            assert origin>0 and origin%4096==0
            if base is None:base=origin
            assert base==origin
            key=(address,generation);old=identities.setdefault(key,(desc,payload))
            assert old==(desc,payload)and address not in leases
            leases[address]=dict(role=role,generation=generation,payload=payload,descriptor=desc)
            return payload
        generation=cid*32+31
        code,out,counts=invoke(case,2,63,sc,generation,80)
        assert code==0xfffffffe and out==b'\xa9'*80 and counts==[1,0,0,0,0,0]
        metrics['capacity_refusals']+=1
        code,out,counts=invoke(case,2,64,sc,generation,80)
        assert code==64 and out[:8]==b'HSSMR001'and out[64:]==b'\xa9'*16 and counts[4]==1
        address=U(out,24);assert address>0
        payload=record(address,'message',generation)
        assert payload[:8]==b'HSSMV001'and U(payload,8)==len(payload)-32
        kind,variant=f.check_projection(payload[32:],case,answer)
        assert (U(payload,16),U(payload,24))==(kind,variant)
        assert tuple(U(out,n)for n in(8,16,32,40,48,56))==(kind,variant,len(payload)-32,case['operation'],case['legacy'],0)
        assert counts[0]==counts[1]//3+2 and counts[1]==counts[2]*3 and counts[3]==counts[2]
        metrics['actual_message_creations']+=1
        def drop(value):
            assert value in leases and value not in retired
            role=leases[value]['role']
            R.take('DROP_ENTER',case=cid,descriptor=value,role=role)
            P.call('value_lease_drop',[value],0)
            R.take('DROP_RETURN',case=cid,descriptor=value,role=role)
            retired.add(value);logical.append(dict(action='drop',role=role))
            if role=='receiver'and scenario==3:retired.add(address)
        def channel(context,op,waker,status,value=0):
            wire=b'HRONQ001'+struct.pack('<9Q',op,cid,0,waker,0,0,0,0,0)
            R.take('CHANNEL_ENTER',case=cid,context=context,input_hex=wire.hex())
            P.call('oneshot_call',[context,None,80,None,80],80)
            reply=bytes.fromhex(R.take('CHANNEL_RETURN',case=cid,context=context)['output_hex'])
            assert len(reply)==80 and reply[:8]==b'HRONR001'and U(reply,8)==status and U(reply,16)==cid and U(reply,24)==value
            metrics['channel_calls']+=1;logical.append(dict(action='channel',op=op,status=status))
        def select(expected):
            for _ in range(4):
                value,_=P.call('cooperative_scheduler_next',[sc])
                if value:assert value==expected;return
            raise AssertionError('no saved task selection')
        if scenario:
            context,_=P.call('oneshot_create',[sc,cid,pubargs[1]]);assert context>0
            channels.append(context);metrics['channel_creates']+=1;handles=[]
            for side in(1,2):
                body=b'HROHL001'+struct.pack('<3Q',side,context,cid)
                desc,_=P.call('value_lease_create',[None,32,cid*32+side,base+build['exports']['owned_oneshot_handle_drop_entry'],sc])
                assert desc>0 and record(desc,'sender'if side==1 else'receiver',cid*32+side)==body
                handles.append(desc)
            tx,rx=handles
            if scenario==1:
                cell,_=P.call('cooperative_scheduler_register',[sc,None,0]);assert cell>0
                select(cell);channel(context,4,cell,3)
                P.call('cooperative_scheduler_finish',[sc,cell,0],0)
            if scenario==2:drop(rx)
            R.take('OWNED_SEND_ENTER',case=cid,sender=tx,value=address)
            assert tx not in retired and address not in retired
            P.call('owned_oneshot_send',[tx,address,None,80],80)
            reply=bytes.fromhex(R.take('OWNED_SEND_RETURN',case=cid)['output_hex'])
            assert len(reply)==80 and reply[:8]==b'HROSNR01'
            assert U(reply,8)==(2 if scenario==2 else 1)and U(reply,24)==(address if scenario==2 else 0)
            retired.add(tx);metrics['owned_sends']+=1
            if scenario==2:
                metrics['closed_returns']+=1;drop(address)
            elif scenario==3:drop(rx)
            else:
                select(cell);channel(context,4,cell,4,address)
                P.call('cooperative_scheduler_finish',[sc,cell,1],0)
                drop(rx);drop(address)
        else:drop(address)
        if cell:
            count=0
            while P.at<len(P.rows)and P.rows[P.at][0]['name']=='cooperative_scheduler_next':
                P.call('cooperative_scheduler_next',[sc],0);count+=1
            assert 1<=count<=4
            P.call('cooperative_scheduler_retire',[cell],0)
        metrics['automatic_channel_retirements']+=len(channels)
        row=R.take('OBSERVERS',case=cid)
        assert set(row)=={'event','case','typed_hex','wakers_hex'}
        typed=bytes.fromhex(row['typed_hex']);wakers=bytes.fromhex(row['wakers_hex'])
        assert len(typed)%48==0 and len(wakers)%16==0
        stack=[];seen=[];arenas=set();typed_order=[]
        for stage,tag,desc,arena,hias,effects in struct.iter_unpack('<6Q',typed):
            assert desc in leases;role=leases[desc]['role']
            assert tag=={'message':12,'sender':3,'receiver':1}[role]
            if stage==1:
                assert arena>0 and arena not in arenas and hias==effects==0 and role not in seen
                stack.append((tag,desc,arena));arenas.add(arena);seen.append(role);metrics['typed_callbacks']+=1
            else:
                assert stage==2 and stack and stack.pop()==(tag,desc,arena);arenas.remove(arena)
                assert hias==effects+1
                if tag==12:assert(hias,effects)==(1,0)
                metrics['typed_hia_entries']+=hias;metrics['typed_effects']+=effects
            typed_order.append((stage,role))
            logical.append(dict(action='typed',stage=stage,type=tag,role=role,entries=hias,effects=effects))
        assert not stack and not arenas and retired==set(leases)
        want_roles=['message']if scenario==0 else['receiver','sender','message']if scenario==2 else['sender','receiver','message']
        assert seen==want_roles
        if scenario==3:
            assert typed_order==[(1,'sender'),(2,'sender'),(1,'receiver'),(1,'message'),(2,'message'),(2,'receiver')]
        else:assert typed_order==[(stage,role)for role in want_roles for stage in(1,2)]
        kinds=[]
        for event,token in struct.iter_unpack('<2Q',wakers):
            assert cell and token==cell;kinds.append(event);logical.append(dict(action='waker',kind=event))
        assert kinds==([1,3,2]if scenario==1 else[])
        metrics['waker_callbacks']+=len(kinds)
        P.call('typed_drop_observer_attach',[sc,0],0);P.call('batch_observer_attach',[sc,0],0)
        P.call('cooperative_scheduler_destroy',[sc],0)
        canonical.append(dict(label=case['label'],scenario=scenario,kind=kind,variant=variant,logical=logical))
        metrics['owned_cases']+=1
    R.done();P.done()
    assert C.pin(folder/'canonical.json')==f.J(canonical)
    assert all(child[k]==v for k,v in metrics.items()),(metrics,{k:child[k]for k in metrics})
    assert child['phase']==10308 and child['frames']==308
    for key in('all_owned_wire_matches_actual_original','all_owned_storage_retired','all_channel_retirement_actual','all_file_descriptors_balanced','real_wire_original_paired'):
        assert child[key]is True
    assert child['production_activated']is child['whole_runtime_replaced']is False
    return metrics

def boundary(C):
    root=M/'message-boundary-pairs-v2';source=M/'qualify_server_message_boundary_v2.py'
    report=C.js(root/'result.json','656647803e4b773af135c88b50a3648d12fe6b96db08647c8bee610335b5ba2f')
    assert report['status']=='PASS_FINITE_EXACT8M_SERVER_MESSAGE'
    completed(C,M/'message-boundary-pairs-v2.external.json','a719baa080356074c634f49f6371828b2cb75b75f642b6bd74af0084d0861f4a',
        report,'1a1eb8863ba-392-4339',source)
    C.allpins(report['source_pins']);C.directory(root,report['retained_files'])
    admit,handoff,original,recheck,build,f=inputs(C)
    old=C.module(source,'590c5f2e6496a7afbbafe5930cfb2e8d472bad7a1b5b9343f37a59119a90aad3','boundary_retained_assertions')
    raw,description=old.fixture()
    assert len(raw)==8388608 and description==report['fixture']==C.js(root/'fixture.json')
    assert C.SHA(raw)=='d842860219a37fdb92349cf6cbf28bf89e068b23caa7370f9e241cb47a7a1820'
    def unpack(item):
        packed=C.pin(item['path'],item['compressed_sha256'],item['compressed_bytes'])
        value=gzip.decompress(packed);assert len(value)==item['bytes']and C.SHA(value)==item['sha256'];return value
    assert unpack(report['input'])==raw
    request=(json.dumps(dict(op='server_message_normalize',hex=raw.hex()),separators=(',',':'))+'\n').encode()
    process(C,root,'original',report['original_process'],[handoff['binary']['path']],request,'original-start.json','original-finish.json')
    answer=json.loads(C.pin(root/'original.stdout'))
    assert answer['input_bytes']==len(raw)and answer['status']=='OK'and answer['kind']=='Response'and answer['variant']=='InitializeResult'
    wire=answer['wire'].encode();assert json.loads(wire)==answer['value']
    assert len(wire)==report['original_wire_bytes']==31876198
    assert C.SHA(wire)==report['original_wire_sha256']=='5dba45a6fe2ee167c9128037f52bfe7f6eb70e82b264dca892d726d72d60fd5e'
    process(C,root,'native',report['native_process'],['/usr/bin/python3','-I','-B',str(source),'--child'],
        start_name='native-start.json',finish_name='native-finish.json')
    child=C.js(root/'native/result.json')
    assert child==report['native']==json.loads(C.pin(root/'native.stdout'))
    assert child['pid']==report['native_process']['pid']and child['status']=='PASS_FINITE_EXACT8M_SERVER_MESSAGE'
    assert child['actual_original_processes']==0
    folder=root/'native';P=Physical(C,folder/'physical.calls.jsonl',build,child)
    calls=C.js(folder/'calls.json');assert len(calls)==2
    case=dict(label='exact8MiB/InitializeResult/dense-floats',operation=1,kind=0,variant=0,
        body_hex=raw.hex(),id_hex='',legacy=False,positive=True)
    total_hia=0
    def call(index,mode,capacity,sc=0,generation=0):
        nonlocal total_hia
        row=calls[index]
        assert row['mode']==mode and row['capacity']==capacity
        frame=f.input_frame(case,mode,sc,generation);assert unpack(row['input'])==frame
        code,args=P.call('server_message_call',[None,len(frame),None,capacity,None])
        assert row['code']==code and 0<=code<=capacity
        output=unpack(row['output']);assert len(output)==capacity+16 and output[code:]==b'\xa9'*(len(output)-code)
        counts=row['counts'];assert len(counts)==6 and all(type(n)is int and n>=0 for n in counts)and counts[-1]==0
        total_hia+=sum(counts[:4])
        return output[:code],counts
    projection,counts=call(0,1,67108864)
    kind,variant=f.check_projection(projection,case,answer);assert(kind,variant)==(2,2)
    assert len(projection)==child['projection_bytes']==31876326
    assert C.SHA(projection)==child['projection_sha256']=='53c0905679336ad0fb4921ad62610dfab068c689542f307a01033af7bce61669'
    assert counts[4]==0
    sc,_=P.call('cooperative_scheduler_create',[9001,1]);assert sc>0
    P.call('typed_drop_observer_attach',[sc,None],0)
    owned,counts=call(1,2,64,sc,9002)
    assert len(owned)==64 and owned[:8]==b'HSSMR001'and counts[4]==1
    assert tuple(U(owned,n)for n in(8,16,32,40,48,56))==(2,2,len(projection),1,0,0)
    assert C.pin(folder/'owned-answer.bin')==owned
    descriptor=U(owned,24);assert descriptor>0
    span,_=P.call('value_lease_span',[descriptor]);assert isinstance(span,list)and len(span)==2
    desc=C.pin(folder/'descriptor.bin');owner=C.js(folder/'owner.json')
    assert owner==dict(descriptor=descriptor,payload_pointer=span[0],sc=sc,descriptor_hex=desc.hex(),actual_read_only=True)
    payload=unpack(child['payload'])
    assert len(desc)==80 and desc[:8]==b'HRVLS001'
    assert U(desc,8)==9002 and U(desc,16)==span[0]and U(desc,24)==span[1]==len(payload)==U(desc,48)
    assert U(desc,40)==sc and U(desc,56)==child['pid']and U(desc,64)==4096 and U(desc,72)==0
    base=U(desc,32)-build['exports']['server_message_drop_entry'];assert base>0 and base%4096==0
    assert payload==b'HSSMV001'+struct.pack('<3Q',len(projection),2,2)+projection
    assert len(payload)==31876358 and C.SHA(payload)=='03aefebdf83e0e9d0e390f9722a8f51ef67e4873aa83d51c26eeda269e4932c9'
    P.call('value_lease_drop',[descriptor],0)
    typed=C.pin(folder/'typed.bin');assert len(typed)==96
    rows=list(struct.iter_unpack('<6Q',typed));arena=rows[0][3];assert arena>0
    assert rows==[(1,12,descriptor,arena,0,0),(2,12,descriptor,arena,1,0)]
    P.call('typed_drop_observer_attach',[sc,0],0);P.call('cooperative_scheduler_destroy',[sc],0);P.done()
    assert child['actual_hia_entries']==total_hia==15
    assert child['actual_projection_calls']==child['actual_owned_creates']==child['actual_typed_drops']==1
    assert child['input_bytes']==len(raw)and child['input_sha256']==C.SHA(raw)
    assert child['wire_bytes']==len(wire)and child['wire_sha256']==C.SHA(wire)
    for key in('immutable_input','typed_wire_equal','owned_payload_wire_equal','all_guarded_allocations_retired','fd_sets_balanced'):assert child[key]is True
    assert report['actual_original_processes']==report['actual_native_processes']==report['actual_original_normalizations']==report['actual_native_owned_drops']==1
    assert report['actual_native_normalizations']==2 and report['actual_compiles']==0 and report['original_ownership_paired']is False
    assert child['production_activated']is child['whole_runtime_replaced']is False
    recheck();admit.recheck_all();C.mergepins(admit)
    return dict(historical_original_normalizations=1,historical_native_normalizations=2,historical_owned_creates=1,
        historical_owned_drops=1,historical_hia_normalizer_entries=15,historical_typed_drop_entries=1,
        input_bytes=len(raw),input_sha256=C.SHA(raw),wire_bytes=len(wire),wire_sha256=C.SHA(wire),
        projection_bytes=len(projection),projection_sha256=C.SHA(projection),
        full_input_output_payload_and_physical_trace_reconstructed=True,
        historical_original_ownership_paired=False,
        mapping_and_fd_retirement='Bound to completed immutable fixture assertions; no raw maps or fd snapshots were captured.',
        new_semantic_executions=0,new_original_processes=0,new_native_image_entries=0)
