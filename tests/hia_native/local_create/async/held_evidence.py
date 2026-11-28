"""Read complete owned-process evidence without executing either implementation.

The source-selected corpus, actual input/output bytes, raw syscall completions,
publication reads, descendant custody and retained files must all agree. A PASS
word or a rehashed summary alone is never an admission.
"""
from pathlib import Path,PurePosixPath
from collections import Counter
import gzip
import hashlib
import json
import math
import os
import struct

CORPUS_SHA='069ba8299eff7b39583ef8f1be54ff855a7c038f2b5f817f0039659cf77a906e'
DRIVER_FILES=('cases.json','owned_trace.py','held_cases.py','run_held.py')
CHUNK=2<<20
MASK=(1<<64)-1
Q=lambda x:struct.pack('<Q',x)
U=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]


def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def compact(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def require(condition,message):
    if not condition:raise ValueError(message)
def exact(actual,expected,message):require(compact(actual)==compact(expected),message)
def integer(value,minimum=0):return type(value)is int and value>=minimum
def finite(value,limit):return type(value)in(int,float)and math.isfinite(value)and 0<=value<=limit


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'duplicate evidence JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda value:(_ for _ in()).throw(ValueError('non-finite evidence JSON')))


def owned(base,name):
    require(type(name)is str and name and not PurePosixPath(name).is_absolute()
            and PurePosixPath(name).as_posix()==name and '..'not in PurePosixPath(name).parts,
            'held evidence path must be an exact relative file')
    path=Path(base)/name
    require(path.is_file()and not path.is_symlink()and path.resolve()==path.absolute(),
            'held evidence file is absent or aliased: '+name)
    return path


class Evidence:
    def __init__(self,root):self.root=Path(root).resolve(strict=True);self.artifacts={}
    def read(self,name):
        raw=owned(self.root,name).read_bytes();self.artifacts[name]=sha(raw);return raw
    def object(self,name):return decode(self.read(name))
    def compressed(self,name):return gzip.decompress(self.read(name))


def corpus(source):
    raw=owned(source,'cases.json').read_bytes();require(sha(raw)==CORPUS_SHA,'fixed held corpus changed')
    value=decode(raw)
    require(value['case_count']==43 and type(value['case_count'])is int and len(value['cases'])==43,
            'complete held case inventory differs')
    require(len({case['name']for case in value['cases']})==43,'duplicate held case')
    return value


def source_files(source):return {name:pin(owned(source,name).read_bytes())for name in DRIVER_FILES}


def absolute(value):
    return type(value)is str and Path(value).is_absolute()and str(Path(value))==value and '..'not in Path(value).parts


def content(size):return(bytes(range(251))*((size+250)//251))[:size]


def packet_stream(raw):
    offset=0;rows=[]
    while offset<len(raw):
        require(len(raw)-offset>=8,'truncated captured write length');size=U(raw,offset);offset+=8
        require(0<size<=CHUNK and size<=len(raw)-offset,'captured write extent differs')
        rows.append(raw[offset:offset+size]);offset+=size
    return rows


def journal(raw,mode):
    offset=0;markers=[];effects=[]
    while offset<len(raw):
        magic=raw[offset:offset+8]
        if mode=='rust':
            require(magic==b'HLCARP01'and len(raw)-offset>=128,'incomplete actual Rust observer stream')
            frame=raw[offset:offset+128];offset+=128
            require(U(frame,8)==128 and frame[72:]==bytes(56)and 1<=U(frame,16)<=17,
                    'actual Rust observer record differs')
            markers.append(frame)
        elif magic==b'HLCASR01':
            require(len(raw)-offset>=128,'incomplete actual HIA journal')
            frame=raw[offset:offset+128];offset+=128
            require(U(frame,8)==128 and U(frame,120)==0 and U(frame,32)==1
                    and U(frame,16)in(1,2,3,4,6,8,9,10,11)and 1<=U(frame,24)<=6,
                    'actual HIA journal record differs')
            markers.append(frame)
        else:
            require(magic==b'HLCREF01'and len(raw)-offset>=96,'incomplete actual native syscall record')
            frame=raw[offset:offset+96];offset+=96;effects.append(frame)
    if mode=='rust':exact(sorted(U(frame,24)for frame in markers),list(range(1,len(markers)+1)),
                          'actual Rust observer serial inventory differs')
    return markers,effects


def check_outcome(spec,mode,stdout,markers):
    require(len(stdout)>=16 and U(stdout,0)==len(stdout)-8,'complete actual response extent differs')
    expected=spec['expected_result'];body=stdout[8:]
    if expected['outcome']=='cancelled':
        if mode=='rust':require(body==b'HLCCAN01'+Q(16),'actual Tokio cancellation result differs')
        else:
            require(len(body)==128 and body[:8]==b'HLCASR01'and U(body,8)==128
                    and U(body,16)==6 and U(body,24)in(4,6)and U(body,120)==0
                    and body in markers,'native cancellation was not the actual admitted HIA result')
        return dict(outcome='cancelled')
    written=spec['size']if expected['kind']==0 else(0 if mode=='rust'else(spec['expected_file_bytes']or 0))
    want=b'HLCRER01'+struct.pack('<5Q',48,expected['kind'],expected['error'],written,0)
    require(body==want,'actual filesystem result or written-byte projection differs')
    return dict(**expected,written=written)


def check_syscalls(spec,mode,body,path,root,entries,exits,prepared,effects,payload_bytes):
    expected_counts=spec['expected_calls'];counts=Counter(event['operation']for event in entries)
    exact({key:counts[key]for key in expected_counts},expected_counts,'actual syscall entry domain differs')
    require(set(counts)<=set(expected_counts),'unknown target syscall')
    require(len(entries)==len(exits),'an actual target syscall has no completion')
    entry_by_key={};exit_by_key={}
    for event in entries:
        key=(event['operation'],event['call']);require(key not in entry_by_key,'duplicate target syscall entry')
        require(integer(event['call'],1),'target syscall call ordinal differs');entry_by_key[key]=event
    for event in exits:
        key=(event['operation'],event['call']);require(key not in exit_by_key,'duplicate target syscall completion')
        require(key in entry_by_key,'completion has no actual target entry');entry=entry_by_key[key]
        require(event['index']>entry['index']and event['tid']==entry['tid']and event['nr']==entry['nr'],
                'target syscall identity changed across completion');exit_by_key[key]=event
    for operation,count in expected_counts.items():
        exact(sorted(call for op,call in entry_by_key if op==operation),list(range(1,count+1)),
              'target syscall ordinals are incomplete')
    injections={(row['operation'],row['index']):row for row in spec['options'].get('injections',[])}
    expected_prepared=[dict(operation=op,call=index,injection=row)for(op,index),row in injections.items()]
    exact([{key:event[key]for key in('operation','call','injection')}for event in prepared],expected_prepared,
          'actual injected completion inventory differs')
    payloads=packet_stream(payload_bytes);require(len(payloads)==expected_counts['write'],'full requested write payloads are incomplete')
    opened=None;completed=0;projection=[];write_index=0
    for event in entries:
        operation=event['operation'];key=(operation,event['call']);end=exit_by_key[key];injection=injections.get(key)
        exact(end.get('injection'),injection,'actual completion injection differs')
        require(type(end.get('kernel_return'))is int and type(end.get('completion'))is int,
                'actual syscall return must retain signed integer semantics')
        require(event['nr']in((2,257)if operation=='open'else(1,)if operation=='write'else(3,)),
                'unexpected actual target syscall number')
        if operation=='open':
            require(opened is None and event['tid']!=root,'exclusive open escaped its actual worker')
            exact((event['path_hex'],event['flags'],event['mode']),(path.hex(),0x800c1,0o666),
                  'actual exclusive-open flags, mode or path differ')
            nominal=None
        elif operation=='write':
            require(opened is not None and event['fd']==opened and event['tid']!=root,
                    'actual write lost its worker descriptor custody')
            raw=payloads[write_index];write_index+=1
            stop=min(((completed//CHUNK)+1)*CHUNK,len(body));wanted=body[completed:stop]
            require(raw==wanted and wanted,'complete actual write request crossed a ticket boundary')
            exact((event['length'],event['payload'],event['completed_before']),(len(raw),pin(raw),completed),
                  'actual write request metadata differs')
            nominal=len(raw)
        else:
            require(opened is not None and event['fd']==opened,'actual close lost descriptor custody')
            nominal=0
        if injection and injection['kind']in('errno','zero'):
            exact(end['kernel_return'],-38,'explicit skipped syscall did not retain its actual kernel return')
            want=0 if injection['kind']=='zero'else-injection['value']
            exact((end['completion'],end['target_syscall_executed']),(want,False),'injected completion was not identified separately')
        else:
            require(end['target_syscall_executed']is True,'actual syscall execution was falsely omitted')
            if injection and injection['kind']=='partial':nominal=injection['value']
            if operation=='open':require(integer(end['kernel_return']),'unplanned actual open error')
            else:exact(end['kernel_return'],nominal,'actual kernel completion differs from the fixed case')
            want=-injection['value']if injection and injection['kind']=='close_errno'else end['kernel_return']
            exact(end['completion'],want,'visible completion differs from the actual or explicitly injected result')
        if operation=='open'and end['completion']>=0:
            opened=end['completion']
            if spec['options'].get('fd0'):exact(opened,0,'descriptor zero was not actually exercised')
        elif operation=='write'and end['completion']>0:completed+=end['completion']
        elif operation=='close':opened=None
        exact(end['completed_bytes'],completed,'actual cumulative write completion differs')
        projection.append(dict(operation=operation,call=event['call'],completion=end['completion'],
            requested=event.get('length'),completed_bytes=completed,injection=injection))
    require(opened is None,'actual descriptor was not closed')
    if mode=='native':
        require(len(effects)==len(entries),'native syscall journal omitted actual effects')
        sequence=0;written=0
        for frame,event in zip(effects,entries,strict=True):
            words=struct.unpack('<12Q',frame);_,seq,action,a,b,c,d,ready,value,error,token,reserved=words
            operation=event['operation'];end=exit_by_key[(operation,event['call'])]
            require(seq==sequence+1 or(seq==sequence+2 and operation=='close'),
                    'native prepared-effect sequence gap is not the one cancelled WRITE')
            sequence=seq;exact((action,ready,reserved),({'open':1,'write':2,'close':3}[operation],1,0),
                              'native syscall effect action/completion differs')
            completion=end['completion'];expected_error=-completion if completion<0 else 0
            exact((value,error),(completion&MASK,expected_error),'native journal changed actual injected/kernel completion')
            if operation=='open':
                exact((a,b,c,d,token),(512,len(path),0x800c1,0o666,0 if completion<0 else 1),
                      'native exclusive-open journal differs')
            elif operation=='write':
                exact((a,b,c,d,token),(1,513+len(path)+written,event['length'],0,0),
                      'native write journal crossed its actual input lease')
                if completion>0:written+=completion
            else:exact((a,b,c,d,token),(1,0,0,0,0),'native close journal differs')
    else:require(not effects,'Rust evidence contains native syscall frames')
    return dict(complete_write_payload_bytes=len(payload_bytes),syscall_projection=projection)


def check_boundaries(spec,mode,events,markers,barriers,entries,exits,publication,cancel,wakes,root,stdout_size):
    scene=spec['scenario'];normal=scene in('normal','completion_before_wait')
    exact(len(cancel),0 if normal else 1,'actual cancellation request count differs')
    require(publication,'actual result was never published')
    first_publication=publication[0]['index']
    reads=[event for event in events if event['kind']=='stdout_read']
    require(reads and sum(event['bytes']for event in reads)==stdout_size,'complete result visibility is absent')
    visible=reads[-1]['index']
    cancelled=spec['expected_result']['outcome']=='cancelled'
    if cancel:require(cancel[0]['tid']==root and cancel[0]['index']<first_publication,'cancel was requested after publication')
    parent_markers=[event for event in markers if event['tid']==root]
    if mode=='rust':
        require(sum(event['event']==13 for event in parent_markers)==1,'actual Runtime drain was not observed once')
        drain=next(event for event in parent_markers if event['event']==13)
        require(drain['index']>first_publication,'runtime drain replaced cancellation visibility')
        starts=[event for event in markers if event['event']==16];stops=[event for event in markers if event['event']==17]
        require(len(starts)==len(stops)==(0 if scene=='unpolled_cancel'else 1),'actual blocking worker startup/drain differs')
        if stops:require(stops[0]['index']<drain['index'],'runtime returned before the blocking worker stopped')
        if cancel:
            aborts=[event for event in markers if event['event']in(8,9)]
            exact([event['event']for event in aborts],[8,9],'actual Tokio AbortHandle call was not completed once')
            require(cancel[0]['index']<aborts[0]['index']<aborts[1]['index'],'Tokio abort observer order differs')
        result_events=[event for event in parent_markers if event['event']in(11,12)]
        require(len(result_events)==1 and result_events[0]['event']==(11 if cancelled else 12)
                and result_events[0]['index']<first_publication,'actual JoinHandle result differs')
        if cancelled:
            drops=[event for event in parent_markers if event['event']in(6,7)]
            exact([event['event']for event in drops],[6,7],'actual future drop was not completed once')
            require(drops[-1]['index']<result_events[0]['index'],'cancellation became visible before synchronous future drop')
    else:
        descendants={event['pid']for event in events if event['kind']=='owned_descendant'}
        actual_waits=[event for event in events if event['kind']=='mechanism_syscall_exit'
                      and event['nr']==61 and event['kernel_return']>0]
        exact(sorted(event['kernel_return']for event in actual_waits),sorted(descendants),
              'native wait4 did not really reap every admitted worker exactly once')
        require(all(event['tid']==root for event in actual_waits),'native worker reaping escaped its parent')
        if cancel:
            signals=[event for event in events if event['kind']=='signal_delivery'and event['signal']==10]
            require(len(signals)==1 and signals[0]['tid']==root,'native cancellation signal was not actually delivered')
    by_reason={}
    for row in barriers:by_reason.setdefault(row['hold']['reason'],[]).append(row)
    if scene=='unpolled_cancel':
        require(len(by_reason.get('unpolled',[]))==1,'unpolled cancellation barrier is absent')
        if mode=='rust':require(not any(event['event']==1 for event in parent_markers),'unpolled future was actually polled')
    if scene in('open_ready_cancel','open_ready_close_cancel','write_ready_cancel','nul_ready_cancel'):
        require(len(by_reason.get('ready',[]))==1,'ready-before-next-poll boundary is absent')
    if scene=='open_ready_close_cancel':require(len(by_reason.get('close',[]))==1,'inline destructor close was not actually held')
    if scene in('open_ready_poll_cancel','write_ready_poll_cancel','empty_ready_poll_cancel','last_ready_poll_cancel','nul_ready_poll_cancel'):
        require(len(by_reason.get('poll',[]))==1,'same-poll cancellation boundary is absent')
    if scene=='completion_before_wait':
        require(len(by_reason.get('pending_gate',[]))==1,'completion-before-wait boundary is absent')
    held_effect_scenes={'open_inflight_cancel','write1_inflight_cancel','write2_inflight_cancel','flush_inflight_cancel',
                        'open_ready_poll_cancel','write_ready_poll_cancel'}
    if scene in held_effect_scenes:require(len(by_reason.get('effect',[]))==1,'actual in-flight syscall was not held')
    if scene=='nul_inflight_cancel':require(len(by_reason.get('nul_effect',[]))==1,'actual NUL worker was not held')
    if scene.startswith('repeat_pending_'):require(len(by_reason.get('repeat_effect',[]))==1,'repeated Pending worker barrier is absent')
    pending_cancel_scenes={'open_inflight_cancel','write1_inflight_cancel','write2_inflight_cancel',
        'flush_inflight_cancel','nul_inflight_cancel','repeat_pending_open','repeat_pending_write'}
    if scene in pending_cancel_scenes:
        states=[event for event in parent_markers if event['index']<cancel[0]['index']and
                (event['event']in(1,2,3)if mode=='rust'else event['life']==2 or event['action']==3 and event['life']==3)]
        require(states and(states[-1]['event']==2 if mode=='rust'else states[-1]['action']==3 and states[-1]['life']==3),
                'worker cancellation was not requested after an actual Pending return')
    for reason,rows in by_reason.items():
        for row in rows:
            hold,release,observed=row['hold'],row['release'],row['observed']
            if reason in('ready','effect','nul_effect','repeat_effect'):
                require(cancelled and hold['index']<cancel[0]['index']if reason in('ready','nul_effect','repeat_effect')else cancelled,
                        'cancellation did not occur at its held worker boundary')
                require(visible<release['index'],'in-flight/ready worker was released before cancellation was actually readable')
            if reason=='ready':
                require(observed.get('event')==4 if mode=='rust'else observed.get('action')==9 and observed.get('life')==3,
                        'ready barrier was not an actual published join result')
                closes=[event for event in exits if event['operation']=='close']
                if spec['expected_file_bytes']is not None:
                    require(len(closes)==1 and closes[0]['tid']==root and closes[0]['index']<first_publication,
                            'ready-result destructor close did not precede cancellation publication')
            elif reason=='poll':
                require(observed['tid']==root and hold['index']<cancel[0]['index']<release['index'],
                        'cancellation was not requested inside an already-running poll')
                if mode=='rust':
                    require(observed['event']==1 and any(event['event']==9 and hold['index']<event['index']<release['index']for event in markers),
                            'actual AbortHandle did not return during the held Rust poll')
                else:require(observed['life']==2 and observed['action']in(2,4,11),'native held turn was not POLLING')
            elif reason=='close':
                require(observed['kind']=='syscall_entry'and observed['operation']=='close'and observed['tid']==root,
                        'inline close hold was not a real parent syscall')
                close_exit=next(event for event in exits if event['operation']=='close')
                require(release['index']<close_exit['index']<first_publication,'inline close added a cancellation publication point')
            elif reason=='pending_gate':
                if mode=='rust':completed=[event for event in markers if event['event']==5]
                else:completed=[event for event in events if event['kind']=='process_reaped'and event['tid']!=root]
                require(any(hold['index']<event['index']<release['index']for event in completed),
                        'actual wake/worker completion did not precede wait-boundary release')
    if spec['expected_result']['outcome']=='result'and spec['expected_file_bytes']is not None:
        require(max(event['index']for event in exits if event['operation']=='close')<first_publication,
                'normal completion preceded actual close')
    repeated=scene.startswith('repeat_pending_');exact(len(wakes),3 if repeated else 0,'actual forced-wake inventory differs')
    if repeated:
        pending=[event for event in parent_markers if(event['event']==2 if mode=='rust'else event['action']==3 and event['life']==3)]
        for index,wake in enumerate(wakes):
            until=wakes[index+1]['index']if index+1<len(wakes)else cancel[0]['index']
            require(any(wake['index']<event['index']<until for event in pending),'an explicit wake did not produce another actual Pending turn')
        if mode=='rust':require(sum(event['event']==10 for event in markers)==3,'actual Rust waker was not invoked three times')
        else:require(sum(event['kind']=='signal_delivery'and event['signal']==12 for event in events)==3,
                     'native mechanical wake signal was not delivered three times')


def capture(output,source,mode,*,binary_identity,execution=None):
    evidence=Evidence(output);source=Path(source);specification=corpus(source)
    summary=evidence.object('summary.json');origin=summary.get('execution')
    require(type(origin)is dict and set(origin)=={'source','output','binary'}and all(absolute(value)for value in origin.values()),
            'held execution origin differs')
    if execution is not None:exact(origin,execution,'held original/native process origin differs')
    expected=dict(schema='hepta.runtime.local-create-held-execution.v1',status='PASS',mode=mode,
        binary_before=binary_identity,binary_after=binary_identity,source_before=source_files(source),
        source_after=source_files(source),corpus_sha256=CORPUS_SHA,case_count=43,
        process_deadline_seconds=60,qualifier_deadline_seconds=180,scope=specification['scope'],
        retired_fixture_directories=43,actual_root_processes=43)
    exact({key:summary.get(key)for key in expected},expected,'complete held execution/source/scope differs')
    require('error'not in summary and finite(summary.get('elapsed_seconds'),180),'held corpus exceeded its retained deadline')
    rows=[];expected_rows=[]
    for index,spec in enumerate(specification['cases']):
        row=check_trace(evidence,spec,mode,origin,binary_identity);rows.append(row)
        expected_rows.append(dict(index=index,**{key:row[key]for key in('name','result_sha256','syscall_counts','file','owned_processes','elapsed_seconds')}))
        require(not(evidence.root/spec['name']/'work').exists(),'live held fixture was not retired')
    exact(summary.get('rows'),expected_rows,'complete held case set, ordering or actual process receipts differ')
    exact(summary.get('actual_owned_processes'),sum(row['owned_processes']for row in rows),'actual owned-process total differs')
    return dict(schema='hepta.runtime.local-create-held-capture.v1',status='PASS',mode=mode,case_count=43,
        corpus_sha256=CORPUS_SHA,binary_identity=binary_identity,scope=specification['scope'],
        actual_root_processes=43,actual_owned_processes=sum(row['owned_processes']for row in rows),
        complete_file_bytes=sum(row['complete_file_bytes']for row in rows),
        complete_write_payload_bytes=sum(row['complete_write_payload_bytes']for row in rows),
        rows=rows,artifact_sha256=dict(sorted(evidence.artifacts.items())))


def compare(native_output,rust_output,source,*,native_identity,rust_identity,
            native_execution=None,rust_execution=None):
    native=capture(native_output,source,'native',binary_identity=native_identity,execution=native_execution)
    rust=capture(rust_output,source,'rust',binary_identity=rust_identity,execution=rust_execution)
    compared=0
    for spec,left,right in zip(corpus(source)['cases'],native['rows'],rust['rows'],strict=True):
        for key in('name','file','syscall_counts'):
            exact(left[key],right[key],'actual Rust/native held '+key+' differs')
        def projection(value):
            result=[]
            for effect in value['syscall_projection']:
                row=dict(effect)
                if row['operation']=='open'and row['completion']>=0:row['completion']='opened-owned-descriptor'
                result.append(row)
            return result
        exact(projection(left),projection(right),'actual Rust/native syscall completions differ')
        for kind,folder in(('native',native_output),('rust',rust_output)):
            require((kind=='native'and left or right)['semantic_result']['outcome']==spec['expected_result']['outcome'],
                    'actual held semantic outcome differs')
        for leaf in('file.bin.gz','write-payloads.bin.gz'):
            paths=[Path(folder)/spec['name']/'trace'/leaf for folder in(native_output,rust_output)]
            require(paths[0].exists()==paths[1].exists(),'actual held artifact presence differs')
            if paths[0].exists():
                left_bytes=gzip.decompress(paths[0].read_bytes());right_bytes=gzip.decompress(paths[1].read_bytes())
                require(left_bytes==right_bytes,'complete Rust/native held bytes differ');compared+=len(left_bytes)
    return dict(status='PASS',case_count=43,actual_root_processes=86,complete_compared_bytes=compared,
        native=native,rust=rust,public_handler_qualified=False,full_create_file_spec_qualified=False,
        whole_runtime_replaced=False,old_stack_removal_qualified=False)


def check_trace(evidence,spec,mode,origin,binary_identity):
    base=spec['name']+'/trace/'
    raw_result=evidence.read(base+'result.json');result=decode(raw_result)
    expected=dict(schema='hepta.runtime.owned-create-trace.v2',status='PASS',error=None,mode=mode,
        timed_out=False,timeout_seconds=60,unreaped_owned_pids=[],raw_syscall_results_preserved=True,
        all_injections_explicit=True,public_handler_qualified=False,whole_runtime_replaced=False)
    exact({key:result.get(key)for key in expected},expected,'actual held process completion/scope differs')
    require(finite(result.get('elapsed_seconds'),60),'held process deadline was not retained')
    body=content(spec['size']);work=origin['output']+'/'+spec['name']+'/work'
    path=os.fsencode(work+'/created.bin')+(b'\0tail'if spec['options'].get('nul',False)else b'')
    frame=b'HLCARQ01'+struct.pack('<7Q',1,len(path),len(body),1,0,0,0)+path+body
    stdin=evidence.compressed(base+'stdin.bin.gz');stdout=evidence.read(base+'stdout.bin');stderr=evidence.read(base+'stderr.bin')
    require(stdin==Q(len(frame))+frame,'complete actual held input differs')
    for name,raw in(('stdin',stdin),('stdout',stdout),('stderr',stderr)):
        exact(result.get(name),pin(raw),'held '+name+' full-stream identity differs')
    exact(result.get('input_delivered_bytes'),len(stdin),'held input was not completely delivered')
    event_bytes=evidence.read(base+'events.jsonl');require(event_bytes.endswith(b'\n'),'incomplete owned-process event stream')
    events=[decode(line)for line in event_bytes.splitlines()]
    require(events and len(events)==result['events']and type(result['events'])is int,'owned event count differs')
    elapsed=0
    for index,event in enumerate(events):
        exact(event.get('index'),index,'owned event ordering differs')
        require(finite(event.get('elapsed_seconds'),result['elapsed_seconds'])and event['elapsed_seconds']>=elapsed,
                'owned event clock differs');elapsed=event['elapsed_seconds']
    profile=events[0]
    profile_expected=dict(kind='profile',mode=mode,binary=origin['binary'],binary_identity=binary_identity,
        target_hex=path.hex(),timeout_seconds=60,injected_completions=spec['options'].get('injections',[]),
        fd0_setup=spec['options'].get('fd0',False),command=[origin['binary']],cwd=work,umask=0o022,
        environment={'PATH':'','LC_ALL':'C'},initial_directory_entries=[])
    exact({k:v for k,v in profile.items()if k not in('index','elapsed_seconds')},profile_expected,
          'owned execution identity, arguments, environment or fixture differs')
    root=result.get('root_pid');require(integer(root,2),'owned root PID differs')
    owned_pids={root};reaped={};holds={};barriers=[];stdout_reads=bytearray();publication=[]
    markers=[];entries=[];exits=[];prepared=[];cancel=[];wakes=[]
    allowed={'profile','owned_root','owned_descendant','process_event','process_reaped','child_first_syscall',
        'syscall_entry','syscall_exit','mechanism_syscall_entry','mechanism_syscall_exit','marker_entry',
        'signal_delivery','hold','release','cancel_signal_sent','forced_wake_signal','stdout_write_entry',
        'stdout_read','injection_prepared','fd0_setup_entry','fd0_setup_completed'}
    for event in events:
        kind=event['kind'];require(kind in allowed,'unadmitted owned process event: '+str(kind))
        if kind=='owned_root':exact(event['pid'],root,'actual owned root differs')
        elif kind=='owned_descendant':
            require(event['parent']in owned_pids and integer(event['pid'],2)and event['pid']not in owned_pids
                    and event['ptrace_event']in(1,2,3),'unreported or duplicate owned descendant')
            owned_pids.add(event['pid'])
        elif'tid'in event:require(event['tid']in owned_pids,'event escaped the reported owned process tree')
        if kind=='process_reaped':
            require(event['tid']not in reaped,'owned process reaped twice');exact(event['exit_code'],0,'actual child exit was not successful')
            reaped[event['tid']]=0
        elif kind=='hold':
            index=event['event_index'];require(integer(index)and index<event['index']and event['tid']not in holds,
                'held stop identity differs');require(events[index].get('tid')==event['tid'],'held stop TID differs')
            holds[event['tid']]=event
        elif kind=='release':
            hold=holds.pop(event['tid'],None);require(hold is not None,'release has no held actual stop')
            exact((event['held_event'],event['held_reason']),(hold['event_index'],hold['reason']),
                  'release changed the held actual boundary')
            barriers.append(dict(hold=hold,release=event,observed=events[hold['event_index']]))
        elif kind=='stdout_read':
            raw=bytes.fromhex(event['raw_hex']);exact(event['offset'],len(stdout_reads),'actual output read order differs')
            exact(event['bytes'],len(raw),'actual output read extent differs');exact(event['payload'],pin(raw),'actual output read bytes differ')
            stdout_reads.extend(raw)
        elif kind=='stdout_write_entry':
            raw=bytes.fromhex(event['raw_hex']);exact(event['length'],len(raw),'output syscall request extent differs')
            exact(event['payload'],pin(raw),'output syscall request bytes differ');publication.append(event)
        elif kind=='marker_entry':markers.append(event)
        elif kind=='syscall_entry':entries.append(event)
        elif kind=='syscall_exit':exits.append(event)
        elif kind=='injection_prepared':prepared.append(event)
        elif kind=='cancel_signal_sent':cancel.append(event)
        elif kind=='forced_wake_signal':wakes.append(event)
    require(not holds,'an actual scheduling hold was never released')
    exact(result['owned_pids'],sorted(owned_pids),'owned descendant inventory differs')
    exact(result['exit_codes'],{str(pid):0 for pid in sorted(owned_pids)},'actual process exit inventory differs')
    exact(reaped,{pid:0 for pid in sorted(owned_pids)},'actual descendant reap evidence is incomplete')
    require(bytes(stdout_reads)==stdout and b''.join(bytes.fromhex(event['raw_hex'])for event in publication)==stdout,
            'complete actual output reads and writes disagree')
    raw_markers,raw_effects=journal(stderr,mode)
    exact(Counter(event['raw_hex']for event in markers),Counter(frame.hex()for frame in raw_markers),
          'actual observer writes differ from complete stderr')
    for event in markers:
        raw=bytes.fromhex(event['raw_hex'])
        if mode=='rust':
            expected_marker=dict(owner='rust',event=U(raw,16),serial=U(raw,24),poll=U(raw,32),wake=U(raw,40),
                                 reported_tid=U(raw,48),details=[U(raw,56),U(raw,64)])
            require(event['tid']==U(raw,48),'Rust observer TID differs')
        else:
            keys=('action','life','generation','sequence','accepted','completed','result_kind','error',
                  'ticket_start','ticket_end','phase','token','flags')
            expected_marker=dict(owner='native',**{key:U(raw,16+8*i)for i,key in enumerate(keys)})
        exact({key:event.get(key)for key in expected_marker},expected_marker,'decoded actual marker differs')
    syscall_capture=check_syscalls(spec,mode,body,path,root,entries,exits,prepared,raw_effects,
                                  evidence.compressed(base+'write-payloads.bin.gz'))
    exact(result['syscall_counts'],spec['expected_calls'],'held target syscall inventory differs')
    expected_file=spec['expected_file_bytes'];file_bytes=None
    expected_file_pin=None;filesystem=[]
    if expected_file is not None:
        file_bytes=evidence.compressed(base+'file.bin.gz');require(file_bytes==body[:expected_file],'complete retained file bytes differ')
        expected_file_pin=pin(file_bytes);filesystem=[dict(name='created.bin',kind='file',mode=0o644,content=expected_file_pin)]
    else:require(not(evidence.root/base/'file.bin.gz').exists(),'absent-file case retained an unexpected file')
    exact(result['file'],expected_file_pin,'final retained file identity differs')
    exact(result['filesystem'],dict(initial_entries=[],final_entries=filesystem),'complete private fixture inventory differs')
    exact(result['completed_kernel_bytes'],0 if expected_file is None else expected_file,'actual completed byte count differs')
    semantic=check_outcome(spec,mode,stdout,raw_markers)
    exact(result['policy']['semantic_result'],semantic,'policy result differs from actual stdout')
    exact(result['policy']['expected_file_bytes'],expected_file,'policy file boundary differs')
    exact(result['policy']['scenario'],spec['scenario'],'held scenario identity differs')
    check_boundaries(spec,mode,events,markers,barriers,entries,exits,publication,cancel,wakes,root,len(stdout))
    exact(result['cancellation_sent'],bool(cancel),'cancellation flag differs from actual signal event')
    fd0=spec['options'].get('fd0',False)
    setup=[event for event in events if event['kind']=='fd0_setup_completed']
    exact(len(setup),1 if fd0 else 0,'FD0 fixture setup did not actually execute once')
    if setup:require(setup[0]['kernel_return']==0 and setup[0]['replay_original_syscall']is True,'FD0 setup failed')
    return dict(name=spec['name'],result_sha256=sha(raw_result),file=expected_file_pin,
        syscall_counts=spec['expected_calls'],owned_processes=len(owned_pids),
        elapsed_seconds=result['elapsed_seconds'],semantic_result=semantic,
        complete_file_bytes=0 if file_bytes is None else len(file_bytes),**syscall_capture)
