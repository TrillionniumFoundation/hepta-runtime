"""Pure complete original race admission; no fixture restoration or execution."""
from pathlib import Path
import os,struct
from common import Files,require,pin,integer,same,encoded,loads,frames,parse_wire,snapshot,unb64
from strict_reference import evidence as ordinary_evidence,semantic_state,alias_shape
from race_native_predecessor import evidence as race_native_evidence
from race_cases import race_cases
from ptrace_evidence import evidence as trace_evidence,blob
import hia_native_text_publication_fixtures as fixture
PINS={'GENERATOR-SOURCE.json': {'bytes': 396, 'sha256': 'ec858f8d91e6353db0b0b0494e2e71c69e81d5202eae7e764f3ff07d978902a0'}, 'original/native_races.py': {'bytes': 19050, 'sha256': '550cf160469171fda477dc5f7fdae070a094727a04f7ce6085d0fff3e190a421'}, 'ptrace_capture.py': {'bytes': 11988, 'sha256': 'fd796b8ffca32c6a94eec53d8ea9869a63f57b90df73c9c890386fbc3dc1fe18'}, 'race_cases.py': {'bytes': 3374, 'sha256': '337aebcf57b9f7998813f3c1b154722083397a660172c477875988037c0f32cc'}, 'race_native_predecessor.py': {'bytes': 6327, 'sha256': 'a7af1aeec6d94121dd256f3c15cb7553f099af0d86a9f3ae425ed56c177942a9'}, 'run_races.py': {'bytes': 17119, 'sha256': '2e89ff4e0c656691f3e9531ee28078ab23195dfb15ae34dac551912744e56aa9'}}
ORDINARY_READER_PINS={'strict_reference.py': {'bytes': 22488, 'sha256': 'f797b9e1e7e1e337adf33367d7f76391930adce36b71bf7674fa601a10d2b81b'}, 'trace_evidence.py': {'bytes': 10447, 'sha256': '01586d600bd23761c08141c80912e80184859484a2147aaeb6f5bd99a8ee4407'}}
def process(p):
    require(p['exit_code']==0 and type(p['exit_code']) is int and p['timed_out'] is False and p['start_error'] is None,'successful real original process')
    require(type(p['timeout_seconds']) is int and p['timeout_seconds']==180,'actual unchanged 180-second budget')
    integer(p['pid'],'actual PID',1);a=integer(p['started_monotonic_ns'],'actual start',1);b=integer(p['finished_monotonic_ns'],'actual end',a+1)
    require(type(p['elapsed_seconds']) in (float,int) and 0<p['elapsed_seconds']<180 and abs(p['elapsed_seconds']-(b-a)/1e9)<1e-9,'actual process duration')
def evidence(*,source,output,native_corpus,outer_receipt,origins):
    f=Files(origins);source=Path(source);out=Path(output);native_corpus=Path(native_corpus)
    table=f.json(out/'SOURCE-FILES.json');same(table,PINS,'all actual race source bytes')
    raw={n:f.raw(source/n,p) for n,p in PINS.items()}
    full=raw['original/native_races.py'];begin=full.index(b'def race_cases():');end=full.index(b'\ndef parse_receipt(',begin)
    part=full[begin:end];prefix=b'from hia_native_text_publication_fixtures import b64,data,node,file_node,case,EXISTING_LIMIT\n'
    require(raw['race_cases.py']==prefix+part,'whole unchanged unique native case generator')
    same(loads(raw['GENERATOR-SOURCE.json']),{'original_source':'original/native_races.py',
      'original':pin(full),'span':{'offset':begin,**pin(part)},'generated':pin(prefix+part),'whole_function_unchanged':True},'exact generator extraction source')
    summary=f.json(out/'RESULT.json');require(summary['schema']=='hepta.runtime.text-publication-original-races.v1' and summary['status']=='PASS','actual complete original race capture')
    for key,want in (('cases',20),('actual_external_mutations',20),('original_replay_processes',1),('new_fresh_builds',0),('new_native_calls',0)):
        require(type(summary[key]) is int and summary[key]==want,'typed exact actual race domain count')
    require(summary['syscall_results_injected'] is False and summary['tracee_instructions_modified'] is False and summary['actual_original_stat_fields_preserved'] is True and summary['unchanged_linux_publish_executed'] is True,'unchanged original external-writer observation')
    require(summary['public_handler_complete'] is False and summary['whole_runtime_replaced'] is False,'no public/runtime scope inflation')
    require(summary['source_files']==pin(f.raw(out/'SOURCE-FILES.json')),'whole race source table binding')
    reference_input=summary['ordinary_request_input'];require(set(reference_input)=={'path','bytes','sha256'},'complete actual original request input')
    reference_raw=f.raw(reference_input['path'],{k:reference_input[k] for k in ('bytes','sha256')})
    require(f.raw(out/'ORDINARY-REQUEST.json')==reference_raw,'complete native predecessor/reference selection input')
    reader_root=Path(summary['ordinary_reader']);reader_pins=f.json(out/'ORDINARY-READERS.json',summary['ordinary_readers'])
    same(reader_pins,ORDINARY_READER_PINS,'exact actual ordinary pure-reader source')
    for name,expected in reader_pins.items():f.raw(reader_root/name,expected)
    ore=loads(reference_raw);require(ore['native_root']==str(native_corpus),'same completed native corpus')
    ordinary=ordinary_evidence(**{**ore,'origins':origins})
    same(f.json(out/'ORDINARY-EVIDENCE.json',summary['ordinary_reference_evidence']),ordinary,'same fresh fixed-1.95 ordinary original source/binary')
    f.artifacts.update(ordinary['artifact_sha256'])
    predecessor=race_native_evidence(native_corpus,origins)
    same(f.json(out/'NATIVE-PREDECESSOR.json',summary['native_predecessor']),predecessor,'all actual native races precede original replay')
    f.artifacts.update(predecessor['artifact_sha256'])
    binary=summary['reused_original_binary'];same(binary,ordinary['binary'],'reuse exact already-admitted original executable')
    f.raw(binary['path'],{k:binary[k] for k in ('bytes','sha256')})
    p=f.json(out/'process/PROCESS.json');same(p,summary['process'],'complete actual ptrace original process')
    process(p);require(p['command']==[binary['path']] and p['cwd']==str(out),'actual unchanged reference invocation')
    require(p['failure'] is None and p['remaining_fds']=={} and p['recorded_environment']=={'LC_ALL':'C','TZ':'UTC'},'complete actual replay state')
    require(p['ptrace_operations']==[0,12,24,16896,16910] and type(p['writes_to_tracee_memory_or_registers']) is int and p['writes_to_tracee_memory_or_registers']==0 and type(p['syscall_results_injected']) is int and p['syscall_results_injected']==0,'observation without memory/register/result injection')
    exe=f.json(out/'process/EXECUTABLE.json');same(exe,{'invocation':binary['path'],'kernel_exe':binary['path'],**{k:binary[k] for k in ('bytes','sha256')}},'actual kernel-selected original executable')
    for name in ('status','cmdline','cgroup','maps'):f.raw(out/'process'/('proc-'+name))
    require(f.raw(out/'process/proc-cmdline')==binary['path'].encode()+b'\0','actual original argv')
    actual=f.json(outer_receipt);process(actual)
    command=[actual['command'][0],'-I','-B',str(source/'run_races.py'),'--source',str(source),'--output',str(out),'--native-corpus',str(native_corpus),'--ordinary-request',reference_input['path'],'--ordinary-reader',str(reader_root)]
    require(actual['command']==command and actual['cwd']==str(source),'actual full race producer command')
    require(actual['started_monotonic_ns']<=summary['started_monotonic_ns']<summary['native_predecessor_checked_monotonic_ns']<p['started_monotonic_ns']<p['finished_monotonic_ns']<=summary['finished_monotonic_ns']<=actual['finished_monotonic_ns'],'actual native admission and child replay interval')
    parent=Path(outer_receipt).parent
    same(loads(f.raw(parent/'stdout',actual['stdout'])),{k:v for k,v in summary.items() if k not in ('rows','process')},'complete actual parent stdout')
    require(f.raw(parent/'stderr',actual['stderr'])==f.raw(out/'process/stderr',p['stderr'])==b'','whole actual original stderr')
    input_raw=f.raw(out/'input.bin',summary['input']);require(p['stdin']=={'path':str(out/'input.bin'),**pin(input_raw)},'actual complete input stream identity')
    inputs=frames(input_raw);outputs=frames(f.raw(out/'process/stdout',p['stdout']))
    require(len(inputs)==len(outputs)==len(summary['rows'])==20,'all original race input/output rows')
    trace=trace_evidence(f,out/'process',p,list(range(1000,1020)))
    descriptions=f.json(out/'corpus.json');same(descriptions,race_cases(),'all exact original race inputs')
    nativeblobs=native_corpus/'domains/races/blobs';rows=[];successes=0;errors=0;renames=0;body_bytes=0
    for i,(desc,row,frame,record) in enumerate(zip(descriptions,summary['rows'],inputs,outputs)):
        cid=1000+i;case=out/'cases'/desc['name'];ncase=native_corpus/'domains/races/cases'/desc['name'];tree=out/'fixtures'/str(i)
        require(type(row['case_id']) is int and row['case_id']==cid and type(row['ordinal']) is int and row['ordinal']==i and row['name']==desc['name'] and row['fixture']==str(tree) and row['native_case']==str(ncase),'exact original race identity/origins')
        same(f.json(case/'case.json'),row,'whole complete race case index')
        wire=f.raw(case/'input.bin',row['input']);require(frame==b'HTXPI001'+struct.pack('<3Q',cid,len(wire),0)+wire,'whole actual original case input')
        mode,path,expected,text=parse_wire(wire);nm,np,ne,nt=parse_wire(f.raw(ncase/'input.bin'))
        require((mode,expected,text)==(nm,ne,nt),'complete native/original admitted bytes')
        require(path==str(tree).encode()+unb64(desc['request']['path_base64']),'exact raw owned path without response replacement')
        before=snapshot(f,case/'before.json',out/'blobs');after=snapshot(f,case/'after.json',out/'blobs')
        require(row['before']==pin(f.raw(case/'before.json')) and row['after']==pin(f.raw(case/'after.json')),'complete actual state pin')
        nb=snapshot(f,ncase/'before.json',nativeblobs);na=snapshot(f,ncase/'after.json',nativeblobs)
        same(semantic_state(before),semantic_state(nb),'whole actual initial race content/metadata')
        same(semantic_state(after),semantic_state(na),'whole actual final race content/metadata')
        same(alias_shape(before),alias_shape(nb),'initial actual alias relationships');same(alias_shape(after),alias_shape(na),'final actual alias relationships')
        require(record==f.raw(case/'record.bin',row['record']) and record[:8]==b'HTXPO001','whole actual original race stdout')
        rid,n=struct.unpack_from('<2Q',record,8);require(rid==cid and len(record)==24+n,'actual race output frame')
        answer=loads(record[24:]);same(f.json(case/'original.json',row['original']),answer,'full parsed original body')
        nbody=f.raw(ncase/'record.bin')[64:];tag,en,size,new,*_=struct.unpack_from('<7Q',nbody,8)
        require(type(answer['case_id']) is int and answer['case_id']==cid and type(answer['ok']) is bool and answer['ok'] is (tag==0),'actual race success/error parity')
        original_case=trace['cases'][cid];calls=original_case['calls']
        require(row['begin_event']==original_case['begin']['event'] and row['end_event']==original_case['end']['event'],'actual case syscall marker span')
        actual_renames=[x for x in calls if x['entry']['number'] in (264,316) and x['exit']['return']==0]
        require(type(row['successful_renames']) is int and row['successful_renames']==len(actual_renames)==int(desc['race']['published']),'actual rename before later outcome')
        renames+=len(actual_renames)
        actor=f.json(case/'actor.json',row['actor'])
        require(actor['case_id']==cid and actor['name']==desc['name'],'actual actor identity')
        same(actor['operation'],desc['race']['action'],'actual unchanged mutation input')
        require(actor['effect_results_injected'] is False and actor['tracee_memory_or_registers_written'] is False,'no fake syscall or original memory intervention')
        astates=[actor['before'],actor['after']]
        for state in astates:check_state(f,state,out/'blobs')
        trigger,entry,interval=expected_trigger(desc['name'],calls)
        require(actor['entry_event']==entry['event'] and actor['trigger_event']==trigger['event'] and actor['trigger_kind']==trigger['kind'] and actor['original_interval']==interval,'actual corresponding original syscall boundary')
        same(actor['child_registers_before'],trigger['registers'],'actual registers at actor stop')
        same(actor['child_registers_after'],trigger['registers'],'original instructions/registers unchanged')
        ast=integer(actor['monotonic_start_ns'],'actual actor start',trigger['monotonic_ns'])
        aen=integer(actor['monotonic_end_ns'],'actual actor end',ast)
        require(aen<trace['events'][trigger['event']+1]['monotonic_ns'],'actual mutation completed before next original syscall stop')
        status=bytes.fromhex(actor['child_status_hex'])
        require(('TracerPid:\t'+str(actual['pid'])+'\n').encode() in status and ('Pid:\t'+str(p['pid'])+'\n').encode() in status,'actual observer/tracee identity')
        check_action(f,desc,actor,out/'blobs')
        check_fd_observations(actor,calls,trigger,p,out)
        source_reads=[x for x in calls if x['entry']['number']==0 and x['entry']['details'].get('fd_owner',{}).get('role')=='source' and x['exit']['return']>=0]
        read_bytes=b''.join(blob(f,out/'process',x['exit']['details']['data']) for x in source_reads)
        if source_reads:
            target=next(x for x in before if x['path_base64']==desc['expect']['target_base64'])
            prior=f.raw(out/'blobs'/target['data']['file'],{k:target['data'][k] for k in ('bytes','sha256')})
            if desc['name'] in ('grow-during-read','grow-past-reader-limit'):
                observed=next(x for x in actor['after'] if x['path_base64']==desc['expect']['target_base64'])
                wanted=f.raw(out/'blobs'/observed['data']['file'],{k:observed['data'][k] for k in ('bytes','sha256')})
            elif desc['name']=='shrink-during-read':wanted=prior[:source_reads[0]['exit']['return']]
            else:wanted=prior
            require(read_bytes==wanted,'entire real original source read bytes across external mutation')
        stage_writes=[x for x in calls if x['entry']['number']==1 and x['entry']['details'].get('fd_owner',{}).get('role')=='stage' and x['exit']['return']>=0]
        written=b''.join(blob(f,out/'process',x['entry']['details']['data'])[:x['exit']['return']] for x in stage_writes)
        if stage_writes:require(written==fixture.expected_output(desc),'whole original actual staging writes')
        if actual_renames:
            rename=actual_renames[0];named=rename['entry']['details']
            require(bytes.fromhex(named['destination_hex'])==path.rsplit(b'/',1)[-1],'actual atomic destination component')
            stage=[x for x in calls if x['entry']['number']==257 and x['entry']['args'][2]&0o300==0o300]
            require(len(stage)==1 and stage[0]['entry']['details']['path_hex']==named['source_hex'],'same unique generated staging filename')
            syncs=[x for x in calls if x['entry']['number']==74]
            require(len(syncs)==2 and all(x['exit']['return']==0 for x in syncs) and syncs[0]['exit']['event']<rename['entry']['event']<syncs[1]['entry']['event'],'actual file fsync then rename then held parent fsync')
        if answer['ok']:
            require(set(answer)=={'case_id','ok','bytes','sha256','version','was_new_file'},'complete race success fields')
            require(type(answer['bytes']) is int and type(answer['was_new_file']) is bool and answer['bytes']==size and answer['sha256']==nbody[120:152].hex() and answer['was_new_file'] is bool(new),'complete native/original success values')
            target=next(x for x in after if x['path_base64']==desc['race']['after_target_base64'])
            actual_data=f.raw(out/'blobs'/target['data']['file'],{k:target['data'][k] for k in ('bytes','sha256')})
            require(actual_data==fixture.materialize(desc['race']['actual_data']),'whole actual external-writer final content')
            require(answer['version']==':'.join(map(str,target['identity'])),'own actual seven-field version')
            finalstats=[x['exit']['details']['stat'] for x in calls if x['entry']['number']==262 and x['exit']['return']==0]
            require(finalstats and finalstats[-1]['version']==target['identity'],'actual final kernel stat and returned version')
            require(answer['sha256']==fixture.digest(written),'returned SHA identifies actual staged bytes even after external overwrite')
            if desc['name']=='same-inode-same-size-overwrite-after-rename':
                require(actual_data!=written and len(actual_data)==len(written),'actual same-size final overwrite remains distinguishable')
            successes+=1;body_bytes+=len(actual_data)
        else:
            require(set(answer)=={'case_id','ok','short','chain','errno'} and type(answer['short']) is str and type(answer['chain']) is str,'whole original error and chain')
            require(answer['short'].encode()==nbody[64:],'whole original/native error bytes')
            if answer['errno'] is not None:integer(answer['errno'],'actual raw errno',1,4095)
            stable=lambda xs:[x for x in xs if x['kind']!='directory' and not unb64(x['path_base64']).split(b'/')[-1].startswith(b'.hepta-text-')]
            same(stable(after),stable(actor['after']),'error preserves actual external writer result and cleans only staging')
            errors+=1
        rows.append({'case_id':cid,'name':desc['name'],'syscall_pairs':len(calls),'begin_event':row['begin_event'],'end_event':row['end_event'],
          'actor_trigger_event':trigger['event'],'original_interval':interval,'successful_renames':len(actual_renames),
          'actual_source_read_bytes':len(read_bytes),'actual_staging_write_bytes':len(written),'whole_original_result':answer})
    require((successes,errors,renames,body_bytes)==(summary['successes'],summary['errors'],summary['successful_atomic_renames'],summary['actual_final_success_file_bytes']),'recomputed complete actual original race counts')
    return {'schema':'hepta.runtime.text-publication-original-race-evidence.v1','status':'PASS','cases':20,
      'successes':successes,'errors':errors,'successful_atomic_renames':renames,'actual_final_success_file_bytes':body_bytes,
      'actual_external_mutations':20,'trace_syscalls':trace['syscall_entries'],'trace_events':trace['trace_events'],
      'opens':trace['opens'],'closes':trace['closes'],'marker_pairs':trace['markers'],'rows':rows,
      'new_original_processes':0,'actual_original_replay_processes':1,'shared_fresh_locked_builds_from_ordinary':1,
      'source_sha256':PINS,'ordinary_reference':ordinary,'native_race_predecessor':predecessor,
      'whole_trace_memory_buffers_bound':True,'actual_versions_preserved':True,'original_read_chunks_assumed_equal_to_native':False,
      'syscall_or_tracee_memory_injection':False,'public_handler_complete':False,'whole_runtime_replaced':False,
      'transient_fixture_directories':[r['fixture'] for r in summary['rows']],
      'artifact_sha256':f.artifacts}

def expected_trigger(name,calls):
    owner=lambda p:(p['entry']['details'].get('fd_owner') or {}).get('role')
    source_stats=[p for p in calls if p['entry']['number']==5 and owner(p)=='source' and p['exit']['return']==0]
    if name in ('grow-during-read','grow-past-reader-limit'):
        p=source_stats[0];interval='after first source fstat, before source eligibility/read'
    elif name=='shrink-during-read':
        p=next(p for p in calls if p['entry']['number']==0 and owner(p)=='source' and p['exit']['return']>=0);interval='after first real source read completed'
    elif name in ('replace-open-path','unlink-open-path'):
        p=next(p for p in calls if p['entry']['number']==257 and p['entry']['args'][2]&0o300==0 and not p['entry']['args'][2]&0o200000 and p['exit']['return']>=0);interval='after source openat, before its first fstat'
    elif name in ('replace-after-final-source-stat','unlink-after-final-source-stat'):
        p=source_stats[1];interval='after second source fstat completed'
    elif name in ('replace-before-publish','unlink-before-publish','chmod-before-publish'):
        p=next(p for p in calls if p['entry']['number']==3 and owner(p)=='stage' and p['exit']['return']==0);interval='after staging close, before final source pathname check'
    elif name=='competing-create-after-random':
        p=next(p for p in calls if p['entry']['number']==257 and p['entry']['args'][2]&0o300==0o300)
        return p['entry'],p['entry'],'after unchanged temp_name returned, before actual staging openat; no intervening filesystem syscall'
    elif name in ('competing-create-before-probe','held-parent-directory-renamed'):
        p=next(p for p in calls if p['entry']['number']==73 and p['exit']['return']==0);interval='after advisory parent flock completed'
    elif name=='replace-after-final-source-check':
        p=next(p for p in calls if p['entry']['number']==262 and p['exit']['return']==0);interval='after final source pathname fstatat, before atomic rename'
    else:
        require(name in ('unlink-after-rename','same-inode-same-size-overwrite-after-rename','shrink-after-rename','extend-after-rename','replace-inode-after-rename','symlink-after-rename'),'explicit known external race')
        p=next(p for p in calls if p['entry']['number'] in (264,316) and p['exit']['return']==0);interval='after actual atomic rename completed, before directory fsync'
    return p['exit'],p['entry'],interval
def check_state(f,rows,blobs):
    require(type(rows) is list and rows,'whole actual nested actor state');seen=set()
    for row in rows:
        path=unb64(row['path_base64']);require(path not in seen and not path.startswith(b'/') and b'\0' not in path and b'..' not in path.split(b'/'),'safe unique actual actor path');seen.add(path)
        require(row['kind'] in ('directory','file','symlink'),'actual race node kinds')
        require(type(row['identity']) is list and len(row['identity'])==7,'all own actual stat fields')
        for i,v in enumerate(row['identity']):integer(v,'actual nested stat field',-(1<<63) if i in (3,5) else 0)
        require(0<=row['identity'][4]<10**9 and 0<=row['identity'][6]<10**9,'actual nested nanoseconds')
        for key in ('uid','gid','nlink','mode'):integer(row[key],'actual nested metadata')
        if row['kind']=='file':
            data=row['data'];require(data['file']==data['sha256']+'.bin','content addressed nested file')
            raw=f.raw(Path(blobs)/data['file'],{k:data[k] for k in ('bytes','sha256')})
            require(len(raw)==row['identity'][2],'whole actual nested file data')
        elif row['kind']=='symlink':unb64(row['target_base64'])
        for name,value in row.get('xattrs',{}).items():unb64(name);unb64(value)
    require(b'' in seen,'owned actor snapshot root')

def check_action(f,desc,actor,blobs):
    before={unb64(x['path_base64']):x for x in actor['before']}
    after={unb64(x['path_base64']):x for x in actor['after']}
    target=unb64(desc['expect']['target_base64']);action=desc['race']['action'];op=action['op']
    def data(row):return f.raw(Path(blobs)/row['data']['file'],{k:row['data'][k] for k in ('bytes','sha256')})
    if op=='rename_parent':
        a=unb64(action['from_base64']);b=unb64(action['to_base64'])
        require(a in before and a not in after and b not in before and b in after,'actual held-parent rename shape')
        require(before[a]['kind']==after[b]['kind']=='directory' and before[a]['identity'][:2]==after[b]['identity'][:2],'same held parent inode across external rename')
        require(before.keys()-{a}==after.keys()-{b},'only declared parent pathname changed')
        return
    old=before.get(target);new=after.get(target)
    if op=='unlink':require(old is not None and new is None,'actual external unlink')
    elif op=='symlink':
        require(old is not None and new is not None and new['kind']=='symlink' and new['target_base64']==action['target_base64'],'actual external replacement symlink')
    elif op in ('replace','create'):
        require(new is not None and new['kind']=='file' and data(new)==fixture.materialize(action['data']) and new['mode']==0o600,'whole actual external replacement content')
        require(old is None if op=='create' else old is not None and old['identity'][:2]!=new['identity'][:2],'actual external create/replace inode relation')
    elif op in ('append','truncate','overwrite','chmod_and_mtime'):
        require(old is not None and new is not None and old['kind']==new['kind']=='file' and old['identity'][:2]==new['identity'][:2],'actual external in-place mutation identity')
        prior=data(old);current=data(new)
        if op=='append':require(current==prior+fixture.materialize(action['data']),'complete actual external append bytes')
        elif op=='truncate':require(current==prior[:action['size']] and len(current)==action['size'],'complete actual external truncate bytes')
        elif op=='overwrite':require(current==fixture.materialize(action['data']) and len(current)==len(prior),'actual same-size overwrite bytes')
        else:
            require(current==prior and new['mode']==action['mode'],'actual chmod preserves all content')
            require(new['identity'][3]*10**9+new['identity'][4]==old['identity'][3]*10**9+old['identity'][4]-2000000000,'actual external pinned mtime adjustment')
    else:raise ValueError('unknown actual external action')
    stable=lambda d:{k.hex():v for k,v in d.items() if k!=target and v['kind']!='directory'}
    same(stable(before),stable(after),'external actor changed only the declared file')

def check_fd_observations(actor,calls,trigger,process,out):
    live={}
    for pair in calls:
        entry=pair['entry'];exit=pair['exit']
        if exit['event']>trigger['event']:break
        n=entry['number'];args=entry['args'];ret=exit['return']
        if n in (2,257) and ret>=0:
            name=bytes.fromhex(entry['details']['path_hex'])
            if name.startswith(b'/'):full=name
            else:
                require(args[0] in live,'actual parent FD before relative open')
                full=live[args[0]].rstrip(b'/')+b'/'+name
            live[ret]=full
        elif n==3 and ret==0:
            require(args[0] in live,'actual scope close before actor')
            del live[args[0]]
    wanted={0:process['stdin']['path'].encode(),1:str(Path(out)/'process/stdout').encode(),2:str(Path(out)/'process/stderr').encode(),**live}
    observed=actor['actual_fd_observations'];require(type(observed) is list,'complete actual actor FD snapshot')
    require([x['fd'] for x in observed]==sorted(wanted),'every actual live FD at actor boundary')
    for x in observed:
        integer(x['fd'],'actual observed descriptor')
        require(bytes.fromhex(x['target_hex'])==wanted[x['fd']],'actual held descriptor path relationship')
        require(type(x['identity']) is list and len(x['identity'])==7,'all actual held descriptor stat fields')
        for j,value in enumerate(x['identity']):integer(value,'actual fd stat',-(1<<63) if j in (3,5) else 0)
