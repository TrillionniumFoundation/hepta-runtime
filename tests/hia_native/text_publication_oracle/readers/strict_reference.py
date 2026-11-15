"""Pure admission of complete fixed-1.95 unchanged Linux publication replay."""
from pathlib import Path
import hashlib,struct,tomllib
from common import Files,require,pin,integer,same,encoded,loads,frames,parse_wire,snapshot,unb64
from native_predecessor import evidence as native_evidence,DOMAINS
from trace_evidence import evidence as trace_evidence
from verify_sources import MANIFEST,ORIGINAL_PINS,DIRECT
import hia_native_text_publication_fixtures as fixture
SOURCE_PINS={'Cargo.lock': {'bytes': 5070, 'sha256': 'b7e3bd136133883bff99d542ae984ca7ae7c35a0dd1186d1c1808be98f03c2d5'}, 'common.py': {'bytes': 6132, 'sha256': 'dbcc268859c10b39aadbafda3196cfd47265673db409ee5a2ed8661ebb605fd5'}, 'driver.rs': {'bytes': 3128, 'sha256': '4bcc65aa7006d76444c2eef0fa58aa5221f2219244d67a813df9b2709db698f3'}, 'hia_native_text_publication_fixtures.py': {'bytes': 15120, 'sha256': '444145bdbb842da038d18d04f18484782fad7d5e50b213ef6dd78a8ac0e8b1b1'}, 'native_predecessor.py': {'bytes': 12205, 'sha256': 'c8dedc99f6334d580dff1063f28c21cc264d78f465258257b10471e2b672665d'}, 'original/Cargo.lock': {'bytes': 90148, 'sha256': '7f39704b92d5fc762a98a5313949034db464ca9485827b19b5dde7aa69902d43'}, 'original/text_file_write.rs': {'bytes': 13948, 'sha256': 'f502197e7409c5d565b1c3328816dceb9cacac8031fb4fbadd20b473286facfc'}, 'run.py': {'bytes': 14247, 'sha256': '25c7d7e8bc1c7d85372ed539f4c85126f6ef562fb6a8446ac4faeda8b1dc71a0'}, 'verify_sources.py': {'bytes': 5000, 'sha256': '0adba009fd7aec00e3c6be59ce84e354988006425400c06eaf7c43971b9ee096'}}
TRACE='getpgid,open,openat,close,read,write,readv,writev,lseek,newfstatat,fstat,statx,flock,flistxattr,geteuid,getrandom,fchmod,fsync,fdatasync,renameat,renameat2,unlinkat,fcntl,dup,dup2,dup3,exit,exit_group'
PROCESS_FIELDS={'command','cwd','pid','timeout_seconds','timed_out','start_error','started_monotonic_ns','finished_monotonic_ns','elapsed_seconds','exit_code','stdin','stdout','stderr','recorded_environment'}
def process(files,folder,record,command,cwd,environment=None):
    require(set(record)==PROCESS_FIELDS,'complete actual process receipt fields')
    same(record['command'],command,'actual fixed command');require(record['cwd']==str(cwd),'actual cwd')
    integer(record['pid'],'actual process PID',1);require(record['timeout_seconds']==180 and type(record['timeout_seconds']) is int and record['timed_out'] is False and record['start_error'] is None and record['exit_code']==0 and type(record['exit_code']) is int,'actual successful 180-second gate')
    start=integer(record['started_monotonic_ns'],'actual process start',1);end=integer(record['finished_monotonic_ns'],'actual process end',start+1)
    elapsed=record['elapsed_seconds'];require(type(elapsed) in (int,float) and 0<elapsed<180 and abs(elapsed-(end-start)/1e9)<1e-9,'actual process interval')
    if environment is not None:same(record['recorded_environment'],environment,'explicit selected compiler environment')
    raw=files.raw(folder/'stdout',record['stdout']);err=files.raw(folder/'stderr',record['stderr'])
    if record['stdin'] is not None:
        entry=record['stdin'];files.raw(entry['path'],{k:entry[k] for k in ('bytes','sha256')})
    return raw,err
def semantic_state(rows):
    return [{**{k:v for k,v in row.items() if k!='identity'},**({'file_size':row['identity'][2]} if row['kind']=='file' else {})} for row in rows]
def alias_shape(rows):
    groups={}
    for row in rows:
        if row['kind']=='file':groups.setdefault(tuple(row['identity'][:2]),[]).append(row['path_base64'])
    return sorted(sorted(g) for g in groups.values())
def evidence(*,source,output,native_root,native_source,native_build,outer_receipt,origins):
    files=Files(origins);source=Path(source);out=Path(output);nroot=Path(native_root)
    source_table=files.json(out/'SOURCE-FILES.json');same(source_table,SOURCE_PINS,'complete fixed reference source closure')
    raw_sources={name:files.raw(source/name,expected) for name,expected in SOURCE_PINS.items()}
    summary=files.json(out/'RESULT.json')
    for field in ('cases','original_processes','fresh_locked_builds','original_replay_processes'):
        integer(summary[field],'typed actual original count: '+field)
    require(summary['schema']=='hepta.runtime.text-publication-original-capture.v1' and summary['status']=='PASS','complete actual original capture')
    same(summary['domains'],DOMAINS,'unchanged original domain split')
    require(type(summary['cases']) is int and summary['cases']==99 and summary['original_processes']==8 and summary['fresh_locked_builds']==1 and summary['original_replay_processes']==4,'exact original process/case counts')
    for name in ('actual_version_fields_compared_to_own_inode','unchanged_linux_publish_executed','absolute_path_origins_differ'):
        require(summary[name] is True,'precise original scope')
    for name in ('cross_run_stat_numbers_rewritten','full_response_strings_rewritten','public_handler_executed','whole_runtime_replaced'):
        require(summary[name] is False,'no inflated or rewritten original scope')
    require(pin(files.raw(out/'SOURCE-FILES.json'))==summary['source_files'],'source table root pin')
    original={name:raw_sources['original/'+name] for name in ORIGINAL_PINS}
    spans={}
    for name,begin,end in (
      ('MAX_TEXT_INPUT',b'const MAX_TEXT_INPUT:',b'\n\nstruct Published'),
      ('PUBLISHED',b'struct Published {',b'\n\nfn local_workspace_path'),
      ('LINUX',b'#[cfg(target_os = "linux")]\nmod linux {',b'\n\n#[cfg(test)]')):
        start=original['text_file_write.rs'].index(begin);stop=original['text_file_write.rs'].index(end,start)
        raw=original['text_file_write.rs'][start:stop];spans[name]={'file':'text_file_write.rs','offset':start,**pin(raw)}
    materialized=raw_sources['driver.rs']
    for name,p in spans.items():
        raw=original['text_file_write.rs'][p['offset']:p['offset']+p['bytes']]
        token=('@@'+name+'@@').encode();require(materialized.count(token)==1,'unique original insertion')
        materialized=materialized.replace(token,raw)
    require(b'@@' not in materialized,'all unchanged original spans inserted')
    generated={'Cargo.toml':MANIFEST,'Cargo.lock':raw_sources['Cargo.lock'],'src/main.rs':materialized}
    for name,raw in generated.items():require(files.raw(out/'crate'/name)==raw,'complete actual compiler source input')
    lock=tomllib.loads(raw_sources['Cargo.lock'].decode())['package'];up=tomllib.loads(original['Cargo.lock'].decode())['package']
    registry={(p['name'],p['version']):p for p in up if 'source' in p}
    require(len(lock)==23 and [p for p in lock if 'source' not in p]==[{'name':'hepta-text-publication-original','version':'0.1.0','dependencies':sorted(DIRECT)}],'exact 22-registry carrier closure')
    for p in lock:
        if 'source' not in p:continue
        old=registry.get((p['name'],p['version']));require(old is not None and p['source']==old['source'] and p['checksum']==old['checksum'],'actual locked upstream registry identity')
    expected_manifest={'schema':'hepta.runtime.text-publication-original-source.v1','original_files':{n:pin(r) for n,r in original.items()},
        'unchanged_spans':spans,'materialized':{n:pin(r) for n,r in generated.items()},'registry_dependencies':22,
        'unchanged_complete_linux_module':True,'original_public_handler_executed':False,'original_session_policy_or_delta_executed':False}
    same(files.json(out/'SOURCE.json',summary['source_manifest']),expected_manifest,'exact unchanged source manifest')
    mapping_input=summary['native_origins_input'];require(set(mapping_input)=={'path','bytes','sha256'} and Path(mapping_input['path']).is_absolute(),'actual explicit native origin selection')
    mapping_raw=files.raw(mapping_input['path'],{k:mapping_input[k] for k in ('bytes','sha256')})
    require(files.raw(out/'NATIVE-ORIGINS.json',summary['native_origins'])==mapping_raw,'complete actual native origin mapping input')
    Files(loads(mapping_raw))
    predecessor=native_evidence(native_root,native_source,native_build,origins)
    same(files.json(out/'NATIVE-PREDECESSOR.json',summary['native_predecessor']),predecessor,'complete previously admitted native predecessor')
    files.artifacts.update(predecessor['artifact_sha256'])
    tools=files.json(out/'TOOLS.json',summary['toolchain']);require(set(tools)=={'rustc','cargo','strace'},'selected actual tools')
    for name,entry in tools.items():
        require(entry['retained']==str(out/'tool-binaries'/name),'owned complete selected tool bytes')
        files.raw(entry['retained'],{k:entry[k] for k in ('bytes','sha256')})
        require(Path(entry['path']).is_absolute(),'actual absolute tool invocation')
    binary=files.raw(out/'original.elf',{k:summary['binary'][k] for k in ('bytes','sha256')})
    require(summary['binary']['path']==str(out/'original.elf') and binary[:4]==b'\x7fELF','actual reference executable')
    same(pin(files.raw(out/'target/release/hepta-text-publication-original')),pin(binary),'actual fresh Cargo output executable')
    info=files.json(out/'rustc_info.json');info_raw=files.raw(out/'target/.rustc_info.json')
    same(loads(info_raw),info,'actual Cargo compiler identity retained')
    proc_rows=files.json(out/'PROCESSES.json',summary['processes'])
    names=['rustc-version','cargo-version','strace-version','build']+['original-'+d for d in DOMAINS]
    require([r['name'] for r in proc_rows]==names,'exact actual original process order')
    env={'RUSTC':tools['rustc']['path'],'LC_ALL':'C','CARGO_BUILD_JOBS':'2','TZ':'UTC'}
    last=integer(summary['native_predecessor_checked_monotonic_ns'],'native admission before reference',1)
    streams={}
    for row in proc_rows:
        name=row['name'];record={k:v for k,v in row.items() if k!='name'};folder=out/'processes'/name
        same(files.json(folder/'PROCESS.json'),record,'whole actual per-process receipt')
        if name.endswith('-version'):
            tool=name[:-8];command=[tools[tool]['path'],'-vV' if tool=='rustc' else '--version'];cwd=source
        elif name=='build':
            command=[tools['cargo']['path'],'build','--release','--locked','--manifest-path',str(out/'crate/Cargo.toml'),'--target-dir',str(out/'target')];cwd=out/'crate'
        else:
            domain=name[9:];folder_domain=out/'domains'/domain;cwd=folder_domain
            command=[tools['strace']['path'],'-f','-qq','-ttt','-T','-v','-xx','-yy','-s','128','-e','trace='+TRACE,'-o',str(folder_domain/'strace.log'),str(out/'original.elf')]
            require(record['stdin']['path']==str(folder_domain/'input.bin'),'actual complete replay input path')
        raw,err=process(files,folder,record,command,cwd,env);streams[name]=(raw,err)
        require(row['started_monotonic_ns']>=last,'same-process monotonic actual ordering after native admission')
        last=row['finished_monotonic_ns']
        if name!='build':require(err==b'','complete original semantic/version stderr')
    rustver=streams['rustc-version'][0]
    require(rustver.startswith(b'rustc 1.95.0 ') and b'host: x86_64-unknown-linux-gnu\n' in rustver and b'commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n' in rustver,'actual fixed Rust compiler version')
    require(streams['cargo-version'][0].startswith(b'cargo 1.95.0 '),'actual Cargo version')
    require(any(p.get('stdout','').encode()==rustver and p.get('success') is True for p in info['outputs'].values()),'Cargo actually used recorded fixed compiler')
    require(summary['finished_monotonic_ns']>=last>summary['started_monotonic_ns'],'complete original outer interval')
    actual_outer=files.json(outer_receipt);outerfolder=Path(outer_receipt).parent
    require(set(actual_outer)=={'command','cwd','elapsed_seconds','exit_code','finished_monotonic_ns','pid','start_error','started_monotonic_ns','stderr','stdout','timed_out','timeout_seconds'},'complete actual parent receipt fields')
    require(type(actual_outer['exit_code']) is int and type(actual_outer['timeout_seconds']) is int,'typed actual parent scalar fields')
    expected_command=[actual_outer['command'][0],'-I','-B',str(source/'run.py'),'--source',str(source),'--output',str(out),
        '--native-root',str(native_root),'--native-source',str(native_source),'--native-build',str(native_build),
        '--cargo',tools['cargo']['path'],'--rustc',tools['rustc']['path'],'--strace',tools['strace']['path'],
        '--native-origins',mapping_input['path']]
    same(actual_outer['command'],expected_command,'actual complete original parent command')
    require(actual_outer['cwd']==str(source) and actual_outer['exit_code']==0 and actual_outer['timed_out'] is False and actual_outer['start_error'] is None and actual_outer['timeout_seconds']==180,'actual parent gate')
    integer(actual_outer['pid'],'actual parent PID',1)
    integer(actual_outer['started_monotonic_ns'],'parent start',1)
    integer(actual_outer['finished_monotonic_ns'],'parent end',actual_outer['started_monotonic_ns']+1)
    require(0<actual_outer['elapsed_seconds']<180 and abs(actual_outer['elapsed_seconds']-(actual_outer['finished_monotonic_ns']-actual_outer['started_monotonic_ns'])/1e9)<1e-9,'actual parent time interval')
    require(actual_outer['started_monotonic_ns']<=summary['started_monotonic_ns']<summary['finished_monotonic_ns']<=actual_outer['finished_monotonic_ns'],'actual child interval inside recorded parent')
    outer_stdout=files.raw(outerfolder/'stdout',actual_outer['stdout'])
    require(files.raw(outerfolder/'stderr',actual_outer['stderr'])==b'','whole actual parent stderr')
    same(loads(outer_stdout),{k:v for k,v in summary.items() if k!='rows'},'whole parent stdout reproduces complete capture summary')
    descriptions=fixture.corpus();all_rows=[];all_traces={};successes=0;errors=0;body_bytes=0;comparisons=0
    for domain,count in DOMAINS.items():
        folder=out/'domains'/domain;dr=files.json(folder/'RESULT.json')
        require(dr['status']=='PASS' and dr['cases']==count,'complete original domain')
        ds=files.json(folder/'corpus.json')
        same(ds,[d for d in descriptions if d['domain']==domain],'unchanged unique input-only generator')
        same(ds,files.json(nroot/'domains'/domain/'corpus.json'),'same original/native logical inputs')
        input_raw=files.raw(folder/'input.bin',dr['input']);inputs=frames(input_raw)
        output_raw=streams['original-'+domain][0];require(pin(output_raw)==dr['full_original_output'],'complete original stdout binding')
        outputs=frames(output_raw);require(len(inputs)==len(outputs)==len(dr['rows'])==count,'complete original frames and rows')
        actual_process={k:v for k,v in proc_rows[names.index('original-'+domain)].items() if k!='name'}
        same(dr['process'],actual_process,'actual replay domain process receipt')
        answers={};ids=[];trace_states={}
        for ordinal,(description,row,input_frame,output_frame) in enumerate(zip(ds,dr['rows'],inputs,outputs)):
            case_id=len(all_rows);name=description['name'];case=folder/'cases'/name;tree=folder/'fixtures'/str(ordinal)
            require(type(row['case_id']) is int and type(row['ordinal']) is int and row['case_id']==case_id and row['ordinal']==ordinal and row['name']==name and row['domain']==domain and row['fixture']==str(tree),'unique actual original case identity')
            same(files.json(case/'case.json'),row,'whole actual original case receipt')
            wire=files.raw(case/'input.bin',row['input'])
            require(input_frame==b'HTXPI001'+struct.pack('<3Q',case_id,len(wire),0)+wire,'complete actual original input frame')
            mode,path,expected,text=parse_wire(wire)
            ns=nroot/'domains'/domain/'cases'/name;nwire=files.raw(ns/'input.bin',row['native_input'])
            nmode,npath,nexpected,ntext=parse_wire(nwire)
            require((mode,expected,text)==(nmode,nexpected,ntext),'all admitted original/native content bytes')
            spec=description['request'];suffix=unb64(spec['path_base64'])
            require(path==(str(tree).encode()+suffix if spec['path_anchor']=='fixture' else suffix),'original raw path unchanged except explicit fixture origin')
            require(row['native_fixture']==str(nroot/'domains'/domain/'fixtures'/str(ordinal)),'native actual fixture origin')
            require(npath==(row['native_fixture'].encode()+suffix if spec['path_anchor']=='fixture' else suffix),'native raw path exact')
            require(mode==spec['mode'] and text==fixture.materialize(spec['content']),'actual generated complete text input')
            old=snapshot(files,case/'before.json',folder/'blobs');after=snapshot(files,case/'after.json',folder/'blobs')
            require(pin(files.raw(case/'before.json'))==row['before'] and pin(files.raw(case/'after.json'))==row['after'],'complete state receipt binding')
            nb=snapshot(files,ns/'before.json',nroot/'domains'/domain/'blobs');na=snapshot(files,ns/'after.json',nroot/'domains'/domain/'blobs')
            same(semantic_state(old),semantic_state(nb),'whole actual initial metadata/content')
            same(semantic_state(after),semantic_state(na),'whole actual final metadata/content')
            same(alias_shape(old),alias_shape(nb),'actual initial hardlink identities')
            same(alias_shape(after),alias_shape(na),'actual final hardlink identities')
            if 'literal_hex' in spec['expected']:require(expected==bytes.fromhex(spec['expected']['literal_hex']),'exact expected literal')
            elif 'data' in spec['expected']:require(expected==pin(fixture.materialize(spec['expected']['data']))['sha256'].encode(),'exact preadmitted explicit digest')
            else:
                target=[r for r in old if r['path_base64']==spec['expected']['file_base64']]
                require(len(target)==1 and expected==target[0]['data']['sha256'].encode(),'actual source digest')
            record=files.raw(case/'record.bin',row['record']);require(record==output_frame and record[:8]==b'HTXPO001','whole actual original stdout record')
            rid,pn=struct.unpack_from('<2Q',record,8);require(rid==case_id and len(record)==24+pn,'actual original record framing')
            answer=loads(record[24:]);same(files.json(case/'original.json',row['original_result']),answer,'whole original parsed result')
            require(answer['case_id']==case_id and type(answer['case_id']) is int and type(answer['ok']) is bool,'typed original result identity')
            native=files.raw(ns/'record.bin');body=native[64:];tag,en,size,new,*_=struct.unpack_from('<7Q',body,8)
            require(answer['ok'] is (tag==0),'actual original success/error parity')
            if answer['ok']:
                require(set(answer)=={'case_id','ok','bytes','sha256','version','was_new_file'},'whole success schema')
                integer(answer['bytes'],'full success size');require(type(answer['was_new_file']) is bool,'typed create flag')
                require(answer['bytes']==size and answer['sha256']==body[120:152].hex() and answer['was_new_file'] is bool(new),'full original/native success fields')
                target=[r for r in after if r['path_base64']==description['expect']['target_base64']]
                require(len(target)==1 and target[0]['kind']=='file','actual original final target')
                t=target[0];require(answer['version']==':'.join(map(str,t['identity'])),'seven actual inode stat fields, no cross-run rewriting')
                data=files.raw(folder/'blobs'/t['data']['file'],{k:t['data'][k] for k in ('bytes','sha256')})
                require(len(data)==size and hashlib.sha256(data).hexdigest()==answer['sha256'],'whole actual file data binds return SHA')
                previous=[r for r in old if r['path_base64']==description['expect']['target_base64']]
                if previous:require(previous[0]['identity'][:2]!=t['identity'][:2],'original new inode for replace/append')
                successes+=1;body_bytes+=len(data);cc=6
            else:
                require(set(answer)=={'case_id','ok','short','chain','errno'},'whole error schema')
                require(type(answer['short']) is str and type(answer['chain']) is str and answer['short'].encode()==body[64:],'full short error bytes')
                if answer['errno'] is not None:integer(answer['errno'],'raw OS error',1,4095)
                same(old,after,'original ordinary error leaves actual state unchanged');errors+=1;cc=4
            require(row['comparison_count']==cc and type(row['comparison_count']) is int,'derived case comparisons')
            comparisons+=cc;all_rows.append(row);answers[case_id]=answer;ids.append(case_id)
            trace_states[case_id]=(old,after,description)
        traw=files.raw(folder/'strace.log',dr['trace']);trace=trace_evidence(traw,ids,answers)
        for case in trace['cases']:
            before,after,description=trace_states[case['case_id']]
            target=[r for r in before if r['path_base64']==description['expect']['target_base64']]
            for call in case['syscalls']:
                if call['name']=='fstat' and call['return']==0 and target and call['stat']['version'][:2]==target[0]['identity'][:2]:
                    same(call['stat']['version'],target[0]['identity'],'original source fstat binds its own initial identity')
        all_traces[domain]=trace
    same(all_rows,summary['rows'],'complete original row ordering')
    result={'schema':'hepta.runtime.text-publication-original-evidence.v1','status':'PASS','cases':99,
        'successes':successes,'errors':errors,'comparisons':comparisons,'published_file_bytes':body_bytes,
        'original_processes':8,'fresh_locked_builds':1,'original_replay_processes':4,'version_processes':3,
        'registry_dependencies':22,'unchanged_linux_bytes':spans['LINUX']['bytes'],
        'trace_syscalls':sum(t['syscalls'] for t in all_traces.values()),'marker_pairs':99,
        'trace':all_traces,'native_predecessor':predecessor,
        'original_source':expected_manifest,'toolchain':tools,'binary':summary['binary'],
        'actual_versions_bound_to_full_kernel_stat_and_own_fixture':True,'rewritten_version_fields':False,
        'ordinary_original_comparison_complete':True,'race_original_comparison_complete':False,
        'public_handler_complete':False,'whole_runtime_replaced':False,'new_original_processes':0,'new_native_calls':0,
        'transient_fixture_directories':[r['fixture'] for r in all_rows],
        'artifact_sha256':files.artifacts}
    return result
