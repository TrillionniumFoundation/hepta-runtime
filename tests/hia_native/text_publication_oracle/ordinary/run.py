"""Actual fixed-toolchain replay after a complete native capture, never a fallback."""
from __future__ import annotations
import argparse,hashlib,json,os,shutil,signal,struct,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).absolute().parent))
from common import require,pin,save,loads,encoded,frames,parse_wire,unb64,b64,same,Files
from verify_sources import assemble
from native_predecessor import evidence as native_evidence,DOMAINS
import hia_native_text_publication_fixtures as fixture

TRACE='getpgid,open,openat,close,read,write,readv,writev,lseek,newfstatat,fstat,statx,flock,flistxattr,geteuid,getrandom,fchmod,fsync,fdatasync,renameat,renameat2,unlinkat,fcntl,dup,dup2,dup3,exit,exit_group'
def file_pin(p):return pin(Path(p).read_bytes())
def source_pins(root):
    return {str(p.relative_to(root)):file_pin(p) for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts}
def proc(command,cwd,out,env,stdin=None):
    out=Path(out);out.mkdir();start=time.monotonic_ns();failure=None;timed=False;pid=None;code=None
    source=Path(stdin).open('rb') if stdin else subprocess.DEVNULL
    with (out/'stdout').open('xb') as stdout,(out/'stderr').open('xb') as stderr:
        try:
            child=subprocess.Popen(command,cwd=cwd,env=env,stdin=source,stdout=stdout,stderr=stderr,start_new_session=True)
            pid=child.pid
            for name in ('status','cmdline','cgroup'):
                try:(out/('proc-'+name)).write_bytes((Path('/proc')/str(pid)/name).read_bytes())
                except FileNotFoundError:pass
            try:code=child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(pid,signal.SIGKILL);code=child.wait()
        except BaseException as error:failure=repr(error);raise
        finally:
            if stdin:source.close()
            finished=time.monotonic_ns()
            record={'command':list(command),'cwd':str(cwd),'pid':pid,'timeout_seconds':180,'timed_out':timed,
                'start_error':failure,'started_monotonic_ns':start,'finished_monotonic_ns':finished,
                'elapsed_seconds':(finished-start)/1e9,'exit_code':code,'stdin':None if not stdin else {'path':str(stdin),**file_pin(stdin)},
                'stdout':file_pin(out/'stdout'),'stderr':file_pin(out/'stderr'),
                'recorded_environment':{k:env.get(k) for k in ('RUSTC','LC_ALL','CARGO_BUILD_JOBS','TZ')}}
            save(out/'PROCESS.json',record)
    require(code==0 and not timed and failure is None,'actual process failed: '+out.name)
    return record
def semantic_state(rows):
    result=[]
    for row in rows:
        projected={k:v for k,v in row.items() if k!='identity'}
        if row['kind']=='file':projected['file_size']=row['identity'][2]
        result.append(projected)
    return result
def original_output(raw):
    require(len(raw)>=24 and raw[:8]==b'HTXPO001','complete original output header')
    case_id,pn=struct.unpack_from('<2Q',raw,8)
    require(len(raw)==24+pn,'complete original output extent')
    value=loads(raw[24:]);require(value['case_id']==case_id,'actual original output identity')
    return value
def snapshot_case(path,blobs):return fixture.snapshot(path,blobs)
def main():
    p=argparse.ArgumentParser()
    for key in ('source','output','native-root','native-source','native-build','cargo','rustc','strace','native-origins'):p.add_argument('--'+key,type=Path,required=True)
    args=p.parse_args()
    for key,value in vars(args).items():setattr(args,key,value.absolute())
    require(os.geteuid()!=0,'ordinary Linux account')
    source=args.source;out=args.output;out.mkdir(parents=True,exist_ok=False)
    save(out/'remote-process.json',{'pid':os.getpid(),'cgroup':Path('/proc/self/cgroup').read_text(),'started_monotonic_ns':time.monotonic_ns()})
    start=time.monotonic_ns();mapping_raw=args.native_origins.read_bytes();origins=loads(mapping_raw);native_files=Files(origins)
    (out/'NATIVE-ORIGINS.json').write_bytes(mapping_raw)
    native_mapping={'path':str(args.native_origins),**pin(mapping_raw)}
    before_sources=source_pins(source);save(out/'SOURCE-FILES.json',before_sources)
    predecessor=native_evidence(args.native_root,args.native_source,args.native_build,origins)
    pred_pin=save(out/'NATIVE-PREDECESSOR.json',predecessor)
    native_finished=time.monotonic_ns()
    generated,source_manifest=assemble(source);crate=out/'crate';crate.mkdir()
    for name,raw in generated.items():
        path=crate/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    save(out/'SOURCE.json',source_manifest)
    env=dict(os.environ,RUSTC=str(args.rustc),LC_ALL='C',CARGO_BUILD_JOBS='2',TZ='UTC')
    env['PATH']=str(args.rustc.parent)+os.pathsep+env.get('PATH','')
    env.pop('CARGO_NET_OFFLINE',None)
    processes=[];process_root=out/'processes';process_root.mkdir();tools={};tool_dir=out/'tool-binaries';tool_dir.mkdir()
    for name,executable,option in (('rustc',args.rustc,'-vV'),('cargo',args.cargo,'--version'),('strace',args.strace,'--version')):
        retained=tool_dir/name;shutil.copyfile(executable,retained)
        tools[name]={'path':str(executable),'retained':str(retained),**file_pin(executable)}
        require(file_pin(retained)==file_pin(executable),'complete retained selected tool binary')
        record=proc([str(executable),option],source,process_root/(name+'-version'),env);processes.append({'name':name+'-version',**record})
    rustver=(process_root/'rustc-version/stdout').read_bytes()
    require(rustver.startswith(b'rustc 1.95.0 ') and b'host: x86_64-unknown-linux-gnu\n' in rustver,'fixed Rust 1.95 Linux toolchain')
    require((process_root/'cargo-version/stdout').read_bytes().startswith(b'cargo 1.95.0 '),'fixed Cargo 1.95')
    target=out/'target'
    record=proc([str(args.cargo),'build','--release','--locked','--manifest-path',str(crate/'Cargo.toml'),'--target-dir',str(target)],
                crate,process_root/'build',env);processes.append({'name':'build',**record})
    require(source_manifest['materialized']['Cargo.lock']==file_pin(crate/'Cargo.lock'),'locked bytes unchanged')
    binary=out/'original.elf';shutil.copy2(target/'release/hepta-text-publication-original',binary);binary_pin=file_pin(binary)
    shutil.copy2(target/'.rustc_info.json',out/'rustc_info.json')
    save(out/'TOOLS.json',tools)
    domains=out/'domains';domains.mkdir();rows=[];all_descriptions=fixture.corpus()
    for domain,count in DOMAINS.items():
        folder=domains/domain;folder.mkdir();blobs=folder/'blobs';blobs.mkdir();trees=folder/'fixtures';trees.mkdir();cases=folder/'cases';cases.mkdir()
        descriptions=[d for d in all_descriptions if d['domain']==domain]
        native_descriptions=native_files.json(args.native_root/'domains'/domain/'corpus.json')
        same(descriptions,native_descriptions,'unique original/native input description')
        save(folder/'corpus.json',descriptions);input_bytes=bytearray();records=[]
        for ordinal,description in enumerate(descriptions):
            entry=next(r for r in predecessor['rows'] if r['domain']==domain and r['ordinal']==ordinal)
            case_id=entry['case_id'];case=cases/description['name'];case.mkdir();tree=trees/str(ordinal)
            fixture.setup_fixture(tree,description['setup'])
            wire,projection=fixture.request_bytes(tree,description);(case/'input.bin').write_bytes(wire)
            native_wire=native_files.raw(entry['native_input'])
            mo,pa,ex,te=parse_wire(wire);nmo,npa,nex,nte=parse_wire(native_wire)
            require((mo,ex,te)==(nmo,nex,nte),'full original/native admitted mode/expected/text')
            suffix=unb64(description['request']['path_base64'])
            require(pa==(os.fsencode(tree)+suffix if description['request']['path_anchor']=='fixture' else suffix),'actual original path origin')
            before=snapshot_case(tree,blobs);save(case/'before.json',before)
            native_before=native_files.json(args.native_root/'domains'/domain/'cases'/description['name']/'before.json')
            same(semantic_state(before),semantic_state(native_before),'native/original actual initial content, metadata and link shape')
            frame=b'HTXPI001'+struct.pack('<3Q',case_id,len(wire),0)+wire
            input_bytes.extend(struct.pack('<Q',len(frame)));input_bytes.extend(frame)
            records.append((case_id,description,tree,case,before,entry,projection))
        (folder/'input.bin').write_bytes(input_bytes)
        traced=folder/'strace.log'
        command=[str(args.strace),'-f','-qq','-ttt','-T','-v','-xx','-yy','-s','128','-e','trace='+TRACE,'-o',str(traced),str(binary)]
        record=proc(command,folder,process_root/('original-'+domain),env,folder/'input.bin')
        processes.append({'name':'original-'+domain,**record})
        require((process_root/('original-'+domain)/'stderr').read_bytes()==b'','original process stderr empty')
        outputs=frames((process_root/('original-'+domain)/'stdout').read_bytes())
        require(len(outputs)==count,'all actual original cases completed')
        domain_rows=[]
        for original_raw,details in zip(outputs,records):
            case_id,description,tree,case,before,entry,projection=details
            result=original_output(original_raw);require(result['case_id']==case_id,'original input order')
            (case/'record.bin').write_bytes(original_raw);save(case/'original.json',result)
            after=snapshot_case(tree,blobs);save(case/'after.json',after)
            native_case=args.native_root/'domains'/domain/'cases'/description['name']
            native_after=native_files.json(native_case/'after.json')
            same(semantic_state(after),semantic_state(native_after),'full actual final bytes and metadata, without inode replacement')
            native_record=native_files.raw(native_case/'record.bin');body=native_record[64:]
            tag,en,size,new,*_=struct.unpack_from('<7Q',body,8)
            require(result['ok'] is (tag==0),'actual original success/error projection')
            if result['ok']:
                require(set(result)=={'case_id','ok','bytes','sha256','version','was_new_file'},'complete success output schema')
                require(result['bytes']==size and result['sha256']==body[120:152].hex() and result['was_new_file'] is bool(new),'complete original/native scalar result')
                actual=[r for r in after if r['path_base64']==description['expect']['target_base64']]
                require(len(actual)==1,'actual result target')
                identity=actual[0]['identity'];require(result['version']==':'.join(map(str,identity)),'original seven fields bound to its actual published inode')
                require(actual[0]['data']['sha256']==result['sha256'] and actual[0]['data']['bytes']==result['bytes'],'complete original actual file output')
                old=[r for r in before if r['path_base64']==description['expect']['target_base64']]
                if old:require(old[0]['identity'][:2]!=identity[:2],'original replace/append actual new inode')
                comparisons=6
            else:
                require(set(result)=={'case_id','ok','short','chain','errno'},'complete original error schema')
                require(result['short'].encode()==body[64:],'complete original/native short error bytes')
                require(type(result['chain']) is str and (result['errno'] is None or type(result['errno']) is int),'complete original error chain/OS errno')
                same(before,after,'original ordinary rejection preserved whole actual fixture')
                comparisons=4
            row={'case_id':case_id,'name':description['name'],'domain':domain,'ordinal':entry['ordinal'],'fixture':str(tree),
                'native_fixture':entry['native_fixture'],'input':file_pin(case/'input.bin'),'native_input':entry['native_input_pin'],
                'record':file_pin(case/'record.bin'),'before':file_pin(case/'before.json'),'after':file_pin(case/'after.json'),
                'original_result':file_pin(case/'original.json'),'request':projection,'comparison_count':comparisons}
            save(case/'case.json',row);rows.append(row);domain_rows.append(row)
        save(folder/'RESULT.json',{'status':'PASS','cases':len(domain_rows),'rows':domain_rows,
            'process':record,'input':file_pin(folder/'input.bin'),'trace':file_pin(traced),
            'full_original_output':file_pin(process_root/('original-'+domain)/'stdout')})
    same(source_pins(source),before_sources,'all original sources unchanged')
    same(native_evidence(args.native_root,args.native_source,args.native_build,origins),predecessor,'complete native predecessor unchanged after replay')
    for name,entry in tools.items():require(file_pin(entry['path'])=={k:entry[k] for k in ('bytes','sha256')},'actual selected tool bytes unchanged')
    require(file_pin(binary)==binary_pin,'complete reference ELF unchanged')
    save(out/'PROCESSES.json',processes)
    result={'schema':'hepta.runtime.text-publication-original-capture.v1','status':'PASS','cases':99,'domains':DOMAINS,
        'rows':rows,'original_processes':len(processes),'fresh_locked_builds':1,'original_replay_processes':4,
        'binary':{'path':str(binary),**binary_pin},'native_predecessor':pred_pin,
        'native_predecessor_checked_monotonic_ns':native_finished,
        'started_monotonic_ns':start,'finished_monotonic_ns':time.monotonic_ns(),
        'source_manifest':file_pin(out/'SOURCE.json'),'source_files':file_pin(out/'SOURCE-FILES.json'),
        'native_origins_input':native_mapping,'native_origins':file_pin(out/'NATIVE-ORIGINS.json'),
        'processes':file_pin(out/'PROCESSES.json'),'toolchain':file_pin(out/'TOOLS.json'),
        'actual_version_fields_compared_to_own_inode':True,'cross_run_stat_numbers_rewritten':False,
        'absolute_path_origins_differ':True,'full_response_strings_rewritten':False,
        'unchanged_linux_publish_executed':True,'public_handler_executed':False,'whole_runtime_replaced':False}
    save(out/'RESULT.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},sort_keys=True),flush=True)
if __name__=='__main__':main()
