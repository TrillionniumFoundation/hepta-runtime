"""Actual locked Rust replay with complete streaming comparison and receipts."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,select,shutil,subprocess,sys,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).parent))
from batch_plan_oracle_source import oracle_source,regions
ORIGINALS={'src/mcp/fs/text_editing.rs':'e55ce4df73d6e0b70e4065900d317f6b7329670ab6fcba44979ca69dcac80590','src/utils/line_hash.rs':'904bc9a70e1ade3802213cd067ab7b75bce4dd075e4ab4965f32e9964293ba57'}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def write_json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
def require(condition,message):
    if not condition:raise ValueError(message)
def source_bindings(source_root,runtime,metadata):
    sys.path.insert(0,str(source_root/'scripts'))
    from hia_native_batch_plan_qualification import SOURCE_FILES,REFERENCE_FILES,STREAMS,exact_summary,oracle_dependencies
    require(metadata.get('schema')=='hepta.runtime.batch-plan.native-corpus.v1','batch corpus schema differs')
    report=metadata.get('report',{})
    exact_summary(report)
    require(set(metadata.get('sources',{}))==set(SOURCE_FILES),'native owner source inventory differs')
    require(set(metadata.get('reference_sources',{}))==set(REFERENCE_FILES),'native reference source inventory differs')
    for kind,(name,size,digest) in STREAMS.items():
        require(metadata[kind].get('file')==name and metadata[kind].get('raw_bytes')==size and metadata[kind].get('raw_sha256')==digest,'native original replay domain differs: '+kind)
    require(report.get('status')=='PASS' and report.get('complete_domain') is True,'complete fresh native batch suite required')
    require(type(report.get('reference_rows')) is int and report['reference_rows']>0,'missing original batch rows')
    for name,wanted in metadata['sources'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'source path escaped repository')
        require(sha(source_root/name)==wanted,'native corpus source changed: '+name)
    for name,wanted in metadata.get('reference_sources',{}).items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'reference path escaped repository')
        require(sha(runtime/name)==wanted,'native corpus reference/helper source changed: '+name)
    for name,wanted in ORIGINALS.items():require(sha(runtime/name)==wanted,'original baseline source changed: '+name)
    expected=oracle_source(runtime).encode()
    require((source_root/'tests/hia_native/oracle_batch_plan.rs').read_bytes()==expected,'copied original batch blocks changed')
    return {'sources':dict(metadata['sources']),'reference_sources':dict(metadata.get('reference_sources',{})),'original_sources':dict(ORIGINALS),'oracle_dependencies':oracle_dependencies(source_root,runtime),'oracle_regions':{name:hashlib.sha256(raw.encode()).hexdigest() for name,raw in regions(runtime).items()}}
def stream_identity(path,record):
    require(path.name==record['file'] and sha(path)==record['gzip_sha256'] and path.stat().st_size==record['gzip_bytes'],'compressed corpus changed')
    digest=hashlib.sha256();size=0
    with gzip.open(path,'rb') as stream:
        while raw:=stream.read(1<<20):digest.update(raw);size+=len(raw)
    require(size==record['raw_bytes'] and digest.hexdigest()==record['raw_sha256'],'complete raw corpus changed')
def build_original(source_root,runtime,directory,cargo=None,rustc=None):
    cargo=cargo or shutil.which('cargo');require(cargo is not None,'Cargo is required for original batch owner')
    env=dict(os.environ)
    for name in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','RUSTC_BOOTSTRAP','CARGO_BUILD_TARGET','CARGO_BUILD_RUSTFLAGS'):env.pop(name,None)
    env['HIA_REFERENCE_RUNTIME']=str(runtime.resolve());env['CARGO_TARGET_DIR']=str(directory/'target')
    if rustc:env['RUSTC']=rustc
    manifest=source_root/'tests/hia_native/batch_plan_oracle/Cargo.toml'
    command=[str(cargo),'build','--release','--locked','--manifest-path',str(manifest)]
    begin=time.monotonic();code=None;timed_out=False
    try:
        result=subprocess.run(command,env=env,capture_output=True,timeout=180)
        stdout,stderr,code=result.stdout,result.stderr,result.returncode
    except subprocess.TimeoutExpired as exc:stdout,stderr=exc.stdout or b'',exc.stderr or b'';timed_out=True
    (directory/'build.stdout').write_bytes(stdout);(directory/'build.stderr').write_bytes(stderr)
    binary=directory/'target/release/hia-batch-plan-reference'
    record={'schema':'hepta.runtime.batch-plan.original-build.v1','status':'PASS' if code==0 else 'FAIL','exit_code':code,'timed_out':timed_out,'seconds':time.monotonic()-begin,'command':command,'oracle_sha256':sha(source_root/'tests/hia_native/oracle_batch_plan.rs'),'source_map':{**ORIGINALS,**{name:sha(source_root/name) for name in ['tests/hia_native/oracle_batch_plan.rs','tests/hia_native/batch_plan_oracle/Cargo.toml','tests/hia_native/batch_plan_oracle/Cargo.lock']}},'stdout_sha256':hashlib.sha256(stdout).hexdigest(),'stderr_sha256':hashlib.sha256(stderr).hexdigest()}
    if code==0:record['binary_sha256']=sha(binary)
    write_json(directory/'build.json',record)
    require(code==0 and not timed_out,'actual original Rust compilation failed; complete receipt retained')
    return binary,record

def compare(source_root,runtime,corpus,directory,*,binary=None,build_receipt=None,cargo=None,rustc=None):
    source_root=Path(source_root).resolve(strict=True);runtime=Path(runtime).resolve(strict=True)
    corpus=Path(corpus).resolve(strict=True);directory=Path(directory).absolute();directory.mkdir(parents=True,exist_ok=False)
    metadata=json.loads((corpus/'native-corpus.json').read_bytes());before=source_bindings(source_root,runtime,metadata)
    for kind in ('requests','native_output','history'):stream_identity(corpus/metadata[kind]['file'],metadata[kind])
    record={'schema':'hepta.runtime.batch-plan.original-comparison.v1','status':'FAIL','native_corpus_sha256':sha(corpus/'native-corpus.json'),'source_bindings':before,'rows_expected':metadata['report']['reference_rows'],'timeout_seconds':180}
    process=None;begin=time.monotonic();digest=hashlib.sha256();count=0;errors=[];complete=False;feeder=None;reader=None
    try:
        if binary is None:
            binary,build=build_original(source_root,runtime,directory,cargo=cargo,rustc=rustc)
            record['compilation']='actual locked Cargo invocation'
        else:
            require(build_receipt is not None,'precompiled Rust requires its actual source-bound compile receipt')
            build=json.loads(Path(build_receipt).read_bytes());binary=Path(binary).resolve(strict=True)
            require(build.get('schema')=='hepta.runtime.batch-plan.original-build.v1' and build.get('status')=='PASS' and build.get('exit_code')==0 and build.get('timed_out') is False,'precompiled original build did not pass')
            require(build['oracle_sha256']==sha(source_root/'tests/hia_native/oracle_batch_plan.rs'),'precompiled original source differs')
            for name,wanted in ORIGINALS.items():require(build['source_map'].get(name)==wanted,'precompiled original baseline differs')
            for name in ['tests/hia_native/batch_plan_oracle/Cargo.toml','tests/hia_native/batch_plan_oracle/Cargo.lock']:
                require(build['source_map'].get(name)==sha(source_root/name),'precompiled original locked dependencies differ')
            record['compilation']='reused actual source-matched compiled binary; no fresh compilation claim'
            write_json(directory/'build.json',build)
        require(sha(binary)==build['binary_sha256'],'original binary differs from compile receipt')
        record['binary_sha256']=sha(binary)
        # The pure Rust oracle has no child processes. Keep it in the owning
        # qualification process group so an outer deadline cannot strand it.
        process=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def feed():
            try:
                with gzip.open(corpus/metadata['requests']['file'],'rb') as source:
                    while raw:=source.read(1<<16):process.stdin.write(raw)
                process.stdin.close()
            except BaseException as exc:errors.append(repr(exc))
        def stderr():
            with (directory/'original.stderr').open('xb') as output:
                while raw:=process.stderr.read(1<<16):output.write(raw)
        feeder=threading.Thread(target=feed,daemon=True);reader=threading.Thread(target=stderr,daemon=True)
        feeder.start();reader.start();deadline=time.monotonic()+180
        with gzip.open(corpus/metadata['native_output']['file'],'rb') as expected, gzip.GzipFile(filename=str(directory/'original-output.bin.gz'),mode='wb',mtime=0) as retained:
            while True:
                require(time.monotonic()<deadline,'original batch replay exceeded unchanged 180-second budget')
                ready,_,_=select.select([process.stdout],[],[],min(1,max(0,deadline-time.monotonic())))
                if not ready:continue
                raw=os.read(process.stdout.fileno(),1<<16)
                if not raw:break
                retained.write(raw);digest.update(raw);offset=count;count+=len(raw)
                wanted=expected.read(len(raw))
                if raw!=wanted:
                    mismatch=next((n for n,(a,b) in enumerate(zip(raw,wanted)) if a!=b),min(len(raw),len(wanted)))
                    record['first_mismatch_offset']=offset+mismatch
                    raise AssertionError('original/native output bytes differ')
            require(expected.read(1)==b'','original replay omitted native output bytes')
        process.wait(timeout=max(.01,deadline-time.monotonic()));feeder.join(5);reader.join(5)
        require(not feeder.is_alive() and not reader.is_alive() and not errors,'original replay streams did not complete')
        require(process.returncode==0,'actual original Rust returned failure')
        actual=json.loads((directory/'original.stderr').read_bytes())
        require(actual=={'status':'PASS','original_batch_rows':metadata['report']['reference_rows']},'original replay row count differs')
        require(count==metadata['native_output']['raw_bytes'] and digest.hexdigest()==metadata['native_output']['raw_sha256'],'complete original output identity differs')
        require(source_bindings(source_root,runtime,metadata)==before and sha(binary)==record['binary_sha256'],'original inputs changed during replay')
        for kind in ('requests','native_output','history'):stream_identity(corpus/metadata[kind]['file'],metadata[kind])
        record.update(status='PASS',original_rows=actual['original_batch_rows']);complete=True
    except BaseException as exc:
        record['error']=repr(exc)
        if process is not None and process.poll() is None:process.kill();process.wait(timeout=15)
        raise
    finally:
        if feeder is not None:feeder.join(5)
        if reader is not None:reader.join(5)
        record.update(seconds=time.monotonic()-begin,output_complete=complete,stdout_bytes=count,stdout_sha256=digest.hexdigest(),exit_code=None if process is None else process.poll(),stream_errors=errors)
        write_json(directory/'comparison.json',record)
    return record

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,default=ROOT);parser.add_argument('--runtime',type=Path,default=ROOT)
    parser.add_argument('--corpus',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--binary',type=Path);parser.add_argument('--build-receipt',type=Path)
    parser.add_argument('--cargo');parser.add_argument('--rustc')
    args=parser.parse_args()
    print(json.dumps(compare(args.source_root,args.runtime,args.corpus,args.output,binary=args.binary,build_receipt=args.build_receipt,cargo=args.cargo,rustc=args.rustc),sort_keys=True))
