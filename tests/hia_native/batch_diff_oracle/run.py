"""Fresh Rust 1.95 execution of unchanged diff/apply blocks after native capture."""
from pathlib import Path
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent


def sha(path):
    value=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1<<20),b''):value.update(block)
    return value.hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def run(runtime,native,output,rustc):
    runtime,native,output,rustc=map(lambda p:Path(p).resolve(),(runtime,native,output,rustc))
    assert runtime==HERE.parents[2]
    output.mkdir(parents=True,exist_ok=False)
    assembly=load('batch_diff_original_assembly',HERE/'assemble.py')
    source=assembly.assemble(runtime,output/'generated')
    cases=load('batch_diff_original_cases',HERE/'cases.py')
    with (output/'input.bin').open('xb') as stream:count=cases.write_input(stream)
    with gzip.open(native/'requests.bin.gz','rb') as native_input,(output/'input.bin').open('rb') as original_input:
        while True:
            part=original_input.read(1<<20);assert native_input.read(len(part))==part
            if not part:break
        assert native_input.read(1)==b''
    receipts=[]
    env=dict(os.environ)
    for key in ['RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS','CARGO_BUILD_TARGET']:env.pop(key,None)
    env.update(PATH=str(rustc.parent)+':/usr/bin:/bin',RUSTC=str(rustc),LC_ALL='C')
    def execute(name,argv,stdin_path=None):
        started=time.monotonic();timed_out=False;input_stream=None
        if stdin_path is not None:input_stream=stdin_path.open('rb')
        try:
            with (output/(name+'.stdout')).open('xb') as stdout,(output/(name+'.stderr')).open('xb') as stderr:
                try:code=subprocess.run(list(map(str,argv)),cwd=HERE,env=env,stdin=input_stream,stdout=stdout,stderr=stderr,timeout=180).returncode
                except subprocess.TimeoutExpired:code=None;timed_out=True
        finally:
            if input_stream is not None:input_stream.close()
        record={'name':name,'command':list(map(str,argv)),'cwd':str(HERE),'timeout_seconds':180,'timed_out':timed_out,
                'exit_code':code,'elapsed_seconds':time.monotonic()-started,'controlled_env':{k:env[k] for k in ('PATH','RUSTC','LC_ALL')},
                'stdin':None if stdin_path is None else {'path':stdin_path.name,'bytes':stdin_path.stat().st_size,'sha256':sha(stdin_path)}}
        for kind in ('stdout','stderr'):
            path=output/(name+'.'+kind);record[kind]={'path':path.name,'bytes':path.stat().st_size,'sha256':sha(path)}
        receipts.append(record);(output/'process-receipts.json').write_text(json.dumps(receipts,indent=2,sort_keys=True)+'\n')
        assert not timed_out and code==0,record
        return output/(name+'.stdout')
    version=execute('rustc-version',[rustc,'-Vv']).read_bytes()
    assert version.startswith(b'rustc 1.95.0 (59807616e 2026-04-14)\n'),version
    binary=output/'original-batch-diff'
    execute('rustc-build',[rustc,'-O','--edition=2024',output/'generated/main.rs','-o',binary])
    original=execute('original',[binary],output/'input.bin')
    with gzip.open(native/'native-output.bin.gz','rb') as actual,original.open('rb') as expected:
        while True:
            part=expected.read(1<<20);assert actual.read(len(part))==part
            if not part:break
        assert actual.read(1)==b''
    original_summary=json.loads((output/'original.stderr').read_bytes())
    assert original_summary['status']=='PASS' and original_summary['original_cases']==count
    summary={'schema':'hepta.runtime.batch-diff-original-result.v1','status':'PASS','cases':count,
             'successful_diff_cases':original_summary['successful_diff_cases'],'actual_processes':len(receipts),
             'runtime_root':str(runtime),'native_origin':str(native),'output_root':str(output),
             'source_manifest':source,'original_stdout_bytes':original.stat().st_size,'original_stdout_sha256':sha(original),
             'input_bytes':(output/'input.bin').stat().st_size,'input_sha256':sha(output/'input.bin'),
             'binary_sha256':sha(binary),'binary_bytes':binary.stat().st_size,
             'native_result_sha256':sha(native/'result.json'),
             'execution':{'source_root':str(runtime),'python':sys.executable,'cwd':str(Path.cwd()),
                          'command':[sys.executable,'-I','-B',str(Path(__file__).resolve()),*sys.argv[1:]]},
             'public_batch_route_executed':False,'filesystem_effects_executed':False,
             'harness_sources':{str(p.relative_to(HERE)):sha(p) for p in sorted(HERE.rglob('*')) if p.is_file()}}
    (output/'result.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps(summary,sort_keys=True))
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',required=True);parser.add_argument('--native',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--rustc',required=True)
    args=parser.parse_args();run(args.runtime,args.native,args.output,args.rustc)

