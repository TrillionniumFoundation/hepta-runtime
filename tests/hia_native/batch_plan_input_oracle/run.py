"""Fresh locked original replay, only after complete native capture exists."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import time


def pin(path):
    with Path(path).open('rb') as stream:return {'bytes':Path(path).stat().st_size,'sha256':hashlib.file_digest(stream,'sha256').hexdigest()}
def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def verify(runtime,here):
    declared=json.loads((here/'source_manifest.json').read_bytes())
    original=runtime/'tests/hia_native/batch_edit_params_oracle'
    spec=importlib.util.spec_from_file_location('_typed_original_sources',original/'verify_sources.py')
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    assert verifier.verify(runtime,original)==declared['typed_manifest']
    assert (here/'src/original.rs').read_bytes()==(original/'src/original.rs').read_bytes()
    raw=(runtime/declared['editable_source']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==declared['editable_source_sha256']
    start=raw.index(b'const LF_ENDING:');stop=raw.index(b'\nfn sanitize_incoming_content(',start)
    editable=b'// Copyright 2026 Muvon Un Limited\n// SPDX-License-Identifier: Apache-2.0\nuse anyhow::{anyhow, bail, Result};\n'+raw[start:stop]
    assert editable==(here/'src/editable_original.rs').read_bytes()
    assert pin(here/'src/editable_original.rs')=={'bytes':declared['editable_original_bytes'],'sha256':declared['editable_original_sha256']}
    for name in ['Cargo.toml','Cargo.lock']:
        assert (here/name).read_bytes()==(original/name).read_bytes().replace(b'hepta-batch-edit-params-original-oracle',b'hepta-batch-plan-input-original-oracle')
    return declared


def run(runtime,output,native,rust_bin):
    runtime,output,native,rust_bin=[Path(p).resolve() for p in (runtime,output,native,rust_bin)]
    here=Path(__file__).resolve().parent;output.mkdir(parents=True,exist_ok=False)
    declared=verify(runtime,here);native_summary=json.loads((native/'result.json').read_bytes())
    assert native_summary['status']=='PASS' and native_summary['original_reference_status']=='NOT_RUN'
    native_pins={name:pin(native/name) for name in ['result.json','calls.jsonl','calls.bin.gz','native-cases.jsonl','controls.jsonl','native-results.bin','original-input.jsonl']}
    toolchain={name:{'path':str(rust_bin/name),**pin(rust_bin/name)} for name in ['rustc','cargo']}
    source_pins={str(p.relative_to(runtime)):pin(p)['sha256'] for p in sorted(here.rglob('*')) if p.is_file()}
    source_pins.update({name:pin(runtime/name)['sha256'] for name in [declared['typed_source'],declared['editable_source'],
        'tests/hia_native/batch_edit_params_oracle/source_manifest.json','tests/hia_native/batch_edit_params_oracle/verify_sources.py',
        'tests/hia_native/batch_edit_params_oracle/src/original.rs','tests/hia_native/batch_edit_params_oracle/Cargo.toml','tests/hia_native/batch_edit_params_oracle/Cargo.lock']})
    env=dict(os.environ);env.update(PATH=str(rust_bin)+':/usr/bin:/bin',RUSTC=str(rust_bin/'rustc'),CARGO_BUILD_JOBS='2',LC_ALL='C',CARGO_TARGET_DIR=str(output/'target'))
    records=[]
    def execute(name,args,stdin=None):
        start=time.monotonic();timed=False
        with (output/(name+'.stdout')).open('xb') as out,(output/(name+'.stderr')).open('xb') as err:
            source=None if stdin is None else Path(stdin).open('rb')
            try:
                child=subprocess.Popen(list(map(str,args)),stdin=source or subprocess.DEVNULL,cwd=here,env=env,stdout=out,stderr=err,start_new_session=True)
                try:code=child.wait(timeout=180)
                except subprocess.TimeoutExpired:timed=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait(timeout=3)
            finally:
                if source is not None:source.close()
        row={'name':name,'command':list(map(str,args)),'cwd':str(here),'pid':child.pid,'exit_code':code,'timed_out':timed,
             'timeout_seconds':180,'elapsed_seconds':time.monotonic()-start,
             'controlled_env':{key:env[key] for key in ['PATH','RUSTC','CARGO_BUILD_JOBS','LC_ALL','CARGO_TARGET_DIR']},
             'stdin':None if stdin is None else {'path':str(stdin),**pin(stdin)}}
        for kind in ['stdout','stderr']:row[kind]={'path':name+'.'+kind,**pin(output/(name+'.'+kind))}
        records.append(row);save(output/'processes.json',records)
        assert code==0 and not timed,row
        return output/(name+'.stdout')
    version=execute('rustc-version',[rust_bin/'rustc','--version']).read_bytes()
    assert version==b'rustc 1.95.0 (59807616e 2026-04-14)\n',version
    execute('cargo-version',[rust_bin/'cargo','--version'])
    execute('cargo-build',[rust_bin/'cargo','build','--release','--locked','--manifest-path',here/'Cargo.toml'])
    binary=output/'target/release/hepta-batch-plan-input-original-oracle';binary_before=pin(binary)
    result=execute('original',[binary],native/'original-input.jsonl')
    count=0
    with result.open('rb') as original,(native/'native-results.bin').open('rb') as produced:
        while True:
            left=original.read(1<<20);right=produced.read(1<<20)
            assert left==right,('original/native full-byte mismatch',count)
            if not left:break
            count+=len(left)
    assert pin(binary)==binary_before
    assert source_pins=={name:pin(runtime/name)['sha256'] for name in source_pins}
    assert native_pins=={name:pin(native/name) for name in native_pins}
    assert toolchain=={name:{'path':str(rust_bin/name),**pin(rust_bin/name)} for name in toolchain}
    summary={'schema':'hepta.runtime.batch-plan-input-original.v1','status':'PASS','semantic_inputs':native_summary['semantic_inputs'],
             'semantic_records':native_summary['semantic_records'],'full_compared_bytes':count,'native_before_original':True,
             'native_artifacts_before_and_after':native_pins,'source_manifest':declared,'source_sha256':source_pins,
             'toolchain_before_and_after':toolchain,'binary':{'path':str(binary),**binary_before},'actual_processes':len(records),
             'input':pin(native/'original-input.jsonl'),'output':pin(result),'fresh_target_directory':True,
             'original_batch_handler_executed':False,'effects_executed':False,'public_route_replaced':False}
    save(output/'result.json',summary);print(json.dumps(summary,sort_keys=True))
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--native',required=True);parser.add_argument('--rust-bin',required=True)
    args=parser.parse_args();run(args.runtime,args.output,args.native,args.rust_bin)
