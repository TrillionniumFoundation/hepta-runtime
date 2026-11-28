#!/usr/bin/env python3
"""Fresh retained62 plus candidate79 and the ordinary public9 comparison.

Previously frozen SDK-original and private357 receipts remain separate. This
recipe never launches Rust and does not extend their qualification domains.
"""
from pathlib import Path
import argparse, ast, hashlib, json, os, subprocess, sys, time, traceback
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()

def put(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def verify_source(source):
    manifest=json.loads((source/'source-manifest.json').read_bytes())
    assert manifest['schema']=='hepta.runtime.public-nine-source-package.v1'
    for relative,pin in manifest['files'].items():
        name=Path(relative);assert not name.is_absolute() and '..' not in name.parts
        data=(source/name).read_bytes();assert pin=={'bytes':len(data),'sha256':SHA(data)},relative
        if name.suffix=='.py':ast.parse(data,filename=relative)
    return manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    for name in ('sdk-source','hepta','output'):parser.add_argument('--'+name,type=Path)
    parser.add_argument('--check-only',action='store_true');args=parser.parse_args()
    source=args.source.resolve(strict=True);manifest=verify_source(source)
    if args.check_only:
        print(json.dumps({'status':'SOURCE_CHECK_PASS','files':len(manifest['files']),
            'native_or_rust_executed':False},sort_keys=True));return
    assert args.sdk_source and args.hepta and args.output
    output=args.output.resolve();assert not output.exists() and not output.is_relative_to(source);output.mkdir(parents=True)
    (output/'processes').mkdir();processes=[];started=time.monotonic()
    report={'schema':'hepta.runtime.public-nine-native-recipe.v1','status':'RUNNING',
        'source_manifest_sha256':SHA((source/'source-manifest.json').read_bytes()),
        'existing_binary_inputs':False,'fresh_62_baseline':False,'fresh_79_candidate':False,
        'rust_executed':False,'target_original_public_handler_comparison':False,
        'full_sdk_qualified':False,'full_136_route_qualified':False,'full_async_text_editor_qualified':False,
        'scope_wide_qualified':False,'cancellation_fence_timing_qualified':False,
        'production_activated':False,'old_path_removed':False,'fresh_cold_qualified':False,
        'outer_subprocess_timeout_seconds':None,'public_exchange_timeout_seconds':60}
    def save():report.update(processes=processes,elapsed_seconds=time.monotonic()-started);put(output/'RECIPE.json',report)
    def run(label,command):
        begin=time.monotonic()
        with (output/'processes'/(label+'.stdout')).open('xb') as stdout, (output/'processes'/(label+'.stderr')).open('xb') as stderr:
            process=subprocess.Popen([str(x) for x in command],stdout=stdout,stderr=stderr)
            code=process.wait()
        row={'label':label,'command':[str(x) for x in command],'exit_code':code,
             'elapsed_seconds':time.monotonic()-begin,'outer_timeout_seconds':None}
        for stream in ('stdout','stderr'):
            raw=(output/'processes'/(label+'.'+stream)).read_bytes();row[stream]={'bytes':len(raw),'sha256':SHA(raw)}
        processes.append(row);save();assert code==0,label
    save()
    try:
        run('fresh-retained-62',[sys.executable,'-I','-B',source/'scripts/build_retained_eight.py',
            '--sdk-source',args.sdk_source,'--hepta',args.hepta,'--output',output/'retained-eight'])
        base=json.loads((output/'retained-eight/BUILD.json').read_bytes());assert base['fresh_members']==62
        report['fresh_62_baseline']=True;save()
        run('fresh-public-79',[sys.executable,'-I','-B',source/'scripts/build_nine.py',
            '--source',source/'source','--hepta',args.hepta,'--output',output/'public-nine',
            '--bootstrap',output/'retained-eight/build/bootstrap'])
        nine=json.loads((output/'public-nine/BUILD.json').read_bytes())
        assert nine['fresh_member_compiles']==79 and nine['checked_reused_members']==0
        report['fresh_79_candidate']=True;save()
        run('actual-public-nine',[sys.executable,'-I','-B',source/'scripts/qualify_native_nine.py',
            '--source',source/'source','--manifest',nine['manifest'],'--baseline-elf',base['elf'],
            '--output',output/'public-loop'])
        run('readonly-verification',[sys.executable,'-I','-B',source/'scripts/verify_native_nine.py',
            '--source',source/'source','--build',output/'public-nine','--loop',output/'public-loop'])
        verified=json.loads((output/'processes/readonly-verification.stdout').read_bytes())
        assert verified['status']=='READONLY_NATIVE_PUBLIC_NINE_PASS' and verified['fresh_member_compiles']==79
        put(output/'verification.json',verified)
        assert verify_source(source)==manifest
        report.update(status='PASS',public_ordinary_nine_route_qualified=True,
            counts=verified['counts'],candidate_elf_sha256=verified['elf_sha256'],
            bootstrap_built_fresh_in_same_invocation=True)
    except BaseException:report.update(status='FAIL',failure=traceback.format_exc());raise
    finally:save()
    print(json.dumps(report,sort_keys=True),flush=True)

if __name__=='__main__':main()
