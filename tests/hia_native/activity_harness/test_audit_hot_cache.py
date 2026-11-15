"""Qualify persistent HIA hot-cache policy against unchanged Rust functions."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import struct
import subprocess
import sys
import time
import traceback

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def compressed(path,raw):
    with path.open('xb') as handle:
        with gzip.GzipFile(filename='',mode='wb',fileobj=handle,mtime=0) as stream:
            stream.write(raw)
    assert gzip.decompress(path.read_bytes())==raw
    return dict(path=path.name,bytes=len(raw),sha256=SHA(raw),compressed_bytes=path.stat().st_size,compressed_sha256=SHA(path.read_bytes()))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','runtime','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--oracle',type=Path);args=parser.parse_args()
    args.output.mkdir(parents=True,mode=0o700,exist_ok=False)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    from hia_native_loader import NativeModule
    from audit_hot_cache_cases import cases,request
    from audit_hot_cache_driver import invoke
    items=list(cases());assert len({c['name'] for c in items})==len(items)==194
    assert sum(len(c['steps']) for c in items)==855
    assert sum(len(s['effects']) for c in items for s in c['steps'])==6000
    manifest_raw=args.manifest.read_bytes();manifest_pin=SHA(manifest_raw)
    oracle=args.oracle.resolve(strict=True) if args.oracle else None
    oracle_pin=SHA(oracle.read_bytes()) if oracle else None
    inputs=compressed(args.output/'scripted-input.jsonl.gz',b''.join(ENCODE(c) for c in items))
    original_log=bytearray();native_log=bytearray();requests=bytearray();processes=[];done=[]
    started=time.monotonic()
    try:
        with NativeModule(args.manifest,manifest_sha256=manifest_pin) as module:
            for case in items:
                reference=None
                if oracle:
                    stdin=ENCODE(case);begin=time.monotonic();p=subprocess.Popen([str(oracle)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                    timed=False
                    try:stdout,stderr=p.communicate(stdin,timeout=30)
                    except subprocess.TimeoutExpired:timed=True;p.kill();stdout,stderr=p.communicate()
                    row=dict(name=case['name'],pid=p.pid,reaped=True,exit_code=p.returncode,timed_out=timed,
                        elapsed_seconds=time.monotonic()-begin,stdin_bytes=len(stdin),stdin_sha256=SHA(stdin),
                        stdout_bytes=len(stdout),stdout_sha256=SHA(stdout),stderr_bytes=len(stderr),stderr_sha256=SHA(stderr))
                    processes.append(row);original_log.extend(stdout)
                    if stderr:
                        compressed(args.output/('original-error-'+str(len(processes))+'.gz'),stderr)
                    assert p.returncode==0 and not timed and not stderr,row
                    reference=json.loads(stdout);assert reference['name']==case['name']
                    assert reference['original_functions_executed'] and reference['original_cache_state_uses_std_once_lock_and_mutex']
                    assert not reference['real_archive_executed'] and not reference['real_hot_filesystem_executed']
                results=[]
                with module.session(output_capacity=266304,workspace_capacity=8<<20) as session:
                    for index,command in enumerate(case['steps']):
                        wire=request(command);requests.extend(struct.pack('<Q',len(wire))+wire)
                        value=invoke(session,command);results.append(value)
                        if reference is not None:
                            expected=reference['results'][index]
                            assert value['name']==expected['name']
                            assert value['result_hex']==expected['result_hex'],('result',case['name'],index,value['result_hex'][:128],expected['result_hex'][:128])
                            assert value['trace']==expected['trace'],('effects',case['name'],index)
                if reference is not None:assert len(reference['results'])==len(results)
                native_log.extend(ENCODE(dict(name=case['name'],results=results)))
                done.append(dict(name=case['name'],commands=len(results),
                    native_calls=sum(r['native_calls'] for r in results),
                    child_effects=sum(len(r['trace']) for r in results)))
        assert args.manifest.read_bytes()==manifest_raw
        if oracle:assert SHA(oracle.read_bytes())==oracle_pin
        report=dict(schema='hepta.request-audit.scripted-hot-cache-comparison.v1',status='PASS',
            cases=len(done),commands_per_implementation=sum(x['commands'] for x in done),
            actual_original_processes=len(processes),native_machine_invocations=sum(x['native_calls'] for x in done),
            scripted_child_calls_per_implementation=sum(x['child_effects'] for x in done),
            original_processes=processes,original_executable_sha256=oracle_pin,
            inputs=inputs,original_results=compressed(args.output/'original.stdout.jsonl.gz',original_log),
            native_requests=compressed(args.output/'native.stdin.bin.gz',requests),
            native_results=compressed(args.output/'native.stdout.jsonl.gz',native_log),
            manifest_sha256=manifest_pin,all_original_results_and_effect_transcripts_equal=bool(oracle),
            original_mutex_and_once_lock_executed=bool(oracle),borrowed_canaries_verified=True,
            case_results=done,elapsed_seconds=time.monotonic()-started,
            child_contracts_scripted=True,shared_private_owner_gate=True,
            real_archive_executed=False,real_hot_filesystem_executed=False,
            native_language_unwind_qualified=False,concurrent_cache_interleavings_qualified=False,
            standalone_native_process_qualified=False,whole_runtime_replaced=False,
            production_activated=False,audit_storage_closed=False)
        assert report['native_machine_invocations']==6855 and report['scripted_child_calls_per_implementation']==6000
        (args.output/'result.json').write_bytes(ENCODE(report))
        print(json.dumps({k:v for k,v in report.items() if k not in ('case_results','original_processes','inputs','original_results','native_requests','native_results')},sort_keys=True))
    except BaseException:
        compressed(args.output/'native.partial.jsonl.gz',native_log)
        compressed(args.output/'original.partial.jsonl.gz',original_log)
        (args.output/'failure.json').write_bytes(ENCODE(dict(status='FAIL',completed=len(done),original_processes=processes,traceback=traceback.format_exc())))
        raise

if __name__=='__main__':main()
