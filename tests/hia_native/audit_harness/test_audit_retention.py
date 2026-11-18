"""Compare actual original caller methods and HIA with the same scripted children."""
from pathlib import Path
import argparse,gzip,hashlib,json,struct,subprocess,sys,time,traceback
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ENCODE=lambda value:(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
def compressed(path,raw):
    with path.open('xb') as handle:
        with gzip.GzipFile(filename='',mode='wb',fileobj=handle,mtime=0) as z:z.write(raw)
    assert gzip.decompress(path.read_bytes())==raw
    return dict(path=path.name,bytes=len(raw),sha256=SHA(raw),compressed_bytes=path.stat().st_size,compressed_sha256=SHA(path.read_bytes()))
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('manifest','runtime','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--oracle',type=Path);args=parser.parse_args();args.output.mkdir(parents=True,mode=0o700)
    sys.path[:0]=[str(Path(__file__).resolve().parent),str(args.runtime.resolve(strict=True)/'scripts')]
    from hia_native_loader import NativeModule
    from audit_retention_cases import cases,request
    from audit_retention_driver import invoke
    items=list(cases());assert len({c['name'] for c in items})==len(items)==974
    source_raw=args.manifest.read_bytes();source_pin=SHA(source_raw);stdin=b''.join(ENCODE(c) for c in items)
    inputs=compressed(args.output/'scripted-input.jsonl.gz',stdin);reference=[];original_process=None;started=time.monotonic();done=[];outputs=bytearray();requests=bytearray()
    try:
        if args.oracle:
            oracle=args.oracle.resolve(strict=True);pin=SHA(oracle.read_bytes());start=time.monotonic()
            p=subprocess.Popen([str(oracle)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);timed=False
            try:out,err=p.communicate(stdin,timeout=180)
            except subprocess.TimeoutExpired:timed=True;p.kill();out,err=p.communicate()
            original_process=dict(pid=p.pid,exit_code=p.returncode,reaped=True,timed_out=timed,elapsed_seconds=time.monotonic()-start,executable_sha256=pin,stdout=compressed(args.output/'original.stdout.jsonl.gz',out),stderr=compressed(args.output/'original.stderr.gz',err))
            assert p.returncode==0 and not timed and not err,original_process
            reference=[json.loads(line) for line in out.splitlines()];assert len(reference)==len(items)
            assert SHA(oracle.read_bytes())==pin
        with NativeModule(args.manifest,manifest_sha256=source_pin) as module:
            for index,c in enumerate(items):
                wire=request(c);requests.extend(struct.pack('<Q',len(wire))+wire)
                result=invoke(module,c);outputs.extend(ENCODE(dict(name=c['name'],**result)))
                if reference:
                    old=reference[index];assert old['name']==c['name']
                    assert old['original_policy_executed'] and not old['real_archive_executed'] and not old['real_active_registry_executed'] and not old['real_hot_filesystem_executed']
                    assert old['result_hex']==result['result_hex'],('result',c['name'])
                    assert old['trace']==result['trace'],('child effect order/arguments/results',c['name'])
                done.append(dict(name=c['name'],native_calls=result['native_calls'],child_effects=len(result['trace']),result_bytes=len(result['result_hex'])//2,result_sha256=SHA(bytes.fromhex(result['result_hex']))))
        assert args.manifest.read_bytes()==source_raw
        report=dict(schema='hepta.request-audit.scripted-retention-policy-comparison.v1',status='PASS',cases=len(done),actual_original_processes=int(bool(args.oracle)),native_machine_invocations=sum(r['native_calls'] for r in done),scripted_child_calls_per_implementation=sum(r['child_effects'] for r in done),original_process=original_process,inputs=inputs,native_requests=compressed(args.output/'native.stdin.bin.gz',requests),native_results=compressed(args.output/'native.stdout.jsonl.gz',outputs),manifest_sha256=source_pin,all_original_results_and_effect_transcripts_equal=bool(args.oracle),borrowed_canaries_verified=True,case_results=done,elapsed_seconds=time.monotonic()-started,child_contracts_scripted=True,real_archive_executed=False,real_active_registry_executed=False,real_hot_filesystem_executed=False,standalone_native_process_qualified=False,whole_runtime_replaced=False,production_activated=False,audit_storage_closed=False)
        (args.output/'result.json').write_bytes(ENCODE(report));print(json.dumps({k:v for k,v in report.items() if k not in ('case_results','original_process','inputs','native_requests','native_results')},sort_keys=True))
    except BaseException:
        compressed(args.output/'native.partial.jsonl.gz',outputs)
        (args.output/'failure.json').write_bytes(ENCODE(dict(status='FAIL',completed=len(done),original_process=original_process,traceback=traceback.format_exc())));raise
if __name__=='__main__':main()
