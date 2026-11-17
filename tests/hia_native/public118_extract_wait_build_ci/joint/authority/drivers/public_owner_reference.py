"""Replay actual private observations through the unchanged current Rust resolver.

Only CI runs the freshly built original. Verification reads complete retained
input, output, executable bytes and process receipts and never launches it.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from verify_private_binding import verify as private_read
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def doc(path):return json.loads(path.read_bytes())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def lines(rows):return b''.join(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n' for row in rows)
def put(path,value):
    with path.open('xb') as f:f.write(value if isinstance(value,bytes) else encoded(value))

def verify(owner_output,private_evidence,output):
    original=doc(owner_output/'capture/original-build.json')
    assert original['fresh_build'] is True and original['actual_request_context'] is True
    assert original['original_function_substitution'] is False and original['observed_stdio_fallback_input'] is True
    binary=(owner_output/'capture/original/oracle.bin').read_bytes()
    assert SHA(binary)==original['binary_sha256'] and len(binary)==original['binary_bytes']
    assert (output/'oracle.bin').read_bytes()==binary
    source=private_evidence['original_input'];expected=private_evidence['expected_original']
    assert len(source)==len(expected)==16 and (output/'stdin.jsonl').read_bytes()==lines(source)
    assert doc(output/'expected.json')==expected
    receipt=doc(output/'PROCESS.json');assert receipt['started'] is True and receipt['exit_code']==0 and receipt['timed_out'] is False
    assert receipt['timeout_seconds']==60 and receipt['start_new_session'] is True and receipt['pgid']==receipt['pid']
    assert receipt['environment']=={'PATH':'','LC_ALL':'C','TMPDIR':receipt['cwd']}
    assert list((output/'cwd').iterdir())==[]
    for name,row in receipt['files'].items():
        raw=(output/name).read_bytes();assert row==dict(bytes=len(raw),sha256=SHA(raw))
    stdout=(output/'stdout').read_bytes();observed=[json.loads(line) for line in stdout.splitlines()]
    assert observed==expected
    summary=doc(output/'stderr')
    wanted=dict(status='PASS',rows=16,starts=4,requests=8,shutdowns=4,reconnects=0,
        adapter_only_rows=0,original_load_http_auth_calls=0,original_new_owner_id_calls=0,
        original_stdio_with_fixture_calls=4,synthetic_entropy_fills=16,actual_router_dispatch_calls=8,
        original_resolve_calls=8,original_resolve_operation_crypto_calls=0,native_cases_added_by_replay=0,
        observed_stdio_fallback_calls=4,direct_missing_extension_fixtures=0,paired_rust_random_owner_generator=False,
        optional_http_startup_qualified=False,current_http_listener_qualified=False,
        concurrent_session_binding_qualified=False,original_middleware_executed=True,whole_runtime_replaced=False,
        pid=receipt['pid'],ppid=receipt['parent_pid'],pgid=receipt['pgid'],output_sha256=SHA(stdout))
    assert summary==wanted
    return dict(schema='hepta.public-authority.current-original16.v1',status='PASS',rows=16,
        starts=4,requests=8,shutdowns=4,all_complete_private_output_bytes_equal=True,
        native_elf_sha256=private_evidence['elf_sha256'],original_elf_sha256=SHA(binary),
        native_os_fallback_values_observed=True,paired_random_generators_compared=False,
        source_binding_sha256=private_evidence['source_binding_sha256'],actual_original=summary,
        stdin_sha256=SHA(lines(source)),stdout_sha256=SHA(stdout),
        peer_info_is_authority=False,annotation_integrated=False,request_audit_integrated=False,
        public_http_qualified=False,concurrent_binding_qualified=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False,reader_executed_native_or_rust=False,reader_wrote_files=False)

def run(a,evidence):
    assert os.environ.get('CI')=='true','Current original code is executed only in CI.'
    out=a.output.absolute();out.mkdir(parents=True,exist_ok=False);(out/'cwd').mkdir()
    binary=(a.owner_output/'capture/original/oracle.bin').read_bytes()
    put(out/'oracle.bin',binary);(out/'oracle.bin').chmod(0o500)
    put(out/'stdin.jsonl',lines(evidence['original_input']));put(out/'expected.json',evidence['expected_original'])
    env={'PATH':'','LC_ALL':'C','TMPDIR':str(out/'cwd')};start=time.monotonic_ns();process=None
    receipt=dict(started=False,exit_code=None,timed_out=False,timeout_seconds=60,start_new_session=True,
        parent_pid=os.getpid(),pid=None,pgid=None,environment=env,cwd=str(out/'cwd'),files={})
    try:
        with (out/'stdin.jsonl').open('rb') as stdin,(out/'stdout').open('xb') as stdout,(out/'stderr').open('xb') as stderr:
            process=subprocess.Popen([str(out/'oracle.bin')],stdin=stdin,stdout=stdout,stderr=stderr,cwd=out/'cwd',env=env,start_new_session=True)
            receipt.update(started=True,pid=process.pid,pgid=process.pid)
            try:receipt['exit_code']=process.wait(timeout=60)
            except subprocess.TimeoutExpired:receipt['timed_out']=True;raise
    finally:
        if process is not None:
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
            receipt['exit_code']=process.wait()
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        receipt['elapsed_ns']=time.monotonic_ns()-start
        for name in ('oracle.bin','stdin.jsonl','expected.json','stdout','stderr'):
            if (out/name).exists():
                raw=(out/name).read_bytes();receipt['files'][name]=dict(bytes=len(raw),sha256=SHA(raw))
        put(out/'PROCESS.json',receipt)
    result=verify(a.owner_output,evidence,out);put(out/'REFERENCE.json',result);print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','capture','owner-output','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--verify',action='store_true');p.add_argument('--module-map',type=Path);a=p.parse_args()
    evidence=private_read(a.source.resolve(strict=True),a.manifest.resolve(strict=True),a.capture.resolve(strict=True),a.module_map)
    if a.verify:
        result=verify(a.owner_output.resolve(strict=True),evidence,a.output.resolve(strict=True))
        assert doc(a.output/'REFERENCE.json')==result;print(json.dumps(result,sort_keys=True))
    else:run(a,evidence)
