#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One real LocalWorkerError140 Original process versus two complete retained native captures."""
from pathlib import Path
import hashlib,importlib.util,json,os,stat,subprocess,time,traceback
W=Path('/home/qq/hepta-local-worker-error-original-bd947-v1')
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=W/'pairs-v2'
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def module(path,digest,name):
    assert SHA(Path(path).read_bytes())==digest
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
def main():
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);start=time.monotonic()
    report=dict(schema='hepta.local-worker-error.original-pairs.v2',status='RUNNING',actual_original_processes=0,new_native_processes=0,
        new_compiles=0,original_completed_cases=0,paired_rows=0,complete_worker_qualified=False,actual_typed_destructor_callbacks_observed=False,
        worker_manager_qualified=False,local_worker_error_formatting_qualified=False,join_error_qualified=False,production_activated=False,whole_runtime_replaced=False)
    base=None;process=None
    try:
        base=module(W/'local_worker_error_evidence_base_v1.py','cc8efcf5ca6a77c16cfcedc668ffe97d3e808acab12c3ec9787f5ce85287f55d','local_worker_error_evidence_base')
        frames=base.module(W/'local_worker_error_frames_v3.py','27d0056ea0fd7d802788c01582fe730f3118d18a0f1cdaf70c29011a067b8d88','local_worker_error_evidence_frames')
        base.pin(__file__)
        base.pin(D/'local-worker-error-core-handoff-v1.json','5dbb1c89ce05c288ef286676aaece99cc35c4387bb2af7a90b379cec3848af5c')
        base.pin(D/'LOCAL-WORKER-ERROR-OWNERS-ABI-v1.md','49589141729f81811a2527b6ff19ccaeaa1d6f1681f3d068bcf5bdad52869d3f')
        original,recheck_original=base.admit_original()
        cases=json.loads(base.pin(D/'local-worker-error-cases-v1.json','ca169cb75b8283b9507680f4de838366f1a9ef554ad371e6c2df0c2ea353daf0'))
        assert len(cases)==140
        native,native_metrics=frames.native_captures(cases,base)
        report['retained_native_admitted_before']=True
        wire=b''.join((json.dumps(case,separators=(',',':'),ensure_ascii=False)+'\n').encode()for case in cases)
        (OUT/'original.stdin').write_bytes(wire);(OUT/'cases.json').write_bytes(J(cases))
        command=[original['binary']['path']];timed=False;begin=time.monotonic()
        with (OUT/'original.stdin').open('rb',buffering=0)as inp,(OUT/'original.stdout').open('xb',buffering=0)as out,(OUT/'original.stderr').open('xb',buffering=0)as err:
            try:
                process=subprocess.Popen(command,cwd=OUT,stdin=inp,stdout=out,stderr=err)
                report['actual_original_processes']=1
                row=dict(command=command,pid=process.pid,pgid=os.getpgid(process.pid),started=True)
                report['original_process']=row;(OUT/'original-start.json').write_bytes(J(row))
                try:process.wait(timeout=30)
                except subprocess.TimeoutExpired:timed=True;process.kill();process.wait();raise
            finally:
                if process is not None:
                    if process.poll()is None:process.kill();process.wait()
                    row.update(exit_code=process.returncode,reaped=True,timed_out=timed,elapsed_seconds=time.monotonic()-begin,
                        actual_input_offset=inp.tell())
                    (OUT/'original-finish.json').write_bytes(J(row))
        stdout=(OUT/'original.stdout').read_bytes();stderr=(OUT/'original.stderr').read_bytes()
        row.update(stdin_bytes=len(wire),stdin_sha256=SHA(wire),stdout_bytes=len(stdout),stdout_sha256=SHA(stdout),
            stderr_bytes=len(stderr),stderr_sha256=SHA(stderr))
        assert process.returncode==0 and not timed and not stderr and row['actual_input_offset']==len(wire)
        reconstructed,metrics=frames.original_capture(stdout,cases)
        report['original_completed_cases']=len(reconstructed)
        (OUT/'original-canonical.json').write_bytes(J(reconstructed))
        assert len(reconstructed)==len(native)==140
        differences=[dict(index=i+1,name=cases[i]['name'],original=left,native=right)
            for i,(left,right)in enumerate(zip(reconstructed,native,strict=True))if left!=right]
        (OUT/'differences.json').write_bytes(J(differences))
        assert not differences,differences[:1]
        recheck_original();base.recheck_all()
        second,second_metrics=frames.native_captures(cases,base)
        assert second==native and second_metrics==native_metrics
        report.update(status='PASS_FINITE_ACTUAL_LOCAL_WORKER_ERROR',actual_original_requests=140,retained_native_modes=2,
            paired_rows=280,all_serialized_message_bytes_equal=True,all_step_results_equal=True,all_actual_waker_order_equal=True,
            original_metrics=metrics,retained_native_metrics=native_metrics,retained_native_admitted_after=True,
            source_bytes_rechecked=True,complete_raw_captures=True,original_ownership_paired=True)
    except BaseException as error:
        report.update(status='FAIL',error=repr(error),traceback=traceback.format_exc());raise
    finally:
        report['elapsed_seconds']=time.monotonic()-start
        if base:report['source_pins']=base.PINS
        report['retained_files']={p.relative_to(OUT).as_posix():dict(bytes=p.stat().st_size,sha256=SHA(p.read_bytes()),mode=stat.S_IMODE(p.stat().st_mode))
            for p in sorted(OUT.rglob('*'))if p.is_file()}
        (OUT/'result.json').write_bytes(J(report))
        print(json.dumps({k:v for k,v in report.items()if k not in('source_pins','retained_files','traceback')},sort_keys=True))
if __name__=='__main__':main()
