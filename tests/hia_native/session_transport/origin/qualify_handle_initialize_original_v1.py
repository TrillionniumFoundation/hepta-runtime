#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One real Initialize40 Original process versus two complete retained native captures."""
from pathlib import Path
import hashlib,importlib.util,json,os,stat,subprocess,time,traceback
W=Path('/home/qq/hepta-handle-initialize-original-bd947-v1')
D=Path('/home/qq/hepta-http-transport-bd947-v1')
OUT=W/'pairs-v1'
SHA=lambda b:hashlib.sha256(b).hexdigest()
J=lambda v:(json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def module(path,digest,name):
    assert SHA(Path(path).read_bytes())==digest
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
def main():
    assert os.getpid()==os.getpgrp();os.umask(0o077);OUT.mkdir(mode=0o700);start=time.monotonic()
    report=dict(schema='hepta.handle-initialize.original-pairs.v1',status='RUNNING',actual_original_processes=0,new_native_processes=0,
        new_compiles=0,original_completed_cases=0,paired_rows=0,complete_worker_qualified=False,actual_typed_destructor_callbacks_observed=False,
        worker_manager_qualified=False,production_activated=False,whole_runtime_replaced=False)
    base=None;process=None
    try:
        base=module(W/'handle_initialize_evidence_base_v1.py','6724a5fd74343987206944beaae040471d07ce6a05b9979a1c3e145ffd0fc534','initialize_evidence_base')
        frames=base.module(W/'handle_initialize_frames_v1.py','165b162c302419b5356af50a2d1d960094b903c25c94c90ba1ec59f0348aef64','initialize_evidence_frames')
        base.pin(__file__);original,recheck_original=base.admit_original()
        cases=json.loads(base.pin(D/'session-handle-initialize-cases-v1.json','340eb989c8212c4c76f2d5880a03e40694242513c82bc125ad4f8b4969a54c6d'))
        assert len(cases)==40
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
        assert len(reconstructed)==len(native)==40
        differences=[dict(index=i+1,name=cases[i]['name'],original=left,native=right)
            for i,(left,right)in enumerate(zip(reconstructed,native,strict=True))if left!=right]
        (OUT/'differences.json').write_bytes(J(differences))
        assert not differences,differences[:1]
        recheck_original();base.recheck_all()
        second,second_metrics=frames.native_captures(cases,base)
        assert second==native and second_metrics==native_metrics
        report.update(status='PASS_FINITE_ACTUAL_HANDLE_INITIALIZE',actual_original_requests=40,retained_native_modes=2,
            paired_rows=80,all_serialized_message_bytes_equal=True,all_step_results_equal=True,all_actual_waker_order_equal=True,
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
