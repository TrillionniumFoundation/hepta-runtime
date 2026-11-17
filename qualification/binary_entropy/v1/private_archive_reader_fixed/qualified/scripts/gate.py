#!/usr/bin/env python3
"""Freeze before execution; reuse qualified ELF; one bounded private transport process."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"exact frozen private qualification")
    return source_evidence(ROOT)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();identity=check(a.source_manifest_sha256)
    work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh private export")
        a.output.mkdir();recorder=Recorder(ROOT,a.output/"processes")
        raw,process=recorder.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",process=process,
            archive=result,source=identity,new_application_calls=0)))
        print(encoded(result).decode(),end="");return
    recorder=Recorder(ROOT,work/"processes");started=False
    def run(name,script,args,seconds):
        raw,record=recorder.run(name,[sys.executable,"-I","-S","-B",ROOT/"scripts"/script,*args],timeout=seconds)
        return decode(raw),record,raw
    try:
        admission,_,raw=run("source-check","read_private.py",["source","--source",ROOT],60)
        (work/"INPUT_DOMAIN.json").write_bytes(raw)
        require(admission["status"]=="PRIVATE_SOURCE_DOMAIN_PASS","fixed private source domain")
        reuse=work/"build-reuse";reuse.mkdir()
        fetch,_,_=run("build-fetch","build_reuse.py",["fetch","--source",ROOT,"--work",reuse],60)
        restored,_,_=run("build-unpack","build_reuse.py",["unpack","--source",ROOT,"--work",reuse],180)
        build_read,_,raw=run("build-read","read_main.py",["build","--source",ROOT,"--work",reuse],180)
        require(build_read["before"]==build_read["after"]and len(build_read["probes"])==11,"guarded complete reused build")
        (work/"BUILD_ADMISSION.json").write_bytes(raw)
        build=reuse/"original/restored/run/build";started=True
        captured,_,_=run("private-capture","private_capture.py",["--source",ROOT,"--build",build,
            "--output",work/"capture"],60)
        require(captured["private_hia_entry_calls"]==216 and captured["private_native_admission_calls"]==24,
            "all frozen private calls completed once")
        read,_,raw=run("full-read","read_main.py",["capture","--source",ROOT,"--capture",work/"capture"],180)
        require(read["before"]==read["after"]and len(read["probes"])==11,"guarded complete private buffers")
        (work/"READONLY.json").write_bytes(raw)
        controls,_,_=run("physical-controls","private_controls.py",["run","--source",ROOT,
            "--capture",work/"capture","--output",work/"controls"],180)
        require(controls["status"]=="FOUR_PRIVATE_REFUSALS_TWO_RELOCATIONS_PASS","all private physical controls")
        gate=dict(status="PASS",schema="hepta.runtime.binary-entropy.private-gate.v1",source=identity,
            source_check=admission,build_fetch=fetch,build_restore=restored,build_admission=build_read["evidence"],
            private_capture=captured,private_result=read["evidence"],controls=controls,processes=recorder.records,
            compiled_build_reused=True,compiler_executions=0,private_hia_entry_calls=216,
            private_native_admission_calls=24,original_application_calls=0,actual_kernel_entropy_applications=0,
            application_replays=0,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(gate))
        require(check(a.source_manifest_sha256)==identity,"private frozen source changed")
        print(encoded(dict(status="ENTROPY_PRIVATE_QUALIFICATION_PASS",private_hia_entry_calls=216,
            private_native_admission_calls=24,physical_refusals=4,complete_relocations=2,
            original_application_calls=0,actual_kernel_entropy_applications=0,application_replays=0)).decode(),end="")
    except BaseException as exc:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=recorder.records,
            private_execution_started=started,error_type=type(exc).__name__,message=str(exc),
            traceback=traceback.format_exc(),unknown_inputs_never_replayed=True,whole_runtime_replaced=False)))
        if recorder.records:print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
