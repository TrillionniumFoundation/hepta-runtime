#!/usr/bin/env python3
"""Bound source admission, complete build reuse, actual paired applications and pure readers."""
from pathlib import Path
import argparse,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
def check(expected):
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"exact frozen qualification source")
    return source_evidence(ROOT)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();identity=check(a.source_manifest_sha256)
    work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete export")
        a.output.mkdir();recorder=Recorder(ROOT,a.output/"processes")
        raw,process=recorder.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",process=process,
            archive=result,source=identity,application_calls=0)))
        print(encoded(result).decode(),end="");return
    recorder=Recorder(ROOT,work/"processes");started=False
    def run(name,script,args,seconds):
        raw,record=recorder.run(name,[sys.executable,"-I","-S","-B",ROOT/"scripts"/script,*args],timeout=seconds)
        return decode(raw),record,raw
    try:
        check_value,_,_=run("source-check","check_source.py",["--source",ROOT,"--output",work/"runtime"],60)
        (work/"INPUT_DOMAIN.json").write_bytes(encoded(check_value))
        require(check_value["status"]=="ENTROPY_SOURCE_DOMAIN_AND_ACTUAL_CPYTHON_PASS","frozen source and exact original runtime")
        reuse=work/"build-reuse";reuse.mkdir()
        fetch,_,_=run("build-fetch","build_reuse.py",["fetch","--source",ROOT,"--work",reuse],60)
        restored,_,_=run("build-unpack","build_reuse.py",["unpack","--source",ROOT,"--work",reuse],180)
        admission,_,raw=run("build-read","read_main.py",["build","--source",ROOT,"--work",reuse],180)
        require(admission["before"]==admission["after"]and len(admission["probes"])==11,"complete reused build under guard")
        (work/"BUILD_ADMISSION.json").write_bytes(raw)
        build=reuse/"original/restored/run/build"
        shutil.copyfile(build/"BUILD.json",work/"runtime/BUILD.json")
        started=True
        original,_,_=run("capture-original","capture.py",["--source",ROOT,"--build",build,"--runtime",work/"runtime",
            "--output",work/"application/original","--role","original"],180)
        native,_,_=run("capture-native","capture.py",["--source",ROOT,"--build",build,"--runtime",work/"runtime",
            "--output",work/"application/native","--role","native"],180)
        require(original["application_calls"]==native["application_calls"]==97,"both actual complete fixed domains")
        compared,_,raw=run("full-read","read_main.py",["actual","--source",ROOT,"--application",work/"application",
            "--runtime",work/"runtime"],180)
        require(compared["before"]==compared["after"]and len(compared["probes"])==11,"pure original/native comparison")
        (work/"READONLY.json").write_bytes(raw)
        controls,_,_=run("physical-controls","physical_controls.py",["run","--source",ROOT,
            "--application",work/"application","--runtime",work/"runtime","--output",work/"controls"],180)
        require(controls["status"]=="SEVEN_PHYSICAL_REFUSALS_TWO_RELOCATIONS_PASS","all actual physical reader controls")
        gate=dict(status="PASS",schema="hepta.runtime.binary-entropy.actual-gate.v1",source=identity,
            source_check=check_value,build_fetch=fetch,build_restore=restored,
            build_admission=admission["evidence"],original_native=compared["evidence"],controls=controls,
            processes=recorder.records,compiled_build_reused=True,compiler_executions=0,
            original_application_calls=97,native_application_calls=97,application_replays=0,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(gate))
        require(check(a.source_manifest_sha256)==identity,"frozen qualification source changed")
        print(encoded(dict(status="ENTROPY_ACTUAL_QUALIFICATION_PASS",totals=compared["evidence"]["totals"],
            physical_refusals=7,complete_relocations=2,original_application_calls=97,native_application_calls=97,
            application_replays=0,whole_runtime_replaced=False)).decode(),end="")
    except BaseException as exc:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=recorder.records,
            application_execution_started=started,error_type=type(exc).__name__,message=str(exc),
            traceback=traceback.format_exc(),unknown_inputs_never_replayed=True,whole_runtime_replaced=False)))
        if recorder.records:print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
