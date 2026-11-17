#!/usr/bin/env python3
"""Pure recovery of all completed entropy applications; original and HIA execution is forbidden."""
from pathlib import Path
import argparse,ast,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
def check(expected=None):
    if expected is not None:require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==expected,"exact recovery source")
    return source_evidence(ROOT)
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","check","fetch","unpack","read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--output",type=Path);a=p.parse_args();identity=check(a.source_manifest_sha256)
    work=a.work.absolute();work.mkdir(parents=True,exist_ok=True)
    if a.stage=="check":
        count=0
        for path in ROOT.rglob("*"):
            if path.is_file()and path.suffix in(".py",".pseudo"):ast.parse(path.read_bytes(),filename=str(path));count+=1
        import recover_read
        recover_read.patch(ROOT,ROOT/"qualified")
        print(encoded(dict(status="RECOVERY_SOURCE_ONLY_PASS",source=identity,python_sources=count,
            original_or_native_application_calls=0)).decode(),end="");return
    if a.stage in("fetch","unpack"):
        import capture_restore
        bound=decode((ROOT/"CAPTURE_INPUT.json").read_bytes())
        function=capture_restore.fetch if a.stage=="fetch"else capture_restore.unpack
        print(encoded(function(work/"input",bound)).decode(),end="");return
    if a.stage=="read":
        import recover_read
        from readonly import guarded
        module=recover_read.prepare(work/"input")
        result=guarded(lambda:recover_read.verify(ROOT,work/"input",module),
            roots=[ROOT,work/"input/original",work/"input/download"])
        print(encoded(result).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete recovery export")
        a.output.mkdir();recorder=Recorder(ROOT,a.output/"processes")
        raw,process=recorder.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,
            process=process,archive=result,new_application_executions=0)))
        print(encoded(result).decode(),end="");return
    recorder=Recorder(ROOT,work/"processes")
    def run(name,stage,limit):
        raw,record=recorder.run(name,[sys.executable,"-I","-S","-B",Path(__file__).resolve(),stage,
            "--work",work,"--source-manifest-sha256",a.source_manifest_sha256],timeout=limit)
        return decode(raw),record,raw
    try:
        source,_,_=run("source-check","check",60)
        (work/"input").mkdir()
        fetched,_,_=run("capture-fetch","fetch",60)
        restored,_,_=run("capture-unpack","unpack",180)
        recovered,_,raw=run("complete-recovery-read","read",180)
        require(recovered["before"]==recovered["after"]and len(recovered["probes"])==11,"pure complete recovered evidence")
        (work/"READONLY.json").write_bytes(raw)
        old=work/"input/original/restored";original_source=old/"source";run_root=old/"run"
        raw,process=recorder.run("physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/physical_controls.py","run",
            "--source",original_source,"--application",run_root/"application","--runtime",run_root/"runtime",
            "--output",work/"controls"],timeout=180)
        controls=decode(raw)
        require(controls["status"]=="SEVEN_PHYSICAL_REFUSALS_TWO_RELOCATIONS_PASS","all physical recovered-reader controls")
        result=dict(status="PASS",schema="hepta.runtime.binary-entropy.recovery-gate.v1",source=identity,
            original_capture=decode((ROOT/"CAPTURE_INPUT.json").read_bytes()),source_check=source,
            capture_fetch=fetched,capture_restore=restored,recovered=recovered["evidence"],controls=controls,
            processes=recorder.records,new_original_application_calls=0,new_native_application_calls=0,
            original_terminal_status="FAIL",whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(result))
        require(check(a.source_manifest_sha256)==identity,"recovery modified source")
        print(encoded(dict(status="ENTROPY_COMPLETE_PURE_RECOVERY_PASS",totals=recovered["evidence"]["actual"]["totals"],
            original_failure_reproduced=recovered["evidence"]["diagnosis"],physical_refusals=7,complete_relocations=2,
            new_original_application_calls=0,new_native_application_calls=0,whole_runtime_replaced=False)).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=recorder.records,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            new_original_application_calls=0,new_native_application_calls=0,whole_runtime_replaced=False)))
        if recorder.records:print((recorder.directory/(recorder.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
