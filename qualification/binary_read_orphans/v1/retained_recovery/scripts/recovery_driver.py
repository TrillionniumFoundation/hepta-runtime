#!/usr/bin/env python3
"""Recover only complete retained evidence; all original app processes remain final."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["recover","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--output",type=Path);p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"exact pure recovery manifest")
    identity=source_evidence(ROOT);work=a.work.absolute();capture=work/"capture"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete recovery archive");a.output.mkdir(parents=True)
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-recovery-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=result,process=row)))
        print(encoded(result).decode(),end="");return
    require(not work.exists(),"fresh recovery only");work.mkdir(parents=True);capture.mkdir()
    semantic=capture/"semantic";semantic.mkdir();upstream=work/"upstream";upstream.mkdir()
    rec=Recorder(ROOT,capture/"processes")
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        require(decode(raw)["status"]=="READ_ORPHANS_SOURCE_AND_INPUT_ONLY_PASS","pure exact reader/input source")
        (capture/"SOURCE_CHECK.json").write_bytes(raw)
        for stage,limit in(("fetch",60),("unpack",180),("admit",180)):
            raw,row=rec.run("original-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/restore_original.py",stage,
                "--source",ROOT,"--work",semantic,"--group",a.group],timeout=limit)
            require(decode(raw)["status"]in("PASS","ALL_UPLOADED_INFO_ARCHIVE_BYTES_PASS"),"complete retained original "+stage)
        original_source=semantic/"original/restored/source";original_capture=semantic/"original/restored/run"
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run("upstream-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,
                "--source",original_source,"--work",upstream],timeout=limit)
            require(decode(raw)["status"]=="PASS","complete upstream build "+stage)
        raw,row=rec.run("retained-full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_retained.py",
            "--semantic",semantic,"--upstream",upstream,"--group",a.group],timeout=180)
        guard=decode(raw);require(guard["before"]==guard["after"]and len(guard["probes"])==11
            and guard["evidence"]["status"]=="COMPLETE_RETAINED_READ_ORPHANS_PASS","complete retained source/process/actual guard")
        (capture/"READONLY.json").write_bytes(raw)
        raw,row=rec.run("physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/physical_controls.py",
            "--source",original_source,"--data",original_capture/"application","--group",a.group,
            "--output",capture/"controls","--baseline",capture/"READONLY.json"],timeout=180)
        controls=decode(raw);require(controls["status"]=="EIGHT_PHYSICAL_REFUSALS_TWO_FULL_RELOCATIONS_PASS","complete pure physical controls")
        result=dict(status="PASS",group=a.group,source=identity,processes=rec.records,read=guard["evidence"],controls=controls,
            original_application_executions=0,native_application_executions=0,compiler_executions=0,rust_executions=0,
            original_archive_included_in_full=True,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(result));require(source_evidence(ROOT)==identity,"recovery source changed")
        print(encoded(dict(status="READ_ORPHANS_RETAINED_RECOVERY_PASS",group=a.group,original_status=guard["evidence"]["original_status"],
            actual=guard["evidence"]["actual"],controls=controls["status"],guard_probes=121,applications_replayed=0)).decode(),end="")
    except BaseException as e:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),applications_replayed=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
