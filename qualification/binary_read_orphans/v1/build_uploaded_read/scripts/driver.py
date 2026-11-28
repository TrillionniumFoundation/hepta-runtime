#!/usr/bin/env python3
"""Independent uploaded complete build read; all application entry calls forbidden."""
from pathlib import Path
import argparse,json,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--output",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"exact independent source")
    identity=source_evidence(ROOT);work=a.work.absolute()
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete output")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        report=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,
            archive=report,process=row,application_hia_or_rust_calls=0)))
        print(encoded(report).decode(),end="");return
    require(not work.exists(),"fresh independent work");work.mkdir(parents=True)
    rec=Recorder(ROOT,work/"processes")
    try:
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/build_reuse.py",stage,
                "--source",ROOT,"--work",work],timeout=limit)
            require(decode(raw)["status"]=="PASS","complete build "+stage)
        raw,row=rec.run("independent-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_uploaded.py",
            "--source",ROOT,"--work",work],timeout=180)
        guard=decode(raw);require(guard["before"]==guard["after"] and len(guard["probes"])==11,"independent full guard")
        require(guard["evidence"]["status"]=="COMPLETE_UPLOADED_READ_ORPHANS_BUILD_AND_SEVEN_GUARDS_PASS",
            "independent qualification")
        (work/"READONLY.json").write_bytes(encoded(guard))
        result=dict(status="PASS",source=identity,processes=rec.records,read=guard["evidence"],
            independent_guard_probes=11,whole_guard_entries=guard["entries"],application_hia_executions=0,
            rust_executions=0,whole_runtime_replaced=False)
        (work/"GATE.json").write_bytes(encoded(result))
        require(source_evidence(ROOT)==identity,"source changed during pure read")
        print(encoded(dict(status="INDEPENDENT_READ_ORPHANS_BUILD_FULL_READ_PASS",proof=guard["evidence"],
            elapsed_seconds=row["elapsed_seconds"],guard_probes=11,entries=guard["entries"])).decode(),end="")
    except BaseException as exc:
        (work/"GATE.json").write_bytes(encoded(dict(status="FAIL",source=identity,processes=rec.records,
            error_type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc(),
            application_hia_executions=0,rust_executions=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
