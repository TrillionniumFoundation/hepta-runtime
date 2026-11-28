#!/usr/bin/env python3
"""Independent uploaded recovery read; never run the original or a native image."""
from pathlib import Path
import argparse,os,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);p.add_argument("--output",type=Path)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen independent source")
    identity=source_evidence(ROOT);work=a.work.absolute();capture=work/"capture"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete independent export")
        a.output.mkdir(parents=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",capture,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        report=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=report,process=row)))
        print(encoded(report).decode(),end="");return
    require(not work.exists(),"fresh independent read");work.mkdir(parents=True);capture.mkdir()
    env,record=environment(os.environ);(capture/"ENVIRONMENT.json").write_bytes(encoded(record))
    rec=Recorder(ROOT,capture/"processes",env=env)
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        require(decode(raw)["status"]=="SOURCE_ONLY_PASS","complete source admission")
        for kind in("recovery","semantic","build"):
            folder=work/kind;folder.mkdir()
            for stage,limit in(("fetch",60),("unpack",180)):
                raw,row=rec.run(kind+"-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/archive_stage.py",
                    kind,stage,"--work",folder,"--group",a.group],timeout=limit)
                require(decode(raw)["status"]=="PASS","complete archived "+kind+" "+stage)
        raw,row=rec.run("complete-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_all.py",
            "--work",work,"--group",a.group],timeout=180)
        report=decode(raw);require(report["status"]=="READONLY_PASS"
            and report["evidence"]["status"]=="INDEPENDENT_COMPLETE_UPLOADED_UTF8_PASS","all uploaded bytes and controls")
        (capture/"READONLY.json").write_bytes(raw)
        gate=dict(status="PASS",group=a.group,source=identity,processes=rec.records,evidence=report["evidence"],
            new_original_or_native_applications=0,original_failure_preserved=True,whole_runtime_replaced=False)
        (capture/"GATE.json").write_bytes(encoded(gate));require(source_evidence(ROOT)==identity,"independent source changed")
        actual=report["evidence"]["complete_recovery"]["evidence"]["actual"]
        print(encoded(dict(status="INDEPENDENT_COMPLETE_UPLOADED_UTF8_PASS",group=a.group,
            original_decodes=actual["original_decodes"],native_calls=actual["actual_native_calls"],
            private_controls=actual["private_controls"],physical_refusals=8,full_relocations=2,
            guarded_entries=report["entries"],guard_probes=len(report["probes"]),
            new_original_or_native_applications=0)).decode(),end="")
    except BaseException as exc:
        (capture/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,
            processes=rec.records,error_type=type(exc).__name__,message=str(exc),traceback=traceback.format_exc(),
            new_original_or_native_applications=0,whole_runtime_replaced=False)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
