#!/usr/bin/env python3
"""Bounded full uploaded JSON value archive read; never invoke any application."""
from pathlib import Path
import argparse,json,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import encoded,decode,pin,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["read","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--output",type=Path);p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"exact independent reader manifest")
    identity=source_evidence(ROOT);work=a.work.absolute();proof=work/"proof"
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh complete proof archive");a.output.mkdir(parents=True)
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("proof-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py","--capture",proof,"--archive",a.output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",source=identity,archive=result,process=row)))
        print(encoded(result).decode(),end="");return
    require(not work.exists(),"fresh independent read");work.mkdir(parents=True);proof.mkdir();rec=Recorder(ROOT,proof/"processes")
    (work/"semantic").mkdir()
    bound=decode((ROOT/"INPUTS.json").read_bytes())["groups"][a.group]
    try:
        for stage,limit in(("fetch",60),("unpack",180),("admit",180)):
            raw,row=rec.run("semantic-"+stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/restore_uploaded.py",stage,
                "--source",ROOT,"--work",work/"semantic","--group",a.group],timeout=limit)
            result=decode(raw);require(result["status"]in("PASS","ALL_UPLOADED_JSON_VALUE_ARCHIVE_BYTES_PASS"),"complete semantic archive "+stage)
        raw,row=rec.run("independent-full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_uploaded.py","--work",work,"--group",a.group],timeout=180)
        guard=decode(raw);require(guard["before"]==guard["after"]and len(guard["probes"])==11
            and guard["evidence"]["status"]=="COMPLETE_INDEPENDENT_UPLOADED_JSON_VALUE_BOUNDARY_PASS","complete independent uploaded read")
        (proof/"READONLY.json").write_bytes(raw)
        result=dict(status="PASS",group=a.group,source=identity,processes=rec.records,read=guard["evidence"],
            guard_probes=11,entries=guard["entries"],application_executions=0)
        (proof/"GATE.json").write_bytes(encoded(result));require(source_evidence(ROOT)==identity,"pure source changed")
        print(encoded(dict(status="COMPLETE_JSON_VALUE_BOUNDARY_INDEPENDENT_READ_PASS",group=a.group,read=guard["evidence"],
            entries=guard["entries"],guard_probes=11,elapsed_seconds=row["elapsed_seconds"])).decode(),end="")
    except BaseException as e:
        (proof/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),application_executions=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
