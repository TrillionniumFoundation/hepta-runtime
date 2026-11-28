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
            result=decode(raw);require(result["status"]in("PASS","ALL_UPLOADED_JSON_ITEMS_ARCHIVE_BYTES_PASS"),"complete semantic archive "+stage)
        if a.group=="0":
            raw,row=rec.run("independent-full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_recovered.py",
                "read","--work",work],timeout=180)
            guard=decode(raw);require(guard["before"]==guard["after"]and len(guard["probes"])==11
                and guard["evidence"]["status"]=="COMPLETE_INDEPENDENT_RECOVERED_JSON_ITEMS_PASS",
                "complete archived actual recovery")
            (proof/"READONLY.json").write_bytes(raw)
            raw,row=rec.run("first-physical-controls",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_recovered.py",
                "controls","--work",work],timeout=180)
            physical=decode(raw);require(physical["refusals"]==8 and physical["relocations"]==2,"first controls completed")
            (proof/"PHYSICAL.json").write_bytes(raw)
            raw,row=rec.run("complete-recovery-proof",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_recovered.py",
                "verify","--work",work],timeout=180)
            final=decode(raw);require(final["before"]==final["after"]and len(final["probes"])==11
                and final["evidence"]["status"]=="COMPLETE_RECOVERED_JSON_ITEMS_AND_PHYSICAL_PASS",
                "all recovered bytes and controls independently read")
            (proof/"FINAL_READONLY.json").write_bytes(raw)
            result=dict(status="PASS",group="0",source=identity,processes=rec.records,read=final["evidence"],
                guard_probes=22,entries=final["entries"],application_executions=0,first_physical_controls=10)
            (proof/"GATE.json").write_bytes(encoded(result));require(source_evidence(ROOT)==identity,"pure source changed")
            actual=guard["evidence"]["qualification"]["actual"]
            print(encoded(dict(status="COMPLETE_JSON_ITEMS_RECOVERY_AND_PHYSICAL_PASS",group="0",
                original_calls=actual["original_calls"],native_semantic_calls=actual["native_semantic_calls"],
                private_native_calls=actual["private_native_calls"],full_native_bytes=actual["native_full_buffer_bytes"],
                physical_refusals=8,relocations=2,original_gate_status="FAIL",application_replays=0)).decode(),end="")
        else:
            raw,row=rec.run("independent-full-read",[sys.executable,"-I","-S","-B",ROOT/"scripts/read_uploaded.py","--work",work,"--group",a.group],timeout=180)
            guard=decode(raw);require(guard["before"]==guard["after"]and len(guard["probes"])==11
                and guard["evidence"]["status"]=="COMPLETE_INDEPENDENT_UPLOADED_JSON_ITEMS_PASS","complete independent uploaded read")
            (proof/"READONLY.json").write_bytes(raw)
            result=dict(status="PASS",group=a.group,source=identity,processes=rec.records,read=guard["evidence"],
                guard_probes=11,entries=guard["entries"],application_executions=0)
            (proof/"GATE.json").write_bytes(encoded(result));require(source_evidence(ROOT)==identity,"pure source changed")
            actual=guard["evidence"]["qualification"]["actual"]
            print(encoded(dict(status="COMPLETE_JSON_ITEMS_INDEPENDENT_READ_PASS",group=a.group,
                original_calls=actual["original_calls"],native_semantic_calls=actual["native_semantic_calls"],
                full_native_bytes=actual["native_full_buffer_bytes"],entries=guard["entries"],guard_probes=11,
                elapsed_seconds=row["elapsed_seconds"])).decode(),end="")
    except BaseException as e:
        (proof/"GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,source=identity,processes=rec.records,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),application_executions=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
