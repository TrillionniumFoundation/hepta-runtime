#!/usr/bin/env python3
"""Bounded independent download, restoration and read of each complete group."""
from pathlib import Path
import argparse,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
from archive_reader import frozen,encoded,decode,require,pin
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path);a=p.parse_args()
    identity,bindings=frozen(a.source_manifest_sha256);binding=bindings["groups"][a.group];work=a.work.absolute()
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh independent proof output");a.output.mkdir(parents=True)
        rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"export.py",
            "--capture",work/"proof","--archive",a.output/"evidence.tar.gz"],timeout=180)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",archive=decode(raw),process=row)))
        print(raw.decode(),end="");return
    require(not work.exists(),"fresh independent reader root");work.mkdir(parents=True);(work/"proof").mkdir()
    rec=Recorder(ROOT,work/"proof/processes");outputs={};stage="fetch"
    try:
        for stage,limit in(("fetch",60),("restore",180)):
            raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"archive_reader.py",stage,"--work",work,
                "--group",a.group,"--source-manifest-sha256",a.source_manifest_sha256],timeout=limit);outputs[stage]=decode(raw)
        preserved=work/"previous-reader/download/complete.zip";retained=work/"proof/preserved-initial-reader.zip"
        shutil.copy2(preserved,retained)
        require(preserved.read_bytes()==retained.read_bytes()and pin(retained)=={k:binding["preserved_reader_failure"]["artifact"][k]for k in("bytes","sha256")},
            "complete previous reader failure retained in final proof")
        reuse=work/"build-reuse";reuse.mkdir()
        for stage,limit in(("fetch",60),("unpack",180)):
            raw,row=rec.run("build-"+stage,[sys.executable,"-I","-S","-B",ROOT/"qualified/scripts/build_reuse.py",stage,
                "--source",ROOT/"qualified","--work",reuse],timeout=limit);outputs["build-"+stage]=decode(raw)
            require(outputs["build-"+stage]["status"]=="PASS","whole original build "+stage)
        stage="independent-read"
        raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"archive_reader.py","read","--work",work,
            "--group",a.group,"--source-manifest-sha256",a.source_manifest_sha256],timeout=180)
        outputs["read"]=decode(raw);require(outputs["read"]["evidence"]["status"]=="COMPLETE_INDEPENDENT_PUBLISH_UPLOAD_PASS","complete independent group")
        gate=dict(status="PASS",group=a.group,source_manifest=identity,binding=binding,processes=rec.records,
            archive=outputs["restore"],read=outputs["read"],application_hia_executions=0,rust_executions=0,physical_controls_replayed=0)
        (work/"proof/GATE.json").write_bytes(encoded(gate))
        print(encoded(dict(status="COMPLETE_INDEPENDENT_PUBLISH_UPLOAD_PASS",group=a.group,archive=outputs["restore"],
            evidence=outputs["read"]["evidence"],elapsed_seconds=row["elapsed_seconds"],entries=outputs["read"]["entries"],
            guard_probes=len(outputs["read"]["probes"]),application_executions=0)).decode(),end="")
    except BaseException as e:
        (work/"proof/GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,stage=stage,source_manifest=identity,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),processes=rec.records,
            application_hia_executions=0,rust_executions=0,physical_controls_replayed=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
