#!/usr/bin/env python3
"""Bounded full original uploaded evidence restoration and read; zero application execution."""
from pathlib import Path
import argparse,shutil,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from uploaded_reader import frozen,encoded,decode,require,pin
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["source","run","export"])
    p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--output",type=Path);a=p.parse_args()
    identity,bindings=frozen(a.source_manifest_sha256);binding=bindings["groups"][a.group];work=a.work.absolute()
    if a.stage=="source":
        import ast
        rows=[]
        for path in sorted(ROOT.rglob("*.py")):
            compile(path.read_bytes(),str(path),"exec",flags=ast.PyCF_ONLY_AST);rows.append(path.relative_to(ROOT).as_posix())
        work.mkdir(parents=True);result=dict(status="INDEPENDENT_READER_SOURCE_ONLY_PASS",source=identity,python_sources=rows,
            application_calls=0,control_replays=0)
        (work/"GATE.json").write_bytes(encoded(result));print(encoded(result).decode(),end="");return
    if a.stage=="export":
        require(a.output is not None and not a.output.exists(),"fresh independent proof output");a.output.mkdir(parents=True)
        (work/"proof").mkdir(parents=True,exist_ok=True);rec=Recorder(ROOT,a.output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work/"proof","--archive",a.output/"evidence.tar.gz"],timeout=180)
        (a.output/"EXPORT.json").write_bytes(encoded(dict(status="PASS",archive=decode(raw),process=row)))
        print(raw.decode(),end="");return
    require(not work.exists(),"fresh independent evidence root");work.mkdir(parents=True);(work/"proof").mkdir()
    rec=Recorder(ROOT,work/"proof/processes");outputs={};stage="fetch"
    try:
        for stage,limit in(("fetch",180),("restore",180)):
            raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/uploaded_reader.py",stage,"--work",work,
                "--group",a.group,"--source-manifest-sha256",a.source_manifest_sha256],timeout=limit);outputs[stage]=decode(raw)
        source=work/"capture/download/complete.zip";target=work/"proof/complete-original-capture.zip"
        shutil.copyfile(source,target);require(pin(source)==pin(target)=={k:binding["artifact"][k]for k in("bytes","sha256")},
            "whole completed original capture retained inside independent proof")
        if a.group=="0":
            source=work/"source-failure/download/complete.zip";target=work/"proof/initial-source-failure.zip"
            shutil.copyfile(source,target);require(pin(source)==pin(target),"whole initial source-only failure retained")
        stage="independent-read"
        raw,row=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/uploaded_reader.py","read","--work",work,
            "--group",a.group,"--source-manifest-sha256",a.source_manifest_sha256],timeout=180)
        result=decode(raw);require(result["evidence"]["status"]=="COMPLETE_INDEPENDENT_WRITE_UPLOAD_PASS"
            and result["before"]==result["after"]and len(result["probes"])==11,"complete pure uploaded write qualification")
        gate=dict(status="PASS",group=a.group,source=identity,binding=binding,processes=rec.records,
            archive=outputs["restore"],read=result,application_calls=0,control_replays=0)
        (work/"proof/GATE.json").write_bytes(encoded(gate))
        print(encoded(dict(status="COMPLETE_INDEPENDENT_WRITE_UPLOAD_PASS",group=a.group,archive=outputs["restore"],
            evidence=result["evidence"],elapsed_seconds=row["elapsed_seconds"],entries=result["entries"],
            guard_probes=len(result["probes"]),new_application_calls=0,completed_controls_replayed=0)).decode(),end="")
    except BaseException as e:
        (work/"proof/GATE.json").write_bytes(encoded(dict(status="FAIL",group=a.group,stage=stage,source=identity,
            error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),processes=rec.records,
            application_calls=0,control_replays=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
