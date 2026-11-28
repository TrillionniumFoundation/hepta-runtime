#!/usr/bin/env python3
"""Freeze/source admission and two new observer probes; zero original/HIA target calls."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--manifest",required=True);p.add_argument("--export-to",type=Path)
    a=p.parse_args();require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.manifest,"complete source manifest pin")
    identity=source_evidence(ROOT);work=a.work.absolute()
    if a.export_to is not None:
        output=a.export_to.absolute();require(not output.exists(),"fresh complete observer archive");output.mkdir(parents=True)
        rec=Recorder(ROOT,output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",output/"evidence.tar.gz"],timeout=180)
        value=decode(raw);(output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",source=identity,archive=value,process=row)))
        print(canonical(value).decode(),end="");return
    require(not work.exists(),"fresh observer-only preflight root");work.mkdir(parents=True)
    env,binding=environment(__import__("os").environ);rec=Recorder(ROOT,work/"processes",env);stage="source-check"
    try:
        raw,_=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py","--source",ROOT],timeout=60)
        source=decode(raw);require(source["actual_application_calls"]==source["compiler_calls"]==0,"source-only admission")
        stage="observer-probes"
        raw,_=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/preflight.py","--work",work/"probes"],timeout=180)
        probes=decode(raw);require(probes["status"]=="PASS"and probes["original_target_applications"]==probes["hia_applications"]==0,
            "two independent probes never import target or execute native code")
        require(source_evidence(ROOT)==identity,"complete source changed during preflight")
        result=dict(status="PASS",source=identity,source_check=source,probes=probes,processes=rec.records,
            environment=binding,original_target_applications=0,hia_applications=0,compiler_calls=0)
        (work/"GATE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",stage=stage,source=identity,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),
            processes=rec.records,original_target_applications=0,hia_applications=0,compiler_calls=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
