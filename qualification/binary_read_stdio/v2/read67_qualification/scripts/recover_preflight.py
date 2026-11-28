#!/usr/bin/env python3
"""Bounded complete same-capture recovery; no application or physical control replay."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,decode,pin,require,source_evidence
from process import Recorder,environment
def main():
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);p.add_argument("--manifest",required=True)
    p.add_argument("--export-to",type=Path);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.manifest,"complete frozen recovery source")
    identity=source_evidence(ROOT);work=a.work.absolute()
    if a.export_to is not None:
        output=a.export_to.absolute();require(not output.exists(),"fresh complete recovery export");output.mkdir(parents=True)
        rec=Recorder(ROOT,output/"processes")
        raw,row=rec.run("complete-export",[sys.executable,"-I","-S","-B",ROOT/"scripts/export.py",
            "--capture",work,"--archive",output/"evidence.tar.gz"],timeout=180)
        result=decode(raw);(output/"EXPORT.json").write_bytes(canonical(dict(status="PASS",source=identity,archive=result,process=row)))
        print(canonical(result).decode(),end="");return
    require(not work.exists(),"fresh pure recovery root");work.mkdir(parents=True)
    env,binding=environment(__import__("os").environ);rec=Recorder(ROOT,work/"processes",env);stage="fetch"
    try:
        for stage,limit in(("fetch",60),("unpack",180)):
            rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/restore_observer.py",stage,
                "--source",ROOT,"--work",work,"--group","observer"],timeout=limit)
        stage="read"
        raw,_=rec.run(stage,[sys.executable,"-I","-S","-B",ROOT/"scripts/read_preflight.py","--work",work],timeout=180)
        proof=decode(raw);require(proof["before"]==proof["after"]and len(proof["probes"])==11,"complete quiescent pure read")
        require(proof["evidence"]["status"]=="STDIO_OBSERVER_ORIGINAL_CAPTURE_RECOVERY_PASS","same probe capture closed")
        (work/"READONLY.json").write_bytes(raw)
        require(source_evidence(ROOT)==identity,"pure recovery changed source")
        result=dict(status="PASS",source=identity,proof=proof["evidence"],guard_probes=11,processes=rec.records,
            original_target_applications=0,hia_applications=0,probe_replays=0,physical_control_replays=0)
        (work/"GATE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
    except BaseException as error:
        (work/"GATE.json").write_bytes(canonical(dict(status="FAIL",stage=stage,source=identity,
            error_type=type(error).__name__,message=str(error),traceback=traceback.format_exc(),processes=rec.records,
            original_target_applications=0,hia_applications=0,probe_replays=0,physical_control_replays=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
