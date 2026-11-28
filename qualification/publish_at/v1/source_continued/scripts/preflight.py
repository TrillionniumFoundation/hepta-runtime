#!/usr/bin/env python3
"""Bounded source and input admission; no application, compiler, or fixture execution."""
from pathlib import Path
import argparse,sys,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,pin,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    require(pin(ROOT/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"frozen complete preflight source")
    require(not a.output.exists(),"fresh bounded source preflight");a.output.mkdir(parents=True)
    source=source_evidence(ROOT);rec=Recorder(ROOT,a.output/"processes")
    try:
        raw,row=rec.run("source-input-admission",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        admission=decode(raw);require(admission["status"]=="PUBLISH_SOURCE_AND_INPUT_ONLY_PASS"and admission["source"]==source,"complete source/input result")
        require(source_evidence(ROOT)==source,"source changed during pure preflight")
        report=dict(status="SOURCE_ONLY_PASS",source=source,admission=admission,processes=rec.records,
            application_executions=0,compiler_executions=0,rust_executions=0,fixture_effects=0)
        (a.output/"PREFLIGHT.json").write_bytes(encoded(report));print(encoded(report).decode(),end="")
    except BaseException as e:
        report=dict(status="FAIL",source=source,processes=rec.records,error_type=type(e).__name__,message=str(e),traceback=traceback.format_exc(),
            application_executions=0,compiler_executions=0,rust_executions=0,fixture_effects=0)
        (a.output/"PREFLIGHT.json").write_bytes(encoded(report))
        if rec.records:print((rec.directory/"source-input-admission.stderr").read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
