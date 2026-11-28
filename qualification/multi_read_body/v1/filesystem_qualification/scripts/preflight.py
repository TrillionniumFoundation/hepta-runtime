#!/usr/bin/env python3
"""One bounded source-only preflight before any actual lane is admitted."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,require,source_evidence
from process import Recorder
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    require(not a.output.exists(),"fresh source-only preflight");a.output.mkdir(parents=True)
    before=source_evidence(ROOT);rec=Recorder(ROOT,a.output/"processes")
    try:
        raw,row=rec.run("source-check",[sys.executable,"-I","-S","-B",ROOT/"scripts/check_source.py"],timeout=60)
        result=decode(raw);require(result["status"]=="MULTI_FILESYSTEM_SOURCE_AND_INPUT_ONLY_PASS","complete source-only preflight")
        (a.output/"RESULT.json").write_bytes(encoded(dict(status="PASS",source=before,result=result,processes=rec.records,application_calls=0)))
        print(raw.decode(),end="")
    except BaseException:
        (a.output/"RESULT.json").write_bytes(encoded(dict(status="FAIL",source=before,processes=rec.records,application_calls=0)))
        if rec.records:print((rec.directory/(rec.records[-1]["name"]+".stderr")).read_text(),file=sys.stderr)
        raise
if __name__=="__main__":main()
