#!/usr/bin/env python3
"""Guarded complete actual qualification proof; no original or HIA application call."""
from pathlib import Path
import argparse,encodings.cp437,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded,source_evidence,require
import read_qualification,build_reuse
from readonly import guarded
def main():
    p=argparse.ArgumentParser()
    for key in("source","capture","build-work"):p.add_argument("--"+key,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);capture=a.capture.resolve(strict=True);work=a.build_work.resolve(strict=True)
    before=source_evidence(source);build_reuse.prepare_imports(work)
    result=guarded(lambda:read_qualification.verify(source,capture,a.group,work),
        roots=[source,capture,work/"original",work/"download"])
    require(source_evidence(source)==before,"whole qualification source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
