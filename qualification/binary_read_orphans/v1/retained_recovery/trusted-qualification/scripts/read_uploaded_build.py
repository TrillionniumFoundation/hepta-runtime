#!/usr/bin/env python3
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,source_evidence
import build_reuse,read_build_evidence
def main():
    p=argparse.ArgumentParser()
    for key in("source","work"):p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args();source=a.source.resolve(strict=True);work=a.work.resolve(strict=True)
    before=source_evidence(source)
    build_reuse.prepare_imports(work)
    from readonly import guarded
    result=guarded(lambda:read_build_evidence.verify(source,work),
        roots=[source,work/"original",work/"download"])
    if source_evidence(source)!=before:raise ValueError("pure reader source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
