#!/usr/bin/env python3
"""Complete saved build and all physical guards; zero applications."""
from pathlib import Path
import argparse,encodings.cp437,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,source_evidence,require
from readonly import guarded
import build_reuse,read_build_evidence
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    a=p.parse_args();before=source_evidence(a.source);build_reuse.prepare_imports(a.work)
    value=guarded(lambda:read_build_evidence.verify(a.source,a.work),roots=[a.source,a.work])
    require(source_evidence(a.source)==before,"build read source changed")
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
