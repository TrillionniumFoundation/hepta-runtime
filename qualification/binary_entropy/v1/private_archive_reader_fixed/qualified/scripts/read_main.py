#!/usr/bin/env python3
"""Pure full-build or private-buffer reader under all eleven capability guards."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,require,source_evidence
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("stage",choices=["build","capture"])
    p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path)
    p.add_argument("--capture",type=Path);a=p.parse_args()
    source=a.source.resolve(strict=True);identity=source_evidence(source)
    if a.stage=="build":
        import build_reuse,read_build_evidence
        work=a.work.resolve(strict=True);build_reuse.prepare_imports(work)
        result=guarded(lambda:read_build_evidence.verify(source,work),roots=[source,work/"original",work/"download"])
    else:
        import read_private
        capture=a.capture.resolve(strict=True)
        result=guarded(lambda:read_private.verify(source,capture),roots=[source,capture])
    require(source_evidence(source)==identity,"private reader changed source")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
