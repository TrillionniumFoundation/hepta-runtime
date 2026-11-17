#!/usr/bin/env python3
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from evidence_common import encoded,require,source_evidence
import build_reuse,read_utf8_evidence
def main():
    parser=argparse.ArgumentParser()
    for name in ("source","capture","reuse"):parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    source=args.source.resolve(strict=True);capture=args.capture.resolve(strict=True);reuse=args.reuse.resolve(strict=True)
    before=source_evidence(source);build_reuse.prepare_imports(reuse)
    from readonly import guarded
    result=guarded(lambda:read_utf8_evidence.verify(source,capture,reuse),
        roots=[source,capture,reuse/"original",reuse/"download"])
    require(source_evidence(source)==before,"independent reader source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
