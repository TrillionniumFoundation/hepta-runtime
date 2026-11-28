#!/usr/bin/env python3
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import source_evidence,encoded,require
import read_utf8
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--data",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
    source=a.source.resolve(strict=True);data=a.data.resolve(strict=True);before=source_evidence(source)
    result=guarded(lambda:read_utf8.verify(source,data,a.group),roots=[source,data])
    require(source_evidence(source)==before,"pure reader source changed")
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
