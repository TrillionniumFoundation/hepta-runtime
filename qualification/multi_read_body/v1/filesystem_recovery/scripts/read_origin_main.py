#!/usr/bin/env python3
"""Read original producer custody and the exact reader correction under strict denial."""
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded
import build_reuse,read_origin
from readonly import guarded
def main():
    p=argparse.ArgumentParser()
    for name in ("reader","semantic","reuse"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    reader=a.reader.resolve(strict=True);semantic=a.semantic.resolve(strict=True);reuse=a.reuse.resolve(strict=True)
    build_reuse.prepare_imports(reuse)
    result=guarded(lambda:read_origin.verify(reader,semantic,reuse,a.group),
        roots=[reader,semantic/"original",semantic/"download",reuse/"original",reuse/"download"])
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
