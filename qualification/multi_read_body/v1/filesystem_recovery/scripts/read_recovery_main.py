#!/usr/bin/env python3
from pathlib import Path
import argparse,encodings.cp437,gzip,json,sys,zlib
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded
import build_reuse,read_recovery
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("mode",choices=["final","complete"])
    for name in ("reader","semantic","reuse"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--frozen",type=Path);p.add_argument("--capture",type=Path);p.add_argument("--group",required=True)
    a=p.parse_args();reader=a.reader.resolve(strict=True);semantic=a.semantic.resolve(strict=True);reuse=a.reuse.resolve(strict=True)
    build_reuse.prepare_imports(reuse)
    roots=[reader,semantic/"original",semantic/"download",reuse/"original",reuse/"download"]
    if a.mode=="final":
        frozen=a.frozen.resolve(strict=True);roots.append(frozen)
        operation=lambda:read_recovery.verify(reader,semantic,reuse,frozen,a.group)
    else:
        capture=a.capture.resolve(strict=True);roots.append(capture)
        operation=lambda:read_recovery.completed(reader,semantic,reuse,capture,a.group)
    result=guarded(operation,roots=roots)
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
