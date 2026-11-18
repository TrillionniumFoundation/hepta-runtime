#!/usr/bin/env python3
"""Read an uploaded complete qualification tree under strict nonmutation guard."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,require,pin
import read_evidence
from readonly import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    source,work=map(lambda p:p.resolve(strict=True),(a.source,a.work))
    require(pin(source/"SOURCE_MANIFEST.json")["sha256"]==a.source_manifest_sha256,"whole frozen qualification reader source")
    module=read_evidence.prepare(source,work)
    value=guarded(lambda:read_evidence.verify(source,work,module),roots=[source,work])
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
