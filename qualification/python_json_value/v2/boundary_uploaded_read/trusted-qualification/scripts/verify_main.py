#!/usr/bin/env python3
"""Pure whole retained boundary evidence read; no native/JSON calls."""
import argparse,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical
from readonly import guarded
import read_evidence
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    a=p.parse_args();source,work=a.source.resolve(strict=True),a.work.resolve(strict=True)
    module=read_evidence.prepare(source,work)
    value=guarded(lambda:read_evidence.verify(source,work,module),roots=[source,work])
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
