#!/usr/bin/env python3
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import encoded
from readonly import guarded
import read_partial
p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True)
p.add_argument("--work",type=Path,required=True);p.add_argument("--group",required=True);a=p.parse_args()
print(encoded(guarded(lambda:read_partial.verify(a.source,a.work,a.group),
    roots=[a.source,a.work])).decode(),end="")
