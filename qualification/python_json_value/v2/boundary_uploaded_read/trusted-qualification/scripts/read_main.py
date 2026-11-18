#!/usr/bin/env python3
"""Guard the complete native boundary comparison; no application replay."""
import argparse,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical
from readonly import guarded
import cases,original_input,read_boundary
def roots(source,work):
    return[source,work/"build-input",work/"profile-input",work/"runtime",work/"native",work/"admission"]
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();source,work=a.source.resolve(strict=True),a.work.resolve(strict=True)
    cases.total();original_input.prepare(source,work/"profile-input",a.group)
    value=guarded(lambda:read_boundary.verify(source,work,a.group),roots=roots(source,work))
    print(canonical(value).decode(),end="")
if __name__=="__main__":main()
