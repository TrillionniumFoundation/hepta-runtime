#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full byte-only prior graph restoration and unchanged complete read."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import direct_common as c
def main():
    p=argparse.ArgumentParser();p.add_argument("--recipe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();identity,ac,restore,old,builder,guard,reader=c.setup(a.recipe)
    target,archive=restore.restore(a.output,json.loads((HERE/"BUILD_INPUT.json").read_bytes()))
    c.require(ac.files(target/"recipe-source")==ac.files(a.recipe),"all original build recipe bytes")
    result=old.checked(target/"capture",roots=[target,a.recipe,HERE])
    c.put(a.output/"READ_ONLY.json",result)
    c.put(a.output/"SUMMARY.json",dict(status="FULL_RETAINED_BUILD_ADMITTED",source=identity,archive=archive,
        guards=len(result["probes"]),entries=len(result["before"]),application_executed=False))
    print(json.dumps(dict(status="FULL_RETAINED_BUILD_ADMITTED",guards=len(result["probes"])),sort_keys=True),flush=True)
if __name__=="__main__":main()
