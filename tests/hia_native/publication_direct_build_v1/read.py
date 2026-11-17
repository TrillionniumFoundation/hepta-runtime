#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Independent whole prior graph and actual direct link/pack read, zero execution."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import direct_common as c
def main():
    p=argparse.ArgumentParser()
    for n in ("recipe","previous","capture","output"):p.add_argument("--"+n,type=Path,required=True)
    a=p.parse_args();result=c.checked(a.capture,a.previous,a.recipe);c.put(a.output,result)
    print(json.dumps(dict(status="COMPLETE_DIRECT_BUILD_READ_PASS",guards=len(result["probes"]),
        entries=len(result["before"]),evidence=result["evidence"]["direct"]),sort_keys=True),flush=True)
if __name__=="__main__":main()
