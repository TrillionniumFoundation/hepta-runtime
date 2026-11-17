#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Keep every profile and its actual failed capture; never reduce the domain."""
from pathlib import Path
import argparse
import json
import subprocess
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,require,pin
from input_domain import PROFILES
def main():
    p=argparse.ArgumentParser()
    for name in ("source","dependencies","original-build","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();require(not a.output.exists(),"new profile output");a.output.mkdir(parents=True)
    receipts=[];failed=False
    for profile in PROFILES:
        for kind in ("capture","read"):
            if kind=="read" and receipts[-1]["returncode"]!=0:break
            command=[sys.executable,"-I","-S","-B",str(a.source/"recipe"/("capture_gateway.py" if kind=="capture" else "read_gateway.py"))]
            if kind=="capture":
                command+=["--dependencies",str(a.dependencies),"--original-build",str(a.original_build),
                    "--output",str(a.output/profile),"--profile",profile]
            else:command+=["--capture",str(a.output/profile)]
            out=a.output/(profile+"-"+kind+".stdout");err=a.output/(profile+"-"+kind+".stderr")
            # The capture enforces its own 180/60 deadlines and reaps its owned process group.
            # An outer killpg timeout would not own a child's new session, so none is added.
            with out.open("xb") as stdout,err.open("xb") as stderr:
                result=subprocess.run(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
            row=dict(profile=profile,kind=kind,command=command,returncode=result.returncode,stdout=pin(out),stderr=pin(err))
            receipts.append(row);(a.output/"PROFILES.json").write_bytes(canonical(receipts))
            print(json.dumps(row,sort_keys=True),flush=True)
            if result.returncode:
                failed=True
                print(err.read_text(errors="replace"),file=sys.stderr,flush=True)
    require(not failed and len(receipts)==2*len(PROFILES),"one or more complete gateway profiles failed")
    print(json.dumps(dict(status="COMPLETE_SIX_PROFILE_GATEWAY_COMPARISON_PASS",profiles=len(PROFILES)),sort_keys=True))
if __name__=="__main__":main()
