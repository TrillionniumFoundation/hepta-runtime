#!/usr/bin/env python3
"""Fetch or restore one of three frozen archives, without executing its contents."""
from pathlib import Path
import argparse,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,owned,pin,require,source_evidence
import retained_archive
def main():
    p=argparse.ArgumentParser();p.add_argument("kind",choices=["recovery","semantic","build"])
    p.add_argument("stage",choices=["fetch","unpack"]);p.add_argument("--work",type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args()
    identity=source_evidence(ROOT);source_evidence(ROOT/"trusted-reader")
    if a.kind=="recovery":
        binding=decode(owned(ROOT,"UPLOAD_BINDING.json").read_bytes())["groups"][a.group]
        value=retained_archive.fetch(a.work,binding)if a.stage=="fetch"else retained_archive.unpack(a.work,binding)
    else:
        reader=ROOT/"trusted-reader"
        if a.kind=="semantic":
            binding=decode(owned(reader,"ORIGIN_BINDING.json").read_bytes())["groups"][a.group]
            value=retained_archive.fetch(a.work,binding)if a.stage=="fetch"else retained_archive.unpack(a.work,binding)
        else:
            sys.path.insert(0,str(reader/"scripts"));import build_reuse
            binding=build_reuse.binding(reader)
            value=build_reuse.fetch(a.work,binding)if a.stage=="fetch"else build_reuse.unpack(a.work,binding)
    require(source_evidence(ROOT)==identity,"independent source changed")
    print(encoded(value).decode(),end="")
if __name__=="__main__":main()
