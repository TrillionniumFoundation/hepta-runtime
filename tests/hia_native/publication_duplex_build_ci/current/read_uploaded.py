#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Full uploaded bytes, actual prior receipts and new complete mechanical pack."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True;HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from async_build_common import *
import restore_full,read_all
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--artifact",type=int,required=True);p.add_argument("--bytes",type=int,required=True);p.add_argument("--sha256",required=True)
    a=p.parse_args();package()
    target,archive=restore_full.restore(a.output,dict(artifact=a.artifact,zip=dict(bytes=a.bytes,sha256=a.sha256)))
    require(files(target/"recipe-source")==files(HERE.parent),"complete retained recipe bytes/modes")
    result=read_all.checked(target/"capture",roots=[target,HERE.parent])
    put(a.output/"READ_ONLY.json",result)
    summary=dict(status="COMPLETE_UPLOADED_PUBLICATION124_TWO_SESSION_BUILD_READ_PASS",archive=archive,
        entries=result["evidence"]["current"]["entries"],guards=len(result["probes"]),
        snapshot_entries=len(result["before"]),native_or_rust_executed=False,reader_writes=0,public_async_qualified=False)
    put(a.output/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
