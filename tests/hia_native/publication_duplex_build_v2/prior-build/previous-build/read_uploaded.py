#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete uploaded graph read with immutable evidence and no image invocation."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
from async_build_common import *
import restore_full,read_graph,read_build,dynamic_builder,read_only_guard as guard
def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--artifact",type=int,required=True);p.add_argument("--bytes",type=int,required=True);p.add_argument("--sha256",required=True)
    a=p.parse_args();package()
    target,archive=restore_full.restore(a.output,dict(artifact=a.artifact,zip=dict(bytes=a.bytes,sha256=a.sha256)))
    captured=target/"capture";retained=captured/"retained"
    require(files(target/"recipe-source")==files(HERE),"exact retained recipe bytes/modes")
    read_graph.prepare(retained);dynamic_builder.load(captured/"source")
    result=guard.guarded(lambda:dict(retained=read_graph.verify(retained),current=read_build.verify(retained,captured)),roots=[target,HERE],foreign_path=Path("/dev/null"))
    put(a.output/"READ_ONLY.json",result)
    summary=dict(status="COMPLETE_UPLOADED_PUBLICATION124_GRAPH_READ_PASS",archive=archive,entries=result["evidence"]["current"]["entries"],
        guards=len(result["probes"]),snapshot_entries=len(result["before"]),native_or_rust_executed=False,reader_writes=0,public_async_qualified=False)
    put(a.output/"SUMMARY.json",summary);print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=="__main__":main()
