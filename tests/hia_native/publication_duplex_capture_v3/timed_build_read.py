#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Observe byte restoration and unchanged guarded reader phases, same 180s parent."""
from pathlib import Path
import argparse,json,sys,time
sys.dont_write_bytecode=True
def main():
    p=argparse.ArgumentParser();p.add_argument("--build-recipe",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--artifact",required=True)
    p.add_argument("--bytes",required=True);p.add_argument("--sha256",required=True)
    a=p.parse_args();sys.path.insert(0,str(a.build_recipe/"current"))
    import read_uploaded
    original_restore=read_uploaded.restore_full.restore;original_checked=read_uploaded.read_all.checked
    start=time.monotonic();phases=[]
    def observe(name,**fields):
        phases.append(dict(phase=name,elapsed_seconds=time.monotonic()-start,**fields))
        (a.output.parent/"build-read-phases.json").write_text(json.dumps(phases,sort_keys=True,indent=2)+"\n")
        print("BUILD_READ_PHASE "+json.dumps(phases[-1],sort_keys=True),flush=True)
    def restore(*args,**kwargs):
        observe("restore_start");result=original_restore(*args,**kwargs)
        observe("restore_complete",archive=result[1]);return result
    def checked(*args,**kwargs):
        observe("guarded_read_start");result=original_checked(*args,**kwargs)
        observe("guarded_read_complete",guards=len(result["probes"]));return result
    read_uploaded.restore_full.restore=restore;read_uploaded.read_all.checked=checked
    sys.argv=[read_uploaded.__file__,"--output",str(a.output),"--artifact",a.artifact,
        "--bytes",a.bytes,"--sha256",a.sha256]
    read_uploaded.main()
if __name__=="__main__":main()
