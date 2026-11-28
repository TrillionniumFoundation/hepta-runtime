#!/usr/bin/env python3
"""Create one frozen input-only filesystem group, before either implementation."""
from pathlib import Path
import argparse,sys,json,os
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,source_evidence,require
from cases import group,validate
from filesystem import create,snapshot
from buffer_store import Writer
def main():
    p=argparse.ArgumentParser()
    for name in("source","output","fixtures"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();identity=source_evidence(a.source);validate()
    require(not a.output.exists()and not a.fixtures.exists(),"fresh setup roots")
    a.output.mkdir(parents=True);a.fixtures.mkdir(parents=True);store=Writer(a.output/"buffers");rows=[]
    for case in group(a.group):
        parent=a.fixtures if case["storage"]=="disk"else Path("/dev/shm")/a.fixtures.name
        parent.mkdir(parents=True,exist_ok=True)
        row=create(parent/("case-"+str(case["id"]).zfill(3)),case)
        row["snapshot"]=snapshot(Path(row["fixture"]),store);rows.append(row)
    (a.output/"inputs.json").write_bytes(canonical(rows))
    result=dict(status="FROZEN_INPUTS_CREATED",group=a.group,cases=len(rows),source=identity,images=store.images,
        logical_bytes=store.logical_bytes,original_or_native_application_calls=0)
    (a.output/"SETUP.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
