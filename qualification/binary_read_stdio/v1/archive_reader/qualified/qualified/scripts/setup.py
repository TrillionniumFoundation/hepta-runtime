#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Create the frozen actual input domain before either implementation executes."""
from pathlib import Path
import argparse,sys,json
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,source_evidence,require
from cases import cases,validate
from filesystem import create,snapshot
from buffer_store import Writer
def main():
    p=argparse.ArgumentParser();p.add_argument("--source",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--fixtures",type=Path,required=True)
    a=p.parse_args();identity=source_evidence(a.source);validate()
    require(not a.output.exists()and not a.fixtures.exists(),"fresh setup roots required")
    a.output.mkdir(parents=True);a.fixtures.mkdir(parents=True)
    store=Writer(a.output/"buffers");rows=[]
    for case in cases():
        row=create(a.fixtures/("case-"+str(case["id"]).zfill(3)),case)
        row["snapshot"]=snapshot(Path(row["fixture"]),store);rows.append(row)
    (a.output/"inputs.json").write_bytes(canonical(rows))
    result=dict(status="FROZEN_INPUTS_CREATED",cases=len(rows),source=identity,images=store.images,
        logical_bytes=store.logical_bytes,original_or_native_application_calls=0)
    (a.output/"SETUP.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
