#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Create immutable shared fixtures and independent mutable reference/native fixtures."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,source_evidence,require
from cases import domain,validate
from filesystem import create,describe,snapshot
from buffer_store import Writer
def main():
    p=argparse.ArgumentParser()
    for name in("source","output","fixtures"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();identity=source_evidence(a.source);validate()
    require(not a.output.exists()and not a.fixtures.exists(),"fresh setup roots required")
    a.output.mkdir(parents=True);a.fixtures.mkdir(parents=True);store=Writer(a.output/"buffers");rows=[]
    for case in domain()["cases"]:
        roles=("original","native")if case["mutation"]else("shared",);inputs={}
        for role in roles:
            root=a.fixtures/(str(case["id"]).zfill(3)+"-"+role)
            create(root,case);query=describe(root,case,snapshot(root,store))
            inputs[role]=query
        rows.append(dict(id=case["id"],roles=inputs))
    (a.output/"inputs.json").write_bytes(canonical(rows))
    result=dict(status="FROZEN_BORROWED_PARENT_INPUTS_CREATED",source=identity,cases=59,
        immutable_shared_cases=38,separate_mutable_pairs=21,images=store.images,logical_bytes=store.logical_bytes,
        original_or_native_application_calls=0)
    (a.output/"SETUP.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
