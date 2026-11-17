#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual original execution with a separately owned real mutation barrier."""
from pathlib import Path
import argparse,json,os,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,source_evidence,require
from cases import group
from filesystem import snapshot
from buffer_store import Writer
from reference_carrier import Reference
from hooks import Hooks
def main():
    p=argparse.ArgumentParser()
    for n in("source","setup","output"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--group",required=True);a=p.parse_args();source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh original capture");a.output.mkdir(parents=True)
    inputs={r["id"]:r["roles"]for r in decode(owned(a.setup,"inputs.json").read_bytes())}
    store=Writer(a.output/"buffers");actor=None;rows=[]
    try:
        actor=Reference(source,a.output,store)
        for case in group(a.group):
            role=inputs[case["id"]];q=role.get("shared",role.get("original"))
            row=dict(id=q["id"],input=q,before=snapshot(q["fixture"],store));start=time.monotonic_ns()
            held,first=actor.exchange(dict(command="hold",query=q))
            require(held["status"]=="HELD","original did not hold parent")
            hooks=Hooks(q,actor.pid,store);actor.hooks=hooks;hooks.limit_enter()
            try:returned,second=actor.exchange(dict(command="run"))
            finally:hooks.limit_leave()
            require(returned["status"]=="RETURNED","original did not return")
            fdset={p.name:os.readlink(p)for p in(Path("/proc")/str(actor.pid)/"fd").iterdir()}
            released,last=actor.exchange(dict(command="release"));actor.hooks=None
            require(released["status"]=="RELEASED","original did not release parent")
            row.update(result=returned["result"],original_diagnostic=returned["diagnostic"],
                chain=dict(first_exchange=first,run_exchange=second,last_exchange=last,held=held,
                    returned_parent=returned["parent"],released_parent=released["parent"],fd=fdset),
                hooks=hooks.result(),after=snapshot(q["fixture"],store),elapsed_ns=time.monotonic_ns()-start)
            rows.append(row);(a.output/"cases.json").write_bytes(canonical(rows))
        receipt=actor.finish()
        result=dict(status="ORIGINAL_BORROWED_PARENT_DOMAIN_COMPLETE",cases=len(rows),group=a.group,source=identity,
            buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,exchanges=actor.ordinal,
            process=receipt,exact_original_functions=True,private_branch_exact=True)
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    finally:
        if actor:actor.cleanup()
if __name__=="__main__":main()
