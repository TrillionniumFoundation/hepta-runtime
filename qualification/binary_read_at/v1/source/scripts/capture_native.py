#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual borrowed-parent ELF execution; no reference result is consulted."""
from pathlib import Path
import argparse,json,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,owned,source_evidence,require
from cases import group
from filesystem import snapshot
from buffer_store import Writer
from native_carrier import Carrier,WORD
def main():
    p=argparse.ArgumentParser()
    for n in("source","setup","build","output"):p.add_argument("--"+n,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--unobserved",action="store_true");a=p.parse_args()
    source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh native capture");a.output.mkdir(parents=True)
    inputs={r["id"]:r["roles"]for r in decode(owned(a.setup,"inputs.json").read_bytes())}
    store=Writer(a.output/"buffers");actor=None;rows=[]
    try:
        actor=Carrier(a.build/"binary-read-body-callable.elf",a.output,store)
        if a.unobserved:
            for session in(0,1):
                raw,_=actor.exchange(9,session);require(WORD(raw,8)==0,"unobserved context creation")
        for case in group(a.group):
            role=inputs[case["id"]];q=role.get("shared",role.get("native"))
            row=dict(id=q["id"],input=q,before=snapshot(q["fixture"],store));start=time.monotonic_ns()
            value,chain,hooks=actor.run(q,not a.unobserved)
            row.update(result=value,chain=chain,hooks=hooks,after=snapshot(q["fixture"],store),
                elapsed_ns=time.monotonic_ns()-start)
            rows.append(row);(a.output/"cases.json").write_bytes(canonical(rows))
        receipt=actor.finish()
        require(not a.unobserved or receipt["journal"]["raw"]["bytes"]==0,"disabled observer produced bytes")
        result=dict(status="NATIVE_BORROWED_PARENT_DOMAIN_COMPLETE",cases=len(rows),group=a.group,source=identity,
            buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,exchanges=actor.ordinal,
            native_process=receipt,observer_enabled=not a.unobserved,private_refusals=sum(len(r["chain"]["controls"])for r in rows),
            original_outputs_read=False,runtime_python_required=False,runtime_libc_required=False)
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    finally:
        if actor:actor.cleanup()
if __name__=="__main__":main()
