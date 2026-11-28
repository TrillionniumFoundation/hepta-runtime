#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual native ELF calls; the carrier transports bytes and never reads reference outputs."""
from pathlib import Path
import argparse,json,struct,sys,time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,encoded,owned,pin,require,source_evidence
from native_carrier import Carrier,WORD
from filesystem import snapshot
from cases import group
from buffer_store import Writer

def controls(actor,store,folder):
    rows=[]
    def perform(label,command,session,payload,code,state=None):
        raw,index=actor.exchange(command,session,payload)
        require(WORD(raw,8)==code and (state is None or WORD(raw,24)==state),"private control failed: "+label)
        row=dict(name=label,command=command,session=session,input=store.put(payload),
            exchange=index,expected_code=code,expected_state=state,response=store.put(raw))
        rows.append(row);return raw
    def context(session):
        raw,index=actor.exchange(4,session);require(WORD(raw,8)==0,"context observation")
        return raw[64:],index
    def unchanged(label,command,session,payload,code):
        before,first=context(session);perform(label,command,session,payload,code)
        after,last=context(session);require(before==after,"refusal changed full context")
        rows[-1]["before_context"]=dict(exchange=first,bytes=store.put(before))
        rows[-1]["after_context"]=dict(exchange=last,bytes=store.put(after))
    bad=b"HBRDQ001"+struct.pack("<11Q",1,0,1,1,1,0,0,0,1,0,2)+b"rr"
    for session in (0,1):
        unchanged("existing-create-"+str(session),8,session,b"",0xfffffffd)
        unchanged("idle-release-"+str(session),2,session,b"",0xffffffff)
        for name,value in (("short",b"x"),("magic",b"INVALID!"+bad[8:]),
            ("resume",bad[:8]+struct.pack("<Q",2)+bad[16:]),
            ("sequence",bad[:16]+struct.pack("<Q",1)+bad[24:])):
            unchanged(name+"-"+str(session),1,session,value,0xffffffff)
        perform("borrow-"+str(session),1,session,bad,64,2)
        unchanged("borrow-invoke-"+str(session),1,session,bad,0xfffffffd)
        unchanged("borrow-destroy-"+str(session),3,session,b"",0xfffffffd)
        unchanged("borrow-create-"+str(session),8,session,b"",0xfffffffd)
        before,first=context(session);perform("release-"+str(session),2,session,b"",0,0)
        after,last=context(session);expected=bytearray(before)
        for at in (56,168,176):struct.pack_into("<Q",expected,at,0)
        require(after==expected,"release changed bytes outside explicit borrow fields")
        rows[-1]["before_context"]=dict(exchange=first,bytes=store.put(before))
        rows[-1]["after_context"]=dict(exchange=last,bytes=store.put(after))
        perform("destroy-"+str(session),3,session,b"",0,0)
        perform("destroy-absent-"+str(session),3,session,b"",0xffffffff,0)
        perform("recreate-"+str(session),8,session,b"",0,0)
    # Both independent final borrows remain until the fixture's real EOF cleanup.
    for session in (0,1):perform("eof-borrow-"+str(session),1,session,bad,64,2)
    (folder/"controls.json").write_bytes(encoded(rows))
    return rows


def main():
    p=argparse.ArgumentParser()
    for name in("source","setup","build","output"):p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--group",required=True);p.add_argument("--unobserved",action="store_true")
    a=p.parse_args();source=a.source.resolve(strict=True);identity=source_evidence(source)
    require(not a.output.exists(),"fresh native capture output required");a.output.mkdir(parents=True)
    store=Writer(a.output/"buffers");actor=None;rows=[]
    try:
        actor=Carrier(a.build/"binary-read-body-callable.elf",a.output,store)
        if a.unobserved:
            for session in(0,1):
                raw,_=actor.exchange(9,session)
                require(WORD(raw,8)==0 and WORD(raw,24)==0,"unobserved creation failed")
        queries=decode(owned(a.setup,"inputs.json").read_bytes());ids={r["id"]for r in group(a.group)}
        for query in queries:
            if query["id"]not in ids:continue
            row=dict(id=query["id"],input=query,before=snapshot(query["fixture"],store))
            start=time.monotonic_ns();result,chain=actor.run(query)
            row.update(result=result,chain=chain,elapsed_ns=time.monotonic_ns()-start,
                after=snapshot(query["fixture"],store))
            require(row["before"]==row["after"],"read-only native changed file metadata/content")
            rows.append(row);(a.output/"cases.json").write_bytes(canonical(rows))
        private=controls(actor,store,a.output)if a.group=="g00"and not a.unobserved else[]
        process=actor.finish()
        require(not a.unobserved or process["journal"]["raw"]["bytes"]==0,"disabled observer produced journal")
        result=dict(status="NATIVE_BINARY_READ_DOMAIN_COMPLETE",cases=len(rows),group=a.group,source=identity,
            private_controls=len(private),buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
            exchanges=actor.ordinal,native_process=process,observer_enabled=not a.unobserved,
            original_outputs_read=False,runtime_python_required=False,runtime_libc_required=False)
        (a.output/"CAPTURE.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    finally:
        if actor:actor.cleanup()
if __name__=="__main__":main()
