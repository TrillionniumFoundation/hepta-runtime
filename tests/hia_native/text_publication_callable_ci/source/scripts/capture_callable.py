#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Actual fixed callable domain; original requests/filesystem helpers remain unchanged."""
from pathlib import Path
import argparse
import json
import struct
import sys
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from callable_common import encoded,pin,require,sources
from native_carrier import Carrier,WORD

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
    bad=b"HTPBQ001"+struct.pack("<7Q",1,0,1,1,0,6,7)+b"rabsent"
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

def run(source,build,folder,fixture):
    source=Path(source);build=Path(build);folder=Path(folder);fixture=Path(fixture)
    require(not folder.exists(),"fresh capture required");folder.mkdir(parents=True)
    identity=sources(source);body=source/"body-source"
    sys.path.insert(0,str(body/"scripts"))
    from common import canonical,source_evidence
    from body_cases import cases,request,domain
    from body_filesystem import reset,snapshot,retire
    from buffer_store import Writer
    store=Writer(folder/"buffers");actor=None
    rows=(folder/"cases.jsonl").open("xb");wires=(folder/"wire.jsonl").open("xb")
    (folder/"DOMAIN.json").write_bytes(canonical(domain()));start=time.monotonic_ns()
    try:
        actor=Carrier(build/"text-publication-callable.elf",folder,store)
        for case in cases():
            root=fixture/("case-%03d"%case["id"]);reset(root,case)
            row=dict(id=case["id"],name=case["name"],fixture=str(root),request=request(case,root),before=snapshot(root,store))
            began=time.monotonic_ns()
            try:
                result,chain=actor.run(row["request"]);raw=canonical(result)
                row.update(elapsed_ns=time.monotonic_ns()-began,result=result,chain=chain,response=store.put(raw),after=snapshot(root,store))
                require(row["elapsed_ns"]<60_000_000_000,"whole case exceeded original 60 seconds")
                rows.write(canonical(row));rows.flush();wires.write(raw);wires.flush()
            except BaseException as exc:
                row["failure"]=dict(type=type(exc).__name__,message=str(exc));row["after_failure"]=snapshot(root,store)
                (folder/"FAILURE.json").write_bytes(canonical(row));raise
            finally:retire(root,case)
        control_rows=controls(actor,store,folder)
        process=actor.finish()
        result=dict(status="COMPLETE_PRIVATE_BODY_CAPTURE",role="native",cases=len(cases()),source=source_evidence(body),
            callable_source=identity,callable_build=pin(build/"BUILD.json"),elapsed_ns=time.monotonic_ns()-start,
            domain=pin(folder/"DOMAIN.json"),complete_buffer_images=store.images,logical_buffer_bytes=store.logical_bytes,
            exchanges=actor.ordinal,private_controls=len(control_rows),original_output_read_by_native=False,
            scope=dict(private_synchronous_callable=True,public_route=False,configured_path_authority=False,scope_cache_forget=False,async_task_lifecycle=False),
            native_process=process)
        (folder/"capture.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
    finally:
        rows.close();wires.close()
        if actor:actor.cleanup()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","build","output","fixture"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();run(a.source.resolve(strict=True),a.build.resolve(strict=True),a.output.absolute(),a.fixture.absolute())
if __name__=="__main__":main()
