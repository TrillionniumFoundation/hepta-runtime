#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual six-image HIA producer; never reads Rust reference result streams."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import json
import os
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import source_evidence
import params_cases
INVALID,CAPACITY=0xffffffff,0xfffffffe
sha=lambda raw:hashlib.sha256(raw).hexdigest()
word=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
def json_bytes(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"))+"\n").encode()
def pin(path):
    path=Path(path)
    with path.open("rb") as stream:return dict(bytes=path.stat().st_size,sha256=hashlib.file_digest(stream,"sha256").hexdigest())
def wire_for(kind,raw):
    return b"HBPRQ001"+struct.pack("<2Q",len(raw),kind)+raw
class Recorder:
    def __init__(self,qualification):
        from hia_native_loader import NativeModule
        self.qualification=qualification
        self.out=qualification/"native";self.out.mkdir()
        self.members=json.loads((qualification/"build/typed-params.json").read_bytes())["members"]
        names=["serde_json_span"]+[row["name"]+"_params" for row in params_cases.schemas()]
        self.modules={index+1:NativeModule(qualification/self.members[name]["manifest"],
            manifest_sha256=self.members[name]["manifest_sha256"]) for index,name in enumerate(names)}
        self.stream=gzip.open(self.out/"calls.bin.gz","wb",compresslevel=1)
        self.rows_stream=(self.out/"native-results.jsonl").open("xb")
        self.index=[];self.rows=[];self.controls=[];self.offset=0
        self.artifacts={"build/typed-params.json":pin(qualification/"build/typed-params.json")}
        for member in self.members.values():
            path=qualification/member["manifest"];meta=json.loads(path.read_bytes())
            for artifact in (path,path.parent/meta["source"],path.parent/meta["image"]):
                self.artifacts[str(artifact.relative_to(qualification))]=pin(artifact)
    def invoke(self,owner,cid,label,wire,before,capacity):
        with self.modules[owner].session(workspace_capacity=len(before),output_capacity=capacity) as session:
            if before:ctypes.memmove(session._workspace,before,len(before))
            if capacity:ctypes.memset(session._output,0xa5,capacity)
            code,out,after=session.invoke_raw(wire)
        old=b"\xa5"*capacity;index=len(self.index)+1
        header=struct.pack("<8Q",index,owner,cid,code,len(wire),capacity,len(before),0)
        digest=hashlib.sha256();size=0
        for raw in (header,wire,before,old,out,after):
            self.stream.write(raw);digest.update(raw);size+=len(raw)
        self.index.append(dict(call=index,owner=owner,case_id=cid,label=label,offset=self.offset,
            bytes=size,return_code=code,input_bytes=len(wire),output_capacity=capacity,
            workspace_capacity=len(before),record_sha256=digest.hexdigest(),
            input_sha256=sha(wire),before_sha256=sha(before),output_before_sha256=sha(old),
            output_sha256=sha(out),after_sha256=sha(after)))
        self.offset+=size
        return code,out,after,index
    def complete(self,owner,cid,wire,*,before=None,capacity=None,label="semantic"):
        header=32 if owner==1 else 256
        needed_at=24 if owner==1 else 80
        magic=b"HJSVR002" if owner==1 else b"HBPRR001"
        before=bytes(16512 if owner==1 else 65536) if before is None else before
        capacity=header if capacity is None else capacity;calls=[]
        for _ in range(12):
            code,out,after,index=self.invoke(owner,cid,label,wire,before,capacity);calls.append(index)
            assert code==header and out[:8]==magic,(owner,cid,code,out[:256].hex())
            if owner>1:assert word(out,16)==owner-1
            status,needed=word(out,8),word(out,needed_at)
            if status in (2,3):
                assert out[header:]==b"\xa5"*(capacity-header)
                if status==2:
                    assert len(before)<needed<=self.modules[owner].metadata["workspace_capacity"]
                    before=after+bytes(needed-len(after))
                else:
                    assert capacity<needed<=self.modules[owner].metadata["output_capacity"]
                    capacity,before=needed,after
                continue
            assert status in ((0,1,5) if owner==1 else (0,1)) and needed==0,(owner,cid,status)
            size=header+(word(out,16) if owner==1 else
                sum(word(out,at) for at in range(88,152,8)) if status==0 else word(out,72))
            assert size<=capacity and out[size:]==b"\xa5"*(capacity-size)
            return out[:size],calls
        raise AssertionError(("nonterminating capacity negotiation",owner,cid))
    def semantic(self):
        (self.out/"input.jsonl").write_bytes(params_cases.encoded())
        for row in params_cases.cases():
            cid,kind=row["case_id"],row["kind"];raw=row["raw_json"].encode()
            value,value_calls=self.complete(1,cid,b"HJSMS002"+struct.pack("<2Q",1,len(raw))+raw)
            admitted=word(value,8)==0;result=dict(value_admitted=admitted);params_calls=[]
            if admitted:
                canonical=value[32:]
                params,params_calls=self.complete(kind+1,cid,wire_for(kind,canonical))
                result.update(canonical=canonical.decode(),ok=word(params,8)==0,frame_hex=params.hex())
            self.rows_stream.write(json_bytes(dict(case_id=cid,kind=kind,name=row["name"],result=result)))
            self.rows.append(dict(case_id=cid,kind=kind,name=row["name"],input_sha256=sha(raw),
                value_calls=value_calls,params_calls=params_calls,value_admitted=admitted,
                typed_success=result.get("ok",False)))
    def boundary_controls(self):
        for kind in range(1,6):
            owner=kind+1;values=params_cases.control_values(kind)
            for number,raw in enumerate(values):
                cid=100000+kind*10000+number*100;wire=wire_for(kind,raw)
                full,calls=self.complete(owner,cid,wire,label="control-reference")
                self.controls.append(dict(kind="reference",owner=owner,calls=calls,response_sha256=sha(full)))
                for cap in (0,1,255):
                    before=b"\x7b"*(max(len(wire),512)+65536)
                    code,out,after,index=self.invoke(owner,cid+1,"short-output",wire,before,cap)
                    assert (code,out,after)==(CAPACITY,b"\xa5"*cap,before)
                    self.controls.append(dict(kind="short-output",owner=owner,call=index))
                for capacity in (256,len(full)-1,len(full),len(full)+17):
                    code,out,after,index=self.invoke(owner,cid+2,"output-boundary",wire,
                        b"\x7b"*(max(len(wire),512)+65536),capacity)
                    assert code==256
                    if capacity<len(full):
                        assert word(out,8)==3 and word(out,80)==len(full)
                        assert out[256:]==b"\xa5"*(capacity-256)
                    else:assert out==full+b"\xa5"*(capacity-len(full))
                    self.controls.append(dict(kind="output-boundary",owner=owner,call=index,required=len(full)))
                for size in (0,1,max(len(wire),512)+65535):
                    before=b"\x7b"*size
                    code,out,after,index=self.invoke(owner,cid+3,"workspace-growth",wire,before,len(full)+11)
                    assert code==256 and word(out,8)==2 and word(out,80)==max(len(wire),512)+65536
                    assert after==before and out[256:]==b"\xa5"*(len(full)+11-256)
                    resumed,calls=self.complete(owner,cid+4,wire,before=after+bytes(word(out,80)-size),
                        capacity=len(full),label="growth-resume")
                    assert resumed==full
                    self.controls.append(dict(kind="workspace-growth",owner=owner,call=index,resume_calls=calls))
                dirty=b"\x7b"*(max(len(wire),512)+65536)
                for repeat in range(3):
                    code,out,dirty,index=self.invoke(owner,cid+5,"dirty-workspace",wire,dirty,len(full)+7)
                    assert code==256 and out==full+b"\xa5"*7
                    self.controls.append(dict(kind="dirty-workspace",owner=owner,call=index))
            raw=values[0];wire=wire_for(kind,raw)
            invalid=[b"",wire[:7],wire[:24],b"XXXXXXXX"+wire[8:],
                wire[:8]+struct.pack("<Q",len(raw)+1)+wire[16:],
                wire[:16]+struct.pack("<Q",kind%5+1)+wire[24:]]
            for number,bad in enumerate(invalid):
                before=b"\x7b"*40000
                code,out,after,index=self.invoke(owner,100000+kind*10000+2000+number,
                    "invalid-frame",bad,before,256)
                assert (code,out,after)==(INVALID,b"\xa5"*256,before)
                self.controls.append(dict(kind="invalid-frame",owner=owner,call=index))
    def finish(self,success):
        self.stream.close();self.rows_stream.close()
        for module in self.modules.values():module.close()
        assert self.artifacts=={p:pin(self.qualification/p) for p in self.artifacts}
        for name,rows in (("calls.jsonl",self.index),("native-cases.jsonl",self.rows),("controls.jsonl",self.controls)):
            (self.out/name).write_bytes(b"".join(json_bytes(row) for row in rows))
        result=dict(status="PASS" if success else "FAIL",cases=len(self.rows),native_calls=len(self.index),
            controls=len(self.controls),value_admitted=sum(r["value_admitted"] for r in self.rows),
            typed_successes=sum(r["typed_success"] for r in self.rows),full_record_bytes=self.offset,
            artifacts=self.artifacts,pid=os.getpid(),python=sys.executable,original_results_read=False,
            source_inputs=source_evidence(ROOT),origin=dict(source_root=str(ROOT),output=str(self.qualification)),
            original_handler_executed=False,public_route_replaced=False)
        (self.out/"capture-result.json").write_bytes(json_bytes(result))
        print(json.dumps(result),flush=True)
def run(qualification):
    qualification=Path(qualification).resolve(strict=True);frozen=source_evidence(ROOT)
    recorder=Recorder(qualification);success=False
    try:
        recorder.semantic();recorder.boundary_controls();success=True
    finally:recorder.finish(success)
    assert source_evidence(ROOT)==frozen
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--qualification",required=True);a=p.parse_args()
    run(a.qualification)
