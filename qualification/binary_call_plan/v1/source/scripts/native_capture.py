#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual typed HIA, caller plan and installed config process; never read original outputs."""
from pathlib import Path
import ctypes
import gzip
import hashlib
import json
import os
import struct
import queue
import subprocess
import threading
import time
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import source_evidence,canonical,decode,owned,require
import params_cases
import plan_cases
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
    def __init__(self,qualification,group):
        from hia_native_loader import NativeModule
        self.qualification=qualification
        self.out=qualification/"native"/group["name"]/"plan";self.out.mkdir()
        self.group=group
        self.members=json.loads((qualification/"build/call-plan.json").read_bytes())["members"]
        names=["serde_json_span"]+[row["name"]+"_params" for row in params_cases.schemas()]+["binary_call_plan"]
        self.modules={index+1:NativeModule(qualification/self.members[name]["manifest"],
            manifest_sha256=self.members[name]["manifest_sha256"]) for index,name in enumerate(names)}
        self.stream=gzip.open(self.out/"calls.bin.gz","wb",compresslevel=1)
        self.rows_stream=(self.out/"native-results.jsonl").open("xb")
        self.index=[];self.rows=[];self.controls=[];self.offset=0
        self.artifacts={"build/call-plan.json":pin(qualification/"build/call-plan.json")}
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

    def plan(self,cid,wire,*,before=None,capacity=64,label="plan"):
        before=bytes(512)if before is None else before;calls=[]
        for _ in range(12):
            code,out,after,seq=self.invoke(7,cid,label,wire,before,capacity);calls.append(seq)
            if code==0xffffffd0:
                require(out[:8]==b"HGRWS002"and word(out,24)==0,"caller growth frame")
                which,needed=word(out,8),word(out,16)
                require(out[32:]==b"\xa5"*(capacity-32),"caller growth tail")
                if which==1:
                    require(len(before)<needed<=self.modules[7].metadata["workspace_capacity"],"caller workspace growth")
                    before=after+bytes(needed-len(after))
                else:
                    require(which==2 and capacity<needed<=self.modules[7].metadata["output_capacity"],"caller output growth")
                    before,capacity=after,needed
                continue
            require(64<=code<0xffff0000 and code<=capacity and out[:8]==b"HBPLR001"
                and word(out,56)==code-64 and out[code:]==b"\xa5"*(capacity-code),"caller complete publication")
            return out[:code],calls
        raise ValueError("caller growth did not terminate")
    def semantic(self,root):
        for row in self.group["cases"]:
            cid,kind=row["case_id"],row["kind"];raw=row["raw_json"].encode()
            value,value_calls=self.complete(1,cid,b"HJSMS002"+struct.pack("<2Q",1,len(raw))+raw)
            require(word(value,8)==0,"frozen input must be an admitted JSON object")
            typed,typed_calls=self.complete(kind+1,cid,wire_for(kind,value[32:]))
            stages=[];terminal=None;phase=0;feedback=b""
            if word(typed,8)==0:
                for _ in range(4):
                    wire=b"HBPLQ001"+struct.pack("<5Q",phase,int(row["pool"]),len(typed),len(feedback),0)+typed+feedback
                    plan,calls=self.plan(cid,wire)
                    stage=dict(phase=phase,calls=calls,frame_hex=plan.hex(),config_exchange=None)
                    stages.append(stage)
                    status=word(plan,8)
                    require(word(plan,16)==kind,"caller typed kind differs")
                    if status==2:
                        phase=word(plan,24)
                        feedback,exchange=root.query(plan[64:],cid,phase)
                        stage["config_exchange"]=exchange
                    else:
                        require(status in(1,3),"caller terminal status")
                        terminal=plan;break
                require(terminal is not None,"caller did not terminate")
            result=dict(canonical=value[32:].decode(),typed_ok=word(typed,8)==0,
                typed_frame=typed.hex(),plan_frame=None if terminal is None else terminal.hex())
            self.rows_stream.write(json_bytes(dict(case_id=cid,kind=kind,name=row["name"],result=result)))
            self.rows.append(dict(case_id=cid,kind=kind,name=row["name"],input_sha256=sha(raw),
                value_calls=value_calls,params_calls=typed_calls,stages=stages,
                value_admitted=True,typed_success=result["typed_ok"]))
    def boundary_controls(self):
        # These controls reuse complete actual typed/caller wires, not modeled success values.
        semantic=[entry for entry in self.index if entry["owner"]==7 and entry["label"]=="plan"]
        # The first completed stage input is retained explicitly during invoke below.
        if not self.first_plan:return
        wire,full=self.first_plan
        reference=dict(wire_hex=wire.hex(),frame_hex=full.hex())
        self.controls.append(dict(kind="bound-reference",**reference))
        for cap in(0,1,31,63):
            before=b"\x7b"*512
            code,out,after,call=self.invoke(7,900001,"short-output",wire,before,cap)
            require((code,out,after)==(CAPACITY,b"\xa5"*cap,before),"short caller output mutated")
            self.controls.append(dict(kind="short-output",call=call,output_capacity=cap))
        for cap in(64,max(64,len(full)-1),len(full),len(full)+17):
            code,out,after,call=self.invoke(7,900002,"output-boundary",wire,b"\x7b"*512,cap)
            if cap<len(full):
                require(code==0xffffffd0 and out[:8]==b"HGRWS002"and word(out,8)==2
                    and word(out,16)==len(full)and word(out,24)==0 and out[32:]==b"\xa5"*(cap-32),"caller output growth bound")
            else:require(code==len(full)and out==full+b"\xa5"*(cap-len(full)),"caller output boundary")
            self.controls.append(dict(kind="output-boundary",call=call,output_capacity=cap))
        for size in(0,1,511):
            before=b"\x7b"*size
            code,out,after,call=self.invoke(7,900003,"workspace-growth",wire,before,len(full)+17)
            require(code==0xffffffd0 and out[:8]==b"HGRWS002"and word(out,8)==1
                and word(out,16)==512 and word(out,24)==0 and before==after
                and out[32:]==b"\xa5"*(len(out)-32),"caller workspace bound")
            resumed,calls=self.plan(900003,wire,before=after+bytes(512-size),capacity=len(full),label="growth-resume")
            require(resumed==full,"caller resumed output differs")
            self.controls.append(dict(kind="workspace-growth",call=call,resume_calls=calls,workspace_capacity=size))
        bad=[b"",wire[:47],b"XXXXXXXX"+wire[8:]]
        for at,value in((8,3),(16,2),(24,0),(32,1),(40,1),(48,0),(56,1),(64,0),(200,1)):
            changed=bytearray(wire);struct.pack_into("<Q",changed,at,value);bad.append(bytes(changed))
        for seq,changed in enumerate(bad):
            before=b"\x7b"*512
            code,out,after,call=self.invoke(7,900100+seq,"invalid-frame",changed,before,128)
            require((code,out,after)==(INVALID,b"\xa5"*128,before),"invalid caller frame changed buffers")
            self.controls.append(dict(kind="invalid-frame",call=call,wire_hex=changed.hex()))
        dirty=b"\x7b"*512
        for repeat in range(3):
            code,out,dirty,call=self.invoke(7,900004,"dirty-workspace",wire,dirty,len(full)+7)
            require(code==len(full)and out==full+b"\xa5"*7,"dirty caller workspace result")
            self.controls.append(dict(kind="dirty-workspace",call=call))
    def finish(self,success):
        self.stream.close();self.rows_stream.close()
        for module in self.modules.values():module.close()
        require(self.artifacts=={p:pin(self.qualification/p)for p in self.artifacts},"actual new HIA artifacts changed")
        for name,rows in(("calls.jsonl",self.index),("native-cases.jsonl",self.rows),("controls.jsonl",self.controls)):
            (self.out/name).write_bytes(b"".join(json_bytes(row)for row in rows))
        result=dict(status="PASS"if success else"FAIL",cases=len(self.rows),native_calls=len(self.index),
            controls=len(self.controls),full_record_bytes=self.offset,artifacts=self.artifacts,
            pid=os.getpid(),original_results_read=False,source_inputs=source_evidence(ROOT),
            public_route_replaced=False,remote_body_executed=False)
        (self.out/"capture-result.json").write_bytes(json_bytes(result))
        return result

def plan_reference(rec):
    original=rec.plan
    def invoke(*args,**kwargs):
        frame,calls=original(*args,**kwargs)
        if rec.first_plan is None:rec.first_plan=(args[1],frame)
        return frame,calls
    rec.first_plan=None;rec.plan=invoke

def exact(stream,size):
    data=bytearray()
    while len(data)<size:
        part=stream.read(min(size-len(data),1<<20))
        if not part:raise EOFError("incomplete actual root stream")
        data.extend(part)
    return bytes(data)

class RootSession:
    def __init__(self,q,group):
        self.q=q;self.group=group;self.folder=q/"native"/group["name"]/"root"
        self.folder.mkdir();self.start=time.monotonic();self.deadline=self.start+45
        self.errors=[];self.frames=queue.Queue();self.logical=0;self.digest=hashlib.sha256()
        self.exchanges=[];self.closed=False;self.timed_out=False
        capture=q/"root-reuse/original/restored/run/capture"
        from root_build_reader import original_location
        build=decode((capture/"build/result.json").read_bytes())
        binary=original_location(capture,build["binary"])
        require(pin(binary)["sha256"]==build["binary_sha256"],"admitted config ELF changed")
        command=[str(binary)]
        if group["config"]is not None:
            config=self.folder.parent/"config.json";config.write_bytes(canonical(group["config"]));config.chmod(0o600)
            command+=["--runtime-config",str(config)]
        self.command=command
        self.stdin=(self.folder/"stdin").open("xb")
        self.stderr=(self.folder/"stderr").open("xb")
        rfd,wfd=os.pipe2(os.O_CLOEXEC)
        try:os.fstat(198)
        except OSError:pass
        else:raise ValueError("private observer descriptor occupied")
        os.dup2(wfd,198,inheritable=True);os.close(wfd)
        def drain():
            try:
                with os.fdopen(rfd,"rb")as incoming,gzip.GzipFile(filename=str(self.folder/"calls.bin.gz"),mode="wb",compresslevel=1,mtime=0)as out:
                    while part:=incoming.read(1<<20):
                        out.write(part);self.digest.update(part);self.logical+=len(part)
            except BaseException as error:self.errors.append(repr(error))
        self.drain_thread=threading.Thread(target=drain,daemon=True);self.drain_thread.start()
        try:
            self.child=subprocess.Popen(command,cwd=self.folder.parent,env={"PATH":""},
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr,
                pass_fds=(198,),start_new_session=False,umask=0o22)
        finally:os.close(198)
        def receive():
            try:
                with (self.folder/"stdout").open("xb")as out:
                    while True:
                        first=self.child.stdout.read(1)
                        if not first:break
                        head=first+exact(self.child.stdout,95)
                        require(head[:8]==b"HRGFR002"and word(head,8)==11,"root wire envelope")
                        size=word(head,24);require(size<1<<30,"root output extent")
                        payload=exact(self.child.stdout,size);out.write(head+payload)
                        self.frames.put((head,payload))
            except BaseException as error:self.errors.append(repr(error))
            finally:self.frames.put(None)
        self.read_thread=threading.Thread(target=receive,daemon=True);self.read_thread.start()
    def query(self,wire,cid,phase):
        require(not self.closed and time.monotonic()<self.deadline,"root process budget")
        data=struct.pack("<2Q",11,len(wire))+wire
        self.stdin.write(data);self.stdin.flush()
        self.child.stdin.write(data);self.child.stdin.flush()
        try:row=self.frames.get(timeout=max(.001,self.deadline-time.monotonic()))
        except queue.Empty:
            self.timed_out=True;raise TimeoutError("actual root reply budget")
        require(row is not None,"root exited before reply")
        head,payload=row
        require(word(head,16)==len(payload)and payload[:8]==b"HRCFGM01","actual config query failed")
        exchange=len(self.exchanges)+1
        self.exchanges.append(dict(sequence=exchange,case_id=cid,phase=phase,
            request_hex=wire.hex(),envelope_hex=head.hex(),response_hex=payload.hex()))
        (self.folder/"exchanges.json").write_bytes(canonical(self.exchanges))
        return payload,exchange
    def finish(self,success):
        if self.closed:return
        self.closed=True
        try:
            if self.child.stdin and not self.child.stdin.closed:self.child.stdin.close()
            try:self.child.wait(timeout=max(.001,self.deadline-time.monotonic()))
            except subprocess.TimeoutExpired:self.timed_out=True;self.child.kill();self.child.wait()
        finally:
            if self.child.poll()is None:self.child.kill();self.child.wait()
            self.stdin.close();self.stderr.close()
            self.read_thread.join(timeout=3);self.drain_thread.join(timeout=3)
            from root_state import state_inventory
            state=state_inventory(self.folder.parent/"state")
            (self.folder/"STATE.json").write_bytes(canonical(state))
            (self.folder/"exchanges.json").write_bytes(canonical(self.exchanges))
            process=dict(executable_command=self.command,cwd=str(self.folder.parent),env={"PATH":""},
                pid=self.child.pid,parent_pgid=os.getpgrp(),start_new_session=False,
                uid=os.getuid(),euid=os.geteuid(),gid=os.getgid(),
                exit_code=self.child.returncode,timed_out=self.timed_out,timeout_seconds=45,
                elapsed_seconds=time.monotonic()-self.start,
                original_outputs_read=False,inherited_owned_journal_descriptor=198,
                full_native_buffer_record_bytes=self.logical,
                full_native_buffer_record_sha256=self.digest.hexdigest(),
                streams={name:pin(self.folder/name)for name in("stdin","stdout","stderr","calls.bin.gz")},
                journal_errors=self.errors,exchanges=len(self.exchanges))
            (self.folder/"PROCESS.json").write_bytes(canonical(process))
        require(self.child.returncode==0 and not self.timed_out and not self.errors
            and not self.read_thread.is_alive()and not self.drain_thread.is_alive(),"actual config process did not finish cleanly")
        require(self.frames.get_nowait()is None and self.frames.empty(),"unattributed config responses")
        (self.folder/"RESULT.json").write_bytes(canonical(dict(status="PASS"if success else"FAIL",process=process,state=state)))

def run(qualification,name):
    q=Path(qualification).resolve(strict=True);frozen=source_evidence(ROOT)
    groups=plan_cases.groups(q/"native");selected=[g for g in groups if g["name"]==name]
    require(len(selected)==1,"private group missing");group=selected[0];folder=q/"native"/name
    require(decode((folder/"INPUT.json").read_bytes())==group,"original domain changed")
    rec=Recorder(q,group);plan_reference(rec);root=None;success=False
    try:
        root=RootSession(q,group);rec.semantic(root)
        # One frozen group closes physical private ABI boundaries.
        if name=="operator-00":rec.boundary_controls()
        success=True
    finally:
        try:
            if root is not None:root.finish(success)
        finally:
            result=rec.finish(success)
            (folder/"RESULT.json").write_bytes(canonical(result))
            print(canonical(dict(status="PASS"if success else"FAIL",group=name,
                cases=len(rec.rows),native_calls=len(rec.index),controls=len(rec.controls))).decode(),end="")
    require(source_evidence(ROOT)==frozen,"source changed during native group")
if __name__=="__main__":
    import argparse
    p=argparse.ArgumentParser();p.add_argument("--qualification",required=True);p.add_argument("--group",required=True)
    a=p.parse_args();run(a.qualification,a.group)
