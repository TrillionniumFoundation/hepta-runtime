#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Execute the fixed owned gateway domain with complete per-call observations."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import select
import shutil
import signal
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import canonical,decode,require,sha,pin
from buffer_store import Writer
from body_filesystem import snapshot,reset
from body_cases import cases as body_cases
from input_domain import PROFILES,rows,declaration
from helper_source import prepare
Q=lambda *v:struct.pack("<"+"Q"*len(v),*v)
U=lambda raw,at:struct.unpack_from("<Q",raw,at)[0]
ACTIVE_FIXTURE=None
ACTIVE_OUTPUT=None

class Process:
    def __init__(self,command,cwd,root,fence):
        self.root=root;self.started=time.monotonic();self.pending=b"";self.closed=False
        env={k:v for k,v in os.environ.items() if not k.startswith("HEPTA_EFFECT_OWNER_")}
        if fence:env["HEPTA_EFFECT_OWNER_FENCE_REQUIRED"]="1"
        self.stderr=(root/"stderr").open("xb")
        self.stdin=(root/"stdin").open("xb");self.stdout=(root/"stdout.gz").open("xb")
        self.gz=gzip.GzipFile(fileobj=self.stdout,mode="wb",compresslevel=1,mtime=0,filename="")
        self.command=list(map(str,command));self.cwd=str(cwd)
        self.p=subprocess.Popen(self.command,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.stderr,start_new_session=True,bufsize=0)
        os.set_blocking(self.p.stdin.fileno(),False);os.set_blocking(self.p.stdout.fileno(),False)
        self.total_out=0;self.out_hash=hashlib.sha256();self.timed=False
    def remaining(self,deadline):
        left=min(deadline,self.started+180)-time.monotonic()
        if left<=0:self.timed=True;raise TimeoutError("unchanged 60-second exchange / 180-second process bound")
        return left
    def send(self,raw,deadline):
        self.stdin.write(raw);self.stdin.flush();at=0
        while at<len(raw):
            _,ready,_=select.select([], [self.p.stdin],[],self.remaining(deadline))
            require(ready,"stdin deadline")
            count=os.write(self.p.stdin.fileno(),raw[at:])
            require(count>0,"short stdin write");at+=count
    def more(self,deadline):
        ready,_,_=select.select([self.p.stdout],[],[],self.remaining(deadline))
        require(ready,"stdout deadline")
        raw=os.read(self.p.stdout.fileno(),1<<20)
        if raw:self.gz.write(raw);self.total_out+=len(raw);self.out_hash.update(raw);self.pending+=raw
        return bool(raw)
    def take(self,count,deadline):
        while len(self.pending)<count:require(self.more(deadline),"native stdout ended before complete frame")
        raw,self.pending=self.pending[:count],self.pending[count:];return raw
    def frame(self,deadline):
        head=self.take(104,deadline);require(head[:8]==b"HFSFXR02","native carrier magic")
        length=U(head,32);require(length<=256<<20,"native response exceeds declared owned graph capacity")
        return head+self.take(length,deadline)
    def line(self,deadline):
        while b"\n" not in self.pending:require(self.more(deadline),"original stdout ended before complete line")
        count=self.pending.index(b"\n")+1
        raw,self.pending=self.pending[:count],self.pending[count:];return raw
    def finish(self,success):
        if self.closed:return
        self.closed=True;failure=None
        try:
            self.p.stdin.close()
            if success:
                require(not self.pending,"extra process output")
                while self.more(self.started+180):
                    require(not self.pending,"unexpected output at EOF")
                self.p.wait(timeout=self.remaining(self.started+180))
                require(self.p.returncode==0,"process nonzero at EOF")
        except BaseException as exc:failure=exc
        finally:
            if self.p.poll() is None:
                os.killpg(self.p.pid,signal.SIGKILL);self.p.wait()
            os.set_blocking(self.p.stdout.fileno(),True)
            while remaining := os.read(self.p.stdout.fileno(),1<<20):
                self.gz.write(remaining);self.total_out+=len(remaining);self.out_hash.update(remaining)
            self.p.stdout.close();self.stdin.close();self.gz.close();self.stdout.close();self.stderr.close()
            receipt=dict(command=self.command,cwd=self.cwd,pid=self.p.pid,exit_code=self.p.returncode,
                timed_out=self.timed,elapsed_seconds=time.monotonic()-self.started,timeout_seconds=180,
                exchange_limit_seconds=60,expected_success=success,cleanup_error=repr(failure) if failure else None,
                stdin=pin(self.root/"stdin"),stdout_gzip=pin(self.root/"stdout.gz"),stderr=pin(self.root/"stderr"),
                full_stdout=dict(bytes=self.total_out,sha256=self.out_hash.hexdigest()))
            (self.root/"PROCESS.json").write_bytes(canonical(receipt))
        if failure:raise failure

def setup(root,profile):
    require(root.name=="fixtures-root","fixture root name")
    if root.exists():shutil.rmtree(root)
    root.mkdir(parents=True);(root/"session-a").mkdir();(root/"session-b").mkdir()
    if profile=="body":
        for case in body_cases():reset(root/"fixtures"/("case-%03d"%case["id"]),case)

def main():
    global ACTIVE_FIXTURE,ACTIVE_OUTPUT
    p=argparse.ArgumentParser()
    for name in ("dependencies","original-build","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    a=p.parse_args();require(os.environ.get("GITHUB_ACTIONS")=="true","execution is restricted to CI")
    require(not a.output.exists(),"new capture output required");a.output.mkdir(parents=True)
    deps=decode(a.dependencies.read_bytes());original=decode((a.original_build/"BUILD.json").read_bytes())
    source=Path(deps["source"]);native=Path(deps["binary"]);original_binary=Path(original["binary"])
    require(pin(native)==dict(bytes=deps["binary_bytes"],sha256=deps["binary_sha256"]),"native binary changed")
    require(pin(original_binary)==dict(bytes=original["bytes"],sha256=original["sha256"]),"original binary changed")
    root=a.output/"fixtures-root";ACTIVE_FIXTURE=root;ACTIVE_OUTPUT=a.output
    setup(root,a.profile)
    defined=rows(a.profile,root)
    (a.output/"DOMAIN.json").write_bytes(canonical(declaration()))
    (a.output/"cases.jsonl").write_bytes(b"".join(canonical(r) for r in defined))
    config=a.output/"config.json"
    configured=a.profile!="absent"
    if configured:
        config.write_bytes(canonical(dict(state_dir=str(a.output/"controller-state"),
            controller_workspace_roots=[] if a.profile=="denied" else [str(root)],hosts={})))
        config.chmod(0o600)
    legacy=prepare(Path(__file__).resolve().parents[1]/"retained/text75_qualify.py")
    legacy.SOURCE=source;legacy.OUT=a.output
    members=a.output/"typed-member-paths.json"
    members.write_bytes(canonical(dict(serde_json_span=deps["serde_json_span"])))
    legacy.MEMBERS=members
    typed=legacy.TypedInput()
    wires=[]
    try:
        for row in defined:
            if row["kind"]=="call":
                wire=typed.request(row)
                if row["tool"]=="text_file_write":wire=b"HTPWGQ03"+wire[8:];slot=64
                else:slot=37
            else:wire=bytes.fromhex(row["wire_hex"]);slot=32
            frames=[b"HFSFXQ02"+Q(row["session"],slot,len(wire))+wire]
            frames.extend(b"HFSFXQ02"+Q(sid,33,0) for sid in (0,1))
            frames.append(b"HFSFXQ02"+Q(0,41,0));wires.append(b"".join(frames))
    finally:typed.close()
    capture_reports=[]
    for role,binary in (("native",native),("original",original_binary)):
        if role=="original":setup(root,a.profile)
        lane=a.output/role;lane.mkdir()
        buffers=Writer(lane/"buffers")
        command=[binary]+((["--runtime-config",config] if role=="native" else [config]) if configured else [])
        proc=Process(command,root,lane,a.profile=="fence_required")
        ok=False;completed=0
        try:
            with (lane/"records.jsonl").open("xb") as records:
                for i,row in enumerate(defined):
                    start=time.monotonic();deadline=start+60
                    observed=root/row["fixture"]
                    before=snapshot(observed,buffers)
                    wire=wires[i] if role=="native" else canonical(row)
                    proc.send(wire,deadline)
                    if role=="native":response=b"".join(proc.frame(deadline) for _ in range(4))
                    else:response=proc.line(deadline)
                    after=snapshot(observed,buffers)
                    record=dict(index=i,input=row,request=buffers.put(wire),response=buffers.put(response),
                        fixture=str(observed),before=before,after=after,
                        elapsed_ns=int((time.monotonic()-start)*1_000_000_000))
                    records.write(canonical(record));records.flush();completed+=1
                    require(time.monotonic()<deadline and time.monotonic()<proc.started+180,"capture exceeded frozen deadline")
            ok=True
        finally:
            try:proc.finish(ok)
            finally:
                result=dict(role=role,profile=a.profile,completed=completed,total=len(defined),capture_completed=ok,
                    source_dependencies=deps,original_binary=pin(original_binary),native_binary=pin(native),
                    complete_buffers=buffers.images,logical_buffer_bytes=buffers.logical_bytes,
                    per_exchange_seconds=60,per_process_seconds=180,public_route=False,async_lifecycle=False)
                (lane/"CAPTURE.json").write_bytes(canonical(result));capture_reports.append(result)
        require(ok,"capture did not complete")
    (a.output/"CAPTURE.json").write_bytes(canonical(dict(status="COMPLETE_GATEWAY_CAPTURE_ONLY",
        profile=a.profile,cases=len(defined),roles=capture_reports,semantic_comparison=False)))
    print(json.dumps(dict(status="COMPLETE_GATEWAY_CAPTURE_ONLY",profile=a.profile,cases=len(defined)),sort_keys=True))
if __name__=="__main__":
    try:
        main()
    finally:
        if ACTIVE_FIXTURE is not None and ACTIVE_FIXTURE.exists():
            require(ACTIVE_FIXTURE.parent==ACTIVE_OUTPUT and ACTIVE_FIXTURE.name=="fixtures-root",
                "only the newly owned fixture tree may be retired")
            retained=Writer(ACTIVE_OUTPUT/"retired-fixture-buffers")
            final=snapshot(ACTIVE_FIXTURE,retained)
            (ACTIVE_OUTPUT/"RETIRED_FIXTURE.json").write_bytes(canonical(dict(
                root=str(ACTIVE_FIXTURE),complete_snapshot=final,
                captured_before_retirement=True,case_buffers_preserved=True)))
            shutil.rmtree(ACTIVE_FIXTURE)

