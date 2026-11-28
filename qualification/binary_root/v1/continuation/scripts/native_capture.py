#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Capture real installed query processes and complete physical ABI controls."""
from __future__ import annotations
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import canonical,decode,pin,require,sha
import root_cases
PACK=root_cases.PACK
GROW=0xffffffd0
INVALID=0xffffffff
SHORT=0xfffffffe
JOURNAL=198
def word(raw,at):return struct.unpack_from("<Q",raw,at)[0]
def stream_exact(stream,size):
    data=bytearray()
    while len(data)<size:
        piece=stream.read(min(size-len(data),1<<20))
        require(piece,"incomplete actual buffer record")
        data.extend(piece)
    return bytes(data)
def first_state(folder):
    with gzip.open(folder/"calls.bin.gz","rb") as stream:
        head=stream_exact(stream,64);values=struct.unpack("<8Q",head)
        require(head[:8]==b"HBRJQ001" and values[1:4]==(1,0,0) and values[7]==11,"first actual installed owner snapshot")
        wire=stream_exact(stream,values[4])
        output=stream_exact(stream,values[5])
        work=stream_exact(stream,values[6])
    return work,dict(header_hex=head.hex(),input=sha(wire),output=sha(output),workspace=sha(work))
def state_inventory(folder):
    out={}
    if not folder.exists():return out
    for path in [folder,*sorted(folder.rglob("*"))]:
        st=path.lstat();require(stat.S_ISREG(st.st_mode)or stat.S_ISDIR(st.st_mode),"native state entry kind")
        row=dict(mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid,nlink=st.st_nlink,kind="file"if stat.S_ISREG(st.st_mode)else"directory")
        if stat.S_ISREG(st.st_mode):row.update(pin(path))
        out["."if path==folder else path.relative_to(folder).as_posix()]=row
    return out
def actual_group(q,name):
    groups=root_cases.materialized(q/"native")
    selected=[g for g in groups if g["name"]==name]
    require(len(selected)==1,"frozen group missing")
    group=selected[0];folder=q/"native"/name
    require(decode((folder/"INPUT.json").read_bytes())==group,"frozen actual input differs")
    require({p.name for p in folder.iterdir()}=={"INPUT.json"},"native group is not fresh")
    build=decode((q/"build/result.json").read_bytes());binary=Path(build["binary"])
    require(pin(binary)["sha256"]==build["binary_sha256"],"actual native executable changed")
    command=[str(binary)]
    if group["config"]is not None:
        path=folder/"config.json";path.write_bytes(canonical(group["config"]));path.chmod(0o600)
        command+=["--runtime-config",str(path)]
    pairs=[(x["name"],root_cases.frame(x))for x in group["queries"]]
    controls=root_cases.controls()if name=="operator"else[]
    pairs+=controls
    wire=b"".join(PACK(11,len(frame))+frame for _,frame in pairs)
    (folder/"stdin").write_bytes(wire)
    argv=["/usr/bin/strace","-qq","-f","-s","0","-xx","-o",str(folder/"kernel.trace"),
        "-e","trace=mmap,mremap,munmap,openat,close,flock,mkdirat,chmod,fchmod,newfstatat,readlink,readlinkat",*command]
    begin=time.monotonic();timed=False;code=None;child=None
    errors=[];logical=[0];digest=hashlib.sha256()
    rfd,wfd=os.pipe2(os.O_CLOEXEC)
    try:
        try:os.fstat(JOURNAL)
        except OSError:pass
        else:raise ValueError("private journal descriptor is already occupied")
        os.dup2(wfd,JOURNAL,inheritable=True);os.close(wfd);wfd=None
        def drain():
            try:
                with os.fdopen(rfd,"rb")as incoming,gzip.GzipFile(filename=str(folder/"calls.bin.gz"),mode="wb",compresslevel=1,mtime=0)as target:
                    while True:
                        part=incoming.read(1<<20)
                        if not part:break
                        target.write(part);digest.update(part);logical[0]+=len(part)
            except BaseException as error:errors.append(repr(error))
        thread=threading.Thread(target=drain,daemon=True);thread.start()
        with (folder/"stdin").open("rb")as inp,(folder/"stdout").open("xb")as out,(folder/"stderr").open("xb")as err:
            child=subprocess.Popen(argv,cwd=folder,env={"PATH":""},stdin=inp,stdout=out,stderr=err,
                pass_fds=(JOURNAL,),start_new_session=True,umask=0o22)
            os.close(JOURNAL)
            try:code=child.wait(timeout=45)
            except subprocess.TimeoutExpired:
                timed=True;os.killpg(child.pid,signal.SIGKILL);code=child.wait()
        thread.join(timeout=5)
        require(not thread.is_alive()and not errors,"complete journal drain failed: "+repr(errors))
    finally:
        if child is not None and child.poll()is None:
            os.killpg(child.pid,signal.SIGKILL);code=child.wait()
        try:os.close(JOURNAL)
        except OSError:pass
        if wfd is not None:os.close(wfd)
        streams={name:pin(folder/name)for name in("stdin","stdout","stderr","kernel.trace","calls.bin.gz")if(folder/name).is_file()}
        row=dict(argv=argv,executable_command=command,cwd=str(folder),env={"PATH":""},
            pid=child.pid if child else None,uid=os.getuid(),euid=os.geteuid(),gid=os.getgid(),exit_code=code,timed_out=timed,
            timeout_seconds=45,elapsed_seconds=time.monotonic()-begin,streams=streams,
            full_native_buffer_record_bytes=logical[0],full_native_buffer_record_sha256=digest.hexdigest(),
            semantic_queries=len(group["queries"]),private_wire_controls=len(controls),
            inherited_owned_journal_descriptor=JOURNAL,original_outputs_read=False)
        (folder/"PROCESS.json").write_bytes(canonical(row))
    require(code==0 and not timed,"actual installed native process failed")
    state=state_inventory(folder/"state");(folder/"STATE.json").write_bytes(canonical(state))
    (folder/"RESULT.json").write_bytes(canonical(dict(status="PASS",process=row,state=state)))
    print(json.dumps(dict(status="PASS",group=name,semantic_queries=len(group["queries"]),
        private_wire_controls=len(controls),full_native_buffer_record_bytes=logical[0]),sort_keys=True))
def control_specs():
    valid=root_cases.frame(root_cases.query("control","h","/data"))
    short=valid[:23]
    changed=bytearray(valid);changed[0]^=1
    out=[]
    for name,cap in (("out-zero",0),("out-thirty-one",31),("out-header",32),("out-one-short",36),("out-exact",37),("out-spare",64)):
        out.append(dict(name=name,wire=valid,output=cap,workspace=None))
    for name,cap in(("work-zero",0),("work-small",4096)):
        out.append(dict(name=name,wire=valid,output=64,workspace=cap))
    out.append(dict(name="bad-magic",wire=bytes(changed),output=64,workspace=None))
    out.append(dict(name="short-input",wire=short,output=64,workspace=None))
    for name,wire in root_cases.controls()[:4]:
        out.append(dict(name="owner-"+name,wire=wire,output=64,workspace=None))
    require(len(out)==14,"physical ABI control set changed")
    return out
class Borrow:
    def __init__(self,raw,capacity):
        self.capacity=capacity;self.array=ctypes.create_string_buffer(capacity+32);self.pointer=ctypes.addressof(self.array)+16
        ctypes.memset(ctypes.addressof(self.array),0xa5,16)
        ctypes.memset(self.pointer+capacity,0x5a,16)
        require(len(raw)<=capacity,"borrow initial extent")
        if raw:ctypes.memmove(self.pointer,bytes(raw),len(raw))
    def bytes(self):return ctypes.string_at(self.pointer,self.capacity)
    def guards(self):
        require(ctypes.string_at(self.pointer-16,16)==b"\xa5"*16 and ctypes.string_at(self.pointer+self.capacity,16)==b"\x5a"*16,"native control crossed physical capacity")
def actual_controls(q):
    folder=q/"controls";folder.mkdir(mode=0o700)
    state,origin=first_state(q/"native/operator")
    (folder/"installed-owner.bin").write_bytes(state)
    (folder/"SEED.json").write_bytes(canonical(dict(origin=origin,snapshot=pin(folder/"installed-owner.bin"),
        source="native/operator/calls.bin.gz",synthetic_installed_arena=False)))
    built=decode((q/"build/result.json").read_bytes())
    owner=next(r for r in built["members"]if r["name"]=="config-owner")
    from hia_native_loader import NativeModule
    entries=[];logical=0
    with NativeModule(Path(owner["manifest"]),manifest_sha256=owner["manifest_sha256"])as module,gzip.GzipFile(
        filename=str(folder/"calls.bin.gz"),mode="wb",compresslevel=1,mtime=0)as stream:
        for seq,spec in enumerate(control_specs(),1):
            size=len(state)if spec["workspace"]is None else spec["workspace"]
            work=bytearray(state[:size])
            if size>=256:struct.pack_into("<Q",work,size-136,1)
            incoming=Borrow(spec["wire"],len(spec["wire"]));out=Borrow(b"\xcc"*spec["output"],spec["output"]);workspace=Borrow(work,size)
            before=(incoming.bytes(),out.bytes(),workspace.bytes())
            head=b"HBRJQ001"+PACK(seq,0,0,len(before[0]),len(before[1]),len(before[2]),11)
            record=head+b"".join(before);stream.write(record);logical+=len(record)
            (folder/"PROGRESS.json").write_bytes(canonical(dict(next_control=spec["name"],sequence=seq,phase="before_actual_native_entry")))
            code=module._entry(incoming.pointer,len(spec["wire"]),out.pointer,spec["output"],workspace.pointer,size)
            incoming.guards();out.guards();workspace.guards()
            after=(incoming.bytes(),out.bytes(),workspace.bytes())
            require(before[0]==after[0],"native input changed")
            head=b"HBRJQ001"+PACK(seq,1,code,len(after[0]),len(after[1]),len(after[2]),11)
            record=head+b"".join(after);stream.write(record);logical+=len(record)
            entries.append(dict(name=spec["name"],sequence=seq,code=code,input=sha(spec["wire"]),
                output_capacity=spec["output"],workspace_capacity=size,physical_guards=True))
            (folder/"CONTROLS.json").write_bytes(canonical(entries))
    result=dict(status="PASS",native_calls=len(entries),complete_buffer_record_bytes=logical,
        original_outputs_read=False,synthetic_installed_arena=False,source=owner,journal=pin(folder/"calls.bin.gz"))
    (folder/"RESULT.json").write_bytes(canonical(result));print(json.dumps(result,sort_keys=True))
def main():
    p=argparse.ArgumentParser();p.add_argument("--qualification",required=True,type=Path);p.add_argument("--group");p.add_argument("--controls",action="store_true")
    a=p.parse_args();q=a.qualification.resolve(strict=True)
    require(bool(a.group)!=a.controls,"select one capture domain")
    if a.controls:actual_controls(q)
    else:actual_group(q,a.group)
if __name__=="__main__":main()
