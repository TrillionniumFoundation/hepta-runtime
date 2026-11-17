#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical retained-evidence mutations; every baseline byte and delta is checked."""
from pathlib import Path
import gzip
import os
import shutil
import struct
from common import canonical,decode,pin,require,sha
from buffer_store import Reader,Writer
from read_gateway import read
NAMES=("missing-record","changed-input","changed-full-buffer","changed-cache-result","changed-scope-lifetime",
    "truncated-private-trace","unknown-private-trace","changed-forget-return","changed-file-mode","extra-original-output")
def inventory(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}
def replace(path,raw):
    temp=path.with_name(path.name+".owned-new")
    temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
def resign_process(lane,stdout=None,stderr=None):
    p=lane/"PROCESS.json";v=decode(p.read_bytes())
    if stdout is not None:
        replace(lane/"stdout.gz",gzip.compress(stdout,compresslevel=1,mtime=0))
        v["stdout_gzip"]=pin(lane/"stdout.gz")
        v["full_stdout"]=dict(bytes=len(stdout),sha256=sha(stdout))
    if stderr is not None:
        replace(lane/"stderr",stderr);v["stderr"]=pin(lane/"stderr")
    replace(p,canonical(v))
def rewritten_original(lane,field):
    path=lane/"records.jsonl";records=[decode(x) for x in path.read_bytes().splitlines()]
    raw=gzip.decompress((lane/"stdout.gz").read_bytes());lines=raw.splitlines(keepends=True)
    require(len(lines)==len(records),"physical baseline original stream")
    value=decode(lines[0])
    if field=="cache":
        x=bytearray.fromhex(value["cache_snapshots_hex"][0]);require(x,"baseline cache image")
        x[0]^=1;value["cache_snapshots_hex"][0]=bytes(x).hex()
    else:
        require(field=="lifetime" and value["scope_unbound_after_call"] is True,"baseline Scope evidence")
        value["scope_unbound_after_call"]=False
    wire=canonical(value);lines[0]=wire
    # Append full new blocks without rewriting any existing content-addressed
    # block. This clone intentionally retains all old bytes for exact custody.
    writer=Writer.__new__(Writer);writer.root=lane/"buffers"
    writer.known={p.stem for p in writer.root.iterdir() if p.is_file()}
    writer.images=0;writer.logical_bytes=0;writer.recent=[]
    records[0]["response"]=writer.put(wire)
    replace(path,b"".join(canonical(x) for x in records))
    resign_process(lane,stdout=b"".join(lines))
def mutate(name,root):
    native=root/"native";original=root/"original"
    records_path=native/"records.jsonl";raw_rows=records_path.read_bytes().splitlines(keepends=True)
    if name=="missing-record":replace(records_path,b"".join(raw_rows[1:]))
    elif name=="changed-input":
        first=decode(raw_rows[0]);first["input"]["id"]+=".modified"
        replace(records_path,canonical(first)+b"".join(raw_rows[1:]))
    elif name=="changed-full-buffer":
        first=decode(raw_rows[0]);path=native/"buffers"/(first["response"]["blocks"][0]+".gz")
        raw=bytearray(gzip.decompress(path.read_bytes()));raw[0]^=1
        replace(path,gzip.compress(bytes(raw),compresslevel=1,mtime=0))
    elif name in ("changed-cache-result","changed-scope-lifetime"):
        rewritten_original(original,"cache" if name=="changed-cache-result" else "lifetime")
    elif name in ("truncated-private-trace","unknown-private-trace","changed-forget-return"):
        trace=bytearray((native/"stderr").read_bytes())
        if name=="truncated-private-trace":del trace[-1]
        elif name=="unknown-private-trace":trace[:8]=b"HRGTR003"
        else:
            at=0;found=False
            while at<len(trace):
                tag=trace[at:at+8]
                if tag==b"HRGTR002":
                    if struct.unpack_from("<Q",trace,at+16)[0]==68:
                        require(struct.unpack_from("<Q",trace,at+32)[0]==96,"baseline Forget return")
                        struct.pack_into("<Q",trace,at+32,95);found=True;break
                    at+=224
                else:
                    require(tag in (b"HRCNAK02",b"HFLKEYFX",b"HVRDACK1"),"baseline trace tag")
                    at+=128
            require(found,"baseline actual Forget capability missing")
        resign_process(native,stderr=bytes(trace))
    elif name=="changed-file-mode":
        found=False
        for index,line in enumerate(raw_rows):
            row=decode(line)
            for entry in row["after"]:
                if entry["kind"]=="file":
                    entry["stat"]["mode"]^=0o100;raw_rows[index]=canonical(row);found=True;break
            if found:break
        require(found,"baseline regular output file missing")
        replace(records_path,b"".join(raw_rows))
    else:
        require(name=="extra-original-output","unknown mutation")
        resign_process(original,stdout=gzip.decompress((original/"stdout.gz").read_bytes())+b"{}\n")
def create(baseline,output):
    baseline,output=Path(baseline),Path(output)
    require(not output.exists(),"new physical controls root");output.mkdir()
    before=inventory(baseline);receipts=[]
    for name in NAMES:
        holder=output/name;root=holder/"capture"
        shutil.copytree(baseline,root,copy_function=os.link)
        require(inventory(root)==before,"complete physical clone baseline")
        mutate(name,root);after=inventory(root)
        changed=sorted(p for p in set(before)|set(after) if before.get(p)!=after.get(p))
        require(changed,"physical mutation made no change")
        try:read(root)
        except ValueError as error:reason=str(error)
        else:raise ValueError("physical mutation accepted: "+name)
        receipt=dict(name=name,before=before,after=after,changed=changed,expected_error=reason,
            native_executed=False,rust_executed=False)
        (holder/"CONTROL.json").write_bytes(canonical(receipt));receipts.append(dict(name=name,changed=changed,error=reason))
        require(inventory(baseline)==before,"physical controls changed baseline bytes")
    (output/"CONTROLS.json").write_bytes(canonical(dict(names=list(NAMES),receipts=receipts)))
    return receipts
def verify(baseline,output):
    baseline,output=Path(baseline),Path(output);before=inventory(baseline)
    summary=decode((output/"CONTROLS.json").read_bytes())
    require(summary["names"]==list(NAMES) and len(summary["receipts"])==len(NAMES),"full control domain")
    result=[]
    for name in NAMES:
        holder=output/name;root=holder/"capture";row=decode((holder/"CONTROL.json").read_bytes())
        require(row["name"]==name and row["before"]==before and row["native_executed"] is False
            and row["rust_executed"] is False,"control baseline or ownership changed")
        current=inventory(root)
        require(current==row["after"] and row["changed"]==sorted(p for p in set(before)|set(current)
            if before.get(p)!=current.get(p)),"complete actual physical mutation differs")
        try:read(root)
        except ValueError as error:require(str(error)==row["expected_error"],"control refused for another reason")
        else:raise ValueError("physical mutation accepted: "+name)
        result.append(dict(name=name,rejected=True,changed=row["changed"],reason=row["expected_error"]))
    require(summary["receipts"]==[dict(name=x["name"],changed=x["changed"],error=x["reason"]) for x in result],
        "control summary differs from full actual mutation receipts")
    return dict(controls=result,native_executed=False,rust_executed=False)
