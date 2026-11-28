#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete physical public-evidence controls; no HIA or Rust process is restarted."""
from pathlib import Path
import gzip,os,shutil
from common import canonical,decode,pin,require,sha
from buffer_store import Writer
from read_public import read
NAMES=("missing-record","changed-input","changed-full-buffer","changed-cache-result","changed-scope-lifetime",
    "changed-whole-wire","changed-response-disposition","changed-history-result","changed-file-mode","extra-original-output")
def inventory(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}
def replace(path,raw):
    temp=path.with_name(path.name+".owned-new")
    temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
def resign_process(lane,stdout):
    p=lane/"PROCESS.json";value=decode(p.read_bytes())
    replace(lane/"stdout.gz",gzip.compress(stdout,compresslevel=1,mtime=0))
    value["stdout_gzip"]=pin(lane/"stdout.gz")
    value["full_stdout"]=dict(bytes=len(stdout),sha256=sha(stdout))
    replace(p,canonical(value))
def change_original(lane,field):
    path=lane/"records.jsonl";records=[decode(x) for x in path.read_bytes().splitlines()]
    lines=gzip.decompress((lane/"stdout.gz").read_bytes()).splitlines(keepends=True)
    require(len(lines)==len(records),"complete original baseline lines")
    value=decode(lines[0])
    if field=="cache":
        raw=bytearray.fromhex(value["cache_snapshots_hex"][0]);require(raw,"actual cache image")
        raw[0]^=1;value["cache_snapshots_hex"][0]=bytes(raw).hex()
    elif field=="scope":
        require(value["scope_unbound_after_exchange"] is True,"actual original Scope observation")
        value["scope_unbound_after_exchange"]=False
    elif field=="wire":
        raw=bytes.fromhex(value["output_hex"]);require(raw.endswith(b"\n"),"actual initial response line")
        value["output_hex"]=(raw[:-1]+b" \n").hex()
    else:
        require(field=="history","known physical observer mutation")
        raw=bytearray.fromhex(value["history_snapshot_hex"]);require(raw,"actual history snapshot")
        raw[0]^=1;value["history_snapshot_hex"]=bytes(raw).hex()
    wire=canonical(value);lines[0]=wire
    writer=Writer.__new__(Writer);writer.root=lane/"buffers"
    writer.known={p.stem for p in writer.root.iterdir() if p.is_file()}
    writer.images=0;writer.logical_bytes=0;writer.recent=[]
    records[0]["response"]=writer.put(wire)
    replace(path,b"".join(canonical(x) for x in records));resign_process(lane,b"".join(lines))
def mutate(name,root):
    native=root/"native";original=root/"original"
    path=native/"records.jsonl";lines=path.read_bytes().splitlines(keepends=True)
    if name=="missing-record":replace(path,b"".join(lines[1:]))
    elif name=="changed-input":
        value=decode(lines[0]);value["input"]["id"]+=".modified"
        replace(path,canonical(value)+b"".join(lines[1:]))
    elif name=="changed-full-buffer":
        row=decode(lines[0]);block=native/"buffers"/(row["response"]["blocks"][0]+".gz")
        raw=bytearray(gzip.decompress(block.read_bytes()));raw[0]^=1
        replace(block,gzip.compress(bytes(raw),compresslevel=1,mtime=0))
    elif name in ("changed-cache-result","changed-scope-lifetime","changed-whole-wire","changed-history-result"):
        change_original(original,{"changed-cache-result":"cache","changed-scope-lifetime":"scope",
            "changed-whole-wire":"wire","changed-history-result":"history"}[name])
    elif name=="changed-response-disposition":
        require(len(lines)>1,"actual notification baseline")
        value=decode(lines[1]);require(value["input"]["response"] is False,"actual no-response notification")
        value["input"]["response"]=True;lines[1]=canonical(value);replace(path,b"".join(lines))
    elif name=="changed-file-mode":
        found=False
        for index,line in enumerate(lines):
            value=decode(line)
            for entry in value["after"]:
                if entry["kind"]=="file":
                    entry["stat"]["mode"]^=0o100;lines[index]=canonical(value);found=True;break
            if found:break
        require(found,"actual publisher output regular file");replace(path,b"".join(lines))
    else:
        require(name=="extra-original-output","known mutation")
        resign_process(original,gzip.decompress((original/"stdout.gz").read_bytes())+b"{}\n")
def create(baseline,output):
    baseline,output=Path(baseline),Path(output)
    require(not output.exists(),"fresh controls root");output.mkdir()
    before=inventory(baseline);receipts=[]
    for name in NAMES:
        holder=output/name;root=holder/"capture"
        shutil.copytree(baseline,root,copy_function=os.link)
        require(inventory(root)==before,"complete physical baseline clone")
        mutate(name,root);after=inventory(root)
        changed=sorted(p for p in set(before)|set(after) if before.get(p)!=after.get(p))
        require(changed,"actual physical mutation absent")
        try:read(root)
        except (ValueError,AssertionError) as error:reason=repr(error)
        else:raise ValueError("physical mutation accepted: "+name)
        row=dict(name=name,before=before,after=after,changed=changed,expected_error=reason,
            native_executed=False,rust_executed=False)
        (holder/"CONTROL.json").write_bytes(canonical(row))
        receipts.append(dict(name=name,changed=changed,error=reason))
        require(inventory(baseline)==before,"control changed original evidence bytes")
    (output/"CONTROLS.json").write_bytes(canonical(dict(names=list(NAMES),receipts=receipts)))
    return receipts
def verify(baseline,output):
    baseline,output=Path(baseline),Path(output);before=inventory(baseline)
    summary=decode((output/"CONTROLS.json").read_bytes())
    require(summary["names"]==list(NAMES) and len(summary["receipts"])==len(NAMES),"complete physical control domain")
    result=[]
    for name in NAMES:
        holder=output/name;root=holder/"capture";row=decode((holder/"CONTROL.json").read_bytes())
        require(row["name"]==name and row["before"]==before and row["native_executed"] is False
            and row["rust_executed"] is False,"physical control baseline and scope")
        current=inventory(root)
        require(current==row["after"] and row["changed"]==sorted(p for p in set(before)|set(current)
            if before.get(p)!=current.get(p)),"complete physical changed-byte inventory")
        try:read(root)
        except (ValueError,AssertionError) as error:require(repr(error)==row["expected_error"],"physical control refused elsewhere")
        else:raise ValueError("physical control accepted: "+name)
        result.append(dict(name=name,rejected=True,changed=row["changed"],reason=row["expected_error"]))
    require(summary["receipts"]==[dict(name=x["name"],changed=x["changed"],error=x["reason"]) for x in result],
        "physical receipt does not match retained observations")
    return dict(controls=result,native_executed=False,rust_executed=False)
