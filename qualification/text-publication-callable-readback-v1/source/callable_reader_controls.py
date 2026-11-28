#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical retained-evidence changes, including two consistently resigned journal edits."""
from pathlib import Path
import gzip
import hashlib
import os
import shutil
import struct
from callable_common import decode,encoded,owned,pin,require
from read_callable_all import read_all
NAMES=("changed-image","extra-original-wire","changed-context-buffer","changed-control",
    "resigned-journal-tail","resigned-journal-sequence")

def inventory(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}

def replace(path,raw):
    temp=path.with_name(path.name+".owned-new")
    temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)

def journal_mutation(root,name):
    native=root/"body/native";path=native/"carrier.journal.gz";temp=path.with_name("carrier.journal.new.gz")
    position=0;changed=None;digest=hashlib.sha256()
    with gzip.open(path,"rb") as stream,temp.open("xb") as file:
        with gzip.GzipFile(filename="",mode="wb",fileobj=file,mtime=0,compresslevel=1) as target:
            while True:
                head=stream.read(128)
                if not head:break
                require(len(head)==128 and head[:8]==b"HTPCJR01","source journal malformed")
                event,size=struct.unpack_from("<Q",head,8)[0],struct.unpack_from("<Q",head,32)[0]
                body=stream.read(size);require(len(body)==size,"source journal truncated")
                raw=bytearray(head+body)
                at=None
                if changed is None and name=="resigned-journal-tail" and event==2 and size>=64:
                    at=len(raw)-1;require(raw[at]==0xa5,"selected body output has no unchanged suffix")
                if changed is None and name=="resigned-journal-sequence" and event==9:at=96
                if at is not None:
                    before=raw[at];raw[at]^=1
                    changed=dict(offset=position+at,before=before,after=raw[at],event=event)
                target.write(raw);digest.update(raw);position+=len(raw)
    require(changed is not None,"journal mutation target absent")
    temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
    process=decode((native/"carrier-process.json").read_bytes())
    process["journal"]["compressed"]=pin(path);process["journal"]["raw"]=dict(bytes=position,sha256=digest.hexdigest())
    replace(native/"carrier-process.json",encoded(process))
    capture=decode((native/"capture.json").read_bytes());capture["native_process"]=process
    replace(native/"capture.json",encoded(capture))
    stdout=root/"body/processes/native.stdout";replace(stdout,encoded(capture))
    receipt_path=root/"body/processes/native.json";receipt=decode(receipt_path.read_bytes())
    receipt["streams"]["stdout"]=pin(stdout);replace(receipt_path,encoded(receipt))
    return changed

def mutate(name,root):
    if name.startswith("resigned-journal-"):return journal_mutation(root,name)
    if name=="changed-image":
        build=decode((root/"native-build/BUILD.json").read_bytes())
        manifest=root/"native-build"/build["members"]["publication"]["manifest"]
        item=decode(manifest.read_bytes());path=manifest.parent/item["image"]
        value=bytearray(path.read_bytes());value[0]^=1;raw=bytes(value)
    elif name=="extra-original-wire":
        path=root/"body/original/original.stdout";raw=path.read_bytes()+b"{}\n"
    elif name=="changed-context-buffer":
        first=decode((root/"body/native/cases.jsonl").read_bytes().splitlines()[0])
        key=first["chain"]["snapshots"]["context"]["bytes"]["blocks"][0]
        path=root/"body/native/buffers"/(key+".gz")
        value=bytearray(gzip.decompress(path.read_bytes()));value[-1]^=1
        raw=gzip.compress(bytes(value),mtime=0,compresslevel=1)
    else:
        require(name=="changed-control","unknown physical control")
        path=root/"body/native/controls.json";value=decode(path.read_bytes());value[0]["expected_code"]^=1;raw=encoded(value)
    replace(path,raw);return None

def rejection(root):
    try:read_all(root)
    except ValueError as error:return str(error)
    raise ValueError("physical evidence mutation was accepted")

def create(capture,controls):
    capture,controls=Path(capture),Path(controls)
    require(not controls.exists(),"fresh physical controls required");controls.mkdir()
    baseline=inventory(capture);rows=[]
    for name in NAMES:
        holder=controls/name;holder.mkdir();root=holder/"capture"
        shutil.copytree(capture,root,copy_function=shutil.copy2)
        require(inventory(root)==baseline,"complete physical clone does not match retained capture")
        byte_change=mutate(name,root);current=inventory(root)
        changed=[p for p in baseline if baseline[p]!=current.get(p)]
        require(set(current)==set(baseline) and len(changed)==(5 if name.startswith("resigned-journal-") else 1),
            "physical edit scope differs")
        record=dict(name=name,changes=changed,before={p:baseline[p] for p in changed},after={p:current[p] for p in changed},
            complete_before=baseline,complete_after=current,journal_byte_change=byte_change,
            expected_error=rejection(root),native_or_rust_executed=False)
        (holder/"CONTROL.json").write_bytes(encoded(record));rows.append(dict(name=name,rejected=True))
    (controls/"CONTROLS.json").write_bytes(encoded(dict(names=list(NAMES),controls=len(rows))))
    return rows

def journal_difference(original,changed,expected):
    offset=0;differences=[]
    with gzip.open(original,"rb") as a,gzip.open(changed,"rb") as b:
        while True:
            left,right=a.read(1<<20),b.read(1<<20)
            require(len(left)==len(right),"resigned journal length differs")
            if not left:break
            if left!=right:
                differences.extend((offset+i,x,y) for i,(x,y) in enumerate(zip(left,right)) if x!=y)
                require(len(differences)<=1,"journal changed more than its single declared byte")
            offset+=len(left)
    require(differences==[(expected["offset"],expected["before"],expected["after"])]
        and expected["after"]==expected["before"]^1,"actual resigned journal mutation differs")
    return offset

def verify(capture,controls):
    capture,controls=Path(capture),Path(controls);baseline=inventory(capture)
    require(decode(owned(controls,"CONTROLS.json").read_bytes())==dict(names=list(NAMES),controls=len(NAMES)),
        "physical controls omitted/reordered")
    results=[]
    for name in NAMES:
        holder=controls/name;root=holder/"capture";record=decode(owned(holder,"CONTROL.json").read_bytes())
        require(record["name"]==name and record["native_or_rust_executed"] is False
            and record["complete_before"]==baseline,"control original byte custody differs")
        current=inventory(root);require(current==record["complete_after"] and set(current)==set(baseline),"complete physical clone changed")
        changed=[p for p in baseline if baseline[p]!=current[p]]
        require(changed==record["changes"] and len(changed)==(5 if name.startswith("resigned-journal-") else 1)
            and record["before"]=={p:baseline[p] for p in changed} and record["after"]=={p:current[p] for p in changed},
            "physical evidence mutation changed undeclared bytes/files")
        if name.startswith("resigned-journal-"):
            journal_difference(capture/"body/native/carrier.journal.gz",root/"body/native/carrier.journal.gz",record["journal_byte_change"])
        else:require(record["journal_byte_change"] is None,"unexpected journal mutation")
        require(rejection(root)==record["expected_error"],"physical control rejected for another reason")
        results.append(dict(name=name,rejected=True,changes=changed,expected_error=record["expected_error"],
            journal_byte_change=record["journal_byte_change"]))
    return dict(controls=results,native_or_rust_executed=False)
