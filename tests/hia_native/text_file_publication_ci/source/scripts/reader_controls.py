#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Six physical evidence edits, complete clone custody, and zero-execution refusal."""
from pathlib import Path
import gzip
import os
import shutil
from common import canonical,decode,owned,pin,require
from read_body import compare

NAMES=("missing-effect","changed-input","changed-workspace","changed-image","changed-result","extra-original-wire")
ROOTS=("BUILD.json","build","compiler-source","generated","native","original","rust-target/debug/hepta-text-publication-body-original")

def inventory(root):
    return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
        for p in sorted(root.rglob("*")) if p.is_file()}

def replace(path,raw):
    temporary=path.with_name(path.name+".new-owned")
    temporary.write_bytes(raw);temporary.chmod(path.stat().st_mode&0o777)
    os.replace(temporary,path)

def mutate(name,root):
    if name=="missing-effect":
        path=root/"native/effects.jsonl";lines=path.read_bytes().splitlines(keepends=True);new=b"".join(lines[1:])
    elif name=="changed-input":
        path=root/"native/calls.jsonl";lines=path.read_bytes().splitlines(keepends=True)
        first=decode(lines[0]);first["input"]["sha256"]="0"*64;new=canonical(first)+b"".join(lines[1:])
    elif name=="changed-workspace":
        first=decode((root/"native/calls.jsonl").read_bytes().splitlines()[0])
        path=root/"native/buffers"/(first["workspace_after"]["blocks"][0]+".gz")
        raw=bytearray(gzip.decompress(path.read_bytes()));raw[0]^=1
        new=gzip.compress(bytes(raw),compresslevel=1,mtime=0)
    elif name=="changed-image":
        row=decode((root/"BUILD.json").read_bytes())["members"]["text-file-publication"]
        manifest=root/row["manifest"];meta=decode(manifest.read_bytes());path=manifest.parent/meta["image"]
        raw=bytearray(path.read_bytes());raw[0]^=1;new=bytes(raw)
    elif name=="changed-result":
        path=root/"native/cases.jsonl";lines=path.read_bytes().splitlines(keepends=True)
        first=decode(lines[0]);first["result"]["text"]+="!";new=canonical(first)+b"".join(lines[1:])
    else:
        require(name=="extra-original-wire","unknown control")
        path=root/"original/original.stdout";new=path.read_bytes()+b"{}\n"
    old=pin(path);replace(path,new)
    return dict(path=path.relative_to(root).as_posix(),before=old,after=pin(path))

def create(source,output,controls):
    source=Path(source);output=Path(output);controls=Path(controls)
    require(not controls.exists(),"controls must be fresh");controls.mkdir()
    rows=[]
    for name in NAMES:
        holder=controls/name;root=holder/"capture";root.mkdir(parents=True)
        for selected in ROOTS:
            incoming=output/selected;target=root/selected;target.parent.mkdir(parents=True,exist_ok=True)
            if incoming.is_dir():shutil.copytree(incoming,target,copy_function=os.link)
            else:os.link(incoming,target)
        before=inventory(root);change=mutate(name,root);after=inventory(root)
        require(set(before)==set(after),"physical mutation changed file set")
        require({p for p in before if before[p]!=after[p]}=={change["path"]},"control did not change exactly its declared file")
        try:compare(source,root)
        except ValueError as error:failure=str(error)
        else:raise ValueError("mutated evidence accepted: "+name)
        record=dict(name=name,change=change,before=before,after=after,expected_error=failure,
            native_or_rust_executed=False)
        (holder/"CONTROL.json").write_bytes(canonical(record));rows.append(record)
    (controls/"CONTROLS.json").write_bytes(canonical(dict(names=list(NAMES),controls=len(rows))))
    return dict(controls=len(rows))

def verify(source,output,controls):
    source=Path(source);output=Path(output);controls=Path(controls)
    expected=decode(owned(controls,"CONTROLS.json").read_bytes())
    require(expected==dict(names=list(NAMES),controls=len(NAMES)),"physical control set changed")
    rows=[]
    for name in NAMES:
        holder=controls/name;root=holder/"capture"
        record=decode(owned(holder,"CONTROL.json").read_bytes())
        require(record["name"]==name and record["native_or_rust_executed"] is False,"control identity changed")
        current=inventory(root);require(current==record["after"],"control complete clone changed")
        before=record["before"];change=record["change"]
        require(set(before)==set(current) and {p for p in before if before[p]!=current[p]}=={change["path"]},
            "physical mutation scope differs")
        for path,row in before.items():
            raw=owned(output,path)
            require(row==dict(**pin(raw),mode=raw.stat().st_mode&0o777),"control before image differs from retained original")
        require(change["before"]=={k:before[change["path"]][k] for k in ("bytes","sha256")}
            and change["after"]=={k:current[change["path"]][k] for k in ("bytes","sha256")},"changed file identity differs")
        try:compare(source,root)
        except ValueError as error:
            require(str(error)==record["expected_error"],"control was refused for another reason")
        else:raise ValueError("physical mutation accepted: "+name)
        rows.append(dict(name=name,rejected=True,change=change))
    return dict(controls=rows,native_or_rust_executed=False)
