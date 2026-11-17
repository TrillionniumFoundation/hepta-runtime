#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Complete physical evidence variants, prepared before quiescent pure reads."""
from pathlib import Path
import gzip
import os
import shutil
from common import canonical, decode, pin, require, sha

NAMES=("case-count","module-image","original-wire","source-byte","crate-archive","retained-growth",
       "relocated-one","relocated-two")
def replace(path,raw):
    temp=path.with_name(path.name+".new")
    with temp.open("xb") as stream:stream.write(raw)
    temp.chmod(path.stat().st_mode&0o777)
    os.replace(temp,path)
def files(root):
    return {p.relative_to(root).as_posix():p for p in root.rglob("*") if p.is_file()}
def identity(root):
    return {name:{**pin(path),"mode":path.stat().st_mode&0o777} for name,path in files(root).items()}
def create(source,output,controls):
    from run_ci import read_all
    from readonly import guarded,snapshot
    source,output,controls=Path(source),Path(output),Path(controls)
    require(not controls.exists(),"reader controls output must be fresh")
    controls.mkdir(parents=True)
    original=identity(output)
    changes_by_name={}
    for name in NAMES:
        clone=controls/name
        # All links and atomic replacements are prepared before reader snapshots.
        # Source file bytes and modes stay exact; setup link-count/ctime changes
        # are declared and are not represented as quiescent reader activity.
        shutil.copytree(output,clone,copy_function=os.link)
        changed=[]
        def mutate(path,raw):
            before=pin(path);replace(path,raw)
            changed.append(dict(path=path.relative_to(clone).as_posix(),before=before,after=pin(path)))
        if name=="case-count":
            path=clone/"native/capture-result.json"
            value=decode(path.read_bytes());value["cases"]+=1;mutate(path,canonical(value))
        elif name=="module-image":
            path=clone/"build/modules/binary-upload-params/module.image.bin"
            raw=bytearray(path.read_bytes());raw[0]^=1;mutate(path,bytes(raw))
        elif name=="original-wire":
            path=clone/"processes/original.stdout"
            rows=[decode(x) for x in path.read_bytes().splitlines()]
            row=next(x for x in rows if x["result"].get("ok") and x["kind"]==2)
            raw=bytearray.fromhex(row["result"]["frame_hex"]);raw[48]^=1
            row["result"]["frame_hex"]=raw.hex()
            mutate(path,b"".join(canonical(x) for x in rows))
            path=clone/"processes/original.json"
            receipt=decode(path.read_bytes());receipt["streams"]["stdout"]=pin(clone/"processes/original.stdout")
            mutate(path,canonical(receipt))
        elif name=="source-byte":
            path=clone/"source/native/file_info_params.hepta";mutate(path,path.read_bytes()+b"\n")
        elif name=="crate-archive":
            path=sorted((clone/"cargo-home/registry/cache").glob("*/*.crate"))[0]
            raw=bytearray(path.read_bytes());raw[-1]^=1;mutate(path,bytes(raw))
        elif name=="retained-growth":
            index_path=clone/"native/calls.jsonl"
            rows=[decode(x) for x in index_path.read_bytes().splitlines()]
            row=next(x for x in rows if x["owner"]==2 and x["label"]=="semantic" and x["workspace_capacity"]==65536)
            path=clone/"native/calls.bin.gz";before=pin(path)
            temp=path.with_name(path.name+".new")
            with gzip.open(path,"rb") as src,temp.open("xb") as physical:
                with gzip.GzipFile(fileobj=physical,mode="wb",compresslevel=1,mtime=0) as dst:
                    remaining=row["offset"]
                    while remaining:
                        part=src.read(min(1<<20,remaining));require(part,"short retained prefix")
                        dst.write(part);remaining-=len(part)
                    raw=bytearray(src.read(row["bytes"]));require(len(raw)==row["bytes"],"short retained record")
                    at=64+row["input_bytes"]+row["workspace_capacity"]+2*row["output_capacity"]
                    raw[at]^=1
                    row["after_sha256"]=sha(raw[at:at+row["workspace_capacity"]])
                    row["record_sha256"]=sha(raw)
                    dst.write(raw);shutil.copyfileobj(src,dst,length=1<<20)
            temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
            changed.append(dict(path=path.relative_to(clone).as_posix(),before=before,after=pin(path)))
            mutate(index_path,b"".join(canonical(x) for x in rows))
        changes_by_name[name]=changed
    require(identity(output)==original,"physical setup changed original bytes/modes/set")
    before=snapshot([output])
    outcomes=[]
    for name in NAMES:
        clone=controls/name
        def operation():
            if name.startswith("relocated"):
                result=read_all(clone/"source",clone)
                require(result["status"]=="COMPLETE_TYPED_COMPARISON_PASS","relocated complete evidence failed")
                return dict(name=name,rejected=False,admitted=True,changes=[],cases=result["native"]["cases"],
                            native_calls=result["native"]["calls"])
            try:read_all(clone/"source",clone)
            except (ValueError,AssertionError,EOFError) as error:
                return dict(name=name,rejected=True,error_type=type(error).__name__,
                            error=str(error),changes=changes_by_name[name])
            raise RuntimeError("physical evidence control unexpectedly passed: "+name)
        proof=guarded(operation,roots=[source,clone])
        (controls/(name+"-readonly.json")).write_bytes(canonical(proof))
        outcomes.append(proof["evidence"])
    require(before==snapshot([output]),"pure controls changed original bytes/metadata")
    result=dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=outcomes,
        original_capture_bytes_modes_set_unchanged=True,setup_shared_regular_file_links=True,
        setup_link_counts_and_ctimes_not_claimed_unchanged=True,
        all_mutations_by_atomic_replacement=True,all_reader_snapshots_after_setup=True,
        native_executed=False,rust_executed=False)
    (controls/"controls.json").write_bytes(canonical(result))
    return result
def verify(source,output,controls):
    from run_ci import read_all
    source,output,controls=Path(source),Path(output),Path(controls)
    report=decode((controls/"controls.json").read_bytes())
    require(report["status"]=="PHYSICAL_READER_CONTROLS_PASS" and
        [row["name"] for row in report["controls"]]==list(NAMES),"physical reader domain changed")
    require(report["original_capture_bytes_modes_set_unchanged"] is True and
        report["all_mutations_by_atomic_replacement"] is True and report["all_reader_snapshots_after_setup"] is True,
        "physical preparation contract changed")
    original=files(output);actual=[]
    for row in report["controls"]:
        clone=controls/row["name"];cloned=files(clone)
        require(set(original)==set(cloned),"complete physical variant file set changed")
        changes={item["path"]:item for item in row["changes"]}
        relocated=row["name"].startswith("relocated")
        require(len(changes)==len(row["changes"]) and bool(changes)!=relocated,"physical mutation set changed")
        for path,old in original.items():
            before,after=pin(old),pin(cloned[path])
            require((old.stat().st_mode&0o777)==(cloned[path].stat().st_mode&0o777),"physical variant mode changed")
            if path in changes:
                require(changes[path]["before"]==before and changes[path]["after"]==after and before!=after,
                    "physical declared mutation differs from actual retained bytes")
            else:require(before==after,"unlisted physical variant mutation")
        if relocated:
            result=read_all(clone/"source",clone)
            require(result["status"]=="COMPLETE_TYPED_COMPARISON_PASS" and
                result["native"]["cases"]==row["cases"] and result["native"]["calls"]==row["native_calls"],
                "relocated full admission changed")
        else:
            try:read_all(clone/"source",clone)
            except (ValueError,AssertionError,EOFError) as error:
                require(type(error).__name__==row["error_type"] and str(error)==row["error"],
                    "physical variant no longer produces its retained refusal")
            else:raise ValueError("physical variant unexpectedly accepted")
        proof=decode((controls/(row["name"]+"-readonly.json")).read_bytes())
        require(proof["status"]=="READONLY_PASS" and proof["before"]==proof["after"] and len(proof["probes"])==11
            and all(item["rejected"] is True for item in proof["probes"]) and proof["evidence"]==row,
            "physical reader custody proof changed")
        actual.append(dict(name=row["name"],rejected=not relocated,admitted=relocated,changed_files=len(changes)))
    return dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=actual,complete_physical_file_bytes_modes_set_checked=True)
