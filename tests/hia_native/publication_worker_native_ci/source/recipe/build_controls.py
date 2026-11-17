#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical build-evidence refusals and complete relocated ordinary copies."""
from pathlib import Path
import json,shutil
from common import canonical,decode,pin,require
import readonly
from read_worker_build import verify
def inventory(root):
    root=Path(root)
    return {p.relative_to(root).as_posix():dict(pin(p),mode=p.stat().st_mode&0o777)
            for p in sorted(root.rglob("*")) if p.is_file()}
def refusal(source,root):
    try:verify(source,root)
    except (ValueError,AssertionError,KeyError,IndexError,UnicodeError) as error:
        return dict(rejected=True,type=type(error).__name__,message=str(error))
    raise ValueError("physical mutation unexpectedly accepted")
def source_rows(root):
    return inventory(root)
def create(source,build,output):
    source,build,output=map(Path,(source,build,output))
    require(not output.exists(),"fresh physical control output");output.mkdir()
    original=inventory(build);source_before=source_rows(source);bundle=decode((build/"BUILD.json").read_bytes())
    manifest=build/bundle["members"]["worker"]["manifest"];meta=decode(manifest.read_bytes())
    image=(manifest.parent/meta["image"]).relative_to(build).as_posix()
    specifications=[("actual-worker-image",image,"flip"),("complete-link-workspace","link.workspace.bin","append"),
        ("complete-pack-output","pack.output.bin","flip"),("runtime-image-count","BUILD.json","count")]
    controls=[]
    for name,path,kind in specifications:
        folder=output/name;folder.mkdir();clone=folder/"build";shutil.copytree(build,clone)
        target=clone/path;raw=target.read_bytes()
        if kind=="append":changed=raw+b"\x01"
        elif kind=="flip":
            require(len(raw)>64,"physical mutation has full bytes")
            value=bytearray(raw);value[64]^=1;changed=bytes(value)
        else:
            value=decode(raw);require(value["runtime_images"]==4,"fixed pre-mutation image count")
            value["runtime_images"]=3;changed=canonical(value)
        target.write_bytes(changed)
        proof=readonly.guarded(lambda:refusal(source,clone),roots=(source,clone))
        (folder/"READONLY.json").write_bytes(canonical(proof))
        controls.append(dict(name=name,path=path,kind=kind,before=pin(build/path),after=pin(target),
            exact_changed_offsets=[64] if kind=="flip" else None,rejection=proof["evidence"]))
    relocations=[]
    for number in (1,2):
        folder=output/("relocated-"+str(number));folder.mkdir()
        shutil.copytree(source,folder/"source");shutil.copytree(build,folder/"build")
        proof=readonly.guarded(lambda:verify(folder/"source",folder/"build"),roots=(folder/"source",folder/"build"))
        (folder/"READONLY.json").write_bytes(canonical(proof))
        relocations.append(dict(name=folder.name,evidence=proof["evidence"]))
    require(inventory(build)==original and source_rows(source)==source_before,"control generation changed baseline")
    result=dict(status="WORKER_BUILD_PHYSICAL_CONTROLS_PASS",controls=controls,relocations=relocations,
        application_executions=0,original_inventory=original,source_inventory=source_before)
    (output/"CONTROLS.json").write_bytes(canonical(result))
    return result
def guard_receipt(path,evidence):
    old=decode(Path(path).read_bytes())
    require(old["status"]=="READONLY_PASS" and old["before"]==old["after"]
        and len(old["probes"])==11 and all(x["rejected"] is True for x in old["probes"])
        and old["native_executed"] is old["rust_executed"] is old["evidence_written"] is False
        and old["evidence"]==evidence,"complete prior readonly proof")
def read(source,build,output):
    source,build,output=map(Path,(source,build,output));report=decode((output/"CONTROLS.json").read_bytes())
    require(report["status"]=="WORKER_BUILD_PHYSICAL_CONTROLS_PASS" and report["application_executions"]==0
        and len(report["controls"])==4 and len(report["relocations"])==2,"entire fixed build control domain")
    old=inventory(build);require(old==report["original_inventory"] and source_rows(source)==report["source_inventory"],"baseline complete set")
    expected_names=["actual-worker-image","complete-link-workspace","complete-pack-output","runtime-image-count"]
    require([x["name"] for x in report["controls"]]==expected_names,"fixed physical control names")
    for row in report["controls"]:
        folder=output/row["name"];clone=folder/"build";now=inventory(clone)
        require(set(now)==set(old),"full cloned build file set")
        changes=[key for key in old if old[key]!=now[key]]
        require(changes==[row["path"]] and all(now[k]["mode"]==old[k]["mode"] for k in old),"exact one physical control change")
        target=clone/row["path"];before=(build/row["path"]).read_bytes();after=target.read_bytes()
        require(row["before"]==pin(build/row["path"]) and row["after"]==pin(target),"full physical mutation pins")
        if row["kind"]=="flip":
            expected=bytearray(before);expected[64]^=1
            require(after==bytes(expected) and row["exact_changed_offsets"]==[64],"exact physical image byte")
        elif row["kind"]=="append":require(after==before+b"\x01","exact whole workspace suffix")
        else:
            expected=decode(before);expected["runtime_images"]=3
            require(row["kind"]=="count" and after==canonical(expected),"exact one manifest field")
        evidence=refusal(source,clone);require(evidence==row["rejection"],"same strict reader refusal")
        guard_receipt(folder/"READONLY.json",evidence)
    for number,row in enumerate(report["relocations"],1):
        folder=output/("relocated-"+str(number))
        require(row["name"]==folder.name and inventory(folder/"build")==old
            and source_rows(folder/"source")==report["source_inventory"],"complete physical relocation")
        evidence=verify(folder/"source",folder/"build")
        require(evidence==row["evidence"],"complete relocated build proof")
        guard_receipt(folder/"READONLY.json",evidence)
    require(set(p.name for p in output.iterdir())==set(expected_names)|{"relocated-1","relocated-2","CONTROLS.json"},"complete physical control closure")
    return dict(status="COMPLETE_WORKER_BUILD_CONTROLS_READ_PASS",physical_mutations=4,relocations=2,
        complete_bytes=True,native_executed=False,rust_executed=False)
