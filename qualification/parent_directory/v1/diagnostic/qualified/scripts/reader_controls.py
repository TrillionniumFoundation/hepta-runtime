#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical corruption and whole-capture relocation, with no semantic replay."""
from pathlib import Path
import gzip,hashlib,os,shutil,struct
from common import canonical,decode,pin,require
NAMES=("case-count","module-image","original-result","source-byte","output-tail","resource-evidence",
    "borrowed-parent","mutation-barrier","relocated-one","relocated-two")
def replace(path,raw):
    temp=path.with_name(path.name+".new");temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
def files(root):return {p.relative_to(root).as_posix():p for p in root.rglob("*")if p.is_file()}
def identity(root):return {n:dict(**pin(p),mode=p.stat().st_mode&0o777)for n,p in files(root).items()}
def dirs(root):return {p.relative_to(root).as_posix():p.stat().st_mode&0o777 for p in root.rglob("*")if p.is_dir()}
def create(source,capture,controls):
    import read_all
    from readonly import guarded,snapshot
    source,capture,controls=Path(source),Path(capture),Path(controls)
    require(not controls.exists(),"fresh controls root");controls.mkdir()
    baseline=identity(capture);directory_modes=dirs(capture);mutations={}
    for name in NAMES:
        clone=controls/name;shutil.copytree(capture,clone,copy_function=os.link);changed=[]
        def mutate(path,raw):
            old=pin(path);replace(path,raw)
            changed.append(dict(path=path.relative_to(clone).as_posix(),before=old,after=pin(path)))
        if name=="case-count":
            path=clone/"native/g00/CAPTURE.json";v=decode(path.read_bytes());v["cases"]+=1;mutate(path,canonical(v))
        elif name=="module-image":
            path=clone/"build-reuse/original/restored/run/build/parent-directory-callable.elf"
            v=bytearray(path.read_bytes());v[256]^=1;mutate(path,bytes(v))
        elif name=="original-result":
            path=clone/"original/g00/cases.json";v=decode(path.read_bytes());r=next(r for r in v if r["result"]["ok"])
            r["result"]["name"]+="changed"
            mutate(path,canonical(v))
        elif name=="source-byte":
            path=clone/"source/trusted-build/native/parent_directory.hepta";mutate(path,path.read_bytes()+b"\n")
        elif name=="resource-evidence":
            path=clone/"native/g00/cases.json";v=decode(path.read_bytes());v[0]["held_process"]["fd"]["99"]="unexpected-owned-file"
            mutate(path,canonical(v))
        elif name=="borrowed-parent":
            path=clone/"native/g00/cases.json";v=decode(path.read_bytes());v[0]["result"]["fd"]+=1
            mutate(path,canonical(v))
        elif name=="mutation-barrier":
            path=clone/"native/g05/hooks.json";v=decode(path.read_bytes())
            v["mutations"][0]["after"]["."]["mode"]^=1;mutate(path,canonical(v))
        elif name=="output-tail":
            folder=clone/"native/g00";path=folder/"carrier.journal.gz";old=pin(path);temp=path.with_name(path.name+".new")
            digest=hashlib.sha256();count=0;did=False
            with gzip.open(path,"rb")as src,temp.open("xb")as raw:
                with gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)as dst:
                    while header:=src.read(128):
                        require(len(header)==128,"short mutant journal header")
                        size=struct.unpack_from("<Q",header,32)[0];body=src.read(size);require(len(body)==size,"short mutant journal span")
                        if not did and struct.unpack_from("<Q",header,8)[0]==2:
                            changed_body=bytearray(body);changed_body[-1]^=1;body=bytes(changed_body);did=True
                        for value in(header,body):dst.write(value);digest.update(value);count+=len(value)
            require(did,"missing actual output tail");temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
            changed.append(dict(path=path.relative_to(clone).as_posix(),before=old,after=pin(path)))
            process=decode((folder/"carrier-process.json").read_bytes())
            process["journal"]["raw"]=dict(bytes=count,sha256=digest.hexdigest())
            process["journal"]["compressed"]=pin(path);mutate(folder/"carrier-process.json",canonical(process))
            summary=decode((folder/"CAPTURE.json").read_bytes());summary["process"]=process
            mutate(folder/"CAPTURE.json",canonical(summary))
        mutations[name]=changed
    require(identity(capture)==baseline and dirs(capture)==directory_modes,"physical setup changed original complete bytes/modes/set")
    before=snapshot([capture]);outcomes=[]
    for name in NAMES:
        clone=controls/name
        def operation():
            if name.startswith("relocated"):
                result=read_all.verify(clone/"source",clone)
                return dict(name=name,rejected=False,admitted=True,changes=[],
                    result_status=result["status"],cases=result["comparison"]["native_cases"])
            try:read_all.verify(clone/"source",clone)
            except (ValueError,AssertionError,EOFError)as error:
                return dict(name=name,rejected=True,error_type=type(error).__name__,error=str(error),changes=mutations[name])
            raise RuntimeError("physical mutant admitted: "+name)
        proof=guarded(operation,roots=[source,clone])
        (controls/(name+"-readonly.json")).write_bytes(canonical(proof));outcomes.append(proof["evidence"])
    require(snapshot([capture])==before,"pure controls changed original bytes/metadata")
    result=dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=outcomes,
        complete_original_bytes_modes_set_unchanged=True,setup_hardlinks_before_quiescence=True,
        setup_link_counts_ctimes_not_claimed_unchanged=True,atomic_replacements_only=True,native_or_rust_replay=False)
    (controls/"controls.json").write_bytes(canonical(result));return result
def verify(source,capture,controls):
    import read_all
    capture,controls=Path(capture),Path(controls);report=decode((controls/"controls.json").read_bytes())
    require(report["status"]=="PHYSICAL_READER_CONTROLS_PASS"and report["complete_original_bytes_modes_set_unchanged"]is True
        and report["native_or_rust_replay"]is False and [r["name"]for r in report["controls"]]==list(NAMES),"control report domain")
    actual=identity(capture);directory_modes=dirs(capture);checked=[]
    for row in report["controls"]:
        clone=controls/row["name"];current=identity(clone);changes={v["path"]:v for v in row["changes"]}
        relocated=row["name"].startswith("relocated")
        require(set(current)==set(actual)and dirs(clone)==directory_modes and len(changes)==len(row["changes"])
            and bool(changes)!=relocated,"complete physical variant file/directory set differs")
        for name,old in actual.items():
            new=current[name];require(old["mode"]==new["mode"],"physical variant mode differs")
            if name in changes:
                change=changes[name]
                require(change["before"]=={k:old[k]for k in("bytes","sha256")}
                    and change["after"]=={k:new[k]for k in("bytes","sha256")}and old!=new,"physical mutation identity differs")
            else:require(old==new,"undeclared physical mutation")
        if relocated:
            result=read_all.verify(clone/"source",clone)
            require(result["status"]==row["result_status"]and result["comparison"]["native_cases"]==row["cases"],
                "relocated complete comparison differs")
        else:
            try:read_all.verify(clone/"source",clone)
            except (ValueError,AssertionError,EOFError)as error:
                require(type(error).__name__==row["error_type"]and str(error)==row["error"],"retained refusal differs")
            else:raise ValueError("physical mutant now admitted")
        proof=decode((controls/(row["name"]+"-readonly.json")).read_bytes())
        require(proof["status"]=="READONLY_PASS"and proof["before"]==proof["after"]and proof["evidence"]==row
            and len(proof["probes"])==11 and all(r["rejected"]is True for r in proof["probes"])
            and proof["native_executed"]is False and proof["evidence_written"]is False,"retained control custody differs")
        checked.append(dict(name=row["name"],rejected=not relocated,admitted=relocated,changed_files=len(changes)))
    return dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=checked,full_variant_bytes_modes_directories_checked=True)
