#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Eight actual physical refusals, five honest stream reseals, two full relocations."""
from pathlib import Path
import gzip,hashlib,os,shutil,struct
from common import canonical,decode,pin,require
NAMES=("case-count","module-image","source-byte","original-diagnostic","actual-stdin",
    "body-output-tail","formatter-output-tail","formatter-work-tail","relocated-one","relocated-two")
def replace(path,raw):
    temp=path.with_name(path.name+".new");temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
def files(root):return {p.relative_to(root).as_posix():p for p in root.rglob("*")if p.is_file()}
def identity(root):return {n:dict(**pin(p),mode=p.stat().st_mode&0o777)for n,p in files(root).items()}
def dirs(root):return {p.relative_to(root).as_posix():p.stat().st_mode&0o777 for p in root.rglob("*")if p.is_dir()}
def reseal_stream(clone,role,group,cid,channel,change,mutate):
    folder=clone/role/group;case=folder/("case-"+str(cid).zfill(3));path=case/(channel+".gz")
    raw=gzip.decompress(path.read_bytes());updated=change(raw);require(updated!=raw,"physical stream mutation did not change bytes")
    mutate(path,gzip.compress(updated,compresslevel=1,mtime=0))
    receipt=decode((case/"PROCESS.json").read_bytes())
    receipt["streams"][channel]["raw"]=dict(bytes=len(updated),sha256=hashlib.sha256(updated).hexdigest())
    receipt["streams"][channel]["compressed"]=pin(path);mutate(case/"PROCESS.json",canonical(receipt))
    rows=decode((folder/"cases.json").read_bytes());next(r for r in rows if r["id"]==cid)["process"]=receipt
    mutate(folder/"cases.json",canonical(rows))
    require(len(raw)==len(updated),"honest stream mutant changed extent")
def journal_tail(raw,header_bytes,event):
    value=bytearray(raw);at=0
    while at<len(raw):
        require(at+header_bytes<=len(raw),"mutant truncated journal header")
        kind,size=struct.unpack_from("<Q",raw,at+8)[0],struct.unpack_from("<Q",raw,at+32)[0]
        require(at+header_bytes+size<=len(raw),"mutant truncated journal span")
        if kind==event:
            require(size>0,"mutant empty arena");value[at+header_bytes+size-1]^=1;return bytes(value)
        at+=header_bytes+size
    raise ValueError("missing actual full arena event")
def create(source,capture,controls):
    import read_all
    from readonly import guarded,snapshot
    source,capture,controls=Path(source),Path(capture),Path(controls)
    require(not controls.exists(),"fresh physical controls");controls.mkdir()
    baseline=identity(capture);directory_modes=dirs(capture);mutations={}
    for name in NAMES:
        clone=controls/name;shutil.copytree(capture,clone,copy_function=os.link);changed=[]
        def mutate(path,raw):
            old=pin(path);replace(path,raw)
            changed.append(dict(path=path.relative_to(clone).as_posix(),before=old,after=pin(path)))
        if name=="case-count":
            path=clone/"observed/g00/CAPTURE.json";v=decode(path.read_bytes());v["cases"]+=1;mutate(path,canonical(v))
        elif name=="module-image":
            path=clone/"build-reuse/original/restored/run/build/production/binary-read-stdio.elf"
            v=bytearray(path.read_bytes());v[256]^=1;mutate(path,bytes(v))
        elif name=="source-byte":
            path=clone/"source/trusted-build/native/binary_read_body.hepta";mutate(path,path.read_bytes()+b"\n")
        elif name=="original-diagnostic":
            reseal_stream(clone,"original","g01",16,"stderr",lambda raw:bytes([raw[0]^1])+raw[1:],mutate)
        elif name=="actual-stdin":
            reseal_stream(clone,"production","g00",1,"stdin",lambda raw:raw[:-1]+bytes([raw[-1]^1]),mutate)
        elif name=="body-output-tail":
            reseal_stream(clone,"observed","g00",1,"body",lambda raw:journal_tail(raw,128,2),mutate)
        elif name=="formatter-output-tail":
            reseal_stream(clone,"observed","g01",16,"formatter",lambda raw:journal_tail(raw,64,4),mutate)
        elif name=="formatter-work-tail":
            reseal_stream(clone,"observed","g01",16,"formatter",lambda raw:journal_tail(raw,64,5),mutate)
        mutations[name]=changed
    require(identity(capture)==baseline and dirs(capture)==directory_modes,"physical setup changed complete original bytes/modes/set")
    before=snapshot([capture]);outcomes=[]
    for name in NAMES:
        clone=controls/name
        def admission():
            if name.startswith("relocated"):
                result=read_all.verify(clone/"source",clone)
                return dict(name=name,rejected=False,admitted=True,changes=[],result_status=result["status"],
                    cases=result["comparison"]["native_cases"])
            try:read_all.verify(clone/"source",clone)
            except(ValueError,AssertionError,EOFError)as error:
                return dict(name=name,rejected=True,error_type=type(error).__name__,error=str(error),changes=mutations[name])
            raise RuntimeError("physical mutant admitted: "+name)
        proof=guarded(admission,roots=[source,clone])
        (controls/(name+"-readonly.json")).write_bytes(canonical(proof));outcomes.append(proof["evidence"])
    require(snapshot([capture])==before,"pure controls changed original bytes/metadata")
    result=dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=outcomes,honest_full_stream_reseals=5,
        complete_original_bytes_modes_set_unchanged=True,setup_hardlinks_before_quiescence=True,
        setup_link_counts_ctimes_not_claimed_unchanged=True,atomic_replacements_only=True,native_or_rust_replay=False)
    (controls/"controls.json").write_bytes(canonical(result));return result
def verify(source,capture,controls):
    import read_all
    capture,controls=Path(capture),Path(controls);report=decode((controls/"controls.json").read_bytes())
    require(report["status"]=="PHYSICAL_READER_CONTROLS_PASS"and report["complete_original_bytes_modes_set_unchanged"]is True
        and report["honest_full_stream_reseals"]==5 and report["native_or_rust_replay"]is False
        and [r["name"]for r in report["controls"]]==list(NAMES),"control report domain")
    actual=identity(capture);directory_modes=dirs(capture);checked=[]
    for row in report["controls"]:
        clone=controls/row["name"];current=identity(clone);changes={v["path"]:v for v in row["changes"]}
        relocated=row["name"].startswith("relocated")
        require(set(current)==set(actual)and dirs(clone)==directory_modes and len(changes)==len(row["changes"])
            and bool(changes)!=relocated,"complete physical variant file/directory set")
        for name,old in actual.items():
            new=current[name];require(old["mode"]==new["mode"],"physical variant mode")
            if name in changes:
                change=changes[name]
                require(change["before"]=={k:old[k]for k in("bytes","sha256")}
                    and change["after"]=={k:new[k]for k in("bytes","sha256")}and old!=new,"physical mutation identity")
            else:require(old==new,"undeclared physical mutation")
        if relocated:
            result=read_all.verify(clone/"source",clone)
            require(result["status"]==row["result_status"]and result["comparison"]["native_cases"]==row["cases"],
                "relocated complete admission differs")
        else:
            try:read_all.verify(clone/"source",clone)
            except(ValueError,AssertionError,EOFError)as error:
                require(type(error).__name__==row["error_type"]and str(error)==row["error"],"retained refusal differs")
            else:raise ValueError("physical mutant now admitted")
        proof=decode((controls/(row["name"]+"-readonly.json")).read_bytes())
        require(proof["status"]=="READONLY_PASS"and proof["before"]==proof["after"]and proof["evidence"]==row
            and len(proof["probes"])==11 and all(r["rejected"]is True for r in proof["probes"])
            and proof["native_executed"]is False and proof["evidence_written"]is False,"retained control custody")
        checked.append(dict(name=row["name"],rejected=not relocated,admitted=relocated,changed_files=len(changes)))
    return dict(status="PHYSICAL_READER_CONTROLS_PASS",controls=checked,honest_full_stream_reseals=5,
        full_variant_bytes_modes_directories_checked=True)
