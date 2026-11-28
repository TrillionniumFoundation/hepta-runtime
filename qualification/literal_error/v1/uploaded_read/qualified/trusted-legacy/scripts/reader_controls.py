#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Physical corruption and whole-capture relocation, with no semantic replay."""
from pathlib import Path
import gzip,hashlib,os,shutil,struct
from common import canonical,decode,pin,require
NAMES=("case-count","module-image","original-result","source-byte","output-tail","workspace-tail",
    "wire-input","integer-fd","dual-separator","relocated-one","relocated-two")
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
            path=clone/"native/errno-00/CAPTURE.json";v=decode(path.read_bytes());v["cases"]+=1;mutate(path,canonical(v))
        elif name=="module-image":
            path=clone/"build/modules/path-error/module.image.bin";v=bytearray(path.read_bytes());v[128]^=1;mutate(path,bytes(v))
        elif name=="source-byte":
            path=clone/"source/native/path_error.hepta";mutate(path,path.read_bytes()+b"\n")
        elif name in("original-result","integer-fd","dual-separator","output-tail","workspace-tail","wire-input"):
            side="original"if name in("original-result","integer-fd","dual-separator")else"native"
            group="dual-named-02"if name=="dual-separator"else"metadata-fd-00"if name=="integer-fd"else"errno-00"
            folder=clone/side/group;path=folder/"records.bin.gz"
            records=decode((folder/"records.json").read_bytes());new_records=[];blocks=[]
            with gzip.open(path,"rb")as stream:
                for index,row in enumerate(records):
                    row=dict(row);header=stream.read(24 if side=="original"else 64)
                    if side=="original":
                        cid,nwire,nout=struct.unpack("<3Q",header);wire=stream.read(nwire);out=stream.read(nout)
                        if name=="original-result"and index==0:out=out[:-1]+bytes([out[-1]^1])
                        if name=="integer-fd"and index==0:
                            out=out.rsplit(b": ",1)[0]+b": '0'"
                        if name=="dual-separator"and index==0:
                            require(b" -> "in out,"missing actual two-name separator");out=out.replace(b" -> ",b" => ",1)
                        block=struct.pack("<3Q",cid,len(wire),len(out))+wire+out
                        row.update(response_bytes=len(out),response_sha256=hashlib.sha256(out).hexdigest())
                    else:
                        cid,code,nwire,oc,wc,number,z0,z1=struct.unpack("<8Q",header)
                        wire=stream.read(nwire);before=stream.read(wc);old=stream.read(oc);out=stream.read(oc);after=stream.read(wc)
                        if index==0:
                            if name=="output-tail":out=out[:-1]+bytes([out[-1]^1])
                            elif name=="workspace-tail":after=after[:-1]+bytes([after[-1]^1])
                            elif name=="wire-input":wire=wire[:16]+struct.pack("<Q",3)+wire[24:]
                        block=header+wire+before+old+out+after
                        row.update(input_sha256=hashlib.sha256(wire).hexdigest(),before_sha256=hashlib.sha256(before).hexdigest(),
                            output_before_sha256=hashlib.sha256(old).hexdigest(),output_sha256=hashlib.sha256(out).hexdigest(),
                            after_sha256=hashlib.sha256(after).hexdigest())
                    row.update(offset=sum(len(v)for v in blocks),bytes=len(block),record_sha256=hashlib.sha256(block).hexdigest())
                    new_records.append(row);blocks.append(block)
                require(stream.read()==b"","mutant source complete stream")
            full=b"".join(blocks)
            mutate(path,gzip.compress(full,compresslevel=1,mtime=0));mutate(folder/"records.json",canonical(new_records))
            meta=decode((folder/"CAPTURE.json").read_bytes())
            meta.update(raw=dict(bytes=len(full),sha256=hashlib.sha256(full).hexdigest()),compressed=pin(path),
                records=pin(folder/"records.json"))
            mutate(folder/"CAPTURE.json",canonical(meta))
            pname=side+"-"+group;stdout=clone/"processes"/(pname+".stdout");mutate(stdout,canonical(meta))
            process=decode((clone/"processes/processes.json").read_bytes())
            record=next(r for r in process if r["name"]==pname);record["stdout"].update(pin(stdout))
            mutate(clone/"processes/processes.json",canonical(process))
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
