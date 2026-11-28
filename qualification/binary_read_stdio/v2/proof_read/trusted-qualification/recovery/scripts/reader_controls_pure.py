#!/usr/bin/env python3
"""Eight physical corruptions, honest reseals and two complete relocations; no application replay."""
from pathlib import Path
import gzip,hashlib,os,shutil,struct
from common import canonical,decode,pin,require
from cases import group
from read_build_evidence import saved_guard,tree
NAMES=("case-count","module-image","source-byte","original-wire","actual-stdin","body-output-tail",
    "pool-reserved","kernel-result","relocated-one","relocated-two")
def replace(path,raw):
    temp=path.with_name(path.name+".new");temp.write_bytes(raw);temp.chmod(path.stat().st_mode&0o777);os.replace(temp,path)
def files(root):return {p.relative_to(root).as_posix():p for p in root.rglob("*")if p.is_file()}
def identity(root):return {n:dict(**pin(p),mode=p.stat().st_mode&0o777)for n,p in files(root).items()}
def dirs(root):return {p.relative_to(root).as_posix():p.stat().st_mode&0o777 for p in root.rglob("*")if p.is_dir()}
def publish_receipt(clone,role,name,cid,receipt,mutate):
    folder=clone/role/name;case=folder/("case-"+str(cid).zfill(3))
    mutate(case/"PROCESS.json",canonical(receipt))
    rows=decode((folder/"cases.json").read_bytes());next(r for r in rows if r["id"]==cid)["process"]=receipt
    mutate(folder/"cases.json",canonical(rows))
def reseal_stream(clone,role,name,cid,channel,change,mutate):
    folder=clone/role/name;case=folder/("case-"+str(cid).zfill(3));path=case/(channel+".gz")
    raw=gzip.decompress(path.read_bytes());updated=change(raw)
    require(updated!=raw and len(raw)==len(updated),"honest full stream mutation extent")
    mutate(path,gzip.compress(updated,compresslevel=1,mtime=0))
    receipt=decode((case/"PROCESS.json").read_bytes())
    receipt["streams"][channel]["raw"]=dict(bytes=len(updated),sha256=hashlib.sha256(updated).hexdigest())
    receipt["streams"][channel]["compressed"]=pin(path)
    publish_receipt(clone,role,name,cid,receipt,mutate)
def journal_tail(raw,magic,event):
    value=bytearray(raw);at=0
    while at<len(raw):
        m=raw[at:at+8];require(m in(b"HBRDJR01",b"HBRLJR01"),"full mixed journal framing")
        h=128 if m==b"HBRDJR01"else 64
        require(at+h<=len(raw),"full mixed header")
        kind=struct.unpack_from("<Q",raw,at+8)[0];size=struct.unpack_from("<Q",raw,at+(32 if h==128 else 16))[0]
        require(at+h+size<=len(raw),"full mixed span")
        if m==magic and kind==event:
            require(size>0,"nonempty actual full mapping");value[at+h+size-1]^=1;return bytes(value)
        at+=h+size
    raise ValueError("missing complete observed mapping")
def reseal_kernel(clone,name,cid,mutate):
    folder=clone/"production"/name;case=folder/("case-"+str(cid).zfill(3));path=case/"kernel.jsonl.gz"
    rows=[decode(x)for x in gzip.decompress(path.read_bytes()).splitlines()]
    selected=next(r for r in rows if r["record"]=="LEAVE")
    selected["result"]+=1
    raw=b"".join(canonical(r)for r in rows);mutate(path,gzip.compress(raw,compresslevel=1,mtime=0))
    old=decode((case/"kernel-process.json").read_bytes());before=old["raw"]["bytes"]
    old["raw"]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());old["compressed"]=pin(path)
    mutate(case/"kernel-process.json",canonical(old))
    receipt=decode((case/"PROCESS.json").read_bytes());receipt["kernel"]=old
    publish_receipt(clone,"production",name,cid,receipt,mutate)
    summary=decode((folder/"CAPTURE.json").read_bytes());summary["kernel_bytes"]+=len(raw)-before
    mutate(folder/"CAPTURE.json",canonical(summary))
def create(source,capture,controls,name):
    import read_all
    from readonly import guarded,snapshot
    source,capture,controls=Path(source),Path(capture),Path(controls)
    require(not controls.exists(),"fresh physical controls");controls.mkdir()
    baseline=identity(capture);directory_modes=dirs(capture);mutations={};cid=group(name)[0]["id"]
    for label in NAMES:
        clone=controls/label;shutil.copytree(capture,clone,copy_function=os.link);changed=[]
        def mutate(path,raw):
            old=pin(path);replace(path,raw);changed.append(dict(path=path.relative_to(clone).as_posix(),before=old,after=pin(path)))
        if label=="case-count":
            path=clone/"observed"/name/"CAPTURE.json";v=decode(path.read_bytes());v["cases"]+=1;mutate(path,canonical(v))
        elif label=="module-image":
            path=clone/"build-reuse/original/restored/run/build/production/binary-read-stdio.elf"
            raw=bytearray(path.read_bytes());raw[256]^=1;mutate(path,bytes(raw))
        elif label=="source-byte":
            path=clone/"source/trusted-build/native/binary_read_body.hepta";mutate(path,path.read_bytes()+b"\n")
        elif label=="original-wire":
            folder=clone/"original"/name/("case-"+str(cid).zfill(3))
            channel="stdout"if gzip.decompress((folder/"stdout.gz").read_bytes())else"stderr"
            reseal_stream(clone,"original",name,cid,channel,lambda b:bytes([b[0]^1])+b[1:],mutate)
        elif label=="actual-stdin":
            reseal_stream(clone,"production",name,cid,"stdin",lambda b:b[:-1]+bytes([b[-1]^1]),mutate)
        elif label=="body-output-tail":
            reseal_stream(clone,"observed",name,cid,"body",lambda b:journal_tail(b,b"HBRDJR01",2),mutate)
        elif label=="pool-reserved":
            reseal_stream(clone,"observed",name,cid,"body",lambda b:journal_tail(b,b"HBRLJR01",3),mutate)
        elif label=="kernel-result":reseal_kernel(clone,name,cid,mutate)
        mutations[label]=changed
    require(identity(capture)==baseline and dirs(capture)==directory_modes,"physical setup altered original bytes/modes/set")
    before=snapshot([capture]);outcomes=[]
    for label in NAMES:
        clone=controls/label
        def admission():
            if label.startswith("relocated"):
                result=read_all.verify(clone/"source",clone,name)
                return dict(name=label,rejected=False,admitted=True,changes=[],result_status=result["status"],
                    inputs=result["comparison"]["inputs"])
            try:read_all.verify(clone/"source",clone,name)
            except(ValueError,AssertionError,EOFError,KeyError)as error:
                return dict(name=label,rejected=True,error_type=type(error).__name__,error=str(error),changes=mutations[label])
            raise RuntimeError("physical mutant admitted: "+label)
        proof=guarded(admission,roots=[source,clone])
        (controls/(label+"-readonly.json")).write_bytes(canonical(proof));outcomes.append(proof["evidence"])
    require(snapshot([capture])==before,"pure controls changed original bytes/metadata")
    result=dict(status="PHYSICAL_STDIO_READ67_CONTROLS_PASS",group=name,controls=outcomes,honest_full_stream_reseals=5,
        complete_original_bytes_modes_set_unchanged=True,setup_hardlinks_before_quiescence=True,
        setup_link_counts_ctimes_not_claimed_unchanged=True,atomic_replacements_only=True,
        native_or_original_replay=False,guard_probes=110)
    (controls/"controls.json").write_bytes(canonical(result));return result
def verify(source,capture,controls,name):
    import read_all
    source,capture,controls=Path(source),Path(capture),Path(controls);report=decode((controls/"controls.json").read_bytes())
    require(report["status"]=="PHYSICAL_STDIO_READ67_CONTROLS_PASS"and report["group"]==name
        and report["complete_original_bytes_modes_set_unchanged"]is True and report["honest_full_stream_reseals"]==5
        and report["native_or_original_replay"]is False and report["guard_probes"]==110
        and [r["name"]for r in report["controls"]]==list(NAMES),"complete physical control report")
    actual=identity(capture);directory_modes=dirs(capture);checked=[];guard_files=0;noop_writes=[]
    for row in report["controls"]:
        clone=controls/row["name"];current=identity(clone);changes={v["path"]:v for v in row["changes"]}
        relocated=row["name"].startswith("relocated")
        require(set(current)==set(actual)and dirs(clone)==directory_modes and len(changes)==len(row["changes"])
            and bool(changes)!=relocated,"complete variant file/directory set")
        for path,old in actual.items():
            new=current[path];require(old["mode"]==new["mode"],"physical variant file mode")
            if path in changes:
                change=changes[path];require(change["before"]=={k:old[k]for k in("bytes","sha256")}
                    and change["after"]=={k:new[k]for k in("bytes","sha256")},"complete physical before/after bytes")
                if old==new:
                    require(row["name"]=="kernel-result"and path=="production/"+name+"/CAPTURE.json",
                        "only exact recorded unchanged kernel-byte-count summary")
                    noop_writes.append(dict(control=row["name"],path=path,identity=old))
            else:require(old==new,"undeclared physical change")
        if relocated:
            result=read_all.verify(clone/"source",clone,name)
            require(result["status"]==row["result_status"]and result["comparison"]["inputs"]==row["inputs"],
                "complete relocated admission")
        else:
            try:read_all.verify(clone/"source",clone,name)
            except(ValueError,AssertionError,EOFError,KeyError)as e:
                require(type(e).__name__==row["error_type"]and str(e)==row["error"],"same exact physical refusal")
            else:raise ValueError("physical corruption accepted")
        proof=decode((controls/(row["name"]+"-readonly.json")).read_bytes())
        require(proof["evidence"]==row and len(proof["roots"])==2,"complete saved control result")
        clone_label=next(x for x in proof["roots"]if Path(x).name==row["name"])
        original_label=next(x for x in proof["roots"]if x!=clone_label)
        guard_files+=saved_guard(proof,{clone_label:tree(clone),original_label:tree(source)})
        checked.append(dict(name=row["name"],rejected=not relocated,admitted=relocated,changed_files=len(changes)))
    require(len(noop_writes)==1,"exact one physically written byte-identical summary")
    return dict(status="PHYSICAL_STDIO_READ67_CONTROLS_PASS",group=name,controls=checked,
        fully_bound_byte_identical_writes=noop_writes,
        honest_full_stream_reseals=5,full_variant_bytes_modes_directories_checked=True,guard_probes=110,
        complete_saved_guard_files=guard_files,new_application_executions=0)
