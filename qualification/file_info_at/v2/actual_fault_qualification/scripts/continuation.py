"""Admit complete retained originals and run only the previously absent actual read EIO intervention."""
from pathlib import Path
import encodings.cp437,gzip,os,shutil
from evidence_common import decode,encoded,pin,require
from buffer_store import Reader
import read_partial
from cases import group
def planned(source,name):
    v=decode((Path(source)/"EXECUTION_BOUNDARY.json").read_bytes())
    require(v["original_commit"]=="22d17c24ab7284c30e5808afe9bbfc0dae938b07"
        and v["partial_reader_source"]=="e584b0701d47de99e29c19a4936a45be2c3538b2"
        and v["production_build"]=="d099a1ca66cc0961324c8ad9426c4de9f1145dce","exact failed fixture and corrected build lineage")
    b=v["groups"][name];require(b["conclusion"]=="success","successful complete old-boundary read")
    return b["proof"]["evidence"]
def admission(source,work,name):
    value=read_partial.verify(source,work,name)
    require(value==planned(source,name),"complete original and failed native boundary unchanged")
    return value
def declaration(source,name,role):
    b=planned(source,name);ids=[q["id"]for q in group(name)]
    retained=ids if role=="original"else([27]if name=="shm"else[])
    execute=[]if role=="original"else[i for i in ids if i not in retained]
    q={v["id"]:v for v in group(name)}
    return dict(schema="hepta.runtime.file-info-read67.actual-fault-continuation.v2",
        prior_source="22d17c24ab7284c30e5808afe9bbfc0dae938b07",retained_case_ids=retained,
        newly_executed_ids=execute,retained_application_invocations=sum(q[i]["attempts"]for i in retained),
        newly_executed_application_invocations=sum(q[i]["attempts"]for i in execute),
        retained_rows_and_carriers_kept_byte_for_byte=True,all_application_producers_use_current_source=not retained,
        prior_native_nonfault_calls_retained_as_failed_evidence=True,
        new_native_intervention="actual read phase25/op6 kernel EIO"if execute else None,
        original_applications_replayed=False)
def copy_buffers(value,reader,store):
    if isinstance(value,dict):
        if set(value)=={"bytes","sha256","blocks"}:
            require(store.put(reader.get(value))==value,"exact retained full buffer descriptor")
        else:
            for v in value.values():copy_buffers(v,reader,store)
    elif isinstance(value,list):
        for v in value:copy_buffers(v,reader,store)
def seed(source,work,name,role,output,store):
    admission(source,work,name);folder=Path(work)/"original/restored/run/application"/role
    plan=declaration(source,name,role);wanted=plan["retained_case_ids"]
    reader=Reader(folder/"buffers");out=[]
    with gzip.open(folder/"cases.jsonl.gz","rb")as f:lines=list(f)
    for raw in lines:
        value=decode(raw);cid=value["input"]["id"]
        if cid not in wanted:continue
        copy_buffers(value,reader,store);rel=value["process_path"]
        old=folder/rel;new=Path(output)/rel
        require(rel=="carriers/"+str(cid)and old.is_dir()and not new.exists(),"fixed retained complete carrier")
        for line in(old/"exchanges.jsonl").read_bytes().splitlines():copy_buffers(decode(line),reader,store)
        shutil.copytree(old,new,copy_function=os.link)
        require(files(old)==files(new),"all retained producer bytes/modes copied exactly")
        out.append((raw,value))
    require([v["input"]["id"]for _,v in out]==wanted,"complete retained input extent")
    return out
def files(root):
    return {p.relative_to(root).as_posix():(pin(p),p.stat().st_mode&0o777)for p in root.rglob("*")if p.is_file()}
def old_elf(source):return decode((Path(source)/"trusted-qualification/BUILD_REUSE.json").read_bytes())["elf"]
def verify_capture(source,data,name,report,values):
    data=Path(data);b=admission(source,data/"retained",name);plan=declaration(source,name,report["role"])
    require(report["continuation"]==plan,"all retained and new execution provenance")
    old=data/"retained/original/restored/run/application"/report["role"]
    with gzip.open(old/"cases.jsonl.gz","rb")as f:lines=list(f)
    for raw in lines:
        v=decode(raw);cid=v["input"]["id"]
        if cid not in plan["retained_case_ids"]:continue
        current=next(x for x in values if x["input"]["id"]==cid)
        require(encoded(current)==raw,"complete retained original case is unchanged")
        require(files(old/v["process_path"])==files(data/report["role"]/v["process_path"]),
            "complete retained original process files remain unchanged")
    old_binary=data/"retained/original/restored/run/application/production/file-info-at-callable.elf"
    new_binary=data/"production/file-info-at-callable.elf"
    require(pin(old_binary)==old_elf(source)and pin(new_binary)==decode((Path(source)/"BUILD_REUSE.json").read_bytes())["elf"],
        "complete old and corrected fixture binaries")
    left,right=old_binary.read_bytes(),new_binary.read_bytes()
    changes=[(i,a,z)for i,(a,z)in enumerate(zip(left,right))if a!=z]
    require(len(left)==len(right)and len(changes)==1 and changes[0][1:]==(2,6),
        "complete binary differs only by private read fstat selector immediate")
    return b
def producer_group(data,role,case_id,current):
    data=Path(data);old=data/"retained/original/restored/run"
    report=decode((old/"application"/role/"CAPTURE.json").read_bytes())if role=="original"or case_id==27 else None
    if role=="original"and case_id in report["continuation"]["retained_original_ids"]:
        old=old/"application/retained/original/restored/run"
    records=decode((old/"processes/processes.json").read_bytes())
    return next(p for p in records if p["name"]=="capture-"+role)["pgid"]
