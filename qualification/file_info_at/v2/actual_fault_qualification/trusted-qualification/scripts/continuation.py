"""Lossless retained-prefix assembly and exact unexecuted input admission."""
from pathlib import Path
import encodings.cp437,gzip,os,shutil
from evidence_common import decode,encoded,pin,require,owned
from buffer_store import Reader
import read_partial
from cases import group
def planned(source,name):
    value=decode((Path(source)/"EXECUTION_BOUNDARY.json").read_bytes())
    require(value["original_commit"]=="8d8b5d66bb2c8b0fa974ae1e2f7f616de704bb16"
        and value["partial_reader_source"]=="b34fb5032c5a427d185f126b0a76481e78569dce"
        and value["production_build_unchanged"]=="769181fa985a02a238cc4932752cd47443683ae9",
        "fixed complete capture lineage")
    bound=value["groups"][name];require(bound["conclusion"]=="success","terminal boundary reader")
    return bound["proof"]["evidence"]
def admission(source,work,name):
    observed=read_partial.verify(source,work,name)
    require(observed==planned(source,name),"exact complete old partial boundary remains unchanged")
    return observed
def declaration(source,name,role):
    b=planned(source,name)
    retained=[x["id"]for x in b["retained_complete_original"]]if role=="original"else[]
    execute=b["never_executed_original_ids"]if role=="original"else b["never_executed_native_ids"]
    q={x["id"]:x for x in group(name)}
    return dict(schema="hepta.runtime.file-info-read67.retained-prefix-capture.v1",
        original_source="8d8b5d66bb2c8b0fa974ae1e2f7f616de704bb16",
        retained_original_ids=retained,newly_executed_ids=execute,
        retained_application_invocations=sum(q[x]["attempts"]for x in retained),
        newly_executed_application_invocations=sum(q[x]["attempts"]for x in execute),
        all_application_producers_use_current_source=not retained,
        retained_rows_and_carriers_kept_byte_for_byte=True)
def seed(source,work,name,output,store):
    b=admission(source,work,name);folder=Path(work)/"original/restored/run/application/original"
    with gzip.open(folder/"cases.jsonl.gz","rb")as f:lines=list(f)
    records=b["retained_complete_original"]
    require(len(lines)==len(records),"complete retained prefix")
    reader=Reader(folder/"buffers");result=[]
    def transfer(value):
        if isinstance(value,dict):
            if set(value)=={"bytes","sha256","blocks"}:
                require(store.put(reader.get(value))==value,"unchanged imported complete buffer descriptor")
            else:
                for v in value.values():transfer(v)
        elif isinstance(value,list):
            for v in value:transfer(v)
    for raw,bound in zip(lines,records):
        value=decode(raw);require(value["input"]["id"]==bound["id"],"retained original ordinal")
        transfer(value);relative=value["process_path"]
        old=folder/relative;new=Path(output)/relative
        require(old.is_dir()and relative=="carriers/"+str(bound["id"])and not new.exists(),"owned original carrier prefix")
        for line in(old/"exchanges.jsonl").read_bytes().splitlines():transfer(decode(line))
        shutil.copytree(old,new,copy_function=os.link)
        before={p.relative_to(old).as_posix():(pin(p),p.stat().st_mode&0o777)for p in old.rglob("*")if p.is_file()}
        after={p.relative_to(new).as_posix():(pin(p),p.stat().st_mode&0o777)for p in new.rglob("*")if p.is_file()}
        require(before==after and pin(new/"carrier-process.json")==bound["process"],"complete retained carrier copied exactly")
        result.append((raw,value))
    return result
def verify_capture(source,data,name,report,values):
    data=Path(data);b=admission(source,data/"retained",name)
    expected=declaration(source,name,report["role"])
    require(report["continuation"]==expected,"honest old and new application provenance")
    if report["role"]=="original":
        old=data/"retained/original/restored/run/application/original"
        with gzip.open(old/"cases.jsonl.gz","rb")as f:lines=list(f)
        for raw,bound in zip(lines,b["retained_complete_original"]):
            value=next(v for v in values if v["input"]["id"]==bound["id"])
            require(encoded(value)==raw,"complete retained original case is unchanged")
            folder=old/value["process_path"];copied=data/"original"/value["process_path"]
            a={p.relative_to(folder).as_posix():(pin(p),p.stat().st_mode&0o777)for p in folder.rglob("*")if p.is_file()}
            c={p.relative_to(copied).as_posix():(pin(p),p.stat().st_mode&0o777)for p in copied.rglob("*")if p.is_file()}
            require(a==c,"complete retained original process files remain unchanged")
    return b
