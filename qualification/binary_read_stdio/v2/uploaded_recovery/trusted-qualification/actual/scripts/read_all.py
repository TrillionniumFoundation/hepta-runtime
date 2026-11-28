#!/usr/bin/env python3
"""Complete pure process/build/effect admission; no application replay."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
import build_reuse,read_stdio,read_build_evidence
from cases import group
def prepare(capture):build_reuse.prepare_imports(Path(capture)/"build-reuse")
def process(root,name,limit):
    rows=decode(owned(root,"processes.json").read_bytes())
    require(sum(r["name"]==name for r in rows)==1,"producer process name differs")
    row=next(r for r in rows if r["name"]==name)
    require(row["name"]==name and row["completed"]is True and row["exit_code"]==0
        and row["timed_out"]is False and row["timeout_seconds"]==limit
        and 0<=row["elapsed_seconds"]<limit+1 and row["pid"]==row["pgid"]
        and row["parent_pid"]!=row["pid"]and row["stdin"]is None,"actual producer custody differs: "+name)
    require(row["argv"][1:4]==["-I","-S","-B"],"isolated producer interpreter differs")
    for key in("stdout","stderr"):
        item=row[key];require(item["file"]==name+"."+key and pin(owned(root,item["file"]))==
            {k:item[k]for k in("bytes","sha256")},"full producer stream differs")
    require(owned(root,name+".stderr").read_bytes()==b"","producer stderr differs")
    return row,decode(owned(root,name+".stdout").read_bytes())

def verify(source,capture,name):
    source,capture=Path(source),Path(capture);identity=source_evidence(source)
    require(source_evidence(capture/"source")==identity,"complete retained source identity")
    build=read_build_evidence.verify(source,capture/"build-reuse")
    comparison=read_stdio.verify(source,capture,name)
    root=capture/"processes"
    sequence=[("fetch-build",60),("restore-build",180),("read-build",180),("setup",60)]
    sequence.extend((role+"-"+name,180)for role in("original","production","observed"))
    records=decode(owned(root,"processes.json").read_bytes())
    require([r["name"]for r in records]==[n for n,_ in sequence],"complete producer process order")
    bound_guards=0
    for saved,(stage,limit)in zip(records,sequence):
        actual,output=process(root,stage,limit);require(actual==saved,"producer process publication")
        if any(stage.startswith(role+"-")for role in("original","production","observed")):
            role=stage.split("-",1)[0];summary=decode(owned(capture/role/name,"CAPTURE.json").read_bytes())
            require(output==summary and summary["pid"]==actual["pid"],"complete role process stdout")
            cases=decode(owned(capture/role/name,"cases.json").read_bytes())
            require(all(c["process"]["parent_pgid"]==actual["pgid"]for c in cases),"all actual targets in bounded role group")
        elif stage=="setup":require(output==decode(owned(capture/"setup","SETUP.json").read_bytes()),"actual setup stdout")
        elif stage=="read-build":
            require(output["evidence"]==build,"complete upstream build admission")
            origin_source=actual["argv"][actual["argv"].index("--source")+1]
            origin_work=actual["argv"][actual["argv"].index("--work")+1]
            bound_guards=read_build_evidence.saved_guard(output,{origin_source:read_build_evidence.tree(source),
                origin_work:read_build_evidence.tree(capture/"build-reuse")})
    return dict(status="COMPLETE_STDIO_READ67_CAPTURE_PASS",source=identity,group=name,build=build,comparison=comparison,
        original_processes=len(group(name)),native_processes=2*len(group(name)),producer_processes=len(records),
        complete_upstream_guard_files=bound_guards,application_executed_by_reader=False)
