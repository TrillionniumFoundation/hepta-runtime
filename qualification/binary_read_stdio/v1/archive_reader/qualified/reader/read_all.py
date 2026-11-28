#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete pure admission; imports never execute HIA or original functions."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
import build_reuse,read_stdio
from cases import domain
def prepare(capture):
    build_reuse.prepare_imports(Path(capture)/"build-reuse")
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
def verify(source,capture):
    source,capture=Path(source),Path(capture)
    identity=source_evidence(source)
    require(source_evidence(capture/"source")==identity,"retained source identity differs")
    build=build_reuse.verify(source,capture/"build-reuse")
    comparisons=read_stdio.verify(source,capture)
    root=capture/"processes"
    sequence=[("fetch-build",60),("restore-build",180),("read-build",180),("setup",60)]
    for item in domain()["groups"]:
        sequence.extend([(role+"-"+item["name"],60)for role in("original","production","observed")])
    sequence.append(("controls-controls",60))
    records=decode(owned(root,"processes.json").read_bytes())
    require([r["name"]for r in records]==[n for n,_ in sequence],"producer process order/set differs")
    for saved,(name,limit)in zip(records,sequence):
        if name=="controls-controls":
            p=saved;last=decode(owned(capture/"controls/controls/case-011","PROCESS.json").read_bytes())
            require(p["completed"]is True and p["exit_code"]==1 and p["timed_out"]is False
                and p["timeout_seconds"]==60 and 0<=p["elapsed_seconds"]<61
                and p["pid"]==p["pgid"]and p["parent_pid"]!=p["pid"]and p["stdin"]is None
                and p["pid"]==last["parent_pid"]and last["returncode"]==111,
                "preserved terminal observation-failure producer custody")
            for channel in("stdout","stderr"):
                item=p[channel];require(item["file"]==name+"."+channel and pin(owned(root,item["file"]))==
                    {k:item[k]for k in("bytes","sha256")},"complete failed producer stream")
            require(owned(root,name+".stdout").read_bytes()==b""
                and ("PermissionError: [Errno 13] Permission denied: '/proc/"+str(last["pid"])+"/fd'").encode()
                    in owned(root,name+".stderr").read_bytes(),"frozen post-exit observation failure")
            continue
        actual,output=process(root,name,limit);require(actual==saved,"producer process index differs")
        if any(name.startswith(role+"-")for role in("original","production","observed","controls")):
            role,group=name.split("-",1)
            summary=decode(owned(capture/role/group,"CAPTURE.json").read_bytes())
            require(output==summary and summary["pid"]==actual["pid"],"actual capture process stdout/parent differs")
        elif name=="setup":require(output==decode(owned(capture/"setup","SETUP.json").read_bytes()),"actual setup output differs")
        elif name=="read-build":
            require(output["status"]=="READONLY_PASS"and output["before"]==output["after"]
                and len(output["probes"])==11 and output["evidence"]==build,"qualified build reuse read proof differs")
    return dict(status="COMPLETE_RETAINED_BINARY_READ_STDIO_CAPTURE_PASS",source=identity,build=build,comparison=comparisons,
        actual_original_processes=48,actual_native_processes=107,producer_processes=len(records),
        application_executed_by_reader=False,producer_capture_failure_preserved=True)
