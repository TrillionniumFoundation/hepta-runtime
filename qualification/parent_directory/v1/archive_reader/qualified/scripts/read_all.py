#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Complete pure admission; imports never execute HIA or original functions."""
from pathlib import Path
from common import canonical,decode,owned,pin,require,source_evidence
import build_reuse,read_semantics,read_prior
from cases import domain
def prepare(capture):
    read_prior.prepare(capture)
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
    prior=read_prior.verify(source,capture);build=prior["build"]
    comparisons=read_semantics.verify(source,capture)
    root=capture/"processes"
    sequence=[("fetch-prior",60),("restore-prior",180),("read-prior",180),("setup",60)]
    for item in domain()["groups"][6:]:
        sequence.extend([("original-"+item["name"],60),("native-"+item["name"],60)])
    sequence.append(("native-unobserved",60))
    records=decode(owned(root,"processes.json").read_bytes())
    require([r["name"]for r in records]==[n for n,_ in sequence],"producer process order/set differs")
    for saved,(name,limit)in zip(records,sequence):
        actual,output=process(root,name,limit);require(actual==saved,"producer process index differs")
        if name.startswith("original-"):
            require(output==decode(owned(capture/"original"/name[9:],"CAPTURE.json").read_bytes()),
                "actual original stdout differs from saved capture")
        elif name.startswith("native-"):
            require(output==decode(owned(capture/"native"/name[7:],"CAPTURE.json").read_bytes()),
                "actual native stdout differs from saved capture")
        elif name=="setup":require(output==decode(owned(capture/"setup","SETUP.json").read_bytes()),"actual setup output differs")
        elif name=="read-prior":
            require(output["status"]=="READONLY_PASS"and output["before"]==output["after"]
                and len(output["probes"])==11 and output["evidence"]==prior,"qualified build reuse read proof differs")
    return dict(status="COMPLETE_PARENT_CAPTURE_PASS",source=identity,build=build,comparison=comparisons,
        actual_original_processes=9,actual_native_processes=10,new_original_processes=3,new_native_processes=4,producer_processes=len(records),
        application_executed_by_reader=False,prior=prior)
