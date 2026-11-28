#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Read every frozen paired filesystem result and every retained native byte."""
from pathlib import Path
from types import SimpleNamespace
import gzip,hashlib,stat,struct
from common import canonical,decode,owned,pin,require,source_evidence,SCOPE
from cases import domain,group,validate,wire
from filesystem import data,describe
from buffer_store import Reader
from read_journal import Journal,U,invocation,result

def load(root,name):return decode(owned(root,name).read_bytes())
def fixture_rows(snapshot,store,case):
    require("."in snapshot and snapshot["."]["kind"]=="directory","fixture root missing")
    expected=data(case);rows={}
    for name,row in snapshot.items():
        require(type(name)is str and (name=="."or not name.startswith("/")and".."not in name.split("/")),
            "fixture path outside owned root")
        require(row["kind"]in("directory","file","symlink","fifo"),"fixture kind")
        actual_kind=stat.S_IFMT(row["mode"])
        require(actual_kind=={"directory":stat.S_IFDIR,"file":stat.S_IFREG,"symlink":stat.S_IFLNK,"fifo":stat.S_IFIFO}[row["kind"]],
            "fixture kind/mode mismatch")
        if row["kind"]=="file":
            raw=store.get(row["content"])
            require(raw==expected and row["size"]==len(raw)and stat.S_IMODE(row["mode"])==case.get("permissions",0o644),
                "complete fixture bytes/mode differ from frozen input")
            rows[name]=dict(row,raw=raw)
        else:rows[name]=row
    return rows

def setup(source,root,name):
    validate();identity=source_evidence(source);queries=load(root,"inputs.json");summary=load(root,"SETUP.json")
    selected=group(name)
    require([q["id"]for q in queries]==[c["id"]for c in selected]and summary["status"]=="FROZEN_INPUTS_CREATED"
        and summary["source"]==identity and summary["cases"]==len(selected)and summary["group"]==name
        and summary["original_or_native_application_calls"]==0,"input setup domain or custody")
    reader=Reader(root/"buffers");fixtures={}
    for case,q in zip(selected,queries):
        require(q["id"]==case["id"],"setup input ordinal differs")
        rows=fixture_rows(q["snapshot"],reader,case)
        names=domain()["fixtures"];long=[]
        if case["path"]=="long-path":
            long=["d"*(names["long_path_component_bytes"]-4)+str(n).zfill(4)for n in range(names["long_path_components"])]
        expected=describe(Path(q["fixture"]),case,SimpleNamespace(**q["input_selected_stat"]),long)
        require({k:v for k,v in q.items()if k!="snapshot"}==expected,"input-only request construction differs")
        if case["path"]=="hardlink":selected=rows["hard.bin"]
        elif case["path"]=="nested-sidecar":selected=rows["dir/.hepta-hidden"]
        elif case["path"]in("unicode","control"):selected=rows[names[case["path"]]]
        elif case["path"]=="sidecar":selected=rows[".hepta-hidden"]
        elif case["path"]=="long-path":selected=rows["/".join(long)+"/leaf.bin"]
        else:selected=rows["data.bin"]
        require(q["input_selected_stat"]==dict(st_dev=selected["dev"],st_ino=selected["inode"],
            st_size=selected["size"],st_mtime_ns=selected["mtime_ns"],st_ctime_ns=selected["ctime_ns"]),
            "input version source stat differs")
        fixtures[q["id"]]={q["fixture"]if name=="."else q["fixture"]+"/"+name:value for name,value in rows.items()}
    stats=reader.finish()
    require(stats["complete_images"]==summary["images"]and stats["logical_buffer_bytes"]==summary["logical_bytes"],
        "setup complete buffer inventory differs")
    return queries,fixtures,stats

