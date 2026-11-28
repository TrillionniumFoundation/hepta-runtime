#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Only the frozen input domain; no result oracle."""
from pathlib import Path
import struct
from common import decode,owned,require
ROOT=Path(__file__).resolve().parents[1]
def domain():return decode(owned(ROOT,"DOMAIN.json").read_bytes())
def group(name):
    d=domain()
    ids=d["unobserved_case_ids"]if name=="unobserved"else next(g["case_ids"]for g in d["groups"]if g["name"]==name)
    return [c for c in d["cases"]if c["id"]in ids]
def wire(query):
    q=query["request"];mode={"read":1,"fingerprint":2,"private":3}[query["mode"]]
    if query["entry"]=="at":
        name=q["name"].encode()
        return b"HBRDFD01"+struct.pack("<11Q",1,0,mode,0,len(name),0,0,0,0,0,len(name))+name
    root=q["root"].encode();path=q["path"].encode()
    expected=q.get("expected_version");value=b""if expected is None else expected.encode()
    return b"HBRDQ001"+struct.pack("<11Q",1,0,mode,len(root),len(path),len(value),
        int(expected is not None),q.get("offset",0),q.get("limit",0),0,len(root)+len(path)+len(value))+root+path+value
def validate():
    d=domain();rows=d["cases"];ids=[c["id"]for c in rows]
    require(ids==list(range(1,60))and len(d["groups"])==8,"frozen case domain differs")
    require([i for g in d["groups"]for i in g["case_ids"]]==ids,"group partition differs")
    require(sum(c["entry"]=="at"for c in rows)==52 and sum(c["mutation"]is not None for c in rows)==21
        and sum(c["fd_limit"]for c in rows)==2,"borrow/mutation/descriptor domain differs")
    require(d["unobserved_case_ids"]==[1,5,6,18,21,53,55,56],"observer-off domain differs")
    require(all(not rows[i-1]["mutation"]and not rows[i-1]["fd_limit"]for i in d["unobserved_case_ids"]),
        "unobserved domain needs no barriers")
    return dict(cases=59,groups=8,borrowed_parent_cases=52,mutation_cases=21,one_free_fd_cases=2,unobserved_cases=8)
