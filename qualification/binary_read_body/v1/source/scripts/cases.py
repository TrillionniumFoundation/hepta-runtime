#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Input-only domain expansion; no expected success or error values."""
from pathlib import Path
import struct
from common import decode,owned,require
ROOT=Path(__file__).resolve().parents[1]
def domain():return decode(owned(ROOT,"DOMAIN.json").read_bytes())
def cases():return domain()["cases"]
def expand(v):
    if isinstance(v,dict)and set(v)=={"$u64"}:return int(v["$u64"])
    return v
def group(name):
    dom=domain()
    if name=="unobserved":ids=dom["unobserved_case_ids"]
    else:ids=next(r["case_ids"]for r in dom["groups"]if r["name"]==name)
    return [r for r in dom["cases"]if r["id"]in ids]
def wire(query):
    q=query["request"];root=q["root"].encode();path=q["path"].encode()
    expected=q.get("expected_version");value=b""if expected is None else expected.encode()
    mode={"read":1,"fingerprint":2,"private":3}[query["mode"]]
    return b"HBRDQ001"+struct.pack("<11Q",1,0,mode,len(root),len(path),len(value),
        int(expected is not None),q.get("offset",0),q.get("limit",0),0,len(root)+len(path)+len(value))+root+path+value
def validate():
    d=domain();rows=d["cases"];ids=[r["id"]for r in rows]
    require(ids==list(range(1,115))and len(d["groups"])==15,"frozen domain changed")
    require([i for g in d["groups"]for i in g["case_ids"]]==ids,"frozen group partition changed")
    require(len(d["unobserved_case_ids"])==15 and set(d["unobserved_case_ids"])<=set(ids),"unobserved domain changed")
    require({m:sum(r["mode"]==m for r in rows)for m in("read","fingerprint","private")}==
        dict(read=81,fingerprint=17,private=16),"mode domain changed")
    return dict(cases=114,groups=15,unobserved_cases=15)
