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
    ids=next(r["case_ids"]for r in dom["groups"]if r["name"]==name)
    return [r for r in dom["cases"]if r["id"]in ids]
def wire(query):
    q=query["request"];root=q["root"].encode();path=q["path"].encode()
    expected=q.get("expected_version");value=b""if expected is None else expected.encode()
    mode={"read":1,"fingerprint":2,"private":3}[query["mode"]]
    return b"HBRDQ001"+struct.pack("<11Q",1,0,mode,len(root),len(path),len(value),
        int(expected is not None),q.get("offset",0),q.get("limit",0),0,len(root)+len(path)+len(value))+root+path+value
def validate():
    d=domain();rows=d["cases"];ids=[r["id"]for r in rows]
    require(ids==list(range(1,49))and len(d["groups"])==6,"frozen stdio case domain")
    require([i for g in d["groups"]for i in g["case_ids"]]==ids,"frozen group partition")
    require(all(r["mode"]=="read"and r["input_chunk_bytes"]in(1,7,31,4093,65536)
        and r["output_chunk_bytes"]in(7,65536)for r in rows),"fixed read and fragmented I/O domain")
    require([c["id"]for c in d["controls"]]==list(range(1,12)),"private refusal domain")
    return dict(cases=48,groups=6,original_processes=48,production_processes=48,observed_processes=48,private_controls=11)
def control(case):
    name=case["name"];header=b"HBRDQ001"+struct.pack("<11Q",1,0,1,0,0,0,0,0,0,0,0)
    if name=="empty":return b""
    if name=="short-magic":return header[:7]
    if name=="short-header":return header[:95]
    if name=="borrowed-wire":return b"HBRDFD01"+header[8:]
    if name in("exact-input-limit","over-input-limit"):
        return b"\0"*((128<<20)+(name=="over-input-limit"))
    raw=bytearray(header)
    if name=="wrong-magic":raw[0]^=1
    elif name=="resume-command":struct.pack_into("<Q",raw,8,2)
    elif name=="nonzero-sequence":struct.pack_into("<Q",raw,16,1)
    elif name=="fingerprint-mode":struct.pack_into("<Q",raw,24,2)
    elif name=="private-mode":struct.pack_into("<Q",raw,24,3)
    else:raise ValueError("unknown frozen private control")
    return bytes(raw)
