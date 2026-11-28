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
    require(ids==list(range(1,17))and len(d["groups"])==8,"fixed new stdio rebind domain")
    require([i for g in d["groups"]for i in g["case_ids"]]==ids,"fixed two-case group partition")
    require(all(r["mode"]=="read"and r["input_chunk_bytes"]in(1,7,31,4093)
        and r["output_chunk_bytes"]in(7,65536)and r["storage"]in("disk","shm")
        and type(r["fault"])is bool for r in rows),"fixed read/fragment/storage inputs")
    require([r["id"]for r in rows if r["fault"]]==[11,12,13,14]and not d["controls"],"new actual kernel fault domain")
    return dict(cases=16,groups=8,original_processes=16,production_processes=16,observed_processes=16,
        real_fault_cases=4,private_control_replays=0)
