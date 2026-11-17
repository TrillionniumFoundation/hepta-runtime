# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
from pathlib import Path
import struct
from common import decode,owned,require
ROOT=Path(__file__).resolve().parents[1]
def domain():return decode(owned(ROOT,"DOMAIN.json").read_bytes())
def group(name):
    d=domain();ids=d["unobserved_case_ids"]if name=="unobserved"else next(g["case_ids"]for g in d["groups"]if g["name"]==name)
    return [c for c in d["cases"]if c["id"]in ids]
def wire(q):
    root=q["request"]["root"].encode();path=q["request"]["path"].encode()
    return b"HPRDQ001"+struct.pack("<11Q",1,0,1,len(root),len(path),0,0,0,0,0,len(root)+len(path))+root+path
def validate():
    d=domain();require([r["id"]for r in d["cases"]]==list(range(1,49)),"complete parent domain")
    require([i for g in d["groups"]for i in g["case_ids"]]==list(range(1,49)),"group partition")
    require(sum(c["mutation"]is not None for c in d["cases"])==6 and sum(c["free_fds"]is not None for c in d["cases"])==2,"race/FD domain")
    require(d["unobserved_case_ids"]==[1,3,6,8,9,13,21,34,35,36],"observer off domain")
    return dict(cases=48,groups=9,mutations=6,limited_fd_pairs=2,unobserved=10,coexisting_pairs=2)
