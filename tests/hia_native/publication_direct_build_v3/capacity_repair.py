#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact source-only repair for the actual guarded allocator contract."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent
def require(ok,message):
    if not ok:raise ValueError(message)
def pin(b):
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(b)).encode()+b"\0"+b).hexdigest())
def verify():
    change=json.loads((HERE/"DIRECT_CAPACITY_REPAIR.json").read_bytes())
    before=(HERE/"retained_direct_fixture.S").read_bytes()
    after=(HERE/"retained_aligned_direct_fixture.S").read_bytes()
    require(pin(before)==change["before"] and pin(after)==change["after"],"entire actual fixture capacity before/after")
    text=before.decode()
    for edit in change["edits"]:
        require(text.count(edit["before"])==1,"unique capacity repair")
        text=text.replace(edit["before"],edit["after"],1)
    require(text.encode()==after,"all other private fixture bytes retained")
    for edit in reversed(change["edits"]):
        require(text.count(edit["after"])==1,"unique inverse capacity repair")
        text=text.replace(edit["after"],edit["before"],1)
    require(text.encode()==before,"complete capacity source inverse")
    allocator=(HERE/"retained_view_engine.S").read_bytes()
    require(pin(allocator)=={k:change["actual_allocator"][k] for k in ("bytes","sha256","git_blob")},"whole unchanged actual allocator")
    require(b"    test rbx, 4095\n    jnz view_allocate_invalid\n" in allocator
        and b"    lea rsi, [rbx + 4096]\n" in allocator,"actual page alignment and guard mapping")
    inputs=change["actual_failure"]["inputs"]
    for row in inputs:
        n=row["length"];require(64<=n<=16777216 and n%4096!=0,"all first attempts truly outside old allocator contract")
    boundaries=[64,65,243,245,246,254,4095,4096,4097,8191,8192,16777215,16777216]
    for n in boundaries:
        cap=(n+4095)&~4095
        require(cap>=n and cap-n<4096 and cap%4096==0 and cap<=16777216
            and cap+4096<=16781312,"full admitted input capacity and guard extent")
    require(change["production_changes"]==0 and change["future_cases"]==8,"private-only unchanged domain")
    return dict(status="EXACT_PRIVATE_INPUT_CAPACITY_SOURCE_PASS",repair=pin((HERE/"DIRECT_CAPACITY_REPAIR.json").read_bytes()),
        original_fixture=pin(before),candidate_fixture=pin(after),allocator=pin(allocator),
        production_changes=0,application_executed=False)
