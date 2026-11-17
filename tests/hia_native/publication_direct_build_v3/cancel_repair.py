#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind the real gateway CANCELLED return without inventing a reply body."""
from pathlib import Path
import json
from capacity_repair import pin,require
HERE=Path(__file__).resolve().parent
def verify():
    p=HERE/"DIRECT_CANCEL_REPAIR.json";change=json.loads(p.read_bytes())
    before=(HERE/"retained_aligned_direct_fixture.S").read_bytes();after=(HERE/"direct_fixture.S").read_bytes()
    require(pin(before)==change["before"] and pin(after)==change["after"],"whole direct cancellation observer sources")
    text=before.decode()
    for edit in change["edits"]:
        require(text.count(edit["before"])==1,"unique actual cancellation observer edit")
        text=text.replace(edit["before"],edit["after"],1)
    require(text.encode()==after,"all other direct observer bytes retained")
    for edit in reversed(change["edits"]):
        require(text.count(edit["after"])==1,"unique inverse cancellation observer edit")
        text=text.replace(edit["after"],edit["before"],1)
    require(text.encode()==before,"complete source inverse")
    gateway=(HERE/"retained_gateway.hepta").read_bytes()
    require(pin(gateway)=={k:change["gateway"][k] for k in ("bytes","sha256","git_blob")},"whole actual unchanged gateway")
    source=gateway.decode()
    f17=source[source.index("fn f17("):source.index("\nend",source.index("fn f17("))]
    require('v50:u64 = const() {"value":4294967287}' in f17 and "ret(v51)" in f17
        and 'v21:u64 = const() {"value":3}' in f17,"real no-body cancelled terminal")
    return dict(status="ACTUAL_GATEWAY_CANCEL_RETURN_SOURCE_BOUND",repair=pin(p.read_bytes()),
        production_changes=0,application_executed=False)
