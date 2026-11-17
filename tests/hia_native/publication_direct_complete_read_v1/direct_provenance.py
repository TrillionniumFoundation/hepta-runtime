#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact source joins and inverse reader transformations; no application entry."""
from pathlib import Path
import hashlib
from common import decode,pin,require,source_evidence
def rawpin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest())
def replace_once(text,before,after):
    require(text.count(before)==1,"one exact reader transform input");return text.replace(before,after,1)
def verify(here,producer,graph,direct_recipe,public_recipe,producer_manifest):
    here,producer,graph,direct_recipe,public_recipe=map(Path,(here,producer,graph,direct_recipe,public_recipe))
    info=decode((here/"INPUTS.json").read_bytes());source=source_evidence(here)
    require(producer_manifest in [r["producer_manifest"] for r in info["roles"].values()]
        and pin(producer/"SOURCE_MANIFEST.json")==producer_manifest,"whole exact actual role producer source pin")
    source_evidence(producer)
    retained=decode((here/"RETAINED_SOURCES.json").read_bytes())
    for row in retained["files"]:
        base={"producer":producer,"public":public_recipe}[row["origin"]]
        require((here/row["path"]).read_bytes()==(base/row["source_path"]).read_bytes(),
            "whole unchanged retained source "+row["path"])
    p=decode((here/"CONTROL_READER_SOURCE.json").read_bytes())
    old=(here/"retained_public_read_native.py").read_bytes()
    require(rawpin(old)==p["source"],"whole original public control reader")
    text=old.decode();at=p["prefix_bytes"];end=p["body_end"]
    require(text[at:].startswith("def compare(") and text[end:].startswith("    old_commands=decode("),
        "exact complete control decoder source range")
    text=text[:end]
    for edit in p["edits"]:text=replace_once(text,edit["before"],edit["after"])
    suffix='    return dict(root=n,result=result,process=process,streams=streams,host=host,holder=holder,\n        commands=commands,controls=controls,store=store,get=get,observations=observations,\n        pointers=pointers,event_prefix=event_prefix,counters=lambda:(captured_n,captured_b))\n'
    require((text+suffix).encode()==(here/"read_controls.py").read_bytes()
        and rawpin((text+suffix).encode())==p["after"],"whole inherited actual control checks")
    w=decode((here/"DIRECT_WORKER_SOURCE.json").read_bytes())
    before=(here/"retained_public_worker.py").read_bytes();after=(here/"direct_worker.py").read_bytes()
    require(rawpin(before)==w["before"] and rawpin(after)==w["after"],"whole worker join before/after")
    text=before.decode()
    for edit in w["edits"]:text=replace_once(text,edit["before"],edit["after"])
    require(text.encode()==after,"all worker join transformations reproduced")
    for edit in reversed(w["edits"]):text=replace_once(text,edit["after"],edit["before"])
    require(text.encode()==before,"whole worker join inverse")
    require(pin(graph/"native/runtime_mcp_sources.json")==info["source_binding"],"whole actual production536 binding")
    for row in info["production_sources"]:
        require(rawpin((graph/row["path"]).read_bytes())=={k:row[k] for k in ("bytes","sha256","git_blob")},
            "actual production lifecycle source "+row["path"])
    require((here/"input_domain.py").read_bytes()==(producer/"input_domain.py").read_bytes(),
        "all original thirty inputs unchanged")
    require((here/"retained_gateway.hepta").read_bytes()==(graph/"native/text_publication_gateway.hepta").read_bytes()
        ==(direct_recipe/"retained_gateway.hepta").read_bytes(),"actual no-body CANCELLED gateway")
    return dict(status="WHOLE_DIRECT_READER_PRODUCER_AND_PRODUCTION_SOURCE_PASS",
        source=source,producer=pin(producer/"SOURCE_MANIFEST.json"),graph=info["source_binding"],
        reader_transformations=len(w["edits"])+len(p["edits"]),retained_files=len(retained["files"]),
        production_changed=False,native_executed=False,rust_executed=False)
