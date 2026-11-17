#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Bind the narrow reader delta to complete immutable producer and SDK source."""
from pathlib import Path
import hashlib
from common import decode,pin,require,source_evidence
OLD = "            require(actual_wire==expected_wire,\"complete current SDK wire outside individually stat-bound version differs at command \"+str(number)+\": \"+repr((actual_raw,expected_raw)))\n            require([r[\"path\"] for r in actual_versions]==[r[\"path\"] for r in expected_versions],\"same publication version paths\")\n            version_proofs.append(dict(command=number,native=actual_versions,original=expected_versions))\n"
NEW = "            ordering=concurrent_wire.compare(actual_wire,expected_wire,actual_versions,expected_versions,\n                case,q,number,commands,store,view,ov,host)\n            version_proofs.append(dict(command=number,native=actual_versions,original=expected_versions,ordering=ordering))\n"
def verify(here,old,graph,sdk):
    here,old,graph,sdk=map(Path,(here,old,graph,sdk))
    info=decode((here/"RETAINED_INPUTS.json").read_bytes())
    require(pin(old/"SOURCE_MANIFEST.json")==
        {k:info["native_source_manifest"][k] for k in ("bytes","sha256")},
        "exact original 54-file public capture source manifest")
    previous=source_evidence(old)
    old_text=(old/"read_native.py").read_text();new_text=(here/"read_native.py").read_text()
    require(old_text.count(OLD)==new_text.count(NEW)==1,"unique original and replacement comparison block")
    restored=new_text.replace("import read_state,wire_versions,concurrent_wire\n",
        "import read_state,wire_versions\n",1).replace(NEW,OLD,1)
    require(restored==old_text,"all other complete reader source preserved")
    changed={"SOURCE_MANIFEST.json","read_native.py","RETAINED_INPUTS.json","README.md"}
    for p in old.rglob("*"):
        if p.is_file() and p.relative_to(old).as_posix() not in changed:
            require((here/p.relative_to(old)).read_bytes()==p.read_bytes(),
                "unchanged retained source: "+p.relative_to(old).as_posix())
    old_info=decode((old/"RETAINED_INPUTS.json").read_bytes())
    require(all(info[k]==old_info[k] for k in old_info),"all original dependency identities and domains preserved")
    require(pin(here/"retained_worker_journal.py")==
        {k:info["worker_reader"][k] for k in ("bytes","sha256")},
        "unchanged qualified complete native worker reader")
    require(pin(graph/"native/runtime_mcp_sources.json")["sha256"]==info["source_binding"]["sha256"],
        "exact 536-input production graph binding")
    require(pin(sdk)=={k:info["sdk_service"][k] for k in ("bytes","sha256")},
        "complete exact current rmcp service.rs")
    text=sdk.read_text()
    fragments=["fn spawn_service_task<F>","tokio::spawn(future)",
        "let mut response_send_tasks = tokio::task::JoinSet::<()>::new();",
        "m = sink_proxy_rx.recv()", "local_ct_pool.remove(id)",
        "response_send_tasks.spawn(async move", "spawn_service_task(async move",
        "drop(sink_proxy_tx);", "response_send_tasks.join_next().await",
        "while let Some(m) = sink_proxy_rx.recv().await", "transport.send(m).await"]
    require(all(x in text for x in fragments),"exact SDK independent-handler/completion/drain source")
    return dict(status="EXACT_SOURCE_AND_NARROW_READER_TRANSFORMATION_PASS",
        retained_source=previous,read_native_before=pin(old/"read_native.py"),
        read_native_after=pin(here/"read_native.py"),worker_reader=info["worker_reader"],
        graph_binding=pin(graph/"native/runtime_mcp_sources.json"),sdk_service=pin(sdk),
        sdk_lines=[dict(fragment=x,lines=[i+1 for i,l in enumerate(text.splitlines()) if x in l]) for x in fragments],
        production_changed=False,input_domain_changed=False,semantic_replay=False)
