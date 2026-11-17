#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Admit the exact124 ELF and the unchanged completed original role separately."""
from pathlib import Path
from common import decode,pin,require
import dependencies
ROOT=Path(__file__).resolve().parents[1]
INPUTS=decode((ROOT/"CURRENT_INPUTS.json").read_bytes())
def verify_receipt(value):
    require(value["schema"]=="hepta.runtime.publication124.retained-original.dependencies.v1"
        and value["graph_identity"]==INPUTS["graph"] and value["production"]==INPUTS["production"],
        "exact actual124 graph identity")
    old=value["retained_original_dependencies"];dependencies.verify_receipt(old)
    require(value["original_binary"]==old["original_binary"]
        and value["original_binary_pin"]==old["original_binary_pin"]==INPUTS["original_binary"],
        "unchanged actual original executable identity")
    for field in ("filesystem_binary","public_binary","original_binary"):
        require(type(value[field]) is str and Path(value[field]).is_absolute(),"complete actual executable path")
    require(value["carrier_binary_pin"]==INPUTS["binaries"]["instances"]
        and value["stdio_binary_pin"]==INPUTS["binaries"]["production"],"exact current application binaries")
    g=value["graph_review"]
    require(g["status"]=="COMPLETE_ACTUAL_PUBLICATION124_TWO_SESSION_BUILD_READ_PASS"
        and g["runtime_hia_images"]==124 and g["physical_images"]==117 and g["descriptor_slots"]==69
        and g["fresh_direct"]==0 and g["reverified_reused_direct"]==116 and g["packed_hia_images"]==8
        and g["source_files"]==536 and g["source_binding"]==INPUTS["runtime_source_binding"]
        and g["complete_compile_receipts"] is g["complete_pack_buffers"] is True
        and g["actual_application_semantics_qualified"] is g["native_or_rust_executed"] is False,
        "complete retained actual124 build review")
    require(set(g["entries"])==set(INPUTS["binaries"]),"all four current fixed entries")
    for name,expected in INPUTS["binaries"].items():
        row=g["entries"][name]
        require({k:row["elf"][k] for k in ("bytes","sha256")}==expected
            and row["runtime_hia_images"]==124 and row["reverified_retained_direct_members"]==116
            and row["direct_fresh_members"]==0 and row["actual_link_and_pack"] is True
            and row["complete_pack_input_output_workspace"] is True,"complete current entry "+name)
    require(value["original_replayed"] is value["graph_rebuilt"] is False,"dependency stage never replays implementations")
    return dict(production=value["production"],runtime_hia_images=124,original_replayed=False)
def verify_guard(proof):
    require(proof["schema"]=="hepta.runtime.owner-export-readonly.v1"
        and proof["source_bound_guard"] is True and proof["before"]==proof["after"]
        and isinstance(proof["before"],dict) and len(proof["probes"])==11
        and all(set(row)=={"name","refusal","guard_event"} and row["refusal"] and row["guard_event"] for row in proof["probes"])
        and proof["native_or_rust_executions"]==0 and proof["reader_writes"]==0,
        "complete actual guarded dependency read")
def verify_capture(capture,retained,graph_proof):
    capture,retained,graph_proof=map(Path,(capture,retained,graph_proof))
    value=decode((capture/"DEPENDENCIES.json").read_bytes());verify_receipt(value)
    proof=decode(graph_proof.read_bytes());verify_guard(proof)
    require(pin(graph_proof)==value["complete_graph_proof"]
        and proof["evidence"]["current"]==value["graph_review"],"complete actual graph proof association")
    old=decode((retained/"DEPENDENCIES.json").read_bytes())
    require(old==value["retained_original_dependencies"],"whole unchanged original role dependency record")
    custody=decode((capture/"ORIGINAL_CUSTODY.json").read_bytes())
    wanted=[r for r in decode((ROOT/"RECOVERY_INPUTS.json").read_bytes()) if r["key"]==custody["key"]]
    require(len(wanted)==1 and wanted[0]==custody["artifact"]
        and custody["native_executions"]==1 and custody["original_executions"]==0,
        "actual fixed retained input and one new native process")
    def files(root):
        return {p.relative_to(root).as_posix():dict(**pin(p),mode=p.stat().st_mode&0o777)
            for p in sorted(root.rglob("*")) if p.is_file()}
    require(files(capture/"original")==files(retained/"original")==custody["original_files"],
        "every original stream buffer receipt and mode retained byte for byte")
    for name in ("DOMAIN.json","cases.jsonl"):
        require((capture/name).read_bytes()==(retained/name).read_bytes(),"complete unchanged original input "+name)
    require((capture/"config.json").exists()==(retained/"config.json").exists(),"same configuration presence")
    if (capture/"config.json").exists():
        require((capture/"config.json").read_bytes()==(retained/"config.json").read_bytes(),"whole original configuration")
    require(decode((capture/"RETIRED_FIXTURE.json").read_bytes())["root"]==
        decode((retained/"RETIRED_FIXTURE.json").read_bytes())["root"],"same absolute owned physical fixture")
    meta=decode((capture/"CAPTURE.json").read_bytes())
    require(meta["roles"]==[decode((capture/r/"CAPTURE.json").read_bytes()) for r in ("native","original")],
        "both exact actual role receipts")
    return dict(status="COMPLETE_CURRENT124_AND_RETAINED_ORIGINAL_CUSTODY_PASS",
        original_files=len(custody["original_files"]),native_executions=1,original_executions=0)
