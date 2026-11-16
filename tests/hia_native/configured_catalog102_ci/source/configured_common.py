"""Source and complete-buffer contracts for the configured catalog successor."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "retained"))
import static_common as retained
import read_static_build as retained_build

BASE = retained.BASE
sha, pin, encoded, put = retained.sha, retained.pin, retained.encoded, retained.put
TRUSTED_PROFILE = (ROOT / "source-profile.json").read_bytes() if (ROOT / "source-profile.json").exists() else None
FLAGS = (0, 1, 3, 5, 7, 9, 11, 13, 15)
TARGET = "d3d75c30719db966b004756f610007a7c723729e"
WORKSPACE = 22152
MODULES = {
    "catalog-eleven": ("retained/native/runtime_mcp_catalog_eleven.hepta", "a06073afcfbd748dfcb5bceeec8ed2fff1f44a6cfda3bec2ec0e9af443c0e258", "history.v1"),
    "catalog-configured": ("native/runtime_mcp_catalog_configured.hepta", "ec6609841b61d72631c6ea77d05d112f30b810421364fd077b7afaf2d9174f1f", "history.v1"),
    "frontend-base": ("entry_baseline/runtime_mcp.hepta", "68aa8e005ed38ff778988e0a75bc19588da44de703c0ecc2e642675b5799fdd5", "history.v1"),
    "frontend-configured": ("native/runtime_mcp.hepta", "6e0862f7dde67a3eca7db6f0c79ee36c942d4fc552449dad939016b16fb6d9aa", "history.v1"),
}


def source_check(source=ROOT):
    reader = BASE.Reader(source)
    raw = reader.raw("source-profile.json")
    assert raw == TRUSTED_PROFILE
    profile = BASE.parse(raw)
    assert profile["schema"] == "hepta.runtime.catalog-configured-source.v1"
    assert profile["target_commit"] == TARGET
    actual = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
    assert actual == set(profile["files"]) | {"source-profile.json"}
    for name, expected in profile["files"].items(): reader.raw(name, expected)
    retained.source_check(source / "retained")
    proof = reader.document("native/catalog_configured_composition.json")
    assert proof["source_sha256"] == MODULES["catalog-configured"][1]
    assert proof["author_sha256"] == sha(reader.raw("author_configured.py"))
    assert proof["baseline_source_sha256"] == MODULES["catalog-eleven"][1]
    assert proof["all_old_helpers_exact"] is True and proof["workspace_required"] == WORKSPACE
    assert proof["expected_original_wire_used_as_implementation"] is False
    assert proof["decoder_access_proof"]["native_execution"] is False
    frontend = reader.document("native/catalog_frontend_composition.json")
    assert frontend["source_sha256"] == MODULES["frontend-configured"][1]
    assert frontend["author_sha256"] == sha(reader.raw("author_frontend.py"))
    assert frontend["installed_capability_mask"] == 1 and frontend["config_phase"] == 18
    assert frontend["entry_inverse_restores_exact_baseline"] is True
    assert frontend["bellman_public_route_installed"] is False
    assert reader.document("DOMAIN.json") == specification(source)
    return reader, proof, frontend


def build_check(build, source=ROOT):
    previous = retained_build.SOURCE_PINS
    try:
        retained_build.SOURCE_PINS = MODULES
        return retained_build.build_check(build, source)
    finally:
        retained_build.SOURCE_PINS = previous


def frame(mode, flags, installed):
    return b"HRMCD002" + struct.pack("<4Q", 7, mode, flags, installed)


def projected_asset(source, mode, flags, installed):
    assert mode in (0, 1) and flags in FLAGS and installed in range(4)
    raw = (source / f"retained/native/catalog-mode-{mode}.bin").read_bytes()
    marker = raw.index(b'"tools":[')
    common = raw[marker:]
    proof = json.loads((source / "native/catalog_configured_composition.json").read_bytes())
    chunks = []
    for span in proof["spans"]:
        index = span["index"]
        if index == 0 and not installed & 1: continue
        if index == 9 and not installed & 2: continue
        if span["runtime_only"] and not flags & 1: continue
        chunk = common[span["start"]:span["start"] + span["bytes"]]
        assert sha(chunk) == span["sha256"]
        chunks.append(chunk)
    return raw[:marker] + b'"tools":[' + b",".join(chunks) + b"]}}"


def cases(source=ROOT):
    rows = []
    for previous in retained.cases(source / "retained"):
        rows.append({"name":"retained-" + previous["name"], "wire":previous["wire"],
            "output_capacity":previous["output_capacity"], "workspace_capacity":previous["workspace_capacity"],
            "kind":"retained", "group":("retained-" + previous["group"]) if previous["group"] else None,
            "owners":["catalog-eleven", "catalog-configured"]})
    def add(name, wire, oc=20000, wc=WORKSPACE+17, *, invalid=False, group=None):
        rows.append({"name":name,"wire":wire,"output_capacity":oc,"workspace_capacity":wc,
            "kind":"invalid" if invalid else "configured","group":group,"owners":["catalog-configured"]})
    for installed in range(4):
        for flags in FLAGS:
            for mode in (0, 1):
                add(f"matrix-{installed}-{flags}-{mode}", frame(mode, flags, installed))
    for installed in (0, 1, 3):
        for flags in (0, 15):
            for mode in (0, 1):
                size = 32 + len(projected_asset(source, mode, flags, installed))
                for oc in sorted({0,31,32,33,size-1,size,size+1}):
                    add(f"output-{installed}-{flags}-{mode}-{oc}",frame(mode,flags,installed),oc)
                for wc in (0,6959,6960,WORKSPACE-1,WORKSPACE,WORKSPACE+1):
                    add(f"workspace-{installed}-{flags}-{mode}-{wc}",frame(mode,flags,installed),size+17,wc)
    good = frame(1, 15, 3)
    for size in range(40): add(f"configured-truncated-{size}",good[:size],invalid=True)
    for suffix in (b"\0", b"extra payload"):
        add("configured-trailing-"+str(len(suffix)),good+suffix,invalid=True)
    for index in range(8):
        wire=bytearray(good);wire[index]^=0x80
        add(f"configured-magic-{index}",bytes(wire),invalid=True)
    for mode in (2,255,1<<63,(1<<64)-1):add(f"configured-mode-{mode}",frame(mode,15,3),invalid=True)
    for flags in (2,4,6,8,10,12,14,16,255,1<<63,(1<<64)-1):
        add(f"configured-flags-{flags}",frame(1,flags,3),invalid=True)
    for installed in (4,255,1<<63,(1<<64)-1):
        add(f"configured-installed-{installed}",frame(1,15,installed),invalid=True)
    for index,(mode,flags,installed) in enumerate(((1,15,3),(0,0,1),(2,1,1),(1,1,0),(0,13,2),(1,0,3),(0,15,1))):
        add(f"configured-dirty-{index}",frame(mode,flags,installed),invalid=mode>1,group="configured-dirty")
    assert len({row["name"] for row in rows}) == len(rows)
    return rows


def specification(source=ROOT):
    rows=cases(source)
    return {"schema":"hepta.runtime.catalog-configured-domain.v1", "target_commit":TARGET,
        "flags":list(FLAGS),"installed_masks":[0,1,2,3],"protocol_modes":[0,1],
        "retained_cases":len(retained.cases(source/"retained")),"retained_non_list_operations":18,
        "case_count":len(rows),"actual_native_calls":sum(len(row["owners"]) for row in rows),
        "cases":[{**{k:v for k,v in row.items() if k!="wire"},"wire_hex":row["wire"].hex()} for row in rows],
        "native_replay_seconds":180,"sdk_reference_replay_seconds":60,
        "complete_input_output_workspace":True,"public102_installed_mask":1,
        "public_all_configuration_qualified":False,"public_handler_admission_qualified":False,
        "whole_runtime_replaced":False}
