#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Extend the HIA composition packer with bounded successful-worker retirement.

GNU binutils are authoring tools only. Runtime bytes are emitted by the HIA
packer, compiled by the pinned HIA compiler. The unchanged 43 original
functions remain source-bound, with f0 relocated to f43 and its eight metadata
address constants shifted to make room for the new adapter fragment.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE_REF = "abc9ecb95ee9538518ec3f36c47b881974107021"
BASE_SOURCE_SHA = "4367179d1c4776853d5c9542db6582b24be2c59c76ac8d1c347d6373cb297d5a"
BASE_PREFIX_SHA = "db41d6cf9664e59dcd216e2d0c7df398fc945c8df0a7e73b6137c97dfbf73273"
BASE_METADATA = 8752
METADATA_HOLE = 228
HANDOFF = 0x181a
OLD_HANDOFF = bytes.fromhex("e8a1fcffff")
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def git_file(path):
    return subprocess.run(["git", "-C", str(ROOT), "show", BASE_REF + ":" + path],
                          check=True, stdout=subprocess.PIPE).stdout


def assemble_shim():
    source = ROOT / "scripts/native_read_ready_reap.S"
    with tempfile.TemporaryDirectory(prefix="hia-ready-reap-author-") as name:
        work = Path(name)
        subprocess.run(["as", "--64", "-o", str(work / "shim.o"), str(source)], check=True)
        subprocess.run(["ld", "--build-id=none", "-Ttext=" + hex(0x400000 + BASE_METADATA),
                        "-e", "guard_ready_reap", "-o", str(work / "shim.elf"),
                        str(work / "shim.o")], check=True)
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text",
                        str(work / "shim.elf"), str(work / "shim.bin")], check=True)
        return (work / "shim.bin").read_bytes()


def wrapper(shim, metadata):
    """No writes occur unless the original admission and capacity checks pass."""
    params = [{"name": "v0", "type": "readbuf"}, {"name": "v1", "type": "mutbuf"},
              {"name": "v2", "type": "mutbuf"}]
    ops = [
        {"op": "call", "args": ["v0", "v1", "v2"], "attrs": {"function": "f43"},
         "out": [{"name": "v3", "type": "u32"}]},
        {"op": "const", "args": [], "attrs": {"value": 0xffff0000},
         "out": [{"name": "v4", "type": "u32"}]},
        {"op": "compare.lt", "args": ["v3", "v4"], "attrs": {},
         "out": [{"name": "v5", "type": "bool"}]},
    ]
    first = {"id": "b0", "params": copy.deepcopy(params), "ops": ops,
             "term": {"op": "branch", "cond": "v5",
                      "then": {"target": "b1", "args": ["v1", "v3"]},
                      "else": {"target": "b2", "args": ["v3"]}}}
    writes = []
    next_id = 9

    def value(number):
        nonlocal next_id
        name = "v" + str(next_id)
        next_id += 1
        writes.append({"op": "const", "args": [], "attrs": {"value": number},
                       "out": [{"name": name, "type": "u64"}]})
        return name

    def emit(at, raw):
        nonlocal next_id
        offset, word, count = value(at), value(int.from_bytes(raw, "little")), value(len(raw))
        name = "v" + str(next_id)
        next_id += 1
        writes.append({"op": "call", "args": ["v6", offset, word, count],
                       "attrs": {"function": "f24"}, "out": [{"name": name, "type": "u64"}]})

    jump = b"\xe9" + struct.pack("<i", BASE_METADATA - HANDOFF - 5)
    emit(HANDOFF, jump)
    padded = shim + bytes(metadata - BASE_METADATA - len(shim))
    for at in range(0, len(padded), 8):
        emit(BASE_METADATA + at, padded[at:at+8])
    blocks = [first,
              {"id": "b1", "params": [{"name": "v6", "type": "mutbuf"},
                                     {"name": "v7", "type": "u32"}],
               "ops": writes, "term": {"op": "ret", "values": ["v7"]}},
              {"id": "b2", "params": [{"name": "v8", "type": "u32"}],
               "ops": [], "term": {"op": "ret", "values": ["v8"]}}]
    return {"name": "f0", "params": params, "returns": ["u32"],
            "effects": ["read", "write", "trap"], "entry": "b0", "blocks": blocks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--baseline-elf", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    baseline_raw = git_file("native/composition_packer.hepta")
    if SHA(baseline_raw) != BASE_SOURCE_SHA:
        raise ValueError("original source identity differs")
    base = assemble_program(baseline_raw).as_dict()
    functions = {fn["name"]: fn for fn in base["functions"]}
    if list(functions) != ["f" + str(i) for i in range(43)]:
        raise ValueError("original function set or order differs")
    if any(op["op"] == "call" and op["attrs"].get("function") == "f0"
           for fn in base["functions"] for block in fn["blocks"] for op in block["ops"]):
        raise ValueError("original root is internally referenced")
    prefix = bytearray(args.baseline_elf.read_bytes()[:BASE_METADATA])
    prefix[96:112] = bytes(16)
    if SHA(prefix) != BASE_PREFIX_SHA or prefix[HANDOFF:HANDOFF+5] != OLD_HANDOFF:
        raise ValueError("original runtime prefix identity differs")
    shim = assemble_shim()
    if not 64 <= len(shim) <= 256:
        raise ValueError("unexpected ready-reap fragment extent")
    metadata = (BASE_METADATA + len(shim) + 15) & -16

    retained = copy.deepcopy(functions["f0"])
    retained["name"] = "f43"
    relocations = [(14, "v96", 8752), (63, "v987", 8520), (63, "v990", 8752),
                   (63, "v993", 8760), (63, "v995", 8776), (63, "v997", 8784),
                   (63, "v1000", 8792), (65, "v1036", 8816)]
    changes = []
    for block_index, block in enumerate(retained["blocks"]):
        for op in block["ops"]:
            if op["op"] == "const" and 8000 <= op["attrs"].get("value", 0) < 10000:
                site = (block_index, op["out"][0]["name"], op["attrs"]["value"])
                changes.append(site)
                op["attrs"]["value"] += metadata - BASE_METADATA
    if changes != relocations:
        raise ValueError("metadata relocation sites differ")
    restored = copy.deepcopy(retained)
    restored["name"] = "f0"
    for block_index, name, old_value in relocations:
        matches = [op for op in restored["blocks"][block_index]["ops"]
                   if op["op"] == "const" and op["out"][0]["name"] == name]
        if len(matches) != 1 or matches[0]["attrs"]["value"] != old_value + metadata - BASE_METADATA:
            raise ValueError("relocated metadata value differs")
        matches[0]["attrs"]["value"] = old_value
    if restored != functions["f0"]:
        raise ValueError("original root changed beyond its eight metadata addresses")

    document = copy.deepcopy(base)
    document["functions"] = [wrapper(shim, metadata)] + base["functions"][1:] + [retained]
    raw = render_assembly(document).encode()
    actual = assemble_program(raw).as_dict()
    if render_assembly(actual).encode() != raw or actual != document:
        raise ValueError("HIA source round trip differs")
    if actual["functions"][1:43] != base["functions"][1:43]:
        raise ValueError("an original non-root function changed")

    prefix[METADATA_HOLE:METADATA_HOLE+4] = struct.pack("<i", metadata - METADATA_HOLE - 4)
    prefix[HANDOFF:HANDOFF+5] = b"\xe9" + struct.pack("<i", BASE_METADATA - HANDOFF - 5)
    prefix.extend(shim)
    prefix.extend(bytes(metadata - len(prefix)))
    source = ROOT / "native/composition_packer.hepta"
    source.write_bytes(raw)
    record = {
        "schema": "hepta.runtime.composition-ready-reap-source.v1",
        "base_runtime_commit": BASE_REF, "base_source_sha256": BASE_SOURCE_SHA,
        "source_sha256": SHA(raw), "source_bytes": len(raw),
        "author_sha256": SHA(Path(__file__).read_bytes()),
        "assembly_sha256": SHA((ROOT / "scripts/native_read_ready_reap.S").read_bytes()),
        "shim_sha256": SHA(shim), "shim_hex": shim.hex(), "shim_bytes": len(shim),
        "shim_offset": BASE_METADATA, "handoff_offset": HANDOFF,
        "handoff_original_hex": OLD_HANDOFF.hex(),
        "handoff_replacement_hex": prefix[HANDOFF:HANDOFF+5].hex(),
        "base_metadata_offset": BASE_METADATA, "metadata_offset": metadata,
        "metadata_hole": METADATA_HOLE, "metadata_relocations": changes,
        "elf_template_bytes": BASE_METADATA + len(shim),
        "elf_prefix_normalized_sha256": SHA(prefix),
        "base_elf_prefix_normalized_sha256": BASE_PREFIX_SHA,
        "retained_entry": "f43",
        "original_functions_sha256": {fn["name"]: SHA(CANON(fn)) for fn in base["functions"]},
        "retained_non_entry_functions_unchanged": True,
        "specific_owned_pid_only": True, "original_absolute_deadline_unchanged": True,
        "poll_quantum_nanoseconds": 1000000,
        "timed_out_worker_retirement_unchanged": True,
        "default_public_routes_added": 0, "whole_runtime_replaced": False,
    }
    (ROOT / "native/composition_ready_reap.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    proof = json.loads(git_file("native/scope_os_packer_provenance.json"))
    proof.update({key: record[key] for key in ("source_sha256", "elf_template_bytes",
                                             "metadata_offset", "elf_prefix_normalized_sha256")})
    proof["ready_reap_extension"] = {
        "source": "native/composition_ready_reap.json",
        "source_sha256": SHA((ROOT / "native/composition_ready_reap.json").read_bytes()),
        "baseline_packer_sha256": BASE_SOURCE_SHA,
        "retained_sha_functions_unchanged": True,
    }
    (ROOT / "native/scope_os_packer_provenance.json").write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: record[key] for key in ("source_sha256", "source_bytes", "shim_bytes",
                                                  "metadata_offset", "elf_prefix_normalized_sha256")}))


if __name__ == "__main__":
    main()
