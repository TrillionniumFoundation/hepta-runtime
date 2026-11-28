#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the complete MultiReadParams projection as native HIA source."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

BASELINE_SHA = "244a0ff281d5c3a35464d8ad2a0b043bb3525958f82629fcc078dc7f580ae883"
COMPOSITION_SHA = "c2b7bf88a0b94427e6d4c78e74485ea36468a861c6eb5a81e9d97cef27d11228"
TARGET_SHA = "c0728d40232f18ce6783098cff5a1897f78a4b22f5be0f3c6fec40916455deea"
SUPPORT_SHA = "2587e4a96e56ca33fb92c719fbb11a9a294e3f10c69dea24c679615fb66deda8"
FIELDS = [("host", 1), ("paths", 2), ("max_file_bytes", 3), ("max_response_bytes", 4)]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()

def generated_literals():
    expected = "expected one of " + ", ".join(chr(96) + name + chr(96) for name, _ in FIELDS)
    raw = {
        1: b"missing field \x60host\x60",
        2: b"missing field \x60paths\x60",
        3: b"invalid type: ", 4: b", expected ", 5: b"a string",
        6: b"a boolean", 7: b"string or map",
        8: b"invalid value: map, expected map with a single key",
        9: b"unit", 10: b"unknown variant \x60", 11: b"\x60, expected one of ",
        14: b"unknown field \x60", 15: ("\x60, " + expected).encode(),
        16: b"invalid value: ", 17: b"u64", 18: b"a sequence",
        101: b"missing field \x60host\x60", 102: b"missing field \x60paths\x60",
    }
    text = "\ndef literal(w:mutbuf,o:mutbuf,code:u64) -> u64:\n"
    for code, value in sorted(raw.items()):
        text += f"    if code=={code}:\n"
        for byte in value:
            text += f"        emit(w,o,{byte})\n"
        text += "        return 0\n"
    text += "    return 0\n\ndef field_key(s:readbuf,start:u64,end:u64) -> u64:\n"
    for name, field in FIELDS:
        value = json.dumps(name, separators=(",", ":")).encode()
        text += f"    if end-start=={len(value)}:\n        same=1\n"
        split = len(value) // 8 * 8
        for at in range(0, split, 8):
            word = int.from_bytes(value[at:at+8], "little")
            text += f"        if load(s,start+{at})!={word}:\n            same=0\n"
        for at in range(split, len(value)):
            text += f"        if byte(s,start+{at})!={value[at]}:\n            same=0\n"
        text += f"        if same!=0:\n            return {field}\n"
    return text + "    return 0\n"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--runtime", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    support = runtime / "authoring/public_publication_v1/source_support.py"
    if SHA(support.read_bytes()) != SUPPORT_SHA:
        raise ValueError("Authoring support identity differs")
    sys.path.insert(0, str(support.parent))
    from source_support import tools, compile_delta, identity, ENCODE
    source_path = runtime / "qualification/binary_params/v1/source/native/file_info_params.hepta"
    composition_path = source_path.with_name("file_info_params_composition.json")
    baseline = source_path.read_bytes()
    composition_bytes = composition_path.read_bytes()
    if SHA(baseline) != BASELINE_SHA or SHA(composition_bytes) != COMPOSITION_SHA:
        raise ValueError("Original typed helper authority differs")
    target_path = runtime / "src/mcp/runtime/multi_read.rs"
    if SHA(target_path.read_bytes()) != TARGET_SHA:
        raise ValueError("Original MultiReadParams source differs")
    aliases = json.loads(composition_bytes)["aliases"]
    constants = {"INVALID": 0xffffffff, "CAPACITY": 0xfffffffe, "MAXIMUM": (1 << 64) - 1,
        "REQUEST": int.from_bytes(b"HMRPQ001", "little"),
        "RESPONSE": int.from_bytes(b"HMRPR001", "little"), "META": 65536, "KIND": 1}
    pseudo_path = Path(__file__).with_name("params.pseudo")
    pseudo = pseudo_path.read_text() + generated_literals()
    raw, names, receipt = compile_delta(tools(args.hepta), baseline, aliases,
        pseudo, constants, "multi_read_typed_params")
    receipt.update(schema="hepta.runtime.public-multi-read-params.v1", aliases=names,
        constants=constants, target_source=str(target_path.relative_to(runtime)),
        target_source_identity=identity(target_path.read_bytes()),
        original_typed_source=identity(baseline), original_composition=identity(composition_bytes),
        authoring_source=identity(Path(__file__).read_bytes()),
        pseudo_source=identity(pseudo_path.read_bytes()), arbitrary_typed_vec=True,
        vector_business_count_limit_applied=False, public_route_integrated=False,
        native_executed=False, original_compared=False, whole_runtime_qualified=False)
    output = runtime / "native" if args.output is None else args.output.absolute()
    if args.output is not None:
        output.mkdir(parents=True, exist_ok=False)
    for name, data in [("multi_read_params.hepta", raw),
            ("multi_read_params_composition.json", ENCODE(receipt))]:
        path = output / name
        if path.exists():
            raise ValueError("New owner already exists; compare before replacement: " + name)
        path.write_bytes(data)
    print(json.dumps({k: receipt[k] for k in ["schema", "source", "functions", "blocks",
        "operations", "generated_functions"]}, sort_keys=True))

if __name__ == "__main__":
    main()
