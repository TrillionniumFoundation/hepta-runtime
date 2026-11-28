#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the complete configured multi-file call plan as pure HIA."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

SOURCE_SHA = "fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc"
TARGET_SHA = "c0728d40232f18ce6783098cff5a1897f78a4b22f5be0f3c6fec40916455deea"
SUPPORT_SHA = "2587e4a96e56ca33fb92c719fbb11a9a294e3f10c69dea24c679615fb66deda8"
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
LITERALS = {
    1: b"read_multiple_files requires 1..16 paths",
    2: b"max_file_bytes must be 1..65536; larger files require binary_read",
    3: b"max_response_bytes must be 1024..262144",
    4: b"batch paths must be bounded absolute paths without empty, dot or traversal components",
    5: b"read_multiple_files paths must be distinct",
    6: b"read_multiple_files requires a configured operator host",
    101: b'{"files":[', 102: b'{"path":', 103: b',"root":',
    104: b'],"max_file_bytes":', 105: b',"max_response_bytes":',
}
IMPORTS = {"load":"f1","get":"f2","put":"f3","grow":"f4","emit":"f13",
    "emit_word":"f14","emit_span":"f15","json_string":"f17","number":"f18","utf8":"f34"}

def literals():
    text = "\ndef literal(o:mutbuf,w:mutbuf,code:u64) -> u64:\n"
    for code, raw in sorted(LITERALS.items()):
        text += f"    if code=={code}:\n"
        split = len(raw) // 8 * 8
        for at in range(0, split, 8):
            word = int.from_bytes(raw[at:at+8], "little")
            text += f"        emit_word(w,o,{word})\n"
        for byte in raw[split:]:
            text += f"        emit(w,o,{byte})\n"
        text += "        return 0\n"
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
    from source_support import tools, compile_new, identity, ENCODE
    baseline = (runtime / "native/binary_call_plan.hepta").read_bytes()
    if SHA(baseline) != SOURCE_SHA:
        raise ValueError("Original call-plan helpers differ")
    original = (runtime / "src/mcp/runtime/multi_read.rs").read_bytes()
    if SHA(original) != TARGET_SHA:
        raise ValueError("Original multi-file handler differs")
    pseudo_path = Path(__file__).with_name("call_plan.pseudo")
    constants = {name: int.from_bytes(raw, "little") for name, raw in {
        "REQUEST":b"HMRLQ001","RESPONSE":b"HMRLR001","TYPED":b"HMRPR001",
        "CONFIG_REQUEST":b"HRCFGQ01","CONFIG_RESULT":b"HRCFGM01","MODE":b"HRCFMOD1"}.items()}
    constants.update(INVALID=0xffffffff,SHORT=0xfffffffe,LIMIT=0xffff0000)
    raw, names, receipt = compile_new(tools(args.hepta), baseline, IMPORTS,
        pseudo_path.read_text()+literals(), constants, "multi_read_call_plan")
    receipt.update(schema="hepta.runtime.public-multi-read-call-plan.v1",
        aliases=names, constants=constants, original_handler=identity(original),
        authoring_source=identity(Path(__file__).read_bytes()),
        pseudo_source=identity(pseudo_path.read_bytes()), original_validation_order=True,
        original_handler_root_order=True, configuration_operations=[11,12],
        caller_owns_continuation_identity=True, filesystem_effects=False,
        public_route_integrated=False,native_executed=False,original_compared=False,
        whole_runtime_qualified=False)
    output = runtime / "native" if args.output is None else args.output.absolute()
    if args.output is not None:
        output.mkdir(parents=True, exist_ok=False)
    for name, data in [("multi_read_call_plan.hepta",raw),
            ("multi_read_call_plan_composition.json",ENCODE(receipt))]:
        path = output / name
        if path.exists():
            raise ValueError("New owner exists; compare before replacement: "+name)
        path.write_bytes(data)
    print(json.dumps({k:receipt[k] for k in ["schema","source","functions","blocks","operations"]},sort_keys=True))

if __name__=="__main__":
    main()
