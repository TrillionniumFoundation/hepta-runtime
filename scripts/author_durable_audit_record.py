# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the exact audit Record type and read-record identity owner."""
from pathlib import Path
import argparse
import hashlib
import json
from author_durable_common import compile_source
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NAMES = [b"request_id", b"owner", b"tool_name", b"state", b"accepted_unix_ms",
         b"elapsed_ms", b"unknown", b"completed", b"failed"]

def authored_source(root):
    source = (root / "scripts/durable_audit_record_source.py.txt").read_text()
    source += "\ndef name_length(code:u64) -> u64:\n"
    for index, raw in enumerate(NAMES, 1):
        source += f"    if code == {index}:\n        return {len(raw)}\n"
    source += "    return 0\n\ndef name_byte(code:u64, index:u64) -> u64:\n"
    for index, raw in enumerate(NAMES, 1):
        source += f"    if code == {index}:\n"
        for offset, value in enumerate(raw):
            source += f"        if index == {offset}:\n            return {value}\n"
        source += "        return 0\n"
    source += "    return 0\n"
    return source

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--hepta", type=Path, required=True)
    p.add_argument("--runtime", type=Path, default=Path(__file__).resolve().parents[1])
    args = p.parse_args()
    root = args.runtime.resolve(strict=True)
    original = (root / "src/mcp/runtime/request_audit.rs").read_bytes()
    imports = [("native/request_storage_json.hepta",
      "3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128",
      dict(string_info="f22", copy_string="f23", decoded="f28", whitespace="f25",
           unsigned="f7", null="f6", read64="f31", get="f29", put="f30"))]
    record = compile_source(root, args.hepta, "durable_audit_record", authored_source(root), {
        "INVALID": 0xffffffff, "CAPACITY": 0xfffffffe,
        "REQUEST": int.from_bytes(b"HRAJQ001", "little"),
        "RESPONSE": int.from_bytes(b"HRAJR001", "little"),
    }, imports)
    record["original_source"] = {"path": "src/mcp/runtime/request_audit.rs", "bytes": len(original), "sha256": SHA(original)}
    record["domain"] = "Record typed JSON and read_record identity; not filesystem or public query authority"
    (root / "native/durable_audit_record_composition.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))
if __name__ == "__main__":
    main()
