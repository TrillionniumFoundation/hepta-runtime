#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the trusted-root bootstrap for the existing native-local read ELF."""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CANON = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def literal_functions(literals):
    lines = ["def literal(o:mutbuf,w:mutbuf,code:u64) -> u64:"]
    for code, value in literals.items():
        raw = value.encode()
        lines.append(f"    if code=={code}:")
        end = len(raw) // 8 * 8
        for at in range(0, end, 8):
            lines.append(f"        emit_word(o,w,{int.from_bytes(raw[at:at+8], 'little')})")
        for byte in raw[end:]:
            lines.append(f"        emit(o,w,{byte})")
        lines.append("        return 0")
    lines += ["    return 0", "", "def power10(index:u64) -> u64:"]
    for index in range(10):
        lines += [f"    if index=={index}:", f"        return {10 ** (9-index)}"]
    return "\n" + "\n".join(lines + ["    return 1", ""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    baseline_path = ROOT / "native/config_directory_owner_span.hepta"
    baseline = baseline_path.read_bytes()
    original = copy.deepcopy(next(fn for fn in assemble_program(baseline).as_dict()["functions"]
                                  if fn["name"] == "f44"))
    if (original["returns"] != ["u64"] or
            [p["type"] for p in original["params"]] != ["readbuf", "u64", "u64"] or
            any(op["op"] == "call" for block in original["blocks"] for op in block["ops"])):
        raise ValueError("retained UTF-8 owner signature or closure changed")
    pseudo_path = ROOT / "scripts/native_read_bootstrap.pseudo"
    wire_path = ROOT / "native/native_read_bootstrap_wire.json"
    wire = json.loads(wire_path.read_bytes())
    constants = {"INVALID": 0xffffffff, "OUTPUT_SHORT": 0xfffffffe,
                 "WORK_SHORT": 0xfffffffd, "LIMIT": 0xffff0000,
                 "REQUEST": int.from_bytes(b"HLRBQ001", "little"),
                 "RESPONSE": int.from_bytes(b"HLRBR001", "little")}
    pseudo = pseudo_path.read_text() + literal_functions(wire["bootstrap_literals"])
    pseudo = re.sub(r"\b(" + "|".join(constants) + r")\b",
                    lambda match: str(constants[match[0]]), pseudo)
    nodes = ast.parse(pseudo).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
                  for node in nodes}
    names["utf8"] = "f" + str(len(nodes))
    signatures["utf8"] = (["readbuf", "u64", "u64"], "u64")
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                              returns=[builder.returns], effects=["read", "write", "trap"],
                              entry="b0", blocks=builder.blocks))
    retained = copy.deepcopy(original)
    retained["name"] = names["utf8"]
    document = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
                                         module="native_read_bootstrap", functions=functions + [retained]))
    document["functions"][-1] = retained
    raw = render_assembly(document).encode()
    actual = assemble_program(raw).as_dict()
    if render_assembly(actual).encode() != raw or actual["functions"][-1] != retained:
        raise ValueError("generated source/retained UTF-8 round trip differs")
    source = ROOT / "native/native_read_bootstrap.hepta"
    source.write_bytes(raw)
    record = {
        "schema": "hepta.runtime.native-read-bootstrap-source.v1",
        "source": str(source.relative_to(ROOT)), "source_sha256": SHA(raw), "source_bytes": len(raw),
        "functions": names, "function_sha256": {fn["name"]: SHA(CANON(fn)) for fn in actual["functions"]},
        "pseudo_sha256": SHA(pseudo_path.read_bytes()), "wire_sha256": SHA(wire_path.read_bytes()),
        "author_sha256": SHA(Path(__file__).read_bytes()),
        "retained_utf8": {"source": str(baseline_path.relative_to(ROOT)), "source_sha256": SHA(baseline),
                          "original_function": "f44", "function_sha256": SHA(CANON(original))},
        "inherited_bootstrap_commit": "819ed071a9ddd37643d52ef442cf54fd92de2945",
        "profile": "explicit-native-local-read",
        "configured_host_alias_mapping": False, "default_public_route": False,
        "ssh_lifecycle_qualified": False, "whole_runtime_replaced": False,
    }
    source.with_name("native_read_bootstrap_composition.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"source_sha256": record["source_sha256"], "source_bytes": len(raw),
                      "functions": len(actual["functions"])}))


if __name__ == "__main__":
    main()
