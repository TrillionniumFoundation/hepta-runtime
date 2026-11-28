# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Author the REA Unix path and same-descriptor metadata policy in HIA.

This is a development author. The product is a pure HIA module. A separate
closed descriptor owner executes its admitted filesystem effects.
"""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("hepta", "runtime", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.hepta = args.hepta.resolve(strict=True)
    args.runtime = args.runtime.resolve(strict=True)
    args.output.mkdir(mode=0o700, exist_ok=False)
    compiler = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=args.hepta).decode().strip()
    if compiler != "d3e2c90173cf733e42b299d0c4274df4b593a12f":
        raise ValueError("REA file policy author requires the pinned compiler")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta))
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    source_path = Path(__file__).with_name("rea_file_policy_source.py.txt")
    body = source_path.read_text()
    constants = {
        "REQUEST_MAGIC": int.from_bytes(b"HREAFPL1", "little"),
        "RESPONSE_MAGIC": int.from_bytes(b"HRFPLAN1", "little"),
    }
    code = re.sub(r"\b(" + "|".join(constants) + r")\b",
                  lambda match: str(constants[match[0]]), body)
    nodes = ast.parse(code).body
    if not nodes or not all(isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError("file policy author input must contain only functions")
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {
        node.name: ([param.annotation.id for param in node.args.args], node.returns.id)
        for node in nodes
    }
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            "name": names[node.name],
            "params": [builder.param(value) for value in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks,
        })
    doc = compact_authoring_cfg({
        "schema": "hepta.hia.program.v8",
        "module": "hepta_runtime_rea_file_policy",
        "functions": functions,
    })
    raw = render_assembly(doc).encode()
    assembled = assemble_program(raw).as_dict()
    if assembled["functions"] != doc["functions"]:
        raise ValueError("file policy assembly roundtrip differs")
    operations = sum(len(block["ops"]) for fun in assembled["functions"]
                     for block in fun["blocks"])
    if operations > 8192 or len(assembled["functions"]) > 128:
        raise ValueError("file policy exceeds the original native compiler limits")
    digest = lambda data: hashlib.sha256(data).hexdigest()
    origins = {}
    for name in ("src/mcp/rea_files.rs", "src/mcp/rea_files_tests.rs"):
        data = (args.runtime / name).read_bytes()
        origins[name] = {"bytes": len(data), "sha256": digest(data)}
    manifest = {
        "schema": "hepta.runtime.rea-file-policy-composition.v1",
        "source_sha256": digest(raw), "source_bytes": len(raw),
        "author_input_sha256": digest(body.encode()),
        "compiler_commit": compiler, "functions": names, "instruction_count": operations,
        "original_sources": origins, "request_magic": "HREAFPL1",
        "response_magic": "HRFPLAN1",
        "operations": {"1": "ordered-absolute-root-path-plan",
                       "2": "same-fd-eleven-field-metadata-equality",
                       "3": "private-regular-single-link-uid-mode0600"},
        "filesystem_effects_performed": False,
        "descriptor_owner_qualified": False, "public_route_qualified": False,
        "whole_runtime_replaced": False,
    }
    (args.output / "rea_file_policy.hepta").write_bytes(raw)
    (args.output / "composition.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    (args.output / "author-input.py.txt").write_text(code)
    (args.output / "author.py").write_bytes(Path(__file__).read_bytes())
    (args.output / "source.py.txt").write_bytes(source_path.read_bytes())
    print(json.dumps({"source_sha256": digest(raw), "source_bytes": len(raw),
                      "functions": len(assembled["functions"]),
                      "instructions": operations,
                      "descriptor_owner_qualified": False}, sort_keys=True))

if __name__ == "__main__":
    main()

