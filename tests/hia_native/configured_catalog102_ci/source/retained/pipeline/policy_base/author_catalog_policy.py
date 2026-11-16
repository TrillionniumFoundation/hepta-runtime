"""Lower a full AST policy; author inputs contain no observed result wires."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
FROZEN_REA = {"rea_inspect_elf_notes", "rea_get_evidence_bundle",
    "rea_inspect_apk_signature_evidence", "rea_inspect_analysis_view",
    "rea_export_evidence_bundle", "rea_import_evidence_bundle"}
FIELDS = ("type", "anyOf", "oneOf", "$schema", "format", "default", "properties", "$defs", "name", "inputSchema")

def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

def generate(hepta: Path, source: Path, destination: Path):
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(hepta))
    from tools.generate_hia_selfhost import Builder, total_scalar_functions, compact_authoring_cfg
    from hepta.hia_agent_assembly import render_assembly, assemble_program
    asset_raw = (source / "declarations.json").read_bytes()
    asset = json.loads(asset_raw)
    assert set(asset) == {"schema", "target_commit", "raw_tool_wires", "runtime_tool_names", "weight_tool_names", "hia_tool_names"}
    assert asset["target_commit"] == TARGET
    tools = [json.loads(value) for value in asset["raw_tool_wires"]]
    names = [tool["name"] for tool in tools]
    assert len(names) == 136 and names == sorted(set(names))
    classes = []
    table = bytearray()
    for name in names:
        encoded = name.encode("ascii")
        flags = (int(name in asset["runtime_tool_names"]) |
            (int(name in asset["hia_tool_names"]) << 1) |
            (int(name in asset["weight_tool_names"]) << 2) |
            (int(name in FROZEN_REA) << 3) |
            (int(name.startswith("rea_static_")) << 4) |
            (int(name == "shell") << 5))
        table.extend(bytes((len(encoded), flags)) + encoded)
        classes.append({"name": name, "classification": flags})
    assert 8192 + len(table) <= 16384
    assert len(asset["hia_tool_names"]) + len(FROZEN_REA) == 17
    literal = bytearray()
    field_records = []
    for field in FIELDS:
        field_records.append((7168 + len(literal), len(field)))
        literal.extend(field.encode())
    null_text = 7168 + len(literal)
    literal.extend(b"null")
    prefix_offset = 7168 + len(literal)
    prefix = b'{"resultType":"complete","tools":'
    literal.extend(prefix)
    suffix_offset = 7168 + len(literal)
    suffix = b',"ttlMs":0,"cacheScope":"public"}'
    literal.extend(suffix)
    assert 7168 + len(literal) < 8192
    constants = {"MAGIC_REQUEST": int.from_bytes(b"HCATCQ01", "little"),
        "MAGIC_REPLY": int.from_bytes(b"HCATCR01", "little"),
        "NULL_TEXT": null_text, "PREFIX_OFFSET": prefix_offset, "PREFIX_BYTES": len(prefix),
        "SUFFIX_OFFSET": suffix_offset, "SUFFIX_BYTES": len(suffix)}
    def packed_function(name, offset, data, records=()):
        lines = [f"def {name}(w: mutbuf) -> u64:"]
        for index, (position, size) in enumerate(records):
            lines.extend((f"    put(w, {6400 + index * 16}, {position})", f"    put(w, {6408 + index * 16}, {size})"))
        for position in range(0, len(data), 8):
            word = int.from_bytes(data[position:position + 8].ljust(8, b"\0"), "little")
            lines.append(f"    put(w, {offset + position}, {word})")
        lines.append("    return 0")
        return "\n".join(lines) + "\n"
    pseudo_raw = (source / "catalog_policy.pseudo").read_bytes()
    author_text = pseudo_raw.decode() + "\n" + packed_function("init_literals", 7168, literal, field_records) + "\n" + packed_function("init_names", 8192, table)
    nodes = ast.parse(author_text).body
    class ConstantSubstitution(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
    nodes = [ConstantSubstitution().visit(node) for node in nodes]
    names_map = {node.name: f"f{index}" for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    class BulkBuilder(Builder):
        def expr(self, expression):
            if isinstance(expression, ast.Call) and expression.func.id in {"copy_span", "copy_workspace"}:
                assert len(expression.args) == 5 and not expression.keywords
                args = [self.expr(value) for value in expression.args]
                dst, src, dp, sp, count = args
                loan = None
                if expression.func.id == "copy_workspace":
                    loan = self.op("borrow.read", [src], "readbuf")
                    src = loan
                self.op("buffer.copy_range", [dst, src, self.cast(dp, "usize"), self.cast(sp, "usize"), self.cast(count, "usize")])
                if loan:
                    self.op("loan.end", [loan])
                return None
            return super().expr(expression)
    functions = []
    for node in nodes:
        builder = BulkBuilder(node, names_map, signatures, total)
        builder.statements(node.body)
        functions.append({"name": names_map[node.name], "params": [builder.param(value) for value in builder.params],
            "returns": [builder.returns], "effects": ["read", "write", "trap"], "entry": "b0", "blocks": builder.blocks})
    document = compact_authoring_cfg({"schema": "hepta.hia.program.v8", "module": "runtime_catalog_policy", "functions": functions})
    encoded = render_assembly(document).encode()
    assert assemble_program(encoded).as_dict() == document
    stats = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in document["functions"]),
        "operations": sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"])}
    assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192, stats
    assert len(encoded) <= 1048576
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "catalog_policy.hepta"
    path.write_bytes(encoded)
    proof = {"schema": "hepta.runtime.catalog-policy-author.v1", "target_commit": TARGET,
        "author_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "pseudo_sha256": hashlib.sha256(pseudo_raw).hexdigest(), "declarations_sha256": hashlib.sha256(asset_raw).hexdigest(),
        "source_sha256": hashlib.sha256(encoded).hexdigest(), "source_bytes": len(encoded), **stats,
        "classifications": classes, "function_map": names_map,
        "allowed_asset_keys": sorted(asset), "expected_result_input": False,
        "node_stride": 96, "nodes_base": 16384, "parser_stack": [1024, 6144],
        "field_table": [6400, 6560], "literal_table": [7168, 7168 + len(literal)],
        "name_table": [8192, 8192 + len(table)], "full_runtime_qualified": False}
    (destination / "author-proof.json").write_bytes(canonical(proof))
    return proof

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.hepta, args.source, args.output)
    print(json.dumps({key: result[key] for key in ("source_sha256", "source_bytes", "functions", "blocks", "operations")}, sort_keys=True))

if __name__ == "__main__":
    main()
