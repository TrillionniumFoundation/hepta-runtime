#!/usr/bin/env python3
"""Author the new Batch adapters from exact, retained HIA owner graphs.

The original Batch parser/serializer helpers remain unchanged. Its new entry
exports a checked envelope containing the complete existing HBPRR002 result.
Gateway/caller policy is reused by exact symbolic ABI relocation, with only
the admitted typed-result validation replaced. No observed answer is an input.
"""
from __future__ import annotations
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import sys

PINS = {
    "batch_edit_params": "c7e14bb0424792cc7fbd90af8321730f721cf327654b796876baaae3c006fb7f",
    "text_editor_gateway": "fc5efb3ef4a4f7679328358764d2b9bd5e3a6d2a5732751c1d53de0533f0c6e8",
    "text_editor_call": "8f0e291eea49ae9f568b0fe803a0446977966b8c7e977ba3ae52fd516d16f22e",
}
MAGICS = {
    "HTEWGQ02": "HBAWGQ02", "HTEWGQ03": "HBAWGQ03",
    "HTEWGS03": "HBAWGS01", "HTEWGA02": "HBAWGA01",
    "HTEPRQ02": "HBPRQ002", "HTEPRR02": "HBAPRR01",
    "HTECQ002": "HBECQ001", "HTECST02": "HBECST01",
    "HTECCA02": "HBECCA01", "HTECLI02": "HBECLI01",
    "HTECLR02": "HBECLR01", "HLCSPQ01": "HBBSPQ01",
    "HLCSPR01": "HBBSPR01", "HTEBDQ02": "HBBBDQ01",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def word(text):
    raw = text.encode("ascii")
    assert len(raw) == 8
    return int.from_bytes(raw, "little")


def signature(function):
    return ([p["type"] for p in function["params"]], function["returns"][0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.hepta.resolve(strict=True)))
    from tools.generate_hia_selfhost import Builder, total_scalar_functions, compact_authoring_cfg
    from hepta.hia_agent_assembly import assemble_program, render_assembly

    class Constants(ast.NodeTransformer):
        def __init__(self, values):
            self.values = values

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in self.values:
                return ast.copy_location(ast.Constant(self.values[node.id]), node)
            return node

    class BulkBuilder(Builder):
        def expr(self, expression):
            if isinstance(expression, ast.Call) and expression.func.id == "move_range":
                assert len(expression.args) == 4 and not expression.keywords
                buf, dst, src, length = [self.expr(x) for x in expression.args]
                self.op("buffer.move_within", [buf, self.cast(dst, "usize"),
                        self.cast(src, "usize"), self.cast(length, "usize")])
                return None
            return super().expr(expression)

    specs = {
        "batch_params": {
            "retained": "batch_edit_params", "replacements": {"entry": "f0", "header": "f46"},
            "aliases": {"scan": "f15", "parse": "f3", "serialize": "f5",
                "unicode_table": "f32", "diagnostic": "f23", "string_emit": "f14",
                "load": "f26", "get": "f27", "put": "f28"},
            "constants": {"RAW_REQUEST": word("HBPRQ002"), "RAW_RESULT": word("HBPRR002"),
                "RESULT": word("HBAPRR01")}, "relocate_magic": False,
        },
        "batch_gateway": {
            "retained": "text_editor_gateway", "replacements": {"after_params": "f1"},
            "aliases": {"region": "f18", "get": "f34", "put": "f35", "finish": "f17",
                "reserve": "f21", "pending_grow": "f23", "prepare": "f11"},
            "constants": {"PARAMS_RESULT": word("HBAPRR01")}, "relocate_magic": True,
        },
        "batch_call": {
            "retained": "text_editor_call", "replacements": {"valid_params": "f1"},
            "aliases": {"load": "f23"},
            "constants": {"PARAMS_RESULT": word("HBAPRR01"), "RAW_RESULT": word("HBPRR002")},
            "relocate_magic": True,
        },
    }
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"schema": "hepta.runtime.rebuilt-batch-adapters-author.v1",
        "new_version_not_lost_private91": True, "observed_result_inputs": False,
        "native_executed": False, "fresh_current_original_compared": False,
        "whole_runtime_replaced": False, "modules": {}}
    magic_values = {word(before): word(after) for before, after in MAGICS.items()}
    for name, spec in specs.items():
        original = (args.source / "retained" / (spec["retained"] + ".hepta")).read_bytes()
        assert sha(original) == PINS[spec["retained"]]
        old = assemble_program(original).as_dict()
        functions = copy.deepcopy(old["functions"])
        old_by_name = {f["name"]: f for f in old["functions"]}
        relocation = {}
        if spec["relocate_magic"]:
            for function in functions:
                changed = []
                for block in function["blocks"]:
                    for operation in block["ops"]:
                        if operation["op"] == "const":
                            value = operation["attrs"]["value"]
                            if type(value) is int and value in magic_values:
                                operation["attrs"]["value"] = magic_values[value]
                                changed.append([value, magic_values[value]])
                if changed:
                    relocation[function["name"]] = changed
        pseudo = (args.source / "authoring" / (name + ".pseudo")).read_bytes()
        constants = {"INVALID": 0xffffffff, "CAPACITY": 0xfffffffe,
                     "MAXIMUM": (1 << 64) - 1, **spec["constants"]}
        nodes = [Constants(constants).visit(node) for node in ast.parse(pseudo).body]
        names = {**spec["aliases"], **spec["replacements"]}
        signatures = {alias: signature(old_by_name[target]) for alias, target in spec["aliases"].items()}
        signatures.update({node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes})
        total = total_scalar_functions(nodes)
        produced = []
        for node in nodes:
            builder = BulkBuilder(node, names, signatures, total)
            builder.statements(node.body)
            produced.append({"name": names[node.name], "params": [builder.param(v) for v in builder.params],
                "returns": [builder.returns], "effects": ["read", "write", "trap"],
                "entry": "b0", "blocks": builder.blocks})
        replacement_names = {f["name"] for f in produced}
        complete_for_compaction = [f for f in functions if f["name"] not in replacement_names] + produced
        compact = compact_authoring_cfg({"schema": old["schema"], "module": "batch_new_functions",
            "functions": complete_for_compaction})["functions"]
        replacements = {f["name"]: f for f in compact if f["name"] in replacement_names}
        functions = [replacements.pop(f["name"], f) for f in functions]
        functions.extend(replacements.values())
        document = {"schema": old["schema"], "module": "runtime_rebuilt_" + name, "functions": functions}
        encoded = render_assembly(document).encode()
        assert assemble_program(encoded).as_dict() == document
        by_name = {f["name"]: f for f in functions}
        changed_set = set(spec["replacements"].values())
        retained = {}
        for fname, function in old_by_name.items():
            if fname in changed_set:
                continue
            current = copy.deepcopy(by_name[fname])
            if spec["relocate_magic"]:
                reverse = {after: before for before, after in relocation.get(fname, [])}
                for block in current["blocks"]:
                    for operation in block["ops"]:
                        if operation["op"] == "const":
                            value = operation["attrs"]["value"]
                            if type(value) is int and value in reverse:
                                operation["attrs"]["value"] = reverse[value]
            assert current == function, (name, fname, "retained graph differs")
            retained[fname] = sha(canonical(function))
        stats = {"functions": len(functions), "blocks": sum(len(f["blocks"]) for f in functions),
            "operations": sum(len(b["ops"]) for f in functions for b in f["blocks"])}
        assert stats["functions"] <= 128 and stats["blocks"] <= 1536 and stats["operations"] <= 8192
        path = args.output / (name + ".hepta")
        assert not path.exists(), path
        path.write_bytes(encoded)
        report["modules"][name] = {"source_bytes": len(encoded), "source_sha256": sha(encoded),
            "retained_source_sha256": sha(original), "retained_source": spec["retained"],
            "pseudo_sha256": sha(pseudo), "replacement_functions": spec["replacements"],
            "abi_constant_relocations": relocation, "retained_function_sha256": retained, **stats}
    report["author_sha256"] = sha(Path(__file__).read_bytes())
    (args.output / "adapter-author-proof.json").write_bytes(canonical(report))
    print(json.dumps({k: {x: v[x] for x in ("source_sha256", "source_bytes", "functions", "blocks", "operations")}
                      for k, v in report["modules"].items()}, sort_keys=True))


if __name__ == "__main__":
    main()
