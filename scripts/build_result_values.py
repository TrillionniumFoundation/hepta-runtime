# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile the fixed private result owners and their exact bulk fixture."""
from pathlib import Path
import argparse
import ast
import copy
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_value_registry import COMPILER, COMPILER_IMAGE, MODULES, encoded, regular, require, sha, source_pins


def source_composition(root, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    parsed = {}
    def program(name):
        if name not in parsed:
            parsed[name] = assemble_program(regular(root / name)).as_dict()
        return parsed[name]
    word_source = ""
    for name, kind, buffer in (("get", "mutbuf", "w"), ("read64", "readbuf", "s")):
        word_source += f"def {name}({buffer}:{kind}, at:u64) -> u64:\n    value = byte({buffer}, at)\n"
        for index in range(1, 8):
            word_source += f"    value = value | (byte({buffer}, at + {index}) << {8 * index})\n"
        word_source += "    return value\n\n"
    word_source += "def put(w:mutbuf, at:u64, value:u64) -> u64:\n"
    for index in range(8):
        word_source += f"    store(w, at + {index}, value >> {8 * index})\n"
    word_source += "    return 0\n"

    def authored_functions(text, names):
        nodes = ast.parse(text).body
        signatures = {node.name: ([arg.annotation.id for arg in node.args.args], node.returns.id)
            for node in nodes}
        result = {}
        for node in nodes:
            builder = Builder(node, names, signatures, total_scalar_functions(nodes))
            builder.statements(node.body)
            function = dict(name=names[node.name], params=[builder.param(p) for p in builder.params],
                returns=[builder.returns], effects=["read", "write", "trap"], entry="b0", blocks=builder.blocks)
            result[function["name"]] = compact_authoring_cfg(dict(schema="hepta.hia.program.v8",
                module="word_helpers", functions=[function]))["functions"][0]
        return result

    def check_word_source(proof):
        require(proof.get("authoring_source") == word_source
            and proof.get("authoring_source_sha256") == sha(word_source.encode()),
            "fixed ordered word helper authoring differs")

    records = {}
    for owner in ("typed_result_json", "request_result"):
        proof = json.loads(regular(root / "native" / (owner + "_composition.json")))
        path = "native/" + owner + ".hepta"
        require(sha(regular(root / path)) == proof["source_sha256"], "frozen owner source changed")
        actual = {f["name"]: f for f in program(path)["functions"]}
        count = 0
        for item in proof["imports"]:
            require(sha(regular(root / item["source"])) == item["sha256"], "import source changed")
            original = {f["name"]: f for f in program(item["source"])["functions"]}
            reverse = {new: old for old, new in item["relocation"].items()}
            for old, new in item["relocation"].items():
                require(sha(canonical(original[old])) == item["functions"][old], "original function changed")
                function = copy.deepcopy(actual[new])
                function["name"] = old
                for block in function["blocks"]:
                    for op in block["ops"]:
                        if op["op"] == "call":
                            op["attrs"]["function"] = reverse[op["attrs"]["function"]]
                require(function == original[old], "native import relocation differs")
                count += 1
        records[owner] = count
        local = proof["local_word_helpers"]
        names = {"read64": "f71", "get": "f72", "put": "f73"} if owner == "typed_result_json" else {
            "read64": "f22", "get": "f23", "put": "f24"}
        require(local.get("schema") == "hepta.runtime.fixed-word-helper-derivation.v1"
            and local.get("source") == "native/text_budget.hepta"
            and local.get("source_sha256") == sha(regular(root / local["source"]))
            and local.get("names") == names and set(local.get("functions", {})) == {"f14", "f15", "f16"},
            "local result word helper dependency differs")
        check_word_source(local)
        expected = authored_functions(word_source, names)
        original = {f["name"]: f for f in program(local["source"])["functions"]}
        for old, name in (("f14", "read64"), ("f15", "get"), ("f16", "put")):
            target = names[name]
            require(local["functions"][old] == dict(target=target,
                before_sha256=sha(canonical(original[old])), after_sha256=sha(canonical(expected[target])))
                and actual[target] == expected[target], "result ordered word helper differs")
        records[owner + "_local_word_helpers"] = 3
    owner = program("native/binary32_json.hepta")
    bulk = program("tests/hia_native/binary32_bulk.hepta")
    require(owner["functions"][1:] == bulk["functions"][1:] and len(owner["functions"]) == 16,
        "bulk fixture does not call the exact production formatter")
    proof = json.loads(regular(root / "native/binary32_json_composition.json"))
    require(proof["source_sha256"] == sha(regular(root / "native/binary32_json.hepta"))
        and proof["bulk_fixture_sha256"] == sha(regular(root / "tests/hia_native/binary32_bulk.hepta"))
        and proof["authoring_pin"] == sha(regular(hepta / "tools/generate_hia_agent_binary64_format.py")),
        "binary32 derivation dependency differs")
    from tools.generate_hia_agent_binary64_format import source_program
    original_nodes = {node.name: node for node in ast.parse(source_program()).body}
    require(set(proof["exact_helper_ast"]) == {"add_big", "bits", "compare_big", "copy_big", "emit",
        "multiply", "normalize", "order_relation", "set64", "shift", "subtract"},
        "binary32 unchanged helper domain differs")
    # Python 3.13+ omits empty fields by default; preserve the full pinned AST.
    dump_options = {"include_attributes": False}
    if sys.version_info >= (3, 13):
        dump_options["show_empty"] = True
    for name, digest in proof["exact_helper_ast"].items():
        require(sha(ast.dump(original_nodes[name], **dump_options).encode()) == digest,
            "binary32 original helper AST differs")
    local = proof["local_word_helpers"]
    check_word_source(local)
    names = {"get": "f14", "put": "f15", "read64": "f6"}
    before = authored_functions("\n\n".join(ast.unparse(original_nodes[name]) for name in names), names)
    expected = authored_functions(word_source, names)
    actual = {function["name"]: function for function in owner["functions"]}
    require(set(local["functions"]) == set(names.values()), "binary32 local helper domain differs")
    for name in names.values():
        require(local["functions"][name] == dict(before=sha(canonical(before[name])), after=sha(canonical(expected[name])))
            and actual[name] == expected[name], "binary32 ordered word helper differs")
    records["binary32_local_word_helpers"] = 3
    records["binary32_exact_bulk_functions"] = 15
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = args.build_root.resolve()
    bundle = build / "result-values-build.json"
    require(not bundle.exists(), "result owner build already exists")
    pins = source_pins(root)
    from hia_native_build import NativeBuild
    compiler = NativeBuild(args.hepta.resolve(strict=True), build)
    compiler.bootstrap()
    composition = source_composition(root, compiler.hepta)
    modules = {}
    for name, (source, source_sha, image_sha) in MODULES.items():
        require(sha(regular(root / source)) == source_sha, "fixed native source differs")
        manifest = compiler.compile("result-" + name, root / source, standalone=None, buffer_profile="serde-json.v1")
        metadata = json.loads(regular(manifest))
        require(metadata["source_sha256"] == source_sha and metadata["image_sha256"] == image_sha,
            "actual native image differs from the qualified owner")
        modules[name] = {"path": str(manifest), "sha256": sha(regular(manifest))}
    require(source_pins(root) == pins, "source changed during native build")
    bundle.write_bytes(encoded(dict(schema="hepta.result-values.native-build.v1", modules=modules,
        compiler_commit=COMPILER, compiler_sha256=COMPILER_IMAGE, sources=pins, composition=composition,
        fresh_cold_qualified=False, production_activated=False, whole_runtime_replaced=False)))
    print(json.dumps(dict(manifest=str(bundle), modules=5, actual_static_elfs=0)))


if __name__ == "__main__":
    main()
