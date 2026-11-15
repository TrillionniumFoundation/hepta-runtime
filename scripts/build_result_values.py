# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compile the fixed private result owners and their exact bulk fixture."""
from pathlib import Path
import argparse
import copy
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_value_registry import COMPILER, COMPILER_IMAGE, MODULES, encoded, regular, require, sha, source_pins


def source_composition(root, hepta):
    sys.path.insert(0, str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    parsed = {}
    def program(name):
        if name not in parsed:
            parsed[name] = assemble_program(regular(root / name)).as_dict()
        return parsed[name]
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
    owner = program("native/binary32_json.hepta")
    bulk = program("tests/hia_native/binary32_bulk.hepta")
    require(owner["functions"][1:] == bulk["functions"][1:] and len(owner["functions"]) == 16,
        "bulk fixture does not call the exact production formatter")
    proof = json.loads(regular(root / "native/binary32_json_composition.json"))
    require(proof["source_sha256"] == sha(regular(root / "native/binary32_json.hepta"))
        and proof["bulk_fixture_sha256"] == sha(regular(root / "tests/hia_native/binary32_bulk.hepta"))
        and proof["authoring_pin"] == sha(regular(hepta / "tools/generate_hia_agent_binary64_format.py")),
        "binary32 derivation dependency differs")
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
