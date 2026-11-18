# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Data corruption controls for complete compiler completion admission."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_session_transport_build import (
    GRAPH, compile_evidence, object_at, read, require, sha,
)
from hia_native_session_transport_admission import inventory, verify_build


def compiler_controls(manifest, root, output):
    manifest, root, output = map(Path, (manifest, root, output))
    require(not output.exists(), "control output is create-only")
    output.mkdir(parents=True, mode=0o700)
    proof = verify_build(manifest, root)
    report = object_at(manifest)
    source, row = sorted(report["semantic_modules"].items())[0]
    build = manifest.parent.parent
    module = build / row["manifest"]
    metadata = object_at(module)
    expected = object_at(root / GRAPH)["sources"][source]
    original = Path(report["build_origin"]) / Path(row["manifest"]).parent
    arguments = (metadata, expected, report["compiler_dependency"], str(original),
                 report["compiler_path_at_execution"])
    saved = {name: read(module.parent / name) for name in
             ("module.stdout.log", "module.receipt.json", "build.json")}
    stdout = json.loads(saved["module.stdout.log"])
    mutations = []
    for name in sorted(stdout):
        mutations.append(("remove-stdout-" + name, "remove", name, None))
    mutations.extend([
        ("coordinated-source-digest", "set", "source_sha256", "0" * 64),
        ("unexpected-stdout-field", "set", "invented_workspace_hash", "0" * 64),
        ("loader-action", "set", "loader_operations", "copy; fixed ABI call"),
        ("output-unchanged", "set", "output_unchanged", True),
        ("negative-native-time", "set", "native_elapsed_ns", -1),
        ("boolean-native-time", "set", "native_elapsed_ns", False),
        ("source-header-length", "header", "0", stdout["workspace_header"]["0"] + 1),
        ("image-header-length", "header", "56", stdout["workspace_header"]["56"] + 1),
        ("missing-header-word", "header-remove", "248", None),
        ("extra-header-word", "header", "32", 0),
        ("boolean-header-word", "header", "8", False),
        ("negative-wall-time", "receipt", "wall_elapsed_ns", -1),
    ])
    results = []
    with tempfile.TemporaryDirectory(prefix="compiler-controls-", dir=output) as temporary:
        folder = Path(temporary) / "module"
        shutil.copytree(module.parent, folder)
        before = inventory(folder)
        baseline = compile_evidence(folder, *arguments)
        require(baseline == row["compile"], "baseline compiler proof differs")
        for name, action, field, value in mutations:
            observed = copy.deepcopy(stdout)
            record = json.loads(saved["module.receipt.json"])
            compiled = json.loads(saved["build.json"])
            if action == "remove":
                del observed[field]
                del record[field]
            elif action == "set":
                observed[field] = value
                record[field] = value
            elif action == "header":
                observed["workspace_header"][field] = value
                record["workspace_header"][field] = value
            elif action == "header-remove":
                del observed["workspace_header"][field]
                del record["workspace_header"][field]
            else:
                require(action == "receipt", "unknown control action")
                record[field] = value
            compiled["compile_receipt"] = record
            changed = {"module.stdout.log": observed, "module.receipt.json": record,
                       "build.json": compiled}
            for filename, content in changed.items():
                (folder / filename).write_text(json.dumps(content, sort_keys=True) + "\n")
            rejected = False
            error = None
            try:
                compile_evidence(folder, *arguments)
            except (ValueError, KeyError, TypeError) as exception:
                rejected, error = True, str(exception)
            finally:
                for filename, content in saved.items():
                    (folder / filename).write_bytes(content)
            require(rejected, "corrupted compiler receipt was admitted: " + name)
            require(inventory(folder) == before and compile_evidence(folder, *arguments) == baseline,
                    "complete compiler capture did not restore after " + name)
            results.append({"name": name, "action": action, "field": field, "value": value,
                            "rejected": True, "error": error, "complete_restore": True})
    after = verify_build(manifest, root)
    require(after == proof, "original complete build changed during data controls")
    result = {"schema": "hepta.runtime.session-compiler-controls.v1", "status": "PASS",
              "build_manifest_sha256": sha(read(manifest)), "module_manifest_sha256": sha(read(module)),
              "source_sha256": sha(read(root / source)), "controls": results,
              "rejections": len(results), "complete_restores": len(results),
              "actual_compilations": 0, "actual_native_executions": 0,
              "actual_original_executions": 0, "whole_runtime_replaced": False}
    (output / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compiler_controls(args.manifest, args.root, args.output)
    print(json.dumps({name: result[name] for name in ("status", "rejections", "complete_restores",
          "actual_compilations", "actual_native_executions", "actual_original_executions")}, sort_keys=True))


if __name__ == "__main__":
    main()
