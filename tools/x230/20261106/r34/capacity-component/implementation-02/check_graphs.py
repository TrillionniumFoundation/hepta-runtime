#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal actual offline component locks/metadata without invoking Cargo or an ELF.

The metadata files must be original retained outputs of the explicit offline
commands in BUILD.md. This verifies inputs; it never reports a compilation pass.
"""
import argparse
import json
import os
from pathlib import Path
import tomllib

import prepare_build as binding


def lock_packages(raw):
    return {(row["name"], row["version"], row.get("source")): row
            for row in tomllib.loads(raw.decode())["package"]}


def graph(metadata, arm, preparation, baseline, selected):
    root = Path(preparation["root"])
    plan = preparation["plan"]
    source = Path(plan["arms"][arm]["source_root"])
    workspace = root / "arms" / arm
    binding.need(Path(metadata["workspace_root"]) == workspace
                 and Path(metadata["target_directory"]) == root / "target-component",
                 "metadata used a different workspace/shared target")
    package_rows = {row["id"]: row for row in metadata["packages"]}
    names = {}
    for identifier, row in package_rows.items():
        name, version, origin = row["name"], row["version"], row.get("source")
        if origin is None:
            binding.need((name, version) in {("hepta-runtime", "0.1.0"), ("hepta-direct-capacity-component", "0.0.0")},
                         "unexpected local path package")
            expected = source / "Cargo.toml" if name == "hepta-runtime" else workspace / "Cargo.toml"
            binding.need(Path(row["manifest_path"]) == expected, "local dependency manifest path differs")
            names[identifier] = name + "@" + version + "|local"
        else:
            binding.need((name, version, origin) in baseline and (name, version, origin) in selected,
                         "metadata registry package is not in both this resolved lock and the accepted lock")
            names[identifier] = name + "@" + version + "|" + origin
    root_id = metadata["resolve"]["root"]
    binding.need(names[root_id] == "hepta-direct-capacity-component@0.0.0|local", "component is not the resolver root")
    result = []
    for node in metadata["resolve"]["nodes"]:
        row = package_rows[node["id"]]
        binding.need(not (row["name"] == "rmcp" and "client" in node["features"]), "test-only rmcp client feature enabled")
        result.append({"package": names[node["id"]], "features": sorted(node["features"]),
                       "deps": sorted((edge["name"], names[edge["pkg"]],
                                       json.dumps(edge["dep_kinds"], sort_keys=True)) for edge in node["deps"])})
    return sorted(result, key=lambda row: row["package"])


def run(root, metadata_paths, output):
    root = root.resolve(strict=True)
    prep_raw = binding.regular(root / "preparation.json")
    prep = json.loads(prep_raw)
    plan_raw = binding.regular(root / "input.json")
    plan = json.loads(plan_raw)
    binding.need(prep["schema"] == "hepta-r34-capacity-component-preparation/v1"
                 and prep["plan_sha256"] == binding.sha(plan_raw)
                 and prep["build_order"] == ["A", "B"]
                 and prep["shared_target"] == str(root / "target-component"), "component preparation differs")
    baseline_raw = binding.regular(root / "reference/runtime-Cargo.lock")
    baseline = lock_packages(baseline_raw)
    graphs, locks, observations = {}, {}, {}
    for arm in ("A", "B"):
        runtime = plan["arms"][arm]
        binding.full_map(runtime["source_root"], runtime["compile_inputs"])
        binding.full_map(runtime["source_root"], runtime["include_inputs"])
        binding.qualified_arm(arm, runtime)
        binding.need(binding.regular(Path(runtime["source_root"]) / "Cargo.lock") == baseline_raw, "runtime lock changed")
        for name, identity in prep["files"].items():
            if name.startswith("arms/" + arm + "/") and not name.endswith("/Cargo.lock"):
                body = binding.regular(root / name)
                binding.need(len(body) == identity["bytes"] and binding.sha(body) == identity["sha256"], "prepared component source changed")
        lock_raw = binding.regular(root / "arms" / arm / "Cargo.lock")
        selected = lock_packages(lock_raw)
        for key, row in selected.items():
            if row.get("source") is None:
                binding.need(key[:2] in {("hepta-runtime", "0.1.0"), ("hepta-direct-capacity-component", "0.0.0")}, "unexpected component local dependency")
            else:
                binding.need(key in baseline and row.get("checksum") == baseline[key].get("checksum"), "locked registry identity/checksum changed")
        binding.need(("hepta-direct-capacity-component", "0.0.0", None) in selected, "seed lock was never resolved for the component root")
        locks[arm] = {"path": str(root / "arms" / arm / "Cargo.lock"), "bytes": len(lock_raw), "sha256": binding.sha(lock_raw)}
        metadata_raw = binding.regular(metadata_paths[arm], 32 * 1024 * 1024)
        metadata = json.loads(metadata_raw)
        graphs[arm] = graph(metadata, arm, {"root": str(root), "plan": plan}, baseline, selected)
        observations[arm] = {"path": str(metadata_paths[arm]), "bytes": len(metadata_raw), "sha256": binding.sha(metadata_raw)}
    binding.need(graphs["A"] == graphs["B"], "A/B normalized package/feature graphs differ")
    report = {"schema": "hepta-r34-capacity-component-graphs/v1", "passed": True,
              "preparation": {"path": str(root / "preparation.json"), "bytes": len(prep_raw), "sha256": binding.sha(prep_raw)},
              "plan_sha256": binding.sha(plan_raw), "locks": locks, "metadata": observations,
              "normalized_graph": graphs["A"], "shared_registry_identities_equal_to_accepted_lock": True,
              "ab_graphs_equal_after_local_path_normalization": True,
              "runtime_sources_rechecked_unchanged": True, "cargo_invoked_by_this_tool": False,
              "compilation_established": False, "binary_identity_established": False}
    binding.need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output),
                 "create-only graph receipt required")
    binding.create(output, binding.encoded(report))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--metadata-a", type=Path, required=True)
    parser.add_argument("--metadata-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.prepared, {"A": args.metadata_a, "B": args.metadata_b}, args.output)
    print(json.dumps({"passed": report["passed"], "compilation_established": False, "output": str(args.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
