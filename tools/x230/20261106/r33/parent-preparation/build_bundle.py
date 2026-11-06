#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create an unsealed R33 parent bundle from pinned original sources; no workload."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
OLD_ROOT = "/home/qian/hepta-runtime-optimization-20261105-r30"
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r33"
MANIFEST_SHA = "2c70eae7cf272689391a49693d4d1587205a2c89e8bb30c36fd1852736873744"
PREP_MANIFEST_SHA = "aaabf3c54ec60e527688d2492c9d0ebe076d98b5e59911c72214c1b11319bbb6"
PREPARE_SHA = "c1e6ef1bf6d4a1c42a644a220ab00a5b14b95281e76e24f94526d367a07f351d"
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
BINDER_NAMES = {"verify_r30_terminal", "verify_r30_candidate_documents", "bind_r30_candidate_preparation"}
OWNER_NAMES = {"native_terminal", "closed_stages", "completed_qualification", "cache_owner_closed"}


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def rename(text):
    return text.replace(OLD_ROOT, ROOT).replace("r30", "r33").replace("R30", "R33").replace('"h30"', '"h33"')


def normalize(text):
    return text.replace(ROOT, OLD_ROOT).replace("r33", "r30").replace("R33", "R30").replace('"h33"', '"h30"')


def tree(text):
    return ast.dump(ast.parse(text), include_attributes=False)


def functions(text):
    return {node.name: node for node in ast.parse(text).body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def main():
    original_dir, prep_dir = HERE / "reference-r30", HERE / "reference-r33"
    original_raw = (original_dir / "runner-bundle-manifest.json").read_bytes()
    require(identity(original_raw)["sha256"] == MANIFEST_SHA, "original R30 manifest changed")
    manifest = json.loads(original_raw)
    original = {}
    for name, pin in manifest["files"].items():
        raw = (original_dir / name).read_bytes()
        require(identity(raw) == pin, "original R30 parent changed: " + name)
        original[name] = raw.decode()
        ast.parse(raw)
    prep_manifest_raw = (prep_dir / "package-manifest.json").read_bytes()
    require(identity(prep_manifest_raw)["sha256"] == PREP_MANIFEST_SHA, "frozen R33 prepare manifest changed")
    prep_manifest = json.loads(prep_manifest_raw)
    for name in ("prepare_qualify.py", "input.json", "chain-proof.json", "cache-owner-closure-inputs.json"):
        require(identity((prep_dir / name).read_bytes()) == prep_manifest["files"][name], "R33 input changed: " + name)
    prep_text = (prep_dir / "prepare_qualify.py").read_text()
    require(hashlib.sha256(prep_text.encode()).hexdigest() == PREPARE_SHA, "preparer changed")
    holder = (original_dir / "held_agent_campaign_02.py").read_bytes()
    require(identity(holder)["sha256"] == HOLDER_SHA, "original held agent changed")
    ast.parse(holder)
    qualification_binding = (HERE / "r33_qualification_binding.py").read_text()
    cache_binding = (HERE / "cache_owner_binding.py").read_text()
    ast.parse(qualification_binding)
    ast.parse(cache_binding)
    generated = {}
    for name, old in original.items():
        text = rename(old)
        if name == "r30_campaign.py":
            first, last = text.index("R33_BASELINE_COMMIT"), text.index("def commands(")
            text = text[:first] + qualification_binding + cache_binding + "\n\n" + text[last:]
        elif name == "install_measurement_tools.py":
            require(text.count('"candidate.patch"') == 2, "installer patch references changed")
            text = text.replace('"candidate.patch"', '"combined.patch"')
        ast.parse(text)
        require("h30" not in text and "r30lc" not in text and "20261105-r33" not in text,
                "old private namespace survived")
        generated[name.replace("r30", "r33")] = text

    # Whole non-binder protocol comparisons. These execute no parent functions.
    for name in ("prepare_campaign_inputs.py", "prepare_lifecycle_inputs.py", "r30_lifecycle_campaign.py"):
        require(tree(normalize(generated[name.replace("r30", "r33")])) == tree(original[name]),
                "a protocol/materializer changed beyond version and root: " + name)
    require(tree(normalize(generated["install_measurement_tools.py"]).replace('"combined.patch"', '"candidate.patch"'))
            == tree(original["install_measurement_tools.py"]), "installer protocol changed")
    old_parent = original["r30_campaign.py"]
    new_parent = generated["r33_campaign.py"]
    a, b = old_parent.index("R30_BASELINE_COMMIT"), old_parent.index("def commands(")
    c, d = new_parent.index("R33_BASELINE_COMMIT"), new_parent.index("def commands(")
    require(old_parent[:a] == normalize(new_parent[:c])
            and old_parent[b:] == normalize(new_parent[d:]), "measurement/control body changed")
    old_functions = functions(old_parent)
    new_functions = functions(normalize(new_parent))
    unchanged = sorted(set(old_functions) - BINDER_NAMES)
    require(all(ast.dump(old_functions[name], include_attributes=False)
                == ast.dump(new_functions[name], include_attributes=False) for name in unchanged),
            "an original observation measurement/control function changed")

    # The four old-owner readers come from the actually launched frozen R33
    # preparer. Only namespaces and the existing stable file reader are adapted.
    owner_expected = prep_text[prep_text.index("def native_terminal("):prep_text.index("\ndef main():")]
    owner_expected = (owner_expected.replace("native_terminal(", "r33_owner_native_terminal(")
        .replace("closed_stages(", "r33_owner_closed_stages(")
        .replace("completed_qualification(", "r33_owner_completed_qualification(")
        .replace("cache_owner_closed(value, harness):", "r33_cache_owner_closed(value, harness, bind):")
        .replace("CACHE_OWNER", "R33_CACHE_OWNER").replace("BASELINE_COMMIT", "R33_BASELINE_COMMIT")
        .replace("== STAGES", "== R33_QUALIFICATION_STAGES")
        .replace("== source_map(source)", "== qualification_projection(source_inputs(source))")
        .replace("json.loads(read_bound(identity))", "json.loads(bind(identity['path'], identity, retain=True)[1])"))
    actual_owner = cache_binding[cache_binding.index("def r33_owner_native_terminal("):]
    require(tree(owner_expected) == tree(actual_owner), "frozen owner closure semantics changed")
    input_value = json.loads((prep_dir / "input.json").read_bytes())
    require(input_value["baseline_commit"] == input_value["git_parent"] == "baab4def80be7af015b2e7a594cb302f66c4130e",
            "R24 is not the direct source baseline")
    require(len(input_value["baseline_compile_inputs"]) == len(input_value["candidate_compile_inputs"]) == 220,
            "two-file input count differs")
    require(set(input_value["changed_paths"]) == {"src/mcp/runtime/ssh_observation_profile.rs",
                                                  "src/mcp/runtime/ssh_observation_profile_tests.rs"},
            "wrong candidate scope")
    files = {name: identity(text.encode()) for name, text in generated.items()}
    future = {"native_job_id": None, "native_terminal_sha256": None, "preparation_sha256": None,
              "qualification_report_sha256": None, "formatted_source_map_sha256": None,
              "test_counts": None,
              "binaries": {name: {"bytes": None, "sha256": None}
                           for name in ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver")}}
    result = {"schema": "hepta-r33-parent-runner-bundle/v1", "sealed": False,
              "status": "UNSEALED_TEMPLATE_ACTUAL_R33_QUALIFICATION_NOT_BOUND",
              "runtime_root": ROOT, "campaign_attempt": "01",
              "reference_parent_bundle_sha256": MANIFEST_SHA,
              "reference_parent_sources": manifest["files"],
              "preparation_package_manifest_sha256": PREP_MANIFEST_SHA,
              "scope": "accepted R24 plus peekable traversal and immutable CString path components; normal lifecycle only",
              "changed_lifecycle_measurement_files": manifest["changed_lifecycle_measurement_files"],
              "open_blockers": ["saturated-cancellation-capacity"],
              "files": files,
              "qualification_inputs": {name: dict(prep_manifest["files"][name], path=ROOT + "/" + name)
                                       for name in ("prepare_qualify.py", "input.json", "combined.patch")},
              "future_qualification": future,
              "private_namespaces": {
                  "observation": ["/home/qian/h33n01", "/home/qian/h33b01", "/home/qian/h33c01"],
                  "normal_lifecycle_prefix": "/home/qian/r33lc1",
                  "recovery": "/home/qian/hepta-runtime-optimization-20261104-r16/r33-cancel-recovery-01"},
              "original_held_agent_sha256": HOLDER_SHA,
              "staging_scope": "Mac file creation and Python AST checks only",
              "x230_calls": 0, "rust_build_or_tests_executed": False,
              "candidate_qualification_status_inferred": False,
              "campaign_entrypoints_executed": False}
    checks = {"schema": "hepta-r33-parent-local-static-checks/v1",
              "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "passed": True,
              "original_r30_sources_sha_verified": True, "frozen_r33_prepare_sources_sha_verified": True,
              "all_generated_python_ast_parsed": True, "all_qualification_future_values_null": True,
              "observation_nonbinder_functions_unchanged": unchanged,
              "observation_nonbinder_prefix_and_suffix_bytes_equal_after_normalization": True,
              "lifecycle_and_two_materializers_ast_equal_after_normalization": True,
              "installer_ast_equal_except_version_root_and_combined_patch_filename": True,
              "four_cache_owner_helpers_equal_to_launched_preparer_after_reader_namespace_adaptation": True,
              "harness_threshold_scheduler_sample_timeout_quiet_cleanup_protocol_unchanged": True,
              "private_namespaces_revised": result["private_namespaces"],
              "qualification_success_claimed": False, "performance_adoption_claimed": False,
              "campaign_entrypoints_executed": False, "x230_calls": 0,
              "rust_build_or_tests_executed": False, "files": files}
    outputs = {HERE / "generated" / name: text.encode() for name, text in generated.items()}
    outputs[HERE / "generated/runner-bundle-manifest.json"] = canonical(result)
    outputs[HERE / "LOCAL_STATIC_CHECKS.json"] = canonical(checks)
    for name in ("r33_campaign.py", "r33_lifecycle_campaign.py"):
        outputs[HERE / "mac-launchers-01" / name] = generated[name].encode()
    outputs[HERE / "mac-launchers-01/held_agent_campaign_02.py"] = holder
    require(not any(path.exists() or path.is_symlink() for path in outputs), "fresh create-only outputs required")
    for path, raw in outputs.items():
        create(path, raw)
    print(json.dumps({"created": True, "directory": str(HERE / "generated"),
                      "manifest": identity(outputs[HERE / "generated/runner-bundle-manifest.json"]),
                      "files": files, "checks": identity(outputs[HERE / "LOCAL_STATIC_CHECKS.json"]),
                      "sealed": False, "campaign_entrypoints_executed": False}, sort_keys=True), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()
