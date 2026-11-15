#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create R34 unsealed observation templates using static source transforms only."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "reference-r33"
PREP = HERE.parent / "r34-qualification-prep-01/sealed-01"
OLD_ROOT = "/home/qian/hepta-runtime-optimization-20261106-r33"
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r34"
PREPARER_SHA = "6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f"
INPUT_SHA = "7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e"
OWNER_SHA = "94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9"
MANIFEST_SHA = "d01e66e75985d339dcf04661f1cd3be6bbacab8c9d355148f3e4cf59f6658143"
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
CHANGED = {"src/mcp/runtime/jobs.rs", "src/mcp/runtime/ssh.rs",
           "src/mcp/runtime/ssh_direct.rs", "src/mcp/runtime/ssh_direct_tests.rs"}


def need(value, reason):
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


def once(text, old, new):
    need(text.count(old) == 1, "nonunique transform: " + old[:100])
    return text.replace(old, new, 1)


def rename(text):
    return text.replace(OLD_ROOT, ROOT).replace("r33", "r34").replace("R33", "R34").replace('"h33"', '"h34"')


def normalize(text):
    return text.replace(ROOT, OLD_ROOT).replace("r34", "r33").replace("R34", "R33").replace('"h34"', '"h33"')


def tree(text):
    return ast.dump(ast.parse(text), include_attributes=False)


def functions(text):
    return {n.name: n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}


def segment(text, name):
    return ast.get_source_segment(text, functions(text)[name])


def qualification_binding(original):
    text = rename(original)
    text = once(text,
        'R34_CHANGED_PATHS = {"src/mcp/runtime/ssh_observation_profile.rs",\n                     "src/mcp/runtime/ssh_observation_profile_tests.rs"}',
        'R34_CHANGED_PATHS = {"src/mcp/runtime/jobs.rs", "src/mcp/runtime/ssh.rs",\n                     "src/mcp/runtime/ssh_direct.rs", "src/mcp/runtime/ssh_direct_tests.rs"}')
    text = text.replace('accepted R24 plus peekable traversal and immutable CString path components only',
        'accepted R24 plus ordinary-first existing-job cancellation reserve; four frozen source files')
    text = text.replace('not included in the R34 source change or normal lifecycle adoption',
        'requires a separate saturation proof beyond the normal observation and lifecycle protocol')
    text = text.replace('R34 does not add cancellation reserve capacity; no saturated cancellation proof is claimed',
        'R34 adds a bounded cancellation reserve; its global-8 saturation proof remains a separate gate')
    text = once(text, 'audit, build_inputs, baseline, source_map):',
        'audit, build_inputs, candidate_inputs, baseline, source_map):')
    text = once(text,
        'R24 plus R32 peekable traversal and R34 cached CString components; two profile files only',
        'R24 plus ordinary-first existing-job cancellation reserve; four frozen files only')
    start = text.index('    need(build_inputs["schema"]')
    end = text.index('    need(isinstance(before, dict)', start)
    text = text[:start] + '''    need(build_inputs["schema"] == "hepta-r34-direct-qualification-input/v1"
         and build_inputs.get("sealed") is True and build_inputs["required_missing_bindings"] == []
         and build_inputs["baseline_commit"] == build_inputs["git_parent"] == R34_BASELINE_COMMIT
         and candidate_inputs["schema"] == "hepta-x230-r34-candidate/v1"
         and candidate_inputs["baseline_commit"] == candidate_inputs["git_parent"] == R34_BASELINE_COMMIT
         and candidate_inputs["patch_path"] == "candidate.patch"
         and candidate_inputs["added_paths"] == candidate_inputs["removed_paths"] == []
         and set(candidate_inputs["changed_paths"]) == R34_CHANGED_PATHS
         and HEX.fullmatch(candidate_inputs["patch_sha256"]), "R34 source input receipt differs")
    before = candidate_inputs["baseline_compile_inputs"]
    candidate = candidate_inputs["candidate_compile_inputs"]
''' + text[end:]
    text = text.replace('only the selected profile source and tests', 'only the four selected source and test files')
    text = text.replace('the two-file R24 ablation', 'the four-file R24 ablation')
    text = text.replace('peekable traversal and immutable CString path components on accepted R24',
        'ordinary-first existing-job cancellation reserve on accepted R24')
    text = text.replace('outside the selected profile files', 'outside the four selected files')
    text = once(text, '"qualification_input": ROOT / "input.json",',
        '"qualification_input": ROOT / "qualification-input.json",')
    text = once(text, '"candidate_patch": ROOT / "combined.patch"}',
        '"candidate_patch": ROOT / "candidate/candidate.patch"}')
    text = once(text, '    need(patch_id["sha256"] == build_inputs["patch_sha256"], "reviewed R34 patch bytes differ")',
        '''    need(input_id == {"path": str(fixed["qualification_input"]), "bytes": 3707,
         "sha256": "7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e"},
         "frozen R34 qualification input differs")
    need(launcher_id == {"path": str(fixed["qualification_launcher"]), "bytes": 29912,
         "sha256": "6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f"},
         "frozen R34 preparation launcher differs")
    candidate_inputs, frozen_patch = r34_frozen_candidate(build_inputs, bind)
    need(patch_id == frozen_patch and patch_id["sha256"] == candidate_inputs["patch_sha256"],
         "reviewed R34 patch bytes differ")''')
    text = once(text, 'tests, audit, build_inputs, baseline, source_map)',
        'tests, audit, build_inputs, candidate_inputs, baseline, source_map)')
    text = once(text, 'preparation["combined_patch"]', 'preparation["candidate_patch"]')
    return text


OWNER_HEAD = '''R34_CACHE_OWNER = Path("/home/qian/hepta-runtime-optimization-20261106-r33")
R34_CACHE_OWNER_CLOSURE = {
    "path": str(ROOT / "cache-owner-closure-inputs.json"), "bytes": 4503,
    "sha256": "94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9",
}


def r34_relative_identity(value):
    relative = Path(value["path"])
    need(not relative.is_absolute() and ".." not in relative.parts, "unsafe R34 frozen member")
    return {**value, "path": str(ROOT / relative)}


def bind_r34_chain_and_cache_owner(preparation, build_inputs, bind):
    """Bind R24-plus-R34 source and the rejected, closed R33 cache owner separately."""
    def document(identity):
        return json.loads(bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1])
    expected_input = r34_relative_identity(build_inputs["candidate_input"])
    expected_manifest = r34_relative_identity(build_inputs["candidate_manifest"])
    need(preparation["frozen_candidate_input"] == expected_input
         and preparation["frozen_candidate_manifest"] == expected_manifest
         and preparation["source_materialization"]
         == "accepted R24 source copy plus the frozen R34 patch; R33 supplies build cache only",
         "R34 source provenance differs")
    candidate, patch = r34_frozen_candidate(build_inputs, bind)
    need(preparation["candidate_patch"] == patch, "frozen four-file patch differs")
    closure_id = R34_CACHE_OWNER_CLOSURE
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "actual R33 cache-owner receipt differs")
    owner = r34_cache_owner_closed(document(closure_id), build_inputs["qualification_harness_sha256"], bind)
    need(preparation["cache_owner_closure"] == owner, "preparer and parent owner-closure results differ")
    return {"source_baseline_commit": R34_BASELINE_COMMIT,
        "frozen_candidate_input": expected_input, "frozen_candidate_manifest": expected_manifest,
        "candidate_patch": patch, "changed_paths": sorted(R34_CHANGED_PATHS),
        "cache_owner_closure": closure_id, "cache_owner_proof": owner,
        "r33_source_used_as_baseline": False, "r33_performance_adopted": False,
        "cache_deletion_scope": "the preparer itself deleted zero files; independent prune-01 failed with zero deletions and prune-02 deleted exactly two rebuildable files",
        "current_machine_idle_claimed": False, "original_auditors_reexecuted": False}


'''


def owner_binding(preparer):
    names = ("native_terminal", "closed_stages", "completed_qualification", "native_streams",
             "frozen_candidate", "cache_owner_closed")
    blocks = []
    for name in names:
        text = segment(preparer, name)
        for old, new in (("native_terminal", "r34_owner_native_terminal"),
            ("closed_stages", "r34_owner_closed_stages"),
            ("completed_qualification", "r34_owner_completed_qualification"),
            ("native_streams", "r34_owner_native_streams"),
            ("frozen_candidate", "r34_frozen_candidate"),
            ("cache_owner_closed", "r34_cache_owner_closed"),
            ("relative_identity", "r34_relative_identity"),
            ("CACHE_OWNER", "R34_CACHE_OWNER"), ("BASELINE_COMMIT", "R34_BASELINE_COMMIT"),
            ("CHANGED", "R34_CHANGED_PATHS"), ("STAGES", "R34_QUALIFICATION_STAGES")):
            text = re.sub(r"\b" + old + r"\b", new, text)
        text = text.replace('== source_map(source)', '== qualification_projection(source_inputs(source))')
        if name in ("frozen_candidate", "cache_owner_closed"):
            first, rest = text.split("\n", 1)
            first = first[:-2] + ", bind):"
            reader = '''    def read_bound(identity):
        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]
'''
            text = first + "\n" + reader + rest
        blocks.append(text)
    return OWNER_HEAD + "\n\n\n".join(blocks) + "\n\n"


def main():
    raw = (REFERENCE / "parent-preparation/generated/runner-bundle-manifest.json").read_bytes()
    need(identity(raw)["sha256"] == MANIFEST_SHA, "R33 original manifest differs")
    old_manifest = json.loads(raw)
    original = {}
    for name, pin in old_manifest["files"].items():
        raw = (REFERENCE / "parent-preparation/generated" / name).read_bytes()
        need(identity(raw) == pin, "R33 source differs: " + name)
        original[name] = raw.decode()
    prep_raw = (PREP / "prepare_qualify.py").read_bytes()
    need(identity(prep_raw) == {"bytes": 29912, "sha256": PREPARER_SHA}, "R34 frozen preparer differs")
    input_raw = (PREP / "qualification-input.json").read_bytes()
    need(identity(input_raw) == {"bytes": 3707, "sha256": INPUT_SHA}, "R34 frozen input differs")
    owner_raw = (PREP / "cache-owner-closure-inputs.json").read_bytes()
    need(identity(owner_raw) == {"bytes": 4503, "sha256": OWNER_SHA}, "R34 frozen old-owner input differs")
    binder_raw = (REFERENCE / "parent-preparation/r33_qualification_binding.py").read_bytes()
    need(identity(binder_raw) == {"bytes": 16019, "sha256": "efe7d0cd4523b032146c2bc77cdfccdcd03574ed96f03e90da1164a0fa939def"}, "R33 binder differs")
    binder, owner = qualification_binding(binder_raw.decode()), owner_binding(prep_raw.decode())
    generated = {}
    for name, old in original.items():
        text = rename(old)
        if name == "r33_campaign.py":
            first, last = text.index("R34_BASELINE_COMMIT"), text.index("def commands(")
            text = text[:first] + binder + owner + "\n\n" + text[last:]
        elif name == "install_measurement_tools.py":
            need(text.count('"combined.patch"') == 2 and text.count('"input.json"') == 2,
                 "installer fixed qualification input anchors differ")
            text = text.replace('"combined.patch"', '"candidate/candidate.patch"').replace('"input.json"', '"qualification-input.json"')
        ast.parse(text)
        generated[name.replace("r33", "r34")] = text.encode()
    holder = (REFERENCE / "parent-preparation/mac-launchers-01/held_agent_campaign_02.py").read_bytes()
    need(identity(holder)["sha256"] == HOLDER_SHA, "original held-agent changed")
    ast.parse(holder)
    for name in ("prepare_campaign_inputs.py", "prepare_lifecycle_inputs.py", "r33_lifecycle_campaign.py"):
        need(normalize(generated[name.replace("r33", "r34")].decode()) == original[name],
             "nonbinder protocol changed: " + name)
    restored = normalize(generated["install_measurement_tools.py"].decode())
    restored = restored.replace('"candidate/candidate.patch"', '"combined.patch"').replace('"qualification-input.json"', '"input.json"')
    need(restored == original["install_measurement_tools.py"], "installer changed beyond fixed names")
    old_parent, new_parent = original["r33_campaign.py"], generated["r34_campaign.py"].decode()
    a, b = old_parent.index("R33_BASELINE_COMMIT"), old_parent.index("def commands(")
    c, d = new_parent.index("R34_BASELINE_COMMIT"), new_parent.index("def commands(")
    need(old_parent[:a] == normalize(new_parent[:c]) and old_parent[b:] == normalize(new_parent[d:]),
         "original measurement/control bytes changed")
    old_nodes = functions(old_parent)
    binder_names = set(functions(old_parent[a:b]))
    unchanged = sorted(set(old_nodes) - binder_names)
    new_nodes = functions(normalize(new_parent))
    need(all(ast.dump(old_nodes[name], include_attributes=False) == ast.dump(new_nodes[name], include_attributes=False)
             for name in unchanged), "original measurement/control function differs")
    # Reverse only the explicit owner namespace/reader adaptation. No helper is called.
    owner_nodes = functions(owner)
    compared = []
    for name in ("native_terminal", "closed_stages", "completed_qualification", "native_streams", "frozen_candidate", "cache_owner_closed"):
        new_name = ("r34_" + name) if name in ("frozen_candidate", "cache_owner_closed") else "r34_owner_" + name
        node = owner_nodes[new_name]
        raw = ast.get_source_segment(owner, node)
        if name in ("frozen_candidate", "cache_owner_closed"):
            raw = raw.replace(", bind):", "):", 1)
            raw = once(raw, '    def read_bound(identity):\n        return bind(identity["path"], identity, retain=True, maximum=8 * 1024 * 1024)[1]\n', '')
        for old, new in (("r34_owner_native_terminal", "native_terminal"),
            ("r34_owner_closed_stages", "closed_stages"), ("r34_owner_completed_qualification", "completed_qualification"),
            ("r34_owner_native_streams", "native_streams"), ("r34_frozen_candidate", "frozen_candidate"),
            ("r34_cache_owner_closed", "cache_owner_closed"), ("r34_relative_identity", "relative_identity"),
            ("R34_CACHE_OWNER", "CACHE_OWNER"), ("R34_BASELINE_COMMIT", "BASELINE_COMMIT"),
            ("R34_CHANGED_PATHS", "CHANGED"), ("R34_QUALIFICATION_STAGES", "STAGES")):
            raw = re.sub(r"\b" + old + r"\b", new, raw)
        raw = raw.replace('== qualification_projection(source_inputs(source))', '== source_map(source)')
        need(tree(raw) == tree(segment(prep_raw.decode(), name)), "actual preparer helper semantics changed: " + name)
        compared.append(name)
    files = {name: identity(raw) for name, raw in sorted(generated.items())}
    qualification_inputs = {name: dict(identity((PREP / name).read_bytes()), path=ROOT + "/" + name)
                            for name in ("prepare_qualify.py", "qualification-input.json", "candidate/candidate.patch")}
    manifest = {
        "schema": "hepta-r34-parent-runner-bundle/v1", "sealed": False,
        "status": "UNSEALED_TEMPLATE_ACTUAL_R34_QUALIFICATION_NOT_BOUND",
        "runtime_root": ROOT, "campaign_attempt": "01",
        "reference_parent_tree": "512d2534f09252b5479193660bd5d163e57f7ee0",
        "reference_parent_bundle_sha256": MANIFEST_SHA, "reference_parent_sources": old_manifest["files"],
        "preparation_launcher_sha256": PREPARER_SHA,
        "scope": "accepted R24 plus four-file R34 reserve; normal observation and lifecycle protocol only",
        "changed_lifecycle_measurement_files": old_manifest["changed_lifecycle_measurement_files"],
        "open_blockers": ["saturated-cancellation-capacity"], "files": files,
        "qualification_inputs": qualification_inputs,
        "future_qualification": {"native_job_id": None, "native_terminal_sha256": None,
            "preparation_sha256": None, "qualification_report_sha256": None,
            "formatted_source_map_sha256": None, "test_counts": None,
            "binaries": {name: {"bytes": None, "sha256": None}
                         for name in ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver")}},
        "private_namespaces": {"observation": ["/home/qian/h34n01", "/home/qian/h34b01", "/home/qian/h34c01"],
            "normal_lifecycle_prefix": "/home/qian/r34lc1",
            "recovery": "/home/qian/hepta-runtime-optimization-20261104-r16/r34-cancel-recovery-01"},
        "original_held_agent_sha256": HOLDER_SHA,
        "staging_scope": "local file creation and Python AST/text checks only",
        "x230_calls": 0, "rust_build_or_tests_executed": False,
        "candidate_qualification_status_inferred": False, "campaign_entrypoints_executed": False,
    }
    outputs = {HERE / "generated" / name: raw for name, raw in generated.items()}
    outputs[HERE / "generated/runner-bundle-manifest.json"] = canonical(manifest)
    outputs[HERE / "r34_qualification_binding.py"] = binder.encode()
    outputs[HERE / "cache_owner_binding.py"] = owner.encode()
    for name in ("r34_campaign.py", "r34_lifecycle_campaign.py"):
        outputs[HERE / "mac-launchers-01" / name] = generated[name]
    outputs[HERE / "mac-launchers-01/held_agent_campaign_02.py"] = holder
    for name in ("campaign-inputs-01.example.json", "lifecycle-inputs-01.example.json"):
        value = json.loads(rename((REFERENCE / name).read_text()))
        value["qualification_launcher"] = qualification_inputs["prepare_qualify.py"]
        value["qualification_input"] = qualification_inputs["qualification-input.json"]
        value["candidate_patch"] = qualification_inputs["candidate/candidate.patch"]
        launcher = "r34_campaign.py" if name.startswith("campaign-") else "r34_lifecycle_campaign.py"
        value["launcher_sha256"] = files[launcher]["sha256"]
        if name.startswith("lifecycle-"):
            value["campaign_helpers"] = dict(files["r34_campaign.py"], path=ROOT + "/tools-01/r34_campaign.py")
            value["tools_manifest"]["bytes"] = value["tools_manifest"]["sha256"] = None
        outputs[HERE / name] = canonical(value)
    checks = {
        "schema": "hepta-r34-parent-local-static-checks/v1", "passed": True,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": "AST and exact source/identity checks only; no imported campaign or helper execution",
        "reference_sources_verified": True, "frozen_r34_preparer_verified": True,
        "all_generated_python_ast_parsed": True, "future_qualification_values_null": True,
        "observation_nonbinder_functions_unchanged": unchanged,
        "nonbinder_prefix_suffix_bytes_equal_after_version_root_normalization": True,
        "lifecycle_and_two_materializers_byte_equal_after_version_root_normalization": True,
        "installer_only_version_root_and_qualification_relative_names_changed": True,
        "actual_preparer_helpers_equal_after_reader_namespace_adaptation": compared,
        "harness_threshold_scheduler_sample_timeout_quiet_cleanup_protocol_unchanged": True,
        "qualification_success_claimed": False, "performance_adoption_claimed": False,
        "remote_calls": 0, "rust_build_or_tests_executed": False, "campaign_entrypoints_executed": False,
        "files": files,
    }
    outputs[HERE / "LOCAL_STATIC_CHECKS.json"] = canonical(checks)
    need(not any(os.path.lexists(path) for path in outputs), "create-only template outputs required")
    for path, raw in outputs.items():
        create(path, raw)
    print(json.dumps({"sealed": False, "files": files,
        "manifest": identity(outputs[HERE / "generated/runner-bundle-manifest.json"]),
        "static_checks": identity(outputs[HERE / "LOCAL_STATIC_CHECKS.json"]),
        "campaign_entrypoints_executed": False}, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    main()
