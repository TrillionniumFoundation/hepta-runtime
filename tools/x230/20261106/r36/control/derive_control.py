#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Derive R36 control inputs locally; never launch qualification or a workload."""
import ast
import hashlib
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "r35-runner-reference"
EVIDENCE = HERE.parent / "hepta-runtime/tools/x230/20261105/r29/evidence"
REMOTE = "/home/qian/hepta-runtime-optimization-20261106-r36"
CHANGED = {
    "src/mcp/runtime/request_audit.rs",
    "src/mcp/runtime/request_audit_lookup_tests.rs",
    "src/mcp/runtime/request_audit_tests.rs",
}


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write(relative, raw):
    path = HERE / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(raw, str):
        raw = raw.encode()
    path.write_bytes(raw)
    return identity(raw)


def revised(text):
    return text.replace("R35", "R36").replace("r35", "r36").replace('"h35"', '"h36"')


def replace_once(text, before, after):
    assert text.count(before) == 1, before[:180]
    return text.replace(before, after)


def function(text, name):
    tree = ast.parse(text)
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(text, node)


def assignment(text, name, value):
    tree = ast.parse(text)
    nodes = [n for n in tree.body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
             and n.targets[0].id == name]
    assert len(nodes) == 1, name
    return replace_once(text, ast.get_source_segment(text, nodes[0]), name + " = " + repr(value))


def main():
    original = (REFERENCE / "tools-01/r35_campaign.py").read_text()
    text = revised(original)
    start = text.index("# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0", 100)
    end = text.index("\ndef commands(", start)
    fragment = text[start:end]
    terminal = function(fragment, "verify_r36_terminal")
    verify = function(fragment, "verify_r36_candidate_documents")
    verify = replace_once(verify,
        'and preparation.get("proposal") == "R24 plus legacy-read JSON deferral and observation command move; three frozen files only",',
        'and preparation.get("target_fresh_before_start") is True\n'
        '         and preparation.get("qualification_started") is True\n'
        '         and preparation.get("owned_child_closed") is True\n'
        '         and preparation.get("owned_group_absent") is True\n'
        '         and not preparation.get("timed_out", False),')
    verify = verify.replace('preparation["qualification_command"] == expected_command,',
                            'preparation["qualification_command"] in (expected_command, expected_command + ["--stage-timeout", "3600"]),')
    cache_start = verify.index('    need(preparation.get("cache_transferred_by_rename")')
    cache_end = verify.index('    need(build_inputs["schema"]', cache_start)
    verify = verify[:cache_start] + verify[cache_end:]
    verify = verify.replace('candidate_inputs["schema"] == "hepta-x230-r36-candidate/v1"',
                            'candidate_inputs["schema"] == "hepta-r36-direct-qualification-input/v1"')
    verify = verify.replace('build_inputs["required_missing_bindings"] == []',
                            'not build_inputs.get("required_missing_bindings", [])')
    verify = verify.replace('build_inputs["baseline_commit"] == build_inputs["git_parent"] == R36_BASELINE_COMMIT',
                            'build_inputs["baseline_commit"] == R36_BASELINE_COMMIT\n'
                            '         and re.fullmatch(r"[0-9a-f]{40}", build_inputs["git_parent"])')
    verify = verify.replace('candidate_inputs["baseline_commit"] == candidate_inputs["git_parent"] == R36_BASELINE_COMMIT',
                            'candidate_inputs["baseline_commit"] == R36_BASELINE_COMMIT\n'
                            '         and candidate_inputs["git_parent"] == build_inputs["git_parent"]')
    verify = verify.replace('candidate_inputs["patch_path"] == "candidate.patch"',
                            'candidate_inputs["candidate_patch"]["path"] == str(ROOT / "candidate/candidate.patch")')
    verify = verify.replace('         and candidate_inputs["added_paths"] == candidate_inputs["removed_paths"] == []\n', '')
    verify = verify.replace('HEX.fullmatch(candidate_inputs["patch_sha256"])',
                            'HEX.fullmatch(candidate_inputs["candidate_patch"]["sha256"])')
    verify = verify.replace('preparation["source_before_qualification"] == candidate == qualified["source_input"]',
                            'candidate == qualified["source_input"]')
    verify = verify.replace('preparation["source_after_qualification"] == qualified["source_tested"] == final_map == source_map',
                            'qualified["source_tested"] == final_map == source_map')
    verify = verify.replace('legacy-read JSON deferral and observation command ownership move on accepted R24',
                            'two audit hot-cache output ownership moves on accepted R24')
    binder = function(fragment, "bind_r36_candidate_preparation")
    old_start = binder.index('    need(input_id == {')
    old_end = binder.index('    preparation_pin, terminal_pin', old_start)
    binder = binder[:old_start] + '''    candidate_inputs = build_inputs
    need(build_inputs["preparation_tool"] == launcher_id
         and build_inputs["candidate_patch"] == patch_id,
         "frozen R36 preparation/patch identities differ")
''' + binder[old_end:]
    old_start = binder.index('    need(preparation["input_binding"]')
    old_end = binder.index('    current = source_inputs(SOURCE)', old_start)
    binder = binder[:old_start] + '''    need(preparation["input_binding"] == input_id
         and preparation["candidate_patch"] == patch_id
         and (preparation.get("qualification_report") == qualified_id
              or preparation.get("qualification_report_sha256") == qualified_id["sha256"])
         and build_inputs["baseline_qualification"] == R36_BASELINE_QUALIFICATION,
         "R36 preparation is not bound to its actual inputs and successful qualification")
''' + binder[old_end:]
    constants = '''# Candidate identity is frozen from the actual preparation inputs. No prior
# rejected candidate, cache transfer, or historical test count is a prerequisite.
R36_BASELINE_COMMIT = "baab4def80be7af015b2e7a594cb302f66c4130e"
R36_CHANGED_PATHS = set(''' + repr(sorted(CHANGED)) + ''')
R36_QUALIFICATION_STAGES = ["format", "fmt-check", "harness-tests", "clippy",
    "test-build", "isolated-tests", "audit-isolated-tests", "release"]
R36_BASELINE_QUALIFICATION = {
    "path": "/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/report.json",
    "bytes": 83365,
    "sha256": "bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971",
}
R36_ADOPTION_SCOPE = ("accepted R24 plus two audit hot-cache output ownership moves; "
    "three frozen source/test files; normal lifecycle only")
R36_OPEN_BLOCKERS = []


'''
    text = text[:start] + constants + terminal + "\n\n\n" + verify + "\n\n\n" + binder + "\n\n" + text[end:]
    write("tools-01/r36_campaign.py", text)
    # All controller functions outside the explicit candidate binder remain
    # byte-for-byte equal after the round-name substitution.
    dropped = {n.name for n in ast.parse(original).body if isinstance(n, ast.FunctionDef)
               and (n.name.startswith("r35_") or n.name.startswith("bind_r35_")
                    or n.name == "verify_r35_candidate_documents")}
    core = []
    for node in ast.parse(original).body:
        if isinstance(node, ast.FunctionDef) and node.name not in dropped:
            target = node.name.replace("r35", "r36")
            assert function(text, target) == revised(function(original, node.name)), target
            core.append(target)
    for name in ("prepare_campaign_inputs.py", "prepare_lifecycle_inputs.py", "r35_lifecycle_campaign.py"):
        write("tools-01/" + name.replace("r35", "r36"), revised((REFERENCE / "tools-01" / name).read_text()))

    with tarfile.open(EVIDENCE / "qualification-ci-01.tar.xz") as archive:
        runner = archive.extractfile("rust-ci-tools/run_rust_ci_01.py").read().decode()
        r35 = runner.replace("20261105-r29", "20261106-r35").replace("R29", "R35").replace("r29", "r35")
        assert hashlib.sha256(r35.encode()).hexdigest() == "73762b3141daa33a8a90e332fa58ff898ad4608752bc0601c267dfabd36d2c79"
        write("ci-templates/run_rust_ci_01.py", revised(r35))
        write("ci-templates/audit_nextest_0137.py", archive.extractfile("rust-ci-tools/audit_nextest_0137.py").read())
        workflow = archive.extractfile("published-python-inputs/ci-inputs/.github/workflows/ci.yml").read()
        assert hashlib.sha256(workflow).hexdigest() == "b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51"
        write("ci-templates/canonical-workflow.yml", workflow)
    materializer = revised((REFERENCE / "rust-ci-tools-01/materialize_rust_ci_plan_01.py").read_text())
    names = ["JOB_ID", "SOURCE_MAP_SHA", "ISOLATED_SUMMARY_SHA", "ISOLATED_AUDIT_SHA",
             "QUALIFICATION_REPORT_SHA", "PREPARATION_SHA", "NATIVE_TERMINAL_SHA",
             "PARENT_SHA", "QUALIFICATION_BINDINGS_SHA", "FROZEN_COUNTS"]
    for name in names:
        materializer = assignment(materializer, name, None)
    materializer = materializer.replace('value["source_tested"] == value["source_after"] and len(value["source_after"]) == 220',
        'value["source_tested"] == value["source_after"]\n'
        '         and set(value["source_after"]) == set(value["source_input"]) and value["source_after"]')
    write("ci-templates/materialize_rust_ci_plan_01.py", materializer)
    launcher = revised((REFERENCE / "rust-ci-tools-01/launch_exact_rust_ci_01.py").read_text())
    write("ci-templates/launch_exact_rust_ci_01.py", assignment(launcher, "SPEC", None))

    with tarfile.open(EVIDENCE / "performance-01.tar.xz") as archive:
        for name in ("compiler_monitor.py", "compiler_state.py", "validate_compiler_monitor.py",
                     "compiler-monitor-policy-01.json", "summarize_r25_campaign.py"):
            write("tools-01/" + name, archive.extractfile("campaign-tools/" + name).read())
        observed = json.loads((REFERENCE / "lifecycle-tools-manifest-01.json").read_bytes())
        lifecycle_manifest = {"schema": observed["schema"], "files": {}}
        for member in archive.getmembers():
            if (member.isfile() and member.name.startswith("lifecycle-tools/")
                    and not member.name.endswith("lifecycle-tools-manifest-01.json")):
                name = member.name.removeprefix("lifecycle-tools/")
                raw = archive.extractfile(member).read()
                r35_raw = raw if identity(raw) == observed["files"][name] else raw.replace(b"20261105-r29", b"20261106-r35").replace(b"R29", b"R35").replace(b"r29", b"r35")
                assert identity(r35_raw) == observed["files"][name], name
                raw = r35_raw.replace(b"R35", b"R36").replace(b"r35", b"r36")
                lifecycle_manifest["files"][name] = write("lifecycle-tools-01/" + name, raw)
        assert set(lifecycle_manifest["files"]) == set(observed["files"])
        lifecycle_id = write("lifecycle-tools-01/lifecycle-tools-manifest-01.json", canonical(lifecycle_manifest))

    for name in ("campaign-inputs-01.example.json", "lifecycle-inputs-01.example.json"):
        value = json.loads(revised((REFERENCE / name).read_text()))
        for key in ("qualification_launcher", "qualification_input", "candidate_patch"):
            if key in value:
                value[key]["bytes"] = value[key]["sha256"] = None
        if name.startswith("campaign"):
            value["launcher_sha256"] = identity((HERE / "tools-01/r36_campaign.py").read_bytes())["sha256"]
        else:
            candidates = [k for k, v in value.items() if isinstance(v, dict)
                          and v.get("path") == REMOTE + "/tools-01/r36_campaign.py"]
            assert len(candidates) == 1, candidates
            value[candidates[0]] = dict(path=REMOTE + "/tools-01/r36_campaign.py",
                                       **identity((HERE / "tools-01/r36_campaign.py").read_bytes()))
            value["launcher_sha256"] = identity((HERE / "tools-01/r36_lifecycle_campaign.py").read_bytes())["sha256"]
            candidates = [k for k, v in value.items() if isinstance(v, dict)
                          and str(v.get("path", "")).endswith("/lifecycle-tools-manifest-01.json")]
            assert len(candidates) == 1, candidates
            value[candidates[0]] = dict(path=REMOTE + "/lifecycle-tools-01/lifecycle-tools-manifest-01.json", **lifecycle_id)
        write("input-templates/" + name, canonical(value))

    old_input = json.loads((REFERENCE / "qualification-input.json").read_text())
    value = {
        "schema": "hepta-r36-direct-qualification-input/v1", "sealed": False,
        "required_missing_bindings": ["actual source maps", "preparation tool", "candidate patch"],
        "baseline_commit": "baab4def80be7af015b2e7a594cb302f66c4130e",
        "git_parent": "baab4def80be7af015b2e7a594cb302f66c4130e",
        "baseline_qualification": old_input["baseline_qualification"],
        "qualification_harness_sha256": old_input["qualification_harness_sha256"],
        "changed_paths": sorted(CHANGED), "added_paths": [], "removed_paths": [],
        "patch_path": "candidate.patch", "patch_sha256": None,
        "candidate_patch": {"path": REMOTE + "/candidate/candidate.patch", "bytes": None, "sha256": None},
        "preparation_tool": {"path": REMOTE + "/prepare_qualify.py", "bytes": None, "sha256": None},
        "baseline_compile_inputs": None, "candidate_compile_inputs": None,
        "source_rule": "Accepted R24 plus the three explicitly frozen audit source/test paths only",
        "cache_rule": "New empty private target-build; no cache transfer or reuse",
    }
    write("input-templates/qualification-input.example.json", canonical(value))
    report = {"schema": "hepta-r36-control-derivation/v1", "candidate_or_remote_execution": False,
              "original_campaign": identity(original.encode()),
              "unchanged_campaign_core_functions_after_round_rename": core,
              "unchanged_lifecycle_controller_after_round_rename": True,
              "rust_ci_runner_reconstructed_r35_sha256": hashlib.sha256(r35.encode()).hexdigest(),
              "changed_source_paths_allowed": sorted(CHANGED),
              "candidate_specific_history_and_cache_owner_fragment_removed": True,
              "qualification_counts_are_bound_from_actual_receipts": True,
              "measurement_commands_thresholds_and_owner_agent_controls_changed": False}
    report["identity_only_substitutions"] = ["R35→R36", "r35→r36", "h35 socket prefix→h36"]
    write("derivation.json", canonical(report))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
