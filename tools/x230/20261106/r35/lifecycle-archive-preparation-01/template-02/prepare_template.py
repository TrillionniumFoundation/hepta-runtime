#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Construct Python source from reviewed text; never import or run the collector."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
REFERENCE = HERE.parent / "r35-observation-archive-template-recovery-01/archive_r35_observation.py"
REFERENCE_SHA = "96fa3ff43180ec0e922c4b6373ec9d7a902037d97ae06d9a774ebf318d9f1f2c"
PROTOCOL_SHA = "c9fd58c7aaebd51f60f1a2fdc3a01c52629b41d5a5818be124c79a547735872e"


def need(value, reason):
    if not value:
        raise ValueError(reason)


def replace_once(source, before, after):
    need(source.count(before) == 1, "exact source replacement count differs: " + before[:90])
    return source.replace(before, after)


def change_assignment(source, name, expression):
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id == name]
    need(len(nodes) == 1, "assignment missing or duplicated: " + name)
    lines = source.splitlines(keepends=True)
    lines[nodes[0].lineno - 1:nodes[0].end_lineno] = [name + " = " + expression + "\n"]
    return "".join(lines)


def change_function(source, name, replacement):
    nodes = [node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(nodes) == 1, "function missing or duplicated: " + name)
    lines = source.splitlines(keepends=True)
    lines[nodes[0].lineno - 1:nodes[0].end_lineno] = [replacement.rstrip() + "\n"] if replacement else []
    return "".join(lines)


def create(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    original = REFERENCE.read_bytes()
    need(hashlib.sha256(original).hexdigest() == REFERENCE_SHA, "reviewed safe collector reference changed")
    source = original.decode()
    pins = json.loads((HERE / "static-pins.json").read_bytes())
    need(len(pins) == 71, "known static input selection differs")
    core = (
        "lifecycle-holder-native-01.json", "lifecycle-holder-read-01.json", "lifecycle-holder-report-01.json",
        "lifecycle-materialization-native-01.json", "lifecycle-materialization-read-01.json",
        "lifecycle-inputs-01.json",
        "lifecycle-campaign-01/report.json", "lifecycle-campaign-01/inputs.json",
        "lifecycle-campaign-01/plan.json", "lifecycle-campaign-01/source-inputs.json",
        "lifecycle-campaign-01/baseline-source-inputs.json",
        "lifecycle-campaign-01/compiler-monitor.json", "lifecycle-campaign-01/compiler-monitor.audit.json",
        "lifecycle-abba-01/report.json", "lifecycle-abba-01/plan.json",
        "lifecycle-abba-01/round-index.json", "lifecycle-abba-01/summary.json", "lifecycle-abba-01/gates.json",
        "lifecycle-tool-tests-01/report.json",
    )
    source = replace_once(source,
        '"""Archive the original R35 ordinary OBS snapshot without rerunning it.',
        '"""Archive the original R35 normal lifecycle evidence, including failed attempts.')
    source = change_assignment(source, "REFERENCE_SHA", repr(REFERENCE_SHA))
    source = change_assignment(source, "STAGES", repr(("lifecycle-tool-tests", "normal-lifecycle-abba")))
    source = change_assignment(source, "SELECTED_DIRS",
        repr(("lifecycle-campaign-01", "lifecycle-abba-01", "lifecycle-tool-tests-01", "tools-01", "lifecycle-tools-01")))
    source = change_assignment(source, "EXTERNAL_DIRS", "()")
    source = change_assignment(source, "OPTIONAL_FILES", "()")
    source = change_assignment(source, "STATIC_PINS", pprint.pformat(pins, sort_dicts=True, width=120))
    source = change_assignment(source, "DYNAMIC_REQUIRED",
        repr(("lifecycle-holder-native-01.json", "lifecycle-holder-read-01.json")))
    source = change_assignment(source, "NAMESPACE_PATHS", "CORE_FILES + RESULT_DIRS + ('cancel-saturation-01',)")
    source = change_assignment(source, "REQUIRED",
        "tuple(sorted(set(STATIC_PINS) | set(ACTUAL['sha256'] if ACTUAL is not None else {})))")
    additions = (
        "FROZEN = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')\n"
        "FROZEN_PREFIX = 'external/frozen-jobs/'\n"
        "PROTOCOL_REFERENCE_SHA = " + repr(PROTOCOL_SHA) + "\n"
        "HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'\n"
        "OBSERVATION_ARCHIVE_SHA = '941e03e20ddcab8baa6049b806e2b447242055abb2f72eefb2a6ed87a9a74b8c'\n"
        "RESULT_DIRS = ('lifecycle-campaign-01', 'lifecycle-abba-01', 'lifecycle-tool-tests-01')\n"
        "REQUIRED_DIRS = ('tools-01', 'lifecycle-tools-01')\n"
        "CORE_FILES = " + pprint.pformat(core, width=120) + "\n"
        "NORMAL_STAGES = tuple(name for n, arm in enumerate('ABBA') for name in "
        "(f'canary-{n}-{arm}', f'audit-{n}-{arm}')) + ('summary', 'normal-lifecycle-gates')\n"
        "LIFECYCLE_PHASES = ('prepare', 'launch', 'before_crash_running', 'after_transport_running', "
        "'after_crash_running', 'same_key_after_crash', 'concurrent_cancel', 'terminal', "
        "'terminal_after_restart', 'same_key_after_cancel', 'cancel_after_terminal')\n"
        "COUNTER_KEYS = ('native_calls', 'independent_ssh_calls', 'new_starts', 'same_key_lookups', "
        "'cancellations', 'automatic_rpc_retries')\n"
    )
    source = replace_once(source, "NAMESPACE_PATHS = ", additions + "NAMESPACE_PATHS = ")
    source = replace_once(source, "SKIP_FILES = {", "SKIP_FILES = {'profile.json', ")
    source = replace_once(source,
        "    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R35/R16 mapping')",
        "    if path.is_relative_to(PurePosixPath(str(FROZEN))):\n"
        "        return FROZEN_PREFIX + path.relative_to(PurePosixPath(str(FROZEN))).as_posix()\n"
        "    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R35/R16/frozen mapping')")
    source = replace_once(source, "    if name.startswith(EXTERNAL_PREFIX):\n",
        "    if name.startswith(FROZEN_PREFIX):\n"
        "        return FROZEN / name[len(FROZEN_PREFIX):]\n"
        "    if name.startswith(EXTERNAL_PREFIX):\n")
    source = change_function(source, "require_sealed", "")
    source = change_function(source, "summary", (HERE / "lifecycle_summary.py").read_text())
    source = replace_once(source,
        "need(ROOT.resolve(strict=True) == ROOT and R16.resolve(strict=True) == R16, 'indirect source root')",
        "need(ROOT.resolve(strict=True) == ROOT and R16.resolve(strict=True) == R16\n"
        "         and FROZEN.resolve(strict=True) == FROZEN, 'indirect source root')")
    source = replace_once(source,
        "    for name in SELECTED_DIRS:\n        directory(ROOT / name)",
        "    for name in CORE_FILES:\n"
        "        if os.path.lexists(ROOT / name):\n"
        "            file(ROOT / name, required=True)\n"
        "    for name in SELECTED_DIRS:\n"
        "        if os.path.lexists(ROOT / name):\n"
        "            directory(ROOT / name)\n"
        "        else:\n"
        "            need(name not in REQUIRED_DIRS, 'required frozen tools directory absent: ' + name)")
    source = source.replace("'unsealed R35 collector:", "'unsealed R35 lifecycle collector:")
    source = source.replace("normal lifecycle output presence changed during collection",
                            "lifecycle evidence presence changed during collection")
    source = source.replace("observation-evidence-01", "lifecycle-evidence-01")
    source = source.replace("hepta-r35-observation-evidence-archive/v1", "hepta-r35-normal-lifecycle-evidence-archive/v1")
    source = replace_once(source, "compact = summary('observation', data, namespace)",
                          "compact = summary('lifecycle', data, namespace)")
    source = source.replace("'kind': 'observation'", "'kind': 'lifecycle'")
    source = source.replace("manifest['kind'] == 'observation'", "manifest['kind'] == 'lifecycle'")
    source = source.replace("'observation_gate_passed': compact['observation_gate_passed']",
                            "'normal_lifecycle_gate_passed': compact['normal_lifecycle_gate_passed']")
    source = source.replace("choices=('observation',)", "choices=('lifecycle',)")
    source = replace_once(source,
        "'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,",
        "'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,\n"
        "        'protocol_reference_sha256': PROTOCOL_REFERENCE_SHA,\n"
        "        'frozen_fixture_source_root': str(FROZEN), 'frozen_fixture_archive_prefix': FROZEN_PREFIX,")
    tree = ast.parse(source)
    assignments = {node.targets[0].id: node.value for node in tree.body
                   if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    need(ast.literal_eval(assignments["ACTUAL"]) is None, "future outcomes are not unsealed")
    for name in ("collect", "summary", "create_archive", "verify_archive"):
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        need(isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Call)
             and isinstance(node.body[0].value.func, ast.Name) and node.body[0].value.func.id == "require_sealed",
             "missing first-entry sealed guard: " + name)
    raw = source.encode()
    path = HERE / "archive_r35_lifecycle.py"
    create(path, raw)
    proof = {"schema": "hepta-r35-lifecycle-archive-construction/v1", "sealed": False, "ACTUAL": None,
        "collector": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "safe_IO_reference_sha256": REFERENCE_SHA, "normal_LC_protocol_reference_sha256": PROTOCOL_SHA,
        "static_inputs": len(pins), "original_core_optional_files": list(core),
        "fixed_output_directories": ["lifecycle-campaign-01", "lifecycle-abba-01", "lifecycle-tool-tests-01"],
        "native_terminal_and_complete_stored_read_required": True,
        "missing_optional_reports_do_not_mean_success": True,
        "failed_completed_originals_supported": True, "collector_executed": False,
        "original_auditors_or_workloads_reexecuted": False, "remote_calls": 0}
    create(HERE / "construction.json", (json.dumps(proof, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
