#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create unsealed R34 exact-CI preparation from published R33 templates, without running CI."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import pprint

BASE = Path(__file__).resolve().parent
REFERENCE = BASE / "reference-r33/exact-ci-preparation"
FIXED_REFERENCE = BASE.parent / "audit-archive/transferred-01/exact-ci-sealed-01/tools"
OLD_ROOT = "/home/qian/hepta-runtime-optimization-20261106-r33"
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r34"
PINS = {
    "templates/materialize_rust_ci_plan_01.py": (25140, "99a5a84cad38683cac82a5e03379d7349b2ec15d584e2c60e2eabcb362e5bf54"),
    "templates/run_rust_ci_01.py": (15182, "bdb64479833a998fa6d8ca6722bd1476af051d61a30716b339a1a60421bacd08"),
    "templates/launch_exact_rust_ci_01.py": (4628, "dd4887f3675618f77267110e51ece49d9fe99bbc3dd54a97bfbc8c29801e195b"),
    "seal_package.py": (15368, "b5492df0b3da19cf043ef939fe0846bacb1a311bba88ee49f9956a62bf4989ec"),
    "actual-pins.example.json": (2360, "ea7bdc647c1d21078b6b33d843dacc1dacaf4a7c8040bac9f276cd4370121c1f"),
}
FIXED = {
    "audit_nextest_0137.py": (8563, "03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2"),
    "canonical-workflow.yml": (7631, "b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51"),
}
FUTURE = ("JOB_ID", "SOURCE_MAP_SHA", "ISOLATED_SUMMARY_SHA", "ISOLATED_AUDIT_SHA",
    "QUALIFICATION_REPORT_SHA", "PREPARATION_SHA", "NATIVE_TERMINAL_SHA", "PARENT_SHA",
    "QUALIFICATION_BINDINGS_SHA", "FROZEN_COUNTS")


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def rename(text):
    return text.replace(OLD_ROOT, ROOT).replace("r33", "r34").replace("R33", "R34")


def assigned(text, name):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.Assign)
             and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name]
    need(len(nodes) == 1, "unique assignment required: " + name)
    return nodes[0]


def literal(text, name):
    return ast.literal_eval(assigned(text, name).value)


def replace_assignment(text, name, value):
    node = assigned(text, name)
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = [name + " = " + pprint.pformat(value, sort_dicts=True) + "\n"]
    return "".join(lines)


def main():
    original = {}
    for name, (size, digest) in PINS.items():
        raw = (REFERENCE / name).read_bytes()
        need(identity(raw) == {"bytes": size, "sha256": digest}, "published R33 source changed: " + name)
        original[name] = raw
    generated = {}
    for name in PINS:
        if name.startswith("templates/"):
            generated[name] = rename(original[name].decode()).encode()
    for name, (size, digest) in FIXED.items():
        raw = (FIXED_REFERENCE / name).read_bytes()
        need(identity(raw) == {"bytes": size, "sha256": digest}, "fixed original CI input changed: " + name)
        generated["fixed/" + name] = raw
    template_ids = {Path(name).name: identity(raw) for name, raw in generated.items() if name.startswith("templates/")}
    seal = rename(original["seal_package.py"].decode())
    need(seal.count('ROOT / "input.json"') == 1 and seal.count('ROOT / "combined.patch"') == 1,
         "expected sealer path anchors differ")
    seal = seal.replace('ROOT / "input.json"', 'ROOT / "qualification-input.json"')
    seal = seal.replace('ROOT / "combined.patch"', 'ROOT / "candidate/candidate.patch"')
    seal = replace_assignment(seal, "TEMPLATE_PINS", template_ids)
    generated["seal_package.py"] = seal.encode()
    example = json.loads(rename(original["actual-pins.example.json"].decode()))
    example["files"]["qualification_input"]["path"] = ROOT + "/qualification-input.json"
    example["files"]["candidate_patch"]["path"] = ROOT + "/candidate/candidate.patch"
    generated["actual-pins.example.json"] = canonical(example)
    for name, raw in generated.items():
        if name.endswith(".py"):
            ast.parse(raw, filename=name)
    materializer = generated["templates/materialize_rust_ci_plan_01.py"].decode()
    launcher = generated["templates/launch_exact_rust_ci_01.py"].decode()
    runner = generated["templates/run_rust_ci_01.py"].decode()
    need(all(literal(materializer, name) is None for name in FUTURE), "future actual pin was invented")
    need(literal(launcher, "SPEC") is None, "launcher was sealed prematurely")
    need(example["qualification_job_id"] is None and all(row["local_path"] is None and row["bytes"] is None
         and row["sha256"] is None for row in example["files"].values()), "example has future actual pins")
    for name in PINS:
        if name.startswith("templates/"):
            need(generated[name].decode() == rename(original[name].decode()), "CI body changed beyond ROOT/version")
    main_node = next(n for n in ast.parse(materializer).body if isinstance(n, ast.FunctionDef) and n.name == "main")
    need(ast.unparse(main_node.body[0]) == "require_frozen_qualification()", "materializer must fail closed before writes")
    need(runner.index("materializer.require_frozen_qualification()") < runner.index("OUT.mkdir")
         < runner.index("subprocess.Popen"), "runner effects precede actual-pin guard")
    need(launcher.index("need(type(SPEC) is dict") < launcher.index("subprocess.run"), "launcher lacks first actual-pin guard")
    old_seal = original["seal_package.py"].decode()
    restored = seal.replace(ROOT, OLD_ROOT).replace("r34", "r33").replace("R34", "R33")
    restored = restored.replace('ROOT / "qualification-input.json"', 'ROOT / "input.json"')
    restored = restored.replace('ROOT / "candidate/candidate.patch"', 'ROOT / "combined.patch"')
    restored = replace_assignment(restored, "TEMPLATE_PINS", literal(old_seal, "TEMPLATE_PINS"))
    old_seal_normalized = replace_assignment(old_seal, "TEMPLATE_PINS", literal(old_seal, "TEMPLATE_PINS"))
    need(ast.dump(ast.parse(restored), include_attributes=False) == ast.dump(ast.parse(old_seal_normalized), include_attributes=False),
         "sealer behavior changed beyond new ROOT, input paths and template pins")
    frozen_constants = ("STAGES", "COMMANDS", "INVENTORY_COMMAND", "BINARY_NAMES", "CI_MANIFEST_SHA",
        "NEXTEST_ROOT", "NEXTEST_RECEIPT_SHA", "NEXTEST_BINARY")
    for name in frozen_constants:
        need(ast.dump(assigned(materializer, name).value, include_attributes=False)
             == ast.dump(assigned(original["templates/materialize_rust_ci_plan_01.py"].decode(), name).value, include_attributes=False),
             "original CI contract changed: " + name)
    report = {
        "schema": "hepta-r34-exact-ci-unsealed-static-review/v1", "passed": True,
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "method": "AST and exact text/identity checks; no template imports or entrypoint execution",
        "source_reference_tree": "512d2534f09252b5479193660bd5d163e57f7ee0",
        "source_reference_prefix": "tools/x230/20261106/r33/exact-ci-preparation",
        "original_template_bodies_unchanged_except_version_root": True,
        "sealer_unchanged_except_version_root_fixed_qualification_paths_and_template_pins": True,
        "fixed_ci_contract_constants_unchanged": list(frozen_constants),
        "auditor_and_canonical_workflow_byte_identical": True,
        "future_actual_assignments_null": list(FUTURE), "launcher_SPEC_null": True,
        "unsealed_guard_precedes_output_creation_and_commands": True,
        "actual_counts_derived_from_original_summary_and_audit_at_seal_time": True,
        "candidate_test_count_prediction": None,
        "x230_or_mac_calls": 0, "ci_executed": False, "rust_compiled_or_tested": False,
        "benchmark_executed": False, "templates_imported_or_executed": False,
        "files": {name: identity(raw) for name, raw in sorted(generated.items())},
    }
    manifest = {
        "schema": "hepta-r34-exact-rust-ci-unsealed-preparation/v1", "sealed": False,
        "status": "UNSEALED_ACTUAL_FIRST_R34_QUALIFICATION_REQUIRED", "root": ROOT,
        "baseline_commit": "baab4def80be7af015b2e7a594cb302f66c4130e", "attempt": "01",
        "actual_qualification_job_id": None, "actual_qualification_counts": None,
        "files": report["files"],
        "frozen_nextest_version": "0.9.137", "qualification_harness_files": 19,
        "compiler_input_count": 220,
        "parent_binder": {"path": ROOT + "/tools-01/r34_campaign.py", "bytes": None, "sha256": None},
        "future_receipts": sorted(example["files"]),
        "qualification_success_inferred": False, "ci_executed": False,
        "hosted_actions_passed": False, "candidate_adopted": False,
    }
    generated["LOCAL_STATIC_CHECKS.json"] = canonical(report)
    generated["unsealed-manifest.json"] = canonical(manifest)
    need(not any(os.path.lexists(BASE / name) for name in generated), "create-only new template paths required")
    for name, raw in generated.items():
        create(BASE / name, raw)
    print(json.dumps({"sealed": False, "files": report["files"],
                      "static_checks": identity(generated["LOCAL_STATIC_CHECKS.json"]),
                      "manifest": identity(generated["unsealed-manifest.json"]), "ci_executed": False}, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    main()
