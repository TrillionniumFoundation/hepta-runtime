#!/usr/bin/env python3
"""AST and exact-byte review of unsealed preparation; no template imports or CI execution."""
import ast
import hashlib
import json
from pathlib import Path

BASE = Path(__file__).resolve().parent
OLD_ROOT = "/home/qian/hepta-runtime-optimization-20261105-r31"
ROOT = "/home/qian/hepta-runtime-optimization-20261106-r33"


def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def source(name, group="templates"):
    return (BASE / group / name).read_text(encoding="utf-8")


def function(body, name):
    tree = ast.parse(body)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(nodes) == 1, "missing unique function " + name)
    return ast.get_source_segment(body, nodes[0])


def assigned(body, name, literal=False):
    nodes = [node for node in ast.parse(body).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(nodes) == 1, "missing unique assignment " + name)
    return ast.literal_eval(nodes[0].value) if literal else ast.dump(nodes[0].value, include_attributes=False)


def normalize(body):
    return (body.replace(OLD_ROOT, ROOT).replace("hepta-r31-", "hepta-r33-")
        .replace("R31", "R33").replace("r31_", "r33_").replace("r31_campaign.py", "r33_campaign.py")
        .replace("rust-ci-tools-02", "rust-ci-tools-01").replace("rust-ci-plan-02.json", "rust-ci-plan-01.json")
        .replace("rust-ci-02", "rust-ci-01").replace('"attempt": "02"', '"attempt": "01"')
        .replace('"attempt"] == "02"', '"attempt"] == "01"')
        .replace("preparation-02.json", "preparation.json"))


def once(body, old, new):
    need(body.count(old) == 1, "expected unique transformation anchor: " + old[:80])
    return body.replace(old, new, 1)


def main():
    reference_ids = json.loads((BASE / "reference-identities.json").read_bytes())
    expected_names = {"launch_exact_rust_ci_01.py", "materialize_rust_ci_plan_01.py",
        "run_rust_ci_01.py", "audit_nextest_0137.py", "canonical-workflow.yml", "package-manifest-01.json"}
    need(set(reference_ids) == expected_names, "six-file immutable reference inventory differs")
    for name, expected in reference_ids.items():
        need(identity((BASE / "reference/r31-attempt-02" / name).read_bytes()) == expected,
             "published reference bytes differ: " + name)
    parsed = []
    for folder in ("templates", "fixed", "reference/r31-attempt-02"):
        for path in sorted((BASE / folder).glob("*.py")):
            ast.parse(path.read_bytes(), filename=str(path))
            parsed.append(path.relative_to(BASE).as_posix())
    for name in ("seal_package.py", "verify_unsealed.py"):
        ast.parse((BASE / name).read_bytes(), filename=name)
        parsed.append(name)
    for name in ("audit_nextest_0137.py", "canonical-workflow.yml"):
        need((BASE / "fixed" / name).read_bytes() == (BASE / "reference/r31-attempt-02" / name).read_bytes(),
             "fixed CI input is not byte-identical: " + name)
    canonical = (BASE / "fixed/canonical-workflow.yml").read_bytes()
    need(hashlib.sha1(b"blob " + str(len(canonical)).encode() + b"\0" + canonical).hexdigest()
         == "34afc29edffd3130df158601c6a14fee5efbf79c", "canonical workflow Git object differs")

    old_materializer = source("materialize_rust_ci_plan_01.py", "reference/r31-attempt-02")
    materializer = source("materialize_rust_ci_plan_01.py")
    old_runner = source("run_rust_ci_01.py", "reference/r31-attempt-02")
    runner = source("run_rust_ci_01.py")
    old_launcher = source("launch_exact_rust_ci_01.py", "reference/r31-attempt-02")
    launcher = source("launch_exact_rust_ci_01.py")
    need(runner == normalize(old_runner), "runner changed beyond R33 root/schema/attempt names")
    begin, end = old_launcher.index("SPEC = "), old_launcher.index("ROOT = ")
    expected_launcher = normalize(old_launcher[:begin] + "SPEC = None\n" + old_launcher[end:])
    expected_launcher = expected_launcher.replace("hepta-r33-exact-rust-ci-tools/v2", "hepta-r33-exact-rust-ci-tools/v1")
    expected_launcher = expected_launcher.replace("manifest['attempt'] == '02'", "manifest['attempt'] == '01'")
    need(launcher == expected_launcher, "launcher changed beyond fresh identity and unsealed SPEC")
    need(assigned(launcher, "SPEC", literal=True) is None, "launcher is already sealed")
    for name in ("need", "read_file", "verify_terminal", "verify_canonical_workflow"):
        need(function(materializer, name) == normalize(function(old_materializer, name)),
             "original helper changed: " + name)
    expected_qualification = normalize(function(old_materializer, "verify_qualification")).replace(
        'len(value["source_after"]) == 222', 'len(value["source_after"]) == 220')
    need(function(materializer, "verify_qualification") == expected_qualification, "qualification gate changed beyond 220-input count")
    expected_main = normalize(function(old_materializer, "main"))
    expected_main = once(expected_main, "    prior_preflight = bind_prior_preflight(bind)\n", "")
    expected_main = once(expected_main, '        "prior_preflight_failure": prior_preflight, "workflow_binding": workflow_binding,',
                         '        "workflow_binding": workflow_binding,')
    expected_main = once(expected_main, '    need(counts == {"passed": 1653, "failed": 0, "ignored": 34, "selected": 1687, "retries": 0},',
                         "    need(counts == FROZEN_COUNTS,")
    need(function(materializer, "main") == expected_main,
         "materializer main changed beyond new names, omitted old recovery and actual dynamic counts")
    for name in ("STAGES", "COMMANDS", "INVENTORY_COMMAND", "BINARY_NAMES", "CI_MANIFEST_SHA",
                 "NEXTEST_ROOT", "NEXTEST_RECEIPT_SHA", "NEXTEST_BINARY"):
        need(assigned(materializer, name) == assigned(old_materializer, name), "fixed CI contract changed: " + name)
    for name in ("JOB_ID", "SOURCE_MAP_SHA", "ISOLATED_SUMMARY_SHA", "ISOLATED_AUDIT_SHA",
                 "QUALIFICATION_REPORT_SHA", "PREPARATION_SHA", "NATIVE_TERMINAL_SHA",
                 "PARENT_SHA", "QUALIFICATION_BINDINGS_SHA", "FROZEN_COUNTS"):
        need(assigned(materializer, name, literal=True) is None, "future actual identity was filled: " + name)
    for body in (materializer, runner, launcher):
        need(not any(word in body for word in ("PRIOR_PREFLIGHT", "prior_preflight", OLD_ROOT,
             "preparation-02.json", "campaign-inputs-01.json", "1653", "1687")),
             "fresh R33 tools retain stale R31 attempt state")
    main_node = next(node for node in ast.parse(materializer).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    need(ast.unparse(main_node.body[0]) == "require_frozen_qualification()", "unsealed materializer does not guard before writes")
    need(runner.index("materializer.require_frozen_qualification()") < runner.index("OUT.mkdir")
         < runner.index("subprocess.Popen"), "runner creates effects before the unsealed guard")
    need(launcher.index("need(type(SPEC) is dict") < launcher.index("subprocess.run"), "launcher lacks its unsealed guard")
    seal = source("seal_package.py", ".")
    template_ids = assigned(seal, "TEMPLATE_PINS", literal=True)
    need(set(template_ids) == {"materialize_rust_ci_plan_01.py", "run_rust_ci_01.py", "launch_exact_rust_ci_01.py"},
         "seal template inventory differs")
    for name, expected in template_ids.items():
        need(identity((BASE / "templates" / name).read_bytes()) == expected, "seal does not bind exact template: " + name)
    need(not any(isinstance(node, (ast.Import, ast.ImportFrom))
         and any(alias.name == "subprocess" for alias in node.names) for node in ast.walk(ast.parse(seal))),
         "seal generator unexpectedly imports subprocess")
    example = json.loads((BASE / "actual-pins.example.json").read_bytes())
    need(example["qualification_job_id"] is None and all(row["local_path"] is None
         and row["bytes"] is None and row["sha256"] is None for row in example["files"].values()),
         "example contains invented future qualification pins")
    return {
        "schema": "hepta-r33-exact-ci-unsealed-static-review/v1", "passed": True,
        "method": "AST parsing and exact original-text/constant comparisons only",
        "python_files_parsed": parsed, "reference_files_verified": len(reference_ids),
        "template_files_verified": template_ids,
        "original_runner_semantics_unchanged": True, "exact_workflow_commands_unchanged": True,
        "auditor_and_canonical_workflow_byte_identical": True,
        "prior_r31_preflight_chain_omitted": True, "independent_qualification_bindings": True,
        "future_qualification_pins_unsealed": True, "compiler_input_count": 220,
        "ci_executed": False, "benchmark_executed": False, "templates_imported_or_executed": False,
    }


if __name__ == "__main__":
    print(json.dumps(main(), indent=2, sort_keys=True))
