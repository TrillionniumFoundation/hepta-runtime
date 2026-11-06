#!/usr/bin/env python3
"""Only read source, parse AST/JSON and hash the D1 preparation; import no target."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def source(name):
    return (ROOT / name).read_text()


def functions(raw):
    tree, lines = ast.parse(raw), raw.splitlines(True)
    return {node.name: "".join(lines[node.lineno - 1:node.end_lineno])
            for node in tree.body if isinstance(node, ast.FunctionDef)}


def constant(raw, name):
    node = next(node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets))
    return ast.literal_eval(node.value)


def expression(raw, name):
    node = next(node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in node.targets))
    return ast.dump(node.value, include_attributes=False)


def nested(raw, name):
    main = next(node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == "main")
    node = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == name)
    return "".join(raw.splitlines(True)[node.lineno - 1:node.end_lineno])


def quiet(raw):
    start = raw.index('        cooling = {"seconds_planned": QUIESCENCE_SECONDS')
    last = '        cooling["passed"] = True\n'
    end = raw.index(last, start) + len(last)
    return raw[start:end]


def ident(raw):
    value = raw.encode()
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def main():
    parent, original = source("d1_campaign.unsealed.py"), source("provenance/r35_campaign.py")
    pf, of = functions(parent), functions(original)
    names = ("need", "utc", "canonical", "bind_compiler_monitor_inputs", "monitor_module",
             "prepare_compiler_monitor", "finish_compiler_monitor", "checked", "create", "save",
             "private_directory", "source_inputs", "machine_snapshot", "compiler_activity",
             "process_identity", "group_present", "qualification_projection", "interrupted")
    originals = {}
    for name in names:
        assert pf[name] == of[name], name
        originals[name] = ident(pf[name])
    nested_originals = {}
    for name in ("checkpoint", "bind", "unchanged", "run_stage"):
        current, baseline = nested(parent, name), nested(original, name)
        assert current == baseline, name
        nested_originals[name] = ident(current)
    current_quiet, original_quiet = quiet(parent), quiet(original)
    assert current_quiet == original_quiet
    assert constant(parent, "QUIESCENCE_SECONDS") == constant(original, "QUIESCENCE_SECONDS") == 90
    assert constant(parent, "CAMPAIGN_SECONDS") == constant(original, "CAMPAIGN_SECONDS") == 3300
    assert expression(parent, "COMPILER_MONITOR_LIMITS") == expression(original, "COMPILER_MONITOR_LIMITS")
    assert constant(parent, "ACTUAL") is None
    assert constant(source("run_c1_phase_cost.unsealed.py"), "SPEC") is None
    assert 'BINDER = TOOLS / "d1_prerequisites.py"' in parent
    assert 'Path("/home/qian/hd1c01")' in parent
    assert "h35n01" not in parent and "h35b01" not in parent and "h35c01" not in parent
    plan = pf["command_plan"]
    assert plan.count('"name":') == 2 and '"name": "native-observation"' in plan and '"name": "native-audit"' in plan
    assert all(word not in plan for word in ("native-boundary", "cancel-recovery", "lifecycle", "capacity"))
    assert "require_sealed()" == pf["main"].splitlines()[1].strip()
    static = constant(parent, "STATIC_INPUTS")
    assert len(static) == 13
    pins = {}
    for name, (size, digest) in static.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, name
        pins[name] = {"bytes": size, "sha256": digest}
    expected_python = {Path(name).name for name in static if name.startswith("reference/") and name.endswith(".py")}
    assert expected_python == {path.name for path in (ROOT / "reference").glob("*.py")} and len(expected_python) == 8
    installer = source("install_campaign.py")
    linux = set(constant(installer, "LINUX_NAMES"))
    assert linux == {"c1-tools-01/" + name for name in static} | {
        "c1-tools-01/d1_prerequisites.py", "c1-tools-01/run_c1_phase_cost.py", "c1-tools-01/d1_campaign.py",
        "c1-prerequisites-01.json", "c1-campaign-inputs-01.json"}
    assert len(linux) == 18 and set(constant(installer, "MAC_NAMES")) == {"held_agent_campaign_02.py", "d1_campaign.py"}
    for name in ("install_campaign.py", "seal_campaign.py"):
        tree = ast.parse(source(name))
        assert all(not isinstance(n, (ast.Import, ast.ImportFrom)) or
                   all(not alias.name.startswith(("subprocess", "socket", "urllib", "requests")) for alias in n.names)
                   for n in ast.walk(tree))
    sealer = source("seal_campaign.py")
    assert "binder.bind_d1_prerequisites(prerequisites, parent.checked)" in sealer
    assert "source-only" not in pf["command_plan"]
    assert 'assignment(sources["run_c1_phase_cost.unsealed.py"], "SPEC", adapter_spec)' in sealer
    assert 'assignment(sources["d1_campaign.unsealed.py"], "ACTUAL", actual)' in sealer
    frozen = {
        "held_agent_campaign_02.py": (11374, "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"),
        "run_c1_phase_cost.unsealed.py": (31131, "b49b95b00f67b33b05b726527ee5f63766fe568f7fed6d372f32417d3f811189"),
        "d1_prerequisites.py": (53934, "11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7"),
        "pre-execution-clarification-01.json": (3821, "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"),
    }
    for name, (size, digest) in frozen.items():
        raw = (ROOT / name).read_bytes()
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == digest, name
    parsed = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix == ".py":
            ast.parse(path.read_bytes())
            parsed.append(path.relative_to(ROOT).as_posix())
        elif path.suffix == ".json":
            json.loads(path.read_bytes())
            parsed.append(path.relative_to(ROOT).as_posix())
    result = {
        "schema": "hepta-d1-c1-outer-static-source-check/v1", "passed": True,
        "parent": ident(parent), "exact_original_top_level_helpers": originals,
        "exact_original_nested_helpers": nested_originals, "exact_original_quiet_block": ident(current_quiet),
        "quiet_seconds": 90, "campaign_seconds": 3300, "original_monitor_limits_equal": True,
        "unchanged_static_runtime_inputs": pins, "reference_python_inventory": sorted(expected_python),
        "unsealed_parent_and_adapter": True, "same_binder_as_reviewed": True,
        "two_stages_only": ["native-observation", "native-audit"],
        "fixed_install_inventory": {"x230": 18, "mac": 2},
        "syntax_parsed_files": parsed,
        "native_auditor_scope_review": "Original analyzer iterates report.concurrency and calls_per_cell. C1-only uses the same original checks; no fixed 2304 constant was removed.",
        "planned_counts_are_not_results": {"measured": 768, "warmup": 96, "preflight_restart": 72, "total": 936},
        "original_measured_failure_continuation_preserved": True,
        "pre_execution_clarification_required": True,
        "target_imports": 0, "target_functions_executed": 0, "native_auditors_or_parsers_executed": 0,
        "workloads_or_compilers_executed": 0, "host_requests": 0,
        "limitations": [
            "AST and byte equality do not establish a future successful qualification, CI or diagnostic measurement.",
            "Only the source construction/check program itself ran; the parent, adapter, holder, binder, sealer and installer did not run.",
            "Final native holder completion, agent reap, original controller shutdowns and compiler-monitor validity remain actual runtime obligations."
        ],
    }
    output = ROOT / "STATIC_CHECKS.json"
    raw = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    with output.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"path": str(output), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                      "passed": True, "target_imports_or_executions": 0}, sort_keys=True))


if __name__ == "__main__":
    main()
