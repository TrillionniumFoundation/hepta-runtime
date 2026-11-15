#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Parse-only metadata verification of independent D2 C1 recovery02; no target imports."""
import ast
import hashlib
import json
from pathlib import Path
ROOT = Path("/tmp/hepta-runtime-recovery-20261106/d2-c1-recovery-preparation-02-revision-02")
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
ledger = json.loads((ROOT / "recovery-edit-ledger.json").read_bytes())
proof = {"schema": "hepta-d2-c1-recovery-static-checks/v1",
         "target_imports_or_entrypoints_executed": False, "host_calls": False,
         "core": [], "python_sources_parsed": [], "unchanged_original_members": [],
         "future_attempt02_results": None}
for row in ledger["files"]:
    raw = (ROOT / row["path"]).read_bytes()
    assert len(raw) == row["revised"]["bytes"] and sha(raw) == row["revised"]["sha256"]
    source = raw.decode()
    revised = ast.parse(source)
    original = source
    for edit in reversed(row["edits"]):
        assert original.count(edit["new"]) == edit["occurrences"]
        original = original.replace(edit["new"], edit["old"])
    original_raw = original.encode()
    assert len(original_raw) == row["original"]["bytes"]
    assert sha(original_raw) == row["original"]["sha256"]
    original_tree = ast.parse(original)
    functions = [node for node in revised.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    prior = {node.name: node for node in original_tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    equal = [node.name for node in functions
             if ast.get_source_segment(source, node) == ast.get_source_segment(original, prior[node.name])]
    proof["core"].append({"path": row["path"], "bytes": len(raw), "sha256": sha(raw),
                         "inverse_complete_original_identity_matches": True,
                         "parse_only": True, "unchanged_function_names": equal,
                         "all_top_level_function_count": len(functions)})
for rel, field in (("d2_campaign.unsealed.py", "ACTUAL"), ("run_c1_phase_cost.unsealed.py", "SPEC")):
    tree = ast.parse((ROOT / rel).read_bytes())
    matches = [node for node in tree.body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == field]
    assert len(matches) == 1 and isinstance(matches[0].value, ast.Constant)
    assert matches[0].value.value is None
proof["parent_and_adapter_unsealed"] = True
parent_source = (ROOT / "d2_campaign.unsealed.py").read_text()
parent_original = parent_source
parent_row = next(row for row in ledger["files"] if row["path"] == "d2_campaign.unsealed.py")
for edit in reversed(parent_row["edits"]):
    parent_original = parent_original.replace(edit["new"], edit["old"])
def declaration(source, name):
    matches = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
               and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == name]
    assert len(matches) == 1
    return ast.get_source_segment(source, matches[0])
for name in ("COMPILER_MONITOR_LIMITS", "COMPILER_MONITOR_POLICY"):
    assert declaration(parent_source, name) == declaration(parent_original, name)
policy_raw = (ROOT / "compiler-monitor-policy-01.json").read_bytes()
assert len(policy_raw) == 1001
assert sha(policy_raw) == "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368"
assert json.loads(policy_raw)["runtime_attempt"] == "01"
proof["complete_monitor_policy_and_limits_source_exact_original"] = True
proof["original_policy_json_exact_and_attempt01"] = True
old = json.loads((ROOT / "provenance/original-preparation-manifest-01.json").read_bytes())
allowed = {"d2_campaign.unsealed.py", "run_c1_phase_cost.unsealed.py",
           "seal_campaign.py", "install_campaign.py", "README.md",
           "campaign-inputs.unsealed.json", "required-actual-inputs.unsealed.json",
           "operator-plan.unsealed.json"}
actual_changed = set()
for row in old["files"]:
    raw = (ROOT / row["path"]).read_bytes()
    if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
        actual_changed.add(row["path"])
    else:
        proof["unchanged_original_members"].append(row["path"])
assert actual_changed == allowed
proof["changed_original_members_exact"] = sorted(actual_changed)
before = (ROOT / "provenance/original-topology.json").read_bytes()
after = (ROOT / "fixtures/topology.json").read_bytes()
prior_sha = b"fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08"
new_sha = b"ed680dc1613e4aea4de99336d21009c73e71554694edbe23f9dc3a433b586e89"
assert before.count(prior_sha) == after.count(new_sha) == 1
assert before.replace(prior_sha, new_sha, 1) == after and len(before) == len(after) == 796
x, y = json.loads(before), json.loads(after)
assert x["profile_template_sha256"] == prior_sha.decode()
assert y["profile_template_sha256"] == new_sha.decode()
y["profile_template_sha256"] = x["profile_template_sha256"]
assert x == y
proof["topology_exact_single_64_byte_value_replacement"] = True
dep = json.loads((ROOT / "fixture-deployment.json").read_bytes())
assert len(dep["files"]) == 7
for item in dep["files"]:
    raw = (ROOT / item["source"]).read_bytes()
    assert len(raw) == item["bytes"] and sha(raw) == item["sha256"]
    assert item["destination"].startswith("/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-fixtures-02/")
proof["seven_fixture_identities_verified"] = True
assert len(list((ROOT / "fixtures/jobs").glob("*.json"))) == 6
for path in sorted(ROOT.rglob("*.py")):
    ast.parse(path.read_bytes())
    proof["python_sources_parsed"].append(path.relative_to(ROOT).as_posix())
for path in ROOT.rglob("*.json"):
    json.loads(path.read_bytes())
proof["all_json_parsed"] = True
proof["all_checks_passed"] = True
raw = (json.dumps(proof, indent=2, sort_keys=True) + "\n").encode()
with (ROOT / "RECOVERY_STATIC_CHECKS.json").open("xb") as stream:
    stream.write(raw)
print(json.dumps({"report": str(ROOT / "RECOVERY_STATIC_CHECKS.json"),
                  "bytes": len(raw), "sha256": sha(raw), "checks_passed": True,
                  "target_executions": 0, "host_calls": 0}))
