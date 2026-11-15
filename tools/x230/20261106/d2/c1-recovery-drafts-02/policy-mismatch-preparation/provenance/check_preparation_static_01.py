#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Source/AST/identity checks only. Never import or execute target modules."""
import ast
import hashlib
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
def raw(name): return (root / name).read_bytes()
def parsed(name): return ast.parse(raw(name))
def functions(name):
    text = raw(name).decode()
    return {node.name: ast.get_source_segment(text, node).encode()
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}
def assignment(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name]
    assert len(rows) == 1
    return rows[0]
def literal(name, key): return ast.literal_eval(assignment(parsed(name), key))
def ident(data): return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
old_parent = "provenance/d1_campaign.unsealed.py"
old_sealer = "provenance/seal_campaign_d1.py"
old_installer = "provenance/install_campaign_d1.py"
parent = "d2_campaign.unsealed.py"
sealer = "seal_campaign.py"
installer = "install_campaign.py"
expected = {
 parent: (47093, "ee13bca3dc1660e373c558e665c2d51967f7973b70221af20c41a95090c9660c"),
 sealer: (17407, "e9af9b320da52ac6a4fe45768816fff32c8ced159d6ce0e4486cb481b154740c"),
 installer: (12402, "bd6e33588cb938a15ffc6ca68bed3f6e11c2df1a1e51da743202dd1a9941faba"),
 old_parent: (46302, "7346d37e0dd7a5eaba9ae09bfdbce62f53505ffc1832cf7ab04b9e32930d6ab9"),
 old_sealer: (15866, "2cb28e0ea18704d3f9b615567c6491bea2834cfc4c67f0a9fcbaa242cc6580b2"),
 old_installer: (12349, "0045ac1a119727260a99f4aab98c554e033f3486d16ae45cca9464e0c811d40a"),
 "run_c1_phase_cost.unsealed.py": (30442, "ba2cd36aa4755888fe01be6a5e0487fb6bf6d7fb0d486618b046e2c166778740"),
 "reference/correlate_trace.py": (15615, "891f511e80273c5fb4a1a76ff3606b7de90827c3eab5d01bb3e283dba952cd84"),
 "reference/summarize_trace.py": (15070, "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927"),
}
for name, (size, digest) in expected.items():
    data = raw(name)
    assert (len(data), hashlib.sha256(data).hexdigest()) == (size, digest)
    ast.parse(data)
pf, po = functions(parent), functions(old_parent)
critical = ["need", "utc", "canonical", "bind_compiler_monitor_inputs", "monitor_module",
 "prepare_compiler_monitor", "finish_compiler_monitor", "checked", "create", "save",
 "private_directory", "source_inputs", "machine_snapshot", "compiler_activity",
 "process_identity", "group_present", "qualification_projection", "verify_completed_compiler_monitor"]
assert all(pf[name] == po[name] for name in critical)
assert set(pf) == set(po)
changed = sorted(name for name in pf if pf[name] != po[name])
assert changed == sorted(["require_sealed", "expected_inputs", "bind_ordinary_prerequisite",
                         "bind_adapter", "diagnostic_result", "main"])
nested = {}
for name in (parent, old_parent):
    text = raw(name).decode()
    main = next(node for node in ast.parse(text).body
                if isinstance(node, ast.FunctionDef) and node.name == "main")
    nested[name] = {node.name: ast.get_source_segment(text, node).encode()
                    for node in main.body if isinstance(node, ast.FunctionDef)}
assert set(nested[parent]) == {"checkpoint", "bind", "unchanged", "run_stage"}
assert nested[parent] == nested[old_parent]
def quiet(name):
    text = raw(name).decode()
    start = text.index('        cooling = {"seconds_planned": QUIESCENCE_SECONDS')
    end = text.index("        for spec in plan:\n", start)
    return text[start:end].encode()
assert quiet(parent) == quiet(old_parent)
for key in ("COMPILER_MONITOR_LIMITS", "COMPILER_MONITOR_POLICY", "QUIESCENCE_SECONDS", "CAMPAIGN_SECONDS"):
    assert ast.dump(assignment(parsed(parent), key), include_attributes=False) == ast.dump(
        assignment(parsed(old_parent), key), include_attributes=False)
assert pf["command_plan"] == po["command_plan"] and pf["bind_static_sources"] == po["bind_static_sources"]
sf, so = functions(sealer), functions(old_sealer)
assert set(sf) == set(so) | {"adapter_with_d2_parser"}
assert all(sf[name] == so[name] for name in so if name != "seal")
inf, ino = functions(installer), functions(old_installer)
assert set(inf) == set(ino) and all(inf[name] == ino[name] for name in ino if name != "install")
assert literal(parent, "ACTUAL") is None
assert literal("run_c1_phase_cost.unsealed.py", "SPEC") is None
for name in (parent, sealer, installer, "run_c1_phase_cost.unsealed.py"):
    assert b"/home/qian/hd1c01" not in raw(name)
    assert raw(name).count(b"/home/qian/hd2c01") == 1
assert b'BASELINE_ROOT = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1")' in raw(parent)
assert b"len(added) == 0 and len(changed) == 2" in raw(parent)
static = literal(parent, "STATIC_INPUTS")
old_static = literal(old_parent, "STATIC_INPUTS")
assert set(static) == set(old_static) | {"reference/correlate_trace.py"}
assert len(static) == 14
for name, (size, digest) in static.items():
    assert (len(raw(name)), hashlib.sha256(raw(name)).hexdigest()) == (size, digest)
    if name not in {"reference/summarize_trace.py", "reference/correlate_trace.py"}:
        assert static[name] == old_static[name]
for key in ("MAX_FILE", "MAX_TOTAL", "MAX_FILES"):
    for new, old in ((sealer, old_sealer), (installer, old_installer)):
        assert ast.dump(assignment(parsed(new), key), include_attributes=False) == ast.dump(
            assignment(parsed(old), key), include_attributes=False)
linux = literal(installer, "LINUX_NAMES")
mac = literal(installer, "MAC_NAMES")
assert len(linux) == 19 and len(set(linux)) == 19
assert "c1-tools-01/reference/correlate_trace.py" in linux
assert mac == ("d2_campaign.py", "held_agent_campaign_02.py")
old_marker = b'"summarize_trace.py": (15057, "f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5")'
new_marker = b'"summarize_trace.py": (15070, "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927")'
adapter = raw("run_c1_phase_cost.unsealed.py")
assert adapter.count(old_marker) == 1 and adapter.count(new_marker) == 0
resolved = adapter.replace(old_marker, new_marker, 1)
assert resolved.replace(new_marker, old_marker, 1) == adapter
original_tree, resolved_tree = ast.parse(adapter), ast.parse(resolved)
old_refs = ast.literal_eval(assignment(original_tree, "REFERENCE"))
new_refs = ast.literal_eval(assignment(resolved_tree, "REFERENCE"))
assert new_refs == {**old_refs, "summarize_trace.py": tuple(static["reference/summarize_trace.py"])}
for node in resolved_tree.body:
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "REFERENCE" for t in node.targets):
        node.value = assignment(original_tree, "REFERENCE")
assert ast.dump(resolved_tree, include_attributes=False) == ast.dump(original_tree, include_attributes=False)
assert new_refs["correlate_trace.py"] == tuple(static["reference/correlate_trace.py"])
result = {
 "schema": "hepta-d2-c1-outer-source-static-checks/v1",
 "passed": True, "target_imports": 0, "target_functions_executed": 0, "host_requests": 0,
 "actual_qualification": None, "actual_ci": None, "actual_ordinary": None, "actual_measurement": None,
 "identities": {name: ident(raw(name)) for name in expected},
 "critical_parent_helpers_byte_equal": critical,
 "all_parent_top_functions_byte_equal": sorted(name for name in pf if pf[name] == po[name]),
 "changed_parent_functions": changed,
 "nested_owner_functions_byte_equal": sorted(nested[parent]),
 "original_owned_stage": ident(nested[parent]["run_stage"]),
 "original_quiet_block": ident(quiet(parent)),
 "compiler_limits_policy_and_timing_AST_equal": True,
 "command_plan_byte_equal": True,
 "sealer_existing_functions_equal_except_seal": sorted(name for name in so if name != "seal"),
 "installer_existing_functions_equal_except_install": sorted(name for name in ino if name != "install"),
 "static_runtime_input_count": len(static), "all_static_runtime_bytes_rehashed": True,
 "old_adapter_bytes_preserved": True, "future_adapter_patch_only_REFERENCE_parser_then_SPEC": True,
 "parser_reference_patch_AST_checked_without_executing_sealer": True,
 "correlation_in_all_reference_and_installation_inventories": True,
 "socket_namespace_all_four_sources": "/home/qian/hd2c01",
 "source_baseline": "/home/qian/hepta-runtime-phase-cost-20261106-d1",
 "compiler_input_count": 222, "changed_paths": 2, "added_paths": 0,
 "fixed_installation_payloads": {"x230": len(linux), "mac": len(mac)},
 "future_static_dependencies": ["d2_prerequisites.py", "ordinary/verify_ordinary_01.py"],
 "scope": "Source parsing, literal and byte comparisons only; no actual prerequisite binder, ordinary verifier, source sealer, installer, adapter, parser, auditor, holder or parent is imported/executed."
}
print(json.dumps(result, sort_keys=True, indent=2))
