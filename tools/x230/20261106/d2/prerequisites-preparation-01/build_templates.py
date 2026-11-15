#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Static D2 derivation only: never import or execute generated target modules."""
import ast
import hashlib
import json
from pathlib import Path
import pprint

HERE = Path(__file__).resolve().parent
REFERENCE = (HERE / 'references/d1_prerequisites.py').read_text()
DATA = json.loads((HERE / 'generation-input.json').read_bytes())
OLD_ROOT = '/home/qian/hepta-runtime-phase-cost-20261106-d1'
ROOT = '/home/qian/hepta-runtime-validation-cost-20261106-d2'
ANCHOR = '8eb1a0af7a85768e374717d24848fd9798871cc9'
TREE = ast.parse(REFERENCE)
FUNCTIONS = {node.name: ast.get_source_segment(REFERENCE, node) + '\n'
             for node in TREE.body if isinstance(node, ast.FunctionDef)}
ASSIGNS = {node.targets[0].id: ast.get_source_segment(REFERENCE, node) + '\n'
           for node in TREE.body if isinstance(node, ast.Assign) and len(node.targets) == 1
           and isinstance(node.targets[0], ast.Name)}

def change(text, before, after):
    assert text.count(before) == 1, (before[:120], text.count(before))
    return text.replace(before, after, 1)

def namespace(text):
    # Replace identifiers/schemas only; lowercase hexadecimal identities may contain d1.
    return (text.replace(OLD_ROOT, ROOT).replace('hepta-d1-', 'hepta-d2-')
            .replace('hepta-x230-d1-', 'hepta-x230-d2-')
            .replace('bind_d1_', 'bind_d2_').replace('actual_d1_', 'actual_d2_')
            .replace('/d1_prerequisites.py', '/d2_prerequisites.py').replace('D1', 'D2'))

def literal(name, value):
    return name + ' = ' + pprint.pformat(value, sort_dicts=True, width=110) + '\n'

header = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only D2 actual qualification and native exact-CI prerequisite proofs.

The caller first binds immutable foundation JSON. Q-only does not depend on CI.
No compiler, auditor, measurement, cache operation or remote request is started.
Prior D1 ownership is bound to the successful D2 preparation and exact originals;
its pre-rename cache validator is never replayed after the recorded rename.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

'''
header += literal('ROOT', ROOT).replace("ROOT = '", "ROOT = Path('").rstrip('\n') + ')\n'
header += 'SOURCE = ROOT / "source"\nQUALIFICATION = ROOT / "qualification-01"\n'
header += 'BASE = Path(' + repr(OLD_ROOT) + ')\nCACHE_OWNER = BASE\n'
header += 'MODULE_PATH = ROOT / "full-prerequisites-01/d2_prerequisites.py"\n'
for name in ('CARGO_HOME', 'NEXTEST_ROOT', 'HEX', 'JOB'):
    header += ASSIGNS[name]
header += literal('BASELINE_COMMIT', ANCHOR)
for name in ('STAGES', 'DIAGNOSTIC_ENV'):
    header += ASSIGNS[name]
header += literal('PINNED', DATA['pinned'])
header += literal('OWNER_INPUTS', DATA['closure']['inputs'])
header += literal('OWNER_JOBS', DATA['closure']['jobs'])
header += literal('ORIGINAL_MISSING_PATHS', DATA['closure']['original_missing_paths'])
for name in ('QUALIFICATION_ARTIFACTS', 'CI_ARTIFACTS'):
    header += ASSIGNS[name]
header += "CHANGED = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}\nADDED = set()\n"
header += literal('BASELINE_QUALIFICATION', DATA['input']['baseline_qualification'])
for name in ('COUNT_KEYS', 'BINARY_NAMES', 'CI_COMMANDS', 'CI_ENVIRONMENT', 'NEXTEST_BINARY',
             'CANONICAL_WORKFLOW', 'PRIVATE_SOURCE_WORKFLOW'):
    header += ASSIGNS[name].replace(OLD_ROOT, ROOT)

module = '''def _module(prerequisites, bind):
    pin = _identity(prerequisites.get("prerequisite_module"), MODULE_PATH)
    canonical_id, canonical_raw = _declared(pin, bind, retain=True)
    executing_path = Path(__file__).resolve()
    current_id, current_raw = bind(executing_path, maximum=8 * 1024 * 1024, retain=True)
    need(current_id["path"] == str(executing_path) and current_raw == canonical_raw,
         "executing module copy differs from the frozen canonical prerequisite source")
    return canonical_id
'''

owner = '''def _previous_owner(prerequisites, preparation, build_inputs, bind):
    """Rebind exact D1 receipts and the successful original pre-rename check; do not replay it."""
    closure_id, closure = _document(prerequisites, "cache-owner-closure-inputs.json", bind)
    need(closure["schema"] == "hepta-d2-d1-cache-owner-closure/v1"
         and closure["sealed"] is True and closure["required_missing_bindings"] == []
         and closure["owner_root"] == str(CACHE_OWNER)
         and closure["inputs"] == OWNER_INPUTS and closure["jobs"] == OWNER_JOBS
         and closure["original_missing_paths"] == ORIGINAL_MISSING_PATHS
         and closure["original_c1_workflow_passed"] is False
         and closure["standalone_original_auditor_already_executed"] is True
         and closure["historical_auditors_to_execute"] == 0 and closure["candidate_adopted"] is False,
         "the exact closed D1 cache-owner input differs")
    need(preparation["cache_owner_closure_input"] == closure_id
         and build_inputs["owner_closure_input_sha256"] == closure_id["sha256"],
         "successful D2 preparation does not bind the fixed prior-owner input")
    docs = {}
    for role, pin in OWNER_INPUTS.items():
        _, raw = _declared(pin, bind, retain=True)
        docs[role] = json.loads(raw)
    need(all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS),
         "an original missing D1 output was subsequently created")
    closed = preparation["cache_owner_closure"]
    post = docs["ordinary_postflight_report"]
    releases = {**{row["path"]: row for row in post["qualified_feature_programs_after"].values()},
                **{row["path"]: row for row in post["ordinary_programs"].values()}}
    expected = {"closed": True, "source_input_count": 222,
        "qualification_counts": {key: docs["qualification_summary"][key] for key in COUNT_KEYS},
        "ordinary_counts": post["tests"], "original_jobs": OWNER_JOBS,
        "original_c1_workflow_passed": False, "c1_original_controller_closures": 8,
        "standalone_original_native_audit_passed": True, "historical_auditors_reexecuted": False,
        "candidate_adopted": False, "current_machine_idle_claimed": False,
        "future_live_cache_process_scan_required": True, "retained_release_programs": releases,
        "original_inputs": OWNER_INPUTS}
    need(closed == expected, "the original successful preparation recorded another owner closure")
    need(preparation["cache_transferred_by_rename"] is True
         and preparation["new_full_cache_copy_bytes"] == 0 and preparation["cache_deletions"] == 0
         and preparation["cache_to_transfer"] == str(CACHE_OWNER / "target-build"),
         "the original single cache rename receipt differs")
    target = ROOT / "target-build"
    need(target.resolve() == target and target.is_dir() and not os.path.lexists(CACHE_OWNER / "target-build"),
         "the cache is not at its recorded post-rename location")
    retained = preparation["retained_programs"]
    need(isinstance(retained, dict) and len(retained) >= 8 and len(releases) == 6
         and all(Path(path).is_relative_to(CACHE_OWNER / "qualification-01")
                 or Path(path).is_relative_to(CACHE_OWNER / "ordinary-02") for path in retained)
         and all(isinstance(digest, str) and HEX.fullmatch(digest) for digest in retained.values()),
         "original retained program custody is incomplete")
    for path, pin in releases.items():
        need(retained.get(path) == pin["sha256"], "the preserved D1 release copy differs")
        _declared(pin, bind, maximum=64 * 1024 * 1024)
    return {"input": closure_id, "original_identity_count": len(OWNER_INPUTS),
        "original_bytes_rebound": True, "original_jobs": OWNER_JOBS,
        "original_c1_workflow_passed": False, "c1_original_controller_closures": 8,
        "standalone_original_native_audit_passed": True,
        "old_preparer_cache_owner_closed_reexecuted": False,
        "current_cache_path": str(target), "original_successful_preparation_rename_bound": True,
        "prior_owner_performance_adopted": False, "old_auditors_reexecuted": False,
        "current_machine_idle_claimed": False, "retained_release_copies_rehashed": 6,
        "retained_test_copies": "bound to the successful original preparation receipt; not rehashed by this later binder"}
'''

q = namespace(FUNCTIONS['bind_d1_qualification'])
q = change(q, '    _foundation(prerequisites)\n', '    _foundation(prerequisites)\n    module_id = _module(prerequisites, bind)\n')
q = change(q, '3de16de910158951dc17bb8f52883b88dd832d5a', 'c4c5359d5bc05bb37a8fa28d62f80f2f3a1263c4')
begin = q.index('    need(candidate["schema"]')
end = q.index('    before, preformat =', begin)
q = q[:begin] + '''    need(candidate["schema"] == "hepta-x230-d2-candidate/v1"
         and candidate_manifest["schema"] == "hepta-x230-d2-source-package/v1"
         and candidate["baseline_commit"] == candidate["git_parent"] == BASELINE_COMMIT
         and candidate["protocol"]["diagnostic_only"] is True
         and candidate["protocol"]["runtime_adoption"] is False
         and candidate["candidate_patch"] == {"bytes": patch_id["bytes"],
             "sha256": patch_id["sha256"], "git_blob": patch_git_blob},
         "the frozen two-file diagnostic candidate and patch do not bind")
''' + q[end:]
q = change(q, 'len(before) == 220 and len(preformat) == 222', 'len(before) == len(preformat) == 222')
q = change(q, '"D2 is not the exact thirteen-path/two-addition R24 patch"', '"D2 is not the exact two-path/no-addition qualified-D1 patch"')
q = change(q, '"candidate preimage is not the accepted R24 qualification"', '"candidate preimage is not the exact qualified D1 source"')
q = change(q, '"native": native, "source_chain_and_cache_owner": owner,', '"native": native, "source_chain_and_cache_owner": owner,\n        "prerequisite_module": module_id,')

full = namespace(FUNCTIONS['bind_d1_prerequisites'])
begin = full.index('    # BEGIN D2_REVIEWED_MANIFEST_CORRECTION_03')
end = full.index('\n    # END D2_REVIEWED_MANIFEST_CORRECTION_03\n', begin) + 1
end = full.index('\n', end) + 1
full = full[:begin] + '''    binder_id = _module(prerequisites, bind)
    need(binder_id == qualification["prerequisite_module"] and binder_id in plan["input_bindings"],
         "the actual CI plan did not bind the same canonical D2 prerequisite module")
''' + full[end:]
full = change(full, '            "qualification_binder_correction": binder_correction,\n', '')

parts = [header]
names = ('checked', 'native_terminal', 'native_stream_pages', 'need', 'canonical', '_identity', '_declared', '_artifact',
         '_document', '_foundation', '_native', '_source_inputs')
for name in names:
    value = FUNCTIONS[name]
    # Generic readers and native stream validation keep their exact original bytes.
    if name == '_foundation':
        value = namespace(value)
        value = change(value, '    job = prerequisites.get("qualification_original_job_id")',
            '    _identity(prerequisites.get("prerequisite_module"), MODULE_PATH)\n    job = prerequisites.get("qualification_original_job_id")')
    parts.append(value)
parts += [module, owner, q, FUNCTIONS['qualification_legacy_inputs'], full]
result = '\n\n'.join(part.rstrip() for part in parts) + '\n'
ast.parse(result)
out = HERE / 'draft-03'
out.mkdir(mode=0o700, exist_ok=False)
output = out / 'd2_prerequisites.py'
with output.open('x') as stream:
    stream.write(result)
review = {'schema': 'hepta-d2-prerequisite-static-derivation/v1',
    'source_reference_sha256': hashlib.sha256(REFERENCE.encode()).hexdigest(),
    'result_bytes': len(result.encode()), 'result_sha256': hashlib.sha256(result.encode()).hexdigest(),
    'unchanged_functions': [name for name in names if name != '_foundation'] + ['qualification_legacy_inputs'],
    'source_count': 222, 'changed_paths': sorted(['src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs']),
    'module_execution': False, 'rust_builds': 0, 'host_calls': 0,
    'future_qualification_and_ci_values': 'null until original actual receipts arrive'}
with (out / 'static-derivation.json').open('x') as stream:
    json.dump(review, stream, indent=2, sort_keys=True)
    stream.write('\n')
print(json.dumps(review, sort_keys=True))
