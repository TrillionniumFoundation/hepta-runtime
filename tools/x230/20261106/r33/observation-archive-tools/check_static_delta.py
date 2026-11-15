#!/usr/bin/env python3
"""Read-only AST and byte comparison for the R33 observation collector draft."""
from pathlib import Path
import argparse
import ast
import hashlib
import json

ROOT = Path(__file__).resolve().parent


def assignment(tree, name):
    return next(n.value for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))


def literal(tree, name):
    return ast.literal_eval(assignment(tree, name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--draft', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    original = (ROOT / 'reference/archive_r31_observation.py').read_text()
    draft = args.draft.read_text()
    before, after = ast.parse(original), ast.parse(draft)
    def functions(text, tree):
        return {n.name: ast.get_source_segment(text, n) for n in tree.body
                if isinstance(n, ast.FunctionDef)}
    old, new = functions(original, before), functions(draft, after)
    identical = ('need', 'sha', 'encoded', 'stamp', 'terminal', 'streams_from_reads',
                 'source_path', 'collect', 'main')
    checks = {name: old[name] == new[name] for name in identical}
    checks['member_path_only_R33_label'] = old['member_path'].replace('R31/R16', 'R33/R16') == new['member_path']
    checks['verify_archive_only_schema_and_holder_binding'] = old['verify_archive'].replace(
        'hepta-r31-observation-evidence-archive/v1', 'hepta-r33-observation-evidence-archive/v1'
    ).replace('HOLDER_02_JOB', 'HOLDER_JOB') == new['verify_archive']
    create = new['create_archive']
    guard = ("    need(SEALED and LIFECYCLE_MATERIALIZATION_JOB is not None\n"
             "         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),\n"
             "         'unsealed R33 collector: original receipt identities are still missing')\n")
    assert create.count(guard) == 1
    create = create.replace(guard, '').replace(
        'hepta-r33-observation-evidence-archive/v1', 'hepta-r31-observation-evidence-archive/v1'
    ).replace("'r33_directories'", "'r31_directories'").replace(
        "'optional_r33_files'", "'optional_r31_files'"
    ).replace('HOLDER_JOB', 'HOLDER_02_JOB')
    checks['create_archive_only_seal_guard_and_labels'] = old['create_archive'] == create
    checks['same_limits_exact_AST'] = all(
        ast.dump(assignment(before, name)) == ast.dump(assignment(after, name))
        for name in ('MAX_TOTAL', 'MAX_FILE', 'MAX_MANIFEST', 'MAX_FILES', 'MAX_TAR')
    )
    checks['same_exclusions_and_stage_order'] = all(
        literal(before, name) == literal(after, name) for name in ('SKIP_DIRS', 'SKIP_FILES', 'STAGES')
    )
    checks['first_attempt_current_namespace'] = (
        literal(after, 'SELECTED_DIRS') == ('campaign-01', 'tools-01', 'boundary-tools-01', 'lifecycle-tools-01')
        and literal(after, 'EXTERNAL_DIRS') == ('measurement-tools', 'boundary-tools', 'r33-cancel-recovery-01')
    )
    checks['no_R31_preflight_history'] = all(token not in draft for token in (
        'HOLDER_01_JOB', 'HOLDER_02_JOB', 'prior_observation_preflight_failure',
        'campaign-02', '20261105-r31', 'r31-cancel-recovery'
    ))
    checks['false_adoption_not_overridden'] = "'candidate_adopted': False" in new['summary']
    checks['original_gate_outcome_retained'] = (
        "'observation_gate_passed': gate_passed" in new['summary']
        and "'performance_gates_passed': gates.get('performance_gates_passed')" in new['summary']
        and "'rejection_reasons': gates.get('rejection_reasons')" in new['summary']
        and "'original_auditors_reexecuted': False" in new['summary']
    )
    assert all(checks.values()), checks
    value = {
        'schema': 'hepta-r33-observation-collector-static-delta/v1', 'all_passed': True,
        'reference_sha256': hashlib.sha256(original.encode()).hexdigest(),
        'draft_sha256': hashlib.sha256(draft.encode()).hexdigest(),
        'sealed': literal(after, 'SEALED'), 'checks': checks,
        'collector_executed': False, 'original_auditors_reexecuted': False,
        'runtime_tests_executed': False, 'remote_calls': 0,
        'qualification_or_performance_result_invented': False,
    }
    with args.receipt.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__':
    main()

