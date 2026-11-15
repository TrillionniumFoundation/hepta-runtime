#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compare original tool text and AST; do not import a CI entry or run a child."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
OLD = '/home/qian/hepta-runtime-optimization-20261106-r35'
NEW = '/home/qian/hepta-runtime-phase-cost-20261106-d1'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def namespace(text):
    return text.replace(OLD, NEW).replace('R35', 'D1').replace('r35', 'd1')


def definitions(text):
    return {node.name: ast.get_source_segment(text, node) for node in ast.parse(text).body
            if isinstance(node, ast.FunctionDef)}


def assignments(text):
    return {node.targets[0].id: ast.unparse(node.value) for node in ast.parse(text).body
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}


def main():
    refs, tools = HERE / 'references-r35', HERE / 'unsealed-tools'
    old_runner = (refs / 'run_rust_ci_01.py').read_text()
    runner = (tools / 'run_rust_ci_01.py').read_text()
    assert runner == namespace(old_runner)
    for name in ('audit_nextest_0137.py', 'canonical-workflow.yml'):
        assert (tools / name).read_bytes() == (refs / name).read_bytes()
    old = namespace((refs / 'materialize_rust_ci_plan_01.py').read_text())
    new = (tools / 'materialize_rust_ci_plan_01.py').read_text()
    before, after = definitions(old), definitions(new)
    assert set(before) == set(after)
    changed = {name for name in before if before[name] != after[name]}
    assert changed == {'verify_preparation', 'verify_qualification'}
    assert after['verify_qualification'] == before['verify_qualification'].replace(
        'len(value["source_after"]) == 220', 'len(value["source_after"]) == 222')
    old_assignments, new_assignments = assignments(old), assignments(new)
    for name in ('COMMANDS', 'INVENTORY_COMMAND', 'STAGES', 'BINARY_NAMES', 'CI_MANIFEST_SHA',
                 'NEXTEST_ROOT', 'NEXTEST_RECEIPT_SHA', 'NEXTEST_BINARY',
                 'CANONICAL_WORKFLOW', 'CANONICAL_WORKFLOW_GIT_BLOB', 'PRIVATE_SOURCE_WORKFLOW'):
        assert old_assignments[name] == new_assignments[name]
    nulls = ['JOB_ID', 'SOURCE_MAP_SHA', 'ISOLATED_SUMMARY_SHA', 'ISOLATED_AUDIT_SHA',
             'QUALIFICATION_REPORT_SHA', 'PREPARATION_SHA', 'NATIVE_TERMINAL_SHA',
             'PARENT_SHA', 'QUALIFICATION_BINDINGS_SHA', 'FROZEN_COUNTS']
    assert all(new_assignments[name] == 'None' for name in nulls)
    main_node = next(node for node in ast.parse(new).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    assert ast.unparse(main_node.body[0]) == 'require_frozen_qualification()'
    launcher = (tools / 'launch_exact_rust_ci_01.py').read_text()
    old_launcher = namespace((refs / 'launch_exact_rust_ci_01.py').read_text())
    old_tree, new_tree = ast.parse(old_launcher), ast.parse(launcher)
    for tree in (old_tree, new_tree):
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'SPEC':
                node.value = ast.Constant(None)
    assert ast.dump(old_tree, include_attributes=False) == ast.dump(new_tree, include_attributes=False)
    assert assignments(launcher)['SPEC'] == 'None'
    parsed = []
    for directory in (HERE, tools):
        for path in sorted(directory.glob('*.py')):
            ast.parse(path.read_bytes())
            parsed.append(path.relative_to(HERE).as_posix())
    report = {'schema': 'hepta-d1-exact-ci-template-static-review/v1',
        'reference_tools_tree': 'a39e0e61163bb5780685fcbc1c9db1fefa2a97e4',
        'runner_namespace_only': True, 'launcher_namespace_and_null_spec_only': True,
        'auditor_and_canonical_workflow_original_bytes': True,
        'original_commands_nextest_and_workflow_pins_unchanged': True,
        'materializer_changed_functions': sorted(changed), 'future_pin_constants_all_null': nulls,
        'source_count': 222, 'q_only_foundation_independent_of_future_ci_result': True,
        'python_ast_inputs': parsed,
        'unsealed_tools': {p.name: identity(p.read_bytes()) for p in sorted(tools.iterdir()) if p.is_file()},
        'sealer': identity((HERE / 'seal_exact_ci.py').read_bytes()),
        'ci_entry_or_qualifier_or_fixture_or_host_executed': False,
        'completed_d1_qualification_claimed': False, 'performance_acceptance_claim': False}
    with (HERE / 'static-review.json').open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({'changed_materializer_functions': sorted(changed), 'ast_inputs': len(parsed),
                      'future_pins_null': True, 'ci_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
