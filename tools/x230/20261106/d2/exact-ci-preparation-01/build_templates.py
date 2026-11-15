#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Derive unsealed D2 exact-CI tools; do not execute their entry points."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = '/home/qian/hepta-runtime-validation-cost-20261106-d2'
OLD_ROOT = '/home/qian/hepta-runtime-phase-cost-20261106-d1'
PINS = ('JOB_ID', 'SOURCE_MAP_SHA', 'ISOLATED_SUMMARY_SHA', 'ISOLATED_AUDIT_SHA',
        'QUALIFICATION_REPORT_SHA', 'PREPARATION_SHA', 'NATIVE_TERMINAL_SHA',
        'PARENT_SHA', 'QUALIFICATION_BINDINGS_SHA', 'FROZEN_COUNTS')
TOOL_NAMES = ('materialize_rust_ci_plan_01.py', 'run_rust_ci_01.py',
              'audit_nextest_0137.py', 'canonical-workflow.yml')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def namespace(text):
    # Never apply unbounded d1 -> d2 substitutions to hexadecimal identities.
    return (text.replace(OLD_ROOT, ROOT).replace('hepta-d1-', 'hepta-d2-')
            .replace('hepta-x230-d1-', 'hepta-x230-d2-').replace('bind_d1_', 'bind_d2_')
            .replace('d1_ci_receipt_only_foundation', 'd2_ci_receipt_only_foundation')
            .replace('_d1_unsealed_materializer_definitions', '_d2_unsealed_materializer_definitions')
            .replace('d1_prerequisites.py', 'd2_prerequisites.py').replace('D1', 'D2'))


def replace_assignments(text, replacements):
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    spans, seen = [], set()
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in replacements:
                assert name not in seen
                seen.add(name)
                spans.append((offsets[node.lineno - 1] + node.col_offset,
                              offsets[node.end_lineno - 1] + node.end_col_offset,
                              name + ' = ' + replacements[name]))
    assert seen == set(replacements)
    for start, end, replacement in sorted(spans, reverse=True):
        text = text[:start] + replacement + text[end:]
    ast.parse(text)
    return text


def prepare_texts():
    names = (*TOOL_NAMES, 'launch_exact_rust_ci_01.py')
    refs = {name: (HERE / 'references-d1' / name).read_bytes() for name in names}
    known = json.loads((HERE / 'reference-identities.json').read_bytes())
    for name, raw in refs.items():
        assert identity(raw) == {key: known[name][key] for key in ('bytes', 'sha256')}
    materializer = namespace(refs['materialize_rust_ci_plan_01.py'].decode())
    materializer = replace_assignments(materializer, {
        **{name: 'None' for name in PINS},
        'PARENT_PATH': 'ROOT / "full-prerequisites-01/d2_prerequisites.py"'})
    runner = namespace(refs['run_rust_ci_01.py'].decode())
    launcher = replace_assignments(namespace(refs['launch_exact_rust_ci_01.py'].decode()), {'SPEC': 'None'})
    tools = {'materialize_rust_ci_plan_01.py': materializer.encode(),
             'run_rust_ci_01.py': runner.encode(), 'launch_exact_rust_ci_01.py': launcher.encode(),
             'audit_nextest_0137.py': refs['audit_nextest_0137.py'],
             'canonical-workflow.yml': refs['canonical-workflow.yml']}
    for name, raw in tools.items():
        if name.endswith('.py'):
            ast.parse(raw)
    tools['package-manifest-01.json'] = encode({
        'schema': 'hepta-d2-exact-rust-ci-tools/v1', 'attempt': '01', 'sealed': False,
        'actual_qualification_job_id': None, 'qualification_report': None,
        'actual_pins': {name: None for name in PINS},
        'files': {name: identity(tools[name]) for name in TOOL_NAMES},
        'executed': False, 'hosted_actions_passed': False})
    return tools


def main():
    tools = prepare_texts()
    out = HERE / 'unsealed-tools'
    out.mkdir(mode=0o700, exist_ok=False)
    for name, raw in tools.items():
        with (out / name).open('xb') as stream:
            stream.write(raw)
    report = {'schema': 'hepta-d2-exact-ci-unsealed-template-generation/v1',
        'files': {name: identity(raw) for name, raw in tools.items()},
        'actual_qualification_pins': None, 'rust_ci_executed': False, 'host_api_used': False,
        'source_count': 222, 'foundation_independent_of_ci_success': True,
        'original_runner_namespace_only': True, 'original_auditor_byte_identical': True,
        'original_canonical_workflow_byte_identical': True,
        'original_nextest_0137_pin_unchanged': True,
        'materializer_delta': ['D2 namespace', 'explicit canonical D2 prerequisite module path'],
        'original_commands_and_cleanup_unchanged': True}
    with (HERE / 'template-generation.json').open('xb') as stream:
        stream.write(encode(report))
    print(json.dumps({'files': len(tools), 'materializer': identity(tools['materialize_rust_ci_plan_01.py']),
                      'pins_sealed': False, 'target_entry_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
