#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create D1 unsealed exact-CI text from the actual reviewed R35 tools."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = '/home/qian/hepta-runtime-phase-cost-20261106-d1'
OLD_ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
PINS = ('JOB_ID', 'SOURCE_MAP_SHA', 'ISOLATED_SUMMARY_SHA', 'ISOLATED_AUDIT_SHA',
        'QUALIFICATION_REPORT_SHA', 'PREPARATION_SHA', 'NATIVE_TERMINAL_SHA',
        'PARENT_SHA', 'QUALIFICATION_BINDINGS_SHA', 'FROZEN_COUNTS')
TOOL_NAMES = ('materialize_rust_ci_plan_01.py', 'run_rust_ci_01.py',
              'audit_nextest_0137.py', 'canonical-workflow.yml')


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def namespace(text):
    return text.replace(OLD_ROOT, ROOT).replace('R35', 'D1').replace('r35', 'd1')


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


def replace_function(text, name, replacement):
    node = next(node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name)
    original = ast.get_source_segment(text, node)
    assert text.count(original) == 1
    return text.replace(original, replacement.rstrip('\n'), 1)


def prepare_texts():
    refs = {name: (HERE / 'references-r35' / name).read_bytes() for name in
            (*TOOL_NAMES, 'launch_exact_rust_ci_01.py', 'package-manifest-01.json')}
    known = json.loads((HERE / 'reference-identities.json').read_bytes())
    for row in known['files']:
        if row['name'] in refs:
            assert identity(refs[row['name']]) == {key: row[key] for key in ('bytes', 'sha256')}
    materializer = namespace(refs['materialize_rust_ci_plan_01.py'].decode())
    assert materializer.count('len(value["source_after"]) == 220') == 1
    materializer = materializer.replace('len(value["source_after"]) == 220', 'len(value["source_after"]) == 222')
    replacements = {name: 'None' for name in PINS}
    replacements.update({'PARENT_PATH': 'ROOT / "rust-ci-prerequisites-01/d1_prerequisites.py"',
                         'QUALIFICATION_BINDINGS_PATH': 'ROOT / "qualification-prerequisites-01.json"'})
    materializer = replace_assignments(materializer, replacements)
    materializer = replace_function(materializer, 'verify_preparation',
                                   (HERE / 'verify_preparation_fragment.py').read_text())
    runner = namespace(refs['run_rust_ci_01.py'].decode())
    launcher = replace_assignments(namespace(refs['launch_exact_rust_ci_01.py'].decode()), {'SPEC': 'None'})
    tools = {'materialize_rust_ci_plan_01.py': materializer.encode(),
             'run_rust_ci_01.py': runner.encode(), 'launch_exact_rust_ci_01.py': launcher.encode(),
             'audit_nextest_0137.py': refs['audit_nextest_0137.py'],
             'canonical-workflow.yml': refs['canonical-workflow.yml']}
    for name, raw in tools.items():
        if name.endswith('.py'):
            ast.parse(raw)
    # The complete runner, including child identity, signals, wait/reap,
    # deadline and original stream handling, differs only in namespace.
    assert runner == namespace(refs['run_rust_ci_01.py'].decode())
    assert tools['audit_nextest_0137.py'] == refs['audit_nextest_0137.py']
    assert tools['canonical-workflow.yml'] == refs['canonical-workflow.yml']
    manifest = {'schema': 'hepta-d1-exact-rust-ci-tools/v1', 'attempt': '01', 'sealed': False,
        'actual_qualification_job_id': None, 'qualification_report': None,
        'actual_pins': {name: None for name in PINS},
        'files': {name: identity(tools[name]) for name in TOOL_NAMES},
        'executed': False, 'hosted_actions_passed': False}
    tools['package-manifest-01.json'] = encode(manifest)
    return tools


def main():
    output = HERE / 'unsealed-tools'
    output.mkdir(mode=0o700, exist_ok=False)
    tools = prepare_texts()
    for name, raw in tools.items():
        with (output / name).open('xb') as stream:
            stream.write(raw)
    receipt = {'schema': 'hepta-d1-exact-ci-unsealed-template-generation/v1',
        'files': {name: identity(raw) for name, raw in sorted(tools.items())},
        'actual_qualification_pins': None, 'rust_ci_executed': False, 'host_api_used': False,
        'original_runner_namespace_only': True, 'original_auditor_byte_identical': True,
        'original_canonical_workflow_byte_identical': True, 'original_nextest_0137_pin_unchanged': True,
        'source_count': 222, 'foundation_independent_of_ci_success': True,
        'materializer_semantic_changes': ['namespace', 'source count 220 to 222',
            'all actual qualification pins are None', 'Q-only prerequisite module and input bindings'],
        'future_original_commands': [
            ['cargo', 'check', '--locked', '--all-targets', '--all-features'],
            ['cargo', 'nextest', 'run', '--locked', '--all-targets', '--all-features',
             '--test-threads', '1', '--retries', '0', '--no-fail-fast']]}
    with (HERE / 'template-generation.json').open('xb') as stream:
        stream.write(encode(receipt))
    print(json.dumps({'output': str(output), 'file_count': len(tools), 'pins_sealed': False,
                      'materializer': identity(tools['materialize_rust_ci_plan_01.py'])}, sort_keys=True))


if __name__ == '__main__':
    main()
