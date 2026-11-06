#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Local text/AST preparation only; never invokes the generated qualifier."""
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent / 'r24-phase-cost-candidate-recovery-02'
HELPERS = ['sha', 'source_map', 'save', 'known_nondumpable_helper', 'inspect_processes',
           'retained_programs', 'read_bound', 'input_identity', 'relative_identity',
           'native_terminal', 'closed_stages', 'completed_qualification', 'native_streams']


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def main():
    original = (HERE / 'references/prepare_r35.py').read_text()
    functions = {node.name: ast.get_source_segment(original, node) for node in ast.parse(original).body
                 if isinstance(node, ast.FunctionDef)}
    candidate = json.loads((PACKAGE / 'input.json').read_bytes())
    constants = '''#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""First D1 qualification: frozen R24 diagnostics, original eight-stage all-features gates.

R35 supplies its unused build cache after its real rejected lifecycle owners
closed. This preparer neither adopts R35 nor starts any diagnostic measurement.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tomllib

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
CACHE_OWNER = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
HEX = re.compile(r'[0-9a-f]{64}\\Z')
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT',
                  'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')
OWNER_POSTFLIGHT_JOB = '1a1afe8986e-fc05-6ca9'
OWNER_JOBS = {'qualification': '1a1af619097-fc05-6813', 'exact_ci': '1a1af88c330-fc05-696f',
              'observation': '1a1af9bb312-fc05-6a14', 'lifecycle_materialization': '1a1afb8c456-fc05-6b1d',
              'normal_lifecycle': '1a1afc4fb4a-fc05-6b7f'}
OWNER_COUNTS = {'passed': 1645, 'failed': 0, 'ignored': 34, 'selected': 1679, 'retries': 0}
'''
    constants += 'CHANGED = set(' + repr(candidate['changed_paths']) + ')\n'
    constants += 'ADDED = set(' + repr(candidate['added_paths']) + ')\n'
    constants += 'NEW_TESTS = set(' + repr(candidate['new_test_functions']) + ')\n\n\n'
    helper_text = '\n\n\n'.join(functions[name] for name in HELPERS) + '\n\n\n'
    fragments = [(HERE / name).read_text() for name in ('candidate_fragment.py', 'owner_fragment.py', 'main_fragment.py')]
    result = constants + helper_text + '\n\n\n'.join(fragments)
    ast.parse(result)
    target = HERE / 'prepare_qualify.py'
    target.write_text(result)
    actual = {node.name: ast.get_source_segment(result, node) for node in ast.parse(result).body
              if isinstance(node, ast.FunctionDef)}
    assert all(actual[name] == functions[name] for name in HELPERS)
    receipt = {'schema': 'hepta-d1-preparer-static-generation/v1',
               'original_preparer': {'bytes': len(original.encode()), 'sha256': digest(original.encode())},
               'generated_preparer': {'bytes': len(result.encode()), 'sha256': digest(result.encode())},
               'unchanged_helpers': {name: {'bytes': len(functions[name].encode()),
                                          'sha256': digest(functions[name].encode())} for name in HELPERS},
               'unchanged_helper_count': 13, 'python_ast_parsed': True,
               'generated_preparer_executed': False, 'host_or_cargo_or_fixture_executed': False}
    (HERE / 'helper-reuse-static.json').write_bytes(json_bytes(receipt))
    print(json.dumps(receipt['generated_preparer'], sort_keys=True))


if __name__ == '__main__':
    main()
