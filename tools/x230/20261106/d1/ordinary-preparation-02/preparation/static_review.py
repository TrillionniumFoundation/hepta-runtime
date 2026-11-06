#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Parse text/AST/TOML and compare derivation; execute no target entry or helper."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import tomllib


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    original = (root / 'references/qualify.py').read_bytes()
    derived = (root / 'unsealed-tools/qualify_ordinary_01.py').read_bytes()
    omitted = (root / 'removed-already-covered-stage-calls.txt').read_bytes()
    assert original.count(b', "--all-features"') == 3 and original.count(omitted) == 1
    assert derived == original.replace(b', "--all-features"', b'').replace(omitted, b'')
    assert b'--all-features' not in derived and b'--no-default-features' not in derived
    original_tree, derived_tree = ast.parse(original), ast.parse(derived)
    class Normalize(ast.NodeTransformer):
        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == 'stage':
                if node.value.args and isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value in {
                    'format', 'fmt-check', 'harness-tests'}:
                    return None
            return self.generic_visit(node)
        def visit_List(self, node):
            node.elts = [value for value in node.elts if not (
                isinstance(value, ast.Constant) and value.value == '--all-features')]
            return self.generic_visit(node)
    assert ast.dump(Normalize().visit(original_tree), include_attributes=False) == ast.dump(derived_tree, include_attributes=False)
    def segments(raw):
        text = raw.decode()
        tree = ast.parse(text)
        main_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        top = {node.name: ast.get_source_segment(text, node) for node in tree.body
               if isinstance(node, ast.FunctionDef) and node.name != 'main'}
        top.update({'main.' + node.name: ast.get_source_segment(text, node)
                    for node in main_node.body if isinstance(node, ast.FunctionDef)})
        return top
    before_helpers, after_helpers = segments(original), segments(derived)
    assert before_helpers == after_helpers and set(before_helpers) == {'sha', 'source_map', 'main.save', 'main.stage'}
    stage_names = [node.args[0].value for node in ast.walk(derived_tree)
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'stage'
                   and node.args and isinstance(node.args[0], ast.Constant)]
    expected = ['clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
    assert stage_names == expected
    old_cargo = tomllib.loads((root / 'references/Cargo-R24.toml').read_text())
    new_cargo = tomllib.loads((root / 'references/Cargo-D1.toml').read_text())
    assert old_cargo.get('features', {}) == {}
    assert new_cargo['features'] == {'phase-cost-diagnostics': []}
    assert {key: value for key, value in new_cargo.items() if key != 'features'} == old_cargo
    parsed = []
    for path in sorted(root.rglob('*.py')):
        ast.parse(path.read_text())
        parsed.append(str(path.relative_to(root)))
    launcher_tree = ast.parse((root / 'unsealed-tools/launch_ordinary_01.py').read_text())
    spec = next(node for node in launcher_tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'SPEC' for target in node.targets))
    assert isinstance(spec.value, ast.Constant) and spec.value.value is None
    verifier_tree = ast.parse((root / 'unsealed-tools/verify_ordinary_01.py').read_text())
    function = next(node for node in verifier_tree.body if isinstance(node, ast.FunctionDef) and node.name == 'verify_ordinary')
    assert [arg.arg for arg in function.args.args] == ['inputs', 'bind', 'foundation', 'prerequisite_proof']
    for name in ('launch-seal-request.unsealed.json', 'result-seal-request.unsealed.json'):
        value = json.loads((root / name).read_bytes())
        assert value['sealed_inputs'] is False
    report = {'schema': 'hepta-d1-ordinary-static-review/v2', 'passed': True,
        'scope': 'AST/text/TOML only; no target import, entry, compiler, test or host call',
        'original_qualifier': identity(original), 'ordinary_qualifier': identity(derived),
        'exact_feature_argument_removals': 3, 'exact_omitted_stage_calls': ['format', 'fmt-check', 'harness-tests'],
        'supplement_stages': stage_names,
        'all_other_qualifier_ast_equal': True, 'preserved_original_helpers': before_helpers.keys(),
        'helper_source_bytes_equal': True, 'package_features_before': [], 'ordinary_package_features': [],
        'diagnostic_only_added_feature': 'phase-cost-diagnostics', 'all_other_cargo_toml_equal': True,
        'python_ast_parsed': parsed, 'launcher_and_requests_unsealed': True,
        'ordinary_results': None, 'ordinary_programs': None, 'performance_acceptance_claim': False}
    report['preserved_original_helpers'] = sorted(report['preserved_original_helpers'])
    body = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(body)
    print(json.dumps({'passed': True, 'report': identity(body), 'target_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
