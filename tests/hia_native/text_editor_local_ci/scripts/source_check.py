#!/usr/bin/env python3
"""Verify portable source closure and case ASTs without compiling or running owners."""
from pathlib import Path
import argparse
import ast
import hashlib
import importlib.util
import json
import re
import sys
import tomllib

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import definitions, encode, fingerprint, load, ordinary_cases, sha


def read_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_pins(root):
    return {str(p.relative_to(root)): {'bytes': p.stat().st_size, 'sha256': sha(p.read_bytes())}
            for p in sorted(root.rglob('*')) if p.is_file()}


def literal(tree, name):
    matches = [node.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    assert len(matches) == 1, name
    return ast.literal_eval(matches[0])


def verify(source):
    assert sys.version_info[:2] == (3, 12), 'the frozen AST fingerprints require Python 3.12'
    source = Path(source).resolve(strict=True)
    manifest = json.loads((source / 'source-manifest.json').read_bytes())
    assert manifest['schema'] == 'hepta.text-local.portable-source-bundle.v1'
    actual = {str(p.relative_to(source)) for p in source.rglob('*') if p.is_file()}
    assert actual == set(manifest['files']) | {'source-manifest.json'}
    python_files = 0
    for relative, pin in manifest['files'].items():
        rel = Path(relative)
        assert not rel.is_absolute() and '..' not in rel.parts
        path = source / rel
        assert path.is_file() and not path.is_symlink(), relative
        raw = path.read_bytes()
        assert pin['bytes'] == len(raw) and pin['sha256'] == sha(raw), relative
        if path.suffix == '.py':
            ast.parse(raw, filename=relative)
            python_files += 1
    for forbidden in ('qualify_complete_v2.py', 'build_reference.py', 'build', 'native-build',
                      'local-native-build.process.json', 'local-native-build.stdout', 'local-native-build.stderr'):
        assert not (source / forbidden).exists(), forbidden
    inputs = json.loads((source / 'source-pins/inputs.json').read_bytes())
    assert len(inputs['files']) == 184
    for relative, pin in inputs['files'].items():
        raw = (source / relative).read_bytes()
        assert pin == {'bytes': len(raw), 'sha256': sha(raw)}, relative
    assert len(file_pins(source / 'source')) == 142
    assert len(file_pins(source / 'reference-v1')) == 35
    assert len(file_pins(source / 'qualification_support')) == 2
    reference = read_module('_frozen_original_reference_source_checker', source / 'verify_reference.py')
    reference_result = reference.verify(source / 'reference-v1')
    assert reference_result['original_items'] == 106
    deps = json.loads((source / 'ci/dependencies.json').read_bytes())
    assert deps['python'] == '3.12'
    assert deps['original_target']['commit'] == 'd3d75c30719db966b004756f610007a7c723729e'
    assert deps['expected_total_cases'] == sum(deps['profiles'].values()) == 357
    assert deps['native_process_deadline_seconds'] == deps['original_process_deadline_seconds'] == 60
    assert deps['reference_step_deadline_seconds'] == 180 and deps['new_outer_process_deadline_seconds'] is None
    portability = json.loads((source / 'portability.json').read_bytes())
    assert portability['qualifier_sha256'] == sha((source / 'qualify_portable.py').read_bytes())
    assert portability['reference_builder_sha256'] == sha((source / 'build_reference_portable.py').read_bytes())
    assert portability['native_process_deadline_seconds'] == portability['original_process_deadline_seconds'] == 60
    assert portability['reference_build_step_deadline_seconds'] == 180
    contract = load(source)
    proof = json.loads((source / 'source-pins/readonly-contract.json').read_bytes())
    assert proof == contract['fingerprints']
    case_pins = json.loads((source / 'source-pins/ordinary-cases.json').read_bytes())
    counts = {}
    for profile, expected in deps['profiles'].items():
        rows = ordinary_cases(contract, profile, '/fixture/effects')
        raw = b''.join(encode(row) for row in rows)
        assert len(rows) == expected
        pin = {'cases': len(rows), 'bytes': len(raw), 'sha256': sha(raw)}
        assert case_pins['profiles'][profile] == pin, profile
        counts[profile] = len(rows)
    native_pins = json.loads((source / 'source-pins/native-target.json').read_bytes())
    builder = ast.parse((source / 'source/scripts/text_editor_create_private_build.py').read_bytes())
    members = literal(builder, 'MEMBERS')
    assert len(members) == len(native_pins['members']) == native_pins['physical_images'] == 75
    for (name, owner, profile), row in zip(members, native_pins['members'], strict=True):
        assert (name, 'native/' + owner + '.hepta', profile) == (row['name'], row['source'], row['buffer_profile'])
        assert sha((source / 'source' / row['source']).read_bytes()) == row['source_sha256'], name
    closure_path = source / 'source/native/runtime_mcp_sources.json'
    closure_raw = closure_path.read_bytes()
    assert sha(closure_raw) == native_pins['source_binding_sha256']
    closure = json.loads(closure_raw)
    for relative, pin in closure['sources'].items():
        raw = (source / 'source' / relative).read_bytes()
        assert pin == {'bytes': len(raw), 'sha256': sha(raw)}, relative
    required = {literal(builder, 'BASE'), literal(builder, 'TRANSPORT'),
                *literal(builder, 'BOUNDARIES'), *literal(builder, 'FIXTURE_BOUNDARIES'),
                *literal(builder, 'HELPERS'), 'native/runtime_mcp_image_packer.hepta',
                *('native/' + owner + '.hepta' for _, owner, _ in members)}
    assert required <= set(closure['sources'])
    reference_root = source / 'reference-v1'
    includes = []
    for path in sorted((reference_root / 'src').rglob('*.rs')):
        for literal_path in re.findall(r'include!\(\s*"([^"\n]+)"\s*\)', path.read_text()):
            dependency = (path.parent / literal_path).resolve(strict=True)
            assert dependency.is_relative_to(reference_root.resolve()) and dependency.is_file()
            includes.append({'source': str(path.relative_to(reference_root)), 'included': str(dependency.relative_to(reference_root))})
    full_lock = tomllib.loads((reference_root / 'target/Cargo.lock').read_text())
    pins = {(p['name'], p['version'], p.get('source')): p.get('checksum')
            for p in full_lock['package'] if p.get('source')}
    retained = []
    for package in tomllib.loads((reference_root / 'Cargo.lock').read_text())['package']:
        if not package.get('source'):
            assert package['name'] == 'hepta-text-editor-gateway-local-original-oracle'
        else:
            key = package['name'], package['version'], package['source']
            assert key in pins and pins[key] == package['checksum'], key
            retained.append(key)
    return {'status': 'SOURCE_CHECK_PASS', 'source_files': len(manifest['files']),
            'frozen_inputs_unchanged': 184, 'python_ast_files': python_files,
            'native_owner_sources': 75, 'original_reference_files': 35,
            'exact_original_fragments': 106, 'rust_literal_include_edges': len(includes),
            'retained_target_registry_packages': len(retained), 'profiles': counts,
            'ordinary_cases': sum(counts.values()), 'case_asts_changed': False,
            'comparison_asts_changed': False, 'read_only_contract': contract['fingerprints'],
            'rust_type_check_executed': False, 'rust_hia_native_executed': False,
            'public_text_editor_route': False, 'whole_runtime_replaced': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.source), sort_keys=True))


if __name__ == '__main__':
    main()
