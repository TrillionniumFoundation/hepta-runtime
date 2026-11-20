#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Check exact CI profile successors and reject physical source corruption.

This only runs source readers and the historical source materializer. It never
builds or executes a compiler, a native application, a Rust binary or SSH.
"""
from pathlib import Path
import argparse, copy, hashlib, importlib.util, json, subprocess, sys
sys.dont_write_bytecode = True

FROZEN = {
    'before-historical-materialize.py': 'b36fe4373497c6958ce3ac0b97a6f8489afce075',
    'before-historical-PROFILE.json': '2bbdec033b1df74070d96aba9b696bea7a6392af',
    'before-hia-public-current.yml': '0613d6e95d85b92ec725c783481c181bf6b0a011',
}
COMPOSITION = 'native/runtime_mcp_binary_root_integration.json'

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

def rejected(operation):
    try:
        operation()
    except (AssertionError, ValueError) as error:
        return {'rejected': True, 'exception': type(error).__name__, 'reason': str(error)}
    raise AssertionError('corrupt source was accepted')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--frozen-inputs', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    root = a.source.resolve(strict=True)
    assert not a.output.exists() and not a.output.absolute().is_relative_to(root)
    a.output.mkdir(parents=True)
    frozen = {}
    for name, expected in FROZEN.items():
        raw = (a.frozen_inputs/name).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest() == expected
        frozen[name] = raw
    recipe = root/'qualification/public124_default_entry_v1/source'
    entry = module('binary_root_ci_entry', recipe/'entry.py')
    checked = entry.check_source(root)
    assert checked['source_files'] == 537 and checked['binary_root_operation9'] is True
    entry.prepare(root, a.output/'source-controls')
    control = a.output/'source-controls/source'
    assert entry.check_source(control) == checked
    controls = []
    for name in ('native/config_directory_owner_span.hepta', 'scripts/runtime_mcp_extra_engine.S',
                 'native/runtime_mcp_sources.json', COMPOSITION, 'native/runtime_mcp.hepta'):
        path = control/name
        original = path.read_bytes()
        try:
            path.write_bytes(original+b'\n')
            result = rejected(lambda: entry.check_source(control))
        finally:
            path.write_bytes(original)
        assert entry.check_source(control) == checked
        controls.append(dict(path=name, exact_source_restored=True, **result))
    path = control/COMPOSITION
    saved = path.with_suffix('.saved')
    try:
        path.rename(saved)
        result = rejected(lambda: entry.check_source(control))
    finally:
        saved.rename(path)
    assert entry.check_source(control) == checked
    controls.append(dict(path=COMPOSITION, missing_successor_rejected=True,
                         exact_source_restored=True, **result))

    prefix = root/'tests/hia_native/historical_public58'
    historical = module('binary_root_ci_historical', prefix/'materialize.py')
    current, digest = historical.check(root)
    before = json.loads(frozen['before-historical-PROFILE.json'])
    restored = copy.deepcopy(current)
    restored['schema'] = before['schema']
    restored['current_default_graph_binding_sha256'] = before['current_default_graph_binding_sha256']
    restored['remove_current_public_only'].remove(COMPOSITION)
    del restored['current_graph_files'][COMPOSITION]
    for name in ('native/config_directory_owner_span.hepta', 'scripts/runtime_mcp_extra_engine.S',
                 'native/runtime_mcp_sources.json'):
        restored['current_graph_files'][name] = before['current_graph_files'][name]
    assert restored == before, 'whole historical profile inverse'
    materializer = (prefix/'materialize.py').read_text()
    replacements = (
        ('source-profile.v6', 'source-profile.v7'),
        ('len(profile["current_graph_files"])==536', 'len(profile["current_graph_files"])==537'),
        ('len(profile["remove_current_public_only"])==392', 'len(profile["remove_current_public_only"])==393'),
        ('current_graph_files=536', 'current_graph_files=537'),
    )
    for old, new in reversed(replacements):
        assert materializer.count(new) == 1
        materializer = materializer.replace(new, old, 1)
    assert materializer.encode() == frozen['before-historical-materialize.py']
    output = a.output/'historical-source'
    command = [sys.executable, '-I', '-S', '-B', str(prefix/'materialize.py'),
               '--source', str(root), '--output', str(output.absolute())]
    with (a.output/'historical.stdout').open('wb') as out, (a.output/'historical.stderr').open('wb') as err:
        process = subprocess.run(command, stdout=out, stderr=err, check=False)
    assert process.returncode == 0
    historical_result = historical.verify_materialized(output)
    path = output/'native/config_directory_owner_span.hepta'
    original = path.read_bytes()
    try:
        path.write_bytes(original+b'\n')
        historical_negative = rejected(lambda: historical.verify_materialized(output))
    finally:
        path.write_bytes(original)
    assert historical.verify_materialized(output) == historical_result

    old_pin = '73a626fdc201bb4b0020101fef06c738141b609587038ca17485974a7254bcc8'
    new_pin = hashlib.sha256((recipe/'SOURCE_MANIFEST.json').read_bytes()).hexdigest()
    workflow = (root/'.github/workflows/hia-public-current.yml').read_text()
    assert workflow.count(new_pin) == 2 and old_pin not in workflow
    assert workflow.replace(new_pin, old_pin).encode() == frozen['before-hia-public-current.yml']
    result = dict(status='EXACT_CI_PROFILE_SUCCESSORS_PASS', source=checked, source_controls=controls,
        historical=historical_result, historical_corruption=historical_negative,
        historical_profile_whole_inverse=True, historical_materializer_whole_inverse=True,
        historical_restore_pins_unchanged=120, workflow_whole_inverse=True,
        workflow_manifest_pin_occurrences_updated=2, workflow_gates_and_budgets_unchanged=True,
        compiler_or_native_application_or_rust_or_ssh_executed=False)
    (a.output/'RESULT.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
