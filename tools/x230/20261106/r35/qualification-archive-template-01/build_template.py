#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Prepare an unsealed R35 collector by static transformations and exact input hashing."""
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import stat

HERE = Path(__file__).resolve().parent
PREP = HERE.parent / 'r35-qualification-prep-01/sealed-01'
INSTALL = HERE.parent / 'r35-installation-originals-01'
REFERENCE = HERE / 'reference-r34/archive_r34_qualification.py'
REFERENCE_SHA = 'b9a5a8cbb64a745cc70cd9acff647dee3faf37c541ea55edee802d80318521aa'
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
FUTURE = ('preparation.json', 'qualification-terminal-status-01.json', 'qualification-native-read-01.json',
          'qualification-01/report.json', 'qualification-01/source-map.json',
          'qualification-01/isolated-tests/summary.json', 'qualification-01/isolated-tests.audit.json')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def functions(text):
    lines = text.splitlines(keepends=True)
    return {node.name: ''.join(lines[node.lineno - 1:node.end_lineno])
            for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


def version(text):
    return text.replace('R34', '__NEW_UPPER__').replace('r34', '__NEW_LOWER__').replace(
        'R33', 'R34').replace('r33', 'r34').replace('__NEW_UPPER__', 'R35').replace('__NEW_LOWER__', 'r35')


def main():
    original_raw = REFERENCE.read_bytes()
    assert len(original_raw) == 57273 and sha(original_raw) == REFERENCE_SHA
    original = original_raw.decode()
    old = functions(original)
    manifest_raw = (PREP / 'frozen-preparation-manifest.json').read_bytes()
    assert len(manifest_raw) == 7532 and sha(manifest_raw) == 'a2c8155bca4bbad9d805270fafc4c6ab968e4d559c794636bdb033ef7307f000'
    manifest = json.loads(manifest_raw)
    pinned, local = {}, {}
    for pin in manifest['files']:
        name = pin['path']
        raw = (PREP / name).read_bytes()
        assert identity(raw) == {key: pin[key] for key in ('bytes', 'sha256')} and name not in pinned
        pinned[name], local[name] = identity(raw), str(PREP / name)
    pinned['frozen-preparation-manifest.json'] = identity(manifest_raw)
    local['frozen-preparation-manifest.json'] = str(PREP / 'frozen-preparation-manifest.json')
    assert len(pinned) == 39
    plan = json.loads((HERE / 'installation-original-copy-plan.json').read_bytes())
    for row in plan['files_to_install_create_only_after_qualification']:
        raw = Path(row['local_path']).read_bytes()
        assert identity(raw) == {key: row[key] for key in ('bytes', 'sha256')}
        name = row['remote_relative_path']
        assert name.startswith('installation-originals-01/') and name not in pinned
        pinned[name], local[name] = identity(raw), row['local_path']
    row = plan['already_installed_receipt']
    raw = (INSTALL / row['path']).read_bytes()
    assert identity(raw) == {key: row[key] for key in ('bytes', 'sha256')}
    pinned[row['path']], local[row['path']] = identity(raw), str(INSTALL / row['path'])
    assert len(pinned) == 54
    for name, path in local.items():
        p = Path(path)
        assert stat.S_ISREG(p.lstat().st_mode) and p.lstat().st_nlink == 1
        raw = p.read_bytes()
        assert identity(raw) == pinned[name] and len(raw) <= 8 * 1024**2
        assert not raw.startswith(b'\x7fELF') and b'PRIVATE KEY-----' not in raw and b'openssh-key-v1\0' not in raw
    # Replace only constants and the original receipt/domain binding functions.
    changed = {'collect': version(old['collect']), 'qualified_summary': version(old['qualified_summary']),
               'create_archive': version(old['create_archive']), 'verify_archive': version(old['verify_archive'])}
    q = changed['qualified_summary']
    replacements = [
        ("len(set(candidate['new_test_functions'])) == len(candidate['new_test_functions']) == 8",
         "candidate['new_test_functions'] == []"),
        ("accepted-R24 four-file candidate", "accepted-R24 three-file candidate"),
        ("hepta-x230-r35-candidate-manifest/v1", "hepta-x230-r35-source-package/v1"),
        ("set(frozen['changed_paths']) == CHANGED_PATHS and len(frozen['files']) == 21",
         "set(frozen['changed_compile_paths']) == CHANGED_PATHS and len(frozen['files']) == 28"),
        ("exact 22-member frozen selection", "exact 29-member frozen selection"),
        ("and prep['cache_owner_closure']['lifecycle_materializer_rejected_before_abba'] is True",
         "and closure['lifecycle_materialization_started'] is False\n"
         "         and closure['lifecycle_materializer_job_id'] is None\n"
         "         and closure['capacity_build_or_campaign_started_by_coordinator'] is False\n"
         "         and prep['cache_owner_closure']['lifecycle_materialization_started'] is False\n"
         "         and prep['cache_owner_closure']['lifecycle_materializer_job_id'] is None\n"
         "         and prep['cache_owner_closure']['normal_lifecycle_started'] is False\n"
         "         and prep['cache_owner_closure']['capacity_build_or_campaign_started_by_coordinator'] is False"),
    ]
    for a, b in replacements:
        assert q.count(a) == 1, a
        q = q.replace(a, b)
    changed['qualified_summary'] = q
    keep = ['need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal']
    prefix = version(original[:original.index('PINNED = ')])
    constants = {
        'PINNED': dict(sorted(pinned.items())),
        'REQUIRED': tuple(sorted(pinned)),
        'FUTURE_PATHS': FUTURE,
        'ACTUAL': None,
        'BASELINE_COMMIT': 'baab4def80be7af015b2e7a594cb302f66c4130e',
        'CHANGED_PATHS': {'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/ssh_observation_pool.rs',
                          'src/mcp/runtime/ssh_observation_pool_tests.rs'},
        'BINARY_NAMES': {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'},
        'SOURCE_REFERENCE_SHA256': REFERENCE_SHA,
    }
    verify_reference = next(n.value for n in ast.parse(original).body if isinstance(n, ast.Assign)
                            and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                            and n.targets[0].id == 'VERIFY_REFERENCE_SHA256')
    constants['VERIFY_REFERENCE_SHA256'] = ast.literal_eval(verify_reference)
    constant_text = '\n'.join(name + ' = ' + pprint.pformat(value, sort_dicts=True) for name, value in constants.items())
    receipt = (HERE / 'receipt_binding.py').read_text()
    result = prefix + constant_text + '\n\n\n' + '\n\n'.join(old[name] for name in keep) + '\n\n' + receipt + '\n\n'
    result += '\n\n'.join(changed[name] for name in ('collect', 'qualified_summary', 'create_archive', 'verify_archive'))
    result += '\n\n' + old['main'] + '\n\n' + original[original.index("if __name__ == '__main__':"):]
    ast.parse(result)
    generated = functions(result)
    assert all(generated[name] == old[name] for name in keep)
    assert all(generated[name] == version(old[name]) for name in ('collect', 'create_archive', 'verify_archive'))
    names = ('MAX_TOTAL', 'MAX_FILE', 'MAX_MANIFEST', 'MAX_FILES', 'MAX_TAR', 'SKIP_DIRS', 'SKIP_FILES')
    def assignments(text):
        return {n.targets[0].id: ast.dump(n.value, include_attributes=False)
                for n in ast.parse(text).body if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)}
    before, after = assignments(original), assignments(result)
    assert all(after[name] == before[name] for name in names)
    assert after['ACTUAL'] == ast.dump(ast.Constant(value=None), include_attributes=False)
    assert not any(name.startswith('cache-prune') for name in pinned)
    for name in ('collect', 'summary', 'create_archive', 'verify_archive'):
        fn = next(n for n in ast.parse(result).body if isinstance(n, ast.FunctionDef) and n.name == name)
        assert 'require_sealed()' in ast.unparse(fn.body[0])
    future = {'schema': 'hepta-r35-qualification-archive-actual-pins/v1', 'sealed': False,
              'qualification_job_id': None, 'outcome': None, 'counts': None, 'qualified_binary_sha256': None,
              'files': {name: None for name in FUTURE},
              'note': 'UNSEALED. Actual completed native/read/preparation/report/map/summary/audit only; explicit later absence allowed for a real failed attempt. The known original start is retained separately and is not a completed result.'}
    metadata = {'schema': 'hepta-r35-full-qualification-archive-unsealed-template/v1', 'sealed': False,
                'root': ROOT, 'source_reference': identity(original_raw), 'collector': identity(result.encode()),
                'required_static_inputs': pinned, 'future_actual_receipts': future,
                'source_input_count_after_success': 220, 'original_harness_files': 19,
                'maximum_payload_and_combined_outputs_bytes': 32 * 1024**2,
                'maximum_file_bytes': 8 * 1024**2, 'maximum_manifest_bytes': 2 * 1024**2, 'maximum_files': 8192,
                'pending_remote_installation_not_observed': plan['files_to_install_create_only_after_qualification'],
                'separately_retained_large_installer': plan['large_original_stdin_payload_excluded_from_q_archive'],
                'completed_r35_qualification_outcome_inferred': False, 'remote_calls': 0,
                'original_installer_pruner_qualification_or_auditor_reexecuted': False}
    checks = {'schema': 'hepta-r35-full-qualification-archive-static-checks/v1', 'passed': True,
              'method': 'Static AST and exact function body comparisons; no collector or receipt function imported or executed',
              'unchanged_helpers': keep, 'collect_create_verify_equal_except_version': True,
              'original_bounded_file_directory_read_create_only_and_zero_extract_logic_unchanged': True,
              'original_bounds_and_exclusions_unchanged': True, 'actual_pins_null': True,
              'static_required_member_count': len(pinned), 'static_selected_bytes': sum(p['bytes'] for p in pinned.values()),
              'preparation_members': 39, 'candidate_members': 29, 'installation_original_files': 15,
              'installation_launch_unknown_retained_without_synthetic_terminal': True,
              'previous_r34_prune_chain_not_relabelled_as_r35': True,
              'remote_calls': 0, 'target_programs_executed': False, 'collector': identity(result.encode())}
    locations = {'schema': 'hepta-r35-qualification-archive-seal-input/v1', 'qualification_job_id': None,
                 'files': {name: {'local_path': None, 'bytes': None, 'sha256': None} for name in FUTURE},
                 'note': 'Fill from exact original terminal receipts after the first Q closes. Null later receipts are allowed only when absent after a real failed attempt. Install the 14 original installation-history copies from the separate exact copy plan before archive collection; do not synthesize a native terminal for the launch_unknown installation.'}
    outputs = {'archive_r35_qualification.py': result.encode(), 'actual-pins.example.json': encoded(future),
               'unsealed-manifest.json': encoded(metadata), 'LOCAL_STATIC_CHECKS.json': encoded(checks),
               'receipt-locations.example.json': encoded(locations)}
    assert not any(os.path.lexists(HERE / name) for name in outputs)
    for name, raw in outputs.items():
        create(HERE / name, raw)
    print(json.dumps({'sealed': False, 'collector': identity(result.encode()),
          'required_static_files': len(pinned), 'known_selected_bytes': checks['static_selected_bytes'],
          'archive_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
