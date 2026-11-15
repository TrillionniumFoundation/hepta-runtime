#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Build the unsealed R34 full-qualification collector by static source transformation."""
import ast
import datetime
import hashlib
import json
import os
from pathlib import Path
import pprint

BASE = Path(__file__).resolve().parent
WORK = BASE.parent
PREP = WORK / 'r34-qualification-prep-01/sealed-01'
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r34'
OLD_ROOT = '/home/qian/hepta-runtime-optimization-20261106-r33'
REFERENCE_SHA = '3b150b9cc56bcad3cb170d1612b2cf2c0a5b0b36e875a5b7430607709a5f7954'
FUTURE_PATHS = ('preparation.json', 'qualification-terminal-status-01.json', 'qualification-native-read-01.json',
                'qualification-01/report.json', 'qualification-01/source-map.json',
                'qualification-01/isolated-tests/summary.json', 'qualification-01/isolated-tests.audit.json')


def need(value, reason):
    if not value:
        raise RuntimeError(reason)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def rename(text):
    return text.replace(OLD_ROOT, ROOT).replace('r33', 'r34').replace('R33', 'R34')


def functions(text):
    return {node.name: ast.get_source_segment(text, node) for node in ast.parse(text).body if isinstance(node, ast.FunctionDef)}


def once(text, old, new):
    need(text.count(old) == 1, 'nonunique transformation anchor: ' + old[:100])
    return text.replace(old, new, 1)


def main():
    original_raw = (BASE / 'reference-r33/archive_r33_qualification.py').read_bytes()
    need(identity(original_raw) == {'bytes': 31940, 'sha256': REFERENCE_SHA}, 'published R33 collector differs')
    original = original_raw.decode()
    old = functions(original)
    prep_manifest = json.loads((PREP / 'frozen-preparation-manifest.json').read_bytes())
    need(identity((PREP / 'frozen-preparation-manifest.json').read_bytes())['sha256']
         == '99e5a9e4826fa9175541174695e0cdaa89210f107ee53d2fcd303ba702c0a4ac', 'frozen R34 prep manifest differs')
    pinned = {}
    for path in sorted(PREP.rglob('*')):
        if path.is_file():
            pinned[path.relative_to(PREP).as_posix()] = identity(path.read_bytes())
    need(len(pinned) == 30 and len([p for p in pinned if p.startswith('candidate/')]) == 22,
         'exact frozen preparation 30-member/candidate 22-member inventory differs')
    need(pinned['prepare_qualify.py'] == {'bytes': 29912, 'sha256': '6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f'}
         and pinned['qualification-input.json'] == {'bytes': 3707, 'sha256': '7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e'},
         'frozen source preparer/input differs')
    for number in ('01', '02'):
        folder = WORK / ('r34-cache-prune-' + number)
        for name in ('prune_cache.py', 'plan.json'):
            pinned['cache-prune-tools-' + number + '/' + name] = identity((folder / name).read_bytes())
        raw = (folder / ('report-original-' + number + '.json')).read_bytes()
        report = json.loads(raw)
        pinned['cache-prune-' + number + '/report.json'] = identity(raw)
        for pin in report['receipts'].values():
            relative = Path(pin['path']).relative_to(ROOT).as_posix()
            need(relative.startswith('cache-prune-' + number + '/') and relative.endswith('.json'), 'unsafe original prune receipt')
            pinned[relative] = {key: pin[key] for key in ('bytes', 'sha256')}
    for path in sorted((WORK / 'r34-cache-prune-02/originals').iterdir()):
        need(path.is_file(), 'unexpected first prune original member')
        pinned['cache-prune-tools-02/originals/' + path.name] = identity(path.read_bytes())
    need(len([p for p in pinned if p.startswith('cache-prune-tools-02/originals/')]) == 7,
         'all seven failed-attempt/precision originals are required')
    pending_install = {
        'cache-prune-native-02.json': {'bytes': 729, 'sha256': '4dd1b42a247454f6e132c4fae19ae386288d51a93c05d455a3c7668be71c1a79'},
        'cache-prune-native-read-02.json': {'bytes': 1422, 'sha256': '5d0001290839aa68e0ef307ae0d2bc22f60898f9d40e8b6885b3a37538e27539'},
    }
    for name, pin in pending_install.items():
        local = WORK / 'r34-cache-prune-02' / ('native-terminal-original-02.json' if name == 'cache-prune-native-02.json' else 'native-read-original-02.json')
        need(identity(local.read_bytes()) == pin, 'exact successful prune native copy differs')
        pinned[name] = pin
    prefix = rename(original[:original.index('REQUIRED =')])
    constants = (
        'PINNED = ' + pprint.pformat(dict(sorted(pinned.items())), sort_dicts=True) + '\n'
        'REQUIRED = sorted(PINNED)\n'
        'FUTURE_PATHS = ' + pprint.pformat(FUTURE_PATHS) + '\n'
        'ACTUAL = None\n'
        "BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'\n"
        "CHANGED_PATHS = {'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/ssh.rs',\n"
        "                 'src/mcp/runtime/ssh_direct.rs', 'src/mcp/runtime/ssh_direct_tests.rs'}\n"
        "BINARY_NAMES = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}\n"
        'SOURCE_REFERENCE_SHA256 = ' + repr(REFERENCE_SHA) + '\n'
        "VERIFY_REFERENCE_SHA256 = 'f1b542cf0abfb7f761c1493bf65c95a446a9d37a8f3ead524a5cfbb470eb4dce'\n\n\n")
    collect = rename(old['collect'])
    collect = once(collect, "    need(kind == 'qualification'", "    actual = require_sealed()\n    need(kind == 'qualification'")
    begin = collect.index('    for name in REQUIRED:')
    end = collect.index("    optional = ['qualification-compact-01.json']", begin)
    collect = collect[:begin] + '''    for name in REQUIRED:
        file(root / name, required=True)
    for name, pin in actual['files'].items():
        if pin is None:
            need(not os.path.lexists(root / name), 'receipt declared absent now exists: ' + name)
        elif not name.startswith('qualification-01/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'qualification-01'):
        directory(root / 'qualification-01')
    # A successful full qualification selects exactly its final compiler map
    # and original harness. An early failed attempt may have no final map.
    if actual['files']['qualification-01/source-map.json'] is not None:
        source_map = json.loads(payloads['qualification-01/source-map.json'])
        qualified = json.loads(payloads['qualification-01/report.json'])
        for name in sorted(source_map):
            safe = PurePosixPath(name)
            need(not safe.is_absolute() and '..' not in safe.parts and str(safe) == name
                 and (name in {'Cargo.toml', 'Cargo.lock', 'rustfmt.toml'}
                      or name.startswith(('src/', 'examples/'))), 'unsafe compiler input path')
            file(root / 'source' / name, required=True)
        harness = root / 'source/tools/x230/20261028'
        need(harness.resolve(strict=True) == harness and harness.is_dir(), 'indirect harness directory')
        expected_harness = qualified.get('harness_after') or qualified['harness_before']
        need({p.name for p in harness.glob('*.py')} == set(expected_harness), 'qualified harness membership differs')
        for name in sorted(expected_harness):
            need(Path(name).name == name, 'unsafe harness input path')
            file(harness / name, required=True)
''' + collect[end:]
    summary = rename(old['summary'])
    summary = once(summary, 'def summary(kind, data):', 'def qualified_summary(kind, data):')
    summary = summary.replace('QUALIFICATION_JOB', "ACTUAL['qualification_job_id']")
    summary = once(summary, "inputs, final_map = read('input.json'), read('qualification-01/source-map.json')",
        "inputs, final_map = read('qualification-input.json'), read('qualification-01/source-map.json')\n    candidate = read('candidate/input.json')")
    summary = once(summary, "prep['input_binding'] == identity('input.json')", "prep['input_binding'] == identity('qualification-input.json')")
    summary = once(summary, "prep['combined_patch'] == identity('combined.patch')", "prep['candidate_patch'] == identity('candidate/candidate.patch')")
    begin = summary.index("    need(inputs['schema']")
    end = summary.index("    need(prep['source_before_qualification']", begin)
    summary = summary[:begin] + '''    need(inputs['schema'] == 'hepta-r34-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['git_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-x230-r34-candidate/v1'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['patch_path'] == 'candidate.patch'
         and candidate['patch_sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['added_paths'] == candidate['removed_paths'] == []
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and len(set(candidate['new_test_functions'])) == len(candidate['new_test_functions']) == 8,
         'R34 input differs from the frozen accepted-R24 four-file candidate')
''' + summary[end:]
    summary = summary.replace("inputs['candidate_compile_inputs']", "candidate['candidate_compile_inputs']")
    summary = summary.replace("inputs['baseline_compile_inputs']", "candidate['baseline_compile_inputs']")
    begin = summary.index("    chain, closure = read('chain-proof.json')")
    end = summary.index("    need(tests.get('schema')", begin)
    summary = summary[:begin] + '''    frozen, closure = read('candidate/manifest.json'), read('cache-owner-closure-inputs.json')
    need(frozen['schema'] == 'hepta-x230-r34-candidate-manifest/v1'
         and frozen['baseline_commit'] == BASELINE_COMMIT and frozen['compile_input_count'] == 220
         and set(frozen['changed_paths']) == CHANGED_PATHS and len(frozen['files']) == 21,
         'frozen R34 candidate manifest differs')
    for pin in frozen['files']:
        name = 'candidate/' + pin['path']
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name]),
             'frozen candidate member differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/manifest.json'} | {'candidate/' + pin['path'] for pin in frozen['files']},
         'candidate manifest is not the exact 22-member frozen selection')
    for name, field in (('candidate/input.json', 'candidate_input'), ('candidate/manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'accepted R24 source copy plus the frozen R34 patch; R33 supplies build cache only'
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-x230-r34-cache-owner-closure/v1' and closure['sealed'] is True
         and closure['required_missing_bindings'] == []
         and closure['closure_is_not_performance_adoption'] is True
         and closure['r33_observation_performance_passed'] is False
         and closure['r33_lifecycle_abba_executed'] is False
         and prep['cache_owner_closure']['inputs'] == closure['inputs']
         and prep['cache_owner_closure']['observation_performance_passed'] is False
         and prep['cache_owner_closure']['r33_adoption_claimed'] is False
         and prep['cache_owner_closure']['rejection_reasons'] == ['C8 regression gate']
         and prep['cache_owner_closure']['lifecycle_materializer_rejected_before_abba'] is True
         and prep['cache_transferred_by_rename'] is True and prep['cache_to_transfer'] == closure['cache_path']
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'R33 cache-only origin, rejected performance history or rename receipt differs')
    postflight = closure['postflight_receipt']
    need(postflight['path'] == 'owner-closure-provenance/observation-postflight-01.json'
         and postflight['bytes'] == len(data[postflight['path']]) and postflight['sha256'] == sha(data[postflight['path']]),
         'original rejected-owner postflight reference differs')
''' + summary[end:]
    summary = summary.replace("'r31_performance_adoption_claimed'", "'r33_performance_adoption_claimed'")
    changed = {'collect': collect, 'summary': summary}
    unchanged = ['need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal']
    body = '\n\n'.join(old[name] for name in unchanged) + '\n\n'
    receipt = (BASE / 'receipt_binding.py').read_text()
    body += receipt + '\n\n' + collect + '\n\n' + summary + '\n\n'
    for name in ('create_archive', 'verify_archive'):
        value = rename(old[name])
        first, rest = value.split('\n', 1)
        value = first + '\n    require_sealed()\n' + rest
        changed[name] = value
        body += value + '\n\n'
    body += old['main'] + '\n\n'
    footer = original[original.index("if __name__ == '__main__':"):]
    result = prefix + constants + body + footer
    ast.parse(result)
    generated = functions(result)
    for name in unchanged:
        need(generated[name] == old[name], 'safety helper changed: ' + name)
    # Preserve the original descriptor/stat/bounded-read and directory-walk bodies.
    def nested(text, name):
        node = next(n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef) and n.name == name)
        return ast.dump(node, include_attributes=False)
    need(nested(collect, 'file') == nested(old['collect'], 'file')
         and nested(collect, 'directory') == nested(old['collect'], 'directory'), 'bounded collector helper changed')
    for name in ('create_archive', 'verify_archive'):
        value = once(generated[name], '    require_sealed()\n', '')
        need(value == rename(old[name]), 'archive/create-only/verify helper changed beyond guard and R34 names')
    require_node = next(n for n in ast.parse(result).body if isinstance(n, ast.Assign)
                        and any(isinstance(x, ast.Name) and x.id == 'ACTUAL' for x in n.targets))
    need(isinstance(require_node.value, ast.Constant) and require_node.value.value is None, 'actual pins must remain unsealed')
    for name in ('collect', 'summary', 'create_archive', 'verify_archive'):
        node = next(n for n in ast.parse(result).body if isinstance(n, ast.FunctionDef) and n.name == name)
        need('require_sealed()' in ast.unparse(node.body[0]), 'actual-pin guard must precede source/archive access: ' + name)
    limits = {name: ast.dump(next(n.value for n in ast.parse(result).body if isinstance(n, ast.Assign)
              and any(isinstance(x, ast.Name) and x.id == name for x in n.targets)), include_attributes=False)
              for name in ('MAX_TOTAL', 'MAX_FILE', 'MAX_MANIFEST', 'MAX_FILES', 'MAX_TAR', 'SKIP_DIRS', 'SKIP_FILES')}
    for name, value in limits.items():
        need(value == ast.dump(next(n.value for n in ast.parse(original).body if isinstance(n, ast.Assign)
             and any(isinstance(x, ast.Name) and x.id == name for x in n.targets)), include_attributes=False), 'original bound/exclusion changed')
    pin_example = {'schema': 'hepta-r34-qualification-archive-actual-pins/v1', 'sealed': False,
        'qualification_job_id': None, 'outcome': None, 'counts': None, 'qualified_binary_sha256': None,
        'files': {name: None for name in FUTURE_PATHS},
        'note': 'UNSEALED. Populate only from original completed native/read/preparation/qualification/map/summary/audit bytes. For a failed attempt, explicitly absent later receipts remain null; successful full qualification requires all seven originals.'}
    metadata = {'schema': 'hepta-r34-full-qualification-archive-unsealed-template/v1', 'sealed': False,
        'root': ROOT, 'source_reference': identity(original_raw),
        'source_reference_git_blob': '7d8fd957f9beef1077be4188e02f84d2fba9093e',
        'collector': identity(result.encode()), 'required_static_inputs': pinned,
        'future_actual_receipts': pin_example, 'source_input_count_after_success': 220, 'original_harness_files': 19,
        'maximum_payload_and_combined_outputs_bytes': 32 * 1024 ** 2, 'maximum_file_bytes': 8 * 1024 ** 2,
        'maximum_manifest_bytes': 2 * 1024 ** 2, 'maximum_files': 8192,
        'pending_remote_installation_not_observed': pending_install,
        'current_qualification_outcome_inferred': False, 'remote_calls': 0,
        'prune_or_qualification_or_auditor_reexecuted': False, 'source_or_elf_read_from_x230': False}
    checks = {'schema': 'hepta-r34-full-qualification-archive-static-checks/v1', 'passed': True,
        'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'method': 'AST and exact helper body comparisons only; collector/receipt helpers not imported or executed',
        'unchanged_helpers': unchanged, 'bounded_file_and_directory_helpers_ast_equal': True,
        'create_archive_and_zero_extract_verify_body_equal_except_version_and_first_guard': True,
        'original_size_member_count_and_exclusion_bounds_unchanged': True,
        'actual_pins_null_and_first_guard_on_all_archive_paths': True,
        'static_required_member_count': len(pinned), 'static_selected_bytes': sum(x['bytes'] for x in pinned.values()),
        'candidate_members': 22, 'prune_cache_inventory_manifests': 4,
        'old_prune_failure_and_decimal_precision_recovery_included': True,
        'runtime_or_measurement_programs_executed': False, 'remote_calls': 0,
        'collector': identity(result.encode())}
    outputs = {'archive_r34_qualification.py': result.encode(), 'actual-pins.example.json': canonical(pin_example),
               'unsealed-manifest.json': canonical(metadata), 'LOCAL_STATIC_CHECKS.json': canonical(checks)}
    need(not any(os.path.lexists(BASE / name) for name in outputs), 'fresh create-only outputs required')
    for name, raw in outputs.items():
        create(BASE / name, raw)
    print(json.dumps({'sealed': False, 'collector': identity(result.encode()),
        'required_static_files': len(pinned), 'known_selected_bytes': checks['static_selected_bytes'],
        'archive_executed': False, 'manifest': identity(outputs['unsealed-manifest.json'])}, sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    main()
