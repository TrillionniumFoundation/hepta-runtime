#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Derive a bounded D2 collector from the completed D1 archive03 collector."""
import ast
import hashlib
import json
from pathlib import Path
import tarfile

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / 'reference-archive-d1-q03.py'
reference = REFERENCE.read_text()
assert hashlib.sha256(reference.encode()).hexdigest() == 'b35343eac80708051744a09b0eff3862556043386c8c835a5ab74c55fcf61ddd'
lines = reference.splitlines(keepends=True)
nodes = {n.name: n for n in ast.parse(reference).body if isinstance(n, ast.FunctionDef)}


def function(name):
    n = nodes[name]
    return ''.join(lines[n.lineno - 1:n.end_lineno]) + '\n'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


payloads = {}
with tarfile.open(HERE / 'd2-deployment.tar.gz', 'r:gz') as archive:
    for entry in archive:
        assert entry.isfile() and not entry.name.startswith('/') and '..' not in Path(entry.name).parts
        assert entry.name not in payloads
        payloads[entry.name] = archive.extractfile(entry).read()
assert len(payloads) == 15
for name in ['installation-start-01.json', 'installation-native-01.json',
             'installation-read-01.json', 'qualification-start-01.json',
             'install_qualification.py', 'launch-command.json']:
    payloads['archive-inputs-01/' + name] = (HERE / 'archive-local-inputs' / name).read_bytes()
payloads['archive-inputs-01/deployment.tar.gz'] = (HERE / 'd2-deployment.tar.gz').read_bytes()
payloads['installation-01.json'] = (HERE / 'archive-local-inputs/installation-01.json').read_bytes()
assert len(payloads) == 23
for name, raw in payloads.items():
    assert b'PRIVATE KEY-----' not in raw and b'openssh-key-v1\x00' not in raw, name
pins = {name: identity(raw) for name, raw in sorted(payloads.items())}

header = ''.join(lines[:30]).replace('D1', 'D2').replace(
    'hepta-runtime-phase-cost-20261106-d1', 'hepta-runtime-validation-cost-20261106-d2')
constants = '''
PINNED = %s
REQUIRED = tuple(sorted(PINNED))
FUTURE_PATHS = ('preparation.json', 'qualification-terminal-status-01.json',
    'qualification-native-read-01.json', 'qualification-01/report.json',
    'qualification-01/source-map.json', 'qualification-01/isolated-tests/summary.json',
    'qualification-01/isolated-tests.audit.json')
ACTUAL = None
BASELINE_COMMIT = '8eb1a0af7a85768e374717d24848fd9798871cc9'
CHANGED_PATHS = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}
ADDED_PATHS = set()
BINARY_NAMES = {'hepta-runtime-jobctl', 'native_process_driver', 'hepta-runtime'}
SOURCE_REFERENCE_SHA256 = 'b35343eac80708051744a09b0eff3862556043386c8c835a5ab74c55fcf61ddd'
VERIFY_REFERENCE_SHA256 = SOURCE_REFERENCE_SHA256
''' % repr(pins)

installation = '''def installation_summary(data):
    read = lambda name: json.loads(data[name])
    installed = read('installation-01.json')
    package_name = 'qualification-package-manifest.json'
    package = read(package_name)
    need(package['schema'] == 'hepta-d2-qualification-deployment-inputs/v1'
         and package['sealed'] is True and package['root'] == str(ROOT)
         and package['file_count'] == len(package['files']) == 14
         and package['future_d2_results_sealed'] is False,
         'D2 sealed installation package differs')
    members = dict(package['files'])
    need(package_name not in members, 'duplicate package member')
    need(sum(row['bytes'] for row in members.values()) == package['payload_bytes'], 'deployment payload size differs')
    members[package_name] = {'bytes': len(data[package_name]), 'sha256': sha(data[package_name])}
    need(installed['schema'] == 'hepta-d2-qualification-create-only-install/v1'
         and installed['root'] == str(ROOT) and installed['member_count'] == 15
         and installed['members'] == members and installed['manifest'] == members[package_name]
         and all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == row
                 for name, row in members.items()), 'installed original membership differs')
    need(installed['source_package_unchanged'] is True and installed['cache_moved_or_deleted'] is False
         and installed['qualifier_or_compiler_started'] is False and installed['automatic_retries'] == 0
         and installed['original_archive_preserved'] is True, 'installation outcome differs')
    archive_name = 'archive-inputs-01/deployment.tar.gz'
    need(installed['archive'] == {
        'path': '/home/qian/hepta-runtime-d2-qualification-deployment-01.tar.gz',
        'bytes': len(data[archive_name]), 'sha256': sha(data[archive_name])}, 'staged archive differs')
    job = '1a1b0ca8c3b-fc05-72f2'
    terminal = read('archive-inputs-01/installation-native-01.json')
    native_terminal(terminal, job, 'succeeded', 0)
    streams = original_streams(read('archive-inputs-01/installation-read-01.json'), terminal)
    need(streams['stderr'] == b'' and json.loads(streams['stdout']) == {
        'installation_receipt': {'bytes': len(data['installation-01.json']), 'sha256': sha(data['installation-01.json'])},
        'installed': str(ROOT), 'member_count': 15, 'qualification_started': False}, 'actual installation output differs')
    start = read('archive-inputs-01/installation-start-01.json')
    need(start['audit_recorded'] is True and start['job']['id'] == job and start['job']['host'] == 'x230'
         and start['job']['executable'] == '/usr/bin/python3' and start['job']['env_keys'] == []
         and start['job']['launch_state'] == 'launched' and start['launch']['ok'] is True
         and start['reused'] is False and start['job']['args'] == ['-B',
             '/home/qian/hepta-runtime-d2-install-01.py', '--archive', installed['archive']['path']],
         'actual original installer launch differs')
    qstart = read('archive-inputs-01/qualification-start-01.json')
    launch = read('archive-inputs-01/launch-command.json')
    need(launch['host'] == 'x230' and launch['cwd'] == str(ROOT) and launch['submitted'] is False
         and launch['automatic_retry'] is False and launch['env'] == {}, 'frozen launch command differs')
    need(qstart['audit_recorded'] is True and qstart['job']['id'] == ACTUAL['qualification_job_id']
         and qstart['job']['host'] == 'x230' and qstart['job']['env_keys'] == []
         and qstart['job']['cwd'] == str(ROOT) and qstart['job']['launch_state'] == 'launched'
         and qstart['launch']['ok'] is True and qstart['reused'] is False
         and [qstart['job']['executable'], *qstart['job']['args']] == [launch['executable'], *launch['args']],
         'actual original qualification launch differs')
    return {'installation_job_id': job, 'installation_succeeded': True, 'original_installed_members': 15,
        'source_package_files': 8, 'installer_did_not_start_qualification': True,
        'original_qualification_job_id': ACTUAL['qualification_job_id'],
        'diagnostic_environment_absent_at_native_launch': True,
        'originals_reencoded': False, 'installation_reexecuted': False}
'''

qualified = function('qualified_summary')
qualified = qualified.replace("    need(inputs['schema']", "    need(inputs['schema']", 1)
start = qualified.index("    need(inputs['schema']")
end = qualified.index("    need(prep['source_before_qualification']")
qualified = qualified[:start] + '''    need(inputs['schema'] == 'hepta-d2-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['source_construction_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-x230-d2-candidate/v1'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['candidate'] == 'D2' and candidate['root'] == str(ROOT)
         and candidate['candidate_patch']['sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['candidate_patch']['bytes'] == len(data['candidate/candidate.patch'])
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and candidate['added_paths'] == candidate['removed_paths'] == candidate['new_test_functions'] == []
         and candidate['protocol']['diagnostic_only'] is True and candidate['protocol']['runtime_adoption'] is False,
         'D2 input differs from its frozen qualified-D1 diagnostic candidate')
    need(all(inputs[name] is None for name in ('actual_d2_qualification', 'actual_d2_formatted_map',
             'actual_d2_test_counts', 'actual_d2_release_programs')),
         'pre-execution inputs were overwritten with future results')
''' + qualified[end:]
start = qualified.index("    frozen, closure =")
end = qualified.index("    need(tests.get('schema')")
qualified = qualified[:start] + '''    frozen, closure = read('candidate/package-manifest.json'), read('cache-owner-closure-inputs.json')
    need(frozen['schema'] == 'hepta-x230-d2-source-package/v1'
         and frozen['source_parent'] == BASELINE_COMMIT and frozen['diagnostic_only'] is True
         and frozen['file_count'] == len(frozen['files']) == 7 and frozen['qualification_executed'] is False
         and frozen['future_qualification_counts'] is None and frozen['future_qualification_job_id'] is None,
         'D2 frozen candidate package differs')
    for relative, pin in frozen['files'].items():
        name = 'candidate/' + relative
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name])
             and pin['git_blob'] == hashlib.sha1(b'blob ' + str(len(data[name])).encode('ascii') + bytes([0]) + data[name]).hexdigest(),
             'frozen candidate original differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/package-manifest.json'} | {'candidate/' + name for name in frozen['files']},
         'candidate package inventory differs')
    for name, field in (('candidate/input.json', 'candidate_input'), ('candidate/package-manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'exact qualified D1 source copy plus frozen two-file D2 patch; D1 supplies only its closed build cache'
         and prep['diagnostic_name'] == 'D2' and prep['performance_acceptance_claim'] is False
         and prep['diagnostic_environment_absent'] is True and prep['ordinary_supplemental_executed'] is False
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-d2-d1-cache-owner-closure/v1' and closure['sealed'] is True
         and closure['required_missing_bindings'] == [] and closure['original_c1_workflow_passed'] is False
         and closure['standalone_original_auditor_already_executed'] is True
         and closure['historical_auditors_to_execute'] == 0 and closure['candidate_adopted'] is False
         and prep['cache_transferred_by_rename'] is True
         and prep['cache_to_transfer'] == closure['owner_root'] + '/target-build'
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'closed D1 cache-owner history differs')
''' + qualified[end:]
qualified = qualified.replace("len(candidate['baseline_compile_inputs']) == 220", "len(candidate['baseline_compile_inputs']) == 222")
qualified = qualified.replace("'r35_performance_adoption_claimed': False", "'prior_d1_original_c1_workflow_passed': False")
qualified = qualified.replace('hepta-x230-d1-preparation/v1', 'hepta-x230-d2-preparation/v1')
qualified = qualified.replace('first_actual_d1_qualification_required', 'first_actual_d2_qualification_required')
qualified = qualified.replace('first D1 preparation and first actual eight-stage qualification', 'first D2 preparation and first actual eight-stage qualification')
qualified = qualified.replace('actual first D1 preparation', 'actual first D2 preparation')
qualified = qualified.replace('original D1', 'original D2').replace('D1 final actual', 'D2 final actual').replace('completed D1 qualification', 'completed D2 qualification')

summary = function('summary')
start = summary.index('    external_sources =')
end = summary.index("    result['original_qualification_or_measurement_retried']")
summary = summary[:start] + summary[end:]
summary = summary.replace('original D1 qualification', 'original D2 qualification')

chunks = [header, constants]
reused = ['need', 'sha', 'encoded', 'stamp', 'tool_sha256', 'native_terminal', 'original_streams']
chunks.extend(function(name) for name in reused)
chunks.append(function('require_sealed').replace('hepta-d1-qualification', 'hepta-d2-qualification').replace('D1', 'D2'))
chunks += [installation, summary, function('collect').replace('D1 qualification', 'D2 qualification'), qualified]
for name in ['create_archive', 'verify_archive', 'main']:
    text = function(name).replace('hepta-d1-qualification', 'hepta-d2-qualification').replace('D1 qualification', 'D2 qualification')
    text = text.replace("base = root / 'qualification-evidence-03'", "base = root / 'qualification-evidence-01'")
    chunks.append(text)
chunks.append(''.join(lines[718:]))
output = '\n\n'.join(chunks)
compile(output, 'archive_d2_qualification.py', 'exec')
assert output.count('ACTUAL = None') == 1
assert '1a1b01385a8' not in output and '1a1b01cee00' not in output
destination = HERE / 'archive_d2_qualification.py'
destination.write_text(output)
report = {'schema': 'hepta-d2-qualification-archive-construction/v1',
          'source': identity(REFERENCE.read_bytes()), 'output': identity(output.encode()),
          'original_pins': len(pins), 'reused_exact_functions': reused,
          'limits_unchanged': True, 'credential_scan_unchanged': True,
          'archive_extracts_members_to_filesystem': False,
          'd1_historical_archive_failures_remain_in_d1_evidence': True,
          'new_actual_results_sealed': False, 'target_execution': False}
for name in reused:
    assert function(name).rstrip() in output
(HERE / 'construction.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
