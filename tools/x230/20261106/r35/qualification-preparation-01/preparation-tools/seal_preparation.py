#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal actual local R35 preparation inputs without launching any target program.

Only the large observation body is not downloaded here. Its exact identity must
agree in the original closed parent and the pinned original postflight. The
remote preparer independently reads, hashes and checks that original body before
it can move the old cache. This sealer does not claim to have read that body.
"""
from pathlib import Path
import ast
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile

HERE = Path(__file__).resolve().parent
FROZEN = HERE.parent / 'r35'
OBS = HERE.parent / 'r34-observation-originals-01'
OUTPUT = HERE / 'sealed-01'
OWNER = '/home/qian/hepta-runtime-optimization-20261106-r34'
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
POSTFLIGHT_SHA = '17a371b24de733c7e412afdcf31a1fdad1745bbe2b560177e010816ee5193cc1'
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
CHANGED = {'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/ssh_observation_pool.rs',
           'src/mcp/runtime/ssh_observation_pool_tests.rs'}
GENERAL_HELPERS = ['sha', 'source_map', 'save', 'known_nondumpable_helper',
                   'inspect_processes', 'retained_programs', 'read_bound',
                   'input_identity', 'relative_identity', 'native_terminal',
                   'closed_stages', 'completed_qualification', 'native_streams']
PATHS = {'qualification_report': 'qualification-01/report.json', 'qualification_native': 'qualification-terminal-status-01.json', 'qualification_preparation': 'preparation.json', 'qualification_map': 'qualification-01/source-map.json', 'exact_ci_report': 'rust-ci-01/report.json', 'exact_ci_native': 'rust-ci-native-01.json', 'exact_ci_read': 'rust-ci-native-read-01.json', 'observation_parent': 'campaign-01/report.json', 'observation_native': 'observation-holder-native-01.json', 'observation_holder_read': 'observation-holder-read-01.json', 'observation_holder_report': 'observation-holder-report-01.json', 'observation_report': 'campaign-01/native-observation/report.json', 'observation_audit': 'campaign-01/native-observation/independent-summary.json', 'compiler_monitor_audit': 'campaign-01/compiler-monitor.audit.json', 'observation_summary': 'campaign-01/summary.json'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def read_local(path, limit=8 * 1024**2):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert 0 <= before.st_size <= limit
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(limit + 1)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = lambda value: tuple(getattr(value, field) for field in fields)
        assert len(raw) == before.st_size
        assert stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        return raw
    finally:
        os.close(fd)


def identity(path, raw):
    return {'path': path, 'bytes': len(raw), 'sha256': sha(raw)}


def native(value, job, state='succeeded', code=0):
    assert value['job_id'] == job and value['state'] == state and value['exit_code'] == code
    assert all(value[name] is True for name in ('audit_recorded', 'output_complete', 'output_durable', 'terminal_publication_confirmed'))
    assert value['terminal_publication_protocol'] == 1
    assert all(value[name] is False for name in ('automatic_retry', 'timed_out', 'cancelled'))
    for name in ('stdout', 'stderr'):
        assert value['log_bytes'][name]['seen'] == value['log_bytes'][name]['stored']
        assert value['log_errors'][name] is None and value['log_synced'][name] is True
        assert value['log_truncated'][name] is False


def streams(value, terminal):
    assert value['job_id'] == terminal['job_id'] and value['audit_recorded'] is True
    out = {}
    for name in ('stdout', 'stderr'):
        item = value[name]
        raw = bytes.fromhex(item['bytes_hex'])
        assert item['offset'] == 0 and item['eof'] is True
        assert item['size'] == item['next_offset'] == len(raw) == terminal['log_bytes'][name]['stored']
        assert item['text'] == raw.decode('utf-8', errors='replace')
        out[name] = raw
    return out


def closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert all(row[name] is True for name in ('waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent'))
        assert row.get('timed_out', False) is False


def function_text(raw):
    text = raw.decode()
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    return {node.name: ''.join(lines[node.lineno-1:node.end_lineno])
            for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def write_new(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    assert not os.path.lexists(OUTPUT), 'sealed output already exists; never overwrite or silently reseal'
    postflight_raw = read_local(OBS / 'observation-postflight-01.json')
    assert len(postflight_raw) == 5064 and sha(postflight_raw) == POSTFLIGHT_SHA
    postflight = json.loads(postflight_raw)
    assert postflight['schema'] == 'hepta-r34-rejected-observation-owner-postflight/v1'
    assert postflight['accepted_baseline_commit'] == BASELINE_COMMIT
    assert postflight['cache_path'] == OWNER + '/target-build'
    assert postflight['current_source_matches_qualified_map'] is True and postflight['compiler_input_count'] == 220
    assert postflight['observation_workflow_closed'] is True and postflight['original_owned_agent_reaped'] is True
    assert postflight['observation_gate_passed'] is False and postflight['performance_gates_passed'] is False
    assert postflight['candidate_adopted'] is False and postflight['normal_lifecycle_started'] is False
    assert postflight['rejection_reasons'] == ['C8 regression gate']
    assert postflight['normal_lifecycle_paths_absent'] == ['lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01']
    assert postflight['tests_benchmarks_or_auditors_reexecuted'] is False

    local_paths = {
        'qualification_report': HERE.parent / 'r34-qualified-originals-01/report.json',
        'qualification_native': HERE.parent / 'r34-qualified-originals-01/qualification-terminal-status-01.json',
        'qualification_preparation': HERE.parent / 'r34-qualified-originals-01/preparation.json',
        'qualification_map': HERE.parent / 'r34-qualified-originals-01/source-map.json',
        'exact_ci_report': HERE.parent / 'r34-exact-ci-results-01/report.json',
        'exact_ci_native': HERE.parent / 'r34-exact-ci-results-01/rust-ci-native-01.json',
        'exact_ci_read': HERE.parent / 'r34-exact-ci-results-01/rust-ci-native-read-01.json',
        'observation_parent': OBS / 'parent-report.json',
        'observation_native': OBS / 'observation-holder-native-01.json',
        'observation_holder_read': OBS / 'observation-holder-read-01.json',
        'observation_holder_report': OBS / 'observation-holder-report-01.json',
        'observation_summary': OBS / 'summary.json',
        'observation_audit': OBS / 'native-independent-summary.json',
        'compiler_monitor_audit': OBS / 'compiler-monitor.audit.json',
    }
    inputs, values = {}, {}
    for label, relative in PATHS.items():
        pin = postflight['originals'][relative]
        assert pin['path'] == OWNER + '/' + relative
        assert type(pin['bytes']) is int and 0 < pin['bytes'] <= 8 * 1024**2
        assert len(pin['sha256']) == 64 and all(c in '0123456789abcdef' for c in pin['sha256'])
        inputs[label] = pin
        if label in local_paths:
            raw = read_local(local_paths[label])
            assert identity(pin['path'], raw) == pin, label
            values[label] = json.loads(raw)
    assert set(PATHS) - set(values) == {'observation_report'}

    qjob, cijob, obsjob = ('1a1aef7882f-fc05-6499', '1a1af1ebf1d-fc05-65f2',
                          '1a1af308953-fc05-6698')
    native(values['qualification_native'], qjob)
    native(values['exact_ci_native'], cijob)
    native(values['observation_native'], obsjob)
    assert postflight['original_observation_job_id'] == obsjob
    assert postflight['original_lifecycle_materializer_job_id'] is None
    assert postflight['lifecycle_materialization_started'] is False
    assert postflight['capacity_build_or_campaign_started_by_coordinator'] is False
    assert postflight['cache_moved'] is False and postflight['cache_deleted'] is False
    assert set(postflight['originals']) == set(PATHS.values())
    assert streams(values['exact_ci_read'], values['exact_ci_native'])['stderr'] == b''
    original_input = json.loads(read_local(FROZEN / 'reference-r33-input.json'))
    harness = original_input['qualification_harness_sha256']
    assert len(harness) == 19
    q, prep = values['qualification_report'], values['qualification_preparation']
    assert q['schema'] == 'hepta-x230-composed-qualification/v1' and q['qualified'] is True
    assert q.get('finished_utc') and not q.get('error') and q['source'] == OWNER + '/source'
    assert q['jobs'] == 2 and q['automatic_test_retries'] == 0 and q['service_changes'] is False
    assert [row['name'] for row in q['stages']] == STAGES and all(row['returncode'] == 0 for row in q['stages'])
    assert q['source_tested'] == q['source_after'] == values['qualification_map']
    assert len(q['source_tested']) == 220
    assert q['harness_before'] == q['harness_after'] == harness
    assert prep['schema'] == 'hepta-x230-r34-preparation/v1' and prep['passed'] is True
    assert prep['qualification_returncode'] == 0 and prep['qualification_started'] is True
    assert prep['qualification_report_sha256'] == inputs['qualification_report']['sha256']
    assert prep['source_baseline'] == BASELINE_COMMIT
    assert prep['source_before_qualification'] == q['source_input']
    assert prep['source_after_qualification'] == q['source_tested']
    assert prep['automatic_retries'] == 0 and prep['production_services_modified'] is False
    ci = values['exact_ci_report']
    assert ci['schema'] == 'hepta-r34-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['original_qualification_job_id'] == qjob
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version', 'cargo-check', 'nextest-list', 'nextest-run'])
    counts = {name: ci['nextest_output_audit'][name] for name in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    assert counts == {'passed': 1653, 'failed': 0, 'ignored': 34, 'selected': 1687, 'retries': 0}
    assert ci['nextest_output_audit']['verified'] is True
    holder = streams(values['observation_holder_read'], values['observation_native'])
    assert holder['stderr'] == b''
    rows = [json.loads(row) for row in holder['stdout'].splitlines()]
    assert len(rows) == 2 and rows[0]['phase'] == 'owned_agent_ready' and rows[0]['identity_count'] == 5
    assert rows[1]['passed'] is True and rows[1]['remote_returncode'] == 0 and rows[1]['owned_agent_reaped'] is True
    parent, summary = values['observation_parent'], values['observation_summary']
    assert parent['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert parent['passed'] is True and parent.get('finished_utc') and not parent.get('error')
    assert rows[0]['remote_script_sha256'] == parent['launcher_sha256']
    assert parent['observation_gate_passed'] is False and parent['rejection_reasons'] == ['C8 regression gate']
    assert all(parent[key] is True for key in ('correctness_stages_completed', 'measurement_attribution_valid', 'source_inputs_unchanged', 'inputs_unchanged'))
    assert parent['compiler_monitor']['passed'] is True
    closed_stages(parent['stages'], ['native-observation', 'native-audit', 'native-boundary', 'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    assert parent['stages'][0]['output_bindings'] == [inputs['observation_report']]
    assert parent['summary'] == inputs['observation_summary']
    assert summary['schema'] == 'hepta-r25-observation-gates/v1'
    assert summary['correctness_verified'] is True and summary['evidence_verified'] is True
    assert summary['observation_gate_passed'] is False and summary['performance_gates_passed'] is False
    assert summary['rejection_reasons'] == ['C8 regression gate']
    holder_report = values['observation_holder_report']
    assert holder_report['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder_report['passed'] is True and holder_report['remote_returncode'] == 0
    assert holder_report.get('finished_utc') and not holder_report.get('error')
    assert holder_report['remote_script_sha256'] == parent['launcher_sha256']
    assert holder_report['automatic_ssh_retries'] == 0 and holder_report['services_modified'] is False
    for key in ('owned_agent_reaped', 'owned_agent_directory_absent_after_context', 'owned_agent_socket_absent_after_context'):
        assert holder_report[key] is True
    assert parent['stages'][1]['output_bindings'] == [inputs['observation_audit']]
    audit = values['observation_audit']
    assert audit['schema'] == 'hepta-native-observation-independent-analysis/v3' and audit['verified'] is True
    assert audit['original_bytes'] == inputs['observation_report']['bytes']
    assert audit['original_sha256'] == inputs['observation_report']['sha256']
    assert {name: audit[name] for name in ('measured_calls', 'warmup_calls', 'preflight_restart_calls',
                                          'total_calls', 'failed_calls')} == {
        'measured_calls': 2304, 'warmup_calls': 288, 'preflight_restart_calls': 72,
        'total_calls': 2664, 'failed_calls': 0}
    monitor = values['compiler_monitor_audit']
    assert parent['compiler_monitor']['independent_audit'] == inputs['compiler_monitor_audit']
    assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
    assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
    assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
    assert monitor['validation']['validated_sample_count'] == 301
    assert monitor['ledger'] == parent['compiler_monitor']['ledger']
    postflight_native_raw = read_local(OBS / 'postflight-native-status-01.json')
    postflight_read_raw = read_local(OBS / 'postflight-native-read-01.json')
    assert identity('postflight-native-status-01.json', postflight_native_raw) == {
        'path': 'postflight-native-status-01.json', 'bytes': 731,
        'sha256': '4fb5fbb783b1e302a16fef462bd90e14ac35c80bb4fe9efc89e7b3d84e9f4e46'}
    assert identity('postflight-native-read-01.json', postflight_read_raw) == {
        'path': 'postflight-native-read-01.json', 'bytes': 14879,
        'sha256': '49dedd1eefed821e27d84fd0382358a8b77850f0f5c11dcde479e5c3776c73dc'}
    postflight_native = json.loads(postflight_native_raw)
    native(postflight_native, '1a1af3c8508-fc05-66fa')
    original_streams = streams(json.loads(postflight_read_raw), postflight_native)
    assert original_streams['stderr'] == b''
    postflight_output = json.loads(original_streams['stdout'])
    assert postflight_output.pop('receipt') == identity(OWNER + '/observation-postflight-01.json', postflight_raw)
    assert postflight_output == postflight

    launcher = read_local(HERE / 'prepare_qualify.py')
    reference = read_local(HERE / 'reference/prepare_r34_qualify.py')
    assert len(reference) == 29912 and sha(reference) == '6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f'
    before, after = function_text(reference), function_text(launcher)
    assert all(before[name] == after[name] for name in GENERAL_HELPERS)
    payload = {'prepare_qualify.py': launcher,
               'preparation-tools/seal_preparation.py': read_local(Path(__file__)),
               'preparation-tools/reference/prepare_r34_qualify.py': reference,
               'owner-closure-provenance/observation-postflight-01.json': postflight_raw,
               'owner-closure-provenance/postflight-native-status-01.json': postflight_native_raw,
               'owner-closure-provenance/postflight-native-read-01.json': postflight_read_raw}
    frozen_manifest_raw = read_local(FROZEN / 'manifest.json')
    assert len(frozen_manifest_raw) == 5225 and sha(frozen_manifest_raw) == 'e5f4338e3581ecc4560269a417941b4802a8b58307eb60eea6e04dd7a4f5102b'
    frozen_manifest = json.loads(frozen_manifest_raw)
    assert frozen_manifest['schema'] == 'hepta-x230-r35-source-package/v1'
    assert frozen_manifest['compile_input_count'] == 220
    assert set(frozen_manifest['changed_compile_paths']) == CHANGED
    assert frozen_manifest['file_count_excluding_manifest'] == 28
    payload['candidate/manifest.json'] = frozen_manifest_raw
    seen = set()
    for pin in frozen_manifest['files']:
        relative = Path(pin['path'])
        assert not relative.is_absolute() and '..' not in relative.parts and pin['path'] not in seen
        seen.add(pin['path'])
        raw = read_local(FROZEN / relative)
        assert identity(pin['path'], raw) == pin
        payload['candidate/' + pin['path']] = raw
    assert len(seen) == 28
    candidate = json.loads(payload['candidate/input.json'])
    assert len(payload['candidate/input.json']) == 53380 and sha(payload['candidate/input.json']) == '7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'
    assert candidate['schema'] == 'hepta-x230-r35-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['patch_path'] == 'candidate.patch'
    assert candidate['patch_sha256'] == sha(payload['candidate/candidate.patch']) == '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a'
    baseline, expected = candidate['baseline_compile_inputs'], candidate['candidate_compile_inputs']
    assert baseline == original_input['baseline_compile_inputs']
    assert len(baseline) == len(expected) == 220 and set(baseline) == set(expected)
    assert {name for name in baseline if baseline[name] != expected[name]} == CHANGED
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert candidate['new_test_functions'] == []

    closure = {
        'schema': 'hepta-x230-r35-cache-owner-closure/v1', 'sealed': True,
        'required_missing_bindings': [], 'cache_owner': OWNER, 'cache_path': OWNER + '/target-build',
        'closure_is_not_performance_adoption': True,
        'r34_observation_performance_passed': False, 'r34_lifecycle_abba_executed': False,
        'qualification_job_id': qjob, 'exact_ci_job_id': cijob,
        'observation_holder_job_id': obsjob, 'lifecycle_materializer_job_id': None,
        'lifecycle_materialization_started': False,
        'capacity_build_or_campaign_started_by_coordinator': False,
        'inputs': inputs,
        'postflight_receipt': identity('owner-closure-provenance/observation-postflight-01.json', postflight_raw),
        'local_validation': {'exact_original_bodies_read': sorted(values),
                             'identity_bound_without_local_body': ['observation_report'],
                             'observation_report_identity_sources': ['observation_parent.stages[0].output_bindings', 'original_postflight.originals'],
                             'remote_preparer_must_read_and_validate_original_observation_report': True,
                             'current_machine_idle_claimed': False,
                             'candidate_adopted': False},
    }
    payload['cache-owner-closure-inputs.json'] = encoded(closure)
    config = {
        'schema': 'hepta-r35-direct-qualification-input/v1', 'sealed': True,
        'required_missing_bindings': [], 'baseline_commit': BASELINE_COMMIT, 'git_parent': BASELINE_COMMIT,
        'candidate_catalog_git_blob': '4251bcdfb0e5897eaba2ebf3f507f0729e2e3667',
        'candidate_input': identity('candidate/input.json', payload['candidate/input.json']),
        'candidate_manifest': identity('candidate/manifest.json', frozen_manifest_raw),
        'baseline_qualification': original_input['baseline_qualification'],
        'qualification_harness_sha256': harness,
        'preparation_tool': identity('prepare_qualify.py', launcher),
        'owner_closure_input_sha256': sha(payload['cache-owner-closure-inputs.json']),
        'source_rule': 'accepted R24 source plus frozen R35 three-path patch; no R34 source or unknown private patch',
        'cache_rule': 'R34 target-build rename after all original owners close; no deletion and no full cache copy',
        'qualification_rule': {'jobs': 2, 'stages': STAGES, 'harness_files': 19, 'automatic_retries': 0,
                               'qualifier_changed': False, 'thresholds_changed': False,
                               'expected_test_counts': None},
    }
    payload['qualification-input.json'] = encoded(config)
    seal = {
        'schema': 'hepta-r35-preparation-seal/v1', 'status': 'sealed_not_executed',
        'root': ROOT, 'cache_owner': OWNER, 'accepted_baseline_commit': BASELINE_COMMIT,
        'local_original_bodies_checked': 14, 'remote_original_identities_bound': 15,
        'observation_large_body_not_read_locally': inputs['observation_report'],
        'postflight': closure['postflight_receipt'],
        'candidate_files_checked': 29, 'candidate_compile_input_count': 220,
        'changed_paths': sorted(CHANGED), 'new_test_functions': candidate['new_test_functions'],
        'unchanged_general_helpers': {name: sha(before[name].encode()) for name in GENERAL_HELPERS},
        'qualification_harness_files': 19, 'qualification_stages': STAGES,
        'reference_launcher': identity('preparation-tools/reference/prepare_r34_qualify.py', reference),
        'launcher': identity('prepare_qualify.py', launcher),
        'seal_tool': identity('preparation-tools/seal_preparation.py', payload['preparation-tools/seal_preparation.py']),
        'source_code_parsed_only': True, 'preparer_executed': False,
        'remote_calls': 0, 'rust_compiled': False, 'tests_executed': False,
        'benchmarks_executed': False, 'original_auditors_reexecuted': False,
        'cache_moved': False, 'cache_deleted': False, 'candidate_adopted': False,
        'future_r35_qualification': {'job_id': None, 'report': None, 'counts': None, 'binaries': None},
        'remaining_runtime_checks': ['All bound original files including the large observation report are independently reread before cache movement.',
                                     'Current source/harness identity, old cache process owners, retained executable hashes and original 3 GiB free-space minimum remain enforced.',
                                     'Actual R35 qualification result is unknown until the single authorized eight-stage execution completes.'],
    }
    payload['qualification-preparation-seal.json'] = encoded(seal)
    argv = ['/usr/bin/python3', '-B', '-u', ROOT + '/prepare_qualify.py',
            '--input-sha256', sha(payload['qualification-input.json']),
            '--owner-closure-sha256', sha(payload['cache-owner-closure-inputs.json'])]
    manifest = {
        'schema': 'hepta-r35-frozen-qualification-preparation/v1', 'status': 'sealed_not_executed',
        'root': ROOT, 'baseline_commit': BASELINE_COMMIT,
        'candidate_catalog_git_blob': '4251bcdfb0e5897eaba2ebf3f507f0729e2e3667',
        'files': [identity(path, raw) for path, raw in sorted(payload.items())],
        'manifest_self_excluded': True, 'candidate_package_layout': 'candidate/',
        'single_authorized_launch_argv': argv,
        'launch_authorized_by_this_manifest': False,
        'runtime_preparation_required_before_cache_use': True,
    }
    payload['frozen-preparation-manifest.json'] = encoded(manifest)
    assert len(payload) <= 8192 and sum(map(len, payload.values())) <= 64 * 1024**2
    assert max(map(len, payload.values())) <= 8 * 1024**2
    OUTPUT.mkdir()
    for path, raw in sorted(payload.items()):
        write_new(OUTPUT / path, raw)
    packed = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=packed, mtime=0) as compressed:
        with tarfile.open(mode='w', fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
            for path, raw in sorted(payload.items()):
                member = tarfile.TarInfo(path)
                member.mode, member.uid, member.gid, member.mtime = 0o644, 0, 0, 0
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
    archive_raw = packed.getvalue()
    assert len(archive_raw) <= 64 * 1024**2
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:gz') as archive:
        members = archive.getmembers()
        assert len(members) == len(payload) and {member.name for member in members} == set(payload)
        for member in members:
            assert member.isfile() and member.size <= 8 * 1024**2
            assert archive.extractfile(member).read(member.size + 1) == payload[member.name]
    archive_path = HERE / 'r35-qualification-preparation-01.tar.gz'
    write_new(archive_path, archive_raw)
    delivery = {'schema': 'hepta-r35-qualification-preparation-delivery/v1',
                'archive': identity(archive_path.name, archive_raw),
                'manifest': identity('sealed-01/frozen-preparation-manifest.json', payload['frozen-preparation-manifest.json']),
                'launcher': identity('prepare_qualify.py', launcher),
                'qualification_input': identity('qualification-input.json', payload['qualification-input.json']),
                'owner_closure': identity('cache-owner-closure-inputs.json', payload['cache-owner-closure-inputs.json']),
                'files': len(payload), 'uncompressed_file_bytes': sum(map(len, payload.values())),
                'single_authorized_launch_argv': argv, 'preparer_executed': False}
    write_new(HERE / 'sealed-delivery.json', encoded(delivery))
    print(json.dumps(delivery, sort_keys=True))


if __name__ == '__main__':
    main()
