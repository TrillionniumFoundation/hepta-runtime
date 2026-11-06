#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""First D2 qualification: two diagnostic-only changes on the qualified D1 source.

Original eight stages, nineteen harness tools, jobs=2 and 3 GiB floor are unchanged.
The closed D1 build cache moves once; no historical workload or auditor is rerun.
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

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
BASE = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
CACHE_OWNER = BASE
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = '8eb1a0af7a85768e374717d24848fd9798871cc9'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
HEX = re.compile(r'[0-9a-f]{64}\Z')
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT',
                  'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')
CHANGED = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}
ADDED = set()
OWNER_JOBS = {'qualification': '1a1aff8769c-fc05-6d26', 'exact_ci': '1a1b0238605-fc05-6e78',
              'ordinary': '1a1b04c6cd1-fc05-6f94', 'ordinary_postflight': '1a1b06d14dd-fc05-7074',
              'c1_holder': '1a1b0849a11-fc05-7119', 'native_audit': '1a1b09af362-fc05-71a6'}
ORIGINAL_MISSING_PATHS = (BASE / 'c1-observation-01/independent-summary.json', BASE / 'c1-campaign-01/summary.json')
OWNER_PATHS = {
    'qualification_report': BASE / 'qualification-01/report.json',
    'qualification_preparation': BASE / 'preparation.json',
    'qualification_native': BASE / 'qualification-terminal-status-01.json',
    'qualification_read': BASE / 'qualification-native-read-01.json',
    'qualification_summary': BASE / 'qualification-01/isolated-tests/summary.json',
    'qualification_map': BASE / 'qualification-01/source-map.json',
    'exact_ci_report': BASE / 'rust-ci-01/report.json',
    'exact_ci_audit': BASE / 'rust-ci-01/nextest-output-audit.json',
    'exact_ci_native': BASE / 'rust-ci-native-01.json',
    'exact_ci_read': BASE / 'rust-ci-native-read-01.json',
    'ordinary_report': BASE / 'ordinary-02/report.json',
    'ordinary_native': BASE / 'ordinary-native-02.json',
    'ordinary_read': BASE / 'ordinary-native-read-02-000.json',
    'ordinary_map': BASE / 'ordinary-02/source-map.json',
    'ordinary_postflight_report': BASE / 'ordinary-postflight-02.json',
    'ordinary_postflight_native': BASE / 'ordinary-postflight-native-02.json',
    'ordinary_postflight_read': BASE / 'ordinary-postflight-native-read-02-000.json',
    'c1_parent': BASE / 'c1-campaign-01/report.json',
    'c1_adapter': BASE / 'c1-adapter-evidence-01/adapter-report.json',
    'c1_report': BASE / 'c1-observation-01/report.json',
    'c1_native': BASE / 'c1-holder-native-01.json',
    'c1_read': BASE / 'c1-holder-native-read-01-000.json',
    'c1_holder': BASE / 'c1-holder-report-01.json',
    'native_audit_report': BASE / 'c1-offline-interpretation-01/native-independent-summary.json',
    'native_audit_start': ROOT / 'provenance/native-audit-start.json',
    'native_audit_native': ROOT / 'provenance/native-audit-native.json',
    'native_audit_read': ROOT / 'provenance/native-audit-native-read-000.json',
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def source_map(root):
    paths = [root / name for name in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml')]
    for name in ('src', 'examples'):
        paths.extend(p for p in (root / name).rglob('*') if p.is_file())
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(paths)}


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.next')
    with temporary.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def known_nondumpable_helper(name, command, cgroup, uids):
    """Classify only observed non-build system helpers using readable metadata.

    Do not try to read protected proc links through another identity. Unknown
    opaque processes still stop preparation. All compiler names remain global.
    """
    if uids != [1000, 1000, 1000, 1000]:
        return False
    command = command.replace(b'\0', b' ').strip()
    group = cgroup.strip()
    if name == '(sd-pam)':
        return command == b'(sd-pam)' and group == '0::/user.slice/user-1000.slice/user@1000.service/init.scope'
    if name == 'sshd':
        return command == b'sshd: qian@notty' and re.fullmatch(r'0::/user.slice/user-1000.slice/session-[0-9]+\.scope', group) is not None
    if name == 'gpg-agent':
        return command == b'/usr/bin/gpg-agent --supervised' and group == '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gpg-agent.service'
    if name == 'ssh-agent':
        return command == b'/usr/bin/ssh-agent -D -a /run/user/1000/gcr/.ssh' and group == '0::/user.slice/user-1000.slice/user@1000.service/app.slice/gcr-ssh-agent.service'
    return False


def inspect_processes(cache):
    matches, compilers, opaque_helpers = [], [], []
    needle = str(cache).encode()
    for proc in Path('/proc').glob('[0-9]*'):
        try:
            name = (proc / 'comm').read_text().strip()
            first_stat = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
            if first_stat[0] in {'Z', 'X'}:
                continue
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld', 'clippy-driver'):
                compilers.append({'pid': int(proc.name), 'comm': name})
            if proc.stat().st_uid != os.getuid():
                continue
            command = (proc / 'cmdline').read_bytes()
            cgroup = (proc / 'cgroup').read_text()
            uid_line = next(line for line in (proc / 'status').read_text().splitlines() if line.startswith('Uid:'))
            uids = [int(value) for value in uid_line.split()[1:]]
            values, denied = [command], []
            for item in ('cwd', 'exe'):
                try:
                    values.append(os.readlink(proc / item).encode())
                except PermissionError:
                    denied.append(item)
                except FileNotFoundError:
                    pass
            try:
                entries = list((proc / 'fd').iterdir())
            except PermissionError:
                denied.append('fd')
                entries = []
            for entry in entries:
                try:
                    values.append(os.readlink(entry).encode())
                except PermissionError:
                    denied.append('fd/' + entry.name)
                except FileNotFoundError:
                    pass
            if any(needle in value for value in values):
                matches.append({'pid': int(proc.name), 'comm': name})
            if denied:
                assert known_nondumpable_helper(name, command, cgroup, uids), 'unknown opaque process: ' + proc.name
                last_stat = (proc / 'stat').read_text().rsplit(') ', 1)[1].split()
                assert last_stat[19] == first_stat[19]
                assert (proc / 'comm').read_text().strip() == name and (proc / 'cmdline').read_bytes() == command
                assert (proc / 'cgroup').read_text() == cgroup
                opaque_helpers.append({'pid': int(proc.name), 'comm': name, 'command': command.replace(b'\0', b' ').decode(),
                                       'cgroup': cgroup.strip(), 'uids': uids, 'start_ticks': first_stat[19],
                                       'unreadable_fields': denied, 'classification': 'observed non-build system helper'})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return {'matched_processes': matches, 'compiler_processes': compilers,
            'opaque_system_helpers': opaque_helpers,
            'scope': 'all readable same-user cmdline/cwd/exe/fd plus global compiler names; exact known non-build system helpers recorded when proc access is denied'}


def retained_programs(root):
    report = json.loads((root / 'qualification-01/report.json').read_bytes())
    assert report['qualified'] and report['source_tested'] == report['source_after']
    result = {}
    for value in report['binaries'].values():
        p = Path(value['path'])
        assert p.is_relative_to(root / 'qualification-01') and p.resolve() == p
        assert stat.S_ISREG(p.lstat().st_mode) and p.stat().st_nlink == 1
        assert sha(p) == value['sha256']
        result[str(p)] = value['sha256']
    for p in (root / 'qualification-01/test-binaries').iterdir():
        assert stat.S_ISREG(p.lstat().st_mode) and p.stat().st_nlink == 1
        result[str(p)] = sha(p)
    assert len(result) >= 5
    return result


def read_bound(identity, maximum=8 * 1024 * 1024):
    path = Path(identity['path'])
    assert path.is_absolute() and path.resolve() == path
    assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= maximum
    assert HEX.fullmatch(identity['sha256'])
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert before.st_size == identity['bytes']
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum + 1)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = lambda value: tuple(getattr(value, key) for key in fields)
        assert len(raw) == before.st_size
        assert stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
    finally:
        os.close(fd)
    assert hashlib.sha256(raw).hexdigest() == identity['sha256'], str(path)
    return raw


def input_identity(path, digest):
    assert HEX.fullmatch(digest)
    return {'path': str(path), 'bytes': path.lstat().st_size, 'sha256': digest}


def relative_identity(value):
    relative = Path(value['path'])
    assert not relative.is_absolute() and '..' not in relative.parts
    return {**value, 'path': str(ROOT / relative)}


def native_terminal(value, job_id, state='succeeded', exit_code=0):
    assert value['job_id'] == job_id and value['state'] == state and value['exit_code'] == exit_code
    assert value['output_complete'] is True and value['output_durable'] is True
    assert value['automatic_retry'] is False and value['timed_out'] is False and value['cancelled'] is False
    assert value['terminal_publication_confirmed'] is True and value['terminal_publication_protocol'] == 1
    for channel in ('stdout', 'stderr'):
        assert value['log_bytes'][channel]['seen'] == value['log_bytes'][channel]['stored']
        assert value['log_errors'][channel] is None
        assert value['log_synced'][channel] is True and value['log_truncated'][channel] is False


def closed_stages(rows, names):
    assert [row['name'] for row in rows] == names
    for row in rows:
        assert row['returncode'] == 0 and row['passed'] is True
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def completed_qualification(value, source, harness):
    assert value['schema'] == 'hepta-x230-composed-qualification/v1'
    assert value['qualified'] is True and value.get('finished_utc') and not value.get('error')
    assert value['source'] == str(source) and value['jobs'] == 2
    assert value['automatic_test_retries'] == 0 and value['service_changes'] is False
    assert [row['name'] for row in value['stages']] == STAGES
    assert all(row['returncode'] == 0 for row in value['stages'])
    assert value['source_tested'] == value['source_after'] == source_map(source)
    assert value['harness_before'] == value['harness_after'] == harness


def native_streams(value, terminal):
    """Bind a complete original single-page native read to its terminal byte counts."""
    assert value['job_id'] == terminal['job_id'] and value['audit_recorded'] is True
    result = {}
    for name in ('stdout', 'stderr'):
        channel = value[name]
        raw = bytes.fromhex(channel['bytes_hex'])
        assert channel['offset'] == 0 and channel['eof'] is True
        assert channel['size'] == channel['next_offset'] == len(raw)
        assert len(raw) == terminal['log_bytes'][name]['stored']
        assert channel['text'] == raw.decode('utf-8', errors='replace')
        result[name] = raw
    return result


def frozen_candidate(manifest):
    assert manifest['baseline_commit'] == manifest['source_construction_parent'] == BASELINE_COMMIT
    candidate = json.loads(read_bound(relative_identity(manifest['candidate_input'])))
    package = json.loads(read_bound(relative_identity(manifest['candidate_manifest'])))
    assert package['schema'] == 'hepta-x230-d2-source-package/v1'
    assert package['source_parent'] == BASELINE_COMMIT and package['diagnostic_only'] is True
    assert package['qualification_executed'] is False
    assert package['future_qualification_counts'] is None and package['future_qualification_job_id'] is None
    expected_members = {'input.json', 'candidate.patch', 'baseline-source-map.json',
                        'candidate-source-map.json', 'summarize_trace_d2.py'} | {'source/' + p for p in CHANGED}
    assert set(package['files']) == expected_members and package['file_count'] == 7
    files = {}
    for name, identity in package['files'].items():
        raw = read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))
        assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == identity['git_blob']
        files[name] = raw
    assert sum(map(len, files.values())) == package['total_payload_bytes']
    assert json.loads(files['input.json']) == candidate
    assert candidate['schema'] == 'hepta-x230-d2-candidate/v1' and candidate['candidate'] == 'D2'
    assert candidate['root'] == str(ROOT)
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['accepted_production_baseline_commit'] == 'baab4def80be7af015b2e7a594cb302f66c4130e'
    assert set(candidate['changed_paths']) == CHANGED
    assert candidate['added_paths'] == candidate['removed_paths'] == candidate['new_test_functions'] == []
    assert all(candidate[key] is None for key in ('actual_formatted_source_map', 'actual_qualification_counts',
                                                 'actual_qualification_job_id', 'actual_qualification_report'))
    protocol = candidate['protocol']
    for key in ('diagnostic_only', 'original_eight_qualification_stages', 'original_nineteen_harness_tools',
                'ordinary_feature_off_cfg_erasure', 'same_feature_elf_for_off_and_on', 'native_auditor_unchanged'):
        assert protocol[key] is True
    assert protocol['runtime_adoption'] is False and protocol['jobs'] == 2
    assert protocol['disk_floor_bytes'] == 3 * 1024**3
    baseline, expected = (json.loads(files[name]) for name in ('baseline-source-map.json', 'candidate-source-map.json'))
    assert baseline == candidate['baseline_compile_inputs'] and expected == candidate['candidate_compile_inputs']
    assert len(baseline) == len(expected) == 222 and set(baseline) == set(expected)
    assert {name for name in expected if expected[name] != baseline[name]} == CHANGED
    for name in CHANGED:
        assert hashlib.sha256(files['source/' + name]).hexdigest() == expected[name]
        assert package['files']['source/' + name] == candidate['source_files'][name]
    for name, field in (('candidate.patch', 'candidate_patch'), ('baseline-source-map.json', 'baseline_source_map'),
                        ('candidate-source-map.json', 'candidate_source_map')):
        assert package['files'][name] == candidate[field]
    # Parser is support evidence, never a compiler input or a qualification stage.
    assert candidate['derived_parser']['executed'] is False
    assert package['files']['summarize_trace_d2.py']['sha256'] == candidate['derived_parser']['sha256']
    assert manifest['qualification_rule'] == {
        'original_all_features': True, 'diagnostic_environment': 'absent',
        'ordinary_supplemental_run_by_this_preparer': False}
    return candidate, relative_identity({**candidate['candidate_patch'], 'path': 'candidate/candidate.patch'})


def ready_inputs(manifest, closure):
    """Unsealed identities stop before the exclusive attempt claim and mutation."""
    assert manifest['schema'] == 'hepta-d2-direct-qualification-input/v1'
    assert closure['schema'] == 'hepta-d2-d1-cache-owner-closure/v1'
    for value in (manifest, closure):
        assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert HEX.fullmatch(manifest['owner_closure_input_sha256'])
    assert manifest['preparation_tool']['path'] == 'prepare_qualify.py'
    assert manifest['actual_d2_qualification'] is None and manifest['actual_d2_formatted_map'] is None
    assert manifest['actual_d2_test_counts'] is None and manifest['actual_d2_release_programs'] is None
    assert set(closure['inputs']) == set(OWNER_PATHS)
    for role, identity in closure['inputs'].items():
        assert identity['path'] == str(OWNER_PATHS[role])
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    assert closure['owner_root'] == str(CACHE_OWNER)
    assert closure['jobs'] == OWNER_JOBS
    assert closure['original_missing_paths'] == [str(path) for path in ORIGINAL_MISSING_PATHS]
    assert closure['original_c1_workflow_passed'] is False
    assert closure['standalone_original_auditor_already_executed'] is True
    assert closure['historical_auditors_to_execute'] == 0
    assert closure['candidate_adopted'] is False


def recheck_owner_inputs(closure):
    for identity in closure['inputs'].values():
        read_bound(identity)
    assert all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS)


def validate_owner_documents(doc, closure, baseline, harness):
    """Current D1 owners only; no recursive replay of their historical binders."""
    ids = closure['inputs']
    q = doc['qualification_report']
    assert q['schema'] == 'hepta-x230-composed-qualification/v1' and q['qualified'] is True
    assert q['source'] == str(BASE / 'source') and q['jobs'] == 2
    assert q['source_tested'] == q['source_after'] == doc['qualification_map'] == baseline
    assert q['harness_before'] == q['harness_after'] == harness
    assert [row['name'] for row in q['stages']] == STAGES and all(row['returncode'] == 0 for row in q['stages'])
    assert q['automatic_test_retries'] == 0 and q['service_changes'] is False and q.get('finished_utc')
    prep = doc['qualification_preparation']
    assert prep['schema'] == 'hepta-x230-d1-preparation/v1' and prep['passed'] is True
    assert prep['qualification_started'] is True and prep['qualification_returncode'] == 0 and not prep.get('error')
    assert prep['source_after_qualification'] == baseline
    assert prep['qualification_report_sha256'] == ids['qualification_report']['sha256']
    summary = doc['qualification_summary']
    assert summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
    assert summary['failed'] == summary['retries'] == 0 and summary['enumeration_errors'] == []
    counts = {key: summary[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    assert summary['source_manifest_path'] == str(BASE / 'qualification-01/source-map.json')
    assert summary['source_manifest_sha256'] == ids['qualification_map']['sha256']
    for prefix, job_key in (('qualification', 'qualification'), ('exact_ci', 'exact_ci'),
                            ('ordinary', 'ordinary'), ('ordinary_postflight', 'ordinary_postflight'),
                            ('native_audit', 'native_audit')):
        terminal = doc[prefix + '_native']
        native_terminal(terminal, OWNER_JOBS[job_key])
        native_streams(doc[prefix + '_read'], terminal)

    ci = doc['exact_ci_report']
    assert ci['schema'] == 'hepta-d1-external-rust-ci/v1' and ci['passed'] is True
    assert ci['original_qualification_job_id'] == OWNER_JOBS['qualification']
    assert ci['source_inputs_unchanged'] is True and ci['owned_children_closed'] is True
    assert ci['automatic_retries'] == 0 and ci['production_services_modified'] is False and ci.get('finished_utc')
    closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    ci_audit = doc['exact_ci_audit']
    assert ci['nextest_output_audit'] == ci_audit and ci_audit['verified'] is True
    assert {key: ci_audit[key] for key in counts} == counts
    assert ci['structured_inventory']['verified'] is True
    assert ci['structured_inventory']['case_inventory_sha256'] == ci_audit['case_inventory_sha256']
    ci_last = json.loads(native_streams(doc['exact_ci_read'], doc['exact_ci_native'])['stdout'].splitlines()[-1])
    assert ci_last['passed'] is True and ci_last['report'] == ids['exact_ci_report']

    ordinary = doc['ordinary_report']
    assert ordinary['schema'] == 'hepta-x230-composed-qualification/v1' and ordinary['qualified'] is True
    assert ordinary['source'] == str(BASE / 'source') and ordinary['jobs'] == 2
    assert ordinary['automatic_test_retries'] == 0 and ordinary['service_changes'] is False
    assert ordinary['source_input'] == ordinary['source_tested'] == ordinary['source_after'] == baseline
    assert ordinary['harness_before'] == ordinary['harness_after'] == harness
    ordinary_names = ['clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
    assert [row['name'] for row in ordinary['stages']] == ordinary_names
    assert all(row['returncode'] == 0 for row in ordinary['stages']) and ordinary.get('finished_utc')
    post = doc['ordinary_postflight_report']
    assert post['schema'] == 'hepta-d1-ordinary-supplement-postflight/v3' and post['passed'] is True
    assert post['ordinary_five_stages_passed'] is True and post['source_maps_unchanged'] is True
    assert post['compiler_input_count'] == 222 and post['original_qualification_harness_count'] == 19
    assert post['original_job_id'] == OWNER_JOBS['ordinary']
    assert post['original_q_job_id'] == OWNER_JOBS['qualification']
    assert post['original_exact_ci_job_id'] == OWNER_JOBS['exact_ci']
    assert post['automatic_retries'] == 0 and post['new_compile_or_workload_started'] is False
    assert post['original_auditors_reexecuted'] is False and post['ordinary_package_features'] == []
    assert post['dependency_defaults_changed'] is False and post['performance_acceptance_claim'] is False
    assert post['qualified_feature_programs_before'] == post['qualified_feature_programs_after']
    assert post['report'] == ids['ordinary_report']
    assert post['native_terminal'] == ids['ordinary_native'] and post['native_read_pages'] == [ids['ordinary_read']]
    assert post['qualification_source_map'] == ids['qualification_map']
    assert post['ordinary_source_map'] == ids['ordinary_map'] and doc['ordinary_map'] == baseline
    assert [row['name'] for row in post['stages']] == ordinary_names
    assert all(row['returncode'] == 0 for row in post['stages'])
    assert post['tests']['failed'] == post['tests']['retries'] == 0
    receipt = json.loads(native_streams(doc['ordinary_postflight_read'], doc['ordinary_postflight_native'])['stdout'])
    assert receipt['verified'] is True and receipt['compiler_or_workload_started'] is False
    assert receipt['original_job_id'] == OWNER_JOBS['ordinary'] and receipt['report'] == ids['ordinary_postflight_report']
    assert set(q['binaries']) == set(ordinary['binaries']) == set(post['ordinary_programs']) == {
        'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
    for name in q['binaries']:
        feature = post['qualified_feature_programs_after'][name]
        standard = post['ordinary_programs'][name]
        assert feature['path'] == str(BASE / 'qualification-01' / name)
        assert standard['path'] == str(BASE / 'ordinary-02' / name)
        assert q['binaries'][name] == {key: feature[key] for key in ('path', 'sha256')}
        assert ordinary['binaries'][name] == {key: standard[key] for key in ('path', 'sha256')}

    parent, adapter, workload = (doc[key] for key in ('c1_parent', 'c1_adapter', 'c1_report'))
    assert parent['schema'] == 'hepta-d1-c1-campaign-control/v1' and parent['passed'] is False
    assert parent['candidate_adopted'] is False and parent['performance_acceptance_claim'] is False
    assert parent['automatic_retries'] == 0 and parent['production_services_modified'] is False
    for key in ('inputs_unchanged', 'source_inputs_unchanged', 'baseline_source_inputs_unchanged',
                'qualified_source_maps_match_current_inputs'):
        assert parent[key] is True
    assert parent['normal_lifecycle_started'] is False and parent['capacity_workload_started'] is False
    assert parent['compiler_monitor']['passed'] is True and parent['quiescence']['passed'] is True
    assert parent['quiescence']['seconds_planned'] == 90 and parent.get('finished_utc')
    assert len(parent['stages']) == 1
    stage = parent['stages'][0]
    assert stage['name'] == 'native-observation' and stage['returncode'] == 1 and stage['passed'] is False
    assert stage['waited_and_reaped'] is True and stage['owned_process_absent'] is True
    assert stage['owned_process_group_absent'] is True and stage['timed_out'] is False
    assert stage['output_bindings'] == [ids['c1_report'], ids['c1_adapter']]
    assert adapter['schema'] == 'hepta-d1-c1-phase-cost-adapter/v1'
    assert adapter['original_returncode'] == 0 and adapter['original_wrapper_returned'] is True
    assert adapter['controller_close_evidence_complete'] is True and adapter['all_trace_reads_after_original_matrix'] is True
    assert adapter['analysis_complete'] is False and adapter['traces'] == []
    assert adapter['errors'] == [{'reason': 'unique original native request identity missing', 'type': 'ValueError'}]
    assert len(adapter['bindings']) == 8 and adapter['original_report'] == ids['c1_report']
    assert workload['passed'] is True and workload['automatic_rpc_retries'] == 0
    assert workload['effect_starts'] == workload['remote_mutation_tool_calls'] == 0
    assert workload['binary_hashes_unchanged'] is True and workload['source_originals_unchanged'] is True
    assert workload['order'] == 'ABBA' and len(workload['rounds']) == 4
    births = set()
    for index, row in enumerate(workload['rounds']):
        assert row['index'] == index and row['version'] == 'ABBA'[index] and row['passed'] is True
        for start_key, end_key in (('startup', 'shutdown'), ('restart_startup', 'restart_shutdown')):
            start, end = row[start_key], row[end_key]
            identity = (start['pid'], start['birth_ticks'])
            assert identity not in births
            births.add(identity)
            assert end['exit_code'] == 0 and end['observed_descendant_survivors'] == []
            assert end['reader_error'] is None and end['unmatched_responses'] == 0
            assert end['shutdown_method'] == 'stdin_eof' and end['transport_capture']['reader_eof'] is True
    native_terminal(doc['c1_native'], OWNER_JOBS['c1_holder'], 'failed', 1)
    native_streams(doc['c1_read'], doc['c1_native'])
    holder = doc['c1_holder']
    assert holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder['passed'] is False and holder['remote_returncode'] == 1
    assert holder['automatic_ssh_retries'] == 0 and holder['services_modified'] is False
    assert holder['owned_agent_reaped'] is True and holder['owned_agent_returncode'] == 2
    assert holder['owned_agent_directory_absent_after_context'] is True
    assert holder['owned_agent_socket_absent_after_context'] is True and holder.get('finished_utc')
    assert holder['remote_script_sha256'] == parent['launcher_sha256']

    audit = doc['native_audit_report']
    assert audit['schema'] == 'hepta-native-observation-independent-analysis/v3' and audit['verified'] is True
    assert audit['original_bytes'] == ids['c1_report']['bytes'] and audit['original_sha256'] == ids['c1_report']['sha256']
    assert audit['measured_calls'] == 768 and audit['warmup_calls'] == 96
    assert audit['preflight_restart_calls'] == 72 and audit['total_calls'] == 936 and audit['failed_calls'] == 0
    assert audit['binary_sha256'] == workload['binary_sha256'] == {
        arm: post['qualified_feature_programs_after']['hepta-runtime']['sha256'] for arm in ('A', 'B')}
    start = doc['native_audit_start']
    assert start['audit_recorded'] is True and start['reused'] is False and start['launch']['ok'] is True
    job = start['job']
    assert job['id'] == OWNER_JOBS['native_audit'] and job['host'] == 'x230'
    assert job['executable'] == '/usr/bin/python3' and job['cwd'] == str(BASE) and job['env_keys'] == []
    assert job['args'] == ['-B', str(BASE / 'c1-tools-01/reference/analyze_native_observation.py'),
                           '--report', str(BASE / 'c1-observation-01/report.json'), '--output',
                           str(BASE / 'c1-offline-interpretation-01/native-independent-summary.json')]
    audit_stdout = json.loads(native_streams(doc['native_audit_read'], doc['native_audit_native'])['stdout'])
    assert audit_stdout == {key: audit[key] for key in ('verified', 'measured_calls', 'warmup_calls', 'total_calls')}
    return {'closed': True, 'source_input_count': 222, 'qualification_counts': counts,
            'ordinary_counts': post['tests'], 'original_jobs': OWNER_JOBS,
            'original_c1_workflow_passed': False, 'c1_original_controller_closures': len(births),
            'standalone_original_native_audit_passed': True, 'historical_auditors_reexecuted': False,
            'candidate_adopted': False, 'current_machine_idle_claimed': False,
            'future_live_cache_process_scan_required': True,
            'retained_release_programs': {**{v['path']: v for v in post['qualified_feature_programs_after'].values()},
                                          **{v['path']: v for v in post['ordinary_programs'].values()}},
            'original_inputs': ids}


def cache_owner_closed(closure, harness):
    doc = {key: json.loads(read_bound(identity)) for key, identity in closure['inputs'].items()}
    result = validate_owner_documents(doc, closure, source_map(BASE / 'source'), harness)
    assert all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS)
    for identity in result['retained_release_programs'].values():
        read_bound(identity, maximum=64 * 1024 * 1024)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--owner-closure-sha256', required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize, 'assertion guards require normal Python execution'
    destination = ROOT / 'preparation.json'
    assert Path(__file__).resolve() == ROOT / 'prepare_qualify.py'
    assert sys.platform == 'linux' and os.getuid() == 1000 and ROOT.resolve() == ROOT
    input_binding = input_identity(ROOT / 'qualification-input.json', args.input_sha256)
    closure_binding = input_identity(ROOT / 'cache-owner-closure-inputs.json', args.owner_closure_sha256)
    manifest = json.loads(read_bound(input_binding))
    closure = json.loads(read_bound(closure_binding))
    ready_inputs(manifest, closure)
    assert manifest['owner_closure_input_sha256'] == args.owner_closure_sha256
    read_bound(relative_identity(manifest['preparation_tool']))
    assert all(name not in os.environ for name in DIAGNOSTIC_ENV), 'diagnostic environment must be absent during original qualification'
    assert all(not os.path.lexists(ROOT / name) for name in
               ('preparation.json', 'preparation.json.next', 'source', 'qualification-01', 'target-build'))
    report = {'schema': 'hepta-x230-d2-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'Qualified D1 plus diagnostic-only validation decomposition; exactly two frozen paths, no additions',
              'diagnostic_name': 'D2', 'performance_acceptance_claim': False,
              'cache_deletions': 0, 'first_actual_d2_qualification_required': True,
              'qualification_started': False,
              'qualified_release_kind': 'phase-cost-diagnostics compiled by original all-features qualification; mode unset',
              'diagnostic_environment_absent': True, 'ordinary_supplemental_executed': False,
              'input_binding': input_binding, 'cache_owner_closure_input': closure_binding}
    # The original first-attempt exclusive claim remains outside try/finally.
    # A duplicate must not replace another invocation's preparation receipt.
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        candidate_input, patch_binding = frozen_candidate(manifest)
        report['frozen_candidate_input'] = relative_identity(manifest['candidate_input'])
        report['frozen_candidate_manifest'] = relative_identity(manifest['candidate_manifest'])
        report['candidate_patch'] = patch_binding
        report['source_materialization'] = 'exact qualified D1 source copy plus frozen two-file D2 patch; D1 supplies only its closed build cache'
        harness = {p.name: sha(p) for p in sorted((BASE / 'source/tools/x230/20261028').glob('*.py'))}
        assert len(harness) == 19 and harness == manifest['qualification_harness_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads(read_bound(manifest['baseline_qualification']))
        completed_qualification(qualified, BASE / 'source', harness)
        assert baseline == qualified['source_tested'] == candidate_input['baseline_compile_inputs']
        candidate_expected = candidate_input['candidate_compile_inputs']
        assert len(baseline) == 222 and len(candidate_expected) == 222
        assert set(candidate_expected) - set(baseline) == ADDED and not set(baseline) - set(candidate_expected)
        assert {name for name in candidate_expected if candidate_expected[name] != baseline.get(name)} == CHANGED
        report['baseline_qualification'] = manifest['baseline_qualification']
        report['qualification_harness_sha256'] = harness
        report['cache_owner_closure'] = cache_owner_closed(closure, harness)
        cache = CACHE_OWNER / 'target-build'
        assert cache.resolve() == cache and cache.is_dir()
        assert set(p.name for p in cache.iterdir()) == {'debug', 'release', '.rustc_info.json'}
        report['free_bytes_before'] = shutil.disk_usage(ROOT).free
        assert report['free_bytes_before'] >= 3 * 1024**3
        report['retained_programs'] = retained_programs(CACHE_OWNER)
        report['retained_programs'].update({name: value['sha256'] for name, value in
            report['cache_owner_closure']['retained_release_programs'].items()})
        report['process_check'] = inspect_processes(cache)
        assert not report['process_check']['matched_processes'] and not report['process_check']['compiler_processes']
        report['cache_to_transfer'] = str(cache)
        save(destination, report)
        target = ROOT / 'target-build'
        assert not os.path.lexists(target)
        cache_identity = (cache.stat().st_dev, cache.stat().st_ino)
        assert cache_identity[0] == ROOT.stat().st_dev, 'cache rename must remain on one filesystem'
        cache.rename(target)
        assert (target.stat().st_dev, target.stat().st_ino) == cache_identity and not cache.exists()
        report['cache_transferred_by_rename'] = True
        report['new_full_cache_copy_bytes'] = 0
        for name, digest in report['retained_programs'].items():
            assert sha(Path(name)) == digest
        recheck_owner_inputs(closure)
        source = ROOT / 'source'
        shutil.copytree(BASE / 'source', source)
        assert source_map(source) == baseline
        assert {p.name: sha(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))} == harness
        subprocess.run(['/usr/bin/git', 'apply', '--check', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        subprocess.run(['/usr/bin/git', 'apply', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        candidate = source_map(source)
        assert candidate == candidate_expected
        report['source_before_qualification'] = candidate
        assert all(name not in os.environ for name in DIAGNOSTIC_ENV)
        command = ['/usr/bin/python3', '-B', '-u', str(source / 'tools/x230/20261028/qualify.py'),
                   '--source', str(source), '--output', str(ROOT / 'qualification-01'),
                   '--target', str(target), '--cargo-home', str(CARGO_HOME), '--jobs', '2']
        report['qualification_command'] = command
        save(destination, report)
        report['qualification_started'] = True
        save(destination, report)
        result = subprocess.run(command, cwd=source)
        report['qualification_returncode'] = result.returncode
        report['source_after_qualification'] = source_map(source)
        if result.returncode == 0:
            actual = json.loads((ROOT / 'qualification-01/report.json').read_bytes())
            completed_qualification(actual, source, harness)
            assert actual['source_input'] == candidate_expected
            assert actual['source_tested'] == report['source_after_qualification']
            assert actual['source_tested'] == json.loads((ROOT / 'qualification-01/source-map.json').read_bytes())
            assert set(actual['source_tested']) == set(candidate_expected)
            assert {name for name in actual['source_tested'] if actual['source_tested'][name] != baseline.get(name)} == CHANGED
            assert actual['source_tested']['Cargo.toml'] == candidate_expected['Cargo.toml']
            actual_cargo = tomllib.loads((source / 'Cargo.toml').read_text())
            assert actual_cargo['features'] == {'phase-cost-diagnostics': []}
            report['qualification_report_sha256'] = sha(ROOT / 'qualification-01/report.json')
            report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save(destination, report)
        print(json.dumps({key: report.get(key) for key in
                          ('passed', 'error', 'qualification_returncode', 'free_bytes_before')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
