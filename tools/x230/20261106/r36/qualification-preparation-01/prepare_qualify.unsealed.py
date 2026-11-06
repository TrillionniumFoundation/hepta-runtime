#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""First R36 qualification: accepted R24 plus the two frozen scratch-path files.

The original eight-stage qualifier, nineteen harness tools, jobs=2 and safety
limits remain unchanged. Only a closed D2 cache may move once; no historical
workload or auditor is rerun, and diagnostic results are not adoption.
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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r36')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
CACHE_OWNER = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED = {'src/mcp/runtime/ssh_observation_profile.rs',
           'src/mcp/runtime/ssh_observation_reference_tests.rs'}
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
HEX = re.compile(r'[0-9a-f]{64}\Z')

OWNER_JOBS = {'qualification':'1a1b0cc0f51-fc05-7301','exact_ci':'1a1b0f08c41-fc05-7434','ordinary':'1a1b1014af6-fc05-74d2','ordinary_postflight':'1a1b1217f3f-fc05-7616'}
OWNER_PATHS = {
    'qualification_report': CACHE_OWNER / 'qualification-01/report.json',
    'qualification_preparation': CACHE_OWNER / 'preparation.json',
    'qualification_native': CACHE_OWNER / 'qualification-terminal-status-01.json',
    'qualification_read': CACHE_OWNER / 'qualification-native-read-01.json',
    'qualification_summary': CACHE_OWNER / 'qualification-01/isolated-tests/summary.json',
    'qualification_map': CACHE_OWNER / 'qualification-01/source-map.json',
    'exact_ci_report': CACHE_OWNER / 'rust-ci-01/report.json',
    'exact_ci_audit': CACHE_OWNER / 'rust-ci-01/nextest-output-audit.json',
    'exact_ci_native': CACHE_OWNER / 'rust-ci-native-01.json',
    'exact_ci_read': CACHE_OWNER / 'rust-ci-native-read-01.json',
    'ordinary_report': CACHE_OWNER / 'ordinary-01/report.json',
    'ordinary_native': CACHE_OWNER / 'ordinary-native-01.json',
    'ordinary_read': CACHE_OWNER / 'ordinary-native-read-01-000.json',
    'ordinary_map': CACHE_OWNER / 'ordinary-01/source-map.json',
    'ordinary_postflight_report': CACHE_OWNER / 'ordinary-postflight-01.json',
    'ordinary_postflight_native': CACHE_OWNER / 'ordinary-postflight-native-01.json',
    'ordinary_postflight_read': CACHE_OWNER / 'ordinary-postflight-native-read-01-000.json',
    'c1_first_parent': CACHE_OWNER / 'c1-campaign-01/report.json',
    'c1_first_monitor_audit': CACHE_OWNER / 'c1-campaign-01/compiler-monitor.audit.json',
    'c1_recovery_parent': CACHE_OWNER / 'c1-campaign-02/report.json',
    'c1_recovery_monitor_audit': CACHE_OWNER / 'c1-campaign-02/compiler-monitor.audit.json',
    'c1_recovery_report': CACHE_OWNER / 'c1-observation-02/report.json',
    'c1_first_native': ROOT / 'owner-closure-provenance/c1-first-native.json',
    'c1_first_read': ROOT / 'owner-closure-provenance/c1-first-read.json',
    'c1_first_holder': ROOT / 'owner-closure-provenance/c1-first-holder.json',
    'c1_recovery_native': ROOT / 'owner-closure-provenance/c1-recovery-native.json',
    'c1_recovery_read': ROOT / 'owner-closure-provenance/c1-recovery-read.json',
    'c1_recovery_holder': ROOT / 'owner-closure-provenance/c1-recovery-holder.json',
}
ORIGINAL_MISSING_PATHS = (
    CACHE_OWNER / 'c1-observation-01/report.json',
    CACHE_OWNER / 'c1-observation-01/independent-summary.json',
    CACHE_OWNER / 'c1-adapter-evidence-01/adapter-report.json',
    CACHE_OWNER / 'c1-campaign-01/summary.json',
)

# General preparation helpers are retained verbatim from the R35 launcher.
# The R36 draft03 candidate package remains immutable under ROOT/candidate/.
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
    assert manifest['schema'] == 'hepta-r36-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['git_parent'] == BASELINE_COMMIT
    assert manifest['candidate_catalog_git_blob'] == 'c140350897adc751682e7eacd6e1874325d86538'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 52381,
        'sha256': '02171769738c0d21c2b94c75bce1ecc8ef301b6c55b06087e57f8b02106d50b0'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/package-manifest.json', 'bytes': 2760,
        'sha256': '637d573634f63fdca168d1c73201466fe601f2158c54e0c5835f205be843c73f'}
    candidate = json.loads(read_bound(relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-r36-source-draft-package/v1'
    assert frozen['revision'] == 'lazy-scratch-draft-03'
    assert frozen['baseline_commit'] == BASELINE_COMMIT
    expected_files = {
        'baseline/src/mcp/runtime/ssh_observation_profile.rs',
        'baseline/src/mcp/runtime/ssh_observation_reference_tests.rs',
        'source/src/mcp/runtime/ssh_observation_profile.rs',
        'source/src/mcp/runtime/ssh_observation_reference_tests.rs',
        'baseline-source-map.json', 'candidate-source-map.json', 'candidate.patch',
        'draft02-to-draft03.patch', 'input.json', 'static-review.json', 'README.md'}
    assert set(frozen['files']) == expected_files and len(expected_files) == 11
    for name, identity in frozen['files'].items():
        read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))
    assert candidate['schema'] == 'hepta-x230-r36-candidate-draft/v1'
    assert candidate['revision'] == 'lazy-scratch-draft-03'
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['patch_sha256'] == 'fc0d76fda9d8fb921443f6031a80a1bff3dd765284fc54bd08055c613abb04d0'
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert set(candidate['changed_paths']) == CHANGED
    assert candidate['new_test_functions'] == [
        'shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths',
        'shared_verification_buffer_keeps_mismatch_cancellation_precedence']
    assert candidate['qualification'] is None and candidate['exact_ci'] is None
    assert candidate['performance'] is None and candidate['adopted'] is False
    for name, field in (('baseline-source-map.json', 'baseline_compile_inputs'),
                        ('candidate-source-map.json', 'candidate_compile_inputs')):
        identity = frozen['files'][name]
        assert json.loads(read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))) == candidate[field]
        assert len(candidate[field]) == 220
    patch = frozen['files']['candidate.patch']
    assert patch == candidate['patch'] and patch['sha256'] == candidate['patch_sha256']
    return candidate, relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def ready_inputs(manifest, closure):
    """Unsealed closure inputs stop before the exclusive attempt claim."""
    assert manifest['schema'] == 'hepta-r36-direct-qualification-input/v1'
    assert closure['schema'] == 'hepta-r36-d2-cache-owner-closure/v1'
    for value in (manifest, closure):
        assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert HEX.fullmatch(manifest['owner_closure_input_sha256'])
    assert manifest['preparation_tool']['path'] == 'prepare_qualify.py'
    assert set(closure['inputs']) == set(OWNER_PATHS)
    for name, path in OWNER_PATHS.items():
        identity = closure['inputs'][name]
        assert identity['path'] == str(path)
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    assert type(closure['c1_recovery_diagnostic_evidence_passed']) is bool
    assert closure['qualification_or_measurement_still_running'] is False


def recheck_owner_inputs(closure):
    for identity in closure['inputs'].values():
        read_bound(identity)
    assert all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS)


def validate_owner_documents(doc, closure, owner_source, harness):
    """Current D2 owners only; no recursive replay of historical binders."""
    ids = closure['inputs']
    assert len(owner_source) == 222
    q = doc['qualification_report']
    assert q['schema'] == 'hepta-x230-composed-qualification/v1' and q['qualified'] is True
    assert q['source'] == str(CACHE_OWNER / 'source') and q['jobs'] == 2
    assert q['source_tested'] == q['source_after'] == doc['qualification_map'] == owner_source
    assert q['harness_before'] == q['harness_after'] == harness
    assert [row['name'] for row in q['stages']] == STAGES and all(row['returncode'] == 0 for row in q['stages'])
    assert q['automatic_test_retries'] == 0 and q['service_changes'] is False and q.get('finished_utc')
    prep = doc['qualification_preparation']
    assert prep['schema'] == 'hepta-x230-d2-preparation/v1' and prep['passed'] is True
    assert prep['qualification_started'] is True and prep['qualification_returncode'] == 0 and not prep.get('error')
    assert prep['source_after_qualification'] == owner_source
    assert prep['qualification_report_sha256'] == ids['qualification_report']['sha256']
    summary = doc['qualification_summary']
    assert summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
    assert summary['failed'] == summary['retries'] == 0 and summary['enumeration_errors'] == []
    counts = {key: summary[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    assert summary['source_manifest_path'] == str(CACHE_OWNER / 'qualification-01/source-map.json')
    assert summary['source_manifest_sha256'] == ids['qualification_map']['sha256']
    for prefix, job_key in (('qualification', 'qualification'), ('exact_ci', 'exact_ci'),
                            ('ordinary', 'ordinary'), ('ordinary_postflight', 'ordinary_postflight')):
        terminal = doc[prefix + '_native']
        native_terminal(terminal, OWNER_JOBS[job_key])
        native_streams(doc[prefix + '_read'], terminal)

    ci = doc['exact_ci_report']
    assert ci['schema'] == 'hepta-d2-external-rust-ci/v1' and ci['passed'] is True
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
    assert ordinary['source'] == str(CACHE_OWNER / 'source') and ordinary['jobs'] == 2
    assert ordinary['automatic_test_retries'] == 0 and ordinary['service_changes'] is False
    assert ordinary['source_input'] == ordinary['source_tested'] == ordinary['source_after'] == owner_source
    assert ordinary['harness_before'] == ordinary['harness_after'] == harness
    ordinary_names = ['clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
    assert [row['name'] for row in ordinary['stages']] == ordinary_names
    assert all(row['returncode'] == 0 for row in ordinary['stages']) and ordinary.get('finished_utc')
    post = doc['ordinary_postflight_report']
    assert post['schema'] == 'hepta-d2-ordinary-supplement-postflight/v1' and post['passed'] is True
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
    assert post['ordinary_source_map'] == ids['ordinary_map'] and doc['ordinary_map'] == owner_source
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
        assert feature['path'] == str(CACHE_OWNER / 'qualification-01' / name)
        assert standard['path'] == str(CACHE_OWNER / 'ordinary-01' / name)
        assert q['binaries'][name] == {key: feature[key] for key in ('path', 'sha256')}
        assert ordinary['binaries'][name] == {key: standard[key] for key in ('path', 'sha256')}

    first = validate_c1_owner(doc, closure, 'first', '01')
    assert first['parent']['passed'] is False and first['exit_code'] == 1
    assert first['parent']['stages'] == []
    assert first['parent']['inputs_unchanged'] is False
    assert first['parent']['source_inputs_unchanged'] is False
    assert first['parent']['error'] == {
        'type': 'FileNotFoundError',
        'reason': "[Errno 2] No such file or directory: '/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json'"}
    assert 'quiescence' not in first['parent']
    assert ids['c1_first_parent']['bytes'] == 396721
    assert ids['c1_first_parent']['sha256'] == '433c88277580f00736096927d3d7cab4e46c65d229f0b8f6a6140490eaf5f990'

    recovery = validate_c1_owner(doc, closure, 'recovery', '02')
    parent = recovery['parent']
    for key in ('inputs_unchanged', 'source_inputs_unchanged', 'baseline_source_inputs_unchanged',
                'qualified_source_maps_match_current_inputs'):
        assert parent[key] is True
    assert parent['quiescence']['passed'] is True and parent['quiescence']['seconds_planned'] == 90
    names = [row['name'] for row in parent['stages']]
    assert names in (['native-observation'], ['native-observation', 'native-audit'])
    for row in parent['stages']:
        assert row['waited_and_reaped'] is True and row['owned_process_absent'] is True
        assert row['owned_process_group_absent'] is True and row['timed_out'] is False
    assert ids['c1_recovery_report'] in parent['stages'][0]['output_bindings']
    workload = doc['c1_recovery_report']
    assert workload['automatic_rpc_retries'] == 0
    assert workload['effect_starts'] == workload['remote_mutation_tool_calls'] == 0
    assert workload['binary_hashes_unchanged'] is True and workload['source_originals_unchanged'] is True
    assert workload['order'] == 'ABBA' and len(workload['rounds']) == 4
    assert workload['binary_sha256'] == {
        arm: post['qualified_feature_programs_after']['hepta-runtime']['sha256'] for arm in ('A', 'B')}
    births = set()
    for index, row in enumerate(workload['rounds']):
        assert row['index'] == index and row['version'] == 'ABBA'[index]
        for start_key, end_key in (('startup', 'shutdown'), ('restart_startup', 'restart_shutdown')):
            start, end = row[start_key], row[end_key]
            identity = (start['pid'], start['birth_ticks'])
            assert identity not in births
            births.add(identity)
            assert end['exit_code'] == 0 and end['observed_descendant_survivors'] == []
            assert end['reader_error'] is None and end['unmatched_responses'] == 0
            assert end['shutdown_method'] == 'stdin_eof' and end['transport_capture']['reader_eof'] is True
    assert len(births) == 8
    assert type(parent['diagnostic_evidence_passed']) is bool
    assert closure['c1_recovery_diagnostic_evidence_passed'] == parent['diagnostic_evidence_passed']
    return {'closed': True, 'source_input_count': 222, 'qualification_counts': counts,
            'ordinary_counts': post['tests'], 'original_jobs': closure['jobs'],
            'c1_original_first_attempt_failed_before_workload': True,
            'c1_original_first_source_recheck_completed': False,
            'c1_recovery_controllers_closed': len(births),
            'c1_recovery_workflow_passed': parent['passed'],
            'c1_recovery_diagnostic_evidence_passed': parent['diagnostic_evidence_passed'],
            'historical_auditors_reexecuted': False, 'candidate_adopted': False,
            'current_machine_idle_claimed': False, 'future_live_cache_process_scan_required': True,
            'retained_release_programs': {**{v['path']: v for v in post['qualified_feature_programs_after'].values()},
                                          **{v['path']: v for v in post['ordinary_programs'].values()}},
            'cache_release_programs': {name: {**post['ordinary_programs'][name],
                'path': str(CACHE_OWNER / 'target-build/release' / relative)}
                for name, relative in (('hepta-runtime', 'hepta-runtime'),
                                       ('hepta-runtime-jobctl', 'hepta-runtime-jobctl'),
                                       ('native_process_driver', 'examples/native_process_driver'))},
            'original_inputs': ids}


def validate_c1_owner(doc, closure, prefix, attempt):
    parent = doc['c1_' + prefix + '_parent']
    native = doc['c1_' + prefix + '_native']
    holder = doc['c1_' + prefix + '_holder']
    monitor = doc['c1_' + prefix + '_monitor_audit']
    job_id = closure['jobs']['c1_' + prefix + '_holder']
    code = native['exit_code']
    assert type(code) is int and code in (0, 1)
    native_terminal(native, job_id, 'succeeded' if code == 0 else 'failed', code)
    raw = native_streams(doc['c1_' + prefix + '_read'], native)
    assert raw['stderr'] == b''
    assert parent['schema'] == 'hepta-d2-c1-campaign-control/v1' and parent['attempt'] == attempt
    assert parent['passed'] is (code == 0) and parent.get('finished_utc')
    assert parent['candidate_adopted'] is False and parent['performance_acceptance_claim'] is False
    assert parent['automatic_retries'] == 0 and parent['production_services_modified'] is False
    assert parent['normal_lifecycle_started'] is False and parent['capacity_workload_started'] is False
    assert parent['compiler_monitor']['passed'] is True
    assert parent['compiler_monitor']['independent_audit'] == closure['inputs']['c1_' + prefix + '_monitor_audit']
    assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
    assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
    assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
    assert monitor['ledger'] == parent['compiler_monitor']['ledger']
    assert holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder['passed'] is (code == 0) and holder['remote_returncode'] == code
    assert holder['automatic_ssh_retries'] == 0 and holder['services_modified'] is False
    assert holder['owned_agent_reaped'] is True and type(holder['owned_agent_returncode']) is int
    assert holder['owned_agent_directory_absent_after_context'] is True
    assert holder['owned_agent_socket_absent_after_context'] is True and holder.get('finished_utc')
    assert holder['remote_script_sha256'] == parent['launcher_sha256']
    return {'parent': parent, 'exit_code': code}


def cache_owner_closed(closure, harness):
    assert closure['schema'] == 'hepta-r36-d2-cache-owner-closure/v1'
    assert closure['sealed'] is True and closure['required_missing_bindings'] == []
    assert closure['owner_root'] == str(CACHE_OWNER)
    assert closure['cache_path'] == str(CACHE_OWNER / 'target-build')
    assert closure['historical_auditors_to_execute'] == 0 and closure['candidate_adopted'] is False
    assert closure['qualification_or_measurement_still_running'] is False
    assert set(closure['inputs']) == set(OWNER_PATHS)
    for name, path in OWNER_PATHS.items():
        assert closure['inputs'][name]['path'] == str(path)
    for name, job_id in OWNER_JOBS.items():
        assert closure['jobs'][name] == job_id
    assert set(closure['jobs']) == set(OWNER_JOBS) | {'c1_first_holder', 'c1_recovery_holder'}
    assert all(type(closure['jobs'][name]) is str and closure['jobs'][name]
               for name in ('c1_first_holder', 'c1_recovery_holder'))
    doc = {key: json.loads(read_bound(identity)) for key, identity in closure['inputs'].items()}
    result = validate_owner_documents(doc, closure, source_map(CACHE_OWNER / 'source'), harness)
    assert closure['original_missing_paths'] == [str(path) for path in ORIGINAL_MISSING_PATHS]
    assert all(not os.path.lexists(path) for path in ORIGINAL_MISSING_PATHS)
    for identity in result['retained_release_programs'].values():
        read_bound(identity, maximum=64 * 1024 * 1024)
    for identity in result['cache_release_programs'].values():
        read_bound(identity, maximum=64 * 1024 * 1024)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--owner-closure-sha256', required=True)
    args = parser.parse_args()
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
    assert all(not os.path.lexists(ROOT / name) for name in
               ('preparation.json', 'preparation.json.next', 'source', 'qualification-01', 'target-build'))
    report = {'schema': 'hepta-x230-r36-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'R24 plus reference-only Context elimination and sweep-local lazy scratch; two frozen files only',
              'cache_deletions': 0, 'first_actual_r36_qualification_required': True,
              'qualification_started': False}
    # Claim this first attempt atomically before any later report replacement.
    # A duplicate launch fails here outside the try/finally and cannot overwrite
    # the original owner's receipt, even if both saw the initial absent paths.
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    try:
        assert sys.platform == 'linux' and os.getuid() == 1000 and ROOT.resolve() == ROOT
        report['input_binding'] = input_binding
        report['cache_owner_closure_input'] = closure_binding
        assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
        assert manifest['owner_closure_input_sha256'] == args.owner_closure_sha256
        assert manifest['preparation_tool']['path'] == 'prepare_qualify.py'
        read_bound(relative_identity(manifest['preparation_tool']))
        candidate_input, patch_binding = frozen_candidate(manifest)
        report['frozen_candidate_input'] = relative_identity(manifest['candidate_input'])
        report['frozen_candidate_manifest'] = relative_identity(manifest['candidate_manifest'])
        report['candidate_patch'] = patch_binding
        report['source_materialization'] = 'accepted R24 source copy plus the frozen R36 patch; D2 supplies its closed build cache only'
        harness = {p.name: sha(p) for p in sorted((BASE / 'source/tools/x230/20261028').glob('*.py'))}
        assert len(harness) == 19 and harness == manifest['qualification_harness_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads(read_bound(manifest['baseline_qualification']))
        completed_qualification(qualified, BASE / 'source', harness)
        assert baseline == qualified['source_tested'] == candidate_input['baseline_compile_inputs']
        candidate_expected = candidate_input['candidate_compile_inputs']
        assert set(baseline) == set(candidate_expected) and len(baseline) == 220
        assert {p for p in baseline if candidate_expected[p] != baseline[p]} == CHANGED
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
        for value in report['cache_owner_closure']['cache_release_programs'].values():
            moved = {**value, 'path': str(target / Path(value['path']).relative_to(cache))}
            read_bound(moved, maximum=64 * 1024 * 1024)
        source = ROOT / 'source'
        shutil.copytree(BASE / 'source', source)
        assert source_map(source) == baseline
        assert {p.name: sha(p) for p in sorted((source / 'tools/x230/20261028').glob('*.py'))} == harness
        subprocess.run(['/usr/bin/git', 'apply', '--check', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        subprocess.run(['/usr/bin/git', 'apply', str(ROOT / 'candidate/candidate.patch')], cwd=source, check=True)
        candidate = source_map(source)
        assert candidate == candidate_expected
        report['source_before_qualification'] = candidate
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
            assert set(actual['source_tested']) == set(baseline)
            assert {p for p in baseline if actual['source_tested'][p] != baseline[p]} == CHANGED
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
