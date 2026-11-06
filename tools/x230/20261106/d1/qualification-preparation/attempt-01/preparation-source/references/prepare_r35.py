#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""First actual R35 qualification: accepted R24 plus three frozen allocation-path files.

After the original R34 owners have closed, rename its unused build cache. Keep
all original reports, source trees and separately preserved executables. Invoke
the unchanged eight-stage qualifier once. This does not adopt R34 performance.
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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
CACHE_OWNER = Path('/home/qian/hepta-runtime-optimization-20261106-r34')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED = {'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/ssh_observation_pool.rs',
           'src/mcp/runtime/ssh_observation_pool_tests.rs'}
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
HEX = re.compile(r'[0-9a-f]{64}\Z')

# General preparation helpers are retained from the successful R34 launcher.
# The R35 candidate package remains immutable under ROOT/candidate/.
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
    assert manifest['schema'] == 'hepta-r35-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['git_parent'] == BASELINE_COMMIT
    assert manifest['candidate_catalog_git_blob'] == '4251bcdfb0e5897eaba2ebf3f507f0729e2e3667'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 53380,
        'sha256': '7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/manifest.json', 'bytes': 5225,
        'sha256': 'e5f4338e3581ecc4560269a417941b4802a8b58307eb60eea6e04dd7a4f5102b'}
    candidate = json.loads(read_bound(relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-x230-r35-source-package/v1'
    assert frozen['baseline_commit'] == BASELINE_COMMIT and frozen['compile_input_count'] == 220
    assert set(frozen['changed_compile_paths']) == CHANGED
    seen = set()
    for identity in frozen['files']:
        name = identity['path']
        assert name not in seen
        seen.add(name)
        read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))
    assert len(seen) == 28 and frozen['file_count_excluding_manifest'] == 28
    assert candidate['schema'] == 'hepta-x230-r35-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['patch_path'] == 'candidate.patch'
    assert candidate['patch_sha256'] == '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a'
    assert candidate['added_paths'] == candidate['removed_paths'] == []
    assert set(candidate['changed_paths']) == CHANGED
    assert candidate['new_test_functions'] == []
    for label, field in (('baseline_map_artifact', 'baseline_compile_inputs'),
                         ('candidate_map_artifact', 'candidate_compile_inputs')):
        identity = candidate[label]
        assert json.loads(read_bound(relative_identity({**identity, 'path': 'candidate/' + identity['path']}))) == candidate[field]
    patch = next(value for value in frozen['files'] if value['path'] == 'candidate.patch')
    assert patch['sha256'] == candidate['patch_sha256']
    return candidate, relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def cache_owner_closed(value, harness):
    assert value['schema'] == 'hepta-x230-r35-cache-owner-closure/v1'
    assert value['cache_owner'] == str(CACHE_OWNER)
    assert value['cache_path'] == str(CACHE_OWNER / 'target-build')
    assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r34_observation_performance_passed'] is False
    assert value['r34_lifecycle_abba_executed'] is False
    assert value['lifecycle_materialization_started'] is False
    assert value['lifecycle_materializer_job_id'] is None
    assert value['capacity_build_or_campaign_started_by_coordinator'] is False
    identities = value['inputs']
    paths = {
        'qualification_report': 'qualification-01/report.json',
        'qualification_native': 'qualification-terminal-status-01.json',
        'qualification_preparation': 'preparation.json',
        'qualification_map': 'qualification-01/source-map.json',
        'exact_ci_report': 'rust-ci-01/report.json',
        'exact_ci_native': 'rust-ci-native-01.json',
        'exact_ci_read': 'rust-ci-native-read-01.json',
        'observation_parent': 'campaign-01/report.json',
        'observation_native': 'observation-holder-native-01.json',
        'observation_holder_read': 'observation-holder-read-01.json',
        'observation_holder_report': 'observation-holder-report-01.json',
        'observation_report': 'campaign-01/native-observation/report.json',
        'observation_audit': 'campaign-01/native-observation/independent-summary.json',
        'compiler_monitor_audit': 'campaign-01/compiler-monitor.audit.json',
        'observation_summary': 'campaign-01/summary.json',
    }
    assert set(identities) == set(paths)
    for label, relative in paths.items():
        assert identities[label]['path'] == str(CACHE_OWNER / relative)
    assert value['postflight_receipt'] == {
        'path': 'owner-closure-provenance/observation-postflight-01.json', 'bytes': 5064,
        'sha256': '17a371b24de733c7e412afdcf31a1fdad1745bbe2b560177e010816ee5193cc1'}
    postflight = json.loads(read_bound(relative_identity(value['postflight_receipt'])))
    assert postflight['schema'] == 'hepta-r34-rejected-observation-owner-postflight/v1'
    assert postflight['accepted_baseline_commit'] == BASELINE_COMMIT
    assert postflight['cache_path'] == value['cache_path']
    assert postflight['cache_moved'] is False and postflight['cache_deleted'] is False
    assert postflight['current_source_matches_qualified_map'] is True and postflight['compiler_input_count'] == 220
    assert postflight['observation_workflow_closed'] is True and postflight['original_owned_agent_reaped'] is True
    assert postflight['observation_gate_passed'] is False and postflight['performance_gates_passed'] is False
    assert postflight['candidate_adopted'] is False and postflight['normal_lifecycle_started'] is False
    assert postflight['lifecycle_materialization_started'] is False
    assert postflight['original_lifecycle_materializer_job_id'] is None
    assert postflight['capacity_build_or_campaign_started_by_coordinator'] is False
    assert postflight['tests_benchmarks_or_auditors_reexecuted'] is False
    assert postflight['rejection_reasons'] == ['C8 regression gate']
    assert set(postflight['originals']) == set(paths.values())
    for label, relative in paths.items():
        assert postflight['originals'][relative] == identities[label]
    receipts = {label: json.loads(read_bound(identity)) for label, identity in identities.items()}
    assert value['qualification_job_id'] == '1a1aef7882f-fc05-6499'
    native_terminal(receipts['qualification_native'], value['qualification_job_id'])
    qualified = receipts['qualification_report']
    completed_qualification(qualified, CACHE_OWNER / 'source', harness)
    assert qualified['source_tested'] == receipts['qualification_map']
    preparation = receipts['qualification_preparation']
    assert preparation['schema'] == 'hepta-x230-r34-preparation/v1'
    assert preparation['passed'] is True and preparation['qualification_returncode'] == 0
    assert preparation['qualification_started'] is True
    assert preparation['automatic_retries'] == 0 and preparation['production_services_modified'] is False
    assert preparation['qualification_report_sha256'] == identities['qualification_report']['sha256']
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']

    assert value['exact_ci_job_id'] == '1a1af1ebf1d-fc05-65f2'
    native_terminal(receipts['exact_ci_native'], value['exact_ci_job_id'])
    assert native_streams(receipts['exact_ci_read'], receipts['exact_ci_native'])['stderr'] == b''
    ci = receipts['exact_ci_report']
    assert ci['schema'] == 'hepta-r34-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == value['qualification_job_id']
    closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    assert ci['nextest_output_audit']['verified'] is True
    # These are completed R34 owner counts, never predicted R35 counts.
    assert {name: ci['nextest_output_audit'][name] for name in
            ('passed', 'failed', 'ignored', 'selected', 'retries')} == {
                'passed': 1653, 'failed': 0, 'ignored': 34, 'selected': 1687, 'retries': 0}

    assert value['observation_holder_job_id'] == '1a1af308953-fc05-6698'
    assert postflight['original_observation_job_id'] == value['observation_holder_job_id']
    native_terminal(receipts['observation_native'], value['observation_holder_job_id'])
    holder_raw = native_streams(receipts['observation_holder_read'], receipts['observation_native'])
    assert holder_raw['stderr'] == b''
    holder_rows = [json.loads(line) for line in holder_raw['stdout'].splitlines()]
    assert len(holder_rows) == 2 and holder_rows[0]['phase'] == 'owned_agent_ready'
    assert holder_rows[0]['identity_count'] == 5
    holder_completion = holder_rows[1]
    assert holder_completion['passed'] is True and holder_completion['remote_returncode'] == 0
    assert holder_completion['owned_agent_reaped'] is True
    parent = receipts['observation_parent']
    assert holder_rows[0]['remote_script_sha256'] == parent['launcher_sha256']
    holder_report = receipts['observation_holder_report']
    assert holder_report['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
    assert holder_report['passed'] is True and holder_report['remote_returncode'] == 0
    assert holder_report.get('finished_utc') and not holder_report.get('error')
    assert holder_report['remote_script_sha256'] == parent['launcher_sha256']
    assert holder_report['owned_agent_reaped'] is True
    assert holder_report['owned_agent_directory_absent_after_context'] is True
    assert holder_report['owned_agent_socket_absent_after_context'] is True
    assert holder_report['automatic_ssh_retries'] == 0 and holder_report['services_modified'] is False
    assert parent['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert parent['passed'] is True and parent.get('finished_utc') and not parent.get('error')
    assert parent['observation_gate_passed'] is False
    assert parent['rejection_reasons'] == ['C8 regression gate']
    assert parent['correctness_stages_completed'] is True and parent['measurement_attribution_valid'] is True
    assert parent['source_inputs_unchanged'] is True and parent['inputs_unchanged'] is True
    assert parent['compiler_monitor']['passed'] is True
    assert parent['compiler_monitor']['independent_audit'] == identities['compiler_monitor_audit']
    monitor = receipts['compiler_monitor_audit']
    assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
    assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
    assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
    assert monitor['validation']['validated_sample_count'] == 301
    assert monitor['ledger'] == parent['compiler_monitor']['ledger']
    closed_stages(parent['stages'], ['native-observation', 'native-audit', 'native-boundary',
                                    'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    assert parent['stages'][0]['output_bindings'] == [identities['observation_report']]
    assert parent['stages'][1]['output_bindings'] == [identities['observation_audit']]
    assert parent['summary'] == identities['observation_summary']
    observation = receipts['observation_report']
    assert observation['passed'] is True and observation.get('finished_unix')
    assert [row['version'] for row in observation['rounds']] == list('ABBA')
    for row in observation['rounds']:
        assert row['passed'] is True
        assert [cell['concurrency'] for cell in row['cells']] == [1, 8, 16]
        assert all(cell['calls'] == cell['successes'] == 192 for cell in row['cells'])
        for label in ('shutdown', 'restart_shutdown'):
            closed = row[label]
            assert closed['exit_code'] == 0 and closed['shutdown_method'] == 'stdin_eof'
            assert not closed['observed_descendant_survivors'] and closed['reader_error'] is None
            assert closed['transport_capture']['reader_eof'] is True and closed['unmatched_responses'] == 0
            assert closed['resources']['sampler_error'] is None
    audit = receipts['observation_audit']
    assert audit['schema'] == 'hepta-native-observation-independent-analysis/v3' and audit['verified'] is True
    assert audit['original_bytes'] == identities['observation_report']['bytes']
    assert audit['original_sha256'] == identities['observation_report']['sha256']
    assert {name: audit[name] for name in ('measured_calls', 'warmup_calls', 'preflight_restart_calls',
                                          'total_calls', 'failed_calls')} == {
        'measured_calls': 2304, 'warmup_calls': 288, 'preflight_restart_calls': 72,
        'total_calls': 2664, 'failed_calls': 0}
    summary = receipts['observation_summary']
    assert summary['schema'] == 'hepta-r25-observation-gates/v1'
    assert summary['correctness_verified'] is True and summary['evidence_verified'] is True
    assert summary['observation_gate_passed'] is False and summary['performance_gates_passed'] is False
    assert summary['rejection_reasons'] == ['C8 regression gate']

    assert postflight['normal_lifecycle_paths_absent'] == [
        'lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01']
    for name in ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01',
                 'lifecycle-materialization-native-01.json', 'lifecycle-materialization-read-01.json'):
        assert not os.path.lexists(CACHE_OWNER / name), 'unreviewed lifecycle output exists: ' + name
    return {'inputs': identities, 'qualification_and_exact_ci_succeeded': True,
            'observation_parent_completed': True, 'observation_controllers_closed': True,
            'observation_holder_owned_agent_reaped': True,
            'observation_performance_passed': False, 'rejection_reasons': ['C8 regression gate'],
            'lifecycle_materialization_started': False, 'lifecycle_materializer_job_id': None,
            'normal_lifecycle_started': False,
            'normal_lifecycle_disposition': postflight['normal_lifecycle_disposition'],
            'capacity_build_or_campaign_started_by_coordinator': False,
            'original_auditors_reexecuted': False, 'r34_adoption_claimed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--owner-closure-sha256', required=True)
    args = parser.parse_args()
    destination = ROOT / 'preparation.json'
    assert Path(__file__).resolve() == ROOT / 'prepare_qualify.py'
    assert sys.platform == 'linux' and os.getuid() == 1000 and ROOT.resolve() == ROOT
    assert all(not os.path.lexists(ROOT / name) for name in
               ('preparation.json', 'preparation.json.next', 'source', 'qualification-01', 'target-build'))
    report = {'schema': 'hepta-x230-r35-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'R24 plus legacy-read JSON deferral and observation command move; three frozen files only',
              'cache_deletions': 0, 'first_actual_r35_qualification_required': True,
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
        input_binding = input_identity(ROOT / 'qualification-input.json', args.input_sha256)
        closure_binding = input_identity(ROOT / 'cache-owner-closure-inputs.json', args.owner_closure_sha256)
        manifest = json.loads(read_bound(input_binding))
        closure = json.loads(read_bound(closure_binding))
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
        report['source_materialization'] = 'accepted R24 source copy plus the frozen R35 patch; R34 supplies build cache only'
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
        report['process_check'] = inspect_processes(cache)
        assert not report['process_check']['matched_processes'] and not report['process_check']['compiler_processes']
        report['cache_to_transfer'] = str(cache)
        save(destination, report)
        target = ROOT / 'target-build'
        assert not os.path.lexists(target)
        cache_identity = (cache.stat().st_dev, cache.stat().st_ino)
        cache.rename(target)
        assert (target.stat().st_dev, target.stat().st_ino) == cache_identity and not cache.exists()
        report['cache_transferred_by_rename'] = True
        report['new_full_cache_copy_bytes'] = 0
        for name, digest in report['retained_programs'].items():
            assert sha(Path(name)) == digest
        for identity in closure['inputs'].values():
            read_bound(identity)
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
