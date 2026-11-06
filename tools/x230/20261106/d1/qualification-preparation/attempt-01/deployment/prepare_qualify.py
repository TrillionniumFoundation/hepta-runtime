#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""First D1 qualification: frozen R24 diagnostics, original eight-stage all-features gates.

R35 supplies its unused build cache after its real rejected lifecycle owners
closed. This preparer neither adopts R35 nor starts any diagnostic measurement.
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

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
CACHE_OWNER = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
HEX = re.compile(r'[0-9a-f]{64}\Z')
DIAGNOSTIC_ENV = ('HEPTA_RUNTIME_PHASE_COST_MODE', 'HEPTA_RUNTIME_PHASE_COST_OUTPUT',
                  'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256')
OWNER_POSTFLIGHT_JOB = '1a1afe8986e-fc05-6ca9'
OWNER_JOBS = {'qualification': '1a1af619097-fc05-6813', 'exact_ci': '1a1af88c330-fc05-696f',
              'observation': '1a1af9bb312-fc05-6a14', 'lifecycle_materialization': '1a1afb8c456-fc05-6b1d',
              'normal_lifecycle': '1a1afc4fb4a-fc05-6b7f'}
OWNER_COUNTS = {'passed': 1645, 'failed': 0, 'ignored': 34, 'selected': 1679, 'retries': 0}
CHANGED = set(['Cargo.toml', 'src/main.rs', 'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/mod.rs', 'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/phase_cost_tests.rs', 'src/mcp/runtime/ssh.rs', 'src/mcp/runtime/ssh_observation_agent_timeout_tests.rs', 'src/mcp/runtime/ssh_observation_maintenance_tests.rs', 'src/mcp/runtime/ssh_observation_pool.rs', 'src/mcp/runtime/ssh_observation_pool_tests.rs', 'src/mcp/runtime/ssh_observation_validation.rs', 'src/mcp/server.rs'])
ADDED = set(['src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/phase_cost_tests.rs'])
NEW_TESTS = set(['concurrent_slot_writers_preserve_every_original_once', 'exhausted_slots_cannot_replace_retained_original_records', 'diagnostic_output_is_create_only_and_refuses_symlink_parent', 'output_byte_limit_preserves_partial_file_without_truncation_or_retry', 'dropping_an_unflushed_diagnostic_sink_does_not_submit_more_bytes', 'context_crosses_only_explicit_task_and_blocking_handoffs'])


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
    assert manifest['schema'] == 'hepta-d1-direct-qualification-input/v1'
    assert manifest['sealed'] is True and manifest['required_missing_bindings'] == []
    assert manifest['baseline_commit'] == manifest['source_construction_parent'] == BASELINE_COMMIT
    assert manifest['published_candidate_commit'] == '5d3fecbeb1d67c288917598f55932e64c878f1e5'
    assert manifest['published_candidate_parent'] == '86155fbf3b89e5a77e2a4aadebd2128c663fe50b'
    assert manifest['candidate_catalog_git_blob'] == 'e100bf52d1b6d4c28113a17bd777c67d98c144e0'
    assert manifest['candidate_input'] == {
        'path': 'candidate/input.json', 'bytes': 53222,
        'sha256': 'd2c45351d8a11a1f472c06e68689c43e8ab821ee3c93428057de401644fb59cc'}
    assert manifest['candidate_manifest'] == {
        'path': 'candidate/package-manifest.json', 'bytes': 10557,
        'sha256': '3f5944705884d1e071f28978fc7ffb911875bf2a93a9c719b2cbe076bbb78fe0'}
    candidate = json.loads(read_bound(relative_identity(manifest['candidate_input'])))
    frozen = json.loads(read_bound(relative_identity(manifest['candidate_manifest'])))
    assert frozen['schema'] == 'hepta-r24-phase-cost-preparation-package/v1'
    assert frozen['revision'] == candidate['revision'] == 'recovery-02'
    assert frozen['baseline_commit'] == BASELINE_COMMIT and frozen['diagnostic_name'] == 'D1'
    assert frozen['performance_acceptance_claim'] is False
    assert frozen['original_qualifier_all_features'] is True and frozen['original_qualifier_changed'] is False
    assert frozen['ordinary_original_package_feature_set'] == []
    assert frozen['candidate_package_feature_set'] == ['phase-cost-diagnostics']
    seen, files = set(), {}
    for identity in frozen['files']:
        name = identity['path']
        assert name not in seen
        seen.add(name)
        files[name] = read_bound(relative_identity({**identity, 'path': 'candidate/' + name}))
    assert len(seen) == frozen['file_count'] == 38
    assert candidate['schema'] == 'hepta-r24-phase-cost-candidate/v1'
    assert candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
    assert candidate['baseline_count'] == 220 and candidate['candidate_count'] == 222
    assert candidate['patch_sha256'] == '3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523'
    assert candidate['patch_bytes'] == 64987 and len(files['candidate.patch']) == candidate['patch_bytes']
    assert set(candidate['changed_paths']) == CHANGED and set(candidate['added_paths']) == ADDED
    assert candidate['nondefault_feature'] == 'phase-cost-diagnostics' and candidate['feature_platform'] == 'linux'
    assert candidate['dependency_changes'] == [] and candidate['release_profile_changes'] == []
    assert candidate['runtime_gate_changes'] == [] and candidate['acceptance_threshold_changes'] == []
    assert candidate['original_remote_python_changed'] is False and candidate['performance_acceptance_claim'] is False
    assert set(candidate['new_test_functions']) == NEW_TESTS
    for field in ('actual_qualification', 'actual_formatted_source_map', 'actual_default_build',
                  'actual_feature_build', 'actual_elf', 'actual_native_jobs', 'actual_measurements'):
        assert candidate[field] is None
    baseline = json.loads(files['baseline-source-map.json'])
    expected = json.loads(files['candidate-source-map.json'])
    assert baseline == candidate['baseline_compile_inputs'] and expected == candidate['candidate_compile_inputs']
    assert len(baseline) == 220 and len(expected) == 222
    assert set(expected) - set(baseline) == ADDED and not set(baseline) - set(expected)
    assert {name for name in expected if expected[name] != baseline.get(name)} == CHANGED
    for name in CHANGED:
        assert hashlib.sha256(files['source/' + name]).hexdigest() == expected[name]
    old_cargo = tomllib.loads((BASE / 'source/Cargo.toml').read_text())
    new_cargo = tomllib.loads(files['source/Cargo.toml'].decode('utf-8'))
    assert old_cargo.get('features', {}) == {} and new_cargo['features'] == {'phase-cost-diagnostics': []}
    assert {k: v for k, v in new_cargo.items() if k != 'features'} == old_cargo
    assert manifest['qualification_rule']['original_all_features'] is True
    assert manifest['qualification_rule']['diagnostic_environment'] == 'absent'
    assert manifest['qualification_rule']['ordinary_supplemental_run_by_this_preparer'] is False
    patch = frozen['candidate_patch']
    assert patch['sha256'] == candidate['patch_sha256'] and patch['bytes'] == candidate['patch_bytes']
    return candidate, relative_identity({**patch, 'path': 'candidate/candidate.patch'})


def native_stream_pages(pages, terminal):
    """Verify original read pages; never replace them with a fabricated single page."""
    assert isinstance(pages, list) and 1 <= len(pages) <= 16
    offsets = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for index, page in enumerate(pages):
        assert page['job_id'] == terminal['job_id'] and page['audit_recorded'] is True
        for name in ('stdout', 'stderr'):
            channel = page[name]
            raw = bytes.fromhex(channel['bytes_hex'])
            total = terminal['log_bytes'][name]['stored']
            assert type(total) is int and 0 <= total <= 256 * 1024
            assert type(channel['offset']) is int and channel['offset'] == offsets[name]
            assert channel['size'] == total and len(raw) <= 16384
            assert channel['next_offset'] == channel['offset'] + len(raw) <= total
            assert channel['text'] == raw.decode('utf-8', errors='replace')
            assert channel['eof'] is (channel['next_offset'] == total)
            # A stream already at EOF may recur as an empty EOF on later calls.
            # A pending stream must make progress, with no gaps or overlaps.
            assert raw or offsets[name] == total
            if index + 1 == len(pages):
                assert channel['eof'] is True
            offsets[name] = channel['next_offset']
            chunks[name].append(raw)
    assert all(offsets[name] == terminal['log_bytes'][name]['stored'] for name in offsets)
    return {name: b''.join(parts) for name, parts in chunks.items()}


def postflight_bytes(report_raw, terminal_raw, page_raws, receipt_identity):
    """Validate actual successful postflight custody without reading any host file."""
    report, terminal = json.loads(report_raw), json.loads(terminal_raw)
    native_terminal(terminal, OWNER_POSTFLIGHT_JOB)
    assert terminal['audit_recorded'] is True
    assert terminal['log_bytes']['stdout'] == {'seen': 46206, 'stored': 46206}
    assert terminal['log_bytes']['stderr'] == {'seen': 0, 'stored': 0}
    assert len(page_raws) == 3
    pages = [json.loads(raw) for raw in page_raws]
    assert [page['stdout']['offset'] for page in pages] == [0, 16384, 32768]
    streams = native_stream_pages(pages, terminal)
    assert streams['stderr'] == b'' and streams['stdout'].endswith(b'\n')
    assert hashlib.sha256(streams['stdout']).hexdigest() == '7820315a573794b9f6789d04ff71283cae1510fffb15d719da886b960a29b0fd'
    rows = streams['stdout'].splitlines()
    assert len(rows) == 1
    original_receipt = {'path': str(CACHE_OWNER / 'lifecycle-owner-postflight-01.json'),
                        'bytes': len(report_raw), 'sha256': hashlib.sha256(report_raw).hexdigest()}
    assert receipt_identity['bytes'] == original_receipt['bytes']
    assert receipt_identity['sha256'] == original_receipt['sha256']
    assert json.loads(rows[0]) == {'receipt': original_receipt, **report}
    assert report['schema'] == 'hepta-r35-rejected-lifecycle-owner-postflight/v1'
    assert report['postflight_job_id_from_supervisor'] == OWNER_POSTFLIGHT_JOB
    assert report['postflight_script'] == {
        'path': str(CACHE_OWNER / 'postflight_r35_lifecycle_owner_01.py'), 'bytes': 46387,
        'sha256': '6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e'}
    assert report['accepted_baseline_commit'] == BASELINE_COMMIT
    assert report['cache_owner'] == str(CACHE_OWNER) and report['cache_path'] == str(CACHE_OWNER / 'target-build')
    for name in ('cache_moved', 'cache_deleted', 'candidate_adopted', 'current_machine_idle_claimed',
                 'tests_benchmarks_or_auditors_reexecuted', 'archive_member_verifier_reexecuted',
                 'original_observation_postflight_modified'):
        assert report[name] is False
    for name in ('future_preparer_must_check_cache_referencing_processes', 'current_source_matches_qualified_map',
                 'qualification_harness_matches_original', 'source_harness_and_retained_programs_rechecked_before_output',
                 'qualification_completed', 'exact_ci_closed', 'observation_workflow_closed', 'observation_gate_passed',
                 'observation_performance_passed', 'lifecycle_materialization_started', 'normal_lifecycle_started',
                 'normal_lifecycle_workflow_closed', 'normal_lifecycle_controllers_closed', 'normal_lifecycle_gate_verified',
                 'lifecycle_archive_whole_file_identity_rechecked'):
        assert report[name] is True
    assert report['compiler_input_count'] == 220 and report['embedded_python_input_count'] == 17
    assert report['qualification_harness_count'] == 19 and report['retained_release_program_count'] == 3
    assert report['qualification_counts'] == report['exact_ci_counts'] == OWNER_COUNTS
    assert report['observation_rejection_reasons'] == [] and report['new_workloads_started'] == 0
    assert report['normal_lifecycle_reported_workflow_passed'] is False
    assert report['normal_lifecycle_reported_adoption_passed'] is False and report['normal_lifecycle_gate_passed'] is False
    assert report['normal_lifecycle_rounds'] == 4 and report['normal_lifecycle_standard_shutdown_count'] == 8
    assert len(report['normal_lifecycle_shutdowns']) == 8
    assert report['normal_lifecycle_required_failed_flags'] == [
        {'comparison': 'concurrent_cancel', 'gate': 'throughput', 'adoption_required': True}]
    fields = {'qualification': 'original_qualification_job_id', 'exact_ci': 'original_exact_ci_job_id',
              'observation': 'original_observation_job_id', 'lifecycle_materialization': 'original_lifecycle_materializer_job_id',
              'normal_lifecycle': 'original_normal_lifecycle_job_id'}
    assert all(report[field] == OWNER_JOBS[name] for name, field in fields.items())
    for name, state, code in (('observation_holder', 'succeeded', 0), ('lifecycle_holder', 'failed', 1)):
        row = report[name]
        key = 'observation' if name == 'observation_holder' else 'normal_lifecycle'
        assert row['job_id'] == OWNER_JOBS[key] and row['state'] == state and row['exit_code'] == code
        assert all(row[field] is True for field in ('complete_native_bytes_verified', 'owned_agent_reaped',
                   'owned_agent_directory_absent', 'owned_agent_socket_absent'))
    assert isinstance(report['originals'], dict) and len(report['originals']) == 150
    for name, identity in report['originals'].items():
        relative = Path(name)
        assert not relative.is_absolute() and '..' not in relative.parts
        assert identity['path'] == str(CACHE_OWNER / relative)
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    return report



def closed_outcomes(rows, names, codes, absent='owned_process_absent', require_passed=True):
    """Check original failed-gate custody without converting rejection to success."""
    assert [row['name'] for row in rows] == names and len(rows) == len(codes)
    for row, code in zip(rows, codes):
        assert row['returncode'] == code
        if require_passed:
            assert row['passed'] is (code == 0)
        assert row['waited_and_reaped'] is True and row[absent] is True
        assert row['owned_process_group_absent'] is True and row.get('timed_out', False) is False


def cache_owner_closed(value, harness):
    assert value['schema'] == 'hepta-d1-r35-cache-owner-closure/v1'
    assert value['cache_owner'] == str(CACHE_OWNER) and value['cache_path'] == str(CACHE_OWNER / 'target-build')
    assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert value['closure_is_not_performance_adoption'] is True
    assert value['r35_observation_performance_passed'] is True
    assert value['r35_normal_lifecycle_executed'] is True and value['r35_normal_lifecycle_adopted'] is False
    bindings = value['postflight']
    assert bindings['job_id'] == OWNER_POSTFLIGHT_JOB
    assert bindings['report']['path'] == str(CACHE_OWNER / 'lifecycle-owner-postflight-01.json')
    assert bindings['native']['path'] == str(CACHE_OWNER / 'lifecycle-owner-postflight-native-01.json')
    assert [row['path'] for row in bindings['read_pages']] == [
        str(CACHE_OWNER / ('lifecycle-owner-postflight-read-01-%03d.json' % number)) for number in range(3)]
    postflight = postflight_bytes(read_bound(bindings['report']), read_bound(bindings['native']),
                                 [read_bound(row) for row in bindings['read_pages']], bindings['report'])
    read_bound(postflight['postflight_script'])
    assert postflight['qualification_harness_sha256'] == harness
    assert value['inputs'] == postflight['originals']
    # The 150 original artifacts include the failed LC receipts and their
    # original logs. Recheck their bytes; never rerun a benchmark or auditor.
    originals = {name: read_bound(identity) for name, identity in value['inputs'].items()}
    def receipt(name):
        return json.loads(originals[name])

    qualified = receipt('qualification-01/report.json')
    completed_qualification(qualified, CACHE_OWNER / 'source', harness)
    assert qualified['source_tested'] == receipt('qualification-01/source-map.json')
    assert len(qualified['source_tested']) == 220
    assert sum(name.endswith('.py') for name in qualified['source_tested']) == 17
    preparation = receipt('preparation.json')
    assert preparation['schema'] == 'hepta-x230-r35-preparation/v1'
    assert preparation['passed'] is True and preparation['qualification_started'] is True
    assert preparation['qualification_returncode'] == 0 and preparation['automatic_retries'] == 0
    assert preparation['production_services_modified'] is False
    assert preparation.get('finished_utc') and not preparation.get('error')
    assert preparation['source_baseline'] == BASELINE_COMMIT
    assert preparation['source_before_qualification'] == qualified['source_input']
    assert preparation['source_after_qualification'] == qualified['source_tested']
    assert preparation['qualification_report_sha256'] == value['inputs']['qualification-01/report.json']['sha256']
    qnative = receipt('qualification-terminal-status-01.json')
    native_terminal(qnative, OWNER_JOBS['qualification'])
    assert native_streams(receipt('qualification-native-read-01.json'), qnative)['stderr'] == b''
    summary = receipt('qualification-01/isolated-tests/summary.json')
    assert summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
    assert summary['enumeration_errors'] == [] and {key: summary[key] for key in OWNER_COUNTS} == OWNER_COUNTS

    cinative = receipt('rust-ci-native-01.json')
    native_terminal(cinative, OWNER_JOBS['exact_ci'])
    assert native_streams(receipt('rust-ci-native-read-01.json'), cinative)['stderr'] == b''
    ci = receipt('rust-ci-01/report.json')
    assert ci['schema'] == 'hepta-r35-external-rust-ci/v1' and ci['passed'] is True
    assert ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
    assert ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
    assert ci['original_qualification_job_id'] == OWNER_JOBS['qualification']
    closed_stages(ci['stages'], ['cargo-version', 'rustc-version', 'nextest-version',
                                'cargo-check', 'nextest-list', 'nextest-run'])
    ciaudit = receipt('rust-ci-01/nextest-output-audit.json')
    assert ci['nextest_output_audit'] == ciaudit and ciaudit['verified'] is True
    assert {key: ciaudit[key] for key in OWNER_COUNTS} == OWNER_COUNTS

    for prefix, job, state, code in (
        ('observation', OWNER_JOBS['observation'], 'succeeded', 0),
        ('lifecycle', OWNER_JOBS['normal_lifecycle'], 'failed', 1),
    ):
        terminal = receipt(prefix + '-holder-native-01.json')
        native_terminal(terminal, job, state, code)
        streams = native_streams(receipt(prefix + '-holder-read-01.json'), terminal)
        assert streams['stderr'] == b''
        rows = [json.loads(row) for row in streams['stdout'].splitlines()]
        assert len(rows) == 2 and rows[0]['phase'] == 'owned_agent_ready' and rows[0]['identity_count'] == 5
        assert rows[1]['passed'] is (code == 0) and rows[1]['remote_returncode'] == code
        assert rows[1]['owned_agent_reaped'] is True
        holder = receipt(prefix + '-holder-report-01.json')
        assert holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1'
        assert holder['passed'] is (code == 0) and holder['remote_returncode'] == code
        assert holder.get('finished_utc')
        assert holder['owned_agent_reaped'] is True and holder['owned_agent_directory_absent_after_context'] is True
        assert holder['owned_agent_socket_absent_after_context'] is True
        assert holder['automatic_ssh_retries'] == 0 and holder['services_modified'] is False
        directory = 'campaign-01' if prefix == 'observation' else 'lifecycle-campaign-01'
        parent = receipt(directory + '/report.json')
        assert holder['remote_script_sha256'] == rows[0]['remote_script_sha256'] == parent['launcher_sha256']
        assert parent['source_inputs_unchanged'] is True and parent['baseline_source_inputs_unchanged'] is True
        assert parent['inputs_unchanged'] is True and parent['measurement_attribution_valid'] is True
        monitor = receipt(directory + '/compiler-monitor.audit.json')
        assert parent['compiler_monitor']['passed'] is True
        assert parent['compiler_monitor']['independent_audit'] == value['inputs'][directory + '/compiler-monitor.audit.json']
        assert monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1'
        assert monitor['monitor_sources_unchanged'] is True and monitor['source_recheck_errors'] == []
        assert monitor['validation']['passed'] is True and monitor['validation']['errors'] == []
        assert monitor['ledger'] == parent['compiler_monitor']['ledger']

    obs = receipt('campaign-01/report.json')
    assert obs['schema'] == 'hepta-r25-observation-campaign-control/v1'
    assert obs['passed'] is True and obs.get('finished_utc') and not obs.get('error')
    assert obs['observation_gate_passed'] is True and obs['rejection_reasons'] == []
    assert obs['correctness_stages_completed'] is True
    closed_stages(obs['stages'], ['native-observation', 'native-audit', 'native-boundary',
                                 'boundary-audit', 'cancel-recovery', 'recovery-audit', 'observation-summary'])
    obs_gates = receipt('campaign-01/summary.json')
    assert obs_gates['schema'] == 'hepta-r25-observation-gates/v1'
    assert all(obs_gates[key] is True for key in ('correctness_verified', 'evidence_verified',
                                                'observation_gate_passed', 'performance_gates_passed'))
    assert obs_gates['rejection_reasons'] == []
    obs_raw = receipt('campaign-01/native-observation/report.json')
    obs_audit = receipt('campaign-01/native-observation/independent-summary.json')
    assert obs_raw['passed'] is True and [row['version'] for row in obs_raw['rounds']] == list('ABBA')
    assert obs_audit['verified'] is True and obs_audit['original_sha256'] == value['inputs']['campaign-01/native-observation/report.json']['sha256']
    assert obs_audit['failed_calls'] == 0 and obs_audit['measured_calls'] == 2304

    materialized = receipt('lifecycle-materialization-native-01.json')
    native_terminal(materialized, OWNER_JOBS['lifecycle_materialization'])
    assert native_streams(receipt('lifecycle-materialization-read-01.json'), materialized)['stderr'] == b''
    lc = receipt('lifecycle-campaign-01/report.json')
    assert lc['schema'] == 'hepta-r35-normal-lifecycle-campaign-control/v1'
    assert lc['passed'] is False and lc['adoption_passed'] is False and lc.get('finished_utc') and lc.get('error')
    assert lc['automatic_retries'] == 0 and lc['production_services_modified'] is False
    assert not lc.get('finalization_error') and lc['open_blockers'] == []
    closed_outcomes(lc['stages'], ['lifecycle-tool-tests', 'normal-lifecycle-abba'], [0, 1])
    normal = receipt('lifecycle-abba-01/report.json')
    assert normal['schema'] == 'hepta-r25-lifecycle-abba-control/v1'
    assert normal['passed'] is False and normal['order'] == 'ABBA' and normal['automatic_retries'] == 0
    assert normal['inputs_unchanged'] is True and normal.get('finished_realtime_ns')
    closed_outcomes(normal['stages'], ['canary-0-A', 'audit-0-A', 'canary-1-B', 'audit-1-B',
        'canary-2-B', 'audit-2-B', 'canary-3-A', 'audit-3-A', 'summary', 'normal-lifecycle-gates'],
        [0] * 9 + [1], 'proc_absent', require_passed=False)
    index = receipt('lifecycle-abba-01/round-index.json')
    assert index['schema'] == 'hepta-r25-lifecycle-round-index/v1' and index['closed'] is True
    assert index['order'] == 'ABBA' and index['round_count'] == len(index['rounds']) == 4
    assert index['rounds'] == normal['rounds'] and index['automatic_retries'] == 0
    gates = receipt('lifecycle-abba-01/gates.json')
    assert gates['schema'] == 'hepta-r25-lifecycle-gates/v1' and gates['verified'] is True and gates['passed'] is False
    assert gates['normal_lifecycle_descriptive_verified'] is True and gates['automatic_retries'] == 0
    failed = [{'comparison': name, 'gate': gate, 'adoption_required': row['adoption_required']}
              for name, row in gates['comparisons'].items() for gate, passed in row['gates'].items() if passed is False]
    assert failed == postflight['normal_lifecycle_all_reported_false_flags']
    assert [row for row in failed if row['adoption_required'] is True] == postflight['normal_lifecycle_required_failed_flags']
    for number, arm in enumerate('ABBA'):
        directory = 'lifecycle-abba-01/round-%d-%s' % (number, arm)
        report, audit = receipt(directory + '/report.json'), receipt(directory + '/independent-summary.json')
        assert report['passed'] is True and report['automatic_rpc_retries'] == 0 and audit['verified'] is True
        assert audit['source_sha256'] == value['inputs'][directory + '/report.json']['sha256']
        for key in ('shutdown', 'after_cancel_shutdown'):
            row = report[key]
            assert row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
            assert row['observed_descendant_survivors'] == [] and row['reader_error'] is None
            assert row['transport_capture']['reader_eof'] is True and row['unmatched_responses'] == 0
            assert row.get('resources', {}).get('sampler_error') is None
    cache = CACHE_OWNER / 'target-build'
    assert (cache.stat().st_dev, cache.stat().st_ino) == (postflight['cache_directory_identity']['device'],
                                                     postflight['cache_directory_identity']['inode'])
    for name, identity in postflight['retained_release_programs'].items():
        assert identity['path'] == qualified['binaries'][name]['path']
        assert identity['sha256'] == qualified['binaries'][name]['sha256']
        read_bound(identity, 16 * 1024 * 1024)
    return {'inputs': value['inputs'], 'postflight': bindings,
            'qualification_and_exact_ci_succeeded': True, 'observation_performance_passed': True,
            'normal_lifecycle_executed': True, 'normal_lifecycle_workflow_closed': True,
            'normal_lifecycle_controllers_closed': True, 'normal_lifecycle_performance_passed': False,
            'original_required_failed_flags': postflight['normal_lifecycle_required_failed_flags'],
            'owned_agents_reaped': True, 'original_auditors_reexecuted': False, 'r35_adoption_claimed': False}



def ready_inputs(manifest, closure):
    """Unsealed future identities stop before the first create/rename/copy."""
    assert manifest['schema'] == 'hepta-d1-direct-qualification-input/v1'
    assert closure['schema'] == 'hepta-d1-r35-cache-owner-closure/v1'
    for value in (manifest, closure):
        assert value['sealed'] is True and value['required_missing_bindings'] == []
    assert HEX.fullmatch(manifest['owner_closure_input_sha256'])
    assert manifest['preparation_tool']['path'] == 'prepare_qualify.py'
    assert type(manifest['preparation_tool']['bytes']) is int and HEX.fullmatch(manifest['preparation_tool']['sha256'])
    postflight = closure['postflight']
    assert postflight['job_id'] == OWNER_POSTFLIGHT_JOB
    assert isinstance(postflight['read_pages'], list) and len(postflight['read_pages']) == 3
    assert isinstance(closure['inputs'], dict) and len(closure['inputs']) == 150
    for identity in [postflight['report'], postflight['native'], *postflight['read_pages'], *closure['inputs'].values()]:
        assert isinstance(identity, dict) and Path(identity['path']).is_absolute()
        assert type(identity['bytes']) is int and 0 <= identity['bytes'] <= 8 * 1024 * 1024
        assert HEX.fullmatch(identity['sha256'])
    # Future D1 results are not part of sealing preparation inputs.
    assert manifest['actual_d1_qualification'] is None and manifest['actual_d1_formatted_map'] is None
    assert manifest['actual_d1_test_counts'] is None and manifest['actual_d1_release_programs'] is None


def publication_provenance(manifest):
    identity = manifest['publication_provenance']
    assert identity == {'path': 'provenance/source-anchor-and-publication-parent.json', 'bytes': 2400,
                        'sha256': '99d1e7c4faef98fd680aa7136c3d73e163ca3f64e15f75a1704a6394c8c1fd34'}
    value = json.loads(read_bound(relative_identity(identity)))
    assert value['schema'] == 'hepta-d1-source-anchor-and-publication-parent/v1'
    assert value['source_construction_anchor'] == BASELINE_COMMIT
    assert value['actual_git_parent'] == value['published_candidate_parent_sha'] == manifest['published_candidate_parent']
    assert value['published_candidate_commit'] == manifest['published_candidate_commit']
    rows = value['compiler_input_root_bindings']
    assert [row['path'] for row in rows] == ['src', 'examples', 'Cargo.toml', 'Cargo.lock', 'rustfmt.toml']
    assert all(row['identical'] is True and row['source_anchor_sha'] == row['actual_git_parent_sha'] for row in rows)
    assert value['complete_baseline_compiler_input_map'] == {'files': 220, 'bytes': 24156,
        'sha256': 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'}
    return relative_identity(identity)


def recheck_owner_inputs(closure):
    for identity in closure['inputs'].values():
        read_bound(identity)
    postflight = closure['postflight']
    for identity in (postflight['report'], postflight['native'], *postflight['read_pages']):
        read_bound(identity)


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
    report = {'schema': 'hepta-x230-d1-preparation/v1', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'R24 plus opt-in bounded D1 phase-cost diagnostics; thirteen frozen paths, two additions',
              'diagnostic_name': 'D1', 'performance_acceptance_claim': False,
              'cache_deletions': 0, 'first_actual_d1_qualification_required': True,
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
        report['publication_provenance'] = publication_provenance(manifest)
        report['frozen_candidate_input'] = relative_identity(manifest['candidate_input'])
        report['frozen_candidate_manifest'] = relative_identity(manifest['candidate_manifest'])
        report['candidate_patch'] = patch_binding
        report['source_materialization'] = 'accepted R24 source copy plus frozen recovery-02 D1 patch; R35 supplies only closed build cache'
        harness = {p.name: sha(p) for p in sorted((BASE / 'source/tools/x230/20261028').glob('*.py'))}
        assert len(harness) == 19 and harness == manifest['qualification_harness_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads(read_bound(manifest['baseline_qualification']))
        completed_qualification(qualified, BASE / 'source', harness)
        assert baseline == qualified['source_tested'] == candidate_input['baseline_compile_inputs']
        candidate_expected = candidate_input['candidate_compile_inputs']
        assert len(baseline) == 220 and len(candidate_expected) == 222
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
