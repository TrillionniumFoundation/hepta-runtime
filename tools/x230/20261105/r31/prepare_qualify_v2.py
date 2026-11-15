#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualify R24 plus the isolated pidfd wait with the unchanged eight-stage tool.

Preparation revision 2 preserves the original failed preflight receipt.
Reuse the completed R30 build cache by rename. Keep all earlier source trees,
qualification executables, reports and raw evidence. No cache is deleted and no
production service is changed.
"""
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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
CACHE_OWNER = Path('/home/qian/hepta-runtime-optimization-20261105-r30')
CARGO_HOME = Path('/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02')
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
ADDED = {'src/mcp/runtime/jobs_cancel_wait_tests.rs',
         'src/mcp/runtime/jobs_cancel_wait_fixture.py'}
CHANGED = ADDED | {'src/mcp/runtime/jobs.rs'}


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


def main():
    report = {'schema': 'hepta-x230-r31-preparation/v2', 'passed': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': BASELINE_COMMIT,
              'proposal': 'R24 plus pidfd cancellation readiness wait only',
              'cache_deletions': 0}
    destination = ROOT / 'preparation-02.json'
    assert not destination.exists() and not (ROOT / 'source').exists()
    try:
        assert os.getuid() == 1000 and ROOT.resolve() == ROOT
        prior_path = ROOT / 'preparation.json'
        assert sha(prior_path) == '0f9ea821eeab65ebc555b9cb30f12188949454ce4d1ce4b3c5a8db8a1cd5f88c'
        prior = json.loads(prior_path.read_bytes())
        assert prior['passed'] is False and prior['error'] == "PermissionError: [Errno 13] Permission denied: '/proc/3766/cwd'"
        assert 'qualification_command' not in prior and 'cache_transferred_by_rename' not in prior
        prior_terminal_path = ROOT / 'preparation-attempt-01-native.json'
        prior_terminal = json.loads(prior_terminal_path.read_bytes())
        assert prior_terminal['job_id'] == '1a1ae1597f5-fc05-5d3e' and prior_terminal['state'] == 'failed' and prior_terminal['exit_code'] == 1
        assert prior_terminal['output_complete'] and prior_terminal['output_durable'] and not prior_terminal['automatic_retry']
        report['prior_preparation_failure'] = {'report_path': str(prior_path), 'report_sha256': sha(prior_path),
            'native_path': str(prior_terminal_path), 'native_sha256': sha(prior_terminal_path),
            'job_id': prior_terminal['job_id'], 'qualification_started': False,
            'reason': prior['error'], 'recovery': 'record exact known nondumpable non-build system helpers; reject unknown opaque processes'}
        manifest = json.loads((ROOT / 'input.json').read_bytes())
        assert manifest['baseline_commit'] == BASELINE_COMMIT
        assert sha(ROOT / 'candidate.patch') == manifest['patch_sha256']
        baseline = source_map(BASE / 'source')
        qualified = json.loads((BASE / 'qualification-01/report.json').read_bytes())
        assert qualified['qualified'] and baseline == qualified['source_tested'] == qualified['source_after']
        assert baseline == manifest['baseline_compile_inputs']
        candidate_expected = manifest['candidate_compile_inputs']
        assert set(baseline) <= set(candidate_expected)
        assert set(candidate_expected) - set(baseline) == ADDED
        changed = {p for p in candidate_expected if candidate_expected[p] != baseline.get(p)}
        assert changed == set(manifest['changed_paths']) == CHANGED

        terminal = json.loads((CACHE_OWNER / 'qualification-terminal-status-01.json').read_bytes())
        assert terminal['job_id'] == '1a1ade0d4f4-fc05-5b52'
        assert terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
        assert terminal['output_complete'] and terminal['output_durable']
        campaign = json.loads((CACHE_OWNER / 'campaign-01/report.json').read_bytes())
        assert campaign.get('finished_utc')
        observations = json.loads((CACHE_OWNER / 'campaign-01/native-observation/report.json').read_bytes())
        assert observations.get('finished_unix') and len(observations['rounds']) == 4
        for row in observations['rounds']:
            for label in ('shutdown', 'restart_shutdown'):
                closed = row[label]
                assert closed['exit_code'] == 0 and closed['shutdown_method'] == 'stdin_eof'
                assert not closed['observed_descendant_survivors'] and closed['reader_error'] is None
                assert closed['transport_capture']['reader_eof'] and closed['unmatched_responses'] == 0
        report['prior_measurement_terminal'] = {
            'campaign_report_sha256': sha(CACHE_OWNER / 'campaign-01/report.json'),
            'observation_report_sha256': sha(CACHE_OWNER / 'campaign-01/native-observation/report.json'),
            'passed': observations['passed'], 'controllers_closed': True}
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
        assert not target.exists()
        cache_inode = cache.stat().st_ino
        cache.rename(target)
        assert target.stat().st_ino == cache_inode and not cache.exists()
        report['cache_transferred_by_rename'] = True
        report['new_full_cache_copy_bytes'] = 0
        for name, digest in report['retained_programs'].items():
            assert sha(Path(name)) == digest
        source = ROOT / 'source'
        shutil.copytree(BASE / 'source', source)
        subprocess.run(['/usr/bin/git', 'apply', '--check', str(ROOT / 'candidate.patch')], cwd=source, check=True)
        subprocess.run(['/usr/bin/git', 'apply', str(ROOT / 'candidate.patch')], cwd=source, check=True)
        candidate = source_map(source)
        assert candidate == candidate_expected
        report['source_before_qualification'] = candidate
        save(destination, report)
        command = ['/usr/bin/python3', '-B', '-u', str(source / 'tools/x230/20261028/qualify.py'),
                   '--source', str(source), '--output', str(ROOT / 'qualification-01'),
                   '--target', str(target), '--cargo-home', str(CARGO_HOME), '--jobs', '2']
        report['qualification_command'] = command
        result = subprocess.run(command, cwd=source)
        report['qualification_returncode'] = result.returncode
        report['source_after_qualification'] = source_map(source)
        report['passed'] = result.returncode == 0
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
