#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Single, instrumented A26 observation sample; never a throughput comparison."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261023')
ORIGINAL = Path('/home/qian/.local/state/hepta-runtime-native-dev-20261018/goal-20261023-a17-native-observation-r01')
HELPER = ROOT / 'x230_observation_benchmark.py'
BINARY = ROOT / 'qualification-a26-r01/hepta-runtime'
QUALIFICATION = ROOT / 'qualification-a26-r01/report.json'
OUT = ROOT / 'a27-syscall-profile-r01'
EXPECTED_HELPER = 'efdf18dc4ded1193884cc7c529ca652ae22c1d7178e2fd29973463cceffa6db0'
EXPECTED_BINARY = '52b9a64618b46d04f339e4af2ce91450894d65a57a5ba58bdff7f4fc0ecadb0a'
EXPECTED_QUALIFICATION = '6e8ee71968d883b100dff89b96e4c9878c68b45b215487fefbb60fa08aa9c7cf'


def receipt(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise RuntimeError('non-regular or multiply-linked input: ' + str(path))
        data = bytearray()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            data.extend(block)
        def identity(s):
            return (s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_nlink,
                    s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat()):
            raise RuntimeError('input changed: ' + str(path))
        return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    finally:
        os.close(fd)


def interrupted(signum, frame):
    raise RuntimeError('bounded profiler interrupted by signal ' + str(signum))


def main():
    if OUT.exists():
        raise RuntimeError('profile output already exists; no rerun')
    before = {str(p): receipt(p) for p in [HELPER, BINARY, QUALIFICATION, Path(__file__)]}
    for p, expected in [(HELPER, EXPECTED_HELPER), (BINARY, EXPECTED_BINARY),
                        (QUALIFICATION, EXPECTED_QUALIFICATION)]:
        if before[str(p)]['sha256'] != expected:
            raise RuntimeError('qualified input differs: ' + str(p))
    spec = importlib.util.spec_from_file_location('a26_frozen_observation', HELPER)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    OUT.mkdir(mode=0o700)
    strace_version = subprocess.run(['/usr/bin/strace', '--version'], capture_output=True,
                                    text=True, timeout=10, check=False)
    base.create_file(OUT / 'strace-version.stdout', strace_version.stdout.encode())
    base.create_file(OUT / 'strace-version.stderr', strace_version.stderr.encode())
    base.need(strace_version.returncode == 0, 'strace version failed')
    jobs = base.load_jobs(ORIGINAL / 'frozen-originals')
    agent = os.environ.get('SSH_AUTH_SOCK', '')
    base.need(agent.startswith('/'), 'held forwarded agent missing')
    agent_before = base.agent_identity(agent)
    profile, profile_receipt = base.fresh_profile(
        ORIGINAL / 'ssh-profile/profile.json', OUT / 'profile',
        Path('/home/qian/hx230-opt-20261023'), agent)
    fixture = OUT / 'fixture'
    config = base.fixture(fixture, jobs)
    session = fixture / 'session'
    session.mkdir(mode=0o700)
    trace_path = OUT / 'syscall-summary.txt'
    plan = {'schema': 'hepta-x230-syscall-profile-plan/v1', 'binary_sha256': EXPECTED_BINARY,
            'instrumentation': ['strace', '-f', '-qq', '-c', '-S', 'time'],
            'scope': 'one controller lifetime, including startup, 6 preflight reads, '
                     '96 C8 timed observations, 12 final observations, EOF cleanup, '
                     'and its traced local descendants',
            'timing_is_instrumented': True, 'performance_comparison': False,
            'no_user_cpu_attribution': True, 'wrapper_pid_is_not_controller_pid': True,
            'kernel_settings_modified': False, 'effect_starts': 0,
            'automatic_rpc_retries': 0, 'original_jobs': [j['id'] for j in jobs],
            'input_receipts': before, 'profile_receipt': profile_receipt,
            'started_unix': time.time()}
    base.create_file(OUT / 'plan.json', base.canonical(plan))
    report = {'schema': 'hepta-x230-syscall-profile/v1', 'passed': False,
              'performance_comparison': False, 'timing_is_instrumented': True,
              'trace_commands': [], 'started_unix': time.time()}
    real_popen = base.subprocess.Popen

    def traced_popen(argv, *args, **kwargs):
        base.need(argv[0] == str(BINARY) and not report['trace_commands'],
                  'unexpected or second controller launch')
        command = ['/usr/bin/strace', '-f', '-qq', '-c', '-S', 'time',
                   '-o', str(trace_path), '--', *argv]
        report['trace_commands'].append(command)
        return real_popen(command, *args, **kwargs)

    active = None
    base.subprocess.Popen = traced_popen
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(300)
    try:
        active = base.Controller(BINARY, config, profile, session, 2)
        report['startup_wrapper'] = active.startup
        report['preflight'] = [active.call('process_read', j, 'profile_preflight') for j in jobs]
        base.need(all(r['okay'] for r in report['preflight']), 'profile preflight failed')
        report['instrumented_cell'] = base.cell(active, jobs, 8, 96)
        report['final_observations'] = [active.call(tool, j, 'profile_final') for j in jobs
                                        for tool in ['process_status', 'process_read']]
        report['shutdown_wrapper'] = active.close()
        active = None
        end = report['shutdown_wrapper']
        base.need(end['exit_code'] == 0 and end['shutdown_method'] == 'stdin_eof'
                  and end['reader_error'] is None and end['unmatched_responses'] == 0
                  and end['observed_descendant_survivors'] == [], 'profile cleanup failed')
        report['passed'] = (report['instrumented_cell']['successes'] == 96
                            and all(r['okay'] for r in report['final_observations']))
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)[:2000]}
    finally:
        signal.alarm(0)
        if active is not None:
            try:
                report['interrupted_shutdown_wrapper'] = active.close()
            except BaseException as error:
                report['cleanup_error'] = {'type': type(error).__name__, 'message': str(error)[:2000]}
                report['passed'] = False
        base.subprocess.Popen = real_popen
        try:
            report['inputs_after'] = {str(p): receipt(Path(p)) for p in before}
            report['inputs_unchanged'] = report['inputs_after'] == before
            report['originals_unchanged'] = all(base.read_file(j['path'], 65536) == j['record_bytes']
                                                for j in jobs)
            report['private_records_unchanged'] = all(
                base.read_file(fixture / 'state/jobs' / (j['id'] + '.json'), 65536) == j['record_bytes']
                for j in jobs)
            report['agent_unchanged'] = base.agent_identity(agent) == agent_before
            report['trace_receipt'] = receipt(trace_path)
        except BaseException as error:
            report['final_verification_error'] = {'type': type(error).__name__, 'message': str(error)[:2000]}
            report['passed'] = False
        report['passed'] = report['passed'] and all(report.get(k) is True for k in
            ['inputs_unchanged', 'originals_unchanged', 'private_records_unchanged', 'agent_unchanged'])
        report['finished_unix'] = time.time()
        base.save_report(OUT / 'report.json', report)
    print(json.dumps({'report': str(OUT / 'report.json'), 'passed': report['passed'],
                      'error': report.get('error'), 'trace': str(trace_path)}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
