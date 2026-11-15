#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One Linux /proc permission fixture, confined to its own original child."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from resource_sampler import Resources

OUT = Path('/home/qian/hepta-runtime-optimization-20261023/a27-resource-sampler-native-r01')
CHILD = '''import ctypes, os, sys
hold = bytearray(8 * 1024 * 1024)
if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE fixture failed")
print("ready", flush=True)
if sys.stdin.readline() != "exit\\n":
    raise SystemExit(7)
print(len(hold), flush=True)
'''


def save_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def main():
    OUT.mkdir(mode=0o700)
    files = [Path(__file__), Path(__file__).with_name('resource_sampler.py'),
             Path(__file__).with_name('resource_sampler_tests.py')]
    before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    report = {'schema': 'hepta-x230-resource-sampler-native-check/v1', 'passed': False,
              'source_before': before, 'runtime_modified': False,
              'kernel_settings_modified': False, 'owned_child_dumpable_temporarily_disabled': True,
              'started_unix': time.time()}
    child = None
    sampler = None
    try:
        tests = subprocess.run([sys.executable, str(files[2])], capture_output=True, timeout=60)
        save_new(OUT / 'unit-tests.stdout', tests.stdout)
        save_new(OUT / 'unit-tests.stderr', tests.stderr)
        report['unit_test_returncode'] = tests.returncode
        if tests.returncode:
            raise RuntimeError('sampler deterministic unit tests failed')
        child = subprocess.Popen([sys.executable, '-I', '-S', '-c', CHILD],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, text=True)
        if not select.select([child.stdout], [], [], 5)[0] or child.stdout.readline() != 'ready\n':
            raise RuntimeError('owned permission fixture failed to start')
        sampler = Resources(os.getpid(), OUT / 'errors.jsonl', start=False)
        child_birth = sampler.proc.stat(child.pid)[0]
        for _ in range(5):
            if child.poll() is not None:
                raise RuntimeError('owned fixture ended before samples')
            sampler.sample_once()
        report['resources'] = sampler.stop()
        errors = [json.loads(line) for line in (OUT / 'errors.jsonl').read_text().splitlines()]
        report['owned_child_observed'] = (child.pid, child_birth) in sampler.seen
        report['owned_child_fd_permission_errors'] = sum(
            row['pid'] == child.pid and row['birth_ticks'] == child_birth
            and row['stage'] == 'fd' and row['error_type'] == 'PermissionError' for row in errors)
        report['all_error_rows_preserved'] = len(errors) == report['resources']['error_count']
        child.stdin.write('exit\n')
        child.stdin.flush()
        stdout, stderr = child.communicate(timeout=5)
        report['child_exit_code'] = child.returncode
        report['child_output_matches'] = stdout == '8388608\n' and stderr == ''
        coverage = report['resources']['field_coverage']
        report['passed'] = (report['owned_child_observed']
            and report['owned_child_fd_permission_errors'] == 5
            and report['all_error_rows_preserved']
            and coverage.get('status_process_samples') == 10
            and coverage.get('fd_process_samples') == 5
            and report['resources']['error_log_finalized']
            and report['resources']['error_log_failure'] is None
            and report['resources']['sampler_thread_stopped']
            and report['child_exit_code'] == 0 and report['child_output_matches'])
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)[:1000]}
    finally:
        report['cleanup_errors'] = []
        if sampler is not None:
            try:
                report['final_resources'] = sampler.stop()
            except BaseException as error:
                report['cleanup_errors'].append({'stage': 'sampler_stop',
                    'type': type(error).__name__, 'message': str(error)[:1000]})
        if child is not None:
            try:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                    report['cleanup_killed_owned_child'] = True
                report['owned_child_reaped'] = child.poll() is not None
            except BaseException as error:
                report['owned_child_reaped'] = False
                report['cleanup_errors'].append({'stage': 'owned_child_reap',
                    'type': type(error).__name__, 'message': str(error)[:1000]})
            for stream in [child.stdin, child.stdout, child.stderr]:
                try:
                    stream.close()
                except BaseException as error:
                    report['cleanup_errors'].append({'stage': 'owned_pipe_close',
                        'type': type(error).__name__, 'message': str(error)[:1000]})
        try:
            report['source_after'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
            report['sources_unchanged'] = report['source_after'] == before
        except BaseException as error:
            report['sources_unchanged'] = False
            report['final_source_error'] = {'type': type(error).__name__, 'message': str(error)[:1000]}
        report['passed'] = report['passed'] and report['sources_unchanged'] and not report['cleanup_errors']
        report['finished_unix'] = time.time()
        save_new(OUT / 'report.json', (json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({'report': str(OUT / 'report.json'), 'passed': report['passed'],
                      'error': report.get('error')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
