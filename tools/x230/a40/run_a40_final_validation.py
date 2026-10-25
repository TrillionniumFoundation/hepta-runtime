#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the frozen A40r02 qualification follow-up serially on X230.

The caller provides an existing forwarded SSH agent. This script changes no
installed service, waits for a fresh qualified binary, and never retries a
failed stage. Every output directory is new and all original stage logs remain.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261023')
BASE = ROOT / 'a40-staggered-output-recovery-20261025-r02'
OUT = BASE / 'validation-series-r01'
OUT.mkdir(mode=0o700, exist_ok=False)
REPORT = {
    'schema': 'hepta-a40-final-validation-series/v1',
    'passed': False,
    'phase': 'waiting_qualification',
    'stages': [],
    'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'production_services_changed': False,
    'automatic_retries': False,
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save():
    pending = OUT / 'report.json.next'
    with pending.open('w') as stream:
        json.dump(REPORT, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, OUT / 'report.json')


save()
try:
    deadline = time.monotonic() + 1800
    qualification_path = BASE / 'qualification/report.json'
    while True:
        qualification_bytes = qualification_path.read_bytes()
        qualification = json.loads(qualification_bytes)
        if qualification.get('qualified'):
            break
        if qualification.get('error'):
            raise RuntimeError('qualification failed: ' + qualification['error'])
        if time.monotonic() >= deadline:
            raise RuntimeError('qualification incomplete at original wait deadline')
        time.sleep(5)
    assert qualification['binary']['cached'] is False
    assert qualification['test_binary']['cached'] is False
    assert qualification['source_tested'] == qualification['source_after']
    binary = Path(qualification['binary']['path'])
    expected = qualification['binary']['sha256']
    assert sha(binary) == expected
    REPORT['binary_sha256'] = expected
    REPORT['qualification_sha256'] = hashlib.sha256(qualification_bytes).hexdigest()
    socket_parent = Path('/home/qian/ha40-r1')
    socket_parent.mkdir(mode=0o700, exist_ok=False)
    shared = [
        '--candidate', str(binary),
        '--profile-template', str(ROOT / 'a28-a31-budget-r01-g0/profile/profile.json'),
        '--frozen-jobs', str(ROOT / 'a28-a31-budget-r01-g0/round-0-A/state/jobs'),
        '--socket-parent', str(socket_parent),
    ]
    stages = [
        ('small-archive-abba', 'x230_small_archive_benchmark.py', [
            '--baseline', str(ROOT / 'qualification-a35-large-usage-two-workers-r02/hepta-runtime'),
            '--candidate', str(binary), '--measured', '1024',
        ], BASE / 'small-archive-abba-r01', 300),
        ('inherited-pipe-canary', 'x230_inherited_pipe_canary_a40.py',
         shared + ['--expected-binary-sha256', expected],
         ROOT / 'a40r02-inherited-pipe-native-r01', 300),
        ('six-running-controller-recovery', 'x230_six_running_recovery_canary.py',
         shared, ROOT / 'a40r02-six-running-recovery-r01', 480),
        ('file-pool-abba', 'x230_file_pool_benchmark.py',
         shared + ['--calls', '96', '--concurrency', '1', '4', '8'],
         BASE / 'file-abba-r01', 600),
        ('file-pool-soak', 'x230_file_pool_benchmark.py',
         shared + ['--calls', '96', '--concurrency', '8', '--soak-seconds', '600'],
         BASE / 'file-pool-soak-r01', 900),
        ('file-pool-c16', 'x230_file_pool_benchmark.py',
         shared + ['--calls', '192', '--concurrency', '16', '--soak-seconds', '1'],
         BASE / 'file-pool-c16-r01', 120),
    ]
    REPORT['planned_stages'] = []
    for name, script, arguments, output, timeout in stages:
        argv = ['/usr/bin/python3', str(BASE / 'tools' / script)] + arguments + ['--out', str(output)]
        REPORT['planned_stages'].append({
            'name': name, 'argv': argv, 'output': str(output), 'timeout_seconds': timeout,
            'script_sha256': sha(BASE / 'tools' / script),
        })
    save()
    for stage in REPORT['planned_stages']:
        REPORT['phase'] = stage['name']
        save()
        assert sha(binary) == expected
        started = time.monotonic()
        name = stage['name']
        with (OUT / (name + '.stdout')).open('xb') as stdout, (OUT / (name + '.stderr')).open('xb') as stderr:
            done = subprocess.run(stage['argv'], stdout=stdout, stderr=stderr,
                                  timeout=stage['timeout_seconds'])
        row = {'name': name, 'returncode': done.returncode, 'seconds': time.monotonic() - started}
        for stream in ('stdout', 'stderr'):
            row[stream + '_sha256'] = sha(OUT / (name + '.' + stream))
        report_path = Path(stage['output']) / 'report.json'
        if report_path.is_file():
            raw = report_path.read_bytes()
            result = json.loads(raw)
            row['report_sha256'] = hashlib.sha256(raw).hexdigest()
            row['report_path'] = str(report_path)
            row['report_success'] = result.get('passed', result.get('complete', False))
        REPORT['stages'].append(row)
        save()
        if done.returncode or not row.get('report_success'):
            raise RuntimeError(name + ' failed; original logs and report retained')
    assert sha(binary) == expected
    assert qualification_path.read_bytes() == qualification_bytes
    REPORT['binary_unchanged'] = True
    REPORT['qualification_unchanged'] = True
    REPORT['phase'] = 'complete'
    REPORT['passed'] = True
except Exception as error:
    REPORT['error'] = type(error).__name__ + ': ' + str(error)
    raise
finally:
    REPORT['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    save()
