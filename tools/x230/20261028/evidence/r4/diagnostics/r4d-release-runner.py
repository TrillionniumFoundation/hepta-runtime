#!/usr/bin/env python3
"""Build one immutable R4d release diagnostic; this is not qualification."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261028')
SOURCE = ROOT / 'source-r4d'
OUT = ROOT / 'diagnostic-r4d-release'
TARGET = ROOT / 'target-r4'
HARNESS = SOURCE / 'tools/x230/20261028'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main():
    OUT.mkdir(mode=0o700, exist_ok=False)
    spec = importlib.util.spec_from_file_location('retained_qualification', HARNESS / 'qualify.py')
    qualify = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(qualify)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(('HEPTA_', 'SSH_', 'RUST_TEST_')) or key in {
            'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'RUSTC_WRAPPER',
            'RUSTC_WORKSPACE_WRAPPER', 'PYTHONPATH', 'PYTHONHOME', 'RUST_LOG',
        }:
            env.pop(key)
    env.update({
        'PATH': '/home/qian/.cargo/bin:/usr/local/bin:/usr/bin:/bin',
        'CARGO_HOME': '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
        'CARGO_TARGET_DIR': str(TARGET), 'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
        'CARGO_PROFILE_DEV_DEBUG': '0', 'CARGO_PROFILE_TEST_DEBUG': '0',
        'RUST_TEST_THREADS': '1', 'TOKIO_WORKER_THREADS': '2',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
    })
    report = {
        'schema': 'hepta-x230-release-diagnostic/v1', 'variant': 'R4d',
        'qualified': False, 'built': False,
        'purpose': 'Early denied-SSH MCP performance diagnosis; full qualification remains required.',
        'source': str(SOURCE), 'started_utc': utc(), 'stages': [],
        'source_input': qualify.source_map(SOURCE),
        'harness_before': {p.name: sha(p) for p in sorted(HARNESS.glob('*.py'))},
        'automatic_retries': 0, 'service_changes': False,
        'runner_sha256': sha(Path(__file__)),
    }
    def save():
        temporary = OUT / 'report.next'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        os.replace(temporary, OUT / 'report.json')
    def stage(name, command):
        row = {'name': name, 'command': command, 'returncode': None, 'timed_out': False}
        report['stages'].append(row)
        report['current_stage'] = name
        save()
        print(json.dumps({'stage': name, 'state': 'started'}), flush=True)
        started = time.monotonic()
        stdout_path, stderr_path = OUT / (name + '.stdout'), OUT / (name + '.stderr')
        with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
            child = subprocess.Popen(command, cwd=SOURCE, env=env, stdout=stdout,
                                     stderr=stderr, start_new_session=True)
            row['original_pid'] = child.pid
            try:
                row['returncode'] = child.wait(timeout=2700)
            except subprocess.TimeoutExpired:
                row['timed_out'] = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=15)
                row['returncode'] = child.returncode
            finally:
                row['seconds'] = time.monotonic() - started
                row['original_child_reaped'] = child.poll() is not None
        row['stdout_sha256'], row['stderr_sha256'] = sha(stdout_path), sha(stderr_path)
        save()
        print(json.dumps({'stage': name, 'exit': row['returncode'], 'seconds': row['seconds']}), flush=True)
        if row['returncode'] != 0 or row['timed_out'] or not row['original_child_reaped']:
            raise RuntimeError(name + ' failed; original output is retained')
    cargo = ['/home/qian/.cargo/bin/cargo', '+1.95.0']
    try:
        stage('format', cargo + ['fmt', '--all'])
        stage('fmt-check', cargo + ['fmt', '--all', '--', '--check'])
        report['source_built'] = qualify.source_map(SOURCE)
        (OUT / 'source-map.json').write_text(json.dumps(report['source_built'], indent=2) + '\n')
        stage('release', cargo + ['build', '--offline', '--locked', '--all-features',
                                  '--release', '--bins', '--examples'])
        original = TARGET / 'release/hepta-runtime'
        copied = OUT / 'hepta-runtime'
        original_sha = sha(original)
        shutil.copy2(original, copied)
        if original_sha != sha(copied) or original_sha != sha(original):
            raise RuntimeError('release binary changed during retention')
        report['binary'] = {'path': str(copied), 'sha256': original_sha}
        report['source_after'] = qualify.source_map(SOURCE)
        report['harness_after'] = {p.name: sha(p) for p in sorted(HARNESS.glob('*.py'))}
        if report['source_after'] != report['source_built']:
            raise RuntimeError('compiler inputs changed during release build')
        if report['harness_after'] != report['harness_before']:
            raise RuntimeError('harness changed during release build')
        report['source_map_sha256'] = sha(OUT / 'source-map.json')
        report['built'] = True
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'reason': str(error)}
    finally:
        report['finished_utc'] = utc()
        save()
        print(json.dumps({'built': report['built'], 'qualified': False,
                          'report': str(OUT / 'report.json'), 'report_sha256': sha(OUT / 'report.json'),
                          'binary': report.get('binary'), 'source_map_sha256': report.get('source_map_sha256'),
                          'error': report.get('error')}), flush=True)
    return 0 if report['built'] else 1

if __name__ == '__main__':
    sys.exit(main())
