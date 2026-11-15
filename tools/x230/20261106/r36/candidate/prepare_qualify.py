#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare one R24-derived source and run the original X230 qualifier once."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r36')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def ident(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}


def write_json(path, data):
    raw = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()
    temporary = path.with_name(path.name + '.next')
    with temporary.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def main(bundle):
    expected = bundle['input']
    assert expected['baseline_commit'] == 'baab4def80be7af015b2e7a594cb302f66c4130e'
    assert expected['changed_paths'] == sorted(bundle['candidate_files'])
    assert not ROOT.exists(), 'new root required; never retry an uncertain preparation'
    memory = {row.split(':')[0]: int(row.split()[1]) for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith(('MemAvailable:', 'MemTotal:'))}
    disk = shutil.disk_usage(ROOT.parent)
    assert disk.free >= 10 * 1024**3, 'fresh target requires 10 GiB available, including 3 GiB reserve'
    assert memory['MemAvailable'] >= 3 * 1024**2, 'qualification requires 3 GiB currently available memory'
    activity = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            name = (proc / 'comm').read_text().strip()
            command = (proc / 'cmdline').read_bytes().split(b'\0')
        except (OSError, ValueError):
            continue
        matches = [Path(x.decode(errors='replace')).name for x in command if x.endswith(b'.py') and any(t in x for t in (b'run_native_observation', b'run_lifecycle_abba', b'_campaign.py'))]
        if name in ('cargo', 'rustc', 'rustfmt', 'clippy-driver') or matches:
            activity.append({'pid': int(proc.name), 'comm': name, 'measurement_scripts': matches})
        if name == 'hepta-runtime':
            try:
                executable = os.readlink(proc / 'exe')
                if '/home/qian/hepta-runtime-' in executable:
                    activity.append({'pid': int(proc.name), 'comm': name, 'candidate_executable': executable})
            except OSError:
                pass
    assert not activity, 'existing compiler or measurement is active: ' + json.dumps(activity)
    baseline_report = BASE / 'qualification-01/report.json'
    assert ident(baseline_report)['sha256'] == expected['baseline_qualification']['sha256']
    old = json.loads(baseline_report.read_bytes())
    assert old['qualified'] and old['source_tested'] == old['source_after'] == expected['baseline_compile_inputs']
    source = BASE / 'source'
    for rel, digest in expected['baseline_compile_inputs'].items():
        assert sha((source / rel).read_bytes()) == digest, 'baseline compile input changed: ' + rel
    harness = source / 'tools/x230/20261028'
    for rel, digest in expected['qualification_harness_sha256'].items():
        assert sha((harness / rel).read_bytes()) == digest, 'qualification harness changed: ' + rel
    originals = []
    for path in source.rglob('*'):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'unsupported baseline source entry'
        assert path.name not in ('.git', 'target', 'target-build'), 'unexpected build data in baseline source'
        if stat.S_ISREG(info.st_mode):
            originals.append((path, info))
    assert len(originals) < 2000 and sum(s.st_size for _, s in originals) < 32 * 1024**2
    ROOT.mkdir(mode=0o700)
    (ROOT / 'candidate').mkdir(mode=0o700)
    (ROOT / 'prepare_qualify.py').write_text(bundle['preparer'])
    (ROOT / 'qualification-input.json').write_text(json.dumps(expected, indent=2, sort_keys=True) + '\n')
    (ROOT / 'candidate/candidate.patch').write_text(bundle['patch'])
    shutil.copytree(source, ROOT / 'source', copy_function=shutil.copyfile)
    for rel, body in bundle['candidate_files'].items():
        raw = body.encode()
        assert sha(raw) == expected['candidate_compile_inputs'][rel]
        (ROOT / 'source' / rel).write_bytes(raw)
        saved = ROOT / 'candidate/source' / rel
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(raw)
    for rel, digest in expected['candidate_compile_inputs'].items():
        assert sha((ROOT / 'source' / rel).read_bytes()) == digest, 'candidate freeze mismatch: ' + rel
    argv = ['/usr/bin/python3', '-B', '-u', str(ROOT / 'source/tools/x230/20261028/qualify.py'),
            '--source', str(ROOT / 'source'), '--output', str(ROOT / 'qualification-01'),
            '--target', str(ROOT / 'target-build'), '--cargo-home', '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
            '--jobs', '2', '--stage-timeout', '3600']
    report = {'schema': 'hepta-x230-r36-preparation/v1', 'started_utc': utc(), 'finished_utc': None,
              'passed': False, 'automatic_retries': 0, 'production_services_modified': False,
              'source_baseline': expected['baseline_commit'], 'git_parent': expected['git_parent'],
              'input_binding': ident(ROOT / 'qualification-input.json'),
              'candidate_patch': ident(ROOT / 'candidate/candidate.patch'),
              'preparer': ident(ROOT / 'prepare_qualify.py'), 'qualification_command': argv,
              'target_fresh_before_start': not (ROOT / 'target-build').exists(), 'qualification_started': False,
              'qualification_returncode': None, 'owned_child_closed': False,
              'preflight': {'utc': utc(), 'available_memory_kib': memory['MemAvailable'], 'disk_free_bytes': disk.free,
                            'loadavg': list(os.getloadavg()), 'observed_compilers_and_measurements': activity,
                            'source_files': len(originals), 'source_bytes': sum(s.st_size for _, s in originals)}}
    write_json(ROOT / 'preparation.json', report)
    assert report['target_fresh_before_start']
    print(json.dumps({'state': 'prepared', 'root': str(ROOT), 'input': report['input_binding'], 'preflight': report['preflight']}), flush=True)
    child = None
    try:
        with (ROOT / 'qualification-launch.stdout').open('xb') as stdout, (ROOT / 'qualification-launch.stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=ROOT / 'source', stdout=stdout, stderr=stderr, start_new_session=True)
            report['qualification_started'] = True
            report['qualification_pid'] = child.pid
            write_json(ROOT / 'preparation.json', report)
            try:
                code = child.wait(timeout=6600)
            except subprocess.TimeoutExpired:
                report['timed_out'] = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
                raise
        report['qualification_returncode'] = code
        report['owned_child_closed'] = child.poll() is not None
        report['qualification_report'] = ident(ROOT / 'qualification-01/report.json')
        qualified = json.loads((ROOT / 'qualification-01/report.json').read_bytes())
        actual = qualified.get('source_tested', {})
        report['formatted_source_matches_preparation'] = actual == expected['candidate_compile_inputs']
        report['actual_changed_paths'] = sorted(rel for rel, digest in actual.items() if digest != expected['baseline_compile_inputs'].get(rel))
        report['passed'] = (code == 0 and qualified['qualified']
                            and qualified['source_input'] == expected['candidate_compile_inputs']
                            and qualified['source_after'] == actual
                            and set(actual) == set(expected['candidate_compile_inputs'])
                            and report['actual_changed_paths'] == expected['changed_paths']
                            and qualified['harness_before'] == qualified['harness_after'] == expected['qualification_harness_sha256'])
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'reason': str(error)}
    finally:
        if child is not None and child.poll() is None:
            report['owned_cleanup_requested'] = True
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
            report['qualification_returncode'] = child.returncode
        if child is not None:
            report['owned_child_closed'] = child.poll() is not None
            try:
                os.killpg(child.pid, 0)
                report['owned_group_absent'] = False
                report['passed'] = False
            except ProcessLookupError:
                report['owned_group_absent'] = True
        report['finished_utc'] = utc()
        report['launch_stdout'] = ident(ROOT / 'qualification-launch.stdout')
        report['launch_stderr'] = ident(ROOT / 'qualification-launch.stderr')
        write_json(ROOT / 'preparation.json', report)
        print(json.dumps({'passed': report['passed'], 'qualification_returncode': report['qualification_returncode'], 'root': str(ROOT), 'error': report.get('error')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main(BUNDLE))
