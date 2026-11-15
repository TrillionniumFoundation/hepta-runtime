"""Execute all four native configuration span domains with complete receipts."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
PRODUCERS = ('guard.py', 'semantic.py', 'state.py', 'lease.py', 'run.py')


def pin(path):
    with path.open('rb') as stream:
        return dict(bytes=path.stat().st_size, sha256=hashlib.file_digest(stream, 'sha256').hexdigest())


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def execute_native(manifest, output, *, source_root=ROOT):
    root = Path(source_root).resolve(strict=True)
    manifest = Path(manifest).resolve(strict=True)
    build, output = manifest.parent, Path(output).resolve()
    home = root / 'tests/hia_native/config_span'
    oracle = home / 'guard_original'
    output.mkdir(mode=0o700)
    started = time.monotonic()
    checks = []
    write(output / 'remote-process.json', dict(pid=os.getpid(), parent_pid=os.getppid(),
                                               cwd=str(Path.cwd()), cgroup=Path('/proc/self/cgroup').read_text()))
    built = json.loads(manifest.read_bytes())
    assert built['schema'] == 'hepta.runtime.config-span-build.v1' and built['status'] == 'PASS'
    assert Path(built['source_root']) == root and Path(built['build_root']) == build
    before = {}
    for name, value in built['sources'].items():
        assert pin(Path(name)) == value
        before[name] = value
    for row in built['members']:
        assert pin(Path(row['source']))['sha256'] == row['source_sha256']
        before[row['source']] = pin(Path(row['source']))
    before[str(root / 'native/config_span_sources.json')] = pin(root / 'native/config_span_sources.json')
    for name in PRODUCERS:
        before[str(home / name)] = pin(home / name)
    build_pin = pin(manifest)
    source = dict(schema='hepta.runtime.config-span-native-source.v1', source_root=str(root),
                  build_root=str(build), reference_source_root=str(root), home=str(home),
                  oracle_root=str(oracle), python=sys.executable, files=before, build=build_pin)
    write(output / 'SOURCE.json', source)
    common = ['--build', str(build), '--build-sha256', build_pin['sha256']]
    declarations = [
        ('guard', 'guard.py', ['--oracle', str(oracle)]),
        ('semantic', 'semantic.py', ['--reference-source', str(root), '--loader-source', str(root)]),
        ('state', 'state.py', ['--support', str(home / 'semantic.py'), '--loader-source', str(root)]),
        ('lease', 'lease.py', []),
    ]
    environment = dict(PATH='/usr/bin:/bin', PYTHONDONTWRITEBYTECODE='1')
    try:
        for name, script, extra in declarations:
            command = [sys.executable, '-I', '-B', str(home / script), *common, *extra,
                       '--output', str(output / name)]
            begin = time.monotonic()
            timed = False
            with (output / (name + '.stdout')).open('xb') as stdout, \
                    (output / (name + '.stderr')).open('xb') as stderr:
                process = subprocess.Popen(command, cwd=home, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    code = process.wait(timeout=180)
                except subprocess.TimeoutExpired:
                    timed = True
                    os.killpg(process.pid, signal.SIGKILL)
                    code = process.wait(timeout=3)
            row = dict(name=name, command=command, cwd=str(home), environment=environment, pid=process.pid,
                       timeout_seconds=180, timed_out=timed, exit_code=code,
                       elapsed_seconds=time.monotonic() - begin,
                       stdout=pin(output / (name + '.stdout')), stderr=pin(output / (name + '.stderr')))
            checks.append(row)
            write(output / 'checks.json', checks)
            assert code == 0 and not timed and row['stderr']['bytes'] == 0, (name, 'actual child incomplete')
            summary = json.loads((output / (name + '.stdout')).read_bytes())
            result = json.loads((output / name / 'RESULT.json').read_bytes())
            assert summary['status'] == 'PASS' and all(result[key] == value for key, value in summary.items())
        assert {name: pin(Path(name)) for name in before} == before
        assert pin(manifest) == build_pin
        result = dict(schema='hepta.runtime.config-span-native-capture.v1', status='PASS',
                      actual_test_processes=4, checks=checks, same_source_before_after=True,
                      elapsed_seconds=time.monotonic() - started, build=build_pin,
                      fresh_cold=False, new_rust_processes=0, public_mcp_complete=False,
                      fresh_original_comparison_complete=False)
        write(output / 'RESULT.json', result)
        return result
    except BaseException:
        write(output / 'FAILURE.json', dict(traceback=traceback.format_exc(),
                                            completed_checks=checks, elapsed_seconds=time.monotonic() - started))
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    args = parser.parse_args()
    result = execute_native(args.manifest, args.output, source_root=args.source_root)
    print(json.dumps(result, sort_keys=True, allow_nan=False), flush=True)
