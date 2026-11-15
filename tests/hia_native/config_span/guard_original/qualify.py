"""Record an actual isolated 180-second admission or refusal-control process."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
sys.dont_write_bytecode = True


def pin(path):
    with Path(path).open('rb') as stream:
        return {'bytes': Path(path).stat().st_size, 'sha256': hashlib.file_digest(stream, 'sha256').hexdigest()}


def dump(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False); stream.write('\n')


def main():
    p = argparse.ArgumentParser()
    for name in ('reader', 'source', 'capture', 'output'): p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--test', type=Path)
    a = p.parse_args()
    for name in ('reader', 'source', 'capture', 'output'):
        setattr(a, name, getattr(a, name).absolute())
    if a.test: a.test = a.test.absolute()
    a.output.mkdir(mode=0o700)
    dump(a.output/'remote-process.json', {'pid': os.getpid(), 'cgroup': Path('/proc/self/cgroup').read_text(), 'argv': sys.argv})
    own_sources = [Path(__file__).absolute(), a.reader]+([a.test] if a.test else [])
    source_pins = {str(path): pin(path) for path in own_sources}
    target = a.test or a.reader
    command = [sys.executable, '-I', '-B', str(target), '--source', str(a.source), '--capture', str(a.capture),
               '--output', str(a.output/('controls' if a.test else 'EVIDENCE.json'))]
    if a.test: command += ['--reader', str(a.reader)]
    started = time.monotonic(); timed_out = False; child = None; start_error = None
    stdout_path, stderr_path = a.output/'stdout.bin', a.output/'stderr.bin'
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            child = subprocess.Popen(command, cwd=a.source, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), start_new_session=True)
            try: child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                timed_out = True; os.killpg(child.pid, signal.SIGKILL); child.wait()
        except OSError as error: start_error = repr(error)
    elapsed = time.monotonic()-started
    receipt = {'schema': 'hepta.runtime.directory-move-guard-reference-admission-process.v1',
        'command': command, 'cwd': str(a.source), 'stdin': None, 'pid': child.pid if child else None,
        'timeout_seconds': 180, 'timed_out': timed_out, 'elapsed_seconds': elapsed,
        'exit_code': child.returncode if child else None, 'source_sha256': source_pins,
        'stdout': {'path': str(stdout_path), **pin(stdout_path)}, 'stderr': {'path': str(stderr_path), **pin(stderr_path)},
        'new_rust_processes': 0, 'new_native_calls': 0}
    if start_error is not None: receipt['start_error'] = start_error
    dump(a.output/'process.json', receipt)
    success = child is not None and child.returncode == 0 and not timed_out and start_error is None
    success = success and {str(path): pin(path) for path in own_sources} == source_pins
    actual = a.output/('controls/RESULT.json' if a.test else 'EVIDENCE.json')
    result = {'status': 'PASS' if success else 'FAIL', 'actual_python_processes': 1, 'timeout_seconds': 180,
        'elapsed_seconds': elapsed, 'new_rust_processes': 0, 'new_native_calls': 0,
        'receipt': {'path': str(a.output/'process.json'), **pin(a.output/'process.json')}}
    if actual.is_file(): result['evidence'] = {'path': str(actual), **pin(actual)}
    dump(a.output/'RESULT.json', result); print(json.dumps(result, sort_keys=True))
    if not success: raise SystemExit(1)


if __name__ == '__main__': main()
