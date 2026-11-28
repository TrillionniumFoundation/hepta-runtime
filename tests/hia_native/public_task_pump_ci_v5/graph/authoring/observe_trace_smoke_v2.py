"""Capture an owned stdio process and its fixed FD3/FD4 observations in full."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import signal
import subprocess
import time


def pin(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': path.stat().st_size, 'sha256': digest}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--elf-sha256', required=True)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--trace', action='store_true')
    a = p.parse_args()
    binary = a.binary.resolve(strict=True)
    assert pin(binary)['sha256'] == a.elf_sha256
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    work = out / 'workspace'
    state = out / 'state'
    work.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    config = out / 'runtime.json'
    config.write_text(json.dumps({'state_dir': str(state), 'controller_workspace_roots': [str(work)],
        'hosts': {'owned': {'ssh_target': 'not-contacted-owned-fixture', 'remote_state_dir': '/unused'}}}) + '\n')
    config.chmod(0o600)
    raw = a.input.read_bytes()
    (out / 'stdin.bin').write_bytes(raw)
    journal = os.open(out / 'journal.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    assert journal == 3, 'fixed owned FD3 unavailable; never overwrite another descriptor'
    trace = None
    if a.trace:
        trace = os.open(out / 'trace.bin', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        assert trace == 4, 'fixed owned FD4 unavailable; never overwrite another descriptor'
    command = [str(binary), '--runtime-config', str(config)]
    process = None
    timed_out = False
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(command, cwd=work, env={'PATH': '', 'LC_ALL': 'C'},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(3, 4) if a.trace else (3,), start_new_session=True)
        (out / 'STARTED.json').write_text(json.dumps({'pid': process.pid,
            'pgid': os.getpgid(process.pid), 'command': command, 'cwd': str(work),
            'started_ns': started, 'timeout_seconds': 60,
            'owned_inherited_descriptors': [3, 4] if a.trace else [3]}, indent=2) + '\n')
        try:
            stdout, stderr = process.communicate(raw, timeout=60)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=5)
        (out / 'stdout.bin').write_bytes(stdout)
        (out / 'stderr.bin').write_bytes(stderr)
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if trace is not None:
            os.close(trace)
        os.close(journal)
    receipt = {'schema': 'hepta.runtime.task-pump.engineering-process.v1',
        'pid': process.pid, 'command': command, 'cwd': str(work),
        'elf': pin(binary), 'started_ns': started, 'finished_ns': time.monotonic_ns(),
        'timeout_seconds': 60, 'timed_out': timed_out, 'exit_code': process.returncode,
        'artifacts': {name: pin(out / name) for name in
            ['stdin.bin', 'stdout.bin', 'stderr.bin', 'journal.bin'] + (['trace.bin'] if a.trace else [])},
        'whole_public_domain_qualified': False, 'fresh_ci_qualified': False}
    (out / 'PROCESS.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(receipt), flush=True)
    if process.returncode != 0 or timed_out:
        raise RuntimeError('actual process failed; complete artifacts retained')


if __name__ == '__main__':
    main()
