# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual original/native syscall faults and post-death staging recovery."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from result_fs_record_io import setup, snapshot, parse
from result_record_io_fault_cases import cases
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def framed(rows):
    return b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw) for raw in rows)


def launch(command, wire, directory, expected, *, umask=0o077):
    directory.mkdir(mode=0o700)
    (directory / 'stdin.bin').write_bytes(wire)
    started = time.monotonic();timed = False
    process = subprocess.Popen([str(x) for x in command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=dict(os.environ, PATH=''), umask=umask)
    try:stdout, stderr = process.communicate(wire, timeout=20)
    except subprocess.TimeoutExpired:
        timed = True;process.kill();stdout, stderr = process.communicate()
    (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
    receipt = dict(command=[str(x) for x in command], pid=process.pid, exit_code=process.returncode,
        expected_exit_code=expected, reaped=True, timed_out=timed, timeout_seconds=20,
        elapsed_seconds=time.monotonic() - started, stdin_bytes=len(wire), stdin_sha256=SHA(wire),
        stdout_bytes=len(stdout), stdout_sha256=SHA(stdout), stderr_bytes=len(stderr), stderr_sha256=SHA(stderr),
        path_environment_empty=True)
    (directory / 'process.json').write_bytes(ENCODE(receipt))
    assert not timed and process.returncode == expected and not stderr, receipt
    return receipt, stdout


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before, identities = snapshot(root);pins = []
    def pin(values):
        for name, identity in values.items():
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            stat = os.fstat(fd);assert (stat.st_dev, stat.st_ino) == identity
            pins.append((fd, identity))
    try:
        pin(identities)
        config = directory / 'config.json';config.write_bytes(ENCODE(row['supervisor']))
        log = directory / 'kernel.json'
        command = [sys.executable, '-I', '-B', HERE / 'result_record_io_supervisor.py', '--fixture', root,
            '--config', config, '--log', log, '--timeout', '10', '--', executable, root]
        killed = 'recovery' in row
        receipt, stdout = launch(command, framed(row['operations']), directory / 'observed', 137 if killed else 0)
        observer = json.loads(log.read_bytes());assert observer['status'] == 'PASS'
        assert observer['all_selected_faults_reached'] and observer['child_reaped']
        assert observer['exit_code'] == (-9 if killed else 0)
        after, following = snapshot(root, identities)
        responses = parse(stdout)
        assert len(responses) == (0 if killed else len(row['operations']))
        if 'file_size_limit' in row['supervisor']:
            limit = row['supervisor']['file_size_limit']
            writes = [e for e in observer['events'] if e['kind'] == 'write_temporary']
            assert len(writes) == 2 and writes[0]['file_bytes_before_kernel_write'] == 0
            assert writes[1]['file_bytes_before_kernel_write'] == limit
            from result_record_io_cases import record, encoded
            assert writes[1]['file_sha256_before_kernel_write'] == SHA(encoded(record())[:limit])
            assert responses[0]['diagnostic'] == 23 and responses[0]['errno'] == 27
        result = dict(before=before, after=after, responses=responses, process=receipt,
            kernel_observer=observer, original_inodes_held_through_observation=True)
        outputs = [stdout]
        if killed:
            pin(following)
            recovery, data = launch([executable, root], framed(row['recovery']), directory / 'recovery', 0)
            final, _ = snapshot(root, following)
            answer = parse(data);assert len(answer) == len(row['recovery'])
            result.update(recovery_process=recovery, recovery_responses=answer, recovery_after=final)
            outputs.append(data)
        for fd, identity in pins:
            stat = os.fstat(fd);assert (stat.st_dev, stat.st_ino) == identity
        (directory / 'observation.json').write_bytes(ENCODE(result))
        return result, outputs
    finally:
        for fd, _ in pins:os.close(fd)
