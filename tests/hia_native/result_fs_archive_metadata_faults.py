# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare original and native archive metadata reads under owned syscall faults."""
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
from result_fs_record_io import setup, snapshot
from result_archive_metadata_fault_cases import cases
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def parse(raw):
    cursor = 0;result = []
    while cursor < len(raw):
        size = struct.unpack_from('<I', raw, cursor)[0];cursor += 4
        assert 64 <= size <= 262144 and cursor + size <= len(raw)
        body = raw[cursor:cursor + size];cursor += size
        magic, diagnostic, error, operation, present, length, digest, cached = struct.unpack_from('<8s7Q', body)
        assert magic == b'HRAMR001' and diagnostic != 255 and size == 64 + length + digest
        result.append(dict(diagnostic=diagnostic, errno=error, operation=operation, present=present,
            projection_bytes=length, digest_bytes=digest, cached_entries=cached, response_sha256=SHA(body)))
    return result


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before, identities = snapshot(root);pins = []
    try:
        for name, identity in identities.items():
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
            pins.append((fd, identity))
        config = directory / 'config.json';config.write_bytes(ENCODE(row['supervisor']))
        log = directory / 'kernel.json'
        command = [sys.executable, '-I', '-B', str(HERE / 'result_archive_metadata_supervisor.py'),
            '--fixture', str(root), '--config', str(config), '--log', str(log), '--timeout', '10',
            '--', str(executable), str(root)]
        wire = b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw) for raw in row['operations'])
        (directory / 'stdin.bin').write_bytes(wire);start = time.monotonic();timed = False
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=dict(os.environ, PATH=''), umask=0o077)
        try:stdout, stderr = process.communicate(wire, timeout=20)
        except subprocess.TimeoutExpired:
            timed = True;process.kill();stdout, stderr = process.communicate()
        (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
        receipt = dict(command=command, pid=process.pid, exit_code=process.returncode, reaped=True,
            timed_out=timed, timeout_seconds=20, elapsed_seconds=time.monotonic() - start,
            stdin_bytes=len(wire), stdin_sha256=SHA(wire), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
            stderr_bytes=len(stderr), stderr_sha256=SHA(stderr))
        (directory / 'process.json').write_bytes(ENCODE(receipt))
        assert process.returncode == 0 and not timed and not stderr, receipt
        observer = json.loads(log.read_bytes())
        assert observer['status'] == 'PASS' and observer['all_selected_faults_reached']
        assert observer['child_reaped'] and observer['exit_code'] == 0
        after, _ = snapshot(root, identities)
        responses = parse(stdout);assert len(responses) == len(row['operations'])
        assert responses[0]['diagnostic'] == row['expected_first_diagnostic'], responses[0]
        result = dict(before=before, after=after, responses=responses, process=receipt, kernel=observer,
            initial_inodes_held_through_observation=True)
        for fd, identity in pins:
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
        (directory / 'observation.json').write_bytes(ENCODE(result))
        return result, stdout
    finally:
        for fd, _ in pins:os.close(fd)
