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
from result_fs_record_io import setup, snapshot
from result_archive_publish_fault_cases import cases
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


def parse(raw):
    at = 0;result = []
    while at < len(raw):
        size = struct.unpack_from('<I', raw, at)[0];at += 4
        assert size == 48 and at + size <= len(raw)
        body = raw[at:at + size];at += size
        magic, diagnostic, error, operation, zero, reserved = struct.unpack('<8s5Q', body)
        assert magic == b'HRAPR001' and diagnostic != 255 and zero == reserved == 0
        result.append(dict(diagnostic=diagnostic, errno=error, operation=operation, response_sha256=SHA(body)))
    return result


def normalized_filesystem(value, names):
    result = dict(value);result['entries'] = {}
    for name, entry in value['entries'].items():
        record = dict(entry);record['aliases'] = sorted(names.get(alias, alias) for alias in entry['aliases'])
        result['entries'][names.get(name, name)] = record
    return result


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before, identities = snapshot(root);pins = [];names = {}
    def pin(values):
        for name, identity in values.items():
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(fd);assert (info.st_dev, info.st_ino) == identity
            pins.append((fd, identity))
    def observed(label, operations, configuration, killed=False):
        config = directory / (label + '-config.json');config.write_bytes(ENCODE(configuration))
        log = directory / (label + '-kernel.json')
        command = [sys.executable, '-I', '-B', HERE / 'result_archive_publish_supervisor.py', '--fixture', root,
            '--config', config, '--log', log, '--timeout', '10', '--', executable, root]
        receipt, stdout = launch(command, framed(operations), directory / label, 137 if killed else 0)
        observer = json.loads(log.read_bytes());assert observer['status'] == 'PASS'
        assert observer['all_selected_faults_reached'] and observer['child_reaped']
        assert observer['exit_code'] == (-9 if killed else 0)
        assert observer['actual_random_bytes_verified_before_each_temporary_open'] is True
        for name in observer['temporary_names']:
            if name not in names:names[name] = '.result-anchor-<observed-nonce-' + str(len(names)) + '>.tmp'
        for event in observer['events']:
            if event['kind'] in ('link_temporary', 'unlink_temporary', 'sync_directory'):
                assert len(event['held_fixture_files']) == 1, event
            if event['kind'] == 'open_temporary':assert event['name_equals_actual_random_bytes'] is True
        responses = parse(stdout);assert len(responses) == (0 if killed else len(operations))
        return receipt, stdout, observer, responses
    try:
        pin(identities);killed = 'recovery' in row
        receipt, stdout, observer, responses = observed('observed', row['operations'], row['supervisor'], killed)
        after, following = snapshot(root, identities)
        if not killed:assert responses[0]['diagnostic'] == row['expected_first_diagnostic'], responses[0]
        if 'actual_short_write_limit' in row:
            limit = row['actual_short_write_limit']
            writes = [event for event in observer['events'] if event['kind'] in ('write_temporary', 'write_record')]
            assert len(writes) == 2 and writes[0]['file_bytes_before_kernel_write'] == 0
            assert writes[1]['file_bytes_before_kernel_write'] == limit
            assert writes[1]['file_sha256_before_kernel_write'] == SHA(bytes.fromhex(row['canonical_written_bytes'])[:limit])
            assert responses[0]['diagnostic'] == 23 and responses[0]['errno'] == 27
        result = dict(before=normalized_filesystem(before, names), after=normalized_filesystem(after, names),
            raw_before=before, raw_after=after, responses=responses, process=receipt, kernel_observer=observer,
            original_inodes_held_through_observation=True)
        outputs = [stdout]
        if killed:
            pin(following)
            recovery, data, recovery_observer, answers = observed('recovery', row['recovery'], dict(faults=[]))
            final, _ = snapshot(root, following)
            result.update(recovery_process=recovery, recovery_responses=answers, recovery_kernel_observer=recovery_observer,
                recovery_after=normalized_filesystem(final, names), raw_recovery_after=final)
            outputs.append(data)
        for fd, identity in pins:
            info = os.fstat(fd);assert (info.st_dev, info.st_ino) == identity
        result['verified_nonce_projection'] = names
        (directory / 'observation.json').write_bytes(ENCODE(result))
        return result, outputs
    finally:
        for fd, _ in pins:os.close(fd)
