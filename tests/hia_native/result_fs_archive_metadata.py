# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual original/native file reads, immutable byte hashes and bounded cache sequences."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import stat
import struct
import subprocess
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_archive_metadata_cases import cases, ANCHOR
from result_fs_record_io import setup, snapshot
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def mutate(root, change):
    if change['action'] == 'chmod':
        (root / change['name']).chmod(change['mode']);return
    raw = bytes.fromhex(change['data'])
    if change['action'] == 'publish_anchor':
        ordinal = change['ordinal'];temporary = root / ('pending-' + str(ordinal))
        temporary.write_bytes(raw);temporary.chmod(0o600)
        if (root / ANCHOR).exists():(root / ANCHOR).rename(root / ('retired-' + str(ordinal)))
        temporary.rename(root / ANCHOR)
    elif change['action'] == 'rewrite_anchor':
        with (root / ANCHOR).open('wb') as stream:stream.write(raw)
    else:raise AssertionError(change)


def exact(process, count):
    raw = bytearray();deadline = time.monotonic() + 10
    while len(raw) < count:
        left = deadline - time.monotonic();assert left > 0
        assert select.select([process.stdout], [], [], left)[0], 'owned reply deadline'
        block = os.read(process.stdout.fileno(), count - len(raw));assert block, ('early EOF', process.poll())
        raw.extend(block)
    return bytes(raw)


def descriptors(process, root):
    assert process.poll() is None
    result = []
    expected = root.stat()
    for path in (Path('/proc') / str(process.pid) / 'fd').iterdir():
        try:target = os.readlink(path)
        except FileNotFoundError:continue
        if target == str(root) or target.startswith(str(root) + '/'):
            info = path.stat()
            assert target == str(root) and stat.S_ISDIR(info.st_mode)
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            result.append(int(path.name))
    assert len(result) == 1 and process.poll() is None
    return result[0]


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    before, _ = snapshot(root);started = time.monotonic()
    process = subprocess.Popen([str(executable), str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=dict(os.environ, PATH=''), umask=0o077, bufsize=0)
    observations = [];input_bytes = bytearray();output_bytes = bytearray();stderr = b'';error = None
    try:
        for step in row['operations']:
            if 'mutation' in step:
                mutate(root, step['mutation']);observations.append(dict(mutation=step['mutation']['action'], filesystem=snapshot(root)[0]));continue
            raw = bytes.fromhex(step['request']);wire = struct.pack('<Q', len(raw)) + raw;input_bytes.extend(wire)
            at = 0
            while at < len(wire):
                count = process.stdin.write(wire[at:]);assert count > 0;at += count
            process.stdin.flush();header = exact(process, 4);code = struct.unpack('<I', header)[0]
            assert code == 0xffffffff or 64 <= code <= 262144
            body = exact(process, code) if code != 0xffffffff else b''
            output_bytes.extend(header + body)
            record = dict(code=code, output_sha256=SHA(body))
            if body:
                magic, diagnostic, errno, operation, present, projection, digest, cached = struct.unpack_from('<8s7Q', body)
                assert magic == b'HRAMR001' and code == 64 + projection + digest and present in (0, 1) and cached <= 16
                assert diagnostic != 255
                record.update(diagnostic=diagnostic, errno=errno, operation=operation, present=present,
                    projection_bytes=projection, digest_bytes=digest, cached_entries=cached)
            record['held_directory_descriptor'] = descriptors(process, root)
            observations.append(dict(response=record, filesystem=snapshot(root)[0]))
        process.stdin.close();process.wait(timeout=10)
        assert not process.stdout.read()
        stderr = process.stderr.read();assert process.returncode == 0 and not stderr
    except BaseException as caught:
        error = repr(caught);raise
    finally:
        if process.poll() is None:process.kill();process.wait()
        if process.stdout and not process.stdout.closed:output_bytes.extend(process.stdout.read())
        if process.stderr and not process.stderr.closed:stderr += process.stderr.read()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:stream.close()
        (directory / 'stdin.bin').write_bytes(input_bytes);(directory / 'stdout.bin').write_bytes(output_bytes)
        (directory / 'stderr.bin').write_bytes(stderr)
        receipt = dict(command=[str(executable), str(root)], pid=process.pid, exit_code=process.returncode,
            reaped=True, elapsed_seconds=time.monotonic() - started, error=error, path_environment_empty=True,
            stdin_bytes=len(input_bytes), stdin_sha256=SHA(input_bytes), stdout_bytes=len(output_bytes),
            stdout_sha256=SHA(output_bytes), stderr_bytes=len(stderr), stderr_sha256=SHA(stderr), observations=observations)
        (directory / 'process.json').write_bytes(ENCODE(receipt))
    comparison = dict(before=before, after=snapshot(root)[0], observations=[])
    for row in observations:
        copied = dict(row)
        if 'response' in copied:
            copied['response'] = dict(copied['response']);del copied['response']['held_directory_descriptor']
        comparison['observations'].append(copied)
    return comparison, bytes(output_bytes)
