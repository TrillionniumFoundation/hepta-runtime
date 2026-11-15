# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original/HIA private archive replies, filesystem graphs, and real held descriptors."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import select
import struct
import subprocess
import sys
import time
import traceback
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_archive_store_cases import cases, ANCHOR
from result_archive_store_fixture import Fixture, setup, mutate

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def exact(process, count):
    raw = bytearray();deadline = time.monotonic() + 15
    while len(raw) < count:
        left = deadline - time.monotonic();assert left > 0
        assert select.select([process.stdout], [], [], left)[0], 'owned reply deadline'
        block = os.read(process.stdout.fileno(), count - len(raw))
        assert block, ('early EOF', process.poll())
        raw.extend(block)
    return bytes(raw)


def run(executable, row, directory):
    directory.mkdir(mode=0o700);root = directory / 'fixture';setup(root, row)
    fixture = Fixture(root, directory);fixture.snapshot()
    for change in row.get('setup', []):
        mutate(root, change);fixture.snapshot()
    before = fixture.snapshot()
    ambient = [fixture.by_identity[(p.stat().st_dev, p.stat().st_ino)] for p in (root / 'root', root / 'legacy')]
    started = time.monotonic()
    command = [str(executable), str(root / 'root'), str(root / 'legacy')]
    if 'supervisor' in row:
        configuration = directory / 'kernel-config.json';configuration.write_bytes(ENCODE(row['supervisor']))
        command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('result_archive_store_supervisor.py')),
            '--fixture', str(root), '--config', str(configuration), '--log', str(directory / 'kernel.json'),
            '--timeout', '30', '--'] + command
    process = subprocess.Popen(command,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=dict(os.environ, PATH=''), umask=row.get('umask', 0o077), bufsize=0)
    observations = [];input_bytes = bytearray();output_bytes = bytearray();projected = bytearray()
    archive_token = None;shard_token = None;stderr = b'';error = None
    try:
        for step in row['operations']:
            if 'mutation' in step:
                mutate(root, step['mutation'])
                observations.append(dict(mutation=step['mutation'], filesystem=fixture.snapshot()));continue
            raw = bytes.fromhex(step['request']);wire = struct.pack('<Q', len(raw)) + raw
            input_bytes.extend(wire);existed = (root / ANCHOR).exists();at = 0
            while at < len(wire):
                count = process.stdin.write(wire[at:]);assert count > 0;at += count
            process.stdin.flush();header = exact(process, 4);code = struct.unpack('<I', header)[0]
            assert code in (64, 0xffffffff), code
            body = exact(process, 64) if code == 64 else b''
            output_bytes.extend(header + body);filesystem = fixture.snapshot()
            projected_body = bytearray(body);record = dict(code=code)
            if body:
                magic, diagnostic, errno, present, held_archive, held_shard, device, inode = struct.unpack('<8s7Q', body)
                assert magic == b'HRASR001' and diagnostic != 255
                operation, create = struct.unpack_from('<QQ', raw, 8);token = None
                if device or inode:
                    assert diagnostic == 0 and operation in (1, 2, 6)
                    token = fixture.by_identity.get((device, inode));assert token is not None
                    projected_body[48:64] = bytes(16)
                if diagnostic == 0:
                    if operation == 1:
                        archive_token = token
                        if present:
                            assert token is not None
                            if create and not existed:fixture.verify_created_anchor()
                        else:assert token is None
                    elif operation == 2:
                        assert token is not None;shard_token = token
                    elif operation == 4:shard_token = None
                    elif operation == 5:archive_token = None
                    elif operation == 6:assert token == shard_token
                else:assert device == inode == 0
                assert (held_archive != 0) == (archive_token is not None)
                assert (held_shard != 0) == (shard_token is not None)
                assert present == int(archive_token is not None or shard_token is not None)
                record.update(diagnostic=diagnostic, errno=errno, operation=operation,
                    archive_lease=held_archive, shard_lease=held_shard, identity=token,
                    actual_device=device, actual_inode=inode)
            observed = process
            if 'supervisor' in row:
                observed = SimpleNamespace(pid=int((directory / 'kernel.pid').read_text()), poll=process.poll)
            descriptors = fixture.descriptors(observed);expected = list(ambient)
            if archive_token is not None:expected.append(archive_token)
            if shard_token is not None:expected.append(shard_token)
            assert sorted(r['identity'] for r in descriptors) == sorted(expected), (descriptors, expected)
            if body and record['identity'] is not None:
                assert any((r['device'], r['inode']) == (record['actual_device'], record['actual_inode']) for r in descriptors)
            record['held_descriptors'] = descriptors;projected.extend(header + projected_body)
            observations.append(dict(response=record, filesystem=filesystem))
        process.stdin.close();process.wait(timeout=15);assert not process.stdout.read()
        stderr = process.stderr.read();assert process.returncode == 0 and not stderr
        if 'supervisor' in row:
            kernel = json.loads((directory / 'kernel.json').read_bytes())
            assert kernel['status'] == 'PASS' and kernel['child_reaped'] and kernel['all_selected_faults_reached']
            assert kernel['exit_code'] == 0 and kernel['semantic_emulation'] is False
    except BaseException as caught:
        error = repr(caught);raise
    finally:
        if process.poll() is None:process.kill();process.wait()
        if process.stdout and not process.stdout.closed:output_bytes.extend(process.stdout.read())
        if process.stderr and not process.stderr.closed:stderr += process.stderr.read()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:stream.close()
        for name, raw in (('stdin.bin', input_bytes), ('stdout.bin', output_bytes),
                ('projected-stdout.bin', projected), ('stderr.bin', stderr)):(directory / name).write_bytes(raw)
        identities = fixture.finish()
        receipt = dict(command=command,
            pid=process.pid, exit_code=process.returncode, reaped=True, path_environment_empty=True,
            elapsed_seconds=time.monotonic() - started, error=error,
            stdin_bytes=len(input_bytes), stdin_sha256=SHA(input_bytes), stdout_bytes=len(output_bytes),
            stdout_sha256=SHA(output_bytes), projected_stdout_sha256=SHA(projected),
            stderr_bytes=len(stderr), stderr_sha256=SHA(stderr), observations=observations, **identities)
        (directory / 'process.json').write_bytes(ENCODE(receipt))
    comparison = dict(before=before, observations=[])
    for observation in observations:
        copied = dict(observation)
        if 'response' in copied:
            response = dict(copied['response'])
            response['held_descriptors'] = sorted(r['identity'] for r in response['held_descriptors'])
            response.pop('actual_device', None);response.pop('actual_inode', None);copied['response'] = response
        comparison['observations'].append(copied)
    return comparison, bytes(projected), identities
