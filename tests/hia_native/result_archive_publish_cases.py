# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Typed anchor publication and marker initialization through owned real files."""
import copy
import struct
import result_storage_json_cases as typed
from result_archive_metadata_cases import ANCHOR, MARKER, anchor, encoded, regular, cases as metadata_cases


def frame(operation, raw):return b'HRAPQ001' + struct.pack('<QQ', operation, len(raw)) + raw
def request(operation, raw):return dict(request=frame(operation, raw).hex())
def case(name, files, operations, **extra):return dict(name=name, files=files, operations=operations, **extra)


def cases():
    typed.ANCHOR = anchor()
    for index, (name, wire) in enumerate(typed.cases()):
        if len(wire) < 24 or wire[:8] != b'HRSTQ001':continue
        kind, size = struct.unpack_from('<QQ', wire, 8)
        if kind != 2 or size != len(wire) - 24:continue
        step = request(1, wire[24:])
        yield case(f'publish-typed-{index:04d}-{name}', {}, [step, step])
    for index, row in enumerate(metadata_cases()):
        if not row['name'].startswith(('typed-', 'missing-', 'mode-', 'kind-', 'links-', 'size-', 'permission-changes-')):continue
        valid = True;steps = []
        for step in row['operations']:
            if 'mutation' in step:steps.append(copy.deepcopy(step));continue
            wire = bytes.fromhex(step['request'])
            if wire != b'HRAMQ001' + struct.pack('<QQ', 2, 0):valid = False;break
            steps.append(request(2, b'a1' * 32))
        if valid:yield case(f'ensure-marker-{index:04d}-{row["name"]}', copy.deepcopy(row['files']), steps)
    raw = encoded(anchor());publish = request(1, raw);marker = request(2, b'a1' * 32)
    for kind in ('file', 'directory', 'fifo', 'socket', 'symlink'):
        spec = regular(b'prior history') if kind == 'file' else dict(kind=kind, mode=0o700 if kind == 'directory' else 0o600)
        if kind == 'symlink':spec['target'] = 'old-target'
        yield case('existing-anchor-' + kind, {ANCHOR: spec, 'old-target': regular(b'untouched')}, [publish, publish, marker])
    for mask in (0, 0o022, 0o027, 0o077, 0o200, 0o777):
        yield case('creation-umask-' + oct(mask), {}, [publish, marker, publish, marker], umask=mask)
    for mode in (0o500, 0o700, 0o750, 0o775):
        yield case('directory-mode-' + oct(mode), {}, [publish, marker, publish, marker], directory_mode=mode)
    yield case('marker-binding-history', {}, [marker, marker, request(2, b'b2' * 32), marker])
    for payload in (b'', b'a' * 63, b'a' * 65, b'A' * 64, b'g' * 64, b'\xff' * 64, b'\0' * 64):
        yield case('private-marker-' + payload.hex(), {}, [request(2, payload), marker])
    for offset, value in ((0, 0), (8, 0), (8, 3), (16, 0), (16, 1 << 63)):
        wire = bytearray(frame(2, b'a1' * 32));struct.pack_into('<Q', wire, offset, value)
        yield case(f'private-header-{offset}-{value}', {}, [dict(request=wire.hex()), marker])
    for length in (0, 1, 7, 8, 23):
        yield case('private-short-' + str(length), {}, [dict(request=frame(1, raw)[:length].hex()), marker])
