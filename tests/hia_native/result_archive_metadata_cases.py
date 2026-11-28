# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original typed JSON corpus through actual archive files, cache and marker reads."""
import copy
import json
import struct
import result_storage_json_cases as typed

ANCHOR = '.request-results-v2-anchor.json'
MARKER = '.request-results-v2.json'
IDENTITY = dict(device=123, inode=(1 << 64) - 1)


def encoded(value):return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
def anchor(index=0):
    return dict(schema=2, root=dict(device=index, inode=index + 1), legacy=IDENTITY,
        store=IDENTITY, archive=IDENTITY, shards=[dict(device=index, inode=i) for i in range(256)])
def regular(raw, mode=0o600):return dict(kind='file', data=raw.hex(), mode=mode)
def frame(operation):return b'HRAMQ001' + struct.pack('<QQ', operation, 0)
def read(operation):return dict(request=frame(operation).hex())
def case(name, files, operations):return dict(name=name, files=files, operations=operations)


def cases():
    typed.ANCHOR = anchor()
    for index, (name, wire) in enumerate(typed.cases()):
        if len(wire) < 24 or wire[:8] != b'HRSTQ001':continue
        kind, size = struct.unpack_from('<QQ', wire, 8)
        if kind not in (2, 3) or size != len(wire) - 24:continue
        operation = kind - 1
        yield case(f'typed-{index:04d}-{name}', {ANCHOR if operation == 1 else MARKER: regular(wire[24:])},
            [read(operation), read(operation)])
    for operation, filename in ((1, ANCHOR), (2, MARKER)):
        raw = encoded(anchor()) if operation == 1 else encoded(dict(schema=2, anchor_sha256='a1' * 32))
        yield case('missing-' + str(operation), {}, [read(operation), read(operation)])
        for mode in (0, 0o400, 0o600, 0o644, 0o666, 0o700, 0o1600, 0o2600, 0o4600):
            yield case('mode-' + str(operation) + '-' + oct(mode), {filename: regular(raw, mode)}, [read(operation)])
        for kind in ('directory', 'fifo', 'socket', 'symlink'):
            value = dict(kind=kind, mode=0o700 if kind == 'directory' else 0o600)
            if kind == 'symlink':value.update(target='target')
            yield case('kind-' + str(operation) + '-' + kind, {filename: value, 'target': regular(raw)}, [read(operation)])
        for links in (2, 3):
            files = {filename: regular(raw)}
            for index in range(links - 1):files['link-' + str(index)] = dict(kind='hardlink', target=filename)
            yield case('links-' + str(operation) + '-' + str(links), files, [read(operation)])
        for length in (0, 1, 1024, 1025, 98304, 98305):
            value = raw + b' ' * max(0, length - len(raw))
            value = value[:length]
            yield case('size-' + str(operation) + '-' + str(length), {filename: regular(value)}, [read(operation)])
    for count in (1, 15, 16, 17, 33):
        operations = []
        for index in range(count):
            operations += [dict(mutation=dict(action='publish_anchor', ordinal=index,
                data=encoded(anchor(index)).hex())), read(1), read(1), read(2)]
        operations += [dict(mutation=dict(action='rewrite_anchor', data=encoded(anchor(1000)).hex())), read(1), read(1)]
        yield case('cache-order-and-replacement-' + str(count), {MARKER: regular(encoded(dict(schema=2, anchor_sha256='c3' * 32)))}, operations)
    for operation in (1, 2):
        filename = ANCHOR if operation == 1 else MARKER
        raw = encoded(anchor()) if operation == 1 else encoded(dict(schema=2, anchor_sha256='a1' * 32))
        yield case('permission-changes-' + str(operation), {filename: regular(raw)},
            [read(operation), dict(mutation=dict(action='chmod', name=filename, mode=0o644)), read(operation),
             dict(mutation=dict(action='chmod', name=filename, mode=0o600)), read(operation)])
    for offset, value in ((0, 0), (8, 0), (8, 3), (16, 1)):
        raw = bytearray(frame(1));struct.pack_into('<Q', raw, offset, value)
        yield case('private-frame-' + str(offset) + '-' + str(value), {}, [dict(request=raw.hex()), read(2)])
    for count in (0, 1, 7, 8, 23, 25):
        raw = (frame(1) + b'x')[:count]
        yield case('private-length-' + str(count), {}, [dict(request=raw.hex()), read(2)])
