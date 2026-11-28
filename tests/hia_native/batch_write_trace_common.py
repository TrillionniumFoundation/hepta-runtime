"""Full-byte qualification snapshots plus the trusted batch test packet."""
from __future__ import annotations
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def snapshot(fixture, stream, ordinal):
    base = os.fsencode(fixture)
    paths = []
    for parent, directories, files in os.walk(base, followlinks=False):
        directories.sort(); files.sort()
        for name in directories + files:
            paths.append(os.path.join(parent, name))
    inventory = []
    for path in sorted(paths):
        metadata = os.lstat(path)
        kind = stat.S_IFMT(metadata.st_mode)
        entry = dict(path_hex=path[len(base) + 1:].hex(), kind=kind,
                     mode=stat.S_IMODE(metadata.st_mode), links=metadata.st_nlink)
        data = None
        if stat.S_ISLNK(metadata.st_mode):
            entry['link_hex'] = os.readlink(path).hex()
        elif stat.S_ISREG(metadata.st_mode):
            entry['bytes'] = metadata.st_size
            try:
                data = open(path, 'rb')
            except OSError as error:
                entry['read_errno'] = error.errno
        header = json_bytes(dict(ordinal=ordinal, **entry))
        stream.write(struct.pack('<QQ', len(header), metadata.st_size if data else 0))
        stream.write(header)
        if data:
            digest = hashlib.sha256(); count = 0
            with data:
                while raw := data.read(1 << 20):
                    stream.write(raw); digest.update(raw); count += len(raw)
            assert count == metadata.st_size
            entry['sha256'] = digest.hexdigest()
        inventory.append(entry)
    stream.write(struct.pack('<QQ', 0, ordinal))
    return inventory


def equal_streams(a, b, compressed=False):
    opening = gzip.open if compressed else open
    digest = hashlib.sha256(); count = 0
    with opening(a, 'rb') as left, opening(b, 'rb') as right:
        while True:
            raw = left.read(1 << 20); other = right.read(1 << 20)
            assert raw == other, ('complete retained transcript differs', a.name, count)
            if not raw: break
            count += len(raw); digest.update(raw)
    return dict(bytes=count, sha256=digest.hexdigest())

def packet(step, path):
    """Fixed test projection of integer/string endpoints, never production JSON."""
    def endpoint(value):
        if isinstance(value, str):
            raw = value.encode('utf-8')
            return b'HIAEP001' + struct.pack('<3Q', 2, len(raw), 0) + raw
        assert type(value) is int and -(1 << 63) <= value < (1 << 63)
        return b'HIAEP001' + struct.pack('<3Q', 0, 0, value & ((1 << 64) - 1))
    records = []
    operations = step.get('operations', [{'operation': 'insert', 'start': 0, 'content': 'next'}])
    for operation in operations:
        name = operation['operation'].encode('utf-8')
        start = endpoint(operation['start'])
        end = endpoint(operation['end']) if operation.get('end') is not None else b''
        content = operation.get('content', '').encode('utf-8')
        records.append(struct.pack('<9Q', 1, 1, 1, bool(end), 1, len(name), len(start), len(end), len(content))
                       + name + start + end + content)
    payload = b''.join(records)
    path = bytes(path)
    return b'HFBWT001' + struct.pack('<7Q', step.get('context', 1), len(path), len(path),
                                   len(records), len(payload), 1, 0) + path + path + payload
