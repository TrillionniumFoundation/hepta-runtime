# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Owned on-disk corpus for the original Record directory operations."""
import base64
import hashlib
import json
import random
import struct

ID = 'a1' * 32
NAME = ID + '.json'
TEMP = '.' + ID + '-' + ID + '.tmp'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def record(state='stored', payload=b'abc', **changed):
    value = dict(request_id=ID, owner='b2' * 32, tool_name='host_list',
        accepted_unix_ms=(1 << 128) - 1, policy_binding='c3' * 32, state=state,
        payload_base64=base64.b64encode(payload).decode() if state == 'stored' else None,
        payload_bytes=len(payload) if state == 'stored' else None,
        payload_sha256=SHA(payload) if state == 'stored' else None)
    value.update(changed);return value


def regular(raw, mode=0o600):
    return dict(kind='file', data=raw.hex(), mode=mode)


def request(operation, value=None, filename=NAME, raw=None):
    body = (encoded(value) if raw is None else raw) if value is not None or raw is not None else b''
    name = filename.encode()
    return b'HRRFQ001' + struct.pack('<5Q', operation, len(name), len(body), 0, 0) + name + body


def case(name, files, operations, **options):
    return dict(name=name, files=files, operations=[raw.hex() for raw in operations], **options)


def cases():
    states = ('unknown', 'stored', 'overflow', 'refused_dto', 'not_completed')
    for state in states:
        value = record(state)
        yield case('new-read-repeat-' + state, {}, [request(2, value), request(1), request(3, value), request(1)])
        yield case('existing-new-refused-' + state, {NAME: regular(encoded(value))}, [request(2, value), request(1)])
        for following in states:
            target = record(following, b'new')
            yield case('replace-' + state + '-to-' + following, {NAME: regular(encoded(value))}, [request(3, target), request(1)])
    for state in states:
        value = record(state)
        for key, changed in [('owner', '00' * 32), ('policy_binding', '11' * 32),
                ('accepted_unix_ms', (1 << 64) - 1), ('tool_name', 'host_health')]:
            yield case('binding-' + state + '-' + key, {NAME: regular(encoded(value))},
                [request(3, record('stored', **{key: changed})), request(1)])
    for size in (0, 1, 2, 3, 63, 64, 65, 4095, 4096, 16384, 65534, 65535, 65536):
        payload = bytes((index * 13 + size) & 255 for index in range(size))
        value = record('stored', payload)
        yield case('size-' + str(size), {}, [request(2, record('unknown')), request(3, value), request(1)])
    for mode in (0o400, 0o600, 0o640, 0o644, 0o700, 0o1600, 0o2600, 0o4600, 0o6600):
        yield case('record-mode-' + oct(mode), {NAME: regular(encoded(record()), mode)}, [request(1), request(3, record())])
        yield case('stage-mode-' + oct(mode), {TEMP: regular(b'interrupted', mode)}, [request(4), request(2, record())])
    for mode in (0o500, 0o700, 0o755, 0o777, 0o1700, 0o2700, 0o4700):
        yield case('directory-mode-' + oct(mode), {NAME: regular(encoded(record()))},
            [request(1), request(3, record()), request(2, record())], directory_mode=mode)
    for mask in (0, 0o022, 0o077, 0o200, 0o400, 0o600, 0o777):
        yield case('umask-' + oct(mask), {}, [request(2, record()), request(1)], umask=mask)
    for kind, extra in [('directory', {}), ('fifo', {}), ('socket', {}),
            ('symlink', {'target': 'absent'}), ('symlink', {'target': 'payload'})]:
        spec = dict(kind=kind, mode=0o600, **extra)
        for name in (NAME, TEMP):
            files = {name: spec, 'payload': regular(encoded(record()))}
            yield case('special-' + kind + '-' + name[:2] + '-' + extra.get('target', ''), files,
                [request(1), request(3, record())])
    for count in (1, 2, 3, 4):
        files = {NAME: regular(encoded(record()))}
        for index in range(1, count):files['alias-' + str(index)] = dict(kind='hardlink', target=NAME)
        yield case('record-links-' + str(count), files, [request(1), request(3, record())])
    for operation in (1, 2, 3, 4):
        call = request(operation, record() if operation in (2, 3) else None)
        yield case('stage-single-' + str(operation), {TEMP: regular(b'partial')}, [call, request(1)])
        yield case('stage-published-' + str(operation), {TEMP: regular(encoded(record('unknown'))), NAME: dict(kind='hardlink', target=TEMP)}, [call, request(1)])
        yield case('stage-link-missing-' + str(operation), {TEMP: regular(b'partial'), 'alias': dict(kind='hardlink', target=TEMP)}, [call])
        yield case('stage-link-mismatch-' + str(operation), {TEMP: regular(b'partial'), 'alias': dict(kind='hardlink', target=TEMP), NAME: regular(encoded(record('unknown')))}, [call])
        yield case('stage-three-links-' + str(operation), {TEMP: regular(b'partial'), NAME: dict(kind='hardlink', target=TEMP), 'alias': dict(kind='hardlink', target=TEMP)}, [call])
    for size in (98303, 98304, 98305):
        valid = encoded(record())
        yield case('record-byte-size-' + str(size), {NAME: regular(valid + b' ' * (size - len(valid)))}, [request(1)])
        yield case('stage-byte-size-' + str(size), {TEMP: regular(b'x' * size)}, [request(4)])
    for raw in (b'', b'{', b'{}', b'[]', b'null', b'false', encoded(record()) + b'x',
            encoded(record(payload_bytes=4)), encoded(record(payload_sha256='0' * 64)),
            encoded(record('unknown', payload_bytes=1)), encoded(record(owner='x')),
            encoded(record(request_id='0' * 64))):
        yield case('bad-record-' + str(len(raw)) + '-' + SHA(raw)[:8], {NAME: regular(raw)}, [request(1), request(3, record())])
    for state in states:
        value = record(state)
        shapes = [encoded(list(value.values())), b' \n' + encoded(dict(reversed(list(value.items())))) + b'\t\r',
            encoded(value).replace(b'"owner"', b'"own\\u0065r"')]
        if state != 'stored':shapes.append(encoded({k: v for k, v in value.items() if not k.startswith('payload_')}))
        for index, raw in enumerate(shapes):
            yield case('typed-shape-' + state + '-' + str(index), {}, [request(2, raw=raw), request(1), request(3, raw=raw)])
    yield case('unrelated-staging-untouched', {'.unrelated.tmp': regular(b'unrelated')}, [request(2, record()), request(4), request(1)])
    rng = random.Random(0x524543494f)
    for index in range(64):
        state = states[index % len(states)]
        value = record(state, rng.randbytes(index * 7), owner=rng.randbytes(32).hex(),
            policy_binding=rng.randbytes(32).hex(), accepted_unix_ms=rng.getrandbits(128),
            tool_name=('host_list', 'host_health', 'effective_config')[index % 3])
        yield case('random-record-' + str(index), {}, [request(2, value), request(1), request(3, value)])
    for label, raw in [('json', b'{}'), ('identity', encoded(record(owner='x'))), ('integrity', encoded(record(payload_bytes=4)))]:
        yield case('private-new-input-refusal-' + label, {}, [request(2, raw=raw), request(2, record()), request(1)])
