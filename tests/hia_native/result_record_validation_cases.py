# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Original emitted records and deterministic integrity boundary inputs."""
from pathlib import Path
import base64
import hashlib
import itertools
import json
import lzma
import random
import struct

ROOT = Path(__file__).resolve().parent
ID = 'a1' * 32
FILENAME = (ID + '.json').encode()
FIELDS = ('payload_base64', 'payload_bytes', 'payload_sha256')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def frame(raw, filename=FILENAME):
    return b'HRRCQ001' + struct.pack('<2Q', len(filename), len(raw)) + filename + raw


def record(payload=b'abc', **values):
    return dict(request_id=ID, owner='b2' * 32, tool_name='host_list',
        accepted_unix_ms=(1 << 128) - 1, policy_binding='c3' * 32, state='stored',
        payload_base64=base64.b64encode(payload).decode(), payload_bytes=len(payload),
        payload_sha256=SHA(payload), **values)


def cases():
    compressed = ROOT / 'fixtures/retention-records-v2.jsonl.xz'
    proof = json.loads((ROOT / 'fixtures/retention-records-v2.json').read_bytes())
    assert SHA(compressed.read_bytes()) == proof['archive_sha256']
    raw = lzma.decompress(compressed.read_bytes())
    assert len(raw) == proof['expanded_bytes'] and SHA(raw) == proof['expanded_sha256']
    lines = raw.splitlines();assert len(lines) == proof['records']
    for line in lines:
        item = json.loads(line);value = json.loads(item['record'])
        yield 'original-emission/' + item['label'], frame(item['record'].encode(), (value['request_id'] + '.json').encode())
    base = record()
    for state in ('unknown', 'stored', 'overflow', 'refused_dto', 'not_completed'):
        for representation in (state, {state: None}):
            for presence in range(8):
                value = dict(base, state=representation)
                for bit, key in enumerate(FIELDS):
                    if not presence & (1 << bit):
                        value[key] = None
                yield 'state-presence', frame(encoded(value))
                yield 'state-presence-sequence', frame(encoded(list(value.values())))
                value = {k: v for k, v in value.items() if k not in FIELDS or v is not None}
                yield 'state-presence-omitted', frame(encoded(value))
    for key in ('request_id', 'owner', 'tool_name', 'policy_binding'):
        for value in ('', '0' * 63, '0' * 65, 'A' * 64, 'f' * 64, 'g' + '0' * 63,
                '汉' * 64, 'host_list', 'host_health', 'effective_config', 'HOST_LIST', 'host_list\0',
                '/', '.', '..', '../' + ID, ID + '.json', '\0' * 64, '9' * 64, 'a' * 64):
            row = dict(base);row[key] = value
            yield 'identity-' + key, frame(encoded(row))
    for filename in (b'', b'.json', FILENAME.upper(), b'.' + FILENAME, FILENAME + b'\0',
            b'../' + FILENAME, FILENAME[:-1], b'0' * 64 + b'.json', b'g' * 64 + b'.json',
            b'a' * 64 + b'.JSON', b'\xff' + FILENAME[1:]):
        yield 'filename', frame(encoded(base), filename)
    for i in range(64):
        value = bytearray(FILENAME);value[i] = ord('z')
        yield 'filename-nonhex-position', frame(encoded(base), bytes(value))
    for count in list(range(0, 260)) + [4095, 4096, 4097, 16383, 16384, 65534, 65535, 65536, 65537, 65538, 65539]:
        payload = bytes((index * 17 + count) & 255 for index in range(count))
        row = record(payload)
        for tool in ('host_list', 'host_health', 'effective_config'):
            row['tool_name'] = tool
            yield 'payload-length-' + str(count), frame(encoded(row))
    for text in ('', 'A', 'AA', 'AAA', 'AAAA', 'AA==', 'AB==', 'AAA=', 'AAB=', '====',
            '=AAA', 'A=AA', 'AA=A', 'AA==AA==', 'YWJj\n', 'YW Jj', 'YWJj\t', '-w==', '_w==',
            '汉', '\0AAA', 'AAAA====', 'AAAA=', 'AAAAA', 'YWJj\r\n', 'A' * 87384, 'A' * 87388):
        yield 'base64-form', frame(encoded(dict(base, payload_base64=text)))
    for index in range(4):
        for ch in range(256):
            text = 'YQ=='[:index] + chr(ch) + 'YQ=='[index + 1:]
            yield 'base64-byte-position', frame(encoded(dict(record(b'a'), payload_base64=text)))
    for key in FIELDS:
        for value in (None, '', 0, 1, 2, 4, 65536, (1 << 64) - 1, False, [], {}, 'A' * 64,
                '0' * 63, SHA(b'abc').upper(), SHA(b'def'), SHA(b'abc') + '\0'):
            row = dict(base);row[key] = value
            yield 'payload-field-' + key, frame(encoded(row))
    for state in ('unknown', 'stored'):
        base_row = dict(base, state=state)
        if state == 'unknown':
            for key in FIELDS:base_row[key] = None
        for order in itertools.islice(itertools.permutations(base_row), 120):
            yield 'field-order', frame(encoded({key: base_row[key] for key in order}))
        for size in (98303, 98304, 98305):
            body = encoded(base_row)
            yield 'record-size-' + str(size), frame(body + b' ' * (size - len(body)))
    for body in (b'', b'null', b'[]', b'{}', b'false', b'{', encoded(base) + b'x',
            encoded(base)[:-1] + b',"owner":"' + b'0' * 64 + b'"}',
            encoded(base).replace(b'"state":"stored"', b'"state":false')):
        yield 'typed-json-refusal', frame(body)
    rng = random.Random(0x5245434F5244)
    for i in range(512):
        payload = rng.randbytes(rng.randrange(0, 512))
        row = record(payload);row['accepted_unix_ms'] = rng.getrandbits(128)
        row['owner'] = rng.randbytes(32).hex();row['policy_binding'] = rng.randbytes(32).hex()
        if i % 3 == 1:row['payload_bytes'] += 1
        if i % 3 == 2:row['payload_sha256'] = rng.randbytes(32).hex()
        yield 'random-integrity-' + str(i), frame(encoded(row))
