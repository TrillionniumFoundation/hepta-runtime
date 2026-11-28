# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Raw JSON derive cases, including u128, enum maps and both struct representations."""
import copy
import itertools
import json
import random
import struct

STATES = ('unknown', 'stored', 'overflow', 'refused_dto', 'not_completed')
RECORD = dict(request_id='a1' * 32, owner='b2' * 32, tool_name='host_list',
    accepted_unix_ms=(1 << 128) - 1, policy_binding='c3' * 32, state='stored',
    payload_base64='YWJj', payload_bytes=3, payload_sha256='d4' * 32)
DIRECTORY = dict(device=123, inode=(1 << 64) - 1)
ANCHOR = dict(schema=2, root=DIRECTORY, legacy=DIRECTORY, store=DIRECTORY, archive=DIRECTORY,
    shards=[DIRECTORY, dict(device=0, inode=1), dict(device=1, inode=2)])
MARKER = dict(schema=2, anchor_sha256='e5' * 32)


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def frame(kind, raw):
    return b'HRSTQ001' + struct.pack('<2Q', kind, len(raw)) + raw


def cases():
    bases = (RECORD, ANCHOR, MARKER)
    for kind, value in enumerate(bases, 1):
        raw = encoded(value)
        yield 'ordinary-map', frame(kind, raw)
        yield 'sequence', frame(kind, encoded(list(value.values())))
        yield 'whitespace', frame(kind, b' \n\r\t' + raw + b'\n\t ')
        for bad in (b'', b'null', b'false', b'0', b'"x"', b'{}', b'[]', raw + b'x', b'\xef\xbb\xbf' + raw):
            yield 'wrong-root-or-trailing', frame(kind, bad)
        for n in range(len(value) + 2):
            array = list(value.values())[:n] + ([None] if n > len(value) else [])
            yield 'sequence-length', frame(kind, encoded(array))
        for key in value:
            missing = copy.deepcopy(value);del missing[key]
            yield 'missing-' + key, frame(kind, encoded(missing))
            for invalid in (None, False, True, 0, -0.0, '', '汉\0😀', [], {}, [0, 0]):
                changed = copy.deepcopy(value);changed[key] = invalid
                yield 'field-type-' + key, frame(kind, encoded(changed))
            extra = (encoded(key) + b':' + encoded(value[key]))
            yield 'duplicate-' + key, frame(kind, b'{' + extra + b',' + raw[1:])
            escaped = ('"' + ''.join('\\u%04x' % ord(ch) for ch in key) + '"').encode()
            yield 'escaped-key-' + key, frame(kind, raw.replace(encoded(key), escaped, 1))
            yield 'escaped-duplicate-' + key, frame(kind, b'{' + escaped + b':' + encoded(value[key]) + b',' + raw[1:])
        for extra in ('extra', '', '\0', 'request_id\0', '汉'):
            changed = copy.deepcopy(value);changed[extra] = None
            yield 'unknown-field', frame(kind, encoded(changed))
        for ending in (b',}', b',]', b'} }', b'\0'):
            yield 'bad-punctuation', frame(kind, raw[:-1] + ending)
        keys = list(value)
        permutations = list(itertools.islice(itertools.permutations(keys), 720))
        for order in permutations:
            yield 'field-permutation', frame(kind, encoded({key: value[key] for key in order}))
    for state in STATES:
        for representation in (state, {state: None}, {state: []}, {state: {}}, {state: False}, {state: None, 'other': None}):
            value = dict(RECORD, state=representation)
            yield 'enum-' + state, frame(1, encoded(value))
            yield 'enum-sequence-' + state, frame(1, encoded(list(value.values())))
    for state in ('Stored', 'not_retained_dto', '', 'stored\0', '主机', 1, ['stored'], {}, {'unknown': None, 'stored': None}):
        yield 'invalid-enum', frame(1, encoded(dict(RECORD, state=state)))
    for mask in range(8):
        value = copy.deepcopy(RECORD)
        for bit, field in enumerate(('payload_base64', 'payload_bytes', 'payload_sha256')):
            if mask & (1 << bit):
                value[field] = None
        yield 'nullable-presence', frame(1, encoded(value))
        yield 'nullable-presence-sequence', frame(1, encoded(list(value.values())))
        for bit, field in enumerate(('payload_base64', 'payload_bytes', 'payload_sha256')):
            if mask & (1 << bit):
                del value[field]
        yield 'optional-omission-map', frame(1, encoded(value))
    for raw_number in [b'-0', b'-1', b'1.0', b'1e0', b'01', b'+1', b'1.', b'1e', b'null', b'false',
                       b'"0"', b'[]', b'{}', b'0e99999', b'1e99999', b'9' * 5000] + [
                       str(number).encode() for bits in (8, 32, 64, 96, 127, 128)
                       for number in ((1 << bits) - 1, 1 << bits, (1 << bits) + 1)]:
        for kind, base, key in ((1, RECORD, 'accepted_unix_ms'), (1, RECORD, 'payload_bytes'),
                                (2, ANCHOR, 'schema'), (3, MARKER, 'schema')):
            value = copy.deepcopy(base);value[key] = 'NUMBER'
            raw = encoded(value).replace(b'"NUMBER"', raw_number)
            yield 'typed-integer-' + key, frame(kind, raw)
        directory = b'{"device":' + raw_number + b',"inode":0}'
        raw = encoded(dict(ANCHOR, root='DIRECTORY')).replace(b'"DIRECTORY"', directory)
        yield 'directory-u64', frame(2, raw)
    rng = random.Random(0x53544F52414745)
    for index in range(512):
        value = dict(RECORD, accepted_unix_ms=rng.getrandbits(128), payload_bytes=rng.getrandbits(64),
                     request_id=hex(rng.getrandbits(256)), state=STATES[index % len(STATES)])
        yield 'random-u128', frame(1, encoded(value))
        yield 'random-u128-sequence', frame(1, encoded(list(value.values())))
    for value in ('', 'a', '"\\\n\t\r\0', '汉😀', '\u2028\u2029', 'e\u0301', 'é'):
        row = dict(RECORD)
        for key in ('request_id', 'owner', 'tool_name', 'policy_binding', 'payload_base64', 'payload_sha256'):
            row[key] = value
        yield 'unicode-record', frame(1, encoded(row))
        yield 'unicode-marker', frame(3, encoded(dict(MARKER, anchor_sha256=value)))
    for byte in range(256):
        for kind, base, key in ((1, RECORD, 'request_id'), (3, MARKER, 'anchor_sha256')):
            row = dict(base);row[key] = 'STRING'
            yield 'raw-single-byte-string', frame(kind, encoded(row).replace(b'STRING', bytes([byte])))
            yield 'escaped-single-byte-string', frame(kind, encoded(row).replace(b'STRING', ('\\u%04x' % byte).encode()))
    for escape in (b'\\ud800', b'\\udfff', b'\\ud800\\udc00', b'\\udbff\\udfff', b'\\ud800a', b'\\x41', b'\\u000g', b'\\/'):
        yield 'string-unicode-escape', frame(1, encoded(dict(RECORD, owner='ESCAPE')).replace(b'ESCAPE', escape))
    for raw_directory in (b'{}', b'[]', b'[0]', b'[0,0]', b'[0,0,0]', b'{"device":0,"inode":0}',
                          b'{"inode":0,"device":0}', b'{"device":0,"inode":0,"other":0}',
                          b'{"device":0,"device":1,"inode":0}', b'{"device":0,"inod\\u0065":0}',
                          b'{"device":null,"inode":0}', b'false', b'null'):
        for key in ('root', 'legacy', 'store', 'archive'):
            value = dict(ANCHOR);value[key] = 'DIRECTORY'
            yield 'directory-map-or-sequence', frame(2, encoded(value).replace(b'"DIRECTORY"', raw_directory))
        value = dict(ANCHOR, shards=['DIRECTORY'])
        yield 'shard-map-or-sequence', frame(2, encoded(value).replace(b'"DIRECTORY"', raw_directory))
    for count in (0, 1, 16, 255, 256, 257, 4096, 16000):
        yield 'all-shard-counts', frame(2, encoded(dict(ANCHOR, shards=[[0, 0]] * count)))
    for kind, base, maximum in ((1, RECORD, 98304), (2, ANCHOR, 98304), (3, MARKER, 1024)):
        raw = encoded(base)
        for length in (maximum - 1, maximum, maximum + 1):
            yield 'raw-size-boundary', frame(kind, raw + b' ' * (length - len(raw)))
    valid = frame(1, encoded(RECORD))
    for length in range(24):
        yield 'short-frame', valid[:length]
    for offset, word in ((0, 0), (8, 0), (8, 4), (16, 0), (16, (1 << 64) - 1)):
        changed = bytearray(valid);struct.pack_into('<Q', changed, offset, word)
        yield 'bad-frame-word', bytes(changed)
    for removed in range(1, 12):
        yield 'truncated-frame', valid[:-removed]
