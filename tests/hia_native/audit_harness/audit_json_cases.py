"""Audit typed metadata cases including u128 and exact identity tuples."""
import copy
import itertools
import json
import random
import struct

STATES = ('unknown', 'completed', 'failed')
RECORD = dict(request_id='a1' * 32, owner='b2' * 32, tool_name='host_list',
    state='unknown', accepted_unix_ms=(1 << 128) - 1, elapsed_ms=(1 << 64) - 1)
LEGACY = dict(root_device=123, root_inode=(1 << 64) - 1, archive_device=0, archive_inode=9)
ANCHOR = dict(format=12, root=[0, 1], legacy=[2, 3], archive=[4, 5], shards=[[6, 7], [8, 9]])
INTENT = dict(format=12, root=[0, 1], legacy=[2, 3], archive=None, shards=[])
BASES = (RECORD, LEGACY, ANCHOR, INTENT)


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def frame(kind, raw):
    return b'HRAJQ001' + struct.pack('<2Q', kind, len(raw)) + raw


def cases():
    bases = BASES
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
    for state in ('Unknown', 'stored', '', 'failed\0', '主机', 1, ['completed'], {}, {'unknown': None, 'failed': None}):
        yield 'invalid-enum', frame(1, encoded(dict(RECORD, state=state)))
    for kind, base, key in ((1, RECORD, 'elapsed_ms'), (4, INTENT, 'archive')):
        for value in (None, 0, [0, 0]):
            row = dict(base, **{key: value})
            yield 'optional-present', frame(kind, encoded(row))
            yield 'optional-present-sequence', frame(kind, encoded(list(row.values())))
        row = dict(base)
        del row[key]
        yield 'optional-omitted', frame(kind, encoded(row))
    numbers = [b'-0', b'-1', b'1.0', b'1e0', b'01', b'+1', b'1.', b'1e', b'null', b'false',
        b'"0"', b'[]', b'{}', b'0e99999', b'1e99999', b'9' * 1800]
    numbers += [str(value).encode() for bits in (8, 32, 64, 96, 127, 128)
        for value in ((1 << bits) - 1, 1 << bits, (1 << bits) + 1)]
    for number in numbers:
        for kind, base, key in ((1, RECORD, 'accepted_unix_ms'), (1, RECORD, 'elapsed_ms'),
            (2, LEGACY, 'archive_inode'), (3, ANCHOR, 'format'), (4, INTENT, 'format')):
            raw = encoded(dict(base, **{key: 'NUMBER'})).replace(b'"NUMBER"', number)
            yield 'typed-integer-' + key, frame(kind, raw)
        for pair in (b'[' + number + b',0]', b'[0,' + number + b']'):
            yield 'tuple-u64', frame(3, encoded(dict(ANCHOR, root='PAIR')).replace(b'"PAIR"', pair))
    rng = random.Random(0x4155444954)
    for index in range(512):
        row = dict(RECORD, accepted_unix_ms=rng.getrandbits(128), elapsed_ms=rng.getrandbits(64),
            request_id=hex(rng.getrandbits(256)), state=STATES[index % len(STATES)])
        yield 'random-u128', frame(1, encoded(row))
        yield 'random-u128-sequence', frame(1, encoded(list(row.values())))
    for value in ('', 'a', '"\\\n\t\r\0', '汉😀', '\u2028\u2029', 'e\u0301', 'é'):
        row = dict(RECORD)
        for key in ('request_id', 'owner', 'tool_name'):
            row[key] = value
        yield 'unicode-record', frame(1, encoded(row))
    for byte in range(256):
        row = dict(RECORD, request_id='STRING')
        yield 'raw-single-byte-string', frame(1, encoded(row).replace(b'STRING', bytes([byte])))
        yield 'escaped-single-byte-string', frame(1, encoded(row).replace(b'STRING', ('\\u%04x' % byte).encode()))
    for escape in (b'\\ud800', b'\\udfff', b'\\ud800\\udc00', b'\\udbff\\udfff', b'\\ud800a', b'\\x41', b'\\u000g', b'\\/'):
        yield 'string-unicode-escape', frame(1, encoded(dict(RECORD, owner='ESCAPE')).replace(b'ESCAPE', escape))
    for pair in (b'{}', b'[]', b'[0]', b'[0,0]', b'[0,0,0]', b'{"device":0,"inode":0}',
        b'{"0":0,"1":0}', b'[null,0]', b'[0,null]', b'[false,0]', b'false', b'null'):
        for kind, base in ((3, ANCHOR), (4, INTENT)):
            for key in ('root', 'legacy', 'archive'):
                yield 'identity-tuple', frame(kind, encoded(dict(base, **{key: 'PAIR'})).replace(b'"PAIR"', pair))
            yield 'shard-tuple', frame(kind, encoded(dict(base, shards=['PAIR'])).replace(b'"PAIR"', pair))
    for count in (0, 1, 16, 255, 256, 257, 4096, 10000, 11000):
        for kind, base in ((3, ANCHOR), (4, INTENT)):
            yield 'all-shard-counts', frame(kind, encoded(dict(base, shards=[[0, 0]] * count)))
    for kind, base in enumerate(BASES, 1):
        maximum = 2048 if kind <= 2 else 65536
        raw = encoded(base)
        for count in (maximum - 1, maximum, maximum + 1):
            yield 'raw-size-boundary', frame(kind, raw + b' ' * (count - len(raw)))
    valid = frame(1, encoded(RECORD))
    for length in range(24):
        yield 'short-frame', valid[:length]
    for offset, word in ((0, 0), (8, 0), (8, 5), (16, 0), (16, (1 << 64) - 1)):
        changed = bytearray(valid)
        struct.pack_into('<Q', changed, offset, word)
        yield 'bad-frame-word', bytes(changed)
    for removed in range(1, 12):
        yield 'truncated-frame', valid[:-removed]
