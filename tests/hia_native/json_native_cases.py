"""Deterministic byte corpora for the independently replayed serde owners."""
from __future__ import annotations

import hashlib
import itertools
import json
import random
import struct
from pathlib import Path

INVALID = 0xFFFFFFFF
CAPACITY = 0xFFFFFFFE
UNKNOWN = object()


def frame(magic: bytes, operation: int, raw: bytes) -> bytes:
    return magic + struct.pack('<QQ', operation, len(raw)) + raw


def fence_frame(kind: int, raw: bytes) -> bytes:
    return frame(b'HFEJSON1', kind, raw)


def value_frame(operation: int, raw: bytes) -> bytes:
    return frame(b'HSJVAL01', operation, raw)


def encode(value, *, ascii=False):
    return json.dumps(value, ensure_ascii=ascii, separators=(',', ':')).encode('utf-8')


def projection(kind, fields, epoch=0):
    flags = (int(fields[4] is not None) if kind == 1 else
             int(fields[2] is not None) | (int(fields[3] is not None) << 1))
    out = bytearray(128)
    out[:8] = b'HFEJRS01'
    struct.pack_into('<QQQ', out, 8, kind, flags, epoch)
    for i, field in enumerate(fields):
        if field is not None:
            raw = field.encode('utf-8')
            struct.pack_into('<QQ', out, 32 + 16 * i, len(out), len(raw))
            out += raw
    return bytes(out)


OWNER = {'schema': 'schema', 'owner': 'v4', 'epoch': 7,
         'phase': 'admitting', 'state_root': '/state'}
LEGACY = {'id': 'job', 'host': 'main'}
OWNER_FIELDS = tuple(OWNER) + ('predecessor_state_root',)
LEGACY_FIELDS = tuple(LEGACY) + ('idempotency_key', 'request_digest')


def typed_expected(kind, value):
    if kind == 1:
        return projection(1, [value['schema'], value['owner'], value['phase'],
                              value['state_root'], value.get('predecessor_state_root')],
                          value['epoch'])
    return projection(2, [value['id'], value['host'], value.get('idempotency_key'),
                          value.get('request_digest')])


def fence_cases():
    """No Python floating-point parsing supplies an expected serde result."""
    for kind, base, names in [(1, OWNER, OWNER_FIELDS), (2, LEGACY, LEGACY_FIELDS)]:
        optional = names[5:] if kind == 1 else names[2:]
        for option_values in itertools.product([None, '', 'old/\x00\n雪😀'], repeat=len(optional)):
            value = dict(base)
            value.update(zip(optional, option_values))
            expected = typed_expected(kind, value)
            for ascii in (False, True):
                yield 'typed-options', fence_frame(kind, encode(value, ascii=ascii)), expected
            array = [value[name] for name in names]
            yield 'typed-sequence', fence_frame(kind, encode(array)), expected
        with_options = dict(base)
        with_options.update((name, '') for name in optional)
        for permutation in itertools.permutations(with_options):
            value = {key: with_options[key] for key in permutation}
            yield 'field-order', fence_frame(kind, encode(value)), typed_expected(kind, value)
        for key in names:
            value = dict(with_options)
            value.pop(key)
            expected = typed_expected(kind, value) if key in optional else INVALID
            yield 'missing-field', fence_frame(kind, encode(value)), expected
            for bad in [None, False, True, 1, -1, 0.0, [], {}]:
                value = dict(with_options)
                value[key] = bad
                valid = ((kind == 1 and key == 'epoch' and type(bad) is int and bad >= 0)
                         or (key in optional and bad is None))
                expected = typed_expected(kind, value) if valid else INVALID
                yield 'typed-field-domain', fence_frame(kind, encode(value)), expected
            for first, second in [(b'null', b'null'), (b'""', b'null'),
                                  (b'null', b'""'), (b'"x"', b'"y"')]:
                parts = [encode(k) + b':' + encode(v) for k, v in base.items() if k != key]
                parts += [encode(key) + b':' + first, encode(key) + b':' + second]
                yield 'duplicate-known', fence_frame(kind, b'{' + b','.join(parts) + b'}'), INVALID
            key_escaped = b'"' + b''.join(f'\\u{ord(ch):04x}'.encode() for ch in key) + b'"'
            raw = encode(with_options)[:-1] + b',' + key_escaped + b':null}'
            yield 'escaped-duplicate-known', fence_frame(kind, raw), INVALID
        array = [with_options[k] for k in names]
        for length in range(len(array) + 3):
            candidate = (array + ['extra', None])[:length]
            valid = length in ([5, 6] if kind == 1 else [4])
            yield 'sequence-length', fence_frame(kind, encode(candidate)), (
                typed_expected(kind, dict(zip(names, candidate))) if valid else INVALID)
        for raw in [b'null', b'true', b'false', b'0', b'"x"', b'[]', b'{}', b'',
                    b'{} {}', b'\xef\xbb\xbf{}', b'\x00', b'\xff', b'NaN']:
            yield 'root-domain', fence_frame(kind, raw), INVALID
        for extra in [b',}', b'}x', b'} []', b'}\x00', b'}\xc2\xa0']:
            yield 'trailing-data', fence_frame(kind, encode(base)[:-1] + extra), INVALID
        for whitespace in [b'', b' ', b'\t\r\n', b' ' * 200]:
            yield 'whitespace', fence_frame(kind, whitespace + encode(base) + whitespace), typed_expected(kind, base)

    chars = ['\x00', '\b\f\n\r\t', '"\\/', '\x1f\x7f\x80', 'é雪😀',
             '\u2028\u2029', '\ue000\U00010000\U0010ffff', 'a' * 257]
    for kind, base, names in [(1, OWNER, OWNER_FIELDS), (2, LEGACY, LEGACY_FIELDS)]:
        for key in names:
            if key == 'epoch':
                continue
            for text in chars:
                value = dict(base)
                value[key] = text
                for ascii in (False, True):
                    yield 'decoded-strings', fence_frame(kind, encode(value, ascii=ascii)), typed_expected(kind, value)
        for raw_byte in range(256):
            raw = encode(base)[:-1] + b',"' + bytes([raw_byte]) + b'":null}'
            yield 'unknown-field-key-byte', fence_frame(kind, raw), UNKNOWN

    for epoch in [b'0', b'1', b'18446744073709551615', b'18446744073709551616',
                  b'-0', b'-1', b'0.0', b'1.0', b'0e0', b'1e0', b'1e9999',
                  b'01', b'1.', b'+1', b'999999999999999999999999999999999']:
        raw = encode(OWNER).replace(b'"epoch":7', b'"epoch":' + epoch)
        valid = epoch in (b'0', b'1', b'18446744073709551615')
        value = dict(OWNER)
        if valid:
            value['epoch'] = int(epoch)
        yield 'epoch-domain', fence_frame(1, raw), typed_expected(1, value) if valid else INVALID

    odd_strings = [b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\ud800"', b'"\\ud800x"',
                   b'"\\ud800\\udc00"', b'"\\udbff\\udfff"', b'"\\u0000"', b'"\\uZZZZ"',
                   b'"\\u123"', b'"\\x00"', b'"\xc0\x80"', b'"\xed\xa0\x80"',
                   b'"\xf4\x90\x80\x80"', b'"\xf0\x90\x80\x80"']
    for value in odd_strings:
        for field in [b'id', b'unknown']:
            raw = b'{"host":"main","' + field + b'":' + value
            if field == b'unknown':
                raw += b',"id":"job"'
            yield 'known-versus-ignored-string', fence_frame(2, raw + b'}'), UNKNOWN
        raw = b'{"id":"job","host":"main",' + value + b':null}'
        yield 'unknown-key-unicode', fence_frame(2, raw), UNKNOWN
        raw = b'{"id":"job","host":"main","x":{' + value + b':null}}'
        yield 'ignored-object-key-unicode', fence_frame(2, raw), UNKNOWN
    for b in range(256):
        raw = b'{"id":"job","host":"main","x":"' + bytes([b]) + b'"}'
        yield 'ignored-string-byte', fence_frame(2, raw), UNKNOWN
    ignored = [b'0', b'-0', b'1e9999', b'-1e9999999999999999999999999999999999',
               b'184467440737095516160000000000000000', b'[]', b'{}', b'null',
               b'true', b'false', b'{"x":1,"x":2}', b'{"\xff":"\xed\xa0\x80"}',
               b'01', b'-01', b'+1', b'.1', b'1.', b'1e', b'1e+', b'1e-',
               b'[1,]', b'{"x":0,}', b'[}', b'{]', b'\xff', b'?', b'']
    for raw_value in ignored:
        for prefix, suffix in [(b'', b''), (b'[', b']'), (b'{"a":', b'}')]:
            raw = b'{"id":"job","host":"main","x":' + prefix + raw_value + suffix + b'}'
            yield 'ignored-grammar', fence_frame(2, raw), UNKNOWN
    for depth in [1, 2, 126, 127, 128, 129, 256, 1024, 4096, 65536]:
        raw = b'{"id":"job","host":"main","x":' + b'[' * depth + b'0' + b']' * depth + b'}'
        yield 'ignored-depth', fence_frame(2, raw), typed_expected(2, LEGACY)
    raw = b'{"id":"job","host":"main","x":null,"x":1e9999}'
    yield 'unknown-duplicate', fence_frame(2, raw), typed_expected(2, LEGACY)

    # The Rust replay, rather than a permissive Python parser, decides mutations.
    seeds = [(1, encode(OWNER)), (1, encode(['s', 'o', 1, 'p', 'r', None])),
             (2, encode(LEGACY)), (2, b'["j","h",null,null]'),
             (2, b'{"id":"j","host":"h","x":[{"a":1},true,null]}')]
    replacements = [0, 9, 34, 44, 58, 91, 93, 123, 125, 255]
    for kind, seed in seeds:
        for index in range(len(seed)):
            yield 'delete-one-byte', fence_frame(kind, seed[:index] + seed[index + 1:]), UNKNOWN
            for ch in replacements:
                yield 'replace-one-byte', fence_frame(kind, seed[:index] + bytes([ch]) + seed[index + 1:]), UNKNOWN
        for index in range(len(seed) + 1):
            for ch in [b' ', b',', b'"', b'\xff']:
                yield 'insert-one-byte', fence_frame(kind, seed[:index] + ch + seed[index:]), UNKNOWN

    for kind, base, limit in [(1, OWNER, 4096), (2, LEGACY, 1 << 20)]:
        for size in [limit - 1, limit, limit + 1]:
            raw = encode(base)
            raw += b' ' * (size - len(raw))
            yield 'raw-byte-limit', fence_frame(kind, raw), typed_expected(kind, base) if size <= limit else INVALID
        value = dict(base)
        name = 'state_root' if kind == 1 else 'id'
        value[name] = ''
        value[name] = 'a' * (limit - len(encode(value)))
        yield 'decoded-string-at-limit', fence_frame(kind, encode(value)), typed_expected(kind, value)


def numeric_cases():
    fixed = [b'0', b'-0', b'0.0', b'-0.0', b'1e-5', b'1e-6', b'1e15', b'1e16',
             b'1e-999999999999', b'0e999999999999', b'-0e999999999999', b'1e999999999999',
             b'1.7976931348623157e308', b'1.7976931348623159e308',
             b'2.2250738585072014e-308', b'2.4703282292062327e-324',
             b'2.4703282292062328e-324', b'5e-324', b'1e-324',
             b' 1 \r\n', b'', b'-', b'+0', b'01', b'-01', b'00.1', b'1.',
             b'.1', b'1e', b'1e+', b'1e-', b'NaN', b'Infinity', b'null',
             b'[]', b'{}', b'1 2', b'1x', b'1\x00', b'\xff']
    for raw in fixed:
        yield 'numeric-fixed', value_frame(2, raw)
    for boundary in [-(1 << 64), -(1 << 63), 0, (1 << 63), (1 << 64)]:
        for delta in range(-65, 66):
            yield 'integer-boundary', value_frame(2, str(boundary + delta).encode())
    rng = random.Random(0x5345524445313531)
    for digits in [1, 17, 18, 19, 20, 21, 50, 100, 400, 800, 801, 1200]:
        for _ in range(80):
            n = str(rng.randrange(1, 10)) + ''.join(str(rng.randrange(10)) for _ in range(digits - 1))
            point = rng.randrange(len(n) + 1)
            value = n[:point] + '.' + n[point:] if 0 < point < len(n) else n
            value += 'e' + str(rng.choice([-2147483649, -2147483648, -5000, -1000, -400, -324,
                                          -308, -17, -6, -5, 0, 15, 16, 308, 400, 1000,
                                          2147483647, 2147483648]))
            if rng.randrange(2):
                value = '-' + value
            yield 'long-decimal', value_frame(2, value.encode())
    bit_patterns = {0, 1 << 63, 1, (1 << 63) | 1, (1 << 52) - 1, 1 << 52,
                    0x7FEFFFFFFFFFFFFF, 0xFFEFFFFFFFFFFFFF, 0x7FF0000000000000,
                    0x7FF8000000000000, 0xFFF0000000000000}
    for exponent in range(1, 2047):
        value = exponent << 52
        bit_patterns.update([value - 1, value, value + 1, (1 << 63) | value])
    bit_patterns.update(rng.getrandbits(64) for _ in range(4096))
    bit_patterns.update(rng.randrange(1 << 52) for _ in range(512))
    for bits in sorted(bit_patterns):
        yield 'binary64-format', value_frame(3, struct.pack('<Q', bits))

def value_cases():
    fixed = [b'null', b'true', b'false', b'0', b'-0', b'1', b'-1', b'[]', b'{}',
             b'""', b'"\\u0000\\b\\f\\n\\r\\t\\/"', b'  [true, false, null]  ',
             b'{"b":0,"a":1}', b'{"a":0,"a":1}', b'{"a":0,"\\u0061":1}',
             b'{"":[],"":{}}', b'{"a":{"z":0,"z":1},"a":[1,2]}',
             b'{"a":1e9999,"a":0}', b'{"a":0,"a":1e9999}',
             b'{"a":"\\ud800","a":0}', b'{"a":0,"a":"\\ud800"}',
             b'[9223372036854775807,9223372036854775808,18446744073709551615,18446744073709551616]',
             b'[-9223372036854775808,-9223372036854775809,-18446744073709551616]',
             b'[1e-5,1e-6,1e15,1e16,1e-324,5e-324,1e308,-0.0]',
             b'1e99999999999999', b'0e99999999999999', b'-0e99999999999999',
             b'1e-99999999999999', b'-1e-99999999999999']
    invalid = [b'', b' ', b'\x00', b'\xff', b'\xef\xbb\xbfnull', b'NaN', b'Infinity',
               b'01', b'-01', b'+1', b'1.', b'.1', b'1e', b'1e+', b'1e-', b'--1',
               b'nulltrue', b'{}[]', b'[1,]', b'{"a":1,}', b'{1:2}', b'{true:0}',
               b'{null:0}', b'{"a" 1}', b'[}', b'{]', b'"\\uZZZZ"', b'"\\x41"']
    for raw in fixed:
        yield 'value-fixed', value_frame(1, raw), UNKNOWN
    for raw in invalid:
        yield 'value-invalid', value_frame(1, raw), INVALID
    for raw_byte in range(256):
        raw = b'"' + bytes([raw_byte]) + b'"'
        yield 'string-byte', value_frame(1, raw), UNKNOWN
        yield 'object-key-byte', value_frame(1, b'{' + raw + b':null}'), UNKNOWN
    unicode_strings = ['', '\x00\b\f\n\r\t\x1f', '"\\/', '\x7f\x80\u07ff\u0800',
                       'é雪😀', '\ud7ff\ue000\uffff\U00010000\U0010ffff', '\u2028\u2029']
    for text in unicode_strings:
        expected = encode(text)
        for ascii in (False, True):
            yield 'unicode-encoding', value_frame(1, encode(text, ascii=ascii)), expected
    for raw in [b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\ud800"', b'"\\ud800x"',
                b'"\\ud800\\udc00"', b'"\\udbff\\udfff"', b'"\xc0\x80"',
                b'"\xed\xa0\x80"', b'"\xf4\x90\x80\x80"', b'"\xf0\x90\x80\x80"']:
        yield 'unicode-boundary', value_frame(1, raw), UNKNOWN
    keys = ['', '\x00', 'a', 'a\x00', 'aa', 'z', 'é', '雪', '\ue000', '😀', '\U0010ffff']
    rng = random.Random(0x56414C5545313531)
    for _ in range(64):
        rng.shuffle(keys)
        parts = []
        values = {}
        for i in range(32):
            key = rng.choice(keys)
            value = {'b': i, 'a': [None, False, True, i - 10]}
            parts.append(encode(key, ascii=bool(rng.randrange(2))) + b':' + encode(value))
            values[key] = value
        raw = b'{' + b','.join(parts) + b'}'
        expected = json.dumps(values, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()
        yield 'stable-last-wins-btree', value_frame(1, raw), expected
    for depth in [1, 2, 125, 126, 127, 128, 129, 256]:
        for prefix, suffix in [(b'[', b']'), (b'{"a":', b'}')]:
            raw = prefix * depth + b'null' + suffix * depth
            yield 'value-depth', value_frame(1, raw), raw if depth <= 127 else INVALID

    def random_value(depth):
        choices = [None, False, True, rng.randint(-(1 << 63), (1 << 64) - 1), rng.choice(unicode_strings)]
        if depth == 0:
            return rng.choice(choices)
        mode = rng.randrange(4)
        if mode == 0:
            return [random_value(depth - 1) for _ in range(rng.randrange(8))]
        if mode == 1:
            return {rng.choice(keys): random_value(depth - 1) for _ in range(rng.randrange(8))}
        return rng.choice(choices)

    for _ in range(512):
        value = random_value(4)
        raw = json.dumps(value, ensure_ascii=bool(rng.randrange(2)), indent=rng.choice([None, 1])).encode()
        expected = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        yield 'integer-unicode-structures', value_frame(1, raw), expected

    seeds = [b'null', b'[true,false,null]', b'{"a":0,"a":1,"z":["x",1.25]}',
             b'"\\ud83d\\ude00"', b'[0,1e-5,-0,18446744073709551616]']
    for seed in seeds:
        for index in range(len(seed)):
            yield 'value-byte-deletion', value_frame(1, seed[:index] + seed[index + 1:]), UNKNOWN
            for ch in [0, 9, 32, 34, 44, 48, 58, 91, 93, 123, 125, 255]:
                raw = seed[:index] + bytes([ch]) + seed[index + 1:]
                yield 'value-byte-replacement', value_frame(1, raw), UNKNOWN
        for index in range(len(seed) + 1):
            for ch in [b' ', b',', b'"', b'\xff']:
                yield 'value-byte-insertion', value_frame(1, seed[:index] + ch + seed[index:]), UNKNOWN
    for size in [1, 17, 18, 19, 20, 50, 100, 400, 800, 801, 1200]:
        for _ in range(40):
            digits = str(rng.randrange(1, 10)) + ''.join(str(rng.randrange(10)) for _ in range(size - 1))
            exponent = rng.choice([-9999, -324, -308, -17, -6, -5, 0, 15, 16, 308, 9999])
            raw = (rng.choice(['', '-']) + digits + 'e' + str(exponent)).encode()
            yield 'value-decimal-boundaries', value_frame(1, b'[' + raw + b']'), UNKNOWN


class Corpus:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=False)
        self.directory = directory
        self.requests = (directory / 'requests.hex').open('wb')
        self.outputs = (directory / 'native-output.txt').open('wb')
        self.labels = (directory / 'categories.txt').open('w')
        self.count = 0
        self.categories = {}

    def record(self, category, request, code, output):
        self.requests.write(request.hex().encode('ascii') + b'\n')
        self.outputs.write(f'{code:08x}:'.encode('ascii') + output.hex().encode('ascii') + b'\n')
        self.labels.write(category + '\n')
        self.count += 1
        self.categories[category] = self.categories.get(category, 0) + 1

    def close(self, metadata):
        self.requests.close()
        self.outputs.close()
        self.labels.close()
        result = dict(metadata, cases=self.count, categories=self.categories)
        for name, key in [('requests.hex', 'requests'), ('native-output.txt', 'native_output')]:
            path = self.directory / name
            result[key + '_file'] = name
            with path.open('rb') as source:
                result[key + '_sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
            result[key + '_bytes'] = path.stat().st_size
        (self.directory / 'native-corpus.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        return result
