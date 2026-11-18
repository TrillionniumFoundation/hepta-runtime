# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Deterministic raw inputs; this file is not a JSON semantic reference."""
import json
import math
import random
import struct

MAXIMUM = 8388608
TOKEN = '$serde_json::private::RawValue'


def unicode_cases():
    for value in range(65536):
        yield ('unicode-u16', f'"\\u{value:04x}"'.encode())
    for first in range(0xD800, 0xDC00, 17):
        for second in range(0xDC00, 0xE000, 31):
            yield ('surrogate-pairs', f'"\\u{first:04X}\\u{second:04x}"'.encode())
    for raw in (b'\xc2', b'\xe0\xa0', b'\xed\xa0\x80', b'\xf0\x90\x80', b'\xf4\x90\x80\x80', b'\xff'):
        for tail in (b'"', b'', b'\\n"', b'\\x"', b'\0"', b'\n"', b'\\uD800"', b'\\uDC00"', b'\\u0q00"'):
            yield ('utf8-error-order', b'"prefix' + raw + tail)


def mutation_cases():
    seeds = [b'null', b'true', b'false', b'[0]', b'{"a":0}', b'[true,false,null]',
        b'{"a":[0,{}],"b":"x"}', b'"\\uD800\\uDC00"', b'"a\\nb"', b'1.0e-10',
        b'{"$serde_json::private::RawValue":"[]"}', b'{"a":0,"$serde_json::private::RawValue":"["}']
    alphabet = bytes([0, 9, 10, 13, 32, 34, 44, 45, 46, 48, 49, 58, 91, 92, 93,
        97, 101, 102, 108, 110, 114, 116, 117, 123, 125, 127, 128, 192, 194, 224, 237, 240, 244, 255])
    for seed in seeds:
        for at in range(len(seed) + 1):
            yield ('all-prefixes', seed[:at])
            for value in alphabet:
                yield ('byte-insertion', seed[:at] + bytes([value]) + seed[at:])
                if at < len(seed):
                    yield ('byte-replacement', seed[:at] + bytes([value]) + seed[at+1:])
    randomizer = random.Random(0x151229)
    for _ in range(4096):
        size = randomizer.randrange(1, 160)
        yield ('arbitrary-bytes', bytes(randomizer.randrange(256) for _ in range(size)))
    for prefix in (b'\n', b'\r', b'\r\n', b' \t\n\r', b'\n'*10, b' '*19 + b'\n' + b'\t'*6):
        for raw in seeds:
            yield ('line-column-prefix', prefix + raw + b'\n#')


def number_cases():
    randomizer = random.Random(0xF64151)
    for _ in range(4096):
        bits = randomizer.getrandbits(64)
        if bits >> 52 & 0x7FF == 0x7FF:
            bits ^= 1 << 52
        number = struct.unpack('<d', struct.pack('<Q', bits))[0]
        assert math.isfinite(number)
        raw = repr(number).encode()
        yield ('finite-f64', raw)
        yield ('raw-unexpected-f64', b'{"' + TOKEN.encode() + b'":' + raw + b'}')
    for value in (0, 1, (1<<31)-1, 1<<31, (1<<63)-1, 1<<63, (1<<63)+1,
            (1<<64)-1, 1<<64, (1<<64)+1):
        for sign in (b'', b'-'):
            raw = sign + str(value).encode()
            yield ('integer-boundary', raw)
            yield ('raw-integer-boundary', b'{"' + TOKEN.encode() + b'":' + raw + b'}')
    for value in (b'0', b'1', b'-0', b'-1', b'0.0', b'0.0001', b'18446744073709551616', b'9'*309):
        for exponent in (b'0', b'308', b'309', b'324', b'325', b'2147483647', b'2147483648', b'2147483649', b'9'*25):
            for sign in (b'', b'+', b'-'):
                for tail in (b'', b'000more', b'\n,'):
                    yield ('exponent-position', value + b'e' + sign + exponent + tail)
    for _ in range(2048):
        digits = ''.join(str(randomizer.randrange(10)) for _ in range(randomizer.randrange(1, 500)))
        raw = ('-' if randomizer.randrange(2) else '') + str(randomizer.randrange(1, 10)) + '.' + digits
        raw += 'e' + str(randomizer.randrange(-1000, 1001))
        yield ('decimal-roundtrip', raw.encode())
    boundary = (1 << 1024) - (1 << 970)
    for distance in range(-16, 17):
        raw = str(boundary + distance).encode()
        for sign in (b'', b'-'):
            yield ('maximum-finite-rounding', sign + raw)
            yield ('maximum-finite-decimal', sign + raw[:1] + b'.' + raw[1:] + b'e308')
    for exponent in range(-326, 310):
        for digit in (b'1', b'5', b'9'):
            yield ('decimal-exponent-domain', digit + b'e' + str(exponent).encode())


def raw_value_cases():
    token = TOKEN.encode()
    errors = [b'', b' ', b'\n', b'[', b'{', b'0#', b'"\\uD800"', b'"\\uDC00"',
        b'1e309', b'1e2147483648000tail', b'[1,]', b'{"a":1,}', b'\n\n{"x":\n}',
        b'"escaped\\ntext"', b'null', b'[0,true,{}]', b'{"a":0,"a":1}']
    for raw in errors:
        value = raw.decode('ascii')
        for depth in range(1, 9):
            value = json.dumps({TOKEN: value}, separators=(',', ':'))
            yield ('nested-raw-values', value.encode())
        first = b'{"' + token + b'":' + json.dumps(raw.decode('ascii')).encode()
        for suffix in (b'}', b'', b',}', b',"x":0}', b'#', b'\n#', b'}#'):
            yield ('raw-inner-first-error', first + suffix)
    for depth in (0, 1, 125, 126, 127, 128, 129):
        value = '[' * depth + '0' + ']' * depth
        for outer in (0, 1, 126, 127):
            raw = json.dumps({TOKEN: value}, separators=(',', ':')).encode()
            yield ('independent-raw-recursion', b'['*outer + raw + b']'*outer)
        value = '{"k":'*depth + '0' + '}'*depth
        yield ('raw-object-recursion', json.dumps({TOKEN:value}, separators=(',', ':')).encode())
    for at in range(len(token)):
        key = token[:at] + ('\\u%04x' % token[at]).encode() + token[at+1:]
        yield ('escaped-raw-key', b'{"' + key + b'":"["}')
        yield ('second-raw-key-is-ordinary', b'{"other":0,"' + key + b'":"["}')
    for key in (token+b'x', b'x'+token, token[:-1], token.replace(b'Value',b'value'), b'', b'\xff'):
        yield ('near-raw-key', b'{"'+key+b'":"["}')
    for value in (b'null', b'true', b'false', b'[]', b'{}', b'[', b'{', b'-', b'1e', b'nul', b'#'):
        for prefix in (b'', b'\n\n'):
            yield ('raw-unexpected-type-position', prefix+b'{"'+token+b'":\n'+value+b'}')


def wide_cases():
    n = MAXIMUM
    yield ('wide-whitespace-valid', b' '*(n-4)+b'null')
    yield ('wide-whitespace-eof', b'\n'*n)
    yield ('wide-string-valid', b'"'+b'x'*(n-2)+b'"')
    yield ('wide-string-invalid-utf8', b'"'+b'x'*(n-3)+b'\xff"')
    yield ('wide-number-zero-fraction', b'0.'+b'0'*(n-2))
    yield ('wide-number-underflow', b'0.'+b'0'*(n-3)+b'1')
    yield ('wide-exponent-underflow', b'1e-'+b'9'*(n-3))
    yield ('wide-array-repeated-number', b'['+b'0,'*((n-4)//2)+b'0] ')
    start = b'{"'+TOKEN.encode()+b'":"'
    tail = b'"}'
    yield ('wide-raw-inner-eof', start+b' '*(n-len(start)-len(tail))+tail)
    body = json.dumps({TOKEN:'['},separators=(',',':')).encode()
    yield ('wide-raw-trailing-ignored-error', body+b' '*(n-len(body)))


GENERATORS = {'unicode': unicode_cases, 'mutation': mutation_cases, 'number': number_cases,
    'raw_value': raw_value_cases, 'wide': wide_cases}
