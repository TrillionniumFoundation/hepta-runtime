"""Locked serde raw_value first-key inputs; ordinary reference corpora stay intact."""
from __future__ import annotations
import json
import struct
from json_native_cases import INVALID, UNKNOWN, numeric_cases, value_cases, value_frame

TOKEN = '$serde_json::private::RawValue'


def wrap(raw: bytes, key: bytes | None = None) -> bytes:
    encoded = json.dumps(raw.decode('utf-8'), ensure_ascii=True, separators=(',', ':')).encode()
    return b'{' + (json.dumps(TOKEN).encode() if key is None else key) + b':' + encoded + b'}'


def raw_value_cases():
    # Every UTF-8-representable payload from the existing complete Value domain.
    for category, wire, _ in value_cases():
        if len(wire) < 24:
            continue
        payload = wire[24:]
        try:
            wrapped = wrap(payload)
        except UnicodeDecodeError:
            continue
        yield 'wrapped-value/' + category, value_frame(1, wrapped), UNKNOWN
    # Retain every UTF-8-representable lexical-number payload through Value and Number.
    # Invalid UTF-8 has no decoded JSON-string representation; the ordinary corpus retains it.
    for category, wire in numeric_cases():
        if struct.unpack_from('<Q', wire, 8)[0] != 2:
            continue
        try:
            wrapped = wrap(wire[24:])
        except UnicodeDecodeError:
            continue
        yield 'wrapped-number/' + category, value_frame(1, wrapped), UNKNOWN
        yield 'wrapped-number-projection/' + category, value_frame(2, wrapped), UNKNOWN
    values = [(b'null', b'null'), (b'true', b'true'), (b'false', b'false'),
              (b'0', b'0'), (b'-0', b'-0.0'), (b'1e15', b'1000000000000000.0'),
              (b'"text"', b'"text"'), (b'[]', b'[]'), (b'{}', b'{}'),
              (b'{"b":2,"a":1,"b":3}', b'{"a":1,"b":3}')]
    for raw, expected in values:
        for name, prefix, suffix in [('root', b'', b''), ('array', b'[0,', b',1]'),
                                     ('object', b'{"value":', b'}')]:
            yield name, value_frame(1, prefix + wrap(raw) + suffix), prefix + expected + suffix
        yield 'nested', value_frame(1, wrap(wrap(raw))), expected
        yield 'whitespace-inner', value_frame(1, wrap(b' \t\n' + raw + b'\r ')), expected
    for i in range(len(TOKEN)):
        key = ('"' + TOKEN[:i] + '\\u%04x' % ord(TOKEN[i]) + TOKEN[i+1:] + '"').encode()
        yield 'escaped-first-key', value_frame(1, wrap(b'[1]', key)), b'[1]'
        changed = TOKEN[:i] + chr(ord(TOKEN[i]) ^ 1) + TOKEN[i+1:]
        plain = json.dumps({changed: 'not JSON'}, ensure_ascii=True, separators=(',', ':')).encode()
        expected = json.dumps({changed: 'not JSON'}, ensure_ascii=False, separators=(',', ':')).encode()
        yield 'changed-key-is-ordinary', value_frame(1, plain), expected
    raw_key = json.dumps(TOKEN).encode()
    for invalid in [b'', b' ', b'01', b'null true', b'1e9999', b'[', b'{"x":}', b'"\\ud800"']:
        yield 'invalid-inner', value_frame(1, wrap(invalid)), INVALID
        yield 'invalid-overwritten-inner', value_frame(1, b'{"a":' + wrap(invalid) + b',"a":0}'), INVALID
    for value in [b'null', b'false', b'1', b'[]', b'{}']:
        yield 'non-string-raw-field', value_frame(1, b'{' + raw_key + b':' + value + b'}'), INVALID
    for suffix in [b',"a":0}', b',' + raw_key + b':"2"}']:
        yield 'extra-raw-member', value_frame(1, wrap(b'1')[:-1] + suffix), INVALID
    yield 'later-key-is-ordinary', value_frame(1, b'{"a":0,' + raw_key + b':"bad"}'), b'{' + raw_key + b':"bad","a":0}'
    yield 'valid-overwritten-inner', value_frame(1, b'{"a":' + wrap(b'[1]') + b',"a":0}'), b'{"a":0}'
    yield 'nested-parent-key-custody', value_frame(1, b'{"first":' + wrap(b'{"a":{}}') + b',"last":{}}'), b'{"first":{"a":{}},"last":{}}'
    for outer in [0, 1, 63, 125, 126, 127]:
        for inner in [0, 1, 63, 126, 127, 128]:
            raw = b'[' * outer + wrap(b'[' * inner + b'0' + b']' * inner) + b']' * outer
            expected = INVALID if outer >= 127 or inner >= 128 else b'[' * (outer + inner) + b'0' + b']' * (outer + inner)
            yield 'independent-depth-budgets', value_frame(1, raw), expected
    raw = b'0'
    for depth in range(1, 15):
        raw = wrap(raw)
        yield 'nested-contexts', value_frame(1, raw), b'0'
    for raw in [b'null', b'[]', b'{}', b'"1"']:
        yield 'raw-not-number', value_frame(2, wrap(raw)), INVALID
