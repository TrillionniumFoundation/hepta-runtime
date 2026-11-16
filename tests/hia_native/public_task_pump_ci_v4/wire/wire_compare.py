"""Compare complete public Bellman wire with one explicit clock normalization.

This module performs no execution and does not admit a native build or process.
Its caller must first verify both complete process captures and the unchanged
current-SDK original recipe. All input rows and outcome classifications come
from that original recipe; private typed-parameter expectations are not used.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import struct


NATIVE_MAGIC = b'HBPNRES1'
NATIVE_HEADER = struct.Struct('<8s11Q')
# The successful solver JSON is a JSON string inside the SDK response. Replace
# only the numeric spelling in that string, retaining every other wire byte.
WIRE_CLOCK = re.compile(
    rb'(\\"native_operation_wall_seconds\\":)'
    rb'(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?=[,}])'
)


def pin(raw: bytes) -> dict:
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def checked_clock_wire(raw: bytes) -> tuple[bytes, float]:
    """Return the full wire with only its one successful wall-time number zeroed."""
    assert raw.endswith(b'\n') and raw.count(b'\n') == 1
    message = json.loads(raw)
    result = message['result']
    assert result['isError'] is False and len(result['content']) == 1
    assert set(result['content'][0]) == {'type', 'text'}
    assert result['content'][0]['type'] == 'text'
    value = json.loads(result['content'][0]['text'])
    assert type(value) is dict and len(value) == 36
    elapsed = value['native_operation_wall_seconds']
    assert type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
    matches = list(WIRE_CLOCK.finditer(raw))
    assert len(matches) == 1, 'the complete SDK wire must contain exactly one solver clock'
    match = matches[0]
    parsed = json.loads(match.group(2))
    assert type(parsed) in (int, float) and parsed == elapsed
    return raw[:match.start(2)] + b'0' + raw[match.end(2):], elapsed


def compare_wire(declared: dict, classification: str, original: bytes,
                 native: bytes, before_ns: int, after_ns: int) -> dict:
    """Compare one complete exchange, including both anonymous-error responses."""
    assert type(before_ns) is int and type(after_ns) is int
    assert 0 <= before_ns <= after_ns and after_ns - before_ns <= 60_000_000_000
    assert type(declared['frames']) is int and declared['frames'] in (0, 1, 2)
    for wire in (original, native):
        assert wire.count(b'\n') == declared['frames']
        assert wire.endswith(b'\n') if declared['frames'] else wire == b''
    if classification == 'success':
        assert declared['kind'] == 'case' and declared['frames'] == 1
        expected, _ = checked_clock_wire(original)
        actual, elapsed = checked_clock_wire(native)
        assert elapsed <= (after_ns - before_ns) / 1_000_000_000, 'solver clock exceeds actual public exchange'
        assert actual == expected, (declared['name'], 'complete successful SDK wire differs')
    else:
        assert classification in ('typed', 'business', 'model', 'initialize',
                                  'notification', 'control', 'close')
        assert native == original, (declared['name'], 'complete SDK wire differs')
        actual = native
    return {'sequence': declared['sequence'], 'name': declared['name'],
            'session': declared['session'], 'classification': classification,
            'native_wire': pin(native), 'original_wire': pin(original),
            'normalized_wire': pin(actual), 'before_ns': before_ns,
            'after_ns': after_ns, 'only_normalized_field':
            'native_operation_wall_seconds' if classification == 'success' else None}


def native_records(stream):
    """Read complete observation frames; EOF cannot truncate a header or payload."""
    while raw := stream.read(NATIVE_HEADER.size):
        assert len(raw) == NATIVE_HEADER.size
        magic, *header = NATIVE_HEADER.unpack(raw)
        assert magic == NATIVE_MAGIC
        sequence, opcode, session, input_length, output_length, before, after, journal_before, journal_after, pid, zero = header
        assert opcode in (1, 2) and session in (0, 1) and pid > 0 and zero == 0
        assert 0 <= before <= after and 0 <= journal_before <= journal_after
        payload = stream.read(output_length)
        assert len(payload) == output_length
        yield tuple(header), payload


def native_frame(declared: dict, wire: bytes, before_ns: int, after_ns: int,
                 journal_before: int, journal_after: int, pid: int) -> bytes:
    """Frame actual observation bytes without constructing a tool response."""
    return NATIVE_HEADER.pack(NATIVE_MAGIC, declared['sequence'], declared['opcode'],
        declared['session'], declared['wire']['bytes'], len(wire), before_ns,
        after_ns, journal_before, journal_after, pid, 0) + wire
