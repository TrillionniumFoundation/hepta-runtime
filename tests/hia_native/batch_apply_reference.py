"""Development-only batch model and exact existing Editable method translation."""
from __future__ import annotations
import bisect
import copy
import importlib.util
import json
import os
from pathlib import Path
import random
import struct

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = Path(os.environ.get('HIA_RUNTIME_REPO', str(ROOT)))
spec = importlib.util.spec_from_file_location('editable_reference', RUNTIME / 'tests/hia_native/test_editable_content.py')
editable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(editable)
Editable, incoming, parts = editable.Editable, editable.incoming, editable.parts
PROPERTIES = json.loads((Path(__file__).with_name('rust_debug_properties.json')).read_text())
RANGES = PROPERTIES['ranges']
STARTS = [row[0] for row in RANGES]
WHITESPACE = ''.join(chr(v) for v in [9, 10, 11, 12, 13, 32, 133, 160, 5760, *range(8192, 8203), 8232, 8233, 8239, 8287, 12288])


def debug(raw):
    output = ['"']
    special = {0: '\\0', 9: '\\t', 13: '\\r', 10: '\\n', 34: '\\"', 92: '\\\\'}
    for char in raw.decode():
        code = ord(char)
        if code in special:
            output.append(special[code])
        elif RANGES[bisect.bisect_right(STARTS, code) - 1][2] == 15:
            output.append('\\u{' + format(code, 'x') + '}')
        else:
            output.append(char)
    return ''.join(output) + '"'


def noise(raw):
    value = raw.decode().strip(WHITESPACE)
    return not value or value.rstrip(',;') in ('}', ']', ')')


def logical_lines(normalized):
    return [v[:-2] if v.endswith(b'\r\n') else v[:-1] if v.endswith(b'\n') else v for v in parts(normalized)]


def line_hash(raw):
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    value = (value >> 16) ^ (value & 65535)
    return format((value >> 8) ^ (value & 255), '02x')


def guards(raw, operations):
    lines = logical_lines(Editable(raw).normalized())
    def identity(at):
        return 'the start of the file' if at == 0 else f'{at}:{line_hash(lines[at - 1])}'
    for i, (k1, s1, e1, _) in enumerate(operations):
        for j, (k2, s2, e2, _) in enumerate(operations[i + 1:], i + 1):
            if k1 == k2 == 2 and s1 <= e2 and s2 <= e1:
                return f'Conflicting operations: operation {i} (replace "{identity(s1)}-{identity(e1)}") and {j} (replace "{identity(s2)}-{identity(e2)}") have overlapping ranges'
            if k1 == k2 == 1 and s1 == s2:
                return f'Conflicting operations: operation {i} and {j} both insert after {identity(s1)}'
            if k1 != k2:
                ii, anchor, ri, start, end = (i, s1, j, s2, e2) if k1 == 1 else (j, s2, i, s1, e1)
                if start <= anchor < end:
                    return f'Conflicting operations: operation {ii} inserts after {identity(anchor)}, inside the range operation {ri} replaces ("{identity(start)}-{identity(end)}"). Put those lines in the replacement content instead.'
    for index, (kind, start, end, content) in enumerate(operations):
        values = incoming(content)
        if not values:
            continue
        if kind == 2:
            for yes, at, which, where, value in [
                (start > 1, start - 1, 'first', 'before', values[0]),
                (end < len(lines), end + 1, 'last', 'after', values[-1]),
            ]:
                if yes and value == lines[at - 1] and not noise(value):
                    return f'Duplicate line detected in operation {index}: content\'s {which} line repeats {identity(at)} ({debug(value)}), the line just {where} the range "{identity(start)}"-"{identity(end)}". Give only the replacement lines, not surrounding context; use str_replace if the repeat is intended.'
        elif len(values) == 1:
            if start < len(lines) and values[0] == lines[start] and not noise(values[0]):
                return f'Duplicate line detected in operation {index}: inserting after {identity(start)} repeats {identity(start + 1)} ({debug(values[0])}), which already exists.'
        else:
            count = min(len(values), len(lines) - start)
            if count >= 2 and values[:count] == lines[start:start + count]:
                return f'Duplicate block detected in operation {index}: the {count} lines inserted after {identity(start)} already exist at {identity(start + 1)}-{identity(start + count)}.'
    return None


def original_apply(raw, operations):
    owner = Editable(raw)
    deltas = []
    for kind, start, end, content in sorted((v for v in operations if v[0] == 2), key=lambda v: -v[1]):
        values = [[text, owner.dominant] for text in incoming(content)]
        owner.lines[start - 1:end] = values
        deltas.append((end, len(values) - (end - start + 1)))
    for kind, anchor, end, content in sorted((v for v in operations if v[0] == 1), key=lambda v: -v[1]):
        position = min(len(owner.lines), max(0, anchor + sum(delta for re, delta in deltas if re <= anchor)))
        owner.lines[position:position] = [[text, owner.dominant] for text in incoming(content)]
    owner.preserve()
    return owner


def private_method_plan(raw, operations):
    original = Editable(raw)
    offsets = [0]
    for text, ending in original.lines:
        offsets.append(offsets[-1] + len(text) + bool(ending))
    translated, deltas = [], []
    count = len(original.lines)
    for kind, start, end, content in sorted((v for v in operations if v[0] == 2), key=lambda v: -v[1]):
        values = incoming(content)
        translated.append((2, offsets[start - 1], offsets[end], b''.join(v + b'\n' for v in values)))
        delta = len(values) - (end - start + 1)
        deltas.append((end, delta))
        count += delta
    inserts = sorted((v for v in operations if v[0] == 1), key=lambda v: -v[1])
    for kind, anchor, end, content in inserts:
        position = min(count, max(0, anchor + sum(delta for re, delta in deltas if re <= anchor)))
        translated.append((1, position, 1, content))
        count += len(incoming(content))
    if inserts and not original.had and count:
        translated.extend([(1, 0, 0, b'\n'), (2, 0, 1, b'')])
    translated.append((3, 0, 0, b''))
    return translated


def method_apply(raw, operations):
    owner = Editable(raw)
    for op, a, b, data in private_method_plan(raw, operations):
        error = owner.insert(a, b, data) if op == 1 else owner.replace(a, b, data) if op == 2 else owner.preserve()
        assert error is None, error
    return owner


def packet(raw, operations, mode=0):
    records = b''.join(struct.pack('<6Q', index, kind, kind, start, end if kind == 2 else 0, len(content)) + content for index, (kind, start, end, content) in enumerate(operations))
    plans = struct.pack('<8s5Q', b'HBPLR001', 0, len(operations), len(records), 0, 0) + records
    return struct.pack('<8s7Q', b'HBACT001', mode, len(raw), len(plans), 0, 0, 0, 0) + raw + plans


def response(raw, operations, mode=0):
    error = guards(raw, operations)
    owner = Editable(raw) if error else original_apply(raw, operations)
    normalized, rendered = owner.normalized(), owner.rendered()
    selected = b'' if error else rendered if mode == 0 else normalized if mode == 1 else normalized + rendered
    error_bytes = error.encode() if error else b''
    return struct.pack('<8s9Q', b'HBAPLR01', bool(error), 0 if error else len(operations), len(owner.dominant), owner.had, len(owner.lines), len(normalized), len(rendered), len(selected), len(error_bytes)) + selected + error_bytes


def generated(count=20000):
    rng = random.Random(0x4150504c)
    alphabet = ['a', 'b', 'é', '😀', '漢', '\r', '\n', '\x00', '}', ']', ';', ',', '\u0301', '\u2028', '\x01']
    for _ in range(count):
        raw = ''.join(rng.choice(alphabet) for __ in range(rng.randrange(35))).encode()
        length = len(Editable(raw).lines)
        operations = []
        for __ in range(rng.randrange(1, 8)):
            kind = 2 if length and rng.randrange(2) else 1
            if kind == 1:
                start, end = rng.randrange(length + 1), 0
            else:
                start, end = sorted([rng.randrange(1, length + 1), rng.randrange(1, length + 1)])
            content = ''.join(rng.choice(alphabet) for ___ in range(rng.randrange(9))).encode()
            operations.append((kind, start, end, content))
        yield raw, operations


if __name__ == '__main__':
    passed = refused = 0
    targeted = [(b'a', [(1, 1, 0, b'\r')]), (b'\r', [(1, 1, 0, b'X')]), (b'a\r\nb\nc', [(2, 1, 1, b'x'), (1, 2, 0, b'Y\n')])]
    for raw, operations in targeted + list(generated()):
        if guards(raw, operations):
            refused += 1
            continue
        direct, methods = original_apply(raw, operations), method_apply(raw, operations)
        assert (direct.lines, direct.dominant, direct.had) == (methods.lines, methods.dominant, methods.had), (raw, operations, direct.lines, methods.lines, private_method_plan(raw, operations))
        passed += 1
    print(json.dumps({'prototype_only': True, 'method_compositions_compared': passed, 'guard_refusals': refused, 'native_calls': 0, 'original_rust_calls': 0}))
