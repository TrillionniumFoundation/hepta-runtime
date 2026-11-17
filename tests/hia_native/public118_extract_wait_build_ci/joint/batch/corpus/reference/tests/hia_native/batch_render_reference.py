"""Independent development model for the original post-write batch diff block."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import struct
import sys


def load_apply(reference):
    path = Path(reference) / 'tests/hia_native/batch_apply_reference.py'
    spec = importlib.util.spec_from_file_location('_batch_render_apply_reference', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def lines(raw):
    values = raw.split(b'\n')
    terminated = raw.count(b'\n')
    if values[-1] == b'':
        values.pop()
    # str::lines removes a single CR only for a segment terminated by LF.
    return [v[:-1] if i < terminated and v.endswith(b'\r') else v
            for i, v in enumerate(values)]


def incoming(raw):
    return [v.rstrip(b'\r') for v in lines(raw)]


def line_id(number, raw):
    value = 2166136261
    for byte in raw:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    value = (value >> 16) ^ (value & 65535)
    return f'{number}:{((value >> 8) ^ (value & 255)):02x}'.encode()


def packet(old, new, operations):
    records = b''.join(struct.pack('<6Q', i, kind, kind, start, end if kind == 2 else 0, len(content)) + content
                       for i, (kind, start, end, content) in enumerate(operations))
    plan = struct.pack('<8s5Q', b'HBPLR001', 0, len(operations), len(records), 0, 0) + records
    return struct.pack('<8s7Q', b'HBDIFF01', len(old), len(new), len(plan), 0, 0, 0, 0) + old + new + plan


def response(old, new, operations):
    old_lines, new_lines = lines(old), lines(new)
    def context(index):
        return line_id(index, new_lines[index - 1]) + b'|' + new_lines[index - 1]
    def added(first, values):
        one = lambda i: b'+' + line_id(first + i, values[i]) + b'|' + values[i]
        if len(values) <= 3:
            return [one(i) for i in range(len(values))]
        return [one(0), b'+' + line_id(first + 1, values[1]) + b'..' + line_id(first + len(values) - 2, values[-2])
                + f' ({len(values)-2} lines as sent)'.encode(), one(len(values) - 1)]
    diffs, offset = [], 0
    for kind, start, end, content in sorted(operations, key=lambda v: v[1]):
        values = incoming(content)
        position = max(1, start + offset) + int(kind == 1 and start != 0)
        before = max(1, position - 2)
        diff = [b'...'] if before > 1 else []
        diff += [context(i) for i in range(before, position) if 1 <= i <= len(new_lines)]
        if kind == 2:
            removed = b'-' + line_id(start, old_lines[start - 1])
            removed += b' (1 line)' if start == end else b'..' + line_id(end, old_lines[end - 1]) + f' ({end-start+1} lines)'.encode()
            diff.append(removed)
        diff += added(position, values)
        after = position + len(values)
        last = min(after + 1, len(new_lines))
        diff += [context(i) for i in range(after, last + 1) if 1 <= i <= len(new_lines)]
        if last < len(new_lines):
            diff.append(b'...')
        diffs.append(b'\n'.join(diff))
        offset += len(values) - (end - start + 1 if kind == 2 else 0)
    body = b'\n---\n'.join(diffs)
    regions = {}
    for kind, start, end, content in operations:
        anchor = end if kind == 2 else start
        regions[anchor] = regions.get(anchor, 0) + len(incoming(content)) - (end-start+1 if kind == 2 else 0)
    total, notes = 0, []
    for end, delta in sorted(regions.items()):
        total += delta
        if delta and end < len(old_lines):
            anchor = b'0' if end == 0 else line_id(end, old_lines[end - 1])
            notes.append(b'after ' + anchor + f' {total:+}'.encode())
    if notes:
        body += b'\nshift: lines ' + b', '.join(notes)
    return struct.pack('<8s3Q', b'HBDIFR01', len(body), 0, 0) + body
