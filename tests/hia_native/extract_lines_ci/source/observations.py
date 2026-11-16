"""Strict readers for complete original Local text-body observations."""
from __future__ import annotations
import hashlib
import struct


def words(raw, count, start=0):
    if start < 0 or len(raw) - start < 8 * count:
        raise ValueError('truncated observation words')
    return struct.unpack_from('<' + 'Q' * count, raw, start)


def text(raw):
    raw.decode('utf-8')
    return raw


def span(raw, at, length):
    if at < 0 or length > len(raw) - at:
        raise ValueError('truncated observation span')
    return raw[at:at + length], at + length


def cache(raw):
    extent, phase, poison, count, body = words(raw, 5, 8)
    if extent != len(raw) or extent != 48 + body or phase not in (0, 1) or poison not in (0, 1):
        raise ValueError('cache observer header differs')
    entries, at, previous = {}, 48, None
    for _ in range(count):
        kn, vn = words(raw, 2, at); at += 16
        key, at = span(raw, at, kn); value, at = span(raw, at, vn)
        text(key); text(value)
        if vn > 1 << 20 or (previous is not None and key <= previous):
            raise ValueError('cache observer ordering or capacity differs')
        previous = key; entries[key] = value
    if at != len(raw):
        raise ValueError('cache observer has trailing bytes')
    return dict(phase=phase, poisoned=bool(poison), entries=entries)


def history(raw):
    extent, phase, generation, poison, count, snapshots, total, qn, body = words(raw, 9, 8)
    if (extent != len(raw) or extent != body + 80 or phase not in (0, 1)
            or not generation or poison not in (0, 1)):
        raise ValueError('history observer header differs')
    entries, queue, at, previous = {}, [], 80, None
    for _ in range(count):
        kn, vn = words(raw, 2, at); at += 16
        key, at = span(raw, at, kn); text(key)
        if (previous is not None and key <= previous) or not 1 <= vn <= 10:
            raise ValueError('history observer ordering or per-key capacity differs')
        previous = key; values = []
        for _ in range(vn):
            size, = words(raw, 1, at); at += 8
            value, at = span(raw, at, size); text(value); values.append(value)
        entries[key] = values
    for _ in range(qn):
        size, = words(raw, 1, at); at += 8
        key, at = span(raw, at, size); text(key); queue.append(key)
    if (at != len(raw) or snapshots != sum(map(len, entries.values()))
            or total != sum(len(value) for values in entries.values() for value in values)):
        raise ValueError('history complete state totals differ')
    return dict(phase=phase, generation=generation, poisoned=bool(poison), entries=entries,
                order=queue, snapshots=snapshots, total_bytes=total)


def locks(raw):
    extent, phase, generation, poison, count, body = words(raw, 6, 8)
    if (extent != len(raw) or extent != body + 56 or phase not in (0, 1)
            or not generation or poison not in (0, 1)):
        raise ValueError('lock observer header differs')
    entries, at, previous = {}, 56, None
    for _ in range(count):
        kn, strong = words(raw, 2, at); at += 16
        key, at = span(raw, at, kn); text(key)
        if (previous is not None and key <= previous) or strong < 1:
            raise ValueError('lock observer ordering or lease differs')
        previous = key; entries[key] = strong
    if at != len(raw):
        raise ValueError('lock observer has trailing bytes')
    return dict(phase=phase, generation=generation, poisoned=bool(poison), entries=entries)


def hints(raw):
    extent, generation, operation, kind, count = words(raw, 5, 8)
    if extent != len(raw) or not generation or operation != 1 or kind not in (0, 1):
        raise ValueError('hint observer header differs')
    entries, at = [], 48
    for _ in range(count):
        size, = words(raw, 1, at); at += 8
        value, at = span(raw, at, size); text(value); entries.append(value)
    if at != len(raw):
        raise ValueError('hint observer has trailing bytes')
    return dict(generation=generation, operation=operation, kind=kind, entries=entries)


PARSERS = {b'HLCSCS01': cache, b'HLTBHS01': history, b'HLTBLK01': locks, b'HLTBHT01': hints}


def decode(raw, operations):
    frames, at = [], 0
    while at < len(raw):
        size, = words(raw, 1, at + 8)
        if size < 16:
            raise ValueError('empty observer frame')
        current, at = span(raw, at, size)
        magic = current[:8]
        if magic not in PARSERS:
            raise ValueError('unknown body observer frame')
        parsed = PARSERS[magic](current)
        frames.append(dict(magic=magic.decode('ascii'), bytes=len(current),
                           sha256=hashlib.sha256(current).hexdigest(), state=parsed))
    if len(frames) != 7 * len(operations):
        raise ValueError('ordinary operation observer count differs')
    pattern = ('HLCSCS01', 'HLTBHS01', 'HLTBLK01', 'HLTBHT01', 'HLCSCS01', 'HLTBHS01', 'HLTBLK01')
    for index, operation in enumerate(operations):
        current = frames[7 * index:7 * index + 7]
        if tuple(row['magic'] for row in current) != pattern:
            raise ValueError('original before/hints/after ordering differs')
        for slot, phase in ((0, 0), (1, 0), (2, 0), (4, 1), (5, 1), (6, 1)):
            if current[slot]['state']['phase'] != phase:
                raise ValueError('observer phase differs')
        for slot in (1, 2, 3, 5, 6):
            if current[slot]['state']['generation'] != index + 1:
                raise ValueError('observer generation differs')
        h = current[3]['state']
        if (h['operation'], h['kind']) != (operation['op'], operation['kind']):
            raise ValueError('hint result differs from admitted body operation')
        if any(value != 1 for value in current[6]['state']['entries'].values()):
            raise ValueError('completed ordinary body retained a file-lock lease')
    return frames
