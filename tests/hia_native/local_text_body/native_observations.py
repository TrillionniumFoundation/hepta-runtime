"""Decode complete native arenas for the serial Local body comparison only.

The decoder checks the actual persistent owners' layouts. It is not a state
model, does not run an owner, and accepts only the quiescent before/after
boundaries in the frozen ordinary corpus.
"""
from __future__ import annotations
import hashlib
import struct

import observations as original

words, span, text = original.words, original.span, original.text


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cache(arena, phase, generation):
    require(len(arena) >= 64 and arena[:8] == b'HVCSTA01', 'native cache state magic differs')
    version, used, count, poison, z0, z1, z2 = words(arena, 7, 8)
    require(version == 1 and 64 <= used <= len(arena) and poison in (0, 1)
        and not (z0 or z1 or z2), 'native cache header differs')
    entries = {};at = 64
    for _ in range(count):
        kn, vn = words(arena, 2, at);at += 16
        key, at = span(arena, at, kn);value, at = span(arena, at, vn)
        text(key);text(value)
        require(at <= used and key not in entries and vn <= 1 << 20,
            'native cache record or per-value bound differs')
        entries[key] = value
    require(at == used and not any(arena[used:]), 'native cache used extent or complete tail differs')
    return dict(phase=phase, poisoned=bool(poison), entries=entries)


def history(arena, phase, generation):
    require(len(arena) >= 64 and arena[:8] == b'HHISTA01', 'native history state magic differs')
    version, used, snapshots, queued, total, poison, snapshot_end = words(arena, 7, 8)
    require(version == 1 and 64 <= snapshot_end <= used <= len(arena) and poison in (0, 1),
        'native history header differs')
    entries = {};at = 64
    for _ in range(snapshots):
        kn, vn = words(arena, 2, at);at += 16
        key, at = span(arena, at, kn);value, at = span(arena, at, vn)
        text(key);text(value)
        require(at <= snapshot_end, 'native history snapshot escaped its extent')
        entries.setdefault(key, []).append(value)
        require(len(entries[key]) <= 10, 'native per-key history limit differs')
    require(at == snapshot_end, 'native chronological snapshot extent differs')
    order = []
    for _ in range(queued):
        kn, = words(arena, 1, at);at += 8
        key, at = span(arena, at, kn);text(key)
        require(at <= used, 'native stale history event escaped its extent')
        order.append(key)
    require(at == used and not any(arena[used:])
        and snapshots == sum(map(len, entries.values()))
        and total == sum(len(value) for values in entries.values() for value in values),
        'native history totals, event queue or complete tail differs')
    return dict(phase=phase, generation=generation, poisoned=bool(poison), entries=entries,
        order=order, snapshots=snapshots, total_bytes=total)


def key_hash(key):
    value = 14695981039346656037
    for byte in key:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def locks(arena, phase, generation):
    require(len(arena) >= 256 and arena[:8] == b'HFLSTATE', 'native lock state magic differs')
    version, used, free_head, node_head, count, next_node, next_lease, lease_head, leases = words(arena, 9, 8)
    require(version == 1 and 256 <= used <= len(arena) and used % 16 == 0
        and next_node > 0 and next_lease > 0 and lease_head == leases == 0
        and not any(arena[80:256]) and not any(arena[used:]),
        'ordinary lock boundary is not quiescent or its full header/tail differs')
    blocks = {};free = {};nodes = {};at = 256
    allocation_magic = int.from_bytes(b'HFLALLOC', 'little')
    while at < used:
        size, marker = words(arena, 2, at)
        require(size >= 32 and size % 16 == 0 and size <= used - at,
            'native lock allocation boundary differs')
        blocks[at] = size
        if marker == allocation_magic:
            payload = at + 16
            require(size >= 96 and arena[payload:payload + 8] == b'HFLNODE1',
                'ordinary lock state retained a non-node allocation')
            identity, following, refs, kn, digest, owner, head, tail, reserved = words(arena, 9, payload + 8)
            key, end = span(arena, payload + 80, kn);text(key)
            require(0 < identity < next_node and end <= at + size
                and refs == owner == head == tail == reserved == 0
                and digest == key_hash(key) and not any(arena[end:at + size]),
                'native retained lock node, key or released lease differs')
            nodes[payload] = dict(identity=identity, following=following, key=key)
        else:
            require(not any(arena[at + 16:at + size]), 'native released allocation payload was not cleared')
            free[at] = marker
        at += size
    require(at == used, 'native complete allocator extent differs')
    seen = set();previous = 0;cursor = free_head
    while cursor:
        require(cursor in free and cursor not in seen and cursor > previous,
            'native free list has an unowned entry, cycle or order mismatch')
        seen.add(cursor);previous = cursor;cursor = free[cursor]
    require(seen == set(free), 'native free blocks are not all retained in the free list')
    seen = set();ids = set();entries = {};cursor = node_head
    while cursor:
        require(cursor in nodes and cursor not in seen, 'native lock map has an unowned entry or cycle')
        node = nodes[cursor];seen.add(cursor)
        require(node['identity'] not in ids and node['key'] not in entries, 'native lock node identity/key is duplicated')
        ids.add(node['identity']);entries[node['key']] = 1
        cursor = node['following']
    require(seen == set(nodes) and len(entries) == count, 'native complete lock map count differs')
    return dict(phase=phase, generation=generation, poisoned=False, entries=entries)


PARSERS = {3: ('locks', locks), 6: ('history', history), 8: ('cache', cache)}


def decode(raw, operations):
    frames = [];at = 0
    while at < len(raw):
        extent, = words(raw, 1, at + 8)
        require(extent >= 16, 'empty native body observer frame')
        current, at = span(raw, at, extent)
        magic = current[:8]
        row = dict(magic=magic.decode('ascii'), bytes=len(current), sha256=hashlib.sha256(current).hexdigest())
        if magic == b'HLTBHT01':
            row.update(owner=None, kind='hints', state=original.hints(current))
        else:
            require(magic == b'HLTBNA01' and extent >= 64, 'unknown native body observer')
            size, phase, generation, owner, capacity, zero0, zero1 = words(current, 7, 8)
            require(size == extent == 64 + capacity and phase in (0, 1) and generation > 0
                and owner in PARSERS and not (zero0 or zero1), 'native complete arena observer header differs')
            kind, parse = PARSERS[owner]
            arena = current[64:]
            row.update(owner=owner, kind=kind, generation=generation, phase=phase,
                arena_bytes=len(arena), arena_sha256=hashlib.sha256(arena).hexdigest(),
                state=parse(arena, phase, generation))
        frames.append(row)
    require(len(frames) == 7 * len(operations), 'native ordinary observer frame count differs')
    for index, operation in enumerate(operations):
        current = frames[index * 7:(index + 1) * 7]
        require(tuple(row['kind'] for row in current) == ('locks', 'history', 'cache', 'hints', 'locks', 'history', 'cache'),
            'native before/hints/after owner order differs')
        for slot, phase in ((0, 0), (1, 0), (2, 0), (4, 1), (5, 1), (6, 1)):
            require(current[slot]['phase'] == phase and current[slot]['generation'] == index + 1,
                'native observer phase/generation differs')
        hints = current[3]['state']
        require((hints['generation'], hints['operation'], hints['kind']) ==
            (index + 1, operation['op'], operation['kind']), 'native hint result differs from the body response')
    return frames


def compare(original_frames, native_frames):
    require(len(original_frames) == len(native_frames) and len(original_frames) % 7 == 0,
        'ordinary original/native observer extent differs')
    # The two transports declare different physical observer orderings. Every
    # complete parsed owner state is compared at the same before/after boundary.
    pairs = ((0, 2), (1, 1), (2, 0), (3, 3), (4, 6), (5, 5), (6, 4))
    for base in range(0, len(original_frames), 7):
        for old, new in pairs:
            require(original_frames[base + old]['state'] == native_frames[base + new]['state'],
                'complete original/native persistent state differs: operation %d, owner %s' %
                (base // 7 + 1, native_frames[base + new]['kind']))
