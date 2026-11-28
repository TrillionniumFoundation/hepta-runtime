# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Owned archive graph creation, immutable identity binding, and real lease cases."""
import struct

ANCHOR = 'root/.request-results-v2-anchor.json'
MARKER = 'legacy/.request-results-v2.json'
STORE = 'root/request-results-v2'
ARCHIVE = STORE + '/archive'


def frame(op, create=0, lease=0, payload=b''):
    return b'HRASQ001' + struct.pack('<5Q', op, create, lease, len(payload), 0) + payload


def request(op, create=0, lease=0, payload=b''):
    return dict(request=frame(op, create, lease, payload).hex())


def identity(index):
    return (f'{index:02x}' + '0' * 62).encode()


def mutation(action, **values):
    return dict(mutation=dict(action=action, **values))


def row(name, operations, initialized=False, **values):
    return dict(name=name, initialized=initialized, operations=operations, **values)


def cases():
    empty = request(1)
    create = request(1, 1)
    release = request(5, lease=1)
    verify = request(3, lease=1)
    yield row('absent-read-does-not-create', [empty, empty])
    steps = [empty, create, verify]
    for index in range(256):
        steps += [request(2, lease=1, payload=identity(index)), request(6, lease=index + 1), request(4, lease=index + 1)]
    steps += [release, empty, request(5, lease=2)]
    yield row('create-verify-all-shards-and-reopen', steps)
    yield row('held-shard-survives-archive-release', [create, request(2, lease=1, payload=identity(171)),
        release, request(6, lease=1), request(4, lease=1), empty, request(5, lease=2)])
    for mask in (0, 0o022, 0o077, 0o200, 0o700, 0o777):
        yield row('create-umask-' + oct(mask), [create, release, empty, request(5, lease=2)], umask=mask)
    for kind in ('directory', 'file', 'fifo', 'symlink', 'dangling'):
        yield row('unanchored-store-' + kind, [empty, create], setup=[dict(action='node', path=STORE, kind=kind)])
    yield row('marker-with-missing-anchor', [empty, create], setup=[dict(action='marker', digest='a1' * 32)])
    for kind in ('directory', 'file', 'fifo', 'symlink', 'dangling'):
        if kind == 'file':continue
        yield row('anchor-kind-' + kind, [empty, create], setup=[dict(action='node', path=ANCHOR, kind=kind)])
        yield row('marker-kind-' + kind, [empty, create], setup=[dict(action='node', path=MARKER, kind=kind)])
    for mode in (0o400, 0o640, 0o644, 0o1600):
        yield row('anchor-mode-' + oct(mode), [empty, create], True,
            setup=[dict(action='chmod', path=ANCHOR, mode=mode)])
        yield row('marker-mode-' + oct(mode), [empty, create], True,
            setup=[dict(action='chmod', path=MARKER, mode=mode)])
    for raw in (b'', b'{', b'null', b'[]', b'{}', b'{"schema":2}', b'x' * 98305):
        yield row('anchor-raw-' + str(len(raw)) + '-' + raw[:4].hex(), [empty, create], True,
            setup=[dict(action='write', path=ANCHOR, data=raw.hex())])
    for raw in (b'', b'{', b'null', b'{}', b'{"schema":1,"anchor_sha256":"' + b'a' * 64 + b'"}', b'x' * 1025):
        yield row('marker-raw-' + str(len(raw)) + '-' + raw[:4].hex(), [empty, create], True,
            setup=[dict(action='write', path=MARKER, data=raw.hex())])
    for field in ('root', 'legacy', 'store', 'archive'):
        yield row('anchor-wrong-' + field, [empty, create], True,
            setup=[dict(action='anchor_pin', field=field, index=0, replacement=dict(device=0, inode=0)), dict(action='remove', path=MARKER)])
    for field, path in (('legacy', 'legacy'), ('store', STORE), ('archive', ARCHIVE)):
        for mode in (0o500, 0o750, 0o1700):
            yield row('private-' + field + '-' + oct(mode), [empty, create], True,
                setup=[dict(action='chmod', path=path, mode=mode)])
    yield row('nonprivate-root-allowed', [empty, verify, release], True,
        setup=[dict(action='chmod', path='root', mode=0o755)])
    yield row('valid-anchor-missing-marker', [empty, release, empty, request(5, lease=2)], True,
        setup=[dict(action='remove', path=MARKER)])
    yield row('marker-wrong-binding', [empty, create], True,
        setup=[dict(action='marker', digest='a1' * 32)])
    yield row('anchor-lost-after-success', [empty, release, mutation('remove', path=ANCHOR), empty, create], True)
    yield row('anchor-and-archive-lost-after-success', [empty, release, mutation('remove', path=ANCHOR),
        mutation('rename', path=STORE, target='retired-store'), empty, create], True)
    for index in (0, 1, 15, 16, 127, 128, 170, 254, 255):
        path = ARCHIVE + f'/{index:02x}'
        for action in ('remove', 'replace', 'chmod', 'symlink'):
            change = dict(action=action, path=path)
            if action == 'replace':change['kind'] = 'directory'
            if action == 'chmod':change['mode'] = 0o750
            if action == 'symlink':change['target'] = f'../{(index + 1) % 256:02x}'
            yield row(f'shard-{index:02x}-{action}', [empty, mutation(**change), verify,
                request(2, lease=1, payload=identity(index)), request(2, lease=1, payload=identity((index + 1) % 256)),
                request(4, lease=1), release], True)
    yield row('held-archive-renamed-and-replaced', [empty,
        mutation('rename', path=ARCHIVE, target=STORE + '/retired-archive'),
        mutation('node', path=ARCHIVE, kind='directory'),
        request(2, lease=1, payload=identity(0)), request(4, lease=1), verify, release, empty], True)
    yield row('held-store-renamed-and-replaced', [empty,
        mutation('rename', path=STORE, target='retired-store'),
        mutation('node', path=STORE, kind='directory'), mutation('node', path=ARCHIVE, kind='directory'),
        request(2, lease=1, payload=identity(255)), request(4, lease=1), release, empty], True)
    yield row('held-shard-unlinked-and-replaced', [empty, request(2, lease=1, payload=identity(0)),
        mutation('remove', path=ARCHIVE + '/00'), mutation('node', path=ARCHIVE + '/00', kind='directory'),
        request(6, lease=1), release, request(6, lease=1), request(4, lease=1), empty,
        request(2, lease=2, payload=identity(0)), request(5, lease=2)], True)
    yield row('held-shard-private-mode-change', [empty, request(2, lease=1, payload=identity(0)),
        mutation('chmod', path=ARCHIVE + '/00', mode=0o750), request(6, lease=1),
        mutation('chmod', path=ARCHIVE + '/00', mode=0o700), request(6, lease=1), request(4, lease=1), release], True)
    yield row('held-legacy-renamed', [empty, release, mutation('rename', path='legacy', target='retired-legacy'),
        mutation('node', path='legacy', kind='directory'), empty, request(5, lease=2)], True)
    yield row('stale-and-conflicting-leases', [request(2, lease=1, payload=identity(0)), create, create,
        request(3, lease=0), request(2, lease=2, payload=identity(0)), request(2, lease=1, payload=identity(0)),
        verify, request(2, lease=1, payload=identity(1)), request(4, lease=2), request(6, lease=2),
        request(4, lease=1), request(4, lease=1), release, release, empty,
        request(3, lease=1), request(5, lease=2)])
    for raw in (b'', b'a' * 63, b'a' * 65, b'A' * 64, b'g' * 64, b'\xff' * 64, b'\0' * 64):
        yield row('bad-id-' + str(len(raw)) + '-' + raw[:1].hex(), [empty, request(2, lease=1, payload=raw), verify, release], True)
    valid = frame(1)
    for length in (0, 1, 7, 8, 47):
        yield row('short-frame-' + str(length), [dict(request=valid[:length].hex()), empty])
    for offset, value in ((0, 0), (8, 0), (8, 7), (16, 2), (24, 1), (32, 1), (40, 1)):
        wire = bytearray(valid);struct.pack_into('<Q', wire, offset, value)
        yield row(f'header-{offset}-{value}', [dict(request=wire.hex()), empty])


if __name__ == '__main__':
    values = list(cases())
    assert len({r['name'] for r in values}) == len(values)
    print(dict(cases=len(values), requests=sum('request' in step for row in values for step in row['operations']),
        observations=sum(len(row['operations']) for row in values)))
