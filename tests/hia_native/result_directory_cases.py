# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Owned path walks, legacy history fences and live directory lease transitions."""
import struct

ANCHOR = '.request-results-v2-anchor.json'
STORE = 'request-results'


def directory(mode=0o700):return dict(kind='directory', mode=mode)
def file(data=b'anchor', mode=0o600):return dict(kind='file', mode=mode, data=data.hex())
def request(op, path=b'', lease=0, private=0):
    return dict(request=dict(op=op, path=path.hex(), lease=lease, private=private))
def mutate(action, **values):return dict(mutation=dict(action=action, **values))
def row(name, nodes, actions, **values):
    return dict(name=name, nodes={'root': directory(), **nodes}, actions=actions, **values)
def lifetime(op, path=b'@ROOT@'):
    return [request(op, path), request(3, lease=1), request(3, lease=1, private=1), request(4, lease=1)]


def cases():
    for op in (1, 2):
        for suffix in (b'', b'/', b'//', b'/child', b'//child///grand//', '/目录😀'.encode()):
            yield row('walk-' + str(op) + '-' + suffix.hex(), {
                'root/child': directory(), 'root/child/grand': directory(), 'root/目录😀': directory()}, lifetime(op, b'@ROOT@' + suffix))
        for path in (b'', b'relative', b'.', b'..', b'@ROOT@/.', b'@ROOT@/../root', b'@ROOT@//..//',
                     b'@ROOT@/missing/.', b'@ROOT@/\xff', b'@ROOT@/\xc0\x80', b'@ROOT@/\xed\xa0\x80',
                     b'@ROOT@/\xf4\x90\x80\x80', b'@ROOT@/\x00', b'@ROOT@/missing/\x00',
                     b'@ROOT@/' + b'x' * 256, b'@ROOT@/missing'):
            yield row('invalid-path-' + str(op) + '-' + path.hex(), {}, [request(op, path)])
        for mode in (0o700, 0o755, 0o770, 0o777, 0o500, 0o1700, 0o2700, 0o4700):
            yield row('root-mode-' + str(op) + '-' + oct(mode), {'root': directory(mode)}, lifetime(op))
        for spec in (file(), dict(kind='fifo', mode=0o600), dict(kind='socket', mode=0o600),
                     dict(kind='symlink', target='target'), dict(kind='symlink', target='missing')):
            yield row('root-kind-' + str(op) + '-' + spec['kind'] + '-' + spec.get('target', ''),
                {'root': spec, 'target': directory()}, [request(op, b'@ROOT@')])
        yield row('symlink-ancestor-' + str(op), {'root/link': dict(kind='symlink', target='target'),
            'root/target': directory(), 'root/target/sub': directory()}, [request(op, b'@ROOT@/link/sub')])
    for kind in ('absent', 'file', 'directory', 'fifo', 'socket', 'symlink', 'unreadable'):
        for existing in (False, True):
            specs = {'file': file(), 'directory': directory(), 'fifo': dict(kind='fifo', mode=0o600),
                'socket': dict(kind='socket', mode=0o600), 'symlink': dict(kind='symlink', target='missing'),
                'unreadable': file(mode=0)}
            nodes = {} if kind == 'absent' else {'root/' + ANCHOR: specs[kind]}
            if existing:nodes['root/' + STORE] = directory()
            yield row('anchor-' + kind + '-store-' + str(existing), nodes, lifetime(2))
    for spec in (file(), dict(kind='fifo', mode=0o600), dict(kind='socket', mode=0o600),
                 dict(kind='symlink', target='target'), dict(kind='symlink', target='missing')):
        yield row('store-kind-' + spec['kind'] + '-' + spec.get('target', ''),
            {'root/' + STORE: spec, 'root/target': directory()}, [request(2, b'@ROOT@')])
    for mode in (0o700, 0o755, 0o770, 0o777, 0o500, 0o600, 0o1700, 0o2700, 0o4700):
        yield row('store-mode-' + oct(mode), {'root/' + STORE: directory(mode)}, lifetime(2))
    for mask in (0, 0o022, 0o077, 0o177, 0o777):
        yield row('store-umask-' + oct(mask), {}, lifetime(2), umask=mask)
    yield row('lease-generation-and-stale-refusal', {}, [request(2, b'@ROOT@'), request(1, b'@ROOT@'),
        request(3, lease=2), request(4, lease=2), request(3, lease=1), request(4, lease=1),
        request(3, lease=1), request(1, b'@ROOT@'), request(3, lease=1), request(3, lease=2), request(4, lease=2)])
    for op, target in ((1, 'root'), (2, 'root/' + STORE)):
        yield row('held-renamed-' + str(op), {}, [request(op, b'@ROOT@'),
            mutate('rename', source=target, target='retained'), mutate('mkdir', path=target),
            request(3, lease=1), request(3, lease=1, private=1), request(4, lease=1),
            request(op, b'@ROOT@'), request(4, lease=2)])
        yield row('held-unlinked-' + str(op), {}, [request(op, b'@ROOT@'),
            mutate('rmdir', path=target), mutate('mkdir', path=target), request(3, lease=1),
            request(3, lease=1, private=1), request(4, lease=1), request(op, b'@ROOT@'), request(4, lease=2)])
        yield row('held-permission-change-' + str(op), {}, [request(op, b'@ROOT@'),
            mutate('chmod', path=target, mode=0o755), request(3, lease=1), request(3, lease=1, private=1),
            mutate('chmod', path=target, mode=0o700), request(3, lease=1, private=1), request(4, lease=1)])
    nodes = {};components = []
    for index in range(40):
        components.append(str(index) + '-' + 'a' * 116)
        nodes['root/' + '/'.join(components)] = directory()
    assert len('/'.join(components)) > 4096
    for op in (1, 2):
        yield row('component-walk-over-PATH_MAX-' + str(op), nodes, lifetime(op, b'@ROOT@/' + '/'.join(components).encode()))
    for offset, value in ((0, 0), (8, 0), (8, 5), (16, 2), (24, 1), (32, (1 << 64) - 1), (40, 1)):
        yield row('private-frame-' + str(offset) + '-' + str(value), {}, [dict(request=dict(op=1, path=b'@ROOT@'.hex(), lease=0,
            private=0, change_word=[offset, value])), request(1, b'@ROOT@'), request(4, lease=1)])


def frame(spec, fixture):
    raw = bytes.fromhex(spec['path']).replace(b'@ROOT@', str(fixture / 'root').encode())
    body = bytearray(b'HRSDQ001' + struct.pack('<5Q', spec['op'], spec['private'], spec['lease'], len(raw), 0) + raw)
    if 'change_word' in spec:struct.pack_into('<Q', body, *spec['change_word'])
    return struct.pack('<Q', len(body)) + body
