"""Complete readiness calls with owned root paths and existing-history mutations."""
import struct

LEGACY = 'root/request-results'
ANCHOR = 'root/.request-results-v2-anchor.json'
MARKER = LEGACY + '/.request-results-v2.json'
STORE = 'root/request-results-v2'
ARCHIVE = STORE + '/archive'

def frame(root):return b'HRSPQ001' + struct.pack('<QQ', 1, len(root)) + root
def request(**values):return dict(root_relative='root', **values)
def mutation(action, **values):return dict(mutation=dict(action=action, **values))
def row(name, operations=None, initialized=False, **values):
    return dict(name=name, initialized=initialized, operations=operations or [request(), request()], **values)

def cases():
    yield row('initialize-and-verify-again')
    yield row('existing-immutable-archive', initialized=True)
    for mask in (0, 0o022, 0o077, 0o200, 0o700, 0o777):
        yield row('creation-umask-' + oct(mask), umask=mask)
    for mode in (0, 0o500, 0o700, 0o755, 0o1700):
        yield row('root-mode-' + oct(mode), setup=[dict(action='chmod', path='root', mode=mode)])
    for mode in (0, 0o500, 0o750, 0o1700):
        yield row('legacy-mode-' + oct(mode), initialized=True, setup=[dict(action='chmod', path=LEGACY, mode=mode)])
    for kind in ('directory', 'file', 'fifo', 'symlink', 'dangling'):
        yield row('unanchored-archive-' + kind, setup=[dict(action='node', path=STORE, kind=kind)])
    yield row('lost-anchor-marker-preserved', initialized=True, setup=[dict(action='remove', path=ANCHOR)])
    yield row('missing-marker-created-from-anchor', initialized=True, setup=[dict(action='remove', path=MARKER)])
    yield row('changed-marker-binding', initialized=True, setup=[dict(action='marker', digest='a1' * 32)])
    for component, path in (('legacy', LEGACY), ('store', STORE), ('archive', ARCHIVE)):
        yield row('lost-' + component, [request(), mutation('rename', path=path, target='retired-' + component), request()], True)
        yield row('replaced-' + component, [request(), mutation('rename', path=path, target='retired-' + component),
            mutation('node', path=path, kind='directory'), request()], True)
    for index in (0, 1, 15, 16, 127, 128, 170, 254, 255):
        path = ARCHIVE + f'/{index:02x}'
        for action in ('remove', 'replace', 'chmod', 'symlink'):
            change = dict(action=action, path=path)
            if action == 'replace':change['kind'] = 'directory'
            if action == 'chmod':change['mode'] = 0o750
            if action == 'symlink':change['target'] = '../00'
            yield row(f'shard-{index:02x}-{action}', [request(), mutation(**change), request(), request()], True)
    for field in ('root', 'legacy', 'store', 'archive'):
        yield row('changed-anchor-' + field, initialized=True,
            setup=[dict(action='anchor_pin', field=field, index=0, replacement=dict(device=0, inode=0))])
    for raw in (b'', b'{', b'null', b'[]', b'{}', b'{"schema":2}', b'x' * 98305):
        yield row('anchor-raw-' + str(len(raw)) + '-' + raw[:4].hex(), initialized=True,
            setup=[dict(action='write', path=ANCHOR, data=raw.hex())])
    for raw in (b'', b'{', b'null', b'{}', b'{"schema":1,"anchor_sha256":"' + b'a' * 64 + b'"}', b'x' * 1025):
        yield row('marker-raw-' + str(len(raw)) + '-' + raw[:4].hex(), initialized=True,
            setup=[dict(action='write', path=MARKER, data=raw.hex())])
    for path, label in ((ANCHOR, 'anchor'), (MARKER, 'marker')):
        for mode in (0o400, 0o640, 0o1600):
            yield row(label + '-mode-' + oct(mode), initialized=True, setup=[dict(action='chmod', path=path, mode=mode)])
    for suffix in (b'/', b'//', b'/' * 4096, b'/' * 8192):
        yield row('root-separators-' + str(len(suffix)), [request(path_suffix=suffix.hex()), request()])
    for raw in (b'', b'relative', b'.', b'../other', b'\xff', b'/\xff', b'/invalid/../root', b'/./invalid'):
        yield row('invalid-root-' + raw.hex(), [dict(path_hex=raw.hex()), request()])
    for suffix in (b'/missing', b'/a/../b', b'/.', b'/\xff', b'/a\0b', b'/' + b'a' * 256):
        yield row('root-suffix-' + suffix[:8].hex(), [request(path_suffix=suffix.hex()), request()])
    yield row('root-symlink-refused', [dict(root_relative='alias'), request()],
        setup=[dict(action='node', path='alias', kind='symlink', target='root')])
    yield row('parent-symlink-refused', [dict(root_relative='alias/child'), request()],
        setup=[dict(action='node', path='alias', kind='symlink', target='root'), dict(action='node', path='root/child', kind='directory')])
    yield row('utf8-root-name', [dict(root_relative='根目录-🧬'), dict(root_relative='根目录-🧬')],
        setup=[dict(action='rename', path='root', target='根目录-🧬')], root_name='根目录-🧬')
    valid = frame(b'root')
    for length in (0, 1, 7, 8, 23):
        yield row('short-frame-' + str(length), [dict(request=valid[:length].hex()), request()])
    for offset, value in ((0, 0), (8, 0), (8, 2), (16, 0), (16, 1 << 63)):
        wire = bytearray(valid);struct.pack_into('<Q', wire, offset, value)
        yield row(f'header-{offset}-{value}', [dict(request=wire.hex()), request()])

if __name__ == '__main__':
    rows=list(cases());assert len({r['name'] for r in rows})==len(rows)
    print(dict(cases=len(rows),requests=sum('mutation' not in s for r in rows for s in r['operations']),
        observations=sum(len(r['operations']) for r in rows)))
