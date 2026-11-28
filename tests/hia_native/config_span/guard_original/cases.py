"""Input-only directory-move root guard corpus and owned Linux fixtures."""
from pathlib import Path
import hashlib
import os
import stat
import struct


def fixture_nodes():
    nodes = []
    for path in (b'workspace', b'workspace/nested', b'workspace/nested/deeper', b'workspace/child',
                 b'workspace-sibling', b'workspace2', b'outside', b'outside/itemdir', b'denied', b'denied/child',
                 b'raw-\xff-dir', b'raw-\xff-dir/child', b'newline-\n-dir', b'long-'+b'n'*250):
        nodes.append({'kind': 'directory', 'path': path, 'mode': 0o700})
    for path in (b'plain-file', b'workspace/file', b'outside/file'):
        nodes.append({'kind': 'file', 'path': path, 'data': b'unchanged guard fixture\0\n', 'mode': 0o600})
    for path, target in ((b'alias-workspace', b'workspace'), (b'alias-nested', b'workspace/nested'),
                         (b'workspace/alias-outside', b'../outside'), (b'alias-file', b'plain-file'),
                         (b'dangling', b'missing'), (b'loop-a', b'loop-b'), (b'loop-b', b'loop-a'),
                         (b'raw-alias', b'raw-\xff-dir')):
        nodes.append({'kind': 'symlink', 'path': path, 'target': target})
    for number in range(42):
        nodes.append({'kind': 'symlink', 'path': ('chain-'+str(number)).encode(),
                      'target': ('chain-'+str(number+1)).encode() if number < 41 else b'workspace'})
    return nodes


def setup(base):
    base = os.fsencode(base); os.mkdir(base, 0o700)
    for node in fixture_nodes():
        path = base+b'/'+node['path']
        if node['kind'] == 'directory': os.mkdir(path, node['mode'])
        elif node['kind'] == 'file':
            fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, node['mode'])
            try:
                with os.fdopen(fd, 'wb') as stream: stream.write(node['data'])
            except BaseException: raise
        else: os.symlink(node['target'], path)
    os.chmod(base+b'/denied', 0)


def snapshot(base):
    base = os.fsencode(base); rows = []
    for node in [{'path': b'', 'kind': 'directory'}, *fixture_nodes()]:
        path = base+(b'/'+node['path'] if node['path'] else b''); row = {'relative_hex': node['path'].hex()}
        try:
            value = os.lstat(path)
            row.update(mode=value.st_mode, device=value.st_dev, inode=value.st_ino, links=value.st_nlink,
                       uid=value.st_uid, gid=value.st_gid, size=value.st_size, mtime_ns=value.st_mtime_ns, ctime_ns=value.st_ctime_ns)
            if stat.S_ISLNK(value.st_mode): row['target_hex'] = os.readlink(path).hex()
            elif stat.S_ISREG(value.st_mode):
                with open(path, 'rb') as stream: raw = stream.read()
                row['content_bytes'] = len(raw); row['content_sha256'] = hashlib.sha256(raw).hexdigest()
        except OSError as error: row['errno'] = error.errno
        rows.append(row)
    return rows


def iter_cases(base):
    base = os.fsencode(base); cases = []
    def p(value): return base+b'/'+value
    def add(name, source, roots=(), operation=1, domain='unchanged-guard-helper'):
        cases.append({'case_id': 60000+len(cases), 'name': name, 'operation': operation,
                      'domain': domain, 'source': source, 'roots': list(roots)})
    tree, nested, child, outside, sibling = p(b'workspace'), p(b'workspace/nested'), p(b'workspace/child'), p(b'outside'), p(b'workspace-sibling')
    for name, source, roots in [
        ('equal-root', tree, [tree]), ('source-ancestor-of-nested-root', tree, [nested]),
        ('child-under-root-is-not-root-relocation', child, [tree]), ('prefix-sibling', sibling, [tree]),
        ('opposite-prefix-sibling', tree, [sibling]), ('prefix-workspace2', p(b'workspace2'), [tree]),
        ('unrelated-roots', tree, [outside, sibling]), ('later-nested-root', tree, [outside, sibling, nested]),
        ('source-root-slash', b'/', [tree]), ('root-slash-does-not-contain-child-as-prefix', tree, [b'/']),
        ('no-roots-valid-source', tree, []), ('no-roots-root-slash', b'/', []),
        ('regular-source-guard-alone', p(b'plain-file'), [tree]), ('regular-root-guard-alone', outside, [p(b'plain-file')]),
        ('equal-regular-source-root-guard-alone', p(b'plain-file'), [p(b'plain-file')]),
        ('root-order-unavailable-first', tree, [p(b'missing'), nested]),
        ('root-order-denial-first', tree, [nested, p(b'missing')]),
        ('root-order-unrelated-then-unavailable', tree, [outside, p(b'missing')]),
        ('root-order-unrelated-denial-unavailable', tree, [outside, nested, p(b'missing')]),
        ('root-order-unrelated-unavailable-denial', tree, [outside, p(b'missing'), nested]),
        ('duplicate-unrelated-roots-still-resolved', tree, [outside, outside, sibling]),
        ('duplicate-nested-first-stops', tree, [nested, nested]),
        ('source-symlink-identity', p(b'alias-workspace'), [nested]),
        ('root-symlink-identity', tree, [p(b'alias-nested')]),
        ('both-symlink-identity', p(b'alias-workspace'), [p(b'alias-nested')]),
        ('source-symlink-outside', p(b'workspace/alias-outside'), [tree]),
        ('root-symlink-outside', tree, [p(b'workspace/alias-outside')]),
        ('source-symlink-file', p(b'alias-file'), [tree]),
        ('dot-relative-source', b'.', [tree]), ('relative-source-child', b'workspace/child', [tree]),
        ('relative-root', tree, [b'workspace/nested']), ('interior-dot', p(b'workspace/./child'), [tree]),
        ('interior-parent', p(b'workspace/child/..'), [nested]), ('repeated-slash', base+b'//workspace///child//', [tree]),
        ('symlink-then-parent', p(b'alias-nested/..'), [nested]),
        ('source-leading-double-slash', b'/'+tree, [tree]), ('root-trailing-slash', child, [tree+b'/']),
        ('long-valid-leaf', p(b'long-'+b'n'*250), [tree]),
        ('newline-path', p(b'newline-\n-dir'), [tree]),
        ('raw-source', p(b'raw-\xff-dir'), [tree]), ('raw-source-via-symlink', p(b'raw-alias'), [tree])]: add(name, source, roots)
    failures = [('missing', p(b'missing')), ('empty', b''), ('NUL', tree+b'\0tail'),
        ('file-parent', p(b'plain-file/child')), ('dangling', p(b'dangling')), ('loop', p(b'loop-a')),
        ('too-many-links', p(b'chain-0')), ('denied', p(b'denied/child')), ('file-trailing-slash', p(b'plain-file/')),
        ('missing-before-parent', p(b'missing/../workspace')), ('file-before-parent', p(b'plain-file/../workspace')),
        ('name-over-255', p(b'x'*256)), ('path-over-PATH_MAX', p(b'q'*5000))]
    for name, path in failures:
        add('source-'+name+'-zero-roots', path)
        add('source-'+name+'-before-invalid-root', path, [p(b'missing-other')])
        add('root-'+name+'-after-valid-source', child, [path])
    add('raw-root-private-pathbuf', tree, [p(b'raw-\xff-dir')], domain='raw-root-pathbuf-helper')
    add('raw-root-ancestor-denial', p(b'raw-\xff-dir'), [p(b'raw-\xff-dir/child')], domain='raw-root-pathbuf-helper')
    add('raw-root-missing', tree, [p(b'bad-\xff')], domain='raw-root-pathbuf-helper')
    add('wide-valid-source-over-eight-MiB', b'/'*(8*1024*1024+19)+tree.lstrip(b'/'), [nested])
    add('wide-valid-root-over-32-MiB', child, [b'/'*(32*1024*1024+23)+tree.lstrip(b'/')])
    add('wide-invalid-root-over-eight-MiB', child, [p(b'X'*(8*1024*1024+7))])
    add('wide-source-NUL', tree+b'\0'+b'z'*(8*1024*1024+11), [nested])
    for name, source in [('valid', tree), ('missing', p(b'missing')), ('empty', b''), ('NUL', b'\0'), ('raw', p(b'raw-\xff-dir'))]:
        add('uninstalled-config-'+name, source, operation=2, domain='actual-uninstalled-config-projection')
    return cases


def encode(stream, cases):
    stream.write(b'HFDGI001'+struct.pack('<Q', len(cases)))
    for case in cases:
        stream.write(struct.pack('<5Q', case['case_id'], case['operation'], len(case['source']), len(case['roots']), 0))
        stream.write(case['source'])
        for root in case['roots']: stream.write(struct.pack('<Q', len(root))); stream.write(root)
