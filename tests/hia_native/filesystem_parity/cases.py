"""Input-only filesystem corpus. All operation results come from original Rust."""
from pathlib import Path
import hashlib
import os
import struct


def raw(value):
    return value.encode() if isinstance(value, str) else value


def groups(home, cross_root):
    home, cross_root = os.fsencode(home), os.fsencode(cross_root)
    result = {}; next_id = 0
    def group(name):
        root = home+b'/'+name.encode()+b'/files'
        item = {'name': name, 'roots': [root], 'setup': [], 'cases': [], 'restore_modes': []}
        result[name] = item
        return item, root
    def setup(g, kind, path, **fields):
        g['setup'].append({'kind': kind, 'path': path, **fields})
        if kind == 'chmod': g['restore_modes'].append({'path': path, 'mode': 0o700})
    def add(g, name, operation, first, second=b''):
        nonlocal next_id
        g['cases'].append({'case_id': next_id, 'name': name, 'operation': operation,
                           'first': first, 'second': second})
        next_id += 1
    def ordinary(g, p):
        setup(g, 'mkdir', p+b'/real')
        setup(g, 'write', p+b'/parent-file', data=b'parent sentinel\n')
        setup(g, 'symlink', p+b'/parent-link', target=b'real')
        setup(g, 'symlink', p+b'/parent-dangling', target=b'absent-parent')
        setup(g, 'fifo', p+b'/parent-fifo')
        setup(g, 'mkdir', p+b'/parent-denied/deeper')
        setup(g, 'write', p+b'/parent-denied/deeper/file', data=b'denied sentinel\n')
        setup(g, 'mkdir', p+b'/parent-denied/deeper/directory')
        setup(g, 'chmod', p+b'/parent-denied', mode=0)
    g, p = group('validation')
    for operation in (2, 3):
        for name, a, b in [
            ('equal empty paths', b'', b''), ('equal relative paths', b'./relative', b'./relative'),
            ('equal root aliases', b'/', b'//'),
            ('equal normalized dot slash paths', p+b'//never/./leaf/', p+b'/never/leaf'),
            ('equal NUL components before validation', p+b'/nul\0leaf', p+b'/nul\0leaf')]:
            add(g, str(operation)+' '+name, operation, a, b)
    for name, value in [('empty', b''), ('dot', b'.'), ('relative', b'relative'),
        ('leading relative dot', b'./relative'), ('root', b'/'), ('slash root', b'////'),
        ('interior dot root', b'/./'), ('parent component', p+b'/../escape'), ('NUL component', p+b'/nul\0tail')]:
        add(g, 'mkdir validation '+name, 1, value)
    for operation in (2, 3):
        for name, a, b in [
            ('relative source', b'./source', p+b'/destination'),
            ('relative destination', p+b'/source', b'./destination'),
            ('source root before invalid destination', b'/', b'relative'),
            ('source NUL before destination parent', p+b'/nul\0', p+b'/../destination'),
            ('source parent before destination NUL', p+b'/../source', p+b'/nul\0')]:
            add(g, str(operation)+' '+name, operation, a, b)

    g, p = group('mkdir')
    ordinary(g, p)
    setup(g, 'mkdir', p+b'/no-read')
    setup(g, 'chmod', p+b'/no-read', mode=0o300)
    cases = [
        ('new leaf', p+b'/created'), ('existing leaf', p+b'/created'),
        ('new complete parent chain', p+b'/nested/a/b'), ('existing complete parent chain', p+b'/nested/a/b'),
        ('repeated slash and interior dot', p+b'//dots/./child/'),
        ('raw invalid UTF8 directory', p+b'/raw-\xff'), ('raw invalid UTF8 existing directory', p+b'/raw-\xff'),
        ('Unicode newline quote directory', p+'/中😀/quote"\nname'.encode()),
        ('file leaf', p+b'/parent-file'), ('symlink directory leaf', p+b'/parent-link'),
        ('dangling symlink leaf', p+b'/parent-dangling'), ('FIFO leaf', p+b'/parent-fifo'),
        ('file parent', p+b'/parent-file/child'), ('symlink parent', p+b'/parent-link/child'),
        ('dangling symlink parent', p+b'/parent-dangling/child'), ('FIFO parent', p+b'/parent-fifo/child'),
        ('search denied parent', p+b'/parent-denied/child'),
        ('write search without directory read', p+b'/no-read/child'),
        ('partial new chain before leaf failure', p+b'/partial/new/'+b'x'*256),
        ('partial success is retained after error', p+b'/partial/new'),
        ('NAME_MAX leaf', p+b'/'+b'y'*255), ('over NAME_MAX leaf', p+b'/'+b'z'*256),
        ('symlink with interior dot suffix', p+b'/parent-link/.')]
    for name, path in cases: add(g, name, 1, path)

    g, p = group('file_move')
    for index in range(7): setup(g, 'write', p+b'/file'+str(index).encode(), data=b'file payload '+str(index).encode()+b'\n')
    setup(g, 'write', p+b'/existing-file', data=b'destination sentinel\n')
    setup(g, 'mkdir', p+b'/existing-directory')
    setup(g, 'symlink', p+b'/existing-link', target=b'existing-file')
    setup(g, 'symlink', p+b'/existing-dangling', target=b'absent-target')
    setup(g, 'fifo', p+b'/existing-fifo')
    setup(g, 'mkdir', p+b'/source-directory/child')
    setup(g, 'symlink', p+b'/source-link', target=b'file1')
    setup(g, 'symlink', p+b'/source-dangling', target=b'absent-source')
    setup(g, 'fifo', p+b'/source-fifo')
    setup(g, 'write', p+b'/raw-\xff', data=b'raw source\0\xff\n')
    setup(g, 'write', p+'/中😀"\n'.encode(), data=b'unicode source\n')
    setup(g, 'write', p+b'/kept-hardlink', data=b'hardlink bytes\n')
    setup(g, 'hardlink', p+b'/source-hardlink', target=p+b'/kept-hardlink')
    for name, a, b in [('first atomic move', b'file0', b'moved'), ('repeated old source', b'file0', b'absent-destination'),
        ('move same inode again', b'moved', b'final'), ('same final path', b'final', b'final')]:
        add(g, name, 2, p+b'/'+a, p+b'/'+b)
    for index, destination in enumerate(('existing-file', 'existing-directory', 'existing-link', 'existing-dangling', 'existing-fifo'), 1):
        add(g, 'no replace '+destination, 2, p+b'/file'+str(index).encode(), p+b'/'+destination.encode())
    for leaf in ('source-directory', 'source-link', 'source-dangling', 'source-fifo', 'source-missing'):
        add(g, 'source leaf '+leaf, 2, p+b'/'+leaf.encode(), p+b'/refused-'+leaf.encode())
    add(g, 'raw invalid UTF8 move', 2, p+b'/raw-\xff', p+b'/raw-\xfe')
    add(g, 'Unicode newline quote move', 2, p+'/中😀"\n'.encode(), p+'/目标\n'.encode())
    add(g, 'hardlink inode and remaining link', 2, p+b'/source-hardlink', p+b'/moved-hardlink')
    add(g, 'normalized source and destination components', 2, p+b'//./file6', p+b'//./normalized')

    g, p = group('directory_move')
    setup(g, 'write', p+b'/outside-target', data=b'outside child-link target unchanged\n')
    setup(g, 'write', p+b'/tree/nested/file', data=b'directory contents\0\xff\n')
    setup(g, 'symlink', p+b'/tree/child-link', target=b'../outside-target')
    setup(g, 'symlink', p+b'/tree/dangling', target=b'absent')
    setup(g, 'fifo', p+b'/tree/child-fifo')
    for index in range(6): setup(g, 'mkdir', p+b'/dir'+str(index).encode())
    setup(g, 'write', p+b'/existing-file', data=b'destination remains\n')
    setup(g, 'mkdir', p+b'/existing-directory/child')
    setup(g, 'symlink', p+b'/existing-link', target=b'existing-directory')
    setup(g, 'symlink', p+b'/existing-dangling', target=b'absent')
    setup(g, 'fifo', p+b'/existing-fifo')
    setup(g, 'write', p+b'/source-file', data=b'file source\n')
    setup(g, 'symlink', p+b'/source-link', target=b'dir0')
    setup(g, 'symlink', p+b'/source-dangling', target=b'absent-source')
    setup(g, 'fifo', p+b'/source-fifo')
    setup(g, 'mkdir', p+b'/ancestor/child')
    setup(g, 'mkdir', p+b'/no-read/from')
    setup(g, 'chmod', p+b'/no-read', mode=0o300)
    for name, a, b in [('whole tree atomic move without child traversal', b'tree', b'moved-tree'),
        ('repeated old directory source', b'tree', b'missing-destination'),
        ('move tree again preserving inode', b'moved-tree', b'final-tree')]:
        add(g, name, 3, p+b'/'+a, p+b'/'+b)
    for index, destination in enumerate(('existing-file', 'existing-directory', 'existing-link', 'existing-dangling', 'existing-fifo')):
        add(g, 'directory no replace '+destination, 3, p+b'/dir'+str(index).encode(), p+b'/'+destination.encode())
    for leaf in ('source-file', 'source-link', 'source-dangling', 'source-fifo', 'source-missing'):
        add(g, 'directory source '+leaf, 3, p+b'/'+leaf.encode(), p+b'/refused-'+leaf.encode())
    add(g, 'move directory into its descendant refused', 3, p+b'/ancestor', p+b'/ancestor/child/destination')
    add(g, 'empty directory atomic move', 3, p+b'/dir5', p+b'/empty-moved')
    add(g, 'write search parent without read permission', 3, p+b'/no-read/from', p+b'/no-read/to')

    g, p = group('ordering')
    ordinary(g, p)
    setup(g, 'write', p+b'/source-file', data=b'order source\n')
    setup(g, 'mkdir', p+b'/source-directory')
    for operation in (2, 3):
        source = p+(b'/source-file' if operation == 2 else b'/source-directory')
        add(g, str(operation)+' destination validation before unsafe source parent', operation, p+b'/parent-file/leaf', b'relative')
        add(g, str(operation)+' destination NUL before unsafe source parent', operation, p+b'/parent-file/leaf', p+b'/nul\0')
        add(g, str(operation)+' source parent missing before destination parent', operation, p+b'/absent-source/leaf', p+b'/absent-destination/leaf')
        add(g, str(operation)+' destination parent before missing source leaf', operation, p+b'/absent-leaf', p+b'/absent-destination/leaf')
        add(g, str(operation)+' destination parent before source type check', operation,
            p+(b'/source-directory' if operation == 2 else b'/source-file'), p+b'/parent-denied/deeper/leaf')
        for parent in ('parent-file', 'parent-link', 'parent-dangling', 'parent-fifo', 'parent-denied/deeper'):
            add(g, str(operation)+' unsafe source parent '+parent, operation, p+b'/'+parent.encode()+b'/leaf', p+b'/destination')
            add(g, str(operation)+' unsafe destination parent '+parent, operation, source, p+b'/'+parent.encode()+b'/leaf')

    g, p = group('cross_device')
    other = cross_root+b'/files'; g['roots'].append(other)
    setup(g, 'write', p+b'/file', data=b'local EXDEV file\n')
    setup(g, 'write', p+b'/directory/nested/file', data=b'local EXDEV tree\n')
    setup(g, 'symlink', p+b'/directory/child-link', target=b'../file')
    setup(g, 'write', other+b'/file', data=b'other filesystem file\n')
    setup(g, 'write', other+b'/directory/nested/file', data=b'other filesystem tree\n')
    setup(g, 'write', other+b'/existing', data=b'cross destination untouched\n')
    add(g, 'file EXDEV no copy or delete', 2, p+b'/file', other+b'/destination-file')
    add(g, 'directory EXDEV no traversal or fallback', 3, p+b'/directory', other+b'/destination-directory')
    add(g, 'reverse file EXDEV', 2, other+b'/file', p+b'/destination-file')
    add(g, 'reverse directory EXDEV', 3, other+b'/directory', p+b'/destination-directory')
    add(g, 'cross-device existing destination precedence', 2, p+b'/file', other+b'/existing')

    g, p = group('wide')
    g['regular_file_stdin'] = True
    add(g, 'over 32 MiB single component actual kernel refusal', 1, p+b'/'+b'x'*((33<<20)+17))
    add(g, 'over 32 MiB repeated slash successful fd-relative path', 1, p+b'/'*((33<<20)+17)+b'wide-success')
    return result


def encode_case(case):
    a, b = case['first'], case['second']
    return struct.pack('<4Q', case['case_id'], case['operation'], len(a), len(b))+a+b


def input_header(cases):
    return b'HFPRI001'+struct.pack('<Q', len(cases))


def summary(case):
    def span(raw): return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return {'case_id': case['case_id'], 'name': case['name'], 'operation': case['operation'],
            'first': span(case['first']), 'second': span(case['second'])}


def fixture_json(value):
    if isinstance(value, bytes): return {'raw_hex': value.hex()}
    if isinstance(value, list): return [fixture_json(x) for x in value]
    if isinstance(value, dict): return {k: fixture_json(v) for k, v in value.items()}
    return value
