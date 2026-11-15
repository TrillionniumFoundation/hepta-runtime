"""Archive admitted owned Text fixtures; read-only admission never restores.

Raw paths, special modes, xattrs, FIFO/socket/symlink inodes and complete closed
hardlink groups are retained. Temporary owner-read grants are journaled with
their actual ctime changes and the original mode is restored before retirement.
"""
from pathlib import Path
import os
import stat
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import hia_native_text_publication_pipeline as p
import hia_native_text_publication_qualification as q


def kind(mode):
    for predicate, name in ((stat.S_ISREG, 'file'), (stat.S_ISDIR, 'directory'),
                            (stat.S_ISLNK, 'symlink'), (stat.S_ISFIFO, 'fifo'),
                            (stat.S_ISSOCK, 'socket')):
        if predicate(mode): return name
    raise ValueError('unsupported fixture inode type')


def metadata(st):
    return {'kind': kind(st.st_mode), 'mode': stat.S_IMODE(st.st_mode),
            'uid': st.st_uid, 'gid': st.st_gid, 'nlink': st.st_nlink,
            'identity': [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns // 10**9,
                         st.st_mtime_ns % 10**9, st.st_ctime_ns // 10**9, st.st_ctime_ns % 10**9]}


def exact_inode(first, second, *, ctime=False):
    for key in ('kind', 'mode', 'uid', 'gid', 'nlink'):
        q.same(first[key], second[key], 'owned fixture stable inode metadata')
    q.same(first['identity'][:5] if ctime else first['identity'],
           second['identity'][:5] if ctime else second['identity'], 'owned fixture stable identity')


def specifications(base, admitted):
    base = Path(base); specs = {}
    smoke = {'file': '中🙂'.encode() + b'\0tail\n',
             'large': b'x' * (4 * 1024 * 1024) + b'Y' * 65536,
             'race': b'competitor\n'}
    for folder, values in [('native/native-smoke/files', smoke),
                           ('native/callable-controls/files', {name: b'body\n' for name in ('first', 'second', 'third')})]:
        specs[folder] = {b'': {'kind': 'directory'}}
        specs[folder].update({name.encode(): {'kind': 'file', 'data': q.pin(raw)}
                              for name, raw in values.items()})
    for group in ('pilot', 'full'):
        result = p.read_json(base / 'faults' / group / 'RESULT.json')
        for row in result['cases_completed']:
            folder = 'faults/' + group + '/' + row['name']; nodes = {b'': {'kind': 'directory'}}
            for item in p.read_json(base / folder / 'tree.json'):
                st = item['metadata']
                nodes[bytes.fromhex(item['name_hex'])] = {
                    'kind': 'file', 'mode': stat.S_IMODE(st['st_mode']),
                    'uid': st['st_uid'], 'gid': st['st_gid'], 'nlink': st['st_nlink'],
                    'identity': [st['st_dev'], st['st_ino'], st['st_size'],
                                 st['st_mtime_ns'] // 10**9, st['st_mtime_ns'] % 10**9,
                                 st['st_ctime_ns'] // 10**9, st['st_ctime_ns'] % 10**9],
                    'data': {'bytes': item['content_bytes'], 'sha256': item['content_sha256']}}
            specs[folder + '/files'] = nodes
    for domain in p.DOMAINS:
        folder = 'corpus/domains/' + domain
        for ordinal, desc in enumerate(p.read_json(base / folder / 'corpus.json')):
            rows = p.read_json(base / folder / 'cases' / desc['name'] / 'after.json')
            nodes = {q.unb64(row['path_base64']): dict(row) for row in rows}
            for rel, node in nodes.items():
                if node['kind'] == 'file' and 'data' not in node:
                    setup = [item for item in desc['setup'] if item['kind'] == 'file'
                             and q.unb64(item['path_base64']) == rel]
                    q.same(len(setup), 1, 'unreadable file has one exact source input')
                    from hia_native_text_publication_fixtures import materialize
                    node['data'] = q.pin(materialize(setup[0]['data']))
                elif 'data' in node:
                    node['data'] = {key: node['data'][key] for key in ('bytes', 'sha256')}
                node.pop('read_errno', None); node.pop('path_base64', None)
            specs[folder + '/fixtures/' + str(ordinal)] = nodes
    q.same(len(specs), 173, 'all source-owned Text fixture roots')
    return specs


def own_directory(path):
    path = Path(path).absolute()
    q.require(path.resolve(strict=True) == path and not path.is_symlink(), 'owned directory has no followed alias')
    st = path.lstat()
    q.require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid(), 'owned live fixture directory')
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def xattrs(path):
    try:
        return {'xattrs': {q.b64(os.fsencode(name)): q.b64(os.getxattr(path, name, follow_symlinks=False))
                           for name in sorted(os.listxattr(path, follow_symlinks=False))}}
    except OSError as error: return {'xattr_errno': error.errno}


def save_blob(folder, raw):
    item = q.pin(raw); name = 'blobs/' + item['sha256'] + '.bin'; path = folder / name
    if path.exists(): q.same(p.file_pin(path), item, 'content-addressed complete archive bytes')
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream: stream.write(raw)
    return dict(item, file=name)


def capture_tree(base, name, expected, archive):
    root_fd = own_directory(base / name); nodes, grants = [], []
    def visit(parent, leaf, rel):
        before = metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False))
        node = dict(before, path_base64=q.b64(rel)); q.require(rel in expected, 'no unexpected fixture entry')
        want = expected[rel]; q.same(node['kind'], want['kind'], 'captured fixture kind')
        for key in ('mode', 'uid', 'gid', 'nlink', 'identity'):
            if key in want: q.same(node[key], want[key], 'fixture still equals native captured ' + key)
        procpath = b'/proc/self/fd/' + str(parent).encode() + b'/' + leaf
        node.update(xattrs(procpath))
        for key in ('xattrs', 'xattr_errno'):
            if key in want: q.same(node.get(key), want[key], 'complete native-captured xattrs')
        if node['kind'] == 'directory':
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                q.same(metadata(os.fstat(fd)), before, 'directory opened without substitution')
                for child in sorted(os.fsencode(x) for x in os.listdir(fd)):
                    q.require(child not in (b'.', b'..') and b'/' not in child and b'\0' not in child, 'raw owned child name')
                    visit(fd, child, child if not rel else rel + b'/' + child)
            finally: os.close(fd)
        elif node['kind'] == 'symlink':
            node['target_base64'] = q.b64(os.fsencode(os.readlink(leaf, dir_fd=parent)))
            q.same(node['target_base64'], want['target_base64'], 'complete symlink target bytes')
        elif node['kind'] == 'file':
            granted = False; pinned = os.open(leaf, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                q.same(metadata(os.fstat(pinned)), before, 'pinned regular inode')
                try: fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                except PermissionError:
                    q.same(before['uid'], os.geteuid(), 'grant only our owned regular inode')
                    q.require(not before['mode'] & 0o400, 'only missing owner read bit granted')
                    os.chmod('/proc/self/fd/' + str(pinned), before['mode'] | 0o400)
                    granted = True; granted_state = metadata(os.fstat(pinned))
                    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                try:
                    q.same(metadata(os.fstat(fd))['identity'][:5], before['identity'][:5], 'bytes read from same actual inode')
                    with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read()
                finally: os.close(fd)
            finally:
                if granted:
                    os.chmod('/proc/self/fd/' + str(pinned), before['mode'])
                    restored = metadata(os.fstat(pinned)); exact_inode(before, restored, ctime=True)
                    grants.append({'path_base64': q.b64(rel), 'before': before, 'granted': granted_state, 'restored': restored})
                os.close(pinned)
            node['data'] = save_blob(archive, raw)
            q.same(q.pin(raw), want['data'], 'every archived byte equals native/source capture')
        nodes.append(node)
    try: visit(root_fd, b'.', b'')
    finally: os.close(root_fd)
    q.same({q.unb64(node['path_base64']) for node in nodes}, set(expected), 'complete owned tree membership')
    return {'root': name, 'nodes': sorted(nodes, key=lambda row: q.unb64(row['path_base64'])), 'permission_grants': grants}


def closed_links(trees):
    links = {}
    for tree in trees:
        for row in tree['nodes']:
            if row['kind'] == 'file': links.setdefault(tuple(row['identity'][:2]), []).append(row)
    for rows in links.values():
        q.same(len(rows), rows[0]['nlink'], 'all hardlink names are in the owned archive')
        for row in rows:
            q.same(row['nlink'], len(rows), 'complete hardlink group')
            q.same(row['data'], rows[0]['data'], 'hardlink complete content identity')


def remove_owned(root, expected):
    root = Path(root); fd = own_directory(root)
    table = {q.unb64(row['path_base64']): row for row in expected['nodes']}
    grants = {q.unb64(row['path_base64']): row['restored'] for row in expected['permission_grants']}
    def remove(parent, leaf, rel):
        current = metadata(os.stat(leaf, dir_fd=parent, follow_symlinks=False)); want = grants.get(rel, table[rel])
        if current['kind'] == 'directory':
            q.same(current['identity'][:2], want['identity'][:2], 'same owned directory to remove')
            q.same([current[k] for k in ('mode', 'uid', 'gid')], [want[k] for k in ('mode', 'uid', 'gid')], 'same owned directory permissions')
            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                names = sorted(os.fsencode(x) for x in os.listdir(child))
                expected_names = sorted(path[len(rel)+1:] if rel else path for path in table
                    if path and ((path.rsplit(b'/', 1)[0] if b'/' in path else b'') == rel))
                q.same(names, expected_names, 'complete child membership before retirement')
                for name in names: remove(child, name, name if not rel else rel + b'/' + name)
            finally: os.close(child)
            if rel: os.rmdir(leaf, dir_fd=parent)
        else:
            # Earlier unlink of a name in the same closed hardlink group changes
            # nlink/ctime. The inode, data extent and modes must remain exact.
            q.same(current['identity'][:5], want['identity'][:5], 'same owned non-directory inode and bytes')
            q.same([current[k] for k in ('kind', 'mode', 'uid', 'gid')], [want[k] for k in ('kind', 'mode', 'uid', 'gid')], 'same owned non-directory permissions')
            os.unlink(leaf, dir_fd=parent)
    try: remove(fd, b'.', b'')
    finally: os.close(fd)
    root.rmdir()


def create(base, admitted):
    base = Path(base).absolute(); directory = base / 'retirement'
    q.require(not directory.exists(), 'new owned retirement transaction')
    expected = specifications(base, admitted); directory.mkdir()
    trees = [capture_tree(base, name, nodes, directory) for name, nodes in sorted(expected.items())]
    closed_links(trees)
    index = {'schema': 'hepta.runtime.text-publication-fixture-archive.v1',
             'execution_base': str(Path(admitted['execution']['execution_output_root']) / p.FOLDER),
             'native_evidence': q.pin(p.encoded(admitted)), 'roots': trees,
             'source_sha256': p.source_table(ROOT), 'restoration_performed': False}
    p.write_new(directory / 'archive.json', index)
    evidence(base, admitted, require_retired=False)
    for tree in trees: remove_owned(base / tree['root'], tree)
    p.write_new(directory / 'retired.json', {'status': 'PASS', 'archive': p.file_pin(directory / 'archive.json'),
        'roots': [tree['root'] for tree in trees], 'all_owned_roots_absent': True,
        'native_evidence': q.pin(p.encoded(admitted)), 'restoration_performed': False})
    return evidence(base, admitted)


def evidence(base, admitted, *, require_retired=True):
    """Pure retained-byte verification; never opens or recreates live fixtures."""
    base = Path(base).absolute(); directory = base / 'retirement'
    index = p.read_json(directory / 'archive.json')
    q.same(index['schema'], 'hepta.runtime.text-publication-fixture-archive.v1', 'archive schema')
    q.same(index['native_evidence'], q.pin(p.encoded(admitted)), 'exact complete native predecessor')
    q.same(index['source_sha256'], p.source_table(ROOT), 'archive actual source producer')
    q.same(index['restoration_performed'], False, 'no archive restoration claim')
    q.same(index['execution_base'], str(Path(admitted['execution']['execution_output_root']) / p.FOLDER), 'recorded original fixture origin')
    expected = specifications(base, admitted)
    q.same([row['root'] for row in index['roots']], sorted(expected), 'exact fixture root set')
    artifacts = {'retirement/archive.json': p.file_pin(directory / 'archive.json')}; grant_count = 0
    for tree in index['roots']:
        names = {q.unb64(row['path_base64']): row for row in tree['nodes']}
        q.same(len(names), len(tree['nodes']), 'no duplicate archive node')
        q.same(set(names), set(expected[tree['root']]), 'complete archived tree')
        grant_paths = set()
        for grant in tree['permission_grants']:
            q.same(set(grant), {'path_base64', 'before', 'granted', 'restored'}, 'exact permission journal fields')
            rel = q.unb64(grant['path_base64']); q.require(rel not in grant_paths, 'unique permission grant')
            grant_paths.add(rel)
            q.same(grant['before'], {k: names[rel][k] for k in ('kind', 'mode', 'uid', 'gid', 'nlink', 'identity')}, 'actual grant preimage')
            q.require(grant['before']['kind'] == 'file' and not grant['before']['mode'] & 0o400, 'needed owned read permission')
            q.same(grant['granted']['mode'], grant['before']['mode'] | 0o400, 'only owner read granted')
            exact_inode(grant['before'], grant['restored'], ctime=True)
            q.same(grant['granted']['identity'][:5], grant['before']['identity'][:5], 'grant preserves inode and bytes')
        q.same(grant_paths, {rel for rel, node in names.items() if node['kind'] == 'file' and not node['mode'] & 0o400}, 'complete unreadable inode grant journal')
        grant_count += len(grant_paths)
        for rel, node in names.items():
            want = expected[tree['root']][rel]
            for key, value in want.items():
                if key == 'data': q.same({k: node['data'][k] for k in ('bytes', 'sha256')}, value, 'archive full original body pin')
                else: q.same(node.get(key), value, 'archive source/native metadata ' + key)
            if node['kind'] == 'file':
                item = node['data']; q.same(item['file'], 'blobs/' + item['sha256'] + '.bin', 'archive content address')
                q.same(p.file_pin(directory / item['file']), {k: item[k] for k in ('bytes', 'sha256')}, 'complete retained file bytes')
                artifacts['retirement/' + item['file']] = p.file_pin(directory / item['file'])
    closed_links(index['roots'])
    if require_retired:
        result = p.read_json(directory / 'retired.json')
        q.same(result, {'status': 'PASS', 'archive': p.file_pin(directory / 'archive.json'),
            'roots': sorted(expected), 'all_owned_roots_absent': True,
            'native_evidence': q.pin(p.encoded(admitted)), 'restoration_performed': False}, 'complete retirement receipt')
        q.require(all(not os.path.lexists(base / name) for name in expected), 'all private fixtures retired')
        artifacts['retirement/retired.json'] = p.file_pin(directory / 'retired.json')
    return {'schema': 'hepta.runtime.text-publication-retirement-evidence.v1', 'status': 'PASS',
            'fixture_roots': len(expected), 'permission_grants': grant_count,
            'artifact_sha256': {p.FOLDER + '/' + name: item['sha256'] for name, item in sorted(artifacts.items())},
            'artifact_pins': {p.FOLDER + '/' + name: item for name, item in sorted(artifacts.items())},
            'native_evidence': q.pin(p.encoded(admitted)), 'native_execution': 0, 'original_execution': 0,
            'fixtures_restored': False, 'public_handler_replaced': False, 'whole_runtime_replaced': False}
