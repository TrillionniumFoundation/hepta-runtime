"""Owned filesystem fixtures and complete observations, outside the unchanged originals."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
from protocol import require


def component(raw):
    require(type(raw) is bytes and raw and b'/' not in raw and b'\0' not in raw
            and raw not in (b'.', b'..'), 'owned fixture component')
    return raw


def setup(root, rows):
    root = Path(root).absolute()
    root.mkdir(parents=False, exist_ok=False)
    os.chmod(root, 0o700)
    for i, case in enumerate(rows):
        folder = os.fsencode(root / ('case-%04d' % i))
        os.mkdir(folder, 0o700)
        seen = set()
        for entry in case['entries']:
            name = component(bytes.fromhex(entry['name_hex']))
            require(name not in seen, 'unique fixture path')
            seen.add(name);path = folder + b'/' + name
            kind = entry['kind']
            if kind == 'file':
                raw = bytes.fromhex(entry['data_hex'])
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
                try:
                    at = 0
                    while at < len(raw):
                        count = os.write(descriptor, raw[at:])
                        require(count > 0, 'fixture complete write');at += count
                    os.fchmod(descriptor, entry['mode'])
                finally:
                    os.close(descriptor)
            elif kind == 'directory':
                os.mkdir(path, entry['mode']);os.chmod(path, entry['mode'])
            elif kind == 'fifo':
                os.mkfifo(path, entry['mode']);os.chmod(path, entry['mode'])
            elif kind == 'hardlink':
                target = component(bytes.fromhex(entry['target_hex']))
                require(target in seen, 'previous owned hardlink source')
                os.link(folder + b'/' + target, path, follow_symlinks=False)
            elif kind == 'symlink':
                target = component(bytes.fromhex(entry['target_hex']))
                os.symlink(target, path)
            else:
                raise ValueError('unknown fixture kind')
        os.chmod(folder, case['root_mode'])
    return root


def metadata(value):
    return {key: getattr(value, key) for key in (
        'st_mode','st_uid','st_gid','st_nlink','st_size','st_dev','st_ino',
        'st_atime_ns','st_mtime_ns','st_ctime_ns')}


def snapshot(folder):
    folder = os.fsencode(Path(folder).absolute())
    rows = []
    def visit(path, relative):
        before = os.lstat(path)
        row = dict(path_hex=relative.hex(), stat=metadata(before))
        if stat.S_ISREG(before.st_mode):
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            try:
                opened = os.fstat(descriptor)
                require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                        'observed exact owned inode')
                chunks = []
                while True:
                    raw = os.read(descriptor, 65536)
                    if not raw:
                        break
                    chunks.append(raw)
                raw = b''.join(chunks)
                after = os.fstat(descriptor)
                require((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) == after.st_size,
                        'observed stable full file')
                row.update(kind='file', data_hex=raw.hex(), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            finally:
                os.close(descriptor)
        elif stat.S_ISDIR(before.st_mode):
            row['kind'] = 'directory'
        elif stat.S_ISLNK(before.st_mode):
            row.update(kind='symlink', target_hex=os.readlink(path).hex())
        elif stat.S_ISFIFO(before.st_mode):
            row['kind'] = 'fifo'
        else:
            raise ValueError('unexpected owned fixture type')
        rows.append(row)
        if row['kind'] == 'directory':
            for name in sorted(os.listdir(path)):
                component(name)
                visit(path + b'/' + name, relative + (b'/' if relative else b'') + name)
    visit(folder, b'')
    return rows


def normalized(rows):
    groups = {}
    for row in rows:
        if row['kind'] == 'file':
            key = (row['stat']['st_dev'], row['stat']['st_ino'])
            groups.setdefault(key, []).append(row['path_hex'])
    result = []
    for row in rows:
        st = row['stat']
        value = dict(path_hex=row['path_hex'], kind=row['kind'], mode=st['st_mode'],
                     uid=st['st_uid'], gid=st['st_gid'], nlink=st['st_nlink'])
        if row['kind'] == 'file':
            raw = bytes.fromhex(row['data_hex'])
            require(len(raw) == row['bytes'] == st['st_size'] and
                    hashlib.sha256(raw).hexdigest() == row['sha256'], 'complete observed file bytes')
            value.update(data_hex=row['data_hex'], size=st['st_size'],
                         hardlinks=sorted(groups[(st['st_dev'], st['st_ino'])]))
        elif row['kind'] == 'symlink':
            value['target_hex'] = row['target_hex']
        result.append(value)
    return result


def retire(root, rows):
    root = Path(root).absolute()
    final = [snapshot(root / ('case-%04d' % i)) for i in range(len(rows))]
    identity = root.lstat()
    # This is fixture teardown after the real child is reaped, never a semantic effect.
    for i in range(len(rows)):
        os.chmod(root / ('case-%04d' % i), 0o700)
    shutil.rmtree(root)
    require(not root.exists(), 'retired only the owned fixture root')
    return dict(owned_root=str(root), device=identity.st_dev, inode=identity.st_ino,
                complete_final_observations=final, removed_after_capture=True)
