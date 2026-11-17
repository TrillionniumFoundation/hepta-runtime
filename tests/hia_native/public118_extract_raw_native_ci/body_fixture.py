from pathlib import Path
import hashlib,os,stat,struct


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())



def q(*values):
    return struct.pack('<' + 'Q' * len(values), *values)



def canonical(work, raw):
    return os.path.realpath(os.path.join(os.fsencode(work), raw)).decode('utf-8', 'replace').encode()



def setup(spec, work):
    work.mkdir()
    root = os.fsencode(work)
    def target(name):
        if not name or name.startswith(b'/') or b'..' in name.split(b'/') or b'\0' in name:
            raise ValueError('setup path is outside the private ordinary fixture')
        return os.path.join(root, name)
    for name in spec['directories']:
        os.makedirs(target(name), mode=0o750, exist_ok=False)
    for name, content, mode in spec['files']:
        path = target(name); os.makedirs(os.path.dirname(path), mode=0o750, exist_ok=True)
        with open(path, 'xb') as stream:
            stream.write(content)
        os.chmod(path, mode)
    for name, original in spec['hardlinks']:
        os.link(target(original), target(name))
    for name, destination in spec['symlinks']:
        if destination.startswith(b'/') or b'..' in destination.split(b'/'):
            raise ValueError('symlink fixture escapes the work directory')
        os.symlink(destination, target(name))
    for name, mode in spec['directory_modes']:
        os.chmod(target(name), mode)



def blob(vault, raw):
    row = pin(raw); path = vault / (row['sha256'] + '.bin')
    if path.exists():
        if path.read_bytes() != raw:
            raise ValueError('content-addressed observation differs')
    else:
        path.write_bytes(raw)
    return dict(path=path.name, **row)



def tree_snapshot(work, vault):
    root = os.fsencode(work); nodes = []; groups = {}
    def visit(folder, prefix):
        for entry in sorted(os.scandir(folder), key=lambda value: value.name):
            name = prefix + entry.name; info = entry.stat(follow_symlinks=False)
            row = dict(path_hex=name.hex(), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                       gid=info.st_gid, links=info.st_nlink)
            if stat.S_ISREG(info.st_mode):
                try:
                    with open(entry.path, 'rb') as stream: raw = stream.read()
                except PermissionError:
                    # Quiescent fixture capture only: restore the exact original mode
                    # before the next actual tool operation; no runtime policy lives here.
                    os.chmod(entry.path, stat.S_IMODE(info.st_mode) | 0o400)
                    try:
                        with open(entry.path, 'rb') as stream: raw = stream.read()
                    finally:
                        os.chmod(entry.path, stat.S_IMODE(info.st_mode))
                if len(raw) != info.st_size or stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode) != stat.S_IMODE(info.st_mode):
                    raise ValueError('ordinary file changed during its completed observation')
                row.update(kind='file', content=blob(vault, raw))
                groups.setdefault((info.st_dev, info.st_ino), []).append(name.hex())
            elif stat.S_ISDIR(info.st_mode):
                row['kind'] = 'directory'
            elif stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target_hex=os.readlink(entry.path).hex())
            else:
                raise ValueError('ordinary fixture contains a special filesystem object')
            nodes.append(row)
            if row['kind'] == 'directory':
                visit(entry.path, name + b'/')
    visit(root, b'')
    return dict(nodes=sorted(nodes, key=lambda row: bytes.fromhex(row['path_hex'])),
                hardlink_groups=sorted(sorted(group) for group in groups.values() if len(group) > 1))

