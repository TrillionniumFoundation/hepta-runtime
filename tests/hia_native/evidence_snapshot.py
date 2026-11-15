"""Copy admitted evidence files without traversing unrelated test fixtures."""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile


@contextmanager
def unrelated_fixture_guard(source):
    """Exercise snapshots beside fresh filesystem fixtures without traversing them."""
    source = Path(source).absolute()
    if (any(part.startswith('.hepta-') for part in source.parts)
            or source.resolve(strict=True) != source or not source.is_dir()):
        raise ValueError('snapshot fixtures require a canonical evidence directory')
    with tempfile.TemporaryDirectory(prefix='snapshot-fixtures-', dir=source) as name:
        folder = Path(name)
        raw = folder / os.fsdecode(b'raw-\xff')
        raw.write_bytes(b'unchanged filesystem fixture\0\xff\n')
        raw.chmod(0o640)
        os.link(raw, folder / 'hardlink')
        (folder / 'loop-a').symlink_to('loop-b')
        (folder / 'loop-b').symlink_to('loop-a')
        (folder / 'dangling').symlink_to('absent')
        os.mkfifo(folder / 'fifo', 0o600)

        def state():
            entries = {}
            for path in folder.iterdir():
                info = path.lstat()
                row = (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                       info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if stat.S_ISREG(info.st_mode):
                    row += (path.read_bytes(),)
                elif stat.S_ISLNK(info.st_mode):
                    row += (os.readlink(path),)
                elif not stat.S_ISFIFO(info.st_mode):
                    raise AssertionError('unexpected snapshot regression fixture type')
                entries[os.fsencode(path.name)] = row
            return entries

        before = state()
        try:
            yield folder
        finally:
            if state() != before:
                raise AssertionError('evidence snapshot changed unrelated filesystem fixtures')


def copy_evidence_files(source, destination, expected):
    """Copy a nonempty relative-path/SHA256 closure into a new private directory."""
    source, destination = Path(source).absolute(), Path(destination).absolute()
    if any(part.startswith('.hepta-') for root in (source, destination) for part in root.parts):
        raise ValueError('protected path is outside evidence snapshots')
    if source.resolve(strict=True) != source or not source.is_dir():
        raise ValueError('evidence source must be a canonical directory')
    if type(expected) is not dict or not expected:
        raise ValueError('evidence file closure must be a nonempty map')
    names = {}
    for name, digest in expected.items():
        if type(name) is not str or '\\' in name:
            raise ValueError('evidence file name must be a relative POSIX path')
        relative = PurePosixPath(name)
        if (relative.is_absolute() or not relative.parts
                or name != relative.as_posix()
                or any(part in ('', '.', '..') or part.startswith('.hepta-')
                       for part in relative.parts)):
            raise ValueError('evidence file escaped its admitted directory')
        if type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
            raise ValueError('evidence file digest must be a SHA256')
        names[name] = digest
    destination.mkdir(mode=0o700)
    copied = {}
    for name in sorted(names):
        original, target = source / name, destination / name
        if original.resolve(strict=True) != original:
            raise ValueError('evidence file must not traverse a symbolic link')
        before = original.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_mode & 0o7000:
            raise ValueError('evidence file must be an ordinary regular file')
        raw = original.read_bytes()
        after = original.stat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise ValueError('evidence file changed while copying')
        digest = hashlib.sha256(raw).hexdigest()
        if digest != names[name]:
            raise ValueError('evidence file differs from its admitted SHA256')
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(stat.S_IMODE(before.st_mode))
        if target.read_bytes() != raw or stat.S_IMODE(target.stat().st_mode) != stat.S_IMODE(before.st_mode):
            raise ValueError('evidence snapshot full read-back differs')
        copied[name] = {'bytes': len(raw), 'sha256': digest,
                        'mode': stat.S_IMODE(before.st_mode)}
    return copied
