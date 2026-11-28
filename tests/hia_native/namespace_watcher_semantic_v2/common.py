"""Source and byte identity helpers; no semantic execution during import."""
import hashlib
import json
import os
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'regular retained file: ' + str(path))
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'retained descriptor identity')
        raw = stream.read()
        after = os.fstat(stream.fileno())
    require((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
            (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and len(raw) == after.st_size,
            'stable complete retained read')
    return raw


def source(root=ROOT):
    raw = read(root / 'SOURCE.json')
    manifest = loads(raw)
    require(manifest['schema'] == 'hepta.namespace-watcher.semantic-source.v1', 'source manifest schema')
    for name, expected in manifest['files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts, 'source relative identity')
        actual = read(root / path)
        require(pin(actual) == {key: expected[key] for key in ('bytes', 'sha256')}, 'complete source pin: ' + name)
        require(hashlib.sha1(b'blob ' + str(len(actual)).encode() + b'\0' + actual).hexdigest() ==
                expected['git_blob'], 'source Git identity: ' + name)
    require(set(files(root))==set(manifest['files'])|{'SOURCE.json'}, 'complete frozen source file set')
    return pin(raw)['sha256']


def sha(raw):
    return pin(raw)['sha256']

def files(root,exclude=()):
    root=Path(root);result={}
    for folder,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:
            require(stat.S_ISDIR((Path(folder)/name).lstat().st_mode),'ordinary retained directory')
        for name in names:
            path=Path(folder)/name;relative=path.relative_to(root).as_posix()
            if relative not in exclude:result[relative]=dict(**pin(read(path)),mode=stat.S_IMODE(path.lstat().st_mode))
    return result
