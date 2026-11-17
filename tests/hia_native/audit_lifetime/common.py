"""Exact source and complete regular-file envelopes for the native boundary."""
from pathlib import Path
import hashlib
import json
import stat

ROOT = Path(__file__).resolve().parent
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
HEPTA_COMMIT = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
HEPTA_TREE = '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(raw):
    return dict(bytes=len(raw), sha256=sha(raw))


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def loads(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def read(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute(), 'non-aliased regular file')
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda row: (row.st_mode, row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    require(identity(info) == identity(after) and len(raw) == info.st_size, 'complete stable file read')
    return raw


def files(root, omit=()):
    root = Path(root).resolve(strict=True)
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'ordinary capture entry')
        name = path.relative_to(root).as_posix()
        if stat.S_ISREG(info.st_mode) and name not in omit:
            result[name] = dict(**pin(read(path)), mode=stat.S_IMODE(info.st_mode))
    return result


def source():
    raw = read(ROOT / 'SOURCE_MANIFEST.json')
    manifest = loads(raw)
    require(manifest['schema'] == 'hepta.audit-lifetime.source.v1', 'source manifest schema')
    require(manifest['compiler_commit'] == HEPTA_COMMIT and manifest['compiler_sha256'] == COMPILER,
            'source compiler identity')
    actual = files(ROOT, ('SOURCE_MANIFEST.json',))
    require(set(actual) == set(manifest['files']), 'complete source set')
    for name, row in actual.items():
        require({k: row[k] for k in ('bytes', 'sha256')} == manifest['files'][name]
                and row['mode'] == 0o644, 'complete source bytes and mode: ' + name)
    return sha(raw)


def seal(root, metadata):
    root = Path(root).resolve(strict=True)
    require(not (root / 'CAPTURE.json').exists(), 'capture seals only once')
    value = dict(metadata, files=files(root))
    (root / 'CAPTURE.json').write_bytes(encoded(value))
    return value


def envelope(root):
    root = Path(root).resolve(strict=True)
    value = loads(read(root / 'CAPTURE.json'))
    require(value['files'] == files(root, ('CAPTURE.json',)), 'complete capture bytes, modes, and set')
    return value
