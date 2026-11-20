"""Restore exact ordinary files from a pinned composition evidence archive.

This is DATA preservation only. Recorded semantic origins are never rewritten;
the original strict readers retain their source, interpreter and argv checks.
Special filesystem nodes remain JSON descriptions and are never recreated.
"""
from pathlib import Path, PurePosixPath
import argparse, gzip, hashlib, json, os, stat, tarfile, time

SOURCE = '4b3ef39a1c93b9d786407310240b890008c5dc468b6db315bd5f03693de896d0'
READBACK = 'c2470b307aa3122559df27b13342099d0538f1538fc058c434693cdac1cda2dd'
CHUNK = 1 << 20

def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            assert key not in result, 'duplicate JSON key'
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def identity(path):
    value = path.lstat()
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)

def regular(path):
    assert stat.S_ISREG(path.lstat().st_mode) and not path.is_symlink()

def relative_name(name, roots=None):
    value = PurePosixPath(name)
    assert name and name == value.as_posix() and not value.is_absolute()
    assert '..' not in value.parts and '\\' not in name
    if roots is not None:
        assert value.parts[0] in roots and len(value.parts) > 1
    return value

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--index', type=Path, required=True)
    p.add_argument('--index-sha256', required=True)
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--archive', type=Path)
    group.add_argument('--parts', type=Path, help='Published PARTS.json with exact range files')
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    began = time.monotonic_ns()
    raw_index = args.index.read_bytes()
    assert sha(raw_index) == args.index_sha256
    evidence = decode(raw_index)
    assert evidence['schema'] == 'hepta.runtime.binary-write-composition.archive-ranges.v1'
    assert evidence['mode'] in ('complete', 'small')
    assert evidence['source_sha256'] == SOURCE and evidence['readback_sha256'] == READBACK
    assert evidence['public_binary_write_registered'] is False
    assert evidence['whole_runtime_replaced'] is False
    assert not args.output.exists() and not args.output.is_symlink()
    args.output.mkdir(parents=True)
    archive = args.archive
    if args.parts is not None:
        parts = decode(args.parts.read_bytes())
        assert parts['schema'] == 'hepta.runtime.binary-write-composition.git-parts.v1'
        assert parts['index'] == dict(bytes=len(raw_index), sha256=sha(raw_index))
        assert len(parts['parts']) == len(evidence['parts'])
        archive = args.output / 'assembled.tar.gz'
        with archive.open('xb') as target:
            for row, original in zip(parts['parts'], evidence['parts']):
                assert {k:v for k,v in row.items() if k != 'path'} == original
                relative = relative_name(row['path'])
                assert len(relative.parts) == 1, 'range files are immediate ordinary children'
                path = args.parts.parent / relative
                regular(path)
                raw = path.read_bytes()
                assert len(raw) == original['bytes'] and sha(raw) == original['sha256']
                target.write(raw)
    regular(archive)
    before = identity(archive)
    full, size = hashlib.sha256(), 0
    with archive.open('rb') as stream:
        for index, row in enumerate(evidence['parts'], 1):
            assert row['index'] == index and row['offset'] == size
            assert type(row['bytes']) is int and 0 < row['bytes'] <= 9 << 20
            assert index == len(evidence['parts']) or row['bytes'] == 9 << 20
            raw = stream.read(row['bytes'])
            assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
            full.update(raw); size += len(raw)
        assert stream.read(1) == b''
    assert size == evidence['archive_bytes'] and full.hexdigest() == evidence['archive_sha256']
    objects = args.output / 'objects'; objects.mkdir()
    with gzip.open(archive, 'rb') as stream:
        extent = 0
        def item(name, expected_size=None):
            nonlocal extent
            header = stream.read(512); extent += len(header)
            assert len(header) == 512 and header != bytes(512)
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            assert info.name == name and info.type == tarfile.REGTYPE
            assert info.mode == 0o644 and info.uid == info.gid == info.mtime == 0
            assert not info.linkname and not info.pax_headers
            assert 0 <= info.size <= 128 << 20
            if expected_size is not None:
                assert info.size == expected_size
            raw = stream.read(info.size); extent += len(raw)
            assert len(raw) == info.size
            padding = -info.size % 512
            assert stream.read(padding) == bytes(padding)
            extent += padding
            return raw
        raw = item('artifact-manifest.json')
        assert sha(raw) == evidence['manifest_sha256']
        manifest = decode(raw)
        assert manifest['schema'] == 'hepta.runtime.binary-write-composition.chunk-archive.v1'
        assert manifest['source_sha256'] == SOURCE and manifest['mode'] == evidence['mode']
        assert manifest['chunk_bytes'] == CHUNK and manifest['authority'] == evidence['authority']
        assert manifest['complete_composition_capture_included'] is (evidence['mode'] == 'complete')
        assert set(manifest['recorded_origins']) == {'dev1', 'r2', 'r3', 'r4'}
        assert manifest['runtime_product_executions_added'] == 0
        assert manifest['public_binary_write_registered'] is False
        assert manifest['whole_runtime_replaced'] is False
        (args.output / 'artifact-manifest.json').write_bytes(raw)
        for key, length in sorted(manifest['objects'].items()):
            assert len(key) == 64 and all(c in '0123456789abcdef' for c in key)
            assert type(length) is int and 0 < length <= CHUNK
            raw = item('objects/' + key, length)
            assert sha(raw) == key
            with (objects/key).open('xb') as target:
                target.write(raw)
        assert stream.read(1024) == bytes(1024)
        extent += 1024
        padding = stream.read(10240)
        assert len(padding) < 10240 and not any(padding) and stream.read(1) == b''
        extent += len(padding)
        assert extent % 10240 == 0
    assert identity(archive) == before and args.index.read_bytes() == raw_index
    restored = args.output / 'restored'; restored.mkdir()
    used, total = set(), 0
    files = manifest['files']
    for name, row in files.items():
        relative = relative_name(name, manifest['recorded_origins'])
        assert type(row['mode']) is int and 0 <= row['mode'] <= 0o777
        target = restored / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        count, whole = 0, hashlib.sha256()
        with target.open('xb') as output:
            for key in row['chunks']:
                assert key in manifest['objects']
                raw = (objects/key).read_bytes()
                assert len(raw) == manifest['objects'][key] and sha(raw) == key
                output.write(raw); whole.update(raw); count += len(raw); used.add(key)
        target.chmod(row['mode'])
        assert count == row['bytes'] and whole.hexdigest() == row['sha256']
        assert target.stat().st_size == count and digest(target) == row['sha256']
        assert stat.S_IMODE(target.stat().st_mode) == row['mode']
        total += count
    special = manifest['special_nodes_as_data']
    assert set(files).isdisjoint(special)
    for name, row in special.items():
        relative_name(name, manifest['recorded_origins'])
        assert row['kind'] in ('symlink', 'fifo') and type(row['mode']) is int
        assert 0 <= row['mode'] <= 0o777
        if row['kind'] == 'symlink':
            assert type(row['target']) is str
    assert used == set(manifest['objects'])
    assert len(files) == manifest['logical_files'] == evidence['logical_files']
    assert total == manifest['logical_bytes'] == evidence['logical_bytes']
    assert sum(manifest['objects'].values()) == manifest['unique_object_bytes'] == evidence['unique_object_bytes']
    result = dict(status='EXACT_ORDINARY_ARCHIVE_FILES_RESTORED', mode=evidence['mode'],
        index=dict(bytes=len(raw_index), sha256=sha(raw_index)), archive_bytes=size,
        archive_sha256=full.hexdigest(), manifest_sha256=evidence['manifest_sha256'],
        logical_files=len(files), logical_bytes=total, special_nodes_as_data=len(special),
        complete_composition_capture_included=evidence['mode']=='complete',
        recorded_origins=manifest['recorded_origins'], semantic_origins_rewritten=False,
        semantic_qualification_repeated=False, product_executions_added=0,
        source_sha256=SOURCE, readback_sha256=READBACK,
        elapsed_seconds=(time.monotonic_ns()-began)/1e9,
        whole_runtime_replaced=False, public_binary_write_registered=False)
    (args.output/'RESTORED.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    main()
