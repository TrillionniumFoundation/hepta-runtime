"""Independently reread all archive bytes, objects and original source-file extents.

No extraction, native execution, compiler or semantic qualification is performed.
The result proves exact preservation of the already qualified retained evidence.
"""
from pathlib import Path, PurePosixPath
import argparse, gzip, hashlib, json, os, stat, sys, tarfile, time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from package_remote import CHUNK, ROOTS, SOURCE_SHA, encoded, identity, pin, qualified, selected, sha

def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--evidence-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    assert not args.output.exists()
    began = time.monotonic_ns()
    raw_index = args.evidence.read_bytes()
    assert sha(raw_index) == args.evidence_sha256
    evidence = decode(raw_index)
    assert evidence['schema'] == 'hepta.runtime.binary-write-composition.archive-ranges.v1'
    assert evidence['source_sha256'] == SOURCE_SHA
    assert evidence['mode'] in ('complete', 'small')
    authority = qualified(evidence['readback_sha256'])
    assert evidence['authority'] == authority
    archive = Path(evidence['archive_path'])
    original_archive_stat = identity(archive.lstat())
    assert stat.S_ISREG(archive.lstat().st_mode) and not archive.is_symlink()
    full = hashlib.sha256(); offset = 0
    with archive.open('rb') as stream:
        for index, row in enumerate(evidence['parts'], 1):
            assert row['index'] == index and row['offset'] == offset
            assert 0 < row['bytes'] <= 9 << 20
            if index != len(evidence['parts']):
                assert row['bytes'] == 9 << 20
            value = stream.read(row['bytes'])
            assert len(value) == row['bytes'] and sha(value) == row['sha256']
            full.update(value); offset += len(value)
        assert stream.read(1) == b''
    assert offset == evidence['archive_bytes'] and full.hexdigest() == evidence['archive_sha256']
    with gzip.open(archive, 'rb') as stream:
        uncompressed = 0
        def item(expected_name, expected_size=None):
            nonlocal uncompressed
            raw = stream.read(512); uncompressed += len(raw)
            assert len(raw) == 512 and raw != b'\0' * 512
            info = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict')
            assert info.name == expected_name and info.type == tarfile.REGTYPE
            assert info.mode == 0o644 and info.uid == info.gid == info.mtime == 0
            assert not info.linkname and not info.pax_headers
            assert 0 <= info.size <= 128 << 20
            if expected_size is not None:
                assert info.size == expected_size
            value = stream.read(info.size); uncompressed += len(value)
            assert len(value) == info.size
            padding = (-info.size) % 512
            assert stream.read(padding) == b'\0' * padding
            uncompressed += padding
            return value
        raw = item('artifact-manifest.json')
        assert sha(raw) == evidence['manifest_sha256']
        manifest = decode(raw)
        assert manifest['schema'] == 'hepta.runtime.binary-write-composition.chunk-archive.v1'
        assert manifest['source_sha256'] == SOURCE_SHA and manifest['mode'] == evidence['mode']
        assert manifest['chunk_bytes'] == CHUNK and manifest['authority'] == authority
        assert manifest['recorded_origins'] == {k:str(v) for k,v in ROOTS.items()}
        assert manifest['complete_composition_capture_included'] is (evidence['mode'] == 'complete')
        objects = manifest['objects']
        for number, (key, size) in enumerate(sorted(objects.items()), 1):
            assert len(key) == 64 and all(c in '0123456789abcdef' for c in key)
            assert 0 < size <= CHUNK
            value = item('objects/' + key, size)
            assert sha(value) == key
            if number % 1000 == 0:
                print(json.dumps(dict(phase='verified-archive-objects', completed=number, total=len(objects))), flush=True)
        assert stream.read(1024) == b'\0' * 1024
        uncompressed += 1024
        padding = stream.read()
        assert len(padding) < 10240 and not any(padding)
        uncompressed += len(padding)
        assert uncompressed % 10240 == 0
    assert identity(archive.lstat()) == original_archive_stat
    files = manifest['files']; special = manifest['special_nodes_as_data']; visited = set(); used = set()
    for path, logical in selected(evidence['mode']):
        relative = PurePosixPath(logical)
        assert not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == logical
        assert logical not in visited
        visited.add(logical)
        before = path.lstat()
        if logical in special:
            expected = special[logical]
            assert stat.S_IMODE(before.st_mode) == expected['mode']
            if expected['kind'] == 'symlink':
                assert stat.S_ISLNK(before.st_mode) and os.readlink(path) == expected['target']
            else:
                assert expected['kind'] == 'fifo' and stat.S_ISFIFO(before.st_mode)
        else:
            assert stat.S_ISREG(before.st_mode) and not path.is_symlink()
            expected = files[logical]
            assert stat.S_IMODE(before.st_mode) == expected['mode']
            whole = hashlib.sha256(); chunks = []; size = 0
            with path.open('rb') as source:
                while value := source.read(CHUNK):
                    key = sha(value)
                    assert objects[key] == len(value)
                    chunks.append(key); used.add(key); size += len(value); whole.update(value)
            assert dict(bytes=size, sha256=whole.hexdigest(), mode=stat.S_IMODE(before.st_mode), chunks=chunks) == expected
        assert identity(path.lstat()) == identity(before)
    assert visited == set(files) | set(special) and used == set(objects)
    assert len(files) == manifest['logical_files'] == evidence['logical_files']
    assert sum(row['bytes'] for row in files.values()) == manifest['logical_bytes'] == evidence['logical_bytes']
    assert sum(objects.values()) == manifest['unique_object_bytes'] == evidence['unique_object_bytes']
    assert qualified(evidence['readback_sha256']) == authority
    assert args.evidence.read_bytes() == raw_index
    report = dict(status='COMPLETE_ARCHIVE_AND_EVERY_RETAINED_SOURCE_BYTE_PASS', mode=evidence['mode'],
        evidence=pin(args.evidence), archive=pin(archive), logical_files=len(files),
        objects=len(objects), special_nodes=len(special), full_payload_bytes_read=True,
        complete_composition_capture_included=evidence['mode']=='complete',
        semantic_qualification_repeated=False, product_executions_added=0,
        source_sha256=SOURCE_SHA, readback_sha256=evidence['readback_sha256'],
        elapsed_seconds=(time.monotonic_ns()-began)/1e9,
        whole_runtime_replaced=False, public_binary_write_registered=False)
    args.output.write_bytes(encoded(report))
    print(json.dumps(report, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
