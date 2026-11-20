"""Preserve full composition evidence without rerunning a product or copying CAS twice.

All source files are streamed in full. Content objects are reread by exact extent
from the immutable originals when creating the archive; they are not staged as
a second multi-GiB tree. Logical 9-MiB transport ranges have complete SHA256s.
"""
from pathlib import Path
import argparse, gzip, hashlib, io, json, os, shutil, stat, tarfile, time

SOURCE_SHA = '4b3ef39a1c93b9d786407310240b890008c5dc468b6db315bd5f03693de896d0'
PARENT_SOURCE_SHA = 'b674d9c033dd43350a2d5f38039df469c8983149c0e568ab9c51ca614411d612'
PARENT_INDEX_SHA = '6f944c79168fd548000d2da3ad6a2e8f78b44d6781cd6e01b74b5da089c46a4e'
PARENT_ARCHIVE_SHA = 'cb99b9b9766b2ea5153d77964c34107b1048b17e1a67623d3ef62d331ccdde7f'
HOME_ROOT = Path('/home/qian-qi')
ROOTS = {'dev1': HOME_ROOT / 'hia-binary-composition-20261120-dev1',
    **{f'r{n}': HOME_ROOT / f'hia-binary-composition-20261120-r{n}' for n in (2, 3, 4)}}
CHUNK = 1 << 20

def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def pin(path):
    return dict(bytes=path.stat().st_size, sha256=file_sha(path))

def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def qualified(expected_readback):
    root = ROOTS['r4']
    assert file_sha(root / 'source/SOURCE_MANIFEST.json') == SOURCE_SHA
    assert file_sha(root / 'source/parent/SOURCE_MANIFEST.json') == PARENT_SOURCE_SHA
    process = json.loads((root / 'PROCESS.json').read_bytes())
    assert process['returncode'] == 0 and process['source_sha256'] == SOURCE_SHA
    q = json.loads((root / 'qualification/QUALIFICATION.json').read_bytes())
    assert q['status'] == 'PASS_COMPLETE_PRIVATE_COMPOSITION'
    expected_stages = ['source', 'reader-controls', 'parent-reader-controls', 'adapter-reader-controls',
        'build', 'link', 'build-data', 'boundary', 'boundary-data', 'original-pure-capture',
        'original-pure-data', 'full-capture', 'full-data']
    assert [row['name'] for row in q['stages']] == expected_stages
    for row in q['stages']:
        assert row['returncode'] == 0 and row['timed_out'] is False and row['whole_group_gone'] is True
    receipt = root / 'qualification/READBACK.json'
    assert pin(receipt) == q['receipts']['READBACK.json'] and file_sha(receipt) == expected_readback
    value = json.loads(receipt.read_bytes())
    assert value['status'] == 'READONLY_PASS' and value['before'] == value['after']
    assert value['timeout_seconds'] == 600 and value['elapsed_seconds'] < 600
    assert len(value['probes']) == 11 and all(row['rejected'] for row in value['probes'])
    result = value['evidence']
    assert result['status'] == 'PASS_COMPLETE_FROZEN_COMPOSITION_DOMAIN'
    for name, number in dict(cases=254, original_parent_inputs=256, typed_null_refusals=2,
            complete_lane_runs=985, original_complete_lane_runs=992, original_runs=508,
            native_observed_runs=254, native_unobserved_runs=223, actual_retry_controls=6,
            explicit_sigterm_cancellations=6).items():
        assert result[name] == number, name
    assert result['whole_runtime_replaced'] is False and result['public_binary_write_registered'] is False
    return dict(qualification=pin(root / 'qualification/QUALIFICATION.json'), readback=pin(receipt),
        process=pin(root / 'PROCESS.json'), complete_natural_runs=985, original_complete_natural_runs=992,
        actual_retry_sigterm_controls=6, typed_null_refusals=2, original_pure_domains=[433,196,256],
        buffers=result['buffers'], reader_elapsed_seconds=value['elapsed_seconds'])

def walk(root):
    for here, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in ('.git', '__pycache__'))
        for name in list(dirs):
            path = Path(here) / name
            if path.is_symlink():
                yield path
                dirs.remove(name)
        for name in sorted(names):
            if not name.endswith('.pyc'):
                yield Path(here) / name

def selected(mode):
    if mode == 'complete':
        for label, root in ROOTS.items():
            for path in walk(root):
                yield path, label + '/' + path.relative_to(root).as_posix()
        return
    root = ROOTS['r4']
    for folder in ('source', 'compiler-source', 'bootstrap', 'qualification/images',
                   'qualification/linked', 'qualification/pure', 'qualification/boundary'):
        for path in walk(root / folder):
            yield path, 'r4/' + path.relative_to(root).as_posix()
    for folder in (root, root / 'qualification', root / 'qualification/full'):
        for path in sorted(folder.iterdir()):
            if path.is_file():
                yield path, 'r4/' + path.relative_to(root).as_posix()
    path = root / 'qualification/full/capture/CAPTURE.json'
    yield path, 'r4/' + path.relative_to(root).as_posix()
    for label in ('dev1', 'r2', 'r3'):
        root = ROOTS[label]
        for path in walk(root / 'source'):
            yield path, label + '/' + path.relative_to(root).as_posix()
        for folder in (root, root / 'qualification'):
            if folder.is_dir():
                for path in sorted(folder.iterdir()):
                    if path.is_file():
                        yield path, label + '/' + path.relative_to(root).as_posix()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('complete', 'small'), required=True)
    parser.add_argument('--readback-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--complete-index', type=Path)
    args = parser.parse_args()
    authority = qualified(args.readback_sha256)
    parent_index_path = HOME_ROOT / 'hia-binary-parent-complete-package-20261120-r3/parts/EVIDENCE.json'
    assert file_sha(parent_index_path) == PARENT_INDEX_SHA
    parent = json.loads(parent_index_path.read_bytes())
    assert parent['archive_sha256'] == PARENT_ARCHIVE_SHA and parent['archive_bytes'] == 4985841200
    assert parent['complete_natural_runs'] == 992 and parent['actual_retry_sigterm_controls'] == 6
    external_composition = None
    if args.mode == 'small':
        assert args.complete_index is not None
        complete = json.loads(args.complete_index.read_bytes())
        assert complete['mode'] == 'complete' and complete['complete_composition_capture_included'] is True
        assert complete['source_sha256'] == SOURCE_SHA and complete['readback_sha256'] == args.readback_sha256
        external_composition = dict(index_path=str(args.complete_index), index=pin(args.complete_index),
            archive_path=complete['archive_path'], archive_bytes=complete['archive_bytes'],
            archive_sha256=complete['archive_sha256'], payload_reread_by_this_packager=False)
    else:
        assert args.complete_index is None
    out = args.output.absolute()
    assert not out.exists() and not any(out.is_relative_to(root) for root in ROOTS.values())
    out.mkdir(mode=0o700)
    began = time.monotonic_ns()
    files, objects, locations, physical, special = {}, {}, {}, {}, {}
    def add(path, logical):
        assert logical not in files and logical not in special
        before = path.lstat()
        physical[logical] = (path, identity(before))
        if stat.S_ISLNK(before.st_mode):
            special[logical] = dict(kind='symlink', target=os.readlink(path), mode=stat.S_IMODE(before.st_mode))
        elif stat.S_ISFIFO(before.st_mode):
            special[logical] = dict(kind='fifo', mode=stat.S_IMODE(before.st_mode))
        else:
            assert stat.S_ISREG(before.st_mode), (path, before.st_mode)
            whole, size, chunks = hashlib.sha256(), 0, []
            with path.open('rb') as stream:
                while raw := stream.read(CHUNK):
                    key = sha(raw)
                    if key not in objects:
                        objects[key] = len(raw)
                        locations[key] = (path, size)
                    else:
                        assert objects[key] == len(raw)
                    whole.update(raw); size += len(raw); chunks.append(key)
            files[logical] = dict(bytes=size, sha256=whole.hexdigest(), mode=stat.S_IMODE(before.st_mode), chunks=chunks)
        assert identity(path.lstat()) == identity(before), path
    last_root = None
    for path, logical in selected(args.mode):
        label = logical.split('/', 1)[0]
        if label != last_root:
            print(json.dumps(dict(phase='capture-root', root=label, files=len(files), mode=args.mode)), flush=True)
            last_root = label
        add(path, logical)
    assert qualified(args.readback_sha256) == authority
    unique = sum(objects.values())
    assert shutil.disk_usage(out).free > unique + (512 << 20)
    manifest = dict(schema='hepta.runtime.binary-write-composition.chunk-archive.v1', mode=args.mode,
        chunk_bytes=CHUNK, files=dict(sorted(files.items())), objects=dict(sorted(objects.items())),
        special_nodes_as_data=dict(sorted(special.items())), recorded_origins={k:str(v) for k,v in ROOTS.items()},
        source_sha256=SOURCE_SHA, authority=authority, logical_files=len(files),
        logical_bytes=sum(row['bytes'] for row in files.values()), unique_object_bytes=unique,
        excluded_generated_names=['.git','__pycache__','*.pyc'],
        external_parent_archive=dict(path=str(parent_index_path.parent.parent/'evidence.tar.xz'),
            bytes=parent['archive_bytes'], sha256=PARENT_ARCHIVE_SHA, index_path=str(parent_index_path),
            index_sha256=PARENT_INDEX_SHA, payload_reread_by_this_packager=False),
        external_composition_archive=external_composition,
        complete_composition_capture_included=args.mode=='complete',
        earlier_build_reader_mismatch_and_partition_holds_retained=True,
        runtime_product_executions_added=0, whole_runtime_replaced=False, public_binary_write_registered=False)
    raw = encoded(manifest)
    (out / 'artifact-manifest.json').write_bytes(raw)
    archive = out / 'evidence.tar.gz'
    with archive.open('xb') as target, gzip.GzipFile(filename='', fileobj=target, mode='wb', mtime=0, compresslevel=1) as compressed, tarfile.open(fileobj=compressed, mode='w|') as tar:
        info = tarfile.TarInfo('artifact-manifest.json'); info.size = len(raw); info.mode = 0o644
        tar.addfile(info, io.BytesIO(raw))
        for number, (key, size) in enumerate(sorted(objects.items()), 1):
            path, offset = locations[key]
            with path.open('rb') as stream:
                stream.seek(offset); value = stream.read(size)
            assert len(value) == size and sha(value) == key
            info = tarfile.TarInfo('objects/' + key); info.size = size; info.mode = 0o644
            tar.addfile(info, io.BytesIO(value))
            if number % 1000 == 0:
                print(json.dumps(dict(phase='archive-objects', completed=number, total=len(objects), mode=args.mode)), flush=True)
    # Every source file and special node stayed the same throughout packaging.
    assert {logical for _, logical in selected(args.mode)} == set(physical)
    for path, expected in physical.values():
        assert identity(path.lstat()) == expected, path
    assert qualified(args.readback_sha256) == authority
    parts, digest, offset = [], hashlib.sha256(), 0
    with archive.open('rb') as stream:
        while data := stream.read(9 << 20):
            parts.append(dict(index=len(parts)+1, offset=offset, bytes=len(data), sha256=sha(data)))
            digest.update(data); offset += len(data)
    result = dict(schema='hepta.runtime.binary-write-composition.archive-ranges.v1', mode=args.mode,
        archive_path=str(archive), archive_bytes=offset, archive_sha256=digest.hexdigest(),
        compression='gzip-level-1-mtime-0', parts_are_exact_read_ranges=True, parts=parts,
        manifest_sha256=sha(raw), logical_files=len(files), logical_bytes=manifest['logical_bytes'],
        unique_object_bytes=unique, source_sha256=SOURCE_SHA, readback_sha256=args.readback_sha256,
        elapsed_seconds=(time.monotonic_ns()-began)/1e9, authority=authority,
        complete_composition_capture_included=args.mode=='complete',
        whole_runtime_replaced=False, public_binary_write_registered=False)
    (out / 'EVIDENCE.json').write_bytes(encoded(result))
    print(json.dumps({k:v for k,v in result.items() if k not in ('parts','authority')}, sort_keys=True), flush=True)

if __name__ == '__main__':
    main()
