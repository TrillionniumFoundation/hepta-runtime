"""Complete archive restoration and byte-deduplicated evidence export; no native execution."""
from pathlib import Path
import hashlib
import io
import json
import os
import stat
import tarfile
import urllib.parse
import urllib.request
import zipfile


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def digest(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and path.resolve() == path.absolute()
    with path.open('rb') as stream:
        sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.lstat()
    assert (info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino) == (
        after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_ino)
    return dict(bytes=info.st_size, sha256=sha, mode=stat.S_IMODE(info.st_mode))


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        if stat.S_ISREG(info.st_mode):
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def export(recovery, destination, archive):
    assert not archive.exists() and not archive.is_relative_to(destination)
    files, sources, objects = {}, {}, {}
    for prefix, root in (('qualification-source', recovery), ('evidence', destination)):
        for name, row in inventory(root).items():
            logical = prefix + '/' + name
            key = row['sha256'] + '-' + format(row['mode'], '03o')
            files[logical] = dict(**row, object='objects/' + key)
            sources[logical] = root / name
            if key in objects:
                assert row == objects[key]['identity']
            else:
                objects[key] = dict(path=root / name, identity=row)
    metadata = dict(schema='hepta.historical-workflow.complete-deduplicated-archive.v1',
                    git_head=os.environ.get('GITHUB_SHA'), run_id=os.environ.get('GITHUB_RUN_ID'),
                    files=files, semantic_reexecutions=0, whole_runtime_replaced=False)
    raw = encoded(metadata)
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, 'w:gz', compresslevel=1, dereference=True) as tar:
        for key, item in sorted(objects.items()):
            path = item['path']
            assert digest(path) == item['identity']
            info = tarfile.TarInfo('objects/' + key)
            info.size, info.mode = item['identity']['bytes'], item['identity']['mode']
            with path.open('rb') as stream:
                tar.addfile(info, stream)
        info = tarfile.TarInfo('artifact-manifest.json')
        info.size, info.mode = len(raw), 0o644
        tar.addfile(info, io.BytesIO(raw))
    observed = {}
    with tarfile.open(archive, 'r|gz') as tar:
        while member := tar.next():
            assert member.isfile() and member.name not in observed
            with tar.extractfile(member) as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            observed[member.name] = dict(bytes=member.size, sha256=sha, mode=member.mode)
            tar.members.clear()
    expected = {'objects/' + key: item['identity'] for key, item in objects.items()}
    expected['artifact-manifest.json'] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=0o644)
    assert observed == expected
    for name, row in files.items():
        assert digest(sources[name]) == observed[row['object']] == {key: row[key] for key in ('bytes','sha256','mode')}
    report = dict(schema='hepta.historical-workflow.archive-write-readback.v1', archive=archive.name,
                  **digest(archive), unique_objects=len(objects), logical_files=len(files),
                  logical_bytes=sum(row['bytes'] for row in files.values()),
                  unique_bytes=sum(row['identity']['bytes'] for row in objects.values()),
                  all_object_bytes_and_modes_reread=True, all_logical_files_reread=True,
                  semantic_reexecutions=0, whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix + '.json').write_bytes(encoded(report))
    return report
