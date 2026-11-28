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


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).hostname != 'api.github.com':
            new.remove_header('Authorization')
        return new


def restore(recovery, destination):
    import shutil
    binding = json.loads((recovery / 'BINDING.json').read_bytes())
    assert not destination.exists()
    destination.mkdir(parents=True)
    archive = destination / 'producer.zip'
    request = urllib.request.Request(
        'https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/'
        + str(binding['producer_artifact']) + '/zip',
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'X-GitHub-Api-Version': '2022-11-28'})
    opener = urllib.request.build_opener(Redirect())
    with opener.open(request, timeout=60) as response, archive.open('xb') as output:
        count = 0
        while block := response.read(1 << 20):
            count += len(block)
            assert count <= binding['producer_zip']['bytes']
            output.write(block)
    assert {key: digest(archive)[key] for key in ('bytes', 'sha256')} == binding['producer_zip']
    restored = destination / 'producer'
    restored.mkdir()
    object_root = destination / 'restore-objects'
    object_root.mkdir()
    observed, outer, manifest_raw = {}, {}, None
    with zipfile.ZipFile(archive) as z:
        assert len(z.infolist()) == 5
        for item in z.infolist():
            assert not item.is_dir() and item.filename not in outer
            with z.open(item) as stream:
                sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            outer[item.filename] = dict(bytes=item.file_size, sha256=sha, mode=item.external_attr >> 16)
        assert {key: outer['audit-retention.tar.gz'][key] for key in ('bytes', 'sha256')} == binding['producer_tar']
        receipt = json.loads(z.read('audit-retention.tar.gz.json'))
        with z.open('audit-retention.tar.gz') as stream, tarfile.open(fileobj=stream, mode='r|gz') as tar:
            while member := tar.next():
                name = Path(member.name)
                assert member.isfile() and member.name not in observed and not name.is_absolute()
                assert '..' not in name.parts and member.mode in (0o600, 0o644, 0o755)
                if member.name == 'artifact-manifest.json':
                    with tar.extractfile(member) as source:
                        manifest_raw = source.read()
                    assert len(manifest_raw) == member.size and member.mode == 0o644
                    observed[member.name] = dict(bytes=member.size, sha256=hashlib.sha256(manifest_raw).hexdigest(), mode=member.mode)
                else:
                    assert len(name.parts) == 2 and name.parts[0] == 'objects'
                    target = object_root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    count, sha = 0, hashlib.sha256()
                    with tar.extractfile(member) as source, target.open('xb') as output:
                        while block := source.read(1 << 20):
                            count += len(block); sha.update(block); output.write(block)
                    assert count == member.size
                    target.chmod(member.mode)
                    identity = dict(bytes=count, sha256=sha.hexdigest(), mode=member.mode)
                    assert member.name == 'objects/' + identity['sha256'] + '-' + format(member.mode, '03o')
                    observed[member.name] = identity
                tar.members.clear()
    assert manifest_raw is not None
    manifest = json.loads(manifest_raw)
    assert manifest['schema'] == 'hepta.audit-retention.complete-archive.v1'
    assert manifest['git_head'] == binding['producer_head'] and int(manifest['run_id']) == binding['producer_run']
    assert manifest['gate_status'] == receipt['gate_status'] == 'FAIL'
    objects, expected, first_paths = {}, {}, {}
    for logical, row in manifest['files'].items():
        path = Path(logical)
        assert not path.is_absolute() and '..' not in path.parts and path.parts[0] in ('source', 'run')
        identity = {key: row[key] for key in ('bytes', 'sha256', 'mode')}
        key = row['object']
        assert key == 'objects/' + row['sha256'] + '-' + format(row['mode'], '03o')
        assert observed[key] == identity
        if key in objects:
            assert objects[key] == identity
        objects[key] = identity
        first_paths.setdefault(key, logical)
        target = restored / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(object_root / key, target)
        target.chmod(row['mode'])
        assert digest(target) == identity
        expected[logical] = identity
    (restored / 'artifact-manifest.json').write_bytes(manifest_raw)
    expected['artifact-manifest.json'] = observed['artifact-manifest.json']
    assert observed == {**objects, 'artifact-manifest.json': expected['artifact-manifest.json']}
    assert inventory(restored) == expected
    assert len(manifest['files']) == receipt['logical_files'] == binding['logical_files']
    assert sum(row['bytes'] for row in manifest['files'].values()) == receipt['logical_bytes'] == binding['logical_bytes']
    assert len(objects) == receipt['unique_objects'] == binding['unique_objects']
    assert sum(row['bytes'] for row in objects.values()) == receipt['unique_bytes'] == binding['unique_bytes']
    assert inventory(restored / 'source') == inventory(recovery.parent / 'audit_retention')
    gate = json.loads((restored / 'run/GATE.json').read_bytes())
    processes = json.loads((restored / 'run/semantic/processes/processes.json').read_bytes())
    semantic = json.loads((restored / 'run/semantic/CAPTURE.json').read_bytes())
    assert gate['status'] == 'FAIL' and len(processes) == 9 and semantic['status'] == 'PASS'
    assert all(p['completed'] and not p['timed_out'] and p['exit_code'] == 0 for p in processes)
    assert inventory(object_root) == objects
    for key, row in objects.items():
        assert digest(object_root / key) == digest(restored / first_paths[key]) == row
    retirement = dict(files=len(objects), bytes=sum(row['bytes'] for row in objects.values()),
        complete_set_bytes_and_modes_equal=True, kept_logical_paths=first_paths)
    shutil.rmtree(object_root)
    proof = dict(schema='hepta.audit-retention.producer-restoration.v1', outer=outer,
        producer_head=binding['producer_head'], producer_run=binding['producer_run'],
        files=expected, logical_files=binding['logical_files'], logical_bytes=binding['logical_bytes'],
        unique_objects=len(objects), temporary_object_retirement=retirement, complete_disk_reread=True,
        original_gate_status='FAIL', semantic_reexecutions=0)
    (destination / 'RESTORE.json').write_bytes(encoded(proof))
    return dict(status='PASS', files=len(expected), logical_bytes=binding['logical_bytes'], semantic_reexecutions=0)


def preserve_original(destination):
    proof = json.loads((destination / 'RESTORE.json').read_bytes())
    original = destination / 'producer'
    for name, expected in proof['files'].items():
        assert digest(original / name) == expected, name
    return len(proof['files'])


def export(recovery, destination, archive):
    assert not archive.exists() and not archive.is_relative_to(destination)
    files, sources, objects = {}, {}, {}
    for prefix, root in (('recovery-source', recovery), ('evidence', destination)):
        for name, row in inventory(root).items():
            logical = prefix + '/' + name
            key = row['sha256'] + '-' + format(row['mode'], '03o')
            files[logical] = dict(**row, object='objects/' + key)
            sources[logical] = root / name
            if key in objects:
                assert row == objects[key]['identity']
            else:
                objects[key] = dict(path=root / name, identity=row)
    metadata = dict(schema='hepta.audit-retention.complete-deduplicated-archive.v1',
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
    report = dict(schema='hepta.audit-retention.recovery-archive-read.v1', archive=archive.name,
                  **digest(archive), unique_objects=len(objects), logical_files=len(files),
                  logical_bytes=sum(row['bytes'] for row in files.values()),
                  unique_bytes=sum(row['identity']['bytes'] for row in objects.values()),
                  all_object_bytes_and_modes_reread=True, all_logical_files_reread=True,
                  semantic_reexecutions=0, whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix + '.json').write_bytes(encoded(report))
    return report
