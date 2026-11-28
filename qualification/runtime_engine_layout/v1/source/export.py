"""Retain complete source and evidence with lossless content-addressed byte deduplication."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import stat
import tarfile
ROOT = Path(__file__).resolve().parent


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def digest(path):
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and path.resolve() == path.absolute()
    with path.open('rb') as handle:
        value = hashlib.file_digest(handle,'sha256').hexdigest()
    after = path.lstat()
    identity = lambda row:(row.st_dev,row.st_ino,row.st_mode,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
    assert identity(before) == identity(after)
    return dict(bytes=before.st_size,sha256=value,mode=stat.S_IMODE(before.st_mode))


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        kind = path.lstat().st_mode
        assert stat.S_ISDIR(kind) or stat.S_ISREG(kind)
        if stat.S_ISREG(kind):
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def export(capture,archive):
    assert not archive.exists() and not archive.is_relative_to(capture) and not archive.is_relative_to(ROOT)
    files,objects,paths = {},{},{}
    for prefix,folder in (('source',ROOT),('run',capture)):
        for name,identity in inventory(folder).items():
            logical = prefix+'/'+name
            key = 'objects/'+identity['sha256']+'-'+format(identity['mode'],'03o')
            files[logical] = dict(**identity,object=key)
            paths[logical] = folder/name
            if key in objects:
                assert objects[key]['identity'] == identity
            else:
                objects[key] = dict(identity=identity,path=folder/name)
    gate = json.loads((capture/'GATE.json').read_bytes()) if (capture/'GATE.json').exists() else {'status':'NO_GATE_RECORD'}
    metadata = dict(schema='hepta.runtime.engine-layout.complete-archive.v1',git_head=os.environ.get('GITHUB_SHA'),
        run_id=os.environ.get('GITHUB_RUN_ID'),source_manifest=files['source/SOURCE_MANIFEST.json'],
        gate_status=gate['status'],files=files,native_or_rust_executions=0,whole_runtime_replaced=False)
    raw = encoded(metadata)
    archive.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(archive,'w:gz',compresslevel=1,dereference=True) as target:
        for name,row in sorted(objects.items()):
            assert digest(row['path']) == row['identity']
            info = tarfile.TarInfo(name)
            info.size,info.mode = row['identity']['bytes'],row['identity']['mode']
            with row['path'].open('rb') as handle:
                target.addfile(info,handle)
        info = tarfile.TarInfo('artifact-manifest.json');info.size,info.mode = len(raw),0o644
        target.addfile(info,io.BytesIO(raw))
    observed = {}
    with tarfile.open(archive,'r|gz') as source:
        while member := source.next():
            assert member.isfile() and member.name not in observed
            with source.extractfile(member) as handle:
                value = hashlib.file_digest(handle,'sha256').hexdigest()
            observed[member.name] = dict(bytes=member.size,sha256=value,mode=member.mode)
            source.members.clear()
    expected = {name:row['identity'] for name,row in objects.items()}
    expected['artifact-manifest.json'] = dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),mode=0o644)
    assert observed == expected
    for name,identity in files.items():
        assert digest(paths[name]) == observed[identity['object']] == {key:identity[key] for key in ('bytes','sha256','mode')}
    result = dict(schema='hepta.runtime.engine-layout.complete-archive-read.v1',archive=archive.name,**digest(archive),
        unique_objects=len(objects),logical_files=len(files),logical_bytes=sum(row['bytes'] for row in files.values()),
        unique_bytes=sum(row['identity']['bytes'] for row in objects.values()),gate_status=gate['status'],
        all_object_bytes_and_modes_reread=True,all_logical_files_reread=True,native_or_rust_executions=0,
        whole_runtime_replaced=False)
    archive.with_suffix(archive.suffix+'.json').write_bytes(encoded(result))
    print(encoded(result).decode(),end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',type=Path,required=True)
    parser.add_argument('--archive',type=Path,required=True)
    args = parser.parse_args()
    export(args.capture.resolve(strict=True),args.archive.absolute())
