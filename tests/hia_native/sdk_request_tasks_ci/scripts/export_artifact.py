"""Archive complete source and captures; exclude only the rebuildable Cargo target."""
from pathlib import Path
import argparse, hashlib, io, json, os, stat, subprocess, sys, tarfile
sys.dont_write_bytecode = True
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def digest(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'run', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args(); source = a.source.resolve(strict=True); run = a.run.absolute(); prefix = a.output.absolute()
    archive_path = Path(str(prefix) + '.tar.gz'); index_path = Path(str(prefix) + '.archive.json')
    assert not archive_path.exists() and not index_path.exists()
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    files, directories, objects = {}, {}, {}
    for root, label in ((source, 'recipe-source'), (run, 'run')):
        if not root.is_dir():
            continue
        for directory, children, names in os.walk(root, followlinks=False):
            folder = Path(directory); relative = folder.relative_to(root).as_posix()
            children[:] = sorted(name for name in children if not (label == 'run' and
                (Path(relative) / name).as_posix() == 'reference/rust-build'))
            assert all(not (folder / child).is_symlink() for child in children)
            key = label if relative == '.' else label + '/' + relative
            directories[key] = folder.stat().st_mode & 0o777
            for name in sorted(names):
                path = folder / name; info = path.lstat()
                assert stat.S_ISREG(info.st_mode) and not path.is_symlink()
                files[key + '/' + name] = path
    status = 'NOT_QUALIFIED'; reader_failure = False
    recipe = run / 'RECIPE.json'
    if recipe.is_file() and json.loads(recipe.read_bytes()).get('status') == 'PASS':
        result = subprocess.run([sys.executable, '-I', '-B', str(source / 'scripts/verify_complete.py'),
            '--source', str(source), '--run', str(run), '--require-recipe-pass'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        objects['EXPORT_READER.stdout'] = result.stdout; objects['EXPORT_READER.stderr'] = result.stderr
        objects['EXPORT_READER.json'] = ENCODE(dict(exit_code=result.returncode,
            stdout_sha256=SHA(result.stdout), stderr_sha256=SHA(result.stderr), native_or_rust_executions=0))
        reader_failure = result.returncode != 0
        if not reader_failure:
            status = json.loads(result.stdout)['status']
    objects['ARTIFACT.json'] = ENCODE(dict(schema='hepta.sdk-request-tasks.artifact.v1', status=status,
        excluded_rebuildable_only=['run/reference/rust-build'], complete_source_and_captures=True,
        public_registry_integrated=False, full_async_runtime_qualified=False, full_sdk_qualified=False,
        production_activated=False, old_path_removed=False))
    rows = {name:dict(bytes=path.stat().st_size, sha256=digest(path)) for name, path in files.items()}
    rows.update({name:dict(bytes=len(raw), sha256=SHA(raw)) for name, raw in objects.items()})
    objects['artifact-manifest.json'] = ENCODE(dict(schema='hepta.sdk-request-tasks.artifact-manifest.v1',
        files=rows, directories=directories, complete_source_and_captures=True))
    with tarfile.open(archive_path, 'w:gz', format=tarfile.PAX_FORMAT, compresslevel=1) as archive:
        for name, mode in sorted(directories.items()):
            item = tarfile.TarInfo(name); item.type=tarfile.DIRTYPE; item.mode=mode; item.mtime=0; archive.addfile(item)
        for name in sorted(set(files) | set(objects)):
            item = tarfile.TarInfo(name); item.mtime=0
            if name in files:
                path=files[name]; item.size=path.stat().st_size; item.mode=path.stat().st_mode & 0o777
                with path.open('rb') as handle:
                    archive.addfile(item, handle)
            else:
                raw=objects[name]; item.size=len(raw); item.mode=0o444; archive.addfile(item, io.BytesIO(raw))
    actual, actual_dirs = {}, {}
    with tarfile.open(archive_path, 'r:gz') as archive:
        for item in archive:
            assert item.uid == item.gid == item.mtime == 0
            if item.isdir():
                assert item.name not in actual_dirs; actual_dirs[item.name]=item.mode; continue
            assert item.isfile() and item.name not in actual
            with archive.extractfile(item) as handle:
                if item.name == 'artifact-manifest.json':
                    raw=handle.read(); assert raw==objects[item.name]; value=SHA(raw)
                else:
                    value=hashlib.file_digest(handle, 'sha256').hexdigest()
            actual[item.name]=dict(bytes=item.size, sha256=value)
    assert actual_dirs == directories
    assert {k:v for k,v in actual.items() if k != 'artifact-manifest.json'} == rows
    index = dict(schema='hepta.sdk-request-tasks.archive.v1', status=status, archive=archive_path.name,
        bytes=archive_path.stat().st_size, sha256=digest(archive_path), files=len(actual), directories=len(actual_dirs),
        uncompressed_bytes=sum(v['bytes'] for v in actual.values()), complete_archive_reread=True)
    index_path.write_bytes(ENCODE(index)); print(json.dumps(index, sort_keys=True))
    if reader_failure:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
