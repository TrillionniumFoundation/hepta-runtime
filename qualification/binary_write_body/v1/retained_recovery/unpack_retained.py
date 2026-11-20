#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Verify and materialize an original Actions ZIP as data; execute no member."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import shutil
import tarfile
import zipfile

HERE = Path(__file__).resolve().parent


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1048576):
            result.update(block)
    return result.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and '..' not in path.parts
            and '.' not in path.parts and str(path) == name,
            'ordinary relative archive member')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True)
    parser.add_argument('--group', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = json.loads((HERE / 'ARTIFACTS.json').read_bytes())
    selected = [row for row in rows if row['group'] == args.group]
    require(len(selected) == 1, 'fixed original group')
    row = selected[0]
    require(args.zip.stat().st_size == row['zip_bytes']
            and digest(args.zip) == row['zip_sha256'], 'exact original Actions ZIP bytes')
    require(not args.output.exists(), 'use a new empty output location')
    args.output.mkdir(parents=True)
    export = args.output / 'export'
    export.mkdir()
    with zipfile.ZipFile(args.zip) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'unique ZIP entries')
        for name in names:
            safe_name(name)
            require(not name.endswith('/'), 'only ordinary ZIP files')
            target = export / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as source, target.open('xb') as destination:
                shutil.copyfileobj(source, destination, 1048576)
    binding = json.loads((export / 'evidence.tar.gz.json').read_bytes())
    tar = export / 'evidence.tar.gz'
    require(tar.stat().st_size == binding['bytes'] and digest(tar) == binding['sha256'],
            'complete exported TAR bytes')
    with tarfile.open(tar, 'r:gz') as archive:
        members = archive.getmembers()
        require(all(member.isfile() for member in members)
                and len({member.name for member in members}) == len(members),
                'unique regular TAR members')
        manifest = json.loads(archive.extractfile('artifact-manifest.json').read())
    require(manifest['git_head'] == row['source_commit']
            and int(manifest['run_id']) == row['original_run']
            and manifest['source_manifest']['sha256']
            == '5a4adda7189b444d5451381e815eaf7defdc4db0e42b77b222c9c630e8f3eb57',
            'frozen original source and workflow identity')
    objects = {}
    for name, mode in manifest['directories'].items():
        safe_name(name)
        require(name.split('/')[0] in ('source', 'run') and 0 <= mode <= 0o777,
                'bounded logical directory mode and root')
        target = args.output / name
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(mode)
    for name, item in manifest['files'].items():
        safe_name(name)
        require(name.split('/')[0] in ('source', 'run') and 0 <= item['mode'] <= 0o777,
                'bounded logical file mode and root')
        require(item['object'] == 'objects/' + item['sha256'] + '-' + oct(item['mode'])[2:],
                'object identity includes full SHA and mode')
        objects.setdefault(item['object'], []).append((name, item))
    require({member.name for member in members} == set(objects) | {'artifact-manifest.json'},
            'no missing or extra TAR members')
    count = 0
    with tarfile.open(tar, 'r|gz') as archive:
        for member in archive:
            if member.name == 'artifact-manifest.json':
                continue
            raw = archive.extractfile(member).read()
            measured = hashlib.sha256(raw).hexdigest()
            for name, item in objects[member.name]:
                require(measured == item['sha256'] and len(raw) == item['bytes'],
                        'full object bytes')
                target = args.output / name
                with target.open('xb') as destination:
                    destination.write(raw)
                target.chmod(item['mode'])
                count += 1
    require(count == len(manifest['files']), 'all original logical files materialized')
    for name, item in manifest['files'].items():
        target = args.output / name
        require(target.stat().st_size == item['bytes'] and digest(target) == item['sha256']
                and target.stat().st_mode & 0o777 == item['mode'],
                'all materialized bytes and modes reread')
    receipt = dict(group=args.group, artifact_id=row['artifact_id'],
                   zip_sha256=row['zip_sha256'], tar_sha256=binding['sha256'],
                   files=count, objects=len(objects), original_gate_status=manifest['gate_status'],
                   captured_applications=manifest['captured_application_statuses'],
                   status='RETAINED_DATA_UNPACK_PASS', application_calls=0, compiler_calls=0)
    (args.output / 'UNPACK.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
