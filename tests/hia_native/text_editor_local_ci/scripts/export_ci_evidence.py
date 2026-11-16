#!/usr/bin/env python3
"""Archive complete successful or failed run evidence; omit only Rust intermediates."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import stat
import tarfile


def digest_file(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--archive-directory', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    destination = args.archive_directory.resolve()
    assert not destination.exists() and not destination.is_relative_to(output) and not destination.is_relative_to(source)
    destination.mkdir(parents=True)
    archive_path = destination / 'text-editor-local-complete-evidence.tar.gz'
    original = output / 'reference-build/target/release/hepta-text-editor-gateway-local-original-oracle'
    target = output / 'reference-build/target'
    # Keep an executable even if the process stopped after linking but before
    # its successful BUILD.json receipt was written. Such a run remains failed.
    original_present = original.is_file() and not original.is_symlink()
    files = {}
    excluded = {'files': 0, 'bytes': 0}
    with archive_path.open('xb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for prefix, root in (('recipe-source', source), ('run', output)):
                    if not root.exists():
                        continue
                    for path in sorted(root.rglob('*')):
                        info = path.lstat()
                        if stat.S_ISDIR(info.st_mode):
                            continue
                        if root == output and path.is_relative_to(target) and path != original:
                            excluded['files'] += 1
                            excluded['bytes'] += info.st_size
                            continue
                        name = prefix + '/' + str(path.relative_to(root))
                        assert name not in files and '..' not in Path(name).parts
                        item = tarfile.TarInfo(name)
                        item.mode = stat.S_IMODE(info.st_mode)
                        item.uid = item.gid = item.mtime = 0
                        if stat.S_ISLNK(info.st_mode):
                            link = os.readlink(path)
                            assert not Path(link).is_absolute() and '..' not in Path(link).parts
                            item.type = tarfile.SYMTYPE
                            item.linkname = link
                            files[name] = {'type': 'symlink', 'target': link, 'mode': item.mode}
                            archive.addfile(item)
                        else:
                            assert stat.S_ISREG(info.st_mode), name
                            size, digest = digest_file(path)
                            assert size == info.st_size
                            item.size = size
                            files[name] = {'type': 'file', 'bytes': size, 'sha256': digest, 'mode': item.mode}
                            with path.open('rb') as payload:
                                archive.addfile(item, payload)
    with tarfile.open(archive_path, 'r:gz') as archive:
        assert set(archive.getnames()) == set(files) and len(archive.getnames()) == len(files)
        for member in archive.getmembers():
            pin = files[member.name]
            assert member.mode == pin['mode']
            if pin['type'] == 'symlink':
                assert member.issym() and member.linkname == pin['target']
            else:
                assert member.isfile() and member.size == pin['bytes']
                digest = hashlib.sha256()
                size = 0
                with archive.extractfile(member) as payload:
                    for chunk in iter(lambda: payload.read(1 << 20), b''):
                        digest.update(chunk)
                        size += len(chunk)
                assert size == pin['bytes'] and digest.hexdigest() == pin['sha256'], member.name
    size, digest = digest_file(archive_path)
    recipe_path = output / 'RECIPE.json'
    recipe = json.loads(recipe_path.read_bytes()) if recipe_path.is_file() else {}
    report = {'schema': 'hepta.text-local.evidence-archive.v1', 'status': 'ARCHIVE_READBACK_PASS',
        'archive': archive_path.name, 'archive_bytes': size, 'archive_sha256': digest,
        'source_manifest_sha256': hashlib.sha256((source / 'source-manifest.json').read_bytes()).hexdigest(),
        'files': files, 'excluded_rust_intermediates': excluded,
        'original_executable_preserved': original_present,
        'retention_policy': 'all existing registry archives, profile snapshots, live fixture files, and observations are included',
        'retained_registry_archive_files': sum(name.startswith('run/reference-build/registry-archives/') for name in files),
        'retained_profile_snapshot_files': sum(name.startswith('run/profiles/') and ('/native-filesystem/' in name or '/original-filesystem/' in name) for name in files),
        'recorded_recipe_status': recipe.get('status'),
        'actual_qualification_is_defined_by_retained_verifier_not_archive_success': True,
        'full_sdk_qualified': False, 'full_136_route_qualified': False,
        'public_text_editor_route': False, 'production_activated': False,
        'old_path_removed': False, 'whole_runtime_replaced': False}
    (destination / 'archive-manifest.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, sort_keys=True))


if __name__ == '__main__':
    main()
