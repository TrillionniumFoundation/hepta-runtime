#!/usr/bin/env python3
"""Archive this CI run, preserving observed binaries while omitting Rust build caches."""
from pathlib import Path
import argparse
import gzip
import hashlib
import io
import json
import tarfile


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache-preparation', type=Path, required=True)
    parser.add_argument('--archive-directory', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    deps = json.loads((source / 'ci/dependencies.json').read_bytes())
    directory = args.archive_directory.resolve()
    assert not directory.exists()
    directory.mkdir(parents=True)
    roots = [('qualification', args.output.resolve()), ('cache-preparation', args.cache_preparation.resolve())]
    exclusions = []
    binaries = set()
    output = roots[0][1]
    for spec in deps['rust_projects']:
        stage = output / spec['root']
        exclusions.append(stage / spec['target_directory'])
        receipt_path = stage / spec['receipt']
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_bytes())
            binary = stage / receipt['binary_relative_path']
            assert binary.is_relative_to(stage)
            assert sha(binary.read_bytes()) == receipt['binary_sha256']
            binaries.add(binary)
    files = {}
    excluded = {'files': 0, 'bytes': 0}
    archive_path = directory / 'sdk-ci-evidence.tar.gz'
    with archive_path.open('wb') as stream:
        with gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0) as compressed:
            with tarfile.open(mode='w', fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for prefix, root in roots:
                    if not root.exists():
                        continue
                    for path in sorted(root.rglob('*')):
                        if path.is_symlink():
                            raise AssertionError(('unexpected evidence symlink', str(path)))
                        if not path.is_file():
                            continue
                        if any(path.is_relative_to(excluded_root) for excluded_root in exclusions) and path not in binaries:
                            excluded['files'] += 1
                            excluded['bytes'] += path.stat().st_size
                            continue
                        raw = path.read_bytes()
                        relative = prefix + '/' + str(path.relative_to(root))
                        files[relative] = {'bytes': len(raw), 'sha256': sha(raw)}
                        info = tarfile.TarInfo(relative)
                        info.size = len(raw)
                        info.mode = path.stat().st_mode & 0o777
                        info.mtime = info.uid = info.gid = 0
                        archive.addfile(info, io.BytesIO(raw))
    with tarfile.open(archive_path, 'r:gz') as archive:
        assert set(archive.getnames()) == set(files)
        for member in archive.getmembers():
            raw = archive.extractfile(member).read()
            assert files[member.name] == {'bytes': len(raw), 'sha256': sha(raw)}, member.name
    report = {'schema': 'hepta.sdk-ci-evidence-archive.v1',
              'source_manifest_sha256': sha((source / 'source-manifest.json').read_bytes()),
              'archive': archive_path.name, 'archive_bytes': archive_path.stat().st_size,
              'archive_sha256': sha(archive_path.read_bytes()), 'files': files,
              'all_archive_members_readback_verified': True,
              'only_rust_build_cache_files_excluded': excluded,
              'original_oracle_executables_retained': len(binaries),
              'qualification_status_is_recorded_in_archived_summaries': True,
              'full_sdk_qualified': False, 'full_136_route_qualified': False,
              'production_activated': False, 'old_path_removed': False}
    (directory / 'archive-manifest.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, sort_keys=True))


if __name__ == '__main__':
    main()
