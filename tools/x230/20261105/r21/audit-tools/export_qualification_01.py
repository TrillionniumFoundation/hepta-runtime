#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Archive a completed accepted R21 qualification, retaining raw test evidence.

ELF bytes remain on X230; their complete independently recomputed identities
are recorded as omissions. No build directory is traversed or modified.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r21')

def stamp(value):
    return tuple(getattr(value, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid',
        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def identity(path):
    assert path.resolve() == path
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        assert stamp(os.fstat(stream.fileno())) == stamp(before)
        while data := stream.read(1024 * 1024):
            digest.update(data)
        assert stamp(os.fstat(stream.fileno())) == stamp(before)
    assert stamp(path.lstat()) == stamp(before)
    return {'path': path.relative_to(ROOT).as_posix(), 'original_path': str(path),
            'size': before.st_size, 'sha256': digest.hexdigest(),
            'mode': stat.S_IMODE(before.st_mode)}

def load(path, expected):
    row = identity(path)
    assert row['sha256'] == expected
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    return json.loads(data)

def enumerate_files():
    files = []
    for name in ('qualification-01', 'qualification-control-01'):
        for path in sorted((ROOT / name).rglob('*')):
            assert not path.is_symlink()
            if path.is_file():
                files.append(path)
    files.extend(ROOT / name for name in (
        'preparation.json', 'candidate-installed-01.json', 'tools-installed-01.json',
        'measurement-plan-01.json', 'source-freeze-01.json', 'source-middle-01.json',
        'source-after-01.json', 'qualification-launch-01.json', 'qualification-exit-01.json',
        'independent-acceptance-01.json', 'progress-01.json',
        'tools/qualify_candidate_01.py', 'tools/verify_qualification_01.py',
        'tools/qualification-tools-manifest-01.json', 'tools/create_component_chain_01.py',
        'component-chain-01.json', 'source/src/mcp/runtime/jobs.rs'))
    files.extend(sorted((ROOT / 'source/tools/x230/20261028').glob('*.py')))
    assert len(files) == len(set(files))
    return sorted(files)

def omitted(path):
    relative = path.relative_to(ROOT)
    return relative.parts[:2] == ('qualification-01', 'test-binaries') or relative.as_posix() in {
        'qualification-01/hepta-runtime', 'qualification-01/hepta-runtime-jobctl',
        'qualification-01/native_process_driver'}

def accepted_elf_bindings(acceptance):
    expected = {}
    release = acceptance['binaries']
    assert set(release) == {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
    for name, row in release.items():
        path = Path(row['path'])
        assert path == ROOT / 'qualification-01' / name
        assert type(row['size']) is int and row['size'] > 0
        expected[path.relative_to(ROOT).as_posix()] = {'sha256': row['sha256'], 'size': row['size'], 'kind': 'release'}
    tests = acceptance['retained_test_binaries']
    assert len(tests) == 5
    for row in tests:
        path = Path(row['path'])
        assert path.is_absolute() and path.resolve() == path
        relative = path.relative_to(ROOT).as_posix()
        assert Path(relative).parts[:2] == ('qualification-01', 'test-binaries') and relative not in expected
        expected[relative] = {'sha256': row['sha256'], 'kind': 'retained_test'}
    assert len(expected) == 8
    return expected

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-control-sha256', required=True)
    parser.add_argument('--expected-acceptance-sha256', required=True)
    parser.add_argument('--expected-report-sha256', required=True)
    args = parser.parse_args()
    control = load(ROOT / 'qualification-control-01/report.json', args.expected_control_sha256)
    acceptance = load(ROOT / 'independent-acceptance-01.json', args.expected_acceptance_sha256)
    qualification = load(ROOT / 'qualification-01/report.json', args.expected_report_sha256)
    assert control['passed'] is True and control['current_stage'] == 'completed'
    assert acceptance['accepted'] is True and all(value is True for value in acceptance['checks'].values())
    assert qualification['qualified'] is True and qualification['automatic_test_retries'] == 0
    assert control['qualification_report']['sha256'] == args.expected_report_sha256
    assert control['independent_acceptance']['sha256'] == args.expected_acceptance_sha256
    inputs = enumerate_files()
    expected_elfs = accepted_elf_bindings(acceptance)
    manifest = {'schema': 'hepta-r21-qualification-export/v1', 'files': [], 'omitted_elf_bytes': [],
                'expected_control_sha256': args.expected_control_sha256,
                'expected_acceptance_sha256': args.expected_acceptance_sha256,
                'expected_report_sha256': args.expected_report_sha256}
    for path in inputs:
        row = identity(path)
        if omitted(path):
            accepted = expected_elfs[row['path']]
            assert row['sha256'] == accepted['sha256']
            if 'size' in accepted:
                assert row['size'] == accepted['size']
            with path.open('rb') as stream:
                assert stream.read(4) == b'\x7fELF'
            manifest['omitted_elf_bytes'].append(row)
        else:
            assert row['size'] <= 128 * 1024 * 1024
            manifest['files'].append(row)
    assert len(manifest['omitted_elf_bytes']) == 8
    assert {row['path'] for row in manifest['omitted_elf_bytes']} == set(expected_elfs)
    manifest['omitted_elf_acceptance_bindings'] = expected_elfs
    manifest['omitted_elf_bytes_match_acceptance'] = True
    output = ROOT / 'export-qualification-01'
    os.umask(0o077)
    output.mkdir(mode=0o700, exist_ok=False)
    archive = output / 'qualification.tar.gz'
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    with archive.open('xb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
        with tarfile.open(mode='w|', fileobj=zipped, format=tarfile.PAX_FORMAT) as tar:
            for row in manifest['files']:
                path = ROOT / row['path']
                data = path.read_bytes()
                assert len(data) == row['size'] and hashlib.sha256(data).hexdigest() == row['sha256']
                item = tarfile.TarInfo(row['path'])
                item.size, item.mode, item.mtime = len(data), row['mode'], 0
                tar.addfile(item, io.BytesIO(data))
            item = tarfile.TarInfo('_export-manifest.json')
            item.size, item.mode, item.mtime = len(manifest_bytes), 0o600, 0
            tar.addfile(item, io.BytesIO(manifest_bytes))
    assert enumerate_files() == inputs
    for row in manifest['files'] + manifest['omitted_elf_bytes']:
        assert identity(ROOT / row['path']) == row
    with (output / 'manifest.json').open('xb') as stream:
        stream.write(manifest_bytes)
    archive_identity = identity(archive)
    receipt = {'schema': 'hepta-r21-qualification-archive/v1', 'passed': True,
               'archive': str(archive), 'size': archive_identity['size'], 'sha256': archive_identity['sha256'],
               'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
               'manifest_size': len(manifest_bytes), 'files': len(manifest['files']),
               'archive_members': len(manifest['files']) + 1, 'omitted_elf_count': 8,
               'omitted_elf_bytes_match_acceptance': True,
               'source_files_unchanged': True, 'build_directory_traversed': False}
    with (output / 'receipt.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(receipt), flush=True)

if __name__ == '__main__':
    main()
