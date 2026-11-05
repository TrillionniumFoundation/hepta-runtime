#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Export terminal R22 evidence with exact identities and explicit omitted bodies."""
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r22')
RECOVERY = Path('/home/qian/hepta-runtime-optimization-20261104-r16/r22-cancel-recovery-01')
OUT = ROOT / 'evidence-export-01'
MAX_FILE_BYTES = 256 * 1024 * 1024


def stamp(value):
    return {k: getattr(value, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                                         'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def read(path, retain=False):
    assert path.is_absolute() and path.resolve() == path, str(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode)
        assert before.st_uid == os.geteuid() or (path == Path('/usr/bin/ssh') and before.st_uid == 0)
        assert not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
        assert 0 <= before.st_size <= MAX_FILE_BYTES
        digest, size, blocks, header = hashlib.sha256(), 0, [], b''
        while block := os.read(fd, 1024 * 1024):
            size += len(block)
            assert size <= before.st_size
            digest.update(block)
            if not header:
                header = block[:4]
            if retain:
                blocks.append(block)
        assert size == before.st_size
        assert stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat())
        return {'source_path': str(path), 'bytes': size, 'sha256': digest.hexdigest(),
                'original_identity': stamp(before), 'is_elf': header == b'\x7fELF'}, b''.join(blocks)
    finally:
        os.close(fd)


def listing(root):
    assert root.resolve() == root and stat.S_ISDIR(root.lstat().st_mode), str(root)

    def fail(error):
        raise error

    files, directories = [], []
    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        directory = Path(current)
        assert not directory.is_symlink() and directory.resolve() == directory
        directories.append(str(directory))
        for name in sorted(dirs):
            assert not (directory / name).is_symlink()
        for name in sorted(names):
            path = directory / name
            assert stat.S_ISREG(path.lstat().st_mode), str(path)
            files.append(path)
    return sorted(files), sorted(directories)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def main():
    terminal_inputs = {}
    reports = []
    for relative in ('qualification-01/report.json', 'campaign-01/report.json', 'microbenchmark-01/report.json'):
        identity, raw = read(ROOT / relative, retain=True)
        terminal_inputs[relative] = identity
        reports.append(json.loads(raw))
    qualification, campaign, mechanism = reports
    assert qualification['qualified'] is True and qualification.get('finished_utc')
    assert campaign.get('finished_utc') and campaign['passed'] is True
    assert mechanism['passed'] is True
    assert qualification['source_tested'] == qualification['source_after']
    OUT.mkdir(mode=0o700)
    groups = {
        'qualification': [('qualification', ROOT / 'qualification-01')],
        'microbenchmark': [('microbenchmark', ROOT / 'microbenchmark-01')],
        'campaign': [('campaign', ROOT / 'campaign-01'), ('recovery', RECOVERY),
                     ('campaign-tools', ROOT / 'campaign-tools'), ('boundary-tools', ROOT / 'boundary-tools')],
    }
    report = {'schema': 'hepta-r22-evidence-export/v1', 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'qualified': True, 'campaign_passed': True, 'candidate_adopted': campaign['adoption_passed'],
              'no_workload_executed': True, 'archives': {}, 'passed': False,
              'terminal_inputs': terminal_inputs}
    try:
        for group, roots in groups.items():
            files, inventories, omissions = {}, {}, []

            def add(path, name, expected_sha=None, omission=None):
                assert not Path(name).is_absolute() and '..' not in Path(name).parts
                identity, _ = read(path)
                assert expected_sha is None or identity['sha256'] == expected_sha, str(path)
                if identity['is_elf']:
                    omission = 'ELF body omitted; complete actual remote byte identity retained'
                if path.parent.name == 'profile' and path.name in ('ssh_config', 'known_hosts', 'profile.json'):
                    omission = 'private transport configuration body omitted; exact identity retained'
                if omission:
                    omissions.append(dict(identity, archive_path=name, omission_reason=omission))
                else:
                    assert name not in files or files[name] == identity
                    files[name] = identity

            for prefix, root in roots:
                paths, dirs = listing(root)
                inventories[str(root)] = {'files': [str(p) for p in paths], 'directories': dirs}
                for path in paths:
                    add(path, prefix + '/' + path.relative_to(root).as_posix())
            if group == 'qualification':
                for relative, sha in qualification['source_after'].items():
                    add(ROOT / 'source' / relative, 'source/' + relative, sha)
                for path in sorted((ROOT / 'source/tools/x230/20261028').glob('*.py')):
                    add(path, 'qualifier-tools/' + path.name)
                for path in sorted((ROOT / 'results/build-release-01').iterdir()):
                    if path.is_file():
                        add(path, 'initial-release/' + path.name)
            if group == 'microbenchmark':
                add(ROOT / 'campaign-tools/run_r22_microbenchmark.py', 'tools/run_r22_microbenchmark.py')
            if group == 'campaign':
                for relative in ('campaign-inputs-01.json', 'qualification-compact.json', 'preparation.json', 'cache-copy.json'):
                    add(ROOT / relative, 'receipts/' + relative)
                for i, identity in enumerate(campaign['input_bindings']):
                    path = Path(identity['path'])
                    if path.is_relative_to(ROOT):
                        continue
                    # Fixed campaign inputs were independently bound by its launcher.
                    # Do not follow arbitrary dependency paths from an unverified report.
                    allowed = (path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261104-r16'))
                               or path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261104-r19/qualification-02'))
                               or path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')))
                    if allowed:
                        add(path, f'bound-inputs/{i:03d}-' + path.name, identity['sha256'])
                    else:
                        add(path, f'bound-inputs/{i:03d}-' + path.name, identity['sha256'],
                            'external system/profile input body omitted; exact identity retained')
            manifest = {'schema': 'hepta-r22-archive-manifest/v1', 'group': group, 'files': files,
                        'omitted_bodies': omissions, 'source_trees': inventories,
                        'qualification_report_sha256': read(ROOT / 'qualification-01/report.json')[0]['sha256'],
                        'campaign_report_sha256': read(ROOT / 'campaign-01/report.json')[0]['sha256']}
            raw_manifest = encode(manifest)
            archive = OUT / (group + '-01.tar.gz')
            with archive.open('xb') as destination, gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0, compresslevel=6) as zipped:
                with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                    item = tarfile.TarInfo('_export-manifest.json')
                    item.size, item.mode, item.mtime = len(raw_manifest), 0o600, 0
                    tar.addfile(item, io.BytesIO(raw_manifest))
                    for name, expected in sorted(files.items()):
                        actual, raw = read(Path(expected['source_path']), retain=True)
                        assert actual == expected, name
                        if name.startswith(('campaign/', 'recovery/')):
                            for marker in (b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                                           b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN DSA PRIVATE KEY-----'):
                                assert marker not in raw, 'private key marker in ' + name
                        item = tarfile.TarInfo(name)
                        item.size, item.mode, item.mtime = len(raw), 0o600, 0
                        tar.addfile(item, io.BytesIO(raw))
            for root, expected in inventories.items():
                paths, dirs = listing(Path(root))
                assert {'files': [str(p) for p in paths], 'directories': dirs} == expected
            for expected in list(files.values()) + omissions:
                actual, _ = read(Path(expected['source_path']))
                assert all(actual[k] == expected[k] for k in actual)
            manifest_path = OUT / (group + '-manifest.json')
            manifest_path.write_bytes(raw_manifest)
            report['archives'][group] = {'archive': read(archive)[0], 'manifest': read(manifest_path)[0],
                                         'payload_files': len(files), 'omitted_bodies': len(omissions),
                                         'source_bytes': sum(r['bytes'] for r in files.values())}
        for relative, expected in terminal_inputs.items():
            assert read(ROOT / relative)[0] == expected, 'terminal input changed: ' + relative
        report['passed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'report.json').write_bytes(encode(report))
        print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
