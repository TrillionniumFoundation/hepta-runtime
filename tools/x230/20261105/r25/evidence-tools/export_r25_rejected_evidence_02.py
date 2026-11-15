#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Freeze qualified but performance-rejected R25 evidence; no workload is rerun."""
import base64
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import traceback

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r25')
BASELINE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
RECOVERY = R16 / 'r25-cancel-recovery-02'
OUT = ROOT / 'evidence-export-rejection-02'
MAX_FILE_BYTES = 1024 * 1024 * 1024


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
        assert 0 <= before.st_size <= MAX_FILE_BYTES, 'file size outside export bound: ' + str(path)
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


def transfer_chunks(archive):
    identity = read(archive)[0]
    directory = OUT / (archive.name + '.chunks')
    directory.mkdir(mode=0o700)
    rows, offset = [], 0
    with archive.open('rb') as stream:
        while data := stream.read(48000):
            name = f'chunk-{len(rows):05d}.b64'
            path = directory / name
            raw = base64.b64encode(data)
            assert len(raw) <= 64000
            with path.open('xb') as output:
                output.write(raw)
            os.chmod(path, 0o600)
            rows.append({'path': str(path), 'offset': offset, 'bytes': len(data),
                         'sha256': hashlib.sha256(data).hexdigest(),
                         'base64_bytes': len(raw), 'base64_sha256': hashlib.sha256(raw).hexdigest()})
            offset += len(data)
    assert offset == identity['bytes'] and read(archive)[0] == identity
    manifest = {'schema': 'hepta-r25-lossless-archive-chunks/v1', 'archive': identity,
                'encoding': 'base64', 'maximum_decoded_chunk_bytes': 48000,
                'maximum_text_file_bytes': 64000, 'chunks': rows}
    path = directory / 'manifest.json'
    with path.open('xb') as stream:
        stream.write(encode(manifest))
    return {'manifest': read(path)[0], 'chunks': len(rows), 'archive': identity}


def main():
    terminal_paths = {
        'qualification': ROOT / 'qualification-02/report.json',
        'observation': ROOT / 'campaign-02/report.json',
        'rust_ci': ROOT / 'rust-ci-02/report.json',
        'python_ci': ROOT / 'python-ci-01/report.json',
    }
    expected_reports = {
        'qualification': '72a4001ed303d565f5c3300ea8786acf1c4e9d7991e0a1f0486fabc140900e3c',
        'observation': '1e06d6bbf06e391505ef8937e304190a4a333f03903c12a9a833ea5133610603',
        'rust_ci': 'ad8d56cc66ff7468e3c1740114756d83fb298b186f7c2423566ceec5c0d12ad3',
        'python_ci': '11dd5af355f8e2f2730ae71d27b1c01b72ce75361e169f8d6c8d9646a052ae05',
    }
    terminal_inputs, values = {}, {}
    for name, path in terminal_paths.items():
        identity, raw = read(path, retain=True)
        assert identity['sha256'] == expected_reports[name], name
        terminal_inputs[name], values[name] = identity, json.loads(raw)
        assert values[name].get('finished_utc'), name
    qualification = values['qualification']
    assert qualification['qualified'] is True and qualification['source_tested'] == qualification['source_after']
    assert all(s['returncode'] == 0 for s in qualification['stages'])
    assert len(qualification['source_after']) == 221 and qualification['automatic_test_retries'] == 0
    observation = values['observation']
    assert observation['passed'] is True and observation['observation_gate_passed'] is False
    assert observation['inputs_unchanged'] is True and observation['source_inputs_unchanged'] is True
    assert observation['rejection_reasons'] == ['C1 regression gate', 'C1 controller CPU regression gate']
    summary_identity, summary_raw = read(ROOT / 'campaign-02/summary.json', retain=True)
    assert summary_identity['sha256'] == '68fd9d1cc05d2c0eab670ccd6d3d99ec4922a3eb369b02cb3b3d16e70bc9737c'
    summary = json.loads(summary_raw)
    assert summary['evidence_verified'] is True and summary['correctness_verified'] is True
    assert summary['observation_gate_passed'] is False and summary['rejection_reasons'] == observation['rejection_reasons']
    for path in ('lifecycle-campaign-02', 'lifecycle-abba-02', 'cancel-saturation-02', 'lifecycle-tool-tests-02'):
        assert not os.path.lexists(ROOT / path), 'unexecuted lifecycle output unexpectedly exists: ' + path
    assert values['rust_ci']['passed'] is True and values['python_ci']['passed'] is True
    assert values['rust_ci']['hosted_actions_passed'] is False and values['python_ci']['hosted_actions_passed'] is False
    native_terminals = {}
    for name, job, digest in (
        ('qualification-terminal-status-02.json', '1a1aaa6552d-fc05-459f', '87db6a4da3004f8fe62c94825136a253c6a63b461f0c22cb493462c1f0c48e85'),
        ('rust-ci-native-terminal-02.json', '1a1aac67f44-fc05-471d', 'fe5f61a673af715f2354e880699669119a5c93d8bdda5c3edb7cf5222916b859'),
        ('python-ci-native-terminal-01.json', '1a1aaa69a3d-fc05-45a1', '7620aa9d736ae6e8045d6c940da7d0db70ac350de26abe70ccce5760f7f695d8'),
        ('observation-native-terminal-02.json', '1a1aacd207e-fc05-4774', '89ede7c586b905c31d56dce1bfa4ff1ba2aa4b5acec8a0e27d1b57aa867d0f1b'),
    ):
        identity, raw = read(ROOT / name, retain=True)
        assert identity['sha256'] == digest, name
        terminal = json.loads(raw)
        assert terminal['job_id'] == job and terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
        assert all(terminal[k] is True for k in ('terminal_publication_confirmed', 'output_durable', 'output_complete', 'audit_recorded'))
        assert all(terminal[k] is False for k in ('automatic_retry', 'timed_out', 'cancelled'))
        assert terminal['terminal_publication_protocol'] == 1
        for stream in ('stdout', 'stderr'):
            assert terminal['log_synced'][stream] is True and terminal['log_truncated'][stream] is False
            assert terminal['log_errors'][stream] is None
            assert terminal['log_bytes'][stream]['seen'] == terminal['log_bytes'][stream]['stored']
        native_terminals[name] = identity
    OUT.mkdir(mode=0o700)
    groups = {
        'qualification': [('qualification', ROOT / 'qualification-02')],
        'observation': [('observation', ROOT / 'campaign-02'), ('recovery', RECOVERY),
                        ('campaign-tools', ROOT / 'campaign-tools-02'), ('boundary-tools', ROOT / 'boundary-tools-02')],
        'ci': [('rust', ROOT / 'rust-ci-02'), ('rust-tools', ROOT / 'rust-ci-tools-02'),
               ('python', ROOT / 'python-ci-01'), ('python-launch', ROOT / 'python-ci-launch-01'),
               ('python-inputs', ROOT / 'ci-gates'), ('private-nextest', ROOT / 'ci-toolchain/nextest-0.9.137')],
    }
    report = {'schema': 'hepta-r25-rejected-evidence-export/v3', 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'qualified': True, 'observation_gate_passed': False, 'lifecycle_executed': False,
              'lifecycle_adoption_passed': False, 'candidate_disposition': 'rejected_observation_performance',
              'rejection_reasons': observation['rejection_reasons'],
              'external_rust_ci_passed': True, 'external_python_ci_passed': True,
              'hosted_actions_passed': False, 'all_optimization_blockers_closed': False,
              'candidate_adoption_ready': False, 'no_workload_executed': True,
              'archives': {}, 'passed': False, 'attempt': 2, 'qualified_source_files': 221,
              'terminal_inputs': terminal_inputs, 'native_terminals': native_terminals, 'exporter_identity': read(Path(__file__).resolve())[0],
              'original_failed_qualification_archive': {
                  'bytes': 2238077, 'sha256': '2382c0bf4de0c48a21d31fcc2e4952b6c2036cc2897612f77227b46682bc5091',
                  'published_separately': True}}
    all_inventories, all_identities = {}, {}
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
                if group in ('observation', 'lifecycle') and (path.name == 'runtime.json'
                        or path.name in ('ssh', 'ssh-original') and path.parent.name == 'bin'):
                    omission = 'fixture transport configuration/session wrapper body omitted; exact identity retained'
                if path == ROOT / 'ci-toolchain/nextest-0.9.137/cargo-nextest-0.9.137.tar.gz.partial':
                    omission = 'verified official upstream tool archive body omitted; exact identity and source URL retained in install receipt'
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
                for relative, digest in qualification['source_after'].items():
                    add(ROOT / 'source-02' / relative, 'source/' + relative, digest)
                for path in sorted((ROOT / 'source-02/tools/x230/20261028').glob('*.py')):
                    add(path, 'qualifier-tools/' + path.name, qualification['harness_after'][path.name])
                for relative in ('qualification-terminal-status-02.json', 'preparation-02.json',
                                 'tools/requalification-02-input.json', 'tools/prepare_and_qualify_r25_02_final.py'):
                    add(ROOT / relative, 'receipts/' + relative)
            if group == 'observation':
                for relative in ('campaign-inputs-02.json', 'qualification-compact-02.json', 'measurement-plan-02.json',
                                 'campaign-inputs-02.example.json', 'observation-tools-02-manifest.json',
                                 'tools-install-02-receipt.json', 'observation-native-terminal-02.json'):
                    add(ROOT / relative, 'receipts/' + relative)
            if group == 'ci':
                for relative in ('rust-ci-plan-02.json', 'python-ci-launcher-01.py', 'tools/install_nextest_0137.py',
                                 'qualification-terminal-status-02.json', 'tool-package-install-01.json',
                                 'rust-ci-tools-install-02.json', 'rust-ci-native-terminal-02.json',
                                 'python-ci-native-terminal-01.json'):
                    add(ROOT / relative, 'receipts/' + relative)
            if group in ('observation', 'lifecycle'):
                for i, identity in enumerate(values[group]['input_bindings']):
                    path = Path(identity['path'])
                    if path.is_relative_to(ROOT):
                        continue
                    allowed = (path.is_relative_to(R16) or path.is_relative_to(BASELINE)
                               or path.is_relative_to(Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')))
                    add(path, f'bound-inputs/{i:03d}-' + path.name, identity['sha256'],
                        None if allowed else 'external system/profile input body omitted; exact identity retained')
            add(Path(__file__).resolve(), 'export-tools/export_r25_rejected_evidence_02.py', report['exporter_identity']['sha256'])
            manifest = {'schema': 'hepta-r25-archive-manifest/v2', 'group': group, 'files': files,
                        'omitted_bodies': omissions, 'source_trees': inventories, 'terminal_inputs': terminal_inputs, 'native_terminals': native_terminals,
                        'candidate_disposition': 'rejected_observation_performance', 'lifecycle_executed': False}
            raw_manifest = encode(manifest)
            archive = OUT / (group + '-02.tar.gz')
            with archive.open('xb') as destination, gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0, compresslevel=6) as zipped:
                with tarfile.open(fileobj=zipped, mode='w|', format=tarfile.PAX_FORMAT) as tar:
                    item = tarfile.TarInfo('_export-manifest.json')
                    item.size, item.mode, item.mtime = len(raw_manifest), 0o600, 0
                    tar.addfile(item, io.BytesIO(raw_manifest))
                    for name, expected in sorted(files.items()):
                        actual, raw = read(Path(expected['source_path']), retain=True)
                        assert actual == expected, name
                        if name.startswith(('observation/', 'recovery/', 'control/', 'abba/', 'saturation/')):
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
                                         'source_bytes': sum(r['bytes'] for r in files.values()),
                                         'transfer': transfer_chunks(archive)}
            all_inventories.update(inventories)
            for expected in list(files.values()) + omissions:
                path = expected['source_path']
                actual = {k: expected[k] for k in ('source_path', 'bytes', 'sha256', 'original_identity', 'is_elf')}
                assert path not in all_identities or all_identities[path] == actual
                all_identities[path] = actual
        for root, expected in all_inventories.items():
            paths, dirs = listing(Path(root))
            assert {'files': [str(p) for p in paths], 'directories': dirs} == expected
        for path, expected in all_identities.items():
            assert read(Path(path))[0] == expected, 'input changed across archives: ' + path
        for name, expected in terminal_inputs.items():
            assert read(terminal_paths[name])[0] == expected, 'terminal input changed: ' + name
        report['passed'] = True
    except Exception as error:
        report['error'] = f'{type(error).__name__}: {error}'
        report['error_trace'] = traceback.format_exc()
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (OUT / 'report.json').write_bytes(encode(report))
        print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
