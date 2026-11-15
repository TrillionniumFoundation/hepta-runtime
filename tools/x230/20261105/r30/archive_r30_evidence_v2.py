#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R30 observation v2 archive, or verify it without extraction.

Only existing receipts/logs are read. No test, benchmark, SSH, download, or
archived program is executed. Output archive, manifest and compact are create-only.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r30')
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
REVISION = {
    'reason': 'The original observation inventory exceeds the v1 16 MiB total limit; raw evidence bytes are unchanged.',
    'previous_archive_schema': 'hepta-r30-evidence-archive/v1',
    'previous_job_id': '1a1ae102cc8-fc05-5d09',
    'previous_tool_sha256': '7ed30b7616f905b43d1c57b2dab366cec0e1c423306a9e998f2325af347c28ee',
    'maximum_total_bytes': MAX_TOTAL,
    'maximum_file_bytes': MAX_FILE,
    'maximum_files': MAX_FILES,
}
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
SKIP_DIRS = {'test-binaries', 'profile', '.ssh', 'credentials', 'secrets', 'keys'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'agent.sock'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def stamp(value):
    return tuple(getattr(value, key) for key in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def collect(root, kind):
    need(kind == 'observation', 'v2 is restricted to the original R30 observation evidence')
    need(root.is_absolute() and root.resolve() == root, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    total = 0

    def file(path, required=False):
        nonlocal total
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'non-regular/link input: ' + relative)
        if path.name in SKIP_FILES or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            need(not required, 'required receipt has a credential filename')
            excluded[relative] = 'credential/configuration file'
            return
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stamp(before) == stamp(info), 'input changed before open: ' + relative)
            head = stream.read(4)
            if head == b'\x7fELF':
                need(not required, 'required receipt is an ELF')
                excluded[relative] = 'ELF executable'
                return
            need(before.st_size <= MAX_FILE, 'file exceeds 8 MiB: ' + relative)
            data = head + stream.read(MAX_FILE + 1 - len(head))
            need(len(data) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno()))
                 == stamp(path.lstat()), 'input changed while read: ' + relative)
        need(b'PRIVATE KEY-----' not in data and b'openssh-key-v1\x00' not in data,
             'private-key material detected; archive was not written: ' + relative)
        total += len(data)
        need(total <= MAX_TOTAL and len(payloads) < MAX_FILES, 'selected source bytes/files exceed archive limits')
        payloads[relative] = data
        snapshots[path] = stamp(info)

    def directory(path):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode), 'non-directory/symlink input: ' + str(path))
        snapshots[path] = stamp(info)
        for child in sorted(path.iterdir()):
            mode = child.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink input: ' + str(child))
            if stat.S_ISDIR(mode):
                if child.name in SKIP_DIRS:
                    excluded[child.relative_to(root).as_posix() + '/'] = 'excluded binary/profile/credential subtree'
                else:
                    directory(child)
            else:
                file(child)

    if kind == 'qualification':
        for name in ('preparation.json', 'input.json', 'candidate.patch', 'qualification-terminal-status-01.json'):
            file(root / name, required=True)
        directory(root / 'qualification-01')
        optional = ['qualification-compact-01.json']
    else:
        file(root / 'campaign-inputs-01.json', required=True)
        directory(root / 'campaign-01')
        optional = ['observation-holder-native-01.json', 'observation-native-terminal-01.json',
                    'qualification-compact-01.json']
    for name in optional:
        if os.path.lexists(root / name):
            file(root / name, required=True)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def summary(kind, data):
    need(kind == 'observation', 'v2 is restricted to the original R30 observation evidence')
    read = lambda name: json.loads(data[name])
    if kind == 'qualification':
        prep, terminal = read('preparation.json'), read('qualification-terminal-status-01.json')
        qualified = read('qualification-01/report.json')
        tests, audit = read('qualification-01/isolated-tests/summary.json'), read('qualification-01/isolated-tests.audit.json')
        need(prep.get('passed') is True and qualified.get('qualified') is True
             and [row['name'] for row in qualified['stages']] == STAGES
             and all(type(row['returncode']) is int and row['returncode'] == 0 for row in qualified['stages']),
             'qualification has not closed successfully')
        need(terminal.get('state') == 'succeeded' and type(terminal.get('exit_code')) is int and terminal['exit_code'] == 0
             and all(terminal.get(key) is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
             and all(terminal.get(key) is False for key in ('automatic_retry', 'timed_out', 'cancelled')),
             'successful durable original native terminal required')
        need(tests.get('success') is True and audit.get('success') is True and tests.get('retries') == 0
             and tests.get('failed') == 0 and audit.get('errors') == [], 'original test audit is not successful')
        counts = {key: tests[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
        need(all(audit[key] == counts[key] for key in ('passed', 'failed', 'ignored', 'selected')),
             'existing test summary and audit disagree')
        binaries = {key: value['sha256'] for key, value in qualified['binaries'].items()}
        return {'kind': kind, 'qualified': True, 'original_job_id': terminal['job_id'], 'counts': counts,
                'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
                'source_map_sha256': sha(data['qualification-01/source-map.json']), 'tests_reexecuted': False}
    parent = read('campaign-01/report.json')
    native_name = 'campaign-01/native-observation/report.json'
    native = read(native_name)
    cells, failures = [], []
    for round_ in native['rounds']:
        for cell in round_['cells']:
            cell_id = {'round': round_['index'], 'arm': round_['version'], 'concurrency': cell['concurrency']}
            cells.append(dict(cell_id, calls=cell['calls'], successes=cell['successes']))
            for call in cell['rows']:
                if call.get('okay') is not True:
                    failures.append(dict(cell_id, call=call))
    need(parent.get('passed') is False and native.get('passed') is False and failures,
         'this archive mode is for the original failed R30 observation')
    planned = [row['name'] for row in parent.get('stage_plan', [])]
    started = [row['name'] for row in parent['stages']]
    counts = {'rounds': len(native['rounds']), 'cells': len(cells),
              'calls': sum(row['calls'] for row in cells), 'successes': sum(row['successes'] for row in cells),
              'failed_calls': len(failures)}
    return {'kind': kind, 'candidate_adopted': False, 'counts': counts, 'cells': cells, 'failures': failures,
            'native_report': {'path': native_name, 'bytes': len(data[native_name]), 'sha256': sha(data[native_name])},
            'parent_error': parent.get('error'), 'stages_not_started': [name for name in planned if name not in started],
            'measurement_attribution_valid': parent.get('measurement_attribution_valid'),
            'compiler_monitor_passed': parent.get('compiler_monitor', {}).get('passed'),
            'qualified_binary_sha256': {arm: rows['hepta-runtime']['sha256'] for arm, rows in parent['binaries'].items()},
            'causal_attribution': 'unresolved; neither router causation nor an environmental explanation is established',
            'automatic_rerun': False, 'saturated_cancellation_verified': False}


def create_archive(root, kind):
    need(kind == 'observation', 'v2 is restricted to the original R30 observation evidence')
    base = root / 'observation-evidence-02'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r30-evidence-archive/v2', 'kind': kind, 'source_root': str(root),
                'revision': REVISION, 'tool_sha256': sha(Path(__file__).read_bytes()),
                'selected_bytes': sum(map(len, data.values())), 'excluded': excluded,
                'files': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(data.items())},
                'summary': compact, 'no_tests_or_benchmarks_run': True}
    manifest_raw, compact_raw = encoded(manifest), encoded(compact)
    need(len(manifest_raw) <= MAX_MANIFEST, 'manifest exceeds 2 MiB')
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in [('manifest.json', manifest_raw), *sorted(data.items())]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.mtime = len(raw), 0o600, 0
                archive.addfile(entry, io.BytesIO(raw))
    archive_raw = buffer.getvalue()
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL, 'combined archive/sidecars exceed 32 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archive': str(outputs[0]), 'bytes': len(archive_raw), 'sha256': sha(archive_raw),
            'manifest_sha256': sha(manifest_raw), 'counts': compact['counts'],
            'qualified_binary_sha256': compact['qualified_binary_sha256']}


def verify_archive(path, expected_sha):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_TOTAL, 'unsafe/oversized archive')
    raw = path.read_bytes()
    need(sha(raw) == expected_sha, 'archive SHA256 differs from the remote receipt')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, 'expanded tar exceeds bounded size')
    data, manifest, manifest_sha, total = {}, None, None, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        for number, entry in enumerate(archive):
            name = PurePosixPath(entry.name)
            need(entry.isfile() and not name.is_absolute() and '..' not in name.parts
                 and str(name) == entry.name and number <= MAX_FILES, 'unsafe/duplicate/oversized tar inventory')
            cap = MAX_MANIFEST if number == 0 else MAX_FILE
            need(0 <= entry.size <= cap, 'oversized tar member')
            value = archive.extractfile(entry).read(cap + 1)
            need(len(value) == entry.size, 'truncated tar member')
            if number == 0:
                need(entry.name == 'manifest.json', 'manifest must be first')
                manifest, manifest_sha = json.loads(value), sha(value)
                need(manifest['schema'] == 'hepta-r30-evidence-archive/v2'
                     and manifest['kind'] == 'observation'
                     and manifest.get('revision') == REVISION
                     and manifest.get('tool_sha256') == sha(Path(__file__).read_bytes()),
                     'unexpected evidence manifest/revision/tool identity')
            else:
                need(entry.name not in data and entry.name != 'manifest.json', 'duplicate tar member')
                need(not value.startswith(b'\x7fELF') and 'test-binaries' not in name.parts,
                     'excluded binary content appeared in archive')
                expected = manifest['files'].get(entry.name)
                need(expected == {'bytes': len(value), 'sha256': sha(value)}, 'manifest entry mismatch: ' + entry.name)
                data[entry.name] = value
                total += len(value)
                need(total <= MAX_TOTAL, 'total tar payload exceeds 32 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data)
    need(compact == manifest['summary'], 'compact summary differs from the retained raw receipts')
    return {'verified': True, 'archive': str(path), 'bytes': len(raw), 'sha256': sha(raw),
            'manifest_sha256': manifest_sha, 'counts': compact['counts'],
            'qualified_binary_sha256': compact['qualified_binary_sha256'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('observation',))
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify is not None:
        need(args.expected_sha256 is not None, '--expected-sha256 from the remote archive receipt is required')
        result = verify_archive(args.verify.absolute(), args.expected_sha256)
    else:
        need(args.expected_sha256 is None, '--expected-sha256 is only for verification')
        result = create_archive(ROOT, args.kind)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
