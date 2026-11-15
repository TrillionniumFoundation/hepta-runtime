#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R31 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
SKIP_DIRS = {'test-binaries', 'profile', '.ssh', 'credentials', 'secrets', 'keys'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'agent.sock'}


REQUIRED = ('preparation-02.json', 'preparation.json', 'preparation-attempt-01-native.json',
    'preparation-permission-inspection-01.json', 'prepare_qualify.py', 'prepare_qualify_v2.py',
    'input.json', 'candidate.patch', 'qualification-terminal-status-01.json')
PINNED = {
    'preparation.json': '0f9ea821eeab65ebc555b9cb30f12188949454ce4d1ce4b3c5a8db8a1cd5f88c',
    'prepare_qualify.py': '6123c64ef487e94c3ec34c20547268a44708e8541815447f8cde9b6eff86c7e3',
    'prepare_qualify_v2.py': '65d891c7cc9fd56c10a1ce26cf55246987298a60c5946e388e4ebd1e6435db56',
    'input.json': 'b54654aa5ea0a414b860a215d6bf0caef73c3b03adccdf7da83fc7f336003383',
    'candidate.patch': '743701d44a9cef52c6cb04115bd8a8d7671c32e7fc0e52459c38ca63ff70ea21',
}
FAILED_JOB = '1a1ae1597f5-fc05-5d3e'
QUALIFICATION_JOB = '1a1ae1c32b8-fc05-5d7a'
BINARY_NAMES = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}


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
    need(kind == 'qualification', 'this script archives only completed R31 qualification')
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

    for name in REQUIRED:
        file(root / name, required=True)
    directory(root / 'qualification-01')
    optional = ['qualification-compact-01.json']
    for name in optional:
        if os.path.lexists(root / name):
            file(root / name, required=True)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def native_terminal(value, job_id, state, exit_code):
    need(value.get('job_id') == job_id and value.get('state') == state
         and type(value.get('exit_code')) is int and value['exit_code'] == exit_code
         and all(value.get(key) is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(value.get(key) is False for key in ('automatic_retry', 'timed_out', 'cancelled'))
         and type(value.get('terminal_publication_protocol')) is int and value['terminal_publication_protocol'] == 1
         and value.get('log_synced') == {'stdout': True, 'stderr': True}
         and value.get('log_errors') == {'stdout': None, 'stderr': None}
         and value.get('log_truncated') == {'stdout': False, 'stderr': False},
         'complete durable original native terminal required: ' + job_id)
    for stream in ('stdout', 'stderr'):
        counts = value['log_bytes'][stream]
        need(set(counts) == {'seen', 'stored'} and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['seen'] == counts['stored'], 'original native log byte counts differ: ' + job_id)


def summary(kind, data):
    need(kind == 'qualification', 'this script archives only completed R31 qualification')
    need(all(name in data for name in REQUIRED), 'missing original R31 preparation/qualification input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'a frozen R31 input differs')
    read = lambda name: json.loads(data[name])
    prep, failed = read('preparation-02.json'), read('preparation.json')
    terminal, failed_terminal = read('qualification-terminal-status-01.json'), read('preparation-attempt-01-native.json')
    qualified = read('qualification-01/report.json')
    tests, audit = read('qualification-01/isolated-tests/summary.json'), read('qualification-01/isolated-tests.audit.json')
    inputs, final_map = read('input.json'), read('qualification-01/source-map.json')
    native_terminal(terminal, QUALIFICATION_JOB, 'succeeded', 0)
    native_terminal(failed_terminal, FAILED_JOB, 'failed', 1)
    need(failed.get('schema') == 'hepta-x230-r31-preparation/v1' and failed.get('passed') is False
         and failed.get('finished_utc')
         and failed.get('error') == "PermissionError: [Errno 13] Permission denied: '/proc/3766/cwd'"
         and all(key not in failed for key in ('qualification_command', 'qualification_returncode',
             'source_before_qualification', 'cache_transferred_by_rename')),
         'the original failure before transfer/qualification must remain visible')
    prior = prep['prior_preparation_failure']
    need(prior.get('job_id') == FAILED_JOB and prior.get('qualification_started') is False
         and prior.get('report_path') == str(ROOT / 'preparation.json')
         and prior.get('native_path') == str(ROOT / 'preparation-attempt-01-native.json')
         and prior.get('report_sha256') == sha(data['preparation.json'])
         and prior.get('native_sha256') == sha(data['preparation-attempt-01-native.json'])
         and prior.get('reason') == failed['error'], 'recovery does not bind the original failed preparation')
    need(prep.get('schema') == 'hepta-x230-r31-preparation/v2' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and qualified.get('schema') == 'hepta-x230-composed-qualification/v1'
         and qualified.get('qualified') is True and qualified.get('finished_utc') and 'error' not in qualified
         and qualified.get('source') == str(ROOT / 'source')
         and type(qualified.get('automatic_test_retries')) is int and qualified['automatic_test_retries'] == 0
         and [row['name'] for row in qualified['stages']] == STAGES
         and all(type(row['returncode']) is int and row['returncode'] == 0 for row in qualified['stages']),
         'the actual first eight-stage qualification has not closed successfully')
    for row in qualified['stages']:
        name = row['name']
        stdout = 'cargo-no-run.jsonl' if name == 'test-build' else name + '.stdout'
        need(sha(data['qualification-01/' + stdout]) == row['stdout_sha256']
             and sha(data['qualification-01/' + name + '.stderr']) == row['stderr_sha256'],
             'original qualification stage log differs: ' + name)
    need(prep['source_before_qualification'] == inputs['candidate_compile_inputs'] == qualified['source_input']
         and prep['source_after_qualification'] == qualified['source_tested'] == qualified['source_after'] == final_map,
         'actual qualification source maps do not agree')
    need(tests.get('schema') == 'hepta-isolated-libtest/v1' and tests.get('success') is True
         and tests.get('filter') == '' and type(tests.get('retries')) is int and tests['retries'] == 0
         and tests.get('failed') == 0 and tests.get('enumeration_errors') == [] and not tests.get('fatal_error')
         and audit.get('schema') == 'hepta-isolated-libtest-audit/v1' and audit.get('success') is True
         and audit.get('expected_filter') == '' and audit.get('errors') == [] and not audit.get('fatal_error'),
         'original full isolated-test summary and audit must have closed successfully')
    counts = {key: tests[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    need(all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
         and counts['selected'] == counts['passed'] + counts['failed'] + counts['ignored']
         and all(type(audit.get(key)) is int and audit[key] == counts[key]
                 for key in ('passed', 'failed', 'ignored', 'selected'))
         and audit.get('executed') == counts['passed'] + counts['failed'],
         'existing full-inventory test counts do not reconcile')
    expected_audit_inputs = {'summary.json', 'cargo-artifacts.jsonl', 'source-manifest.input', 'commands.jsonl', 'tests.jsonl'}
    need(set(audit['input_sha256']) == expected_audit_inputs
         and all(sha(data['qualification-01/isolated-tests/' + name]) == expected
                 for name, expected in audit['input_sha256'].items()), 'original auditor input identity differs')
    need(tests['source_manifest_sha256'] == audit['input_sha256']['source-manifest.input']
         == sha(data['qualification-01/source-map.json']), 'test source manifest differs from final source map')
    need(set(qualified['binaries']) == BINARY_NAMES
         and all(row['path'] == str(ROOT / 'qualification-01' / name) for name, row in qualified['binaries'].items()),
         'qualification runtime-copy identities differ')
    binaries = {key: value['sha256'] for key, value in qualified['binaries'].items()}
    return {'kind': kind, 'qualified': True, 'original_job_id': terminal['job_id'], 'counts': counts,
            'preparation_attempts': [{'job_id': FAILED_JOB, 'state': 'failed', 'qualification_started': False},
                {'job_id': QUALIFICATION_JOB, 'state': 'succeeded', 'qualification_started': True}],
            'preparation_recovery': 'one failed preflight, then the first actual eight-stage qualification',
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'tests_reexecuted': False, 'original_test_audit_reexecuted': False,
            'performance_adoption_evaluated': False}


def create_archive(root, kind):
    need(kind == 'qualification', 'this script archives only completed R31 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r31-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
                'tool_sha256': sha(Path(__file__).read_bytes()),
                'source_reference_sha256': '7ed30b7616f905b43d1c57b2dab366cec0e1c423306a9e998f2325af347c28ee',
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
                need(manifest['schema'] == 'hepta-r31-evidence-archive/v1'
                     and manifest['kind'] == 'qualification'
                     and manifest.get('tool_sha256') == sha(Path(__file__).read_bytes()),
                     'unexpected evidence manifest/tool identity')
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
    mode.add_argument('--kind', choices=('qualification',))
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
