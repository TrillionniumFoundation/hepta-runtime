#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R31 exact-CI follow-up, including unsuccessful results.

Only fixed reports, logs, tools and inputs are read. No test, benchmark, SSH,
download or archived program is executed. Creation uses the fixed x230 root;
verification is local, bounded and never extracts archive members.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile


ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
REFERENCE_SHA = '237a05cebf47007a1f593bc415112474ec06cfd68997e1e2f6e75d795deb5a3f'
QUALIFICATION_ARCHIVE_SHA = 'f802c5fed5e3b79773825a12cbe9c888570e3ea19f954009857350e93c8071d2'
QUALIFICATION_JOB = '1a1ae1c32b8-fc05-5d7a'
CI_JOB = '1a1ae572e9e-fc05-5f26'
CI_PREFLIGHT_JOB = '1a1ae4b6679-fc05-5ec3'
STAGES = ('cargo-version', 'rustc-version', 'nextest-version',
          'cargo-check', 'nextest-list', 'nextest-run')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
PINNED = {
    'preparation-02.json': '77bdf6f1b008b65dfbedcac24b7ea3026e3946ad4fbff68ca96e5980b660d003',
    'qualification-terminal-status-01.json': 'f9f6de27c19b015e072f8169e7155783102d9b2ef3bc6ff2d8705927c0016b4e',
    'qualification-01/report.json': '489e62778972d9a8f4b2908c205b23791a968dbf21dc2bdb995350f29305c5a9',
    'qualification-01/source-map.json': 'a4c654bd8b5057fb6884c36172b198eedcfcddab8e2b291155a4e73146707a3f',
    'qualification-01/isolated-tests/summary.json': '7e388326114b5be8abfc835cead435de0c597e8b2124442d4e293360937208d6',
    'campaign-inputs-01.json': 'd9b18804f1e0ced459ef59af53d3245f24bf8bf416b74a9790d9a9280593bfe2',
    'tools-01/r31_campaign.py': '26b9aa885e049074c2170026ce3bbc9d8a5c2ffed6726899b74f836f9a977e93',
    'rust-ci-preflight-attempt-01/terminal-original.json': '930b46933cb8c062be32ee9e35473c7eede2a50b11ce8eee53bd8b38ecd6558b',
    'rust-ci-preflight-attempt-01/read-envelope.json': 'f75fd9e809a924d966e310b36be9dafd626d05603fb35579dce90b52ecff66e7',
    'rust-ci-preflight-attempt-01/stdout.log': '542bb23573af9bd8a0b1dc8f9bbc805b7fc956aa1f2fb590797bbe92a3cf9b11',
    'rust-ci-preflight-attempt-01/stderr.log': '1ba43fa402c6e5c12ac3a7710df0b363e5d40b3c3b9c6ce48caf356fca3119e8',
    'rust-ci-preflight-attempt-01/remote-source-workflow.yml': '5574840f604a3c7963a274592ac2468a43fdd04cdaa7122851c271188a11065d',
    'rust-ci-tools-02/canonical-workflow.yml': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51',
}
TOOL_FILES = ('audit_nextest_0137.py', 'launch_exact_rust_ci_01.py',
              'materialize_rust_ci_plan_01.py', 'package-manifest-01.json', 'run_rust_ci_01.py')
REQUIRED = tuple(dict.fromkeys(tuple(PINNED) + ('rust-ci-plan-02.json', 'rust-ci-native-02.json',
    'rust-ci-02/report.json', 'rust-ci-02/plan.json') + tuple(
        directory + '/' + name for directory in ('rust-ci-tools-01', 'rust-ci-tools-02')
        for name in TOOL_FILES)))
SELECTED_DIRS = ('rust-ci-tools-01', 'rust-ci-tools-02',
                 'rust-ci-preflight-attempt-01', 'rust-ci-02')
READ_RE = re.compile(r'rust-ci-native-read-02(?:-[0-9]{3})?\.json\Z')


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


def read_names(names):
    result = sorted(name for name in names if READ_RE.fullmatch(name))
    need(result, 'complete original native process_read receipt(s) are required')
    if 'rust-ci-native-read-02.json' in result:
        need(result == ['rust-ci-native-read-02.json'], 'single and paged native receipts cannot be mixed')
    else:
        need(result == ['rust-ci-native-read-02-%03d.json' % index for index in range(len(result))],
             'native receipt pages must be contiguous from 000')
    return result


def collect(root, kind):
    need(kind == 'exact-ci', 'only exact-ci is implemented; later campaigns need their actual reports')
    need(root.is_absolute() and root.resolve(strict=True) == root, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    total = 0
    visited = 0

    def file(path, required=False):
        nonlocal total, visited
        relative = path.relative_to(root).as_posix()
        if relative in payloads:
            return
        visited += 1
        need(visited <= MAX_FILES * 2 + 256, 'source traversal exceeds bounded inventory')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and path.resolve(strict=True) == path, 'non-regular/link input: ' + relative)
        if path.name in SKIP_FILES or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            need(not required, 'required receipt has a credential/binary filename')
            excluded[relative] = 'credential/configuration/binary filename'
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
        need(total <= MAX_TOTAL and len(payloads) < MAX_FILES,
             'selected source bytes/files exceed 64 MiB/8192 limits')
        payloads[relative] = data
        snapshots[path] = stamp(info)

    def directory(path, depth=0):
        nonlocal visited
        visited += 1
        need(visited <= MAX_FILES * 2 + 256 and depth <= 32, 'source directory traversal exceeds limits')
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and path.resolve(strict=True) == path,
             'non-directory/symlink input: ' + str(path))
        snapshots[path] = stamp(info)
        for child in sorted(path.iterdir()):
            mode = child.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink input: ' + str(child))
            if stat.S_ISDIR(mode):
                if child.name in SKIP_DIRS:
                    excluded[child.relative_to(root).as_posix() + '/'] = 'excluded source/target/binary/profile/credential subtree'
                else:
                    directory(child, depth + 1)
            else:
                file(child)

    for name in REQUIRED:
        file(root / name, required=True)
    for name in SELECTED_DIRS:
        directory(root / name)
    for name in read_names(path.name for path in root.iterdir()):
        file(root / name, required=True)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def terminal(value, job_id):
    need(value.get('job_id') == job_id and value.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (value.get('exit_code') is None or type(value['exit_code']) is int)
         and value.get('terminal_publication_confirmed') is True,
         'original completed native terminal required: ' + job_id)
    for stream in ('stdout', 'stderr'):
        counts = value['log_bytes'][stream]
        need(set(counts) == {'seen', 'stored'} and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['seen'] >= counts['stored'], 'invalid native log counts: ' + job_id)
    return {key: value.get(key) for key in ('job_id', 'state', 'exit_code', 'automatic_retry',
        'timed_out', 'cancelled', 'output_complete', 'output_durable', 'log_synced',
        'log_errors', 'log_truncated', 'log_bytes', 'terminal_publication_confirmed')}


def streams_from_reads(native, reads):
    cursors = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for receipt in reads:
        need(receipt.get('job_id') == native['job_id'], 'native process_read job differs')
        for name in cursors:
            part = receipt[name]
            body = bytes.fromhex(part['bytes_hex'])
            need(part['offset'] == cursors[name] and part['next_offset'] == cursors[name] + len(body)
                 and part['next_offset'] <= part['size']
                 and (not part['eof'] or part['next_offset'] == part['size'])
                 and part['text'].encode() == body, 'native stream gap or byte/text mismatch: ' + name)
            chunks[name].append(body)
            cursors[name] = part['next_offset']
    result = {}
    for name in cursors:
        body = b''.join(chunks[name])
        final = reads[-1][name]
        need(final['eof'] is True and final['size'] == cursors[name] == native['log_bytes'][name]['stored'],
             'native read does not cover all final stored bytes: ' + name)
        result[name] = {'bytes': len(body), 'sha256': sha(body), 'pages': len(reads),
            'contiguous_from_zero': True, 'complete_to_final_stored_bytes': True,
            'seen_equals_stored': native['log_bytes'][name]['seen'] == len(body)}
    return result


def summary(kind, data, expected_plan_sha):
    need(kind == 'exact-ci' and re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha), 'exact-ci plan pin is required')
    need(all(name in data for name in REQUIRED), 'missing core exact-CI input/report')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')
    need(sha(data['rust-ci-plan-02.json']) == expected_plan_sha
         and data['rust-ci-02/plan.json'] == data['rust-ci-plan-02.json'], 'original plan identity differs')
    read = lambda name: json.loads(data[name])
    plan, report = read('rust-ci-plan-02.json'), read('rust-ci-02/report.json')
    need(plan.get('schema') == 'hepta-r31-materialized-exact-rust-ci-plan/v1'
         and plan.get('attempt') == '02' and plan.get('qualification_job_id') == QUALIFICATION_JOB
         and report.get('schema') == 'hepta-r31-external-rust-ci/v1' and report.get('attempt') == '02'
         and type(report.get('passed')) is bool, 'original exact-CI schema/attempt differs')
    current_native = read('rust-ci-native-02.json')
    native = terminal(current_native, CI_JOB)
    native_streams = streams_from_reads(current_native, [read(name) for name in read_names(data)])
    prior_native = read('rust-ci-preflight-attempt-01/terminal-original.json')
    prior_terminal = terminal(prior_native, CI_PREFLIGHT_JOB)
    prior_streams = streams_from_reads(prior_native, [read('rust-ci-preflight-attempt-01/read-envelope.json')])
    need(prior_terminal['state'] == 'failed' and prior_terminal['exit_code'] == 1,
         'original failed planning attempt must remain failed')
    for name in ('stdout', 'stderr'):
        body = data['rust-ci-preflight-attempt-01/' + name + '.log']
        need(prior_streams[name]['bytes'] == len(body) and prior_streams[name]['sha256'] == sha(body),
             'original planning failure log differs')

    errors = []

    for directory in ('rust-ci-tools-01', 'rust-ci-tools-02'):
        tools_manifest = read(directory + '/package-manifest-01.json')
        for name, expected in tools_manifest.get('files', {}).items():
            body = data.get(directory + '/' + name)
            if body is None or expected != {'bytes': len(body), 'sha256': sha(body)}:
                errors.append(directory + ': tool does not match original package manifest: ' + name)

    def binding(identity, label):
        if not isinstance(identity, dict) or not isinstance(identity.get('path'), str):
            errors.append(label + ': missing identity')
            return
        path = PurePosixPath(identity['path'])
        if not path.is_relative_to(PurePosixPath(str(ROOT))) or '..' in path.parts:
            errors.append(label + ': path outside fixed root')
            return
        relative = path.relative_to(PurePosixPath(str(ROOT))).as_posix()
        body = data.get(relative)
        if body is None or identity.get('bytes') != len(body) or identity.get('sha256') != sha(body):
            errors.append(label + ': archived bytes do not match reported identity')

    binding(report.get('plan'), 'plan')
    for name in ('materializer', 'auditor', 'launcher'):
        binding(report.get(name), name)
    rows = report.get('stages', [])
    need(isinstance(rows, list) and all(isinstance(row, dict) for row in rows),
         'stage inventory must be a list of objects')
    names = [row.get('name') for row in rows]
    if names != list(STAGES[:len(rows)]) or len(rows) > len(STAGES):
        errors.append('stage names are not the original ordered prefix')
    stage_results = []
    for index, row in enumerate(rows):
        logs = {}
        for stream in ('stdout', 'stderr'):
            if stream in row:
                binding(row[stream], 'stage %d %s' % (index, stream))
                logs[stream] = row[stream]
        stage_results.append({key: row.get(key) for key in ('name', 'argv', 'returncode', 'passed',
            'timed_out', 'waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent',
            'cleanup_error', 'error', 'elapsed_seconds')} | {'logs': logs})
    audit = report.get('nextest_output_audit')
    audit_name = 'rust-ci-02/nextest-output-audit.json'
    if audit is not None:
        if audit_name not in data or read(audit_name) != audit:
            errors.append('nextest output audit file differs from report')
    if report['passed']:
        if native['state'] != 'succeeded' or native['exit_code'] != 0:
            errors.append('reported CI success conflicts with native terminal')
        if names != list(STAGES) or any(row.get('passed') is not True for row in rows):
            errors.append('reported CI success lacks six successful stages')
        if report.get('source_inputs_unchanged') is not True or report.get('owned_children_closed') is not True:
            errors.append('reported CI success lacks source/owned-child closure')
        if not isinstance(audit, dict) or audit.get('verified') is not True:
            errors.append('reported CI success lacks original nextest audit')
    if native['state'] == 'succeeded' and native['exit_code'] == 0 and report['passed'] is False:
        errors.append('native success conflicts with failed report')
    if report.get('hosted_actions_passed') is not False:
        errors.append('external report must not claim hosted Actions success')
    if not report.get('finished_utc'):
        errors.append('report has no finished timestamp; terminal may represent an aborted run')

    qualified_tests = read('qualification-01/isolated-tests/summary.json')
    qualified_counts = {key: qualified_tests[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    observed_counts = None if not isinstance(audit, dict) else {
        key: audit.get(key) for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    return {
        'kind': kind, 'original_job_id': CI_JOB, 'reported_passed': report['passed'],
        'reported_error': report.get('error'), 'started_utc': report.get('started_utc'),
        'finished_utc': report.get('finished_utc'), 'native_terminal': native,
        'original_native_streams': native_streams,
        'plan_sha256': expected_plan_sha, 'report_sha256': sha(data['rust-ci-02/report.json']),
        'stages': stage_results, 'reported_nextest_counts': observed_counts,
        'original_nextest_audit': audit,
        'prior_failed_planning_attempt': {'native_terminal': prior_terminal, 'original_streams': prior_streams,
            'cargo_stages_started': 0, 'failure_retained': True},
        'qualification_reference': {'original_job_id': QUALIFICATION_JOB,
            'archive_sha256': QUALIFICATION_ARCHIVE_SHA, 'counts': qualified_counts,
            'source_map_sha256': PINNED['qualification-01/source-map.json'],
            'full_case_logs_and_test_ELFs_repeated_here': False},
        'archived_receipt_binding_errors': errors,
        'reported_source_inputs_unchanged': report.get('source_inputs_unchanged'),
        'reported_owned_children_closed': report.get('owned_children_closed'),
        'reported_automatic_retries': report.get('automatic_retries'),
        'archive_scope': {'archives_successful_and_failed_outcomes': True, 'tests_or_benchmarks_run': False,
            'archived_programs_executed': False, 'nextest_auditor_reexecuted': False,
            'hosted_actions_passed': False, 'performance_adoption_evaluated': False},
    }


def create_archive(root, kind, expected_plan_sha):
    need(kind == 'exact-ci', 'only exact-ci is implemented')
    base = root / 'exact-ci-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data, expected_plan_sha)
    manifest = {'schema': 'hepta-r31-followup-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
        'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,
        'expected_plan_sha256': expected_plan_sha, 'selected_bytes': sum(map(len, data.values())),
        'limits': {'total_bytes': MAX_TOTAL, 'file_bytes': MAX_FILE, 'files': MAX_FILES},
        'selection': {'required_files': list(REQUIRED), 'directories': list(SELECTED_DIRS),
            'native_read_receipts': read_names(data)},
        'excluded': excluded, 'qualification_archive_reference_sha256': QUALIFICATION_ARCHIVE_SHA,
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
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL,
         'combined archive/sidecars exceed 64 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archived': True, 'kind': kind, 'archive': str(outputs[0]), 'bytes': len(archive_raw),
        'sha256': sha(archive_raw), 'manifest_sha256': sha(manifest_raw),
        'compact_sha256': sha(compact_raw), 'original_job_id': CI_JOB,
        'reported_passed': compact['reported_passed'], 'reported_nextest_counts': compact['reported_nextest_counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors']}


def verify_archive(path, expected_sha):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect archive path')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_TOTAL,
         'unsafe/oversized archive')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'archive changed before open')
        raw = stream.read(MAX_TOTAL + 1)
        need(len(raw) <= MAX_TOTAL and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'archive changed while read or exceeded 64 MiB')
    need(sha(raw) == expected_sha, 'archive SHA256 differs from the remote receipt')
    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb') as compressed:
        tar_raw = compressed.read(MAX_TAR + 1)
    need(len(tar_raw) <= MAX_TAR, 'expanded tar exceeds bounded size')
    data, manifest, manifest_sha, total = {}, None, None, 0
    with tarfile.open(fileobj=io.BytesIO(tar_raw), mode='r:') as archive:
        for number, entry in enumerate(archive):
            name = PurePosixPath(entry.name)
            need(entry.isfile() and not name.is_absolute() and '..' not in name.parts
                 and str(name) == entry.name and number <= MAX_FILES, 'unsafe/nonregular/oversized tar inventory')
            cap = MAX_MANIFEST if number == 0 else MAX_FILE
            need(0 <= entry.size <= cap, 'oversized tar member')
            value = archive.extractfile(entry).read(cap + 1)
            need(len(value) == entry.size, 'truncated tar member')
            if number == 0:
                need(entry.name == 'manifest.json', 'manifest must be first')
                manifest, manifest_sha = json.loads(value), sha(value)
                need(manifest['schema'] == 'hepta-r31-followup-evidence-archive/v1'
                     and manifest['kind'] == 'exact-ci'
                     and manifest.get('tool_sha256') == sha(Path(__file__).read_bytes()),
                     'unexpected evidence manifest/tool identity')
            else:
                need(entry.name not in data and entry.name != 'manifest.json', 'duplicate tar member')
                need(not value.startswith(b'\x7fELF') and not any(part in SKIP_DIRS for part in name.parts)
                     and name.name not in SKIP_FILES and name.suffix.lower() not in {'.pem', '.key', '.p12', '.pfx'}
                     and b'PRIVATE KEY-----' not in value and b'openssh-key-v1\x00' not in value,
                     'excluded source/binary/profile/credential content appeared in archive')
                expected = manifest['files'].get(entry.name)
                need(expected == {'bytes': len(value), 'sha256': sha(value)}, 'manifest entry mismatch: ' + entry.name)
                data[entry.name] = value
                total += len(value)
                need(total <= MAX_TOTAL, 'total tar payload exceeds 64 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data, manifest['expected_plan_sha256'])
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
        'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
        'original_job_id': CI_JOB, 'reported_passed': compact['reported_passed'],
        'reported_nextest_counts': compact['reported_nextest_counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('exact-ci',))
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify is not None:
        need(args.expected_sha256 is not None and args.plan_sha256 is None,
             '--expected-sha256 from the remote archive receipt is required for verification')
        result = verify_archive(args.verify.absolute(), args.expected_sha256)
    else:
        need(args.expected_sha256 is None and args.plan_sha256 is not None,
             '--plan-sha256 from the original materialization receipt is required for creation')
        result = create_archive(ROOT, args.kind, args.plan_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
