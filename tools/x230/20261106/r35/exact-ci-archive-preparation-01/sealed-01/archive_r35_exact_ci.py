#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R35 exact-CI follow-up, including unsuccessful results.

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


ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
REFERENCE_SHA = '616b19b3f4859954a08f79e1e038a79bfe59465c7c9ab7ebe6fcbce57833b9e8'
ACTUAL = {'ci_job_id': '1a1af88c330-fc05-696f',
 'files': {'rust-ci-01/nextest-output-audit.json': {'bytes': 719,
                                                    'sha256': '545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3'},
           'rust-ci-01/report.json': {'bytes': 14132,
                                      'sha256': 'b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f'},
           'rust-ci-native-01.json': {'bytes': 731,
                                      'sha256': 'c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746'},
           'rust-ci-native-read-01.json': {'bytes': 5126,
                                           'sha256': '31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b'},
           'rust-ci-plan-01.json': {'bytes': 554743,
                                    'sha256': '4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28'}},
 'native_terminal': {'exit_code': 0, 'state': 'succeeded'},
 'qualification_archive_sha256': 'a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a',
 'reported_nextest_counts': {'failed': 0,
                             'ignored': 34,
                             'passed': 1645,
                             'retries': 0,
                             'selected': 1679},
 'reported_passed': True,
 'schema': 'hepta-r35-exact-ci-archive-actual-pins/v1',
 'sealed': True}
FUTURE_CORE = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-native-01.json')
FUTURE_AUDIT = 'rust-ci-01/nextest-output-audit.json'
QUALIFICATION_ARCHIVE_SHA = None if ACTUAL is None else ACTUAL['qualification_archive_sha256']
QUALIFICATION_JOB = '1a1af619097-fc05-6813'
CI_JOB = '1a1af88c330-fc05-696f'
STAGES = ('cargo-version', 'rustc-version', 'nextest-version',
          'cargo-check', 'nextest-list', 'nextest-run')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
PINNED = {'candidate/candidate.patch': '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a',
 'preparation.json': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc',
 'prepare_qualify.py': '6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4',
 'qualification-01/isolated-tests/summary.json': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904',
 'qualification-01/report.json': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1',
 'qualification-01/source-map.json': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313',
 'qualification-input.json': '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63',
 'qualification-terminal-status-01.json': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844',
 'rust-ci-qualification-bindings-01.json': 'f9f0872c0b325809a2e0712537f173e8d7f1cac128ffdd54be11b6ad279a9e81',
 'rust-ci-sealed-01/actual-pins.json': '56eec0756059f369f5299a8ee0983a32f2a3931b1f69a7594118e7fc43edefe8',
 'rust-ci-sealed-01/seal-manifest.json': '922e19932011877f53d603bd3715635ce8be4988752fffef1b9559151daa2dbe',
 'rust-ci-tools-01/audit_nextest_0137.py': '03fc242ae6ba3f5fa2fc948d3401e5f93a7a388ee9edb5b703183d6410aab8d2',
 'rust-ci-tools-01/canonical-workflow.yml': 'b9061fd671ac5fff33ad47d7ec5787f82cfadd88f5e71d54a8825cb55a02cd51',
 'rust-ci-tools-01/launch_exact_rust_ci_01.py': '15da1e478972e6971229756f0bf387fbf8b7ad4db80778dd0b5c921409e8172b',
 'rust-ci-tools-01/materialize_rust_ci_plan_01.py': '506a15cf4a73197e19025ff4413ec3f7a021e80f806064d9af58f90b85a68c2f',
 'rust-ci-tools-01/package-manifest-01.json': 'f4f7734a14bd8c886a126d911e030d956c22ef9d08e37ea329f4bf3b989ba568',
 'rust-ci-tools-01/run_rust_ci_01.py': '73762b3141daa33a8a90e332fa58ff898ad4608752bc0601c267dfabd36d2c79',
 'tools-01/r35_campaign.py': '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c'}
TOOL_FILES = ('audit_nextest_0137.py', 'launch_exact_rust_ci_01.py',
              'materialize_rust_ci_plan_01.py', 'package-manifest-01.json',
              'run_rust_ci_01.py', 'canonical-workflow.yml')
REQUIRED = tuple(dict.fromkeys(tuple(PINNED) + ('rust-ci-plan-01.json', 'rust-ci-native-01.json',
    'rust-ci-qualification-bindings-01.json', 'rust-ci-01/report.json', 'rust-ci-01/plan.json')))
SELECTED_DIRS = ('rust-ci-tools-01', 'rust-ci-01')

READ_RE = re.compile(r'rust-ci-native-read-01(?:-[0-9]{3})?\.json\Z')


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
    if 'rust-ci-native-read-01.json' in result:
        need(result == ['rust-ci-native-read-01.json'], 'single and paged native receipts cannot be mixed')
    else:
        need(result == ['rust-ci-native-read-01-%03d.json' % index for index in range(len(result))],
             'native receipt pages must be contiguous from 000')
    return result


def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-exact-ci-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True and ACTUAL.get('ci_job_id') == CI_JOB,
         'UNSEALED: complete original R35 exact-CI receipts are required')
    archive_sha = ACTUAL.get('qualification_archive_sha256')
    need(type(archive_sha) is str and re.fullmatch(r'[0-9a-f]{64}', archive_sha),
         'actual completed qualification archive reference required')
    files = ACTUAL.get('files')
    need(type(files) is dict and len(files) <= MAX_FILES, 'actual CI receipt inventory required')
    native_reads = read_names(files)
    need(set(files) == set(FUTURE_CORE) | {FUTURE_AUDIT} | set(native_reads),
         'actual CI receipt names differ from the original fixed namespace')
    for name, pin in files.items():
        if pin is None:
            need(name == FUTURE_AUDIT, 'only a genuinely absent nextest audit can have a null pin')
        else:
            need(type(pin) is dict and set(pin) == {'bytes', 'sha256'}
                 and type(pin['bytes']) is int and 0 < pin['bytes'] <= MAX_FILE
                 and type(pin['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', pin['sha256']),
                 'invalid actual original CI receipt identity: ' + name)
    need(all(files[name] is not None for name in FUTURE_CORE)
         and all(files[name] is not None for name in native_reads), 'core original CI receipt is absent')
    need(type(ACTUAL.get('reported_passed')) is bool, 'original reported CI outcome is unbound')
    counts = ACTUAL.get('reported_nextest_counts')
    need(counts is None or (type(counts) is dict and set(counts) == {'passed', 'failed', 'ignored', 'selected', 'retries'}),
         'reported original CI count shape differs')
    terminal_identity = ACTUAL.get('native_terminal')
    need(type(terminal_identity) is dict and set(terminal_identity) == {'state', 'exit_code'}
         and terminal_identity['state'] in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (terminal_identity['exit_code'] is None or type(terminal_identity['exit_code']) is int),
         'actual original CI terminal outcome is unbound')
    return ACTUAL


def bind_actual_receipts(data, expected_plan_sha):
    actual = require_sealed()
    need(expected_plan_sha == actual['files']['rust-ci-plan-01.json']['sha256'],
         'plan argument differs from sealed original CI plan')
    for name, pin in actual['files'].items():
        need((name not in data) if pin is None else
             (name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin),
             'actual original CI receipt presence/identity differs: ' + name)
    need(read_names(data) == read_names(actual['files']), 'native read receipt membership differs')
    report = json.loads(data['rust-ci-01/report.json'])
    native = json.loads(data['rust-ci-native-01.json'])
    audit = report.get('nextest_output_audit')
    counts = None if not isinstance(audit, dict) else {
        key: audit.get(key) for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    need(report.get('passed') == actual['reported_passed']
         and counts == actual['reported_nextest_counts']
         and {key: native.get(key) for key in ('state', 'exit_code')} == actual['native_terminal'],
         'reported outcome/counts/native state differ from original sealed bytes')
    return actual


def collect(root, kind):
    require_sealed()
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
    bind_actual_receipts(data, expected_plan_sha)
    need(kind == 'exact-ci' and re.fullmatch(r'[0-9a-f]{64}', expected_plan_sha), 'exact-ci plan pin is required')
    need(all(name in data for name in REQUIRED), 'missing core exact-CI input/report')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')
    need(sha(data['rust-ci-plan-01.json']) == expected_plan_sha
         and data['rust-ci-01/plan.json'] == data['rust-ci-plan-01.json'], 'original plan identity differs')
    read = lambda name: json.loads(data[name])
    plan, report = read('rust-ci-plan-01.json'), read('rust-ci-01/report.json')
    need(plan.get('schema') == 'hepta-r35-materialized-exact-rust-ci-plan/v1'
         and plan.get('attempt') == '01' and plan.get('qualification_job_id') == QUALIFICATION_JOB
         and report.get('schema') == 'hepta-r35-external-rust-ci/v1' and report.get('attempt') == '01'
         and type(report.get('passed')) is bool, 'original exact-CI schema/attempt differs')
    current_native = read('rust-ci-native-01.json')
    native = terminal(current_native, CI_JOB)
    native_streams = streams_from_reads(current_native, [read(name) for name in read_names(data)])

    errors = []

    for directory in ('rust-ci-tools-01',):
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

    tools_manifest = read('rust-ci-tools-01/package-manifest-01.json')
    for key in ('qualification_report', 'qualification_bindings', 'parent_binder', 'canonical_workflow'):
        binding(tools_manifest.get(key), 'sealed package ' + key)
    qbindings = read('rust-ci-qualification-bindings-01.json')
    for key in ('qualification_launcher', 'qualification_input', 'candidate_patch',
                'qualification_preparation', 'qualification_terminal_status'):
        binding(qbindings.get(key), 'qualification ' + key)
    for index, identity in enumerate(qbindings.get('qualification_reports', [])):
        binding(identity, 'qualification report %d' % index)
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
    audit_name = 'rust-ci-01/nextest-output-audit.json'
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
    if report['passed'] and observed_counts != qualified_counts:
        errors.append('reported successful nextest counts differ from original full qualification counts')
    return {
        'kind': kind, 'original_job_id': CI_JOB, 'reported_passed': report['passed'],
        'reported_error': report.get('error'), 'started_utc': report.get('started_utc'),
        'finished_utc': report.get('finished_utc'), 'native_terminal': native,
        'original_native_streams': native_streams,
        'plan_sha256': expected_plan_sha, 'report_sha256': sha(data['rust-ci-01/report.json']),
        'stages': stage_results, 'reported_nextest_counts': observed_counts,
        'original_nextest_audit': audit,
        'preparation_history': 'First actual R35 exact-CI attempt; no earlier R35 CI attempt is represented.',
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
    require_sealed()
    need(kind == 'exact-ci', 'only exact-ci is implemented')
    base = root / 'exact-ci-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data, expected_plan_sha)
    manifest = {'schema': 'hepta-r35-followup-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
    require_sealed()
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
                need(manifest['schema'] == 'hepta-r35-followup-evidence-archive/v1'
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
