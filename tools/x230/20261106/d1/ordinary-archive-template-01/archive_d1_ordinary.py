#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded D1 ordinary supplement evidence archive, or verify it locally without extraction.

Only existing receipts/logs are read. No test, benchmark, SSH, download, or
archived program is executed. Output archive, manifest and compact are create-only.
"""
import argparse
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ["clippy", "test-build", "isolated-tests", "audit-isolated-tests", "release"]
SKIP_DIRS = {'target', 'target-build', 'test-binaries', '.git', '__pycache__', 'profile', '.ssh', 'credentials', 'secrets', 'keys'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'agent.sock'}

PINNED = {"full-prerequisites-03/d1_prerequisites.py": {"bytes": 58168, "sha256": "623c8678fe2ed89dae7fb8cdf188e34e009e8d73fee10275f51b753fe3d41b98"}, "ordinary-deployment-manifest-01.json": {"bytes": 1625, "sha256": "e26f85e5dab07f97e9d50635e8a92aaf75b1d0d417c20ff981918d710f0ff6ff"}, "ordinary-deployment-manifest-02.json": {"bytes": 2331, "sha256": "66bd8db53af0df75475a9b91d32944ffabd4622253bab5a090a91f270e65f7f5"}, "ordinary-launch-command-01.json": {"bytes": 682, "sha256": "fecf031bd89937f70ac0301b9b9e384aa7d9ed53c5ecde81d7e2ada56f9ef1e9"}, "ordinary-launch-command-02.json": {"bytes": 682, "sha256": "3bd486275845828c6ae0b98c8a87c06bb3e88347cbd80ad6adee0c13d34b2599"}, "ordinary-preflight-failure-01/native.json": {"bytes": 726, "sha256": "23948ec44e028ba5fffd22e8307f53fadf8c462e772947c16facfaccd2c8315b"}, "ordinary-preflight-failure-01/read-000.json": {"bytes": 3070, "sha256": "545625f7fd83c76aeddba073acbc1b1b8b9178f89d26c0feacd44beac277d820"}, "ordinary-preflight-failure-01/start.json": {"bytes": 1209, "sha256": "2efe45c06a235e3c4536d416c3ccbffa9ded4014271d2e0babc91fbfae3723e2"}, "ordinary-prerequisites-01.json": {"bytes": 5063, "sha256": "9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb"}, "ordinary-prerequisites-02.json": {"bytes": 5063, "sha256": "9d5ca9b3d4e276d8f7b830cf028eac9eded76ab3b0f560758279451989c966cb"}, "ordinary-seal-manifest-01.json": {"bytes": 2156, "sha256": "ea6f3928d163c7b3d408e3f471440a70bc0626ca41179b3fa119e1f51f146ebb"}, "ordinary-seal-manifest-02.json": {"bytes": 2153, "sha256": "ac1ee21ca2b55dcb4f9e17d4f55ce81f4c919d36bfd55605ba4c2172b45dad7e"}, "ordinary-seal-request-01.json": {"bytes": 843, "sha256": "8bfe056f291c582a4a2d683146c14f1fd243a3f17633f36275fcac8f637925de"}, "ordinary-seal-request-02.json": {"bytes": 840, "sha256": "e033a31f2655bba13f07466f76cb878a5da26348aa5119c6d9fc4e780fa338ca"}, "ordinary-tools-01/launch_ordinary_01.py": {"bytes": 11725, "sha256": "72aed2c63820afcd9f2584564259bbc1c2962d229103339b82b5071d807ed286"}, "ordinary-tools-01/package-manifest-01.json": {"bytes": 703, "sha256": "31cc9b03baf8ec8e53ecbd1038f7d321391325ef23d5c5efe071358f23140e13"}, "ordinary-tools-01/qualify_ordinary_01.py": {"bytes": 7320, "sha256": "07a6ebae6b2579c1935c1b64abce9ff50be5f58e83faeb30be622a52d27aed51"}, "ordinary-tools-01/verify_ordinary_01.py": {"bytes": 21164, "sha256": "b0140801f13178c7e16a5da8c70b59e342d1a166689636ef94c360dedb39829b"}, "ordinary-tools-02/launch_ordinary_02.py": {"bytes": 12092, "sha256": "0de3b663b14e274ee80c3cfb9b8c800f29933f8674cdb266bf8c4fb24cd7b317"}, "ordinary-tools-02/package-manifest-02.json": {"bytes": 703, "sha256": "ff53ecdaaa5ecffd2787fbea12d31d05a68f7dd41f793b8f16e2ac313fa7c196"}, "ordinary-tools-02/qualify_ordinary_02.py": {"bytes": 7320, "sha256": "07a6ebae6b2579c1935c1b64abce9ff50be5f58e83faeb30be622a52d27aed51"}, "ordinary-tools-02/verify_ordinary_02.py": {"bytes": 27238, "sha256": "bcf8551a7523fb051a9987433fa0210303d575c540ae14341648e4d2afe6b7e3"}, "qualification-01/report.json": {"bytes": 83976, "sha256": "0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437"}, "source/tools/x230/20261028/qualify.py": {"bytes": 7661, "sha256": "95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d"}}
REQUIRED = sorted(PINNED)
CORE_PATHS = ["ordinary-native-02.json", "ordinary-plan-02.json", "ordinary-02/report.json", "ordinary-02/source-map.json", "ordinary-02/isolated-tests/summary.json", "ordinary-02/isolated-tests.audit.json", "ordinary-verification-input-02.json", "ordinary-postflight-02.json", "ordinary-postflight-native-02.json", "ordinary-installation-started-02.json", "ordinary-installation-02.json"]
BINARY_NAMES = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')
EXPECTED_JOB_ID = '1a1b04c6cd1-fc05-6f94'
SOURCE_REFERENCE_SHA256 = 'e7a0787a110c50a93e18bf951c02f195e62752c532ea3f649f956ca1b06d018f'
VERIFY_REFERENCE_SHA256 = SOURCE_REFERENCE_SHA256
EXTERNAL_EVIDENCE_REFERENCES = {"exact_ci_original_file_collection_catalog": {"bytes": 7310, "git_blob": "417ae66f5a3b9580f95ac4a2c89544d77f4c8b02", "kind": "catalog_of_24_original_files_not_a_compressed_archive", "repository": "TrillionniumFoundation/hepta-runtime", "sha256": "8790460216b614ab839438647cb2c4bbbe20f4e7c75fcc5fdf1df9df876306e0"}, "qualification_archive": {"bytes": 3023187, "git_blob": "e5af9ce0c97cb57bcc983c819b5ede29e8f347d0", "kind": "tar.gz", "local_zero_extraction_verification_stdout": {"bytes": 828, "git_blob": "a9661d4d9aad8f2559611757f0d19392f9d25127"}, "repository": "TrillionniumFoundation/hepta-runtime", "sha256": "384ab01dcd7e8e2556605fa038f266ecc6449889fdaf1d4958d8c93baea4877b"}, "scope": "External reference identities supplied from root's completed transfers/publication; not downloaded or executed by this collector."}
ACTUAL = None


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

def tool_sha256():
    path = Path(__file__).absolute()
    need(path.resolve(strict=True) == path, 'indirect archive tool')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_FILE,
         'unsafe/oversized archive tool')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'archive tool changed before open')
        raw = stream.read(MAX_FILE + 1)
        need(len(raw) <= MAX_FILE and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'archive tool changed while read')
    return sha(raw)

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


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Pure original receipt functions embedded by the builder; never executed during preparation.

def original_streams(value, terminal):
    need(value.get('job_id') == terminal['job_id'] and value.get('audit_recorded') is True,
         'native read does not identify the original terminal')
    result = {}
    for name in ('stdout', 'stderr'):
        row = value[name]
        raw = bytes.fromhex(row['bytes_hex'])
        need(row['offset'] == 0 and row['eof'] is True
             and row['next_offset'] == row['size'] == len(raw) == terminal['log_bytes'][name]['stored']
             and row['text'] == raw.decode('utf-8', errors='replace'), 'incomplete original native stream: ' + name)
        result[name] = raw
    return result

def native_stream_pages(pages, terminal):
    """Verify original read pages; never replace them with a fabricated single page."""
    assert isinstance(pages, list) and 1 <= len(pages) <= 16
    offsets = {'stdout': 0, 'stderr': 0}
    chunks = {'stdout': [], 'stderr': []}
    for index, page in enumerate(pages):
        assert page['job_id'] == terminal['job_id'] and page['audit_recorded'] is True
        for name in ('stdout', 'stderr'):
            channel = page[name]
            raw = bytes.fromhex(channel['bytes_hex'])
            total = terminal['log_bytes'][name]['stored']
            assert type(total) is int and 0 <= total <= 256 * 1024
            assert type(channel['offset']) is int and channel['offset'] == offsets[name]
            assert channel['size'] == total and len(raw) <= 16384
            assert channel['next_offset'] == channel['offset'] + len(raw) <= total
            assert channel['text'] == raw.decode('utf-8', errors='replace')
            assert channel['eof'] is (channel['next_offset'] == total)
            # A stream already at EOF may recur as an empty EOF on later calls.
            # A pending stream must make progress, with no gaps or overlaps.
            assert raw or offsets[name] == total
            if index + 1 == len(pages):
                assert channel['eof'] is True
            offsets[name] = channel['next_offset']
            chunks[name].append(raw)
    assert all(offsets[name] == terminal['log_bytes'][name]['stored'] for name in offsets)
    return {name: b''.join(parts) for name, parts in chunks.items()}

def require_sealed():
    need(not sys.flags.optimize, 'original receipt assertions must be enabled')
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d1-ordinary-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True,
         'UNSEALED: actual ordinary terminal, original pages and captured result identities are required')
    need(ACTUAL.get('producer_original_job_id') == EXPECTED_JOB_ID
         and ACTUAL.get('outcome') in {'passed', 'not_passed'}, 'actual ordinary attempt is unbound')
    pages = ACTUAL.get('native_read_paths')
    postpages = ACTUAL.get('postflight_native_read_paths')
    need(type(pages) is list and 1 <= len(pages) <= 16
         and pages == ['ordinary-native-read-02-%03d.json' % i for i in range(len(pages))]
         and type(postpages) is list and len(postpages) <= 16
         and postpages == ['ordinary-postflight-native-read-02-%03d.json' % i for i in range(len(postpages))],
         'only complete original contiguous page inventories are supported')
    files = ACTUAL.get('files')
    need(type(files) is dict and set(files) == set(CORE_PATHS) | set(pages) | set(postpages),
         'actual captured file inventory differs')
    for name, pin in files.items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual receipt pin: ' + name)
    need(all(files[name] is not None for name in ['ordinary-native-02.json', *pages]),
         'actual original ordinary terminal and all stored native pages are mandatory')
    post_id = ACTUAL.get('postflight_original_job_id')
    need((post_id is None and not postpages and files['ordinary-postflight-native-02.json'] is None)
         or (type(post_id) is str and len(post_id.split('-')) == 3
             and all(part and set(part) <= set('0123456789abcdef') for part in post_id.split('-'))
             and post_id != EXPECTED_JOB_ID and postpages
             and files['ordinary-postflight-native-02.json'] is not None),
         'postflight original native identity/pages are inconsistent')
    if ACTUAL['outcome'] == 'passed':
        need(all(files[name] is not None for name in CORE_PATHS)
             and post_id is not None, 'original successful ordinary validation is incomplete')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == set(COUNTS)
             and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored'],
             'actual ordinary test counts are incomplete')
    return ACTUAL


def archived_identity(data, name):
    need(name in data, 'required original is not in the archive: ' + name)
    return {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}


def match_original(data, pin):
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact original identity required')
    path = Path(pin['path'])
    need(path.is_absolute() and path.is_relative_to(ROOT), 'ordinary original is outside its fixed root')
    name = path.relative_to(ROOT).as_posix()
    need(archived_identity(data, name) == pin, 'archived original differs: ' + name)
    return name


def captured_native(data, terminal_name, page_names, job_id, successful):
    terminal = json.loads(data[terminal_name])
    need(terminal.get('job_id') == job_id
         and terminal.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (terminal.get('exit_code') is None or type(terminal.get('exit_code')) is int),
         'captured native terminal is not a terminal of the original job')
    for name in ('stdout', 'stderr'):
        counts = terminal['log_bytes'][name]
        need(set(counts) == {'seen', 'stored'}
             and all(type(n) is int and n >= 0 for n in counts.values())
             and counts['seen'] >= counts['stored'], 'invalid captured native byte counts')
    if successful:
        native_terminal(terminal, job_id, 'succeeded', 0)
    pages = [json.loads(data[name]) for name in page_names]
    streams = native_stream_pages(pages, terminal)
    return terminal, streams


def prior_failure_summary(data):
    native = json.loads(data['ordinary-preflight-failure-01/native.json'])
    native_terminal(native, '1a1b03a9d15-fc05-6f3f', 'failed', 1)
    streams = original_streams(json.loads(data['ordinary-preflight-failure-01/read-000.json']), native)
    start = json.loads(data['ordinary-preflight-failure-01/start.json'])
    need(streams['stdout'] == b'' and len(streams['stderr']) == 910
         and sha(streams['stderr']) == '5a8ca32053dccead093751eb8cc8bbe7b244042936744c50ed41fe0a5b4a8245'
         and start['job']['id'] == native['job_id'] and start['launch']['ok'] is True
         and start['reused'] is False and start['job']['args']
             == ['-B', '-u', str(ROOT / 'ordinary-tools-01/launch_ordinary_01.py'),
                 '--launcher-sha256', '72aed2c63820afcd9f2584564259bbc1c2962d229103339b82b5071d807ed286'],
         'original failed preflight native/start/raw stream does not reconcile')
    return {'original_job_id': native['job_id'], 'state': 'failed', 'exit_code': 1,
            'native': archived_identity(data, 'ordinary-preflight-failure-01/native.json'),
            'read': archived_identity(data, 'ordinary-preflight-failure-01/read-000.json'),
            'start': archived_identity(data, 'ordinary-preflight-failure-01/start.json'),
            'original_stdout_bytes': 0, 'original_stderr_bytes': 910,
            'original_stderr_sha256': sha(streams['stderr']),
            'classification': 'full prerequisite rejected before ordinary plan or qualifier exec',
            'old_job_restarted': False, 'original_failure_preserved': True}


def compressed_case_inventory(data, tests, audit, report):
    need(tests.get('schema') == 'hepta-isolated-libtest/v1' and tests.get('success') is True
         and tests.get('filter') == '' and tests.get('enumeration_errors') == [] and not tests.get('fatal_error')
         and audit.get('schema') == 'hepta-isolated-libtest-audit/v1' and audit.get('success') is True
         and audit.get('expected_filter') == '' and audit.get('errors') == [] and not audit.get('fatal_error'),
         'original ordinary test summary or audit was not successful')
    counts = {key: tests[key] for key in COUNTS}
    need(all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
         and counts['failed'] == counts['retries'] == 0
         and counts['selected'] == counts['passed'] + counts['ignored']
         and all(type(audit.get(key)) is int and audit[key] == counts[key]
                 for key in ('passed', 'failed', 'ignored', 'selected'))
         and audit.get('executed') == counts['passed'], 'ordinary full test counts do not reconcile')
    expected_audit_inputs = {'summary.json', 'cargo-artifacts.jsonl', 'source-manifest.input', 'commands.jsonl', 'tests.jsonl'}
    need(set(audit['input_sha256']) == expected_audit_inputs
         and all(sha(data['ordinary-02/isolated-tests/' + name]) == digest
                 for name, digest in audit['input_sha256'].items()), 'original auditor input differs')
    need(tests['source_manifest_sha256'] == audit['input_sha256']['source-manifest.input']
         == sha(data['ordinary-02/source-map.json'])
         and audit['auditor_sha256'] == report['harness_after']['audit_isolated_tests.py'],
         'original test source map or auditor identity differs')
    # Match compressed original bytes to the already executed original audit.
    # No case log is decompressed and neither binary enumeration nor audit runs.
    commands = [json.loads(line) for line in data['ordinary-02/isolated-tests/commands.jsonl'].splitlines()]
    by_stdout = {row['stdout_gzip']: row for row in commands}
    need(len(by_stdout) == len(commands) == len(audit['commands'])
         and {row['stdout_gzip'] for row in audit['commands']} == set(by_stdout),
         'original audited command-log membership differs')
    logs = set()
    for proof in audit['commands']:
        command = by_stdout[proof['stdout_gzip']]
        for stream in ('stdout', 'stderr'):
            name = command[stream + '_gzip']
            need(Path(name).name == name and name not in {'.', '..'} and name not in logs,
                 'unsafe or duplicated original compressed log')
            logs.add(name)
            need(sha(data['ordinary-02/isolated-tests/' + name]) == proof[stream]['gzip_sha256'],
                 'original compressed log missing or changed: ' + name)
    archived_logs = {name.removeprefix('ordinary-02/isolated-tests/')
                     for name in data if name.startswith('ordinary-02/isolated-tests/') and name.endswith('.gz')}
    need(archived_logs == logs, 'compressed raw log archive is incomplete or contains unbound members')
    return counts, len(logs)


def successful_summary(data, documents, native_streams):
    plan = documents['ordinary-plan-02.json']
    report = documents['ordinary-02/report.json']
    source_map = documents['ordinary-02/source-map.json']
    tests = documents['ordinary-02/isolated-tests/summary.json']
    audit = documents['ordinary-02/isolated-tests.audit.json']
    verification = documents['ordinary-verification-input-02.json']
    postflight = documents['ordinary-postflight-02.json']
    qualified = json.loads(data['qualification-01/report.json'])
    proof = plan['completed_q_and_exact_ci_proof']
    need(plan['schema'] == 'hepta-d1-ordinary-supplement-plan/v3' and plan['executed'] is False
         and plan['supplement_stage_names'] == STAGES
         and plan['omitted_previously_completed_stages'] == ['format', 'fmt-check', 'harness-tests']
         and plan['ordinary_five_stage_supplement'] is True
         and plan['original_qualification_eight_stages_unchanged'] is True
         and plan['exact_removed_arguments'] == ['--all-features'] * 3
         and plan['automatic_retries'] == 0 and plan['package_features'] == []
         and plan['dependency_defaults_changed'] is False and plan['no_default_features_switch'] is False
         and plan['diagnostic_environment_absent'] is True
         and plan['performance_acceptance_claim'] is False, 'original ordinary plan protocol differs')
    need(report['schema'] == 'hepta-x230-composed-qualification/v1'
         and report.get('qualified') is True and report.get('finished_utc') and not report.get('error')
         and report['source'] == str(ROOT / 'source') and report['jobs'] == 2
         and report['automatic_test_retries'] == 0 and report['service_changes'] is False
         and report['source_input'] == report['source_tested'] == report['source_after']
         == source_map == qualified['source_tested'] == proof['source_tested'] == plan['source_files']
         and len(source_map) == 222
         and report['harness_before'] == report['harness_after'] == qualified['harness_after']
         == proof['qualification']['qualification_harness'] and len(report['harness_after']) == 19,
         'ordinary source or original harness identity differs')
    need(verification['schema'] == 'hepta-d1-ordinary-verification-input/v3'
         and verification['sealed_inputs'] is True and verification['performance_acceptance_claim'] is False
         and verification['original_job_id'] == EXPECTED_JOB_ID,
         'actual ordinary verification input differs')
    for field in ('foundation', 'prerequisites', 'plan', 'report', 'source_map', 'isolated_summary',
                  'isolated_audit', 'native_terminal'):
        match_original(data, verification[field])
    need([match_original(data, pin) for pin in verification['native_read_pages']]
         == ACTUAL['native_read_paths'], 'verification used another native read inventory')
    need(postflight['schema'] == 'hepta-d1-ordinary-supplement-postflight/v3'
         and postflight['validation_schema'] == 'hepta-d1-ordinary-supplement-validation/v3'
         and postflight.get('passed') is True and postflight.get('ordinary_five_stages_passed') is True
         and postflight.get('source_maps_unchanged') is True
         and postflight['original_job_id'] == EXPECTED_JOB_ID
         and postflight['verification_input'] == archived_identity(data, 'ordinary-verification-input-02.json')
         and postflight['report_written_create_only'] is True
         and postflight['source_files'] == source_map and postflight['compiler_input_count'] == 222
         and postflight['original_qualification_harness_count'] == 19
         and postflight['automatic_retries'] == 0
         and postflight['original_auditors_reexecuted'] is False
         and postflight['new_compile_or_workload_started'] is False
         and postflight['performance_acceptance_claim'] is False
         and postflight['original_test_audit_binary_custody'] is True
         and postflight['retained_test_elves_rehashed_by_postflight'] is False,
         'original postflight did not validate the completed five-stage ordinary supplement')
    for field in ('foundation', 'prerequisites', 'verifier', 'plan', 'report', 'isolated_summary',
                  'isolated_audit', 'native_terminal', 'ordinary_source_map'):
        match_original(data, postflight[field])
    need(postflight['original_q_job_id'] == proof['qualification']['original_job_id']
         == '1a1aff8769c-fc05-6d26'
         and postflight['original_exact_ci_job_id'] == proof['exact_ci']['original_job_id']
         == '1a1b0238605-fc05-6e78'
         and proof['passed'] is True and proof['exact_ci']['passed'] is True,
         'original ordinary validation references a different Q/CI closure')
    rows = report['stages']
    originals = [row for row in qualified['stages'] if row['name'] in STAGES]
    need([row['name'] for row in rows] == [row['name'] for row in originals] == STAGES
         and len(postflight['stages']) == len(rows), 'original five-stage inventory differs')
    for row, original, saved in zip(rows, originals, postflight['stages']):
        oldroot, newroot = str(ROOT / 'qualification-01'), str(ROOT / 'ordinary-02')
        command = [newroot + arg[len(oldroot):] if arg == oldroot or arg.startswith(oldroot + '/') else arg
                   for arg in original['command'] if arg != '--all-features']
        need(row['command'] == command and type(row['returncode']) is int and row['returncode'] == 0
             and isinstance(row['seconds'], (int, float)) and math.isfinite(row['seconds']) and row['seconds'] >= 0
             and saved['name'] == row['name'] and saved['command'] == command
             and saved['returncode'] == 0 and saved['original_seconds'] == row['seconds'],
             'ordinary stage changed more than the feature selection/output location')
        for stream in ('stdout', 'stderr'):
            name = 'cargo-no-run.jsonl' if row['name'] == 'test-build' and stream == 'stdout' else row['name'] + '.' + stream
            path = 'ordinary-02/' + name
            need(sha(data[path]) == row[stream + '_sha256']
                 and saved['logs'][stream] == archived_identity(data, path), 'original stage stream differs')
    expected_stdout = [{'phase': 'execute_ordinary_feature_off_supplement',
        'plan_sha256': sha(data['ordinary-plan-02.json']), 'automatic_retries': 0, 'preserved_feature_executables': 3}]
    for row in rows:
        expected_stdout.extend([{'stage': row['name'], 'state': 'started'},
                                {'stage': row['name'], 'exit': 0, 'seconds': row['seconds']}])
    expected_stdout.append({'qualified': True, 'report': str(ROOT / 'ordinary-02/report.json'), 'error': None})
    native_ids = {key: {'bytes': len(value), 'sha256': sha(value)} for key, value in native_streams.items()}
    need(native_streams['stderr'] == b''
         and [json.loads(line) for line in native_streams['stdout'].splitlines()] == expected_stdout
         and postflight['native_streams'] == native_ids, 'original native stream/report/postflight differ')
    counts, log_count = compressed_case_inventory(data, tests, audit, report)
    need(postflight['tests'] == ACTUAL['counts'] == counts, 'actual ordinary dynamic counts differ')
    need(postflight['qualified_feature_programs_before'] == postflight['qualified_feature_programs_after']
         == plan['qualification_feature_programs'] == proof['binaries']
         and set(postflight['ordinary_programs']) == set(report['binaries']) == BINARY_NAMES,
         'retained release program evidence differs')
    binary_paths = set()
    for group, directory in ((postflight['qualified_feature_programs_after'], 'qualification-01'),
                              (postflight['ordinary_programs'], 'ordinary-02')):
        need(set(group) == BINARY_NAMES, 'release executable names differ')
        for name, pin in group.items():
            need(set(pin) == {'path', 'bytes', 'sha256'} and pin['path'] == str(ROOT / directory / name)
                 and type(pin['bytes']) is int and pin['bytes'] > 0
                 and len(pin['sha256']) == 64 and set(pin['sha256']) <= set('0123456789abcdef'),
                 'original postflight release identity is malformed')
            binary_paths.add(pin['path'])
            need(directory + '/' + name not in data, 'an ELF body was unexpectedly archived')
            if directory == 'ordinary-02':
                need(report['binaries'][name]['path'] == pin['path']
                     and report['binaries'][name]['sha256'] == pin['sha256'], 'ordinary release report differs')
    need(postflight['retained_test_elf_identities_from_original_audit'] == audit['binaries'],
         'original test ELF custody identities differ')
    for binary in audit['binaries']:
        path = Path(binary['path'])
        need(path.parent == ROOT / 'ordinary-02/test-binaries'
             and binary['recorded_before_sha256'] == binary['current_after_sha256']
             and type(binary['recorded_before_sha256']) is str and len(binary['recorded_before_sha256']) == 64
             and set(binary['recorded_before_sha256']) <= set('0123456789abcdef'),
             'original test audit binary custody differs')
    referenced_release = []
    for path, pin in postflight['originals'].items():
        need(path == pin['path'], 'postflight original identity key differs')
        if path in binary_paths:
            referenced_release.append(pin)
        else:
            match_original(data, pin)
    need(set(pin['path'] for pin in referenced_release) == binary_paths,
         'postflight originals do not name the six preserved release programs')
    prior = postflight['prior_preflight_failure']
    need(prior == plan['prior_preflight_failure']
         and prior['original_job_id'] == '1a1b03a9d15-fc05-6f3f'
         and prior['original_state'] == 'failed' and prior['original_exit_code'] == 1
         and prior['original_plan_absent'] is True and prior['original_output_absent'] is True
         and prior['old_job_reexecuted'] is False and prior['test_retry_performed'] is False,
         'prior failed preflight was hidden or replayed')
    for pin in [prior['native_terminal'], prior['start'], *prior['native_read_pages'],
                *prior['old_deployed_members']]:
        match_original(data, pin)
    post_terminal, post_streams = captured_native(data, 'ordinary-postflight-native-02.json',
        ACTUAL['postflight_native_read_paths'], ACTUAL['postflight_original_job_id'], True)
    expected_post_stdout = {'verified': True, 'original_job_id': EXPECTED_JOB_ID,
        'report': archived_identity(data, 'ordinary-postflight-02.json'), 'compiler_or_workload_started': False}
    need(post_streams['stderr'] == b''
         and [json.loads(line) for line in post_streams['stdout'].splitlines()] == [expected_post_stdout],
         'original postflight native stream does not bind the retained postflight bytes')
    bindings = postflight['all_input_bindings']
    need(type(bindings) is list and bindings, 'original postflight full input binding list is absent')
    copied, external = set(), {}
    for pin in bindings:
        need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'malformed postflight binding')
        path = Path(pin['path'])
        name = path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else None
        if name in data:
            match_original(data, pin)
            copied.add(name)
        else:
            need(pin['path'] not in external or external[pin['path']] == pin,
                 'inconsistent repeated external original')
            external[pin['path']] = pin
    return {'ordinary_passed_from_original_postflight': True, 'counts': counts,
            'ordinary_binary_sha256': {name: pin['sha256'] for name, pin in postflight['ordinary_programs'].items()},
            'feature_binary_sha256': {name: pin['sha256'] for name, pin in postflight['qualified_feature_programs_after'].items()},
            'compiler_source_files': 222, 'original_harness_files': 19,
            'ordinary_source_map_sha256': sha(data['ordinary-02/source-map.json']),
            'compressed_original_log_files': log_count,
            'original_postflight_native': {'job_id': post_terminal['job_id'],
                'streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in post_streams.items()}},
            'postflight_originals_matched_except_explicit_release_elves': True,
            'postflight_original_bindings_count': len(bindings),
            'postflight_bindings_selected_member_count': len(copied),
            'postflight_external_original_references': list(external.values()),
            'external_originals_rehashed_by_archive': False,
            'original_postflight_release_hashes_verified': True,
            'release_elf_bodies_read_by_archive': False,
            'test_binary_hashes_recomputed': False,
            'original_test_audit_binary_custody': True,
            'retained_test_elves_rehashed_by_postflight': False}


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'ordinary', 'this collector captures only the original ordinary02 supplement')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin
             for name, pin in PINNED.items()), 'frozen ordinary preparation or prior failure differs')
    for name, pin in actual['files'].items():
        need((name not in data) if pin is None else
             (name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin),
             'captured original presence/identity differs: ' + name)
    documents, parse_errors = {}, {}
    for name in CORE_PATHS:
        if name not in data:
            documents[name] = None
            continue
        try:
            value = json.loads(data[name])
            need(type(value) is dict, 'original JSON is not an object')
            documents[name] = value
        except (ValueError, TypeError, UnicodeError) as error:
            documents[name] = None
            parse_errors[name] = type(error).__name__ + ': ' + str(error)
    passed = actual['outcome'] == 'passed'
    terminal, streams = captured_native(data, 'ordinary-native-02.json', actual['native_read_paths'],
                                        actual['producer_original_job_id'], passed)
    prior = prior_failure_summary(data)
    if passed:
        need(not parse_errors, 'successful original validation has malformed core JSON')
        result = successful_summary(data, documents, streams)
    else:
        report = documents['ordinary-02/report.json'] or {}
        tests = documents['ordinary-02/isolated-tests/summary.json']
        audit = documents['ordinary-02/isolated-tests.audit.json'] or {}
        postflight = documents['ordinary-postflight-02.json'] or {}
        counts = None if tests is None else {key: tests.get(key) for key in COUNTS}
        need(counts == actual['counts'], 'captured partial test counts differ from actual raw pins')
        result = {'ordinary_passed_from_original_postflight': False, 'counts': counts,
            'ordinary_binary_sha256': None,
            'reported_qualified': report.get('qualified'), 'reported_error': report.get('error'),
            'reported_stages': [{'name': row.get('name'), 'returncode': row.get('returncode')}
                                for row in (report.get('stages') if type(report.get('stages')) is list else []) if type(row) is dict],
            'reported_test_success': None if tests is None else tests.get('success'),
            'reported_test_fatal_error': None if tests is None else tests.get('fatal_error'),
            'reported_audit_success': audit.get('success'), 'reported_audit_errors': audit.get('errors'),
            'reported_postflight_passed': postflight.get('passed'),
            'missing_core_receipts_at_capture': [name for name in CORE_PATHS if name not in data],
            'core_receipt_parse_errors': parse_errors,
            'compressed_case_logs_reconciled': False,
            'failure_scope': 'raw failed or incomplete result retained; no successful supplement inferred'}
        if actual['postflight_original_job_id'] is not None:
            post, poststreams = captured_native(data, 'ordinary-postflight-native-02.json',
                actual['postflight_native_read_paths'], actual['postflight_original_job_id'], False)
            result['original_postflight_native'] = {'job_id': post['job_id'],
                'state': post['state'], 'exit_code': post.get('exit_code'),
                'streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in poststreams.items()}}
    result.update(kind=kind, original_job_id=terminal['job_id'], outcome=actual['outcome'],
        native_state=terminal['state'], native_exit_code=terminal.get('exit_code'),
        native_flags={name: terminal.get(name) for name in
            ('output_complete', 'output_durable', 'terminal_publication_confirmed', 'automatic_retry',
             'timed_out', 'cancelled', 'log_synced', 'log_errors', 'log_truncated', 'log_bytes')},
        native_original_logs={name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in streams.items()},
        prior_preflight_failure=prior, external_evidence_references=EXTERNAL_EVIDENCE_REFERENCES,
        original_five_stages=STAGES, package_features=[], tests_reexecuted=False,
        original_auditor_reexecuted=False, verifier_api_reexecuted_by_archive=False,
        archived_programs_executed=False, performance_adoption_evaluated=False,
        same_source_program_identity_validated_from_original_receipts=passed)
    return result


def collect(root, kind):
    actual = require_sealed()
    need(kind == 'ordinary', 'this script archives only the captured original ordinary02 supplement')
    need(root.is_absolute() and root.resolve() == root, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    total = 0

    def file(path, required=False):
        nonlocal total
        relative = path.relative_to(root).as_posix()
        need(path.resolve(strict=True) == path, 'indirect source member: ' + relative)
        need(relative not in payloads, 'duplicate selected source member: ' + relative)
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
    for name, pin in actual['files'].items():
        if pin is None:
            need(not os.path.lexists(root / name), 'receipt declared absent now exists: ' + name)
        elif not name.startswith('ordinary-02/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'ordinary-02'):
        directory(root / 'ordinary-02')
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def create_archive(root, kind):
    require_sealed()
    need(kind == 'ordinary', 'this script archives only the captured original ordinary02 supplement')
    base = root / 'ordinary-evidence-02-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-d1-ordinary-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
                'tool_sha256': tool_sha256(),
                'source_reference_sha256': SOURCE_REFERENCE_SHA256, 'verify_reference_sha256': VERIFY_REFERENCE_SHA256,
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
            'ordinary_binary_sha256': compact['ordinary_binary_sha256'], 'outcome': compact['outcome']}

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
             'archive changed while read or exceeded 32 MiB')
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
                need(manifest['schema'] == 'hepta-d1-ordinary-evidence-archive/v1'
                     and manifest['kind'] == 'ordinary'
                     and manifest.get('tool_sha256') == tool_sha256(),
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
                need(total <= MAX_TOTAL, 'total tar payload exceeds 32 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data)
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
            'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
            'original_job_id': compact['original_job_id'], 'counts': compact['counts'],
            'ordinary_binary_sha256': compact['ordinary_binary_sha256'], 'outcome': compact['outcome'], 'files_extracted': 0}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('ordinary',))
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
    except (OSError, ValueError, KeyError, TypeError, AssertionError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
