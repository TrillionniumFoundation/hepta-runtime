#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R33 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r33')
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
SKIP_DIRS = {'target', 'target-build', 'test-binaries', '.git', '__pycache__', 'profile', '.ssh', 'credentials', 'secrets', 'keys'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa', 'agent.sock'}


REQUIRED = [
    "prepare_qualify.py",
    "input.json",
    "combined.patch",
    "chain-proof.json",
    "cache-owner-closure-inputs.json",
    "chain/r32/candidate.patch",
    "chain/r32/input.json",
    "chain/r32/manifest.json",
    "chain/r33/candidate.patch",
    "chain/r33/baseline-overlay.patch",
    "chain/r33/input.json",
    "chain/r33/manifest.json",
    "package-manifest.json",
    "preparation.json",
    "qualification-terminal-status-01.json",
    "qualification-native-read-01.json"
]
PINNED = {
    "prepare_qualify.py": {
        "bytes": 25125,
        "sha256": "c1e6ef1bf6d4a1c42a644a220ab00a5b14b95281e76e24f94526d367a07f351d"
    },
    "input.json": {
        "bytes": 52436,
        "sha256": "3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d"
    },
    "combined.patch": {
        "bytes": 11652,
        "sha256": "a6ec7d9f3f75647eed0d421ba69de20cb504cf369c2dde4752ca19f1004133f5"
    },
    "chain-proof.json": {
        "bytes": 2776,
        "sha256": "c93aa390e8f6f2d9d4175f4dd8ed1474a94e8f2d7466b1b19d3f9bc304810b32"
    },
    "cache-owner-closure-inputs.json": {
        "bytes": 3918,
        "sha256": "d10e468c67c21691fd6cb77d080aa589430c30c61accb12482004d4b10cf0353"
    },
    "chain/r32/candidate.patch": {
        "bytes": 2946,
        "sha256": "f009b618afb5dd574ef9d0b1bf2d73ecd108e2882779a05862ebafee9bc5019a"
    },
    "chain/r32/input.json": {
        "bytes": 49713,
        "sha256": "ed47cc74d4189fa0941192846f2ce4e8e2103954c4a3b4636fd1aab69a774a00"
    },
    "chain/r32/manifest.json": {
        "bytes": 4631,
        "sha256": "e1969d047545c70a857c733f3318b0c33140a3a8b6b0b85c2505f8457282985a"
    },
    "chain/r33/candidate.patch": {
        "bytes": 9507,
        "sha256": "05472a554635d415bbafd4b2119c09d88696e90f4e0003cf81cfa8da9271b4d0"
    },
    "chain/r33/baseline-overlay.patch": {
        "bytes": 2946,
        "sha256": "f009b618afb5dd574ef9d0b1bf2d73ecd108e2882779a05862ebafee9bc5019a"
    },
    "chain/r33/input.json": {
        "bytes": 50729,
        "sha256": "46ff8e0cc8327fa97e346acd8afa8c6ab7ef2ffc40e8d2b75d221d4101d9b1f5"
    },
    "chain/r33/manifest.json": {
        "bytes": 7100,
        "sha256": "4da10500f9108f484c4415ec726776685f61bfc73eccf7a12b23fed3f7ab53d5"
    },
    "package-manifest.json": {
        "bytes": 4127,
        "sha256": "aaabf3c54ec60e527688d2492c9d0ebe076d98b5e59911c72214c1b11319bbb6"
    },
    "preparation.json": {
        "bytes": 60636,
        "sha256": "63ead27e4e2414be4daa840a5d8f20ce3e7f0f034fd71d66e4ec8b4e9da8c39b"
    },
    "qualification-terminal-status-01.json": {
        "bytes": 731,
        "sha256": "d342cfc8c9976544f76e7f650ee8108d141a448bfbc7c47880d073e2987ad6f4"
    },
    "qualification-native-read-01.json": {
        "bytes": 4126,
        "sha256": "b4e8f4ae071388c0d6bc7089517024b64a6c08b331917b5ee44f34b7e1100a0e"
    },
    "qualification-01/report.json": {
        "bytes": 83360,
        "sha256": "00aed358a852cbdb9a54b9e97f6a63f66baf28b824dc4383ef900c8125d264a4"
    },
    "qualification-01/source-map.json": {
        "bytes": 24156,
        "sha256": "b3260c858e507f3661da233a9d05fec80399b48ba12fdce250ad29eeca0ba09e"
    },
    "qualification-01/isolated-tests/summary.json": {
        "bytes": 6878,
        "sha256": "352f613378c8e16a5ef23a658ff2692819eefd130ec1ebf079f6672a110ca096"
    },
    "qualification-01/isolated-tests.audit.json": {
        "bytes": 1423409,
        "sha256": "8704d8609754b10ce148e6e014dd99279b6bb95f88c4ff712191f69f9e58568e"
    }
}
QUALIFICATION_JOB = '1a1ae8ce865-fc05-603f'
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED_PATHS = {'src/mcp/runtime/ssh_observation_profile.rs',
                 'src/mcp/runtime/ssh_observation_profile_tests.rs'}
BINARY_NAMES = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SOURCE_REFERENCE_SHA256 = '237a05cebf47007a1f593bc415112474ec06cfd68997e1e2f6e75d795deb5a3f'
VERIFY_REFERENCE_SHA256 = 'f1b542cf0abfb7f761c1493bf65c95a446a9d37a8f3ead524a5cfbb470eb4dce'


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


def collect(root, kind):
    need(kind == 'qualification', 'this script archives only completed R33 qualification')
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
    directory(root / 'qualification-01')
    # Only paths in the actual tested manifest and original harness are selected;
    # no target/cache, whole old source tree, or arbitrary runtime config is walked.
    source_map = json.loads(payloads['qualification-01/source-map.json'])
    qualified = json.loads(payloads['qualification-01/report.json'])
    for name in sorted(source_map):
        safe = PurePosixPath(name)
        need(not safe.is_absolute() and '..' not in safe.parts and str(safe) == name
             and (name in {'Cargo.toml', 'Cargo.lock', 'rustfmt.toml'}
                  or name.startswith(('src/', 'examples/'))), 'unsafe compiler input path')
        file(root / 'source' / name, required=True)
    harness = root / 'source/tools/x230/20261028'
    need(harness.resolve(strict=True) == harness and harness.is_dir(), 'indirect harness directory')
    need({p.name for p in harness.glob('*.py')} == set(qualified['harness_after']),
         'qualified 19-file harness membership differs')
    for name in sorted(qualified['harness_after']):
        need(Path(name).name == name, 'unsafe harness input path')
        file(harness / name, required=True)
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
    need(kind == 'qualification', 'this script archives only completed R33 qualification')
    need(all(name in data for name in REQUIRED), 'missing original R33 preparation/qualification input')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == expected
             for name, expected in PINNED.items()), 'a frozen original R33 input or receipt differs')
    read = lambda name: json.loads(data[name])
    identity = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    prep, terminal = read('preparation.json'), read('qualification-terminal-status-01.json')
    native_read = read('qualification-native-read-01.json')
    qualified = read('qualification-01/report.json')
    tests, audit = read('qualification-01/isolated-tests/summary.json'), read('qualification-01/isolated-tests.audit.json')
    inputs, final_map = read('input.json'), read('qualification-01/source-map.json')
    native_terminal(terminal, QUALIFICATION_JOB, 'succeeded', 0)
    need(native_read.get('job_id') == QUALIFICATION_JOB and native_read.get('audit_recorded') is True,
         'original qualification native read identifies another job')
    native_logs = {}
    for name in ('stdout', 'stderr'):
        row = native_read[name]
        raw = bytes.fromhex(row['bytes_hex'])
        size = terminal['log_bytes'][name]['stored']
        need(row['offset'] == 0 and row['eof'] is True
             and row['next_offset'] == row['size'] == len(raw) == size,
             'original qualification native read is incomplete: ' + name)
        native_logs[name] = {'bytes': len(raw), 'sha256': sha(raw)}
    need(prep.get('schema') == 'hepta-x230-r33-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and prep.get('first_actual_r33_qualification_required') is True
         and prep.get('qualification_started') is True
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and prep.get('production_services_modified') is False
         and prep.get('source_baseline') == BASELINE_COMMIT
         and 'prior_preparation_failure' not in prep
         and prep['input_binding'] == identity('input.json')
         and prep['combined_patch'] == identity('combined.patch')
         and prep['qualification_report_sha256'] == sha(data['qualification-01/report.json']),
         'the actual first R33 preparation did not close successfully')
    need(qualified.get('schema') == 'hepta-x230-composed-qualification/v1'
         and qualified.get('qualified') is True and qualified.get('finished_utc') and 'error' not in qualified
         and qualified.get('source') == str(ROOT / 'source')
         and type(qualified.get('jobs')) is int and qualified['jobs'] == 2
         and type(qualified.get('automatic_test_retries')) is int and qualified['automatic_test_retries'] == 0
         and qualified.get('service_changes') is False
         and [row['name'] for row in qualified['stages']] == STAGES
         and all(type(row['returncode']) is int and row['returncode'] == 0 for row in qualified['stages']),
         'the actual first eight-stage qualification has not closed successfully')
    for row in qualified['stages']:
        name = row['name']
        stdout = 'cargo-no-run.jsonl' if name == 'test-build' else name + '.stdout'
        need(sha(data['qualification-01/' + stdout]) == row['stdout_sha256']
             and sha(data['qualification-01/' + name + '.stderr']) == row['stderr_sha256'],
             'original qualification stage log differs: ' + name)
    need(inputs['schema'] == 'hepta-r33-direct-qualification-input/v1'
         and inputs['baseline_commit'] == inputs['git_parent'] == BASELINE_COMMIT
         and inputs['patch_file'] == 'combined.patch'
         and inputs['patch_sha256'] == sha(data['combined.patch'])
         and inputs['added_paths'] == inputs['removed_paths'] == []
         and set(inputs['changed_paths']) == CHANGED_PATHS
         and all(inputs[key] is False for key in ('r31_pidfd_mixed_in', 'cancel_reserve_mixed_in',
                                                  'router_mixed_in', 'json_deferral_mixed_in')),
         'R33 qualification input differs from the accepted-R24 two-file candidate')
    need(prep['source_before_qualification'] == inputs['candidate_compile_inputs'] == qualified['source_input']
         and prep['source_after_qualification'] == qualified['source_tested'] == qualified['source_after'] == final_map
         and len(final_map) == 220 and set(final_map) == set(inputs['baseline_compile_inputs'])
         and {name for name in final_map if final_map[name] != inputs['baseline_compile_inputs'][name]} == CHANGED_PATHS,
         'actual qualification source maps do not agree')
    need(all(sha(data['source/' + name]) == digest for name, digest in final_map.items()),
         'archived compiler input differs from the final actually tested source')
    need(qualified['harness_before'] == qualified['harness_after'] == inputs['qualification_harness_sha256']
         == prep['qualification_harness_sha256'] and len(qualified['harness_after']) == 19
         and all(sha(data['source/tools/x230/20261028/' + name]) == digest
                 for name, digest in qualified['harness_after'].items()),
         'archived original qualification harness differs')
    need({name for name in data if name.startswith('source/')} ==
         {'source/' + name for name in final_map} |
         {'source/tools/x230/20261028/' + name for name in qualified['harness_after']},
         'unexpected or missing source/harness archive member')
    chain, closure = read('chain-proof.json'), read('cache-owner-closure-inputs.json')
    need(prep['source_chain_proof'] == identity('chain-proof.json')
         and inputs['source_chain_proof'] == {'path': 'chain-proof.json', 'bytes': len(data['chain-proof.json']),
                                              'sha256': sha(data['chain-proof.json'])}
         and chain['schema'] == 'hepta-r33-r24-combined-chain/v1'
         and chain['accepted_baseline_commit'] == BASELINE_COMMIT
         and chain['direct_patch_base_is_accepted_r24'] is True
         and chain['exact_original_patch_chain_matches_final_files'] is True
         and chain['exact_combined_patch_matches_final_files'] is True
         and set(chain['changed_paths']) == CHANGED_PATHS,
         'frozen R32/R33 chain does not bind the direct accepted-R24 candidate')
    for value in chain['originals'].values():
        name = value['path']
        need(name in REQUIRED and value['bytes'] == len(data[name]) and value['sha256'] == sha(data[name]),
             'original source-chain input differs: ' + name)
    need(prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and closure['schema'] == 'hepta-x230-r33-cache-owner-closure/v1'
         and closure['required_missing_bindings'] == []
         and closure['closure_is_not_performance_adoption'] is True
         and closure['r31_observation_performance_passed'] is False
         and closure['r31_lifecycle_abba_executed'] is False
         and closure['current_machine_idle_claimed'] is False
         and prep['cache_owner_closure']['inputs'] == closure['inputs']
         and prep['cache_owner_closure']['observation_performance_passed'] is False
         and prep['cache_owner_closure']['r31_adoption_claimed'] is False
         and prep['cache_owner_closure']['rejection_reasons'] == ['C1 regression gate']
         and prep['cache_owner_closure']['lifecycle_materializer_rejected_before_abba'] is True
         and prep['cache_transferred_by_rename'] is True
         and prep['cache_to_transfer'] == closure['cache_path']
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'old cache-owner closure or its rejected performance history differs')
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
    need(audit['auditor_sha256'] == qualified['harness_after']['audit_isolated_tests.py'],
         'original isolated-test audit identifies another auditor')
    # Reconcile compressed original bytes with the successful existing audit.
    # This does not decompress case logs, enumerate binaries or execute the auditor.
    commands = [json.loads(line) for line in data['qualification-01/isolated-tests/commands.jsonl'].splitlines()]
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
            need(sha(data['qualification-01/isolated-tests/' + name]) == proof[stream]['gzip_sha256'],
                 'original compressed log missing or changed: ' + name)
    archived_logs = {name.removeprefix('qualification-01/isolated-tests/')
                     for name in data if name.startswith('qualification-01/isolated-tests/') and name.endswith('.gz')}
    need(archived_logs == logs, 'compressed raw log archive is incomplete or has unbound extra members')
    need(set(qualified['binaries']) == BINARY_NAMES
         and all(row['path'] == str(ROOT / 'qualification-01' / name) for name, row in qualified['binaries'].items()),
         'qualification runtime-copy identities differ')
    binaries = {key: value['sha256'] for key, value in qualified['binaries'].items()}
    return {'kind': kind, 'qualified': True, 'original_job_id': terminal['job_id'], 'counts': counts,
            'preparation_attempts': [{'job_id': QUALIFICATION_JOB, 'state': 'succeeded', 'qualification_started': True}],
            'preparation_history': 'first R33 preparation and first actual eight-stage qualification',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'compiler_source_files': len(final_map), 'qualification_harness_files': len(qualified['harness_after']),
            'compressed_original_log_files': len(logs), 'native_original_logs': native_logs,
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'cache_owner_original_references': closure['inputs'], 'cache_owner_originals_copied': False,
            'r31_performance_adoption_claimed': False, 'tests_reexecuted': False,
            'original_test_audit_reexecuted': False, 'test_binary_hashes_recomputed': False,
            'performance_adoption_evaluated': False}


def create_archive(root, kind):
    need(kind == 'qualification', 'this script archives only completed R33 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r33-qualification-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
            'qualified_binary_sha256': compact['qualified_binary_sha256']}

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
                need(manifest['schema'] == 'hepta-r33-qualification-evidence-archive/v1'
                     and manifest['kind'] == 'qualification'
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
