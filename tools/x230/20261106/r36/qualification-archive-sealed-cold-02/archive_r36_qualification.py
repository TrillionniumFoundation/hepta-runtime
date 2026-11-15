#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R36 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02')
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




PINNED = {
  "archive-inputs-01/deployment.tar.gz": {
    "bytes": 301611,
    "sha256": "213203755b444fab504cd6da03b3b0f5ce9089c7b62bf3b8734695428b96899d"
  },
  "archive-inputs-01/install_qualification.py": {
    "bytes": 6877,
    "sha256": "9a6e88c70384b7b4677c5a641cc0deb9ff2b7ba6fcdc24157d2946126f57efa7"
  },
  "archive-inputs-01/installation-native-01.json": {
    "bytes": 729,
    "sha256": "2057c82f066c6fb70e1cf7e8aebdd2fe7da74f6b2f0721b1c1dcd42fea7ffaf8"
  },
  "archive-inputs-01/installation-read-01.json": {
    "bytes": 1097,
    "sha256": "5f9444aa8013268cb395a2a45a1da65c8b694bb38b245342d2dbc6a8a68c9c46"
  },
  "archive-inputs-01/installation-start-01.json": {
    "bytes": 1171,
    "sha256": "932ca3d75fc4f4d538aa26abca38ce856344ad9cef41d93025050d1ee83d2849"
  },
  "archive-inputs-01/launch-command.json": {
    "bytes": 638,
    "sha256": "f356fe9a4f459d04ce6206171e8b1115f33a5fe50c26a81772af6b8a0eaaba35"
  },
  "archive-inputs-01/qualification-start-01.json": {
    "bytes": 1344,
    "sha256": "cfb4565d0cbecbb0a3bbf9ae3e0c7a63df52c6b0248a61b1234c4e3a1b87780c"
  },
  "cache-owner-closure-inputs.json": {
    "bytes": 8522,
    "sha256": "9f4ad0dc2da45e10fad64da62beb92b5fbdc68b776d7ea15990f7690a18c6ddd"
  },
  "candidate/baseline-source-map.json": {
    "bytes": 24156,
    "sha256": "c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd"
  },
  "candidate/baseline/src/mcp/runtime/ssh_observation_profile.rs": {
    "bytes": 25093,
    "sha256": "a62169343c2a08c38d69925f33fdc7551cf4be7b4b7f50cf89683f652a8f853a"
  },
  "candidate/baseline/src/mcp/runtime/ssh_observation_reference_tests.rs": {
    "bytes": 14709,
    "sha256": "00f205e2e5f2359bc2f3272f01d84a0d0d8388645f35db006caefc40342f1524"
  },
  "candidate/candidate-source-map.json": {
    "bytes": 24156,
    "sha256": "08130cd38c2b679fd69257a794550826e323c915d321d7df9bf41d69fe2ad729"
  },
  "candidate/candidate.patch": {
    "bytes": 6384,
    "sha256": "fc0d76fda9d8fb921443f6031a80a1bff3dd765284fc54bd08055c613abb04d0"
  },
  "candidate/draft02-to-draft03.patch": {
    "bytes": 937,
    "sha256": "66c96ee765a23c5d7a926a0ca9c8fb73baaf088ced6d522a0638134e0ab685e0"
  },
  "candidate/input.json": {
    "bytes": 52381,
    "sha256": "02171769738c0d21c2b94c75bce1ecc8ef301b6c55b06087e57f8b02106d50b0"
  },
  "candidate/package-manifest.json": {
    "bytes": 2760,
    "sha256": "637d573634f63fdca168d1c73201466fe601f2158c54e0c5835f205be843c73f"
  },
  "candidate/README.md": {
    "bytes": 6651,
    "sha256": "8d5f61495e5afd321dc833c58de4dfd2862bf85934baeb8acde86be497584617"
  },
  "candidate/source/src/mcp/runtime/ssh_observation_profile.rs": {
    "bytes": 25779,
    "sha256": "eb7d677f2ca713d4719668202d7808925785f259aa15d6494ae8ec30fed17a3a"
  },
  "candidate/source/src/mcp/runtime/ssh_observation_reference_tests.rs": {
    "bytes": 17221,
    "sha256": "79d8d7e369e84bb853ab75930fc6a74a44bd519dc1be2f10bb7bba3b0b175dc0"
  },
  "candidate/static-review.json": {
    "bytes": 4146,
    "sha256": "08e8a344ccc5dfdbd4dafd999242b61c839b76fb8ee81a664b1c0ff3128c786c"
  },
  "installation-01.json": {
    "bytes": 4357,
    "sha256": "f4398b24ee9c3a3fa2de926f5cc4b8d3c4fe8532520019caa4719d12f7d139a2"
  },
  "owner-closure-provenance/c1-first-holder.json": {
    "bytes": 9210,
    "sha256": "5ee18bf08bcc19433cdd673ed3afeaebaddc52747fe8ed708840cd76a6ed7f41"
  },
  "owner-closure-provenance/c1-first-native.json": {
    "bytes": 726,
    "sha256": "c8a79f95770f04abd1c3f08314db63a0f5a874100321d81dcb2e8dc4e53e9f02"
  },
  "owner-closure-provenance/c1-first-read.json": {
    "bytes": 1207,
    "sha256": "e9204912a5b8b3373ad025dca5f45bb0e618109d4d093c9ae20d8573c1050701"
  },
  "owner-closure-provenance/c1-recovery-holder.json": {
    "bytes": 9074,
    "sha256": "81490b6b94eb8b1b71c852e08eab4148fe6c721f0ded6ebb52704de79a3150d1"
  },
  "owner-closure-provenance/c1-recovery-native.json": {
    "bytes": 729,
    "sha256": "53bb106afab53405bfd63a578af881f920182336e269e300ae354e6e776c1b90"
  },
  "owner-closure-provenance/c1-recovery-read.json": {
    "bytes": 1204,
    "sha256": "444ffa1fb0d2ac39c33a4166bdc72d3129a5f91e4e5c87bf86ea07878dd4f667"
  },
  "prepare_qualify.py": {
    "bytes": 40160,
    "sha256": "d0816b3c9522f74981141d03dc6745ac2c3923404d8af4e629fe2d37ae28eb79"
  },
  "qualification-input.json": {
    "bytes": 4250,
    "sha256": "a4c41f869095f5aeb32c7e26020bd36cf849048198b7f9cbf39ffc3bba24d305"
  },
  "qualification-package-manifest.json": {
    "bytes": 3701,
    "sha256": "c1f079f194243caa8dd34c37a8de100c7afc50815f9514a92ec7c75ae6e0962f"
  }
}
REQUIRED = tuple(sorted(PINNED))
FUTURE_PATHS = ('preparation.json', 'qualification-terminal-status-01.json',
    'qualification-native-read-01.json', 'qualification-01/report.json',
    'qualification-01/source-map.json', 'qualification-01/isolated-tests/summary.json',
    'qualification-01/isolated-tests.audit.json')
ACTUAL = {'counts': {'failed': 0,
            'ignored': 34,
            'passed': 1647,
            'retries': 0,
            'selected': 1681},
 'files': {'preparation.json': {'bytes': 68217,
                                'sha256': '20ae4a6b83454d2079e23f012c62fddcf88434cce488d0935576d5aa83309035'},
           'qualification-01/isolated-tests.audit.json': {'bytes': 1421791,
                                                          'sha256': '6c33faf1b73d34a1a5ac5bcc8e5570c8a409f3fc8adc106321196ea40c4570c7'},
           'qualification-01/isolated-tests/summary.json': {'bytes': 7046,
                                                            'sha256': '38571b98196196dc7c6af43c61e3cecbb823f22f098353e31e5ee107e4625b41'},
           'qualification-01/report.json': {'bytes': 83532,
                                            'sha256': 'd8af06696cbd7a1bbf0595bf628a18c112e82598cafb1b45b609a7955ced5e08'},
           'qualification-01/source-map.json': {'bytes': 24156,
                                                'sha256': 'b9eff66ea8b14eca80d16069a59588a551fcf6feff0ac4c991690425df65462a'},
           'qualification-native-read-01.json': {'bytes': 3860,
                                                 'sha256': '5e42c26ffc7c0f49e4f229def6d44a26ead695cfc757267f1fed1ddf1fb7f1ee'},
           'qualification-terminal-status-01.json': {'bytes': 731,
                                                     'sha256': 'd064a939e5707b9694a0853b87bd2fff92887966b1daea5b988fe8a5229fc1bb'}},
 'outcome': 'passed',
 'qualification_job_id': '1a1b1cb4862-fc05-7ad9',
 'qualified_binary_sha256': {'hepta-runtime': '0d108670136e41599329fdeb675bf11e5dcc4a8366f0bfb79c9a22af2662e0f3',
                             'hepta-runtime-jobctl': 'bc483761033b70d4704b2906490ffe16a28a77e0aff19d997cca73e9c678c542',
                             'native_process_driver': 'a7f53e4e1253e10a698f4a0cc5f75914990ee7e1765442cd5a5fe7e7f96bb8ff'},
 'schema': 'hepta-r36-qualification-archive-actual-pins/v1',
 'sealed': True}
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED_PATHS = {'src/mcp/runtime/ssh_observation_profile.rs', 'src/mcp/runtime/ssh_observation_reference_tests.rs'}
ADDED_PATHS = set()
BINARY_NAMES = {'hepta-runtime-jobctl', 'native_process_driver', 'hepta-runtime'}
SOURCE_REFERENCE_SHA256 = '3e150f1a3d9c1640a1c89932d2c9fc994e8b149113b524bbc8c86a3a52fd2ce4'
VERIFY_REFERENCE_SHA256 = SOURCE_REFERENCE_SHA256


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



def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r36-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original R36 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original R36 native job identity required')
    need(ACTUAL.get('outcome') in {'passed', 'failed'} and type(ACTUAL.get('files')) is dict
         and set(ACTUAL['files']) == set(FUTURE_PATHS), 'actual qualification outcome/file inventory is unbound')
    for name, pin in ACTUAL['files'].items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual receipt pin: ' + name)
    need(all(ACTUAL['files'][name] is not None for name in
         ('preparation.json', 'qualification-terminal-status-01.json', 'qualification-native-read-01.json')),
         'actual preparation and complete original native receipts required')
    if ACTUAL['outcome'] == 'passed':
        need(all(pin is not None for pin in ACTUAL['files'].values()), 'successful qualification is missing raw evidence')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == {'passed', 'failed', 'ignored', 'selected', 'retries'}
             and all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored'], 'actual full test counts required')
        binaries = ACTUAL.get('qualified_binary_sha256')
        need(type(binaries) is dict and set(binaries) == BINARY_NAMES
             and all(type(v) is str and len(v) == 64 and set(v) <= set('0123456789abcdef')
                     for v in binaries.values()), 'actual retained runtime identities required')
    return ACTUAL



def installation_summary(data):
    read = lambda name: json.loads(data[name])
    installed = read('installation-01.json')
    package_name = 'qualification-package-manifest.json'
    package = read(package_name)
    need(package['schema'] == 'hepta-r36-qualification-deployment-inputs/v1'
         and package['sealed'] is True and package['root'] == str(ROOT)
         and package['file_count'] == len(package['files']) == 21
         and package['future_r36_results_sealed'] is False,
         'R36 sealed installation package differs')
    members = dict(package['files'])
    need(package_name not in members, 'duplicate package member')
    need(sum(row['bytes'] for row in members.values()) == package['payload_bytes'], 'deployment payload size differs')
    members[package_name] = {'bytes': len(data[package_name]), 'sha256': sha(data[package_name])}
    need(installed['schema'] == 'hepta-r36-qualification-create-only-install/v1'
         and installed['root'] == str(ROOT) and installed['member_count'] == 22
         and installed['members'] == members and installed['manifest'] == members[package_name]
         and all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == row
                 for name, row in members.items()), 'installed original membership differs')
    need(installed['source_package_unchanged'] is True and installed['cache_moved_or_deleted'] is False
         and installed['qualifier_or_compiler_started'] is False and installed['automatic_retries'] == 0
         and installed['original_archive_preserved'] is True, 'installation outcome differs')
    archive_name = 'archive-inputs-01/deployment.tar.gz'
    need(installed['archive'] == {
        'path': '/home/qian/r36-validation-scratch-cold02-qualification-deployment-01.tar.gz',
        'bytes': len(data[archive_name]), 'sha256': sha(data[archive_name])}, 'staged archive differs')
    job = '1a1b1caaabc-fc05-7ad2'
    terminal = read('archive-inputs-01/installation-native-01.json')
    native_terminal(terminal, job, 'succeeded', 0)
    streams = original_streams(read('archive-inputs-01/installation-read-01.json'), terminal)
    need(streams['stderr'] == b'' and json.loads(streams['stdout']) == {
        'installation_receipt': {'bytes': len(data['installation-01.json']), 'sha256': sha(data['installation-01.json'])},
        'installed': str(ROOT), 'member_count': 22, 'qualification_started': False}, 'actual installation output differs')
    start = read('archive-inputs-01/installation-start-01.json')
    need(start['audit_recorded'] is True and start['job']['id'] == job and start['job']['host'] == 'x230'
         and start['job']['executable'] == '/usr/bin/python3' and start['job']['env_keys'] == []
         and start['job']['launch_state'] == 'launched' and start['launch']['ok'] is True
         and start['reused'] is False and start['job']['args'] == ['-B',
             '/home/qian/install-r36-validation-scratch-cold02-qualification-01.py', '--archive', installed['archive']['path']],
         'actual original installer launch differs')
    qstart = read('archive-inputs-01/qualification-start-01.json')
    launch = read('archive-inputs-01/launch-command.json')
    need(launch['host'] == 'x230' and launch['cwd'] == str(ROOT) and launch['submitted'] is False
         and launch['automatic_retry'] is False and launch['env'] == {}, 'frozen launch command differs')
    need(qstart['audit_recorded'] is True and qstart['job']['id'] == ACTUAL['qualification_job_id']
         and qstart['job']['host'] == 'x230' and qstart['job']['env_keys'] == []
         and qstart['job']['cwd'] == str(ROOT) and qstart['job']['launch_state'] == 'launched'
         and qstart['launch']['ok'] is True and qstart['reused'] is False
         and [qstart['job']['executable'], *qstart['job']['args']] == [launch['executable'], *launch['args']],
         'actual original qualification launch differs')
    return {'installation_job_id': job, 'installation_succeeded': True, 'original_installed_members': 22,
        'source_package_files': 12, 'installer_did_not_start_qualification': True,
        'original_qualification_job_id': ACTUAL['qualification_job_id'],
        'diagnostic_environment_absent_at_native_launch': True,
        'originals_reencoded': False, 'installation_reexecuted': False}


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original R36 qualification may be archived')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin
             for name, pin in PINNED.items()), 'frozen preparation/installation input differs')
    for name, pin in actual['files'].items():
        need((name not in data) if pin is None else
             (name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin),
             'actual original qualification receipt presence/identity differs: ' + name)
    terminal = json.loads(data['qualification-terminal-status-01.json'])
    if actual['outcome'] == 'passed':
        native_terminal(terminal, actual['qualification_job_id'], 'succeeded', 0)
    else:
        need(terminal.get('state') == 'failed' and type(terminal.get('exit_code')) is int
             and terminal['exit_code'] != 0, 'failed archive requires the original failed terminal')
        native_terminal(terminal, actual['qualification_job_id'], 'failed', terminal['exit_code'])
    native = original_streams(json.loads(data['qualification-native-read-01.json']), terminal)
    installation = installation_summary(data)
    if actual['outcome'] == 'passed':
        result = qualified_summary(kind, data)
        need(result['counts'] == actual['counts'] and result['qualified_binary_sha256'] == actual['qualified_binary_sha256'],
             'actual frozen full inventory or runtime digest differs')
    else:
        prep = json.loads(data['preparation.json'])
        report = json.loads(data['qualification-01/report.json']) if 'qualification-01/report.json' in data else None
        tests = json.loads(data['qualification-01/isolated-tests/summary.json']) if 'qualification-01/isolated-tests/summary.json' in data else None
        audit = json.loads(data['qualification-01/isolated-tests.audit.json']) if 'qualification-01/isolated-tests.audit.json' in data else None
        counts = None if tests is None else {key: tests.get(key) for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
        binaries = None if report is None else {key: value.get('sha256') for key, value in report.get('binaries', {}).items()}
        need(counts == actual['counts'] and binaries == actual['qualified_binary_sha256'], 'raw failed inventory differs from its actual pins')
        result = {'kind': kind, 'qualified': False, 'original_job_id': terminal['job_id'],
            'outcome': 'failed', 'counts': counts, 'qualified_binary_sha256': binaries,
            'reported_preparation_passed': prep.get('passed'), 'preparation_error': prep.get('error'),
            'reported_qualified': None if report is None else report.get('qualified'),
            'qualification_error': None if report is None else report.get('error'),
            'reported_stage_results': [] if report is None else [
                {'name': row.get('name'), 'returncode': row.get('returncode')} for row in report.get('stages', [])],
            'reported_test_success': None if tests is None else tests.get('success'),
            'reported_test_fatal_error': None if tests is None else tests.get('fatal_error'),
            'reported_audit_success': None if audit is None else audit.get('success'),
            'reported_audit_errors': None if audit is None else audit.get('errors'),
            'missing_later_receipts': [name for name, pin in actual['files'].items() if pin is None],
            'failure_scope': 'exact raw first-attempt receipts preserved; no qualification or audit success inferred',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'tests_reexecuted': False, 'original_test_audit_reexecuted': False,
            'test_binary_hashes_recomputed': False, 'performance_adoption_evaluated': False}
    result['original_qualification_or_measurement_retried'] = False
    result['installation_preparation'] = installation
    result['native_original_logs'] = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in native.items()}
    return result



def collect(root, kind):
    actual = require_sealed()
    need(kind == 'qualification', 'this script archives only completed R36 qualification')
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
        elif not name.startswith('qualification-01/'):
            file(root / name, required=True)
    if os.path.lexists(root / 'qualification-01'):
        directory(root / 'qualification-01')
    # A successful full qualification selects exactly its final compiler map
    # and original harness. An early failed attempt may have no final map.
    if actual['files']['qualification-01/source-map.json'] is not None:
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
        expected_harness = qualified.get('harness_after') or qualified['harness_before']
        need({p.name for p in harness.glob('*.py')} == set(expected_harness), 'qualified harness membership differs')
        for name in sorted(expected_harness):
            need(Path(name).name == name, 'unsafe harness input path')
            file(harness / name, required=True)
    optional = ['qualification-compact-01.json']
    for name in optional:
        if os.path.lexists(root / name):
            file(root / name, required=True)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded



def qualified_summary(kind, data):
    need(kind == 'qualification', 'this script archives only completed R36 qualification')
    need(all(name in data for name in REQUIRED), 'missing original R36 preparation/qualification input')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == expected
             for name, expected in PINNED.items()), 'a frozen original R36 input or receipt differs')
    read = lambda name: json.loads(data[name])
    identity = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    prep, terminal = read('preparation.json'), read('qualification-terminal-status-01.json')
    native_read = read('qualification-native-read-01.json')
    qualified = read('qualification-01/report.json')
    tests, audit = read('qualification-01/isolated-tests/summary.json'), read('qualification-01/isolated-tests.audit.json')
    inputs, final_map = read('qualification-input.json'), read('qualification-01/source-map.json')
    candidate = read('candidate/input.json')
    native_terminal(terminal, ACTUAL['qualification_job_id'], 'succeeded', 0)
    need(native_read.get('job_id') == ACTUAL['qualification_job_id'] and native_read.get('audit_recorded') is True,
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
    need(prep.get('schema') == 'hepta-x230-r36-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and prep.get('first_actual_r36_qualification_required') is True
         and prep.get('qualification_started') is True
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and prep.get('production_services_modified') is False
         and prep.get('source_baseline') == BASELINE_COMMIT
         and 'prior_preparation_failure' not in prep
         and prep['input_binding'] == identity('qualification-input.json')
         and prep['candidate_patch'] == {**identity('candidate/candidate.patch'), 'git_blob': hashlib.sha1(b'blob ' + str(len(data['candidate/candidate.patch'])).encode('ascii') + bytes([0]) + data['candidate/candidate.patch']).hexdigest()}
         and prep['qualification_report_sha256'] == sha(data['qualification-01/report.json']),
         'the actual first R36 preparation did not close successfully')
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
    need(inputs['schema'] == 'hepta-r36-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['git_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-x230-r36-candidate-draft/v1'
         and candidate['revision'] == 'lazy-scratch-draft-03'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['patch_sha256'] == candidate['patch']['sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['patch']['bytes'] == len(data['candidate/candidate.patch'])
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and candidate['added_paths'] == candidate['removed_paths'] == []
         and set(candidate['new_test_functions']) == {
             'shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths',
             'shared_verification_buffer_keeps_mismatch_cancellation_precedence'}
         and all(candidate[name] is None for name in ('qualification', 'exact_ci', 'performance'))
         and candidate['adopted'] is False,
         'R36 input differs from its frozen R24 plus two-file scratch candidate')
    need(all(inputs[name] is None for name in ('actual_r36_qualification', 'actual_r36_formatted_map',
             'actual_r36_test_counts', 'actual_r36_release_programs')),
         'pre-execution inputs were overwritten with future results')
    need(prep['source_before_qualification'] == candidate['candidate_compile_inputs'] == qualified['source_input']
         and prep['source_after_qualification'] == qualified['source_tested'] == qualified['source_after'] == final_map
         and len(final_map) == 220 and len(candidate['baseline_compile_inputs']) == 220
         and set(final_map) == set(candidate['candidate_compile_inputs'])
         and set(final_map) - set(candidate['baseline_compile_inputs']) == ADDED_PATHS
         and not set(candidate['baseline_compile_inputs']) - set(final_map)
         and {name for name in final_map if final_map[name] != candidate['baseline_compile_inputs'].get(name)} == CHANGED_PATHS,
         'R36 final actual source maps do not agree')
    need(all(sha(data['source/' + name]) == digest for name, digest in final_map.items()),
         'archived compiler input differs from final tested source')
    need(qualified['harness_before'] == qualified['harness_after'] == inputs['qualification_harness_sha256']
         == prep['qualification_harness_sha256'] and len(qualified['harness_after']) == 19
         and all(sha(data['source/tools/x230/20261028/' + name]) == digest
                 for name, digest in qualified['harness_after'].items()),
         'original qualification harness differs')
    need({name for name in data if name.startswith('source/')} ==
         {'source/' + name for name in final_map} |
         {'source/tools/x230/20261028/' + name for name in qualified['harness_after']},
         'unexpected or missing compiler/harness member')
    frozen, closure = read('candidate/package-manifest.json'), read('cache-owner-closure-inputs.json')
    need(frozen['schema'] == 'hepta-r36-source-draft-package/v1'
         and frozen['baseline_commit'] == BASELINE_COMMIT
         and frozen['revision'] == 'lazy-scratch-draft-03'
         and len(frozen['files']) == 11 and frozen['actual_results'] is None,
         'R36 frozen candidate package differs')
    for relative, pin in frozen['files'].items():
        name = 'candidate/' + relative
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name])
             and pin['git_blob'] == hashlib.sha1(b'blob ' + str(len(data[name])).encode('ascii') + bytes([0]) + data[name]).hexdigest(),
             'frozen candidate original differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/package-manifest.json'} | {'candidate/' + name for name in frozen['files']},
         'candidate package inventory differs')
    for name, field in (('candidate/input.json', 'candidate_input'), ('candidate/package-manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'accepted R24 source copy plus the frozen R36 patch; new empty Cargo target; no D2 cache reuse'
         and prep['build_mode'] == 'cold-only' and prep['preparation_attempt'] == 'cold-02'
         and prep['previous_preparation_root'] == '/home/qian/hepta-runtime-validation-scratch-20261106-r36'
         and prep['previous_preparation_job_id'] == '1a1b1bedd38-fc05-7a99'
         and prep['new_empty_target_created'] is True
         and prep['cache_reused'] is False and prep['cache_transferred_by_rename'] is False
         and prep['ownership_transfer_applicable'] is False and prep['cache_to_transfer'] is None
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-r36-d2-cache-owner-closure/v1'
         and closure['sealed'] is True and closure['required_missing_bindings'] == []
         and closure['build_mode'] == 'cold-only' and closure['cache_path'] is None
         and closure['cold_target_path'] == str(ROOT / 'target-build')
         and closure['cache_reused'] is False and closure['ownership_transfer_applicable'] is False
         and closure['historical_auditors_to_execute'] == 0 and closure['candidate_adopted'] is False
         and closure['qualification_or_measurement_still_running'] is False
         and len(closure['inputs']) == 28
         and prep['cache_owner_closure']['closed'] is True
         and prep['cache_owner_closure']['historical_owner_evidence_only'] is True
         and prep['cache_owner_closure']['cache_reused'] is False
         and prep['cache_owner_closure']['cache_transferred_by_rename'] is False
         and prep['cache_owner_closure']['ownership_transfer_applicable'] is False
         and prep['cache_owner_closure']['original_inputs'] == closure['inputs'],
         'cold-only preparation or historical D2 owner receipt binding differs')
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
            'preparation_attempts': [{'job_id': ACTUAL['qualification_job_id'], 'state': 'succeeded', 'qualification_started': True}],
            'preparation_history': 'first actual cold02 eight-stage qualification after a distinct pre-qualifier wrapper failure',
            'previous_preparation_job_id': prep['previous_preparation_job_id'],
            'build_mode': 'cold-only', 'cache_reused': False, 'ownership_transfer_applicable': False,
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'compiler_source_files': len(final_map), 'qualification_harness_files': len(qualified['harness_after']),
            'compressed_original_log_files': len(logs), 'native_original_logs': native_logs,
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'cache_owner_original_references': closure['inputs'], 'cache_owner_originals_copied': False,
            'historical_d2_first_c1_workflow_passed': False,
            'historical_d2_recovery_diagnostic_evidence_passed': closure['c1_recovery_diagnostic_evidence_passed'],
            'tests_reexecuted': False,
            'original_test_audit_reexecuted': False, 'test_binary_hashes_recomputed': False,
            'performance_adoption_evaluated': False}



def create_archive(root, kind):
    require_sealed()
    need(kind == 'qualification', 'this script archives only completed R36 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r36-qualification-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
                need(manifest['schema'] == 'hepta-r36-qualification-evidence-archive/v1'
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
