#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R34 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r34')
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


PINNED = {'cache-owner-closure-inputs.json': {'bytes': 4503,
                                     'sha256': '94b2649e0a8b66711b122638432848a41af37f06a10973f81e7be21d5705ebb9'},
 'cache-prune-01/cache-after.json': {'bytes': 1645029,
                                     'sha256': '9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154'},
 'cache-prune-01/cache-before.json': {'bytes': 1645029,
                                      'sha256': '9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154'},
 'cache-prune-01/claim.json': {'bytes': 865,
                               'sha256': '0f4f93d03cad176c8574e2f342fb914a98ab46329783f46f20e2f268a67a2a55'},
 'cache-prune-01/owner-after.json': {'bytes': 5710,
                                     'sha256': '6d994f917481efc3e7cbae0fed2c57ab85492b4d0fd9b47660939a846dd32866'},
 'cache-prune-01/owner-before.json': {'bytes': 5710,
                                      'sha256': '6d994f917481efc3e7cbae0fed2c57ab85492b4d0fd9b47660939a846dd32866'},
 'cache-prune-01/report.json': {'bytes': 2200,
                                'sha256': '30d5097ccf5ca12e118cd1272f80983b7e829f6659b208e1302a24698aa1459e'},
 'cache-prune-02/cache-after.json': {'bytes': 1644529,
                                     'sha256': 'a06c8d2ddb29ce56278bafde8163a1c9b49df289c42b32fb7b21831c0e6c305b'},
 'cache-prune-02/cache-before.json': {'bytes': 1645029,
                                      'sha256': '9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154'},
 'cache-prune-02/candidates-before.json': {'bytes': 1182,
                                           'sha256': '1c0146fd68d6d9afab85d7e16b7895c58ef148dc61ff089e42616da2c3efd79f'},
 'cache-prune-02/claim.json': {'bytes': 865,
                               'sha256': '30a6822f30dcfbf2e2d8f4f5910306fef20618f0938bd64460bf4ea9e451aebe'},
 'cache-prune-02/delete-01-intent.json': {'bytes': 793,
                                          'sha256': 'b9d8067dd61a1075b4a87fe47c5903dd6a1f776bfa42f15c03d8538d9e298966'},
 'cache-prune-02/delete-01-result.json': {'bytes': 453,
                                          'sha256': 'e4bc8a5b54f19da448564f7f22f55eb8330dca018312138f96780be36ed963e6'},
 'cache-prune-02/delete-02-intent.json': {'bytes': 387,
                                          'sha256': '9561941a92b5572fd835c9828ff107a60b2e873bd7bc95ce193d1fbd84fe3a57'},
 'cache-prune-02/delete-02-result.json': {'bytes': 461,
                                          'sha256': '016b3d754c6b1b7757b4704eb141d933f8b0fcfa51e25d3284ee16b552679c7e'},
 'cache-prune-02/deletion-intent.json': {'bytes': 2911,
                                         'sha256': '3be88e7a14614ff3fb4fa7124407adeb0c6b7152834b69f37b2487b6d50d9bc3'},
 'cache-prune-02/owner-after.json': {'bytes': 5710,
                                     'sha256': '6d994f917481efc3e7cbae0fed2c57ab85492b4d0fd9b47660939a846dd32866'},
 'cache-prune-02/owner-before.json': {'bytes': 5710,
                                      'sha256': '6d994f917481efc3e7cbae0fed2c57ab85492b4d0fd9b47660939a846dd32866'},
 'cache-prune-02/report.json': {'bytes': 4426,
                                'sha256': '51fae444ad2ec1a11ba371a26f5e4ed5d12df3e2d2ca36187a9f60159b1b9b87'},
 'cache-prune-native-02.json': {'bytes': 729,
                                'sha256': '4dd1b42a247454f6e132c4fae19ae386288d51a93c05d455a3c7668be71c1a79'},
 'cache-prune-native-read-02.json': {'bytes': 1422,
                                     'sha256': '5d0001290839aa68e0ef307ae0d2bc22f60898f9d40e8b6885b3a37538e27539'},
 'cache-prune-tools-01/plan.json': {'bytes': 3244,
                                    'sha256': '0e372a560b119422d41ae29c5b0d2d8c4103cbd95b7f16f3dfe75b1c47d2d256'},
 'cache-prune-tools-01/prune_cache.py': {'bytes': 20249,
                                         'sha256': '96f60f4f1b048c080b36c0bc7e8103af918de6ccf0e096972ea96073e8fd397b'},
 'cache-prune-tools-02/originals/cache-file-inventory-original-01.json': {'bytes': 69145,
                                                                          'sha256': '75d0abe906ba10caf3d73f4c9e896bc6f41ebc538ecd1fb37a854d096755c936'},
 'cache-prune-tools-02/originals/native-read-original-01.json': {'bytes': 1628,
                                                                 'sha256': '7afa521730f4cfdaeea8e6690cdab514da673aa7325708381755843d3328afb4'},
 'cache-prune-tools-02/originals/native-terminal-original-01.json': {'bytes': 726,
                                                                     'sha256': '1f49fa913a28d26b2488fa5deff9cf480f463765f726f2e21c1955668347d15b'},
 'cache-prune-tools-02/originals/precision-crosscheck-original-01.json': {'bytes': 837,
                                                                          'sha256': '1f6d835830e9803b41a887ea1eb2b56f4242145ba5cd0beda5764bfb0f5e412c'},
 'cache-prune-tools-02/originals/precision-native-read-original-01.json': {'bytes': 2937,
                                                                           'sha256': '457d31c333371fa68d96f035c5c775ab346e930625244aeccc015f9b724db508'},
 'cache-prune-tools-02/originals/precision-native-terminal-original-01.json': {'bytes': 729,
                                                                               'sha256': '1a0f5b020c2e61220b768efaf27edee7f2846d15ac71dab8ab0597200872c482'},
 'cache-prune-tools-02/originals/report-original-01.json': {'bytes': 2200,
                                                            'sha256': '30d5097ccf5ca12e118cd1272f80983b7e829f6659b208e1302a24698aa1459e'},
 'cache-prune-tools-02/plan.json': {'bytes': 7307,
                                    'sha256': '1179668edde634ffba8307ca35c129652d9df15c0743c76b5bdc4e6fe8f7d62b'},
 'cache-prune-tools-02/prune_cache.py': {'bytes': 20299,
                                         'sha256': 'fe09125bd509a73b67b5380857f5ff61a5c69a89d592afcfa1172121418588f5'},
 'candidate/README.md': {'bytes': 14206,
                         'sha256': '66a58e649c513a28c5dd96e791fe8dd0fbf4809d2b334f736fce428e2f7030db'},
 'candidate/baseline-compile-inputs.json': {'bytes': 24156,
                                            'sha256': 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'},
 'candidate/baseline/Cargo.lock': {'bytes': 69305,
                                   'sha256': '15b9fb468eb34a210238657d132cbf19e961552d1313de488e1f14936bfa4e5f'},
 'candidate/baseline/Cargo.toml': {'bytes': 3097,
                                   'sha256': '3121870fbf66f65ce6b1925b3500eae8a05fc2d8019a2694da7d6fe941ad4d28'},
 'candidate/baseline/rustfmt.toml': {'bytes': 17,
                                     'sha256': 'bce79651b2e2ff42e1c54b9a26c5e17af5222f9f65ab51d9563a48fd159dae84'},
 'candidate/baseline/src/mcp/runtime/jobs.rs': {'bytes': 186456,
                                                'sha256': 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'},
 'candidate/baseline/src/mcp/runtime/jobs_tests.rs': {'bytes': 107312,
                                                      'sha256': '32009d5f85267026cc56e67d888ccd10e5043b8865904fade3578214340348f5'},
 'candidate/baseline/src/mcp/runtime/ssh.rs': {'bytes': 16929,
                                               'sha256': '4db25902c01d1a501f699ca26c9a70af49860127c625a9e0ff402572ad3e9829'},
 'candidate/baseline/src/mcp/runtime/ssh_direct.rs': {'bytes': 19964,
                                                      'sha256': '9adc4ea54b1a53b301439135f6c9ac506fa75064759ce29552a6cee57a0ab083'},
 'candidate/baseline/src/mcp/runtime/ssh_direct_tests.rs': {'bytes': 32273,
                                                            'sha256': '3dbbf3726c053d300b1fbce2ed525adf38e50927cbca7c407c1be58029b2179a'},
 'candidate/baseline/src/mcp/runtime/ssh_tests.rs': {'bytes': 4652,
                                                     'sha256': '39dacf3f7839b7a013b24b2ec63bd9cf7b51599ebaebc1e5e074cfb98ae79893'},
 'candidate/candidate-compile-inputs.json': {'bytes': 24156,
                                             'sha256': 'cfbf64a87c37ce988321432f31f12f58e98abf0b2a301ca36a21ecb459573b80'},
 'candidate/candidate.patch': {'bytes': 22870,
                               'sha256': '1a73c219fcfd2a273354bcbe0e1eb3f2ba629b1eb9f4969591352c6dd1a4ffc0'},
 'candidate/input.json': {'bytes': 53074,
                          'sha256': '7336fe6abeca46e5f8ebc05e8a75e292a507aad1575565331a850e7cbb8f9c70'},
 'candidate/manifest.json': {'bytes': 3999,
                             'sha256': '22c24ee1f14d1c267d2b88d14919b2fd6c35035af342f56a4c486ce776b1f90c'},
 'candidate/reference-r33-input.json': {'bytes': 52436,
                                        'sha256': '3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d'},
 'candidate/source/src/mcp/runtime/jobs.rs': {'bytes': 186466,
                                              'sha256': 'e6d9de7aed9ab92b9a57544546651a707449577e56ba1fbcd3233e2d9407fec5'},
 'candidate/source/src/mcp/runtime/ssh.rs': {'bytes': 18745,
                                             'sha256': 'cbb064cc63ec8d5217df4c240b255a49348054215411ee1a8bc39ac2886b1ad2'},
 'candidate/source/src/mcp/runtime/ssh_direct.rs': {'bytes': 23273,
                                                    'sha256': '5847841046a14dda46c2c18015ca82c385d76f0154e8fa5cce811b8f3fd07496'},
 'candidate/source/src/mcp/runtime/ssh_direct_tests.rs': {'bytes': 44681,
                                                          'sha256': 'ca1e96978f0b68e1e5a17427f62d01203e219d938fc4f1be3990225f551de9c5'},
 'candidate/static-checks.json': {'bytes': 4954,
                                  'sha256': 'da224c06dc5064c44a58bdd8e6ac57bea89a35bf180fc72ba872795305c9da2a'},
 'candidate/verify_candidate.py': {'bytes': 11763,
                                   'sha256': '461dba0637c31b57a868cb14dfd818f522bd35f1c97047c3bdb454e3544b5c6d'},
 'frozen-preparation-manifest.json': {'bytes': 5848,
                                      'sha256': '99e5a9e4826fa9175541174695e0cdaa89210f107ee53d2fcd303ba702c0a4ac'},
 'owner-closure-provenance/observation-postflight-01.json': {'bytes': 4873,
                                                             'sha256': '975c0a362e8faecf24eb6fdaa9a6ee57557a2776b94e7d54dc814d8b8104861f'},
 'preparation-tools/reference/prepare_r33_qualify.py': {'bytes': 25125,
                                                        'sha256': 'c1e6ef1bf6d4a1c42a644a220ab00a5b14b95281e76e24f94526d367a07f351d'},
 'preparation-tools/seal_preparation.py': {'bytes': 22335,
                                           'sha256': '96407a35679dbd352ba35b3a93a6494432c765290bfb9ad418ee01ef7dd20cda'},
 'prepare_qualify.py': {'bytes': 29912,
                        'sha256': '6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f'},
 'qualification-input.json': {'bytes': 3707,
                              'sha256': '7065ad29178dbec61a1ed78fa24c9697cd6b6d3fed1ca9d5bb6cb7335b097e1e'},
 'qualification-preparation-seal.json': {'bytes': 4275,
                                         'sha256': '7c919f2a9ab414c0291bf47a6ec869d08d9d0b0d490574a235cead9621ab3076'}}
REQUIRED = sorted(PINNED)
FUTURE_PATHS = ('preparation.json',
 'qualification-terminal-status-01.json',
 'qualification-native-read-01.json',
 'qualification-01/report.json',
 'qualification-01/source-map.json',
 'qualification-01/isolated-tests/summary.json',
 'qualification-01/isolated-tests.audit.json')
ACTUAL = None
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED_PATHS = {'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/ssh.rs',
                 'src/mcp/runtime/ssh_direct.rs', 'src/mcp/runtime/ssh_direct_tests.rs'}
BINARY_NAMES = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SOURCE_REFERENCE_SHA256 = '3b150b9cc56bcad3cb170d1612b2cf2c0a5b0b36e875a5b7430607709a5f7954'
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
# Pure receipt binding functions embedded in the generated collector; not executed by the builder.


def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r34-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original R34 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original R34 native job identity required')
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


def cache_preparation_summary(data):
    read = lambda name: json.loads(data[name])
    identity = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    originals = 'cache-prune-tools-02/originals/'
    one = read('cache-prune-01/report.json')
    two = read('cache-prune-02/report.json')
    first_native = read(originals + 'native-terminal-original-01.json')
    second_native = read('cache-prune-native-02.json')
    native_terminal(first_native, '1a1aeeea99f-fc05-6440', 'failed', 1)
    native_terminal(second_native, '1a1aef5957d-fc05-6486', 'succeeded', 0)
    first_streams = original_streams(read(originals + 'native-read-original-01.json'), first_native)
    second_streams = original_streams(read('cache-prune-native-read-02.json'), second_native)
    need(first_streams['stderr'] == second_streams['stderr'] == b'', 'unexpected original prune stderr')
    need(data[originals + 'report-original-01.json'] == data['cache-prune-01/report.json'],
         'failed prune original copy differs')
    for number, value in (('01', one), ('02', two)):
        need(value['schema'] == 'hepta-r34-two-file-cache-prune/v1'
             and value['automatic_retries'] == value['subprocesses_started'] == value['directories_deleted'] == 0
             and value['cache_renamed'] is False and value['source_or_threshold_modified'] is False
             and value['minimum_free_bytes'] == 3 * 1024 ** 3 and value['postcheck_errors'] == []
             and value['independent_retained_programs_unchanged'] is True
             and value['unselected_cache_entries_unchanged'] is True,
             'original cache preparation invariants differ: ' + number)
        need(value['tool'] == identity('cache-prune-tools-' + number + '/prune_cache.py')
             and value['plan'] == identity('cache-prune-tools-' + number + '/plan.json')
             and value['helper_launcher'] == identity('prepare_qualify.py'), 'original prune tool/plan/helper differs')
        for pin in value['receipts'].values():
            relative = Path(pin['path']).relative_to(ROOT).as_posix()
            need(relative.startswith('cache-prune-' + number + '/') and pin == identity(relative),
                 'original prune receipt bytes differ: ' + relative)
    need(one['passed'] is False and one['deletions'] == []
         and one['error'] == 'RuntimeError: candidate fixed stat differs: hepta_runtime-1b8b761b89392e3b',
         'original zero-deletion failure was changed or omitted')
    need(two['passed'] is True and 'error' not in two and two['two_requested_files_unlinked'] is True
         and two['free_space_gate_met'] is True and two['free_bytes_after'] == 3566792704,
         'original second prune successful result differs')
    expected_paths = ['debug/deps/hepta_runtime-1b8b761b89392e3b',
                      'debug/deps/libhepta_runtime-564505b54e9d81cd.rlib']
    need([row['path'] for row in two['deletions']] == expected_paths
         and two['observed_absent_allowed_candidates'] == expected_paths
         and all(all(row[k] is True for k in ('unlinked', 'path_absent', 'opened_inode_unlinked', 'parent_synced'))
                 for row in two['deletions']), 'second prune did not record exactly the two intended deletions')
    need(two['deletions'][0]['sha256'] == 'e2096aa99096233152ffbd11fd1d42aa145cbfa1ef9f4fa81b8191e9055ad3b1',
         'original test artifact digest differs from the retained-audit provenance')
    for raw, value, number in ((first_streams['stdout'], one, '01'), (second_streams['stdout'], two, '02')):
        output = json.loads(raw)
        need(output['passed'] == value['passed'] and output['deleted'] == len(value['deletions'])
             and output['report'] == identity('cache-prune-' + number + '/report.json'),
             'original native prune stdout does not bind the report')
    need(sha(data['cache-prune-01/cache-before.json']) == sha(data['cache-prune-01/cache-after.json'])
         == sha(data['cache-prune-02/cache-before.json'])
         == '9fa4908281b0dcc03921272a7e63a0871f831c6daf3e0edb2377c07488255154',
         'failed prune was not a zero-change predecessor of the second attempt')
    need(len({sha(data['cache-prune-' + number + '/owner-' + side + '.json'])
              for number in ('01', '02') for side in ('before', 'after')}) == 1,
         'original owner/retained receipts differ between cache preparations')
    plan1, plan2 = read('cache-prune-tools-01/plan.json'), read('cache-prune-tools-02/plan.json')
    wrong = ['1793930603038937300', '1793930262097573600']
    exact = ['1793930603038937265', '1793930262097573724']
    need([str(row['stat']['mtime_ns']) for row in plan1['candidates']] == wrong
         and [row['stat']['mtime_ns'] for row in plan2['candidates']] == exact,
         'original imprecise and corrected input identities were not both preserved')
    cross_native = read(originals + 'precision-native-terminal-original-01.json')
    native_terminal(cross_native, '1a1aef15be1-fc05-6460', 'succeeded', 0)
    cross_streams = original_streams(read(originals + 'precision-native-read-original-01.json'), cross_native)
    need(cross_streams['stdout'] == data[originals + 'precision-crosscheck-original-01.json']
         and cross_streams['stderr'] == b'', 'original precision crosscheck native bytes differ')
    cross = read(originals + 'precision-crosscheck-original-01.json')
    need(cross['read_only'] is True and cross['source_sha256'] == sha(data['cache-prune-01/cache-before.json'])
         and [row['path'] for row in cross['rows']] == expected_paths
         and all(row['live_selected_stat_matches_original'] is True for row in cross['rows'])
         and [row['original_cache_before_stat_decimal']['mtime_ns'] for row in cross['rows']] == exact,
         'original exact integer crosscheck differs')
    return {
        'attempts': [{'job_id': first_native['job_id'], 'reported_passed': False, 'deleted': 0,
                      'error': one['error'], 'report': identity('cache-prune-01/report.json')},
                     {'job_id': second_native['job_id'], 'reported_passed': True, 'deleted': 2,
                      'report': identity('cache-prune-02/report.json')}],
        'input_precision_correction': {'first_supplied_mtime_ns': wrong, 'exact_decimal_mtime_ns': exact,
            'method': 'original exact bytes parsed as Python integers; no JS Number or tolerance comparison'},
        'original_free_bytes_after_second_prune': two['free_bytes_after'],
        'minimum_free_bytes_unchanged': 3 * 1024 ** 3,
        'metadata_only_no_cache_or_elf_content': True,
        'raw_cache_before_after_manifests_included': 4,
        'retained_hashes_supported_by_original_receipts': True,
        'retained_or_deleted_elf_rehashed': False, 'pruner_or_helper_reexecuted': False,
    }


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original R34 qualification may be archived')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == pin
             for name, pin in PINNED.items()), 'frozen preparation/prune input differs')
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
    cache = cache_preparation_summary(data)
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
    result['cache_preparation'] = cache
    result['native_original_logs'] = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in native.items()}
    return result


def collect(root, kind):
    actual = require_sealed()
    need(kind == 'qualification', 'this script archives only completed R34 qualification')
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
    need(kind == 'qualification', 'this script archives only completed R34 qualification')
    need(all(name in data for name in REQUIRED), 'missing original R34 preparation/qualification input')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == expected
             for name, expected in PINNED.items()), 'a frozen original R34 input or receipt differs')
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
    need(prep.get('schema') == 'hepta-x230-r34-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and prep.get('first_actual_r34_qualification_required') is True
         and prep.get('qualification_started') is True
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and prep.get('production_services_modified') is False
         and prep.get('source_baseline') == BASELINE_COMMIT
         and 'prior_preparation_failure' not in prep
         and prep['input_binding'] == identity('qualification-input.json')
         and prep['candidate_patch'] == identity('candidate/candidate.patch')
         and prep['qualification_report_sha256'] == sha(data['qualification-01/report.json']),
         'the actual first R34 preparation did not close successfully')
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
    need(inputs['schema'] == 'hepta-r34-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['git_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-x230-r34-candidate/v1'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['patch_path'] == 'candidate.patch'
         and candidate['patch_sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['added_paths'] == candidate['removed_paths'] == []
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and len(set(candidate['new_test_functions'])) == len(candidate['new_test_functions']) == 8,
         'R34 input differs from the frozen accepted-R24 four-file candidate')
    need(prep['source_before_qualification'] == candidate['candidate_compile_inputs'] == qualified['source_input']
         and prep['source_after_qualification'] == qualified['source_tested'] == qualified['source_after'] == final_map
         and len(final_map) == 220 and set(final_map) == set(candidate['baseline_compile_inputs'])
         and {name for name in final_map if final_map[name] != candidate['baseline_compile_inputs'][name]} == CHANGED_PATHS,
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
    frozen, closure = read('candidate/manifest.json'), read('cache-owner-closure-inputs.json')
    need(frozen['schema'] == 'hepta-x230-r34-candidate-manifest/v1'
         and frozen['baseline_commit'] == BASELINE_COMMIT and frozen['compile_input_count'] == 220
         and set(frozen['changed_paths']) == CHANGED_PATHS and len(frozen['files']) == 21,
         'frozen R34 candidate manifest differs')
    for pin in frozen['files']:
        name = 'candidate/' + pin['path']
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name]),
             'frozen candidate member differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/manifest.json'} | {'candidate/' + pin['path'] for pin in frozen['files']},
         'candidate manifest is not the exact 22-member frozen selection')
    for name, field in (('candidate/input.json', 'candidate_input'), ('candidate/manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'accepted R24 source copy plus the frozen R34 patch; R33 supplies build cache only'
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-x230-r34-cache-owner-closure/v1' and closure['sealed'] is True
         and closure['required_missing_bindings'] == []
         and closure['closure_is_not_performance_adoption'] is True
         and closure['r33_observation_performance_passed'] is False
         and closure['r33_lifecycle_abba_executed'] is False
         and prep['cache_owner_closure']['inputs'] == closure['inputs']
         and prep['cache_owner_closure']['observation_performance_passed'] is False
         and prep['cache_owner_closure']['r33_adoption_claimed'] is False
         and prep['cache_owner_closure']['rejection_reasons'] == ['C8 regression gate']
         and prep['cache_owner_closure']['lifecycle_materializer_rejected_before_abba'] is True
         and prep['cache_transferred_by_rename'] is True and prep['cache_to_transfer'] == closure['cache_path']
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'R33 cache-only origin, rejected performance history or rename receipt differs')
    postflight = closure['postflight_receipt']
    need(postflight['path'] == 'owner-closure-provenance/observation-postflight-01.json'
         and postflight['bytes'] == len(data[postflight['path']]) and postflight['sha256'] == sha(data[postflight['path']]),
         'original rejected-owner postflight reference differs')
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
            'preparation_history': 'first R34 preparation and first actual eight-stage qualification',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'compiler_source_files': len(final_map), 'qualification_harness_files': len(qualified['harness_after']),
            'compressed_original_log_files': len(logs), 'native_original_logs': native_logs,
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'cache_owner_original_references': closure['inputs'], 'cache_owner_originals_copied': False,
            'r33_performance_adoption_claimed': False, 'tests_reexecuted': False,
            'original_test_audit_reexecuted': False, 'test_binary_hashes_recomputed': False,
            'performance_adoption_evaluated': False}

def create_archive(root, kind):
    require_sealed()
    need(kind == 'qualification', 'this script archives only completed R34 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r34-qualification-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
                need(manifest['schema'] == 'hepta-r34-qualification-evidence-archive/v1'
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
