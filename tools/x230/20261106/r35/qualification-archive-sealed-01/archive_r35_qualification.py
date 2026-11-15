#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded R35 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261106-r35')
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


PINNED = {'cache-owner-closure-inputs.json': {'bytes': 5378,
                                     'sha256': '2bc6f84cc6f26b8f10306b8a7310f21e64b52b6c3a2a86f7191bc239801dcd47'},
 'candidate/README.md': {'bytes': 10053,
                         'sha256': '06b15279ff326150fd9bcead7625cea410fe3eec05993026e7c254cb29ccbdbd'},
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
 'candidate/baseline/src/mcp/runtime/ssh_observation_pool.rs': {'bytes': 63329,
                                                                'sha256': '92592431b6f4f0d3561c039ed86d9129f3942fb677ba9a336f639003b16b71d9'},
 'candidate/baseline/src/mcp/runtime/ssh_observation_pool_tests.rs': {'bytes': 91747,
                                                                      'sha256': 'c41347b04e3697503dd0f75237b66c7bb24c512b5bc9362cf7d9a5525e843a7c'},
 'candidate/candidate-compile-inputs.json': {'bytes': 24156,
                                             'sha256': '02843e761ae69211b0e0ccb75f8273017e432c3b75708a9edf6cad6fd0d78e05'},
 'candidate/candidate.patch': {'bytes': 3774,
                               'sha256': '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a'},
 'candidate/history/historical-overlap-review-01.json': {'bytes': 5593,
                                                         'sha256': '04f6a7ae3f7a07c0ee7f881509e50f7fbe3b12a5e827e358be36381221caa7e8'},
 'candidate/history/originals/capacity12-pool.rs': {'bytes': 63445,
                                                    'sha256': '547169e952957ceea8a3a6d9ef35630529fd0e579f0eb9cea3f8a15b3e3c8add'},
 'candidate/history/originals/r25-full.patch': {'bytes': 27465,
                                                'sha256': 'e1f0fd01ca3289ba87b35a46fcc27ba5ef229e65d4475afd28b724c5e3c61966'},
 'candidate/history/originals/r26-README.md': {'bytes': 24452,
                                               'sha256': 'cac449f7473cffcc45888506aab3ff0c042e77fd690207f76c510aba6f4abd05'},
 'candidate/history/originals/r26-full.patch': {'bytes': 29666,
                                                'sha256': '1253b7fe0e9a5948582ceb011eb5814fa889a26c0c8d237dbc652828fba534ad'},
 'candidate/history/originals/r26-selected-change.patch': {'bytes': 1368,
                                                           'sha256': 'f06843dd9ba9026ac240ab6761e1abc16b32bcd3dc771d6a2754ff5eeebcb94f'},
 'candidate/history/originals/r28-README.md': {'bytes': 8033,
                                               'sha256': '18837aa54f6edac75e3fd82a06c83d136691cef55c5cdd59692ed4e8aeb173bd'},
 'candidate/history/originals/r28-full.patch': {'bytes': 31533,
                                                'sha256': '2655e1cbde509a2802015315bb1dd514671f83a852fe032a9073a9ee4329f446'},
 'candidate/input.json': {'bytes': 53380,
                          'sha256': '7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d'},
 'candidate/manifest.json': {'bytes': 5225,
                             'sha256': 'e5f4338e3581ecc4560269a417941b4802a8b58307eb60eea6e04dd7a4f5102b'},
 'candidate/reference-r33-input.json': {'bytes': 52436,
                                        'sha256': '3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d'},
 'candidate/review/R35_INDEPENDENT_REVIEW.md': {'bytes': 3438,
                                                'sha256': 'ac5f9df62ad1788fae90d74391069fed7ed934edfc6cddb79244bbadf20575a4'},
 'candidate/review/independent-review-01.json': {'bytes': 7659,
                                                 'sha256': '121ead46cf04b5adfdc01792a86afe63afdccb70a18dd28e159a22b6d75f1fd8'},
 'candidate/source/src/mcp/runtime/jobs.rs': {'bytes': 186465,
                                              'sha256': '17c8bb5c27c6bcc2e466dbfc31951183e9b694fa6e180865477cb2a322743629'},
 'candidate/source/src/mcp/runtime/ssh_observation_pool.rs': {'bytes': 63354,
                                                              'sha256': 'cd7c737faac90b9f2ec7a7faf73df38b63836854105600183e2140340ebc6dbd'},
 'candidate/source/src/mcp/runtime/ssh_observation_pool_tests.rs': {'bytes': 91763,
                                                                    'sha256': '318bbd4566f0d08531d7886fbd0166906df63c2d2b990d165a51e9a2ac280baa'},
 'candidate/static-checks.json': {'bytes': 4206,
                                  'sha256': 'b606f99d28f1da74a47bf40eb15535b7c5683b0a5f06cbdf8f30faa23cad2bd5'},
 'candidate/verify_candidate.py': {'bytes': 9880,
                                   'sha256': '6b798a9dcfc51e01689c64a30de666c0c3ea57c42a6480c1e49c71ce1a44e1df'},
 'frozen-preparation-manifest.json': {'bytes': 7532,
                                      'sha256': 'a2c8155bca4bbad9d805270fafc4c6ab968e4d559c794636bdb033ef7307f000'},
 'installation-originals-01/installation-history-01.json': {'bytes': 4327,
                                                            'sha256': 'b3d5a29e35052cb298a133a915a32a3336a7d4e2163b9782cddac0c51a94ecd2'},
 'installation-originals-01/installation-original-read-error-01.txt': {'bytes': 262,
                                                                       'sha256': '3972979a0df708c3dade11d8e37128338852d1ee16b0eb28f0356386bd4d87de'},
 'installation-originals-01/installation-original-start-01.json': {'bytes': 1116,
                                                                   'sha256': 'ce1dce72b66aaa62eaead5e7df7d9370ffceb4a66a4c7970f48cc1b235b63169'},
 'installation-originals-01/installation-original-status-error-01.txt': {'bytes': 262,
                                                                         'sha256': '3972979a0df708c3dade11d8e37128338852d1ee16b0eb28f0356386bd4d87de'},
 'installation-originals-01/installation-reconcile-native-01.json': {'bytes': 729,
                                                                     'sha256': '07097de6aa7d14e78f1e81d254bb8840e00437f22e78664661ed2f8f85377621'},
 'installation-originals-01/installation-reconcile-read-01.json': {'bytes': 1807,
                                                                   'sha256': 'addca379f4ce7b27d36134dfac38e379394c93dd9d742b3efcc967c5936f2f14'},
 'installation-originals-01/installation-reconcile-start-01.json': {'bytes': 994,
                                                                    'sha256': 'dbffd00d11b125d4de2645d3cfbe29ede74a4dfd36181be38e5451725dde4064'},
 'installation-originals-01/installation-reconcile.py': {'bytes': 1168,
                                                         'sha256': '6bf7bd2ce69de20ec1d8456c7bbd3890a8b23a849d1faadb7d7e5d57ff8fa32a'},
 'installation-originals-01/installation-staged-native-02.json': {'bytes': 729,
                                                                  'sha256': 'b211e3c8a2c2789f7b61d8d505cbf79b72c2a1e48650f3653adcb73cf052989a'},
 'installation-originals-01/installation-staged-read-02.json': {'bytes': 1985,
                                                                'sha256': '51a6acbc64b487838ed6a8bb1a18f32e36c26cf9f59909c4d0dfae9cdd29ad4e'},
 'installation-originals-01/installation-staged-start-02.json': {'bytes': 987,
                                                                 'sha256': '373871da6faecb01e52a7b6208d1df5ed8d486e52a8080147d9dbf03eb591d18'},
 'installation-originals-01/installation-staged.py': {'bytes': 5074,
                                                      'sha256': '0a1d07391d9401f2b98dbbbeb311aa91a4a771c4eb789bfb7edc59e0b061d41e'},
 'installation-originals-01/package-upload-receipts-01.json': {'bytes': 1282,
                                                               'sha256': 'a4e8e7f12c35b7f14057098123bc723ea5fbee929606b69e89ff4ecb81af2839'},
 'installation-originals-01/qualification-start-01.json': {'bytes': 1306,
                                                           'sha256': 'da98a914d721d4d5719a5051cdf2b8427d1330b663ead5d5835af06f73e69153'},
 'owner-closure-provenance/observation-postflight-01.json': {'bytes': 5064,
                                                             'sha256': '17a371b24de733c7e412afdcf31a1fdad1745bbe2b560177e010816ee5193cc1'},
 'owner-closure-provenance/postflight-native-read-01.json': {'bytes': 14879,
                                                             'sha256': '49dedd1eefed821e27d84fd0382358a8b77850f0f5c11dcde479e5c3776c73dc'},
 'owner-closure-provenance/postflight-native-status-01.json': {'bytes': 731,
                                                               'sha256': '4fb5fbb783b1e302a16fef462bd90e14ac35c80bb4fe9efc89e7b3d84e9f4e46'},
 'preparation-tools/reference/prepare_r34_qualify.py': {'bytes': 29912,
                                                        'sha256': '6f50859c6155ecc1c0eea78a027ae94508d6de9dee0545cef00bde8fee0bf67f'},
 'preparation-tools/seal_preparation.py': {'bytes': 26925,
                                           'sha256': '30b51d51af705c9cbffd0c79db25dc0fecabc5491c3fe0b469a2b28ed98be09e'},
 'prepare_qualify.py': {'bytes': 32838,
                        'sha256': '6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4'},
 'qualification-input.json': {'bytes': 3742,
                              'sha256': '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63'},
 'qualification-package-install-02.json': {'bytes': 7081,
                                           'sha256': '0ebcc8a7ad1a4ec397de179e68ff50bd7da19cf9b6ff5100d816c2245eab1e34'},
 'qualification-preparation-seal.json': {'bytes': 3866,
                                         'sha256': '9c0664f58a8e61ae21727a315a766e71405aa77ac87fc68a88be2eec6bd0d4cc'}}
REQUIRED = ('cache-owner-closure-inputs.json',
 'candidate/README.md',
 'candidate/baseline-compile-inputs.json',
 'candidate/baseline/Cargo.lock',
 'candidate/baseline/Cargo.toml',
 'candidate/baseline/rustfmt.toml',
 'candidate/baseline/src/mcp/runtime/jobs.rs',
 'candidate/baseline/src/mcp/runtime/jobs_tests.rs',
 'candidate/baseline/src/mcp/runtime/ssh_observation_pool.rs',
 'candidate/baseline/src/mcp/runtime/ssh_observation_pool_tests.rs',
 'candidate/candidate-compile-inputs.json',
 'candidate/candidate.patch',
 'candidate/history/historical-overlap-review-01.json',
 'candidate/history/originals/capacity12-pool.rs',
 'candidate/history/originals/r25-full.patch',
 'candidate/history/originals/r26-README.md',
 'candidate/history/originals/r26-full.patch',
 'candidate/history/originals/r26-selected-change.patch',
 'candidate/history/originals/r28-README.md',
 'candidate/history/originals/r28-full.patch',
 'candidate/input.json',
 'candidate/manifest.json',
 'candidate/reference-r33-input.json',
 'candidate/review/R35_INDEPENDENT_REVIEW.md',
 'candidate/review/independent-review-01.json',
 'candidate/source/src/mcp/runtime/jobs.rs',
 'candidate/source/src/mcp/runtime/ssh_observation_pool.rs',
 'candidate/source/src/mcp/runtime/ssh_observation_pool_tests.rs',
 'candidate/static-checks.json',
 'candidate/verify_candidate.py',
 'frozen-preparation-manifest.json',
 'installation-originals-01/installation-history-01.json',
 'installation-originals-01/installation-original-read-error-01.txt',
 'installation-originals-01/installation-original-start-01.json',
 'installation-originals-01/installation-original-status-error-01.txt',
 'installation-originals-01/installation-reconcile-native-01.json',
 'installation-originals-01/installation-reconcile-read-01.json',
 'installation-originals-01/installation-reconcile-start-01.json',
 'installation-originals-01/installation-reconcile.py',
 'installation-originals-01/installation-staged-native-02.json',
 'installation-originals-01/installation-staged-read-02.json',
 'installation-originals-01/installation-staged-start-02.json',
 'installation-originals-01/installation-staged.py',
 'installation-originals-01/package-upload-receipts-01.json',
 'installation-originals-01/qualification-start-01.json',
 'owner-closure-provenance/observation-postflight-01.json',
 'owner-closure-provenance/postflight-native-read-01.json',
 'owner-closure-provenance/postflight-native-status-01.json',
 'preparation-tools/reference/prepare_r34_qualify.py',
 'preparation-tools/seal_preparation.py',
 'prepare_qualify.py',
 'qualification-input.json',
 'qualification-package-install-02.json',
 'qualification-preparation-seal.json')
FUTURE_PATHS = ('preparation.json',
 'qualification-terminal-status-01.json',
 'qualification-native-read-01.json',
 'qualification-01/report.json',
 'qualification-01/source-map.json',
 'qualification-01/isolated-tests/summary.json',
 'qualification-01/isolated-tests.audit.json')
ACTUAL = {'counts': {'failed': 0,
            'ignored': 34,
            'passed': 1645,
            'retries': 0,
            'selected': 1679},
 'files': {'preparation.json': {'bytes': 62335,
                                'sha256': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc'},
           'qualification-01/isolated-tests.audit.json': {'bytes': 1419928,
                                                          'sha256': 'cdd5497f7646ddca0ba028cf2d93d4df76c737a87569e19e9596625620397894'},
           'qualification-01/isolated-tests/summary.json': {'bytes': 6878,
                                                            'sha256': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904'},
           'qualification-01/report.json': {'bytes': 83363,
                                            'sha256': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1'},
           'qualification-01/source-map.json': {'bytes': 24156,
                                                'sha256': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313'},
           'qualification-native-read-01.json': {'bytes': 3812,
                                                 'sha256': '4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043'},
           'qualification-terminal-status-01.json': {'bytes': 731,
                                                     'sha256': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844'}},
 'outcome': 'passed',
 'qualification_job_id': '1a1af619097-fc05-6813',
 'qualified_binary_sha256': {'hepta-runtime': '416662310fef6ca6d68907658bb1b882584d1e431bf4ed4263f62984495d8251',
                             'hepta-runtime-jobctl': '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62',
                             'native_process_driver': '31d90610e618041faa5f562c029e496afc39c603fbe3a51d740e4eec3aacd54e'},
 'schema': 'hepta-r35-qualification-archive-actual-pins/v1',
 'sealed': True}
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED_PATHS = {'src/mcp/runtime/jobs.rs',
 'src/mcp/runtime/ssh_observation_pool.rs',
 'src/mcp/runtime/ssh_observation_pool_tests.rs'}
BINARY_NAMES = {'hepta-runtime-jobctl', 'native_process_driver', 'hepta-runtime'}
SOURCE_REFERENCE_SHA256 = 'b9a5a8cbb64a745cc70cd9acff647dee3faf37c541ea55edee802d80318521aa'
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
# Pure original receipt functions embedded by the builder; never executed during preparation.

def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original R35 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original R35 native job identity required')
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



def installation_summary(data):
    """Reconcile already completed installation receipts without running an installer."""
    prefix = 'installation-originals-01/'
    read = lambda name: json.loads(data[prefix + name])
    pin = lambda name: {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}
    history = read('installation-history-01.json')
    need(history['schema'] == 'hepta-r35-installation-history/v1'
         and history['failed_or_unknown_install_is_not_a_qualification_retry'] is True
         and history['cause_of_original_transport_failure_established'] is False,
         'installation history does not retain the unknown outcome')
    selected = set()
    for row in history['files']:
        name = row['path'] if row['path'] == 'qualification-package-install-02.json' else prefix + row['path']
        need(name in PINNED and name not in selected
             and {'bytes': len(data[name]), 'sha256': sha(data[name])}
             == {key: row[key] for key in ('bytes', 'sha256')},
             'installation history original differs: ' + name)
        selected.add(name)
    need(len(selected) == 14 and {name for name in data if name.startswith(prefix)}
         == (selected - {'qualification-package-install-02.json'}) | {prefix + 'installation-history-01.json'},
         'installation history has missing or extra selected originals')

    unknown = read('installation-original-start-01.json')
    original_job = '1a1af5e240e-fc05-67f8'
    need(unknown['audit_recorded'] is True and unknown['reused'] is False
         and unknown['job']['id'] == original_job and unknown['job']['launch_state'] == 'launch_unknown'
         and unknown['launch']['job_id'] == original_job and unknown['launch']['outcome'] == 'unknown'
         and unknown['launch']['state'] == 'launch_unknown'
         and unknown['launch']['status_authoritative'] is False
         and unknown['launch']['automatic_retry'] is False,
         'original launch_unknown response was replaced by a terminal result')
    need(history['original_install']['job_id'] == original_job
         and history['original_install']['launch_state'] == 'launch_unknown'
         and history['original_install']['native_terminal_result_available'] is False,
         'unavailable original native terminal was fabricated')
    for name in ('installation-original-status-error-01.txt', 'installation-original-read-error-01.txt'):
        need(b'FileNotFoundError' in data[prefix + name] and original_job.encode() in data[prefix + name],
             'original unavailable status/read error missing')
    external_payload = history['original_install']['stdin_script']
    need(external_payload == {'path': 'installation-original-payload-01.py', 'bytes': 477316,
         'sha256': '62397e09eee881494e8ed659eb8266f05c591b153224a5b3769ad796c4bff9c6'}
         and prefix + external_payload['path'] not in data,
         'separately retained original stdin identity differs')

    recon_job = '1a1af5f2833-fc05-6802'
    recon_native = read('installation-reconcile-native-01.json')
    native_terminal(recon_native, recon_job, 'succeeded', 0)
    recon_streams = original_streams(read('installation-reconcile-read-01.json'), recon_native)
    need(recon_streams['stderr'] == b'', 'reconciliation original stderr differs')
    recon = json.loads(recon_streams['stdout'])
    recon_start = read('installation-reconcile-start-01.json')
    need(recon_start['job']['id'] == recon_job and recon_start['job']['launch_state'] == 'launched'
         and recon_start['launch']['ok'] is True and recon_start['reused'] is False,
         'read-only reconciliation start identity differs')
    need(recon['schema'] == 'hepta-r35-unknown-package-install-readonly-reconciliation/v1'
         and recon['original_job_id'] == original_job
         and recon['root_exists'] is False and recon['job_directory_exists'] is False
         and recon['qualification_was_not_requested'] is True
         and recon['inputs_modified'] is False and recon['install_or_qualification_reexecuted'] is False
         and history['read_only_reconciliation']['job_id'] == recon_job
         and history['read_only_reconciliation']['observed_result'] == recon,
         'read-only original reconciliation differs')
    unit = recon['unit_query']
    fields = dict(line.split('=', 1) for line in unit['stdout'].splitlines())
    need(unit['returncode'] == 0 and unit['stderr'] == ''
         and fields == {'MainPID': '0', 'ExecMainPID': '0', 'LoadState': 'not-found',
                        'ActiveState': 'inactive', 'SubState': 'dead'},
         'original unit absence observation differs')

    installed = json.loads(data['qualification-package-install-02.json'])
    install_job = '1a1af611834-fc05-680f'
    install_native = read('installation-staged-native-02.json')
    native_terminal(install_native, install_job, 'succeeded', 0)
    install_streams = original_streams(read('installation-staged-read-02.json'), install_native)
    need(install_streams['stderr'] == b'', 'staged installation original stderr differs')
    install_start = read('installation-staged-start-02.json')
    need(install_start['job']['id'] == install_job and install_start['job']['launch_state'] == 'launched'
         and install_start['launch']['ok'] is True and install_start['reused'] is False,
         'staged installation start identity differs')
    output = json.loads(install_streams['stdout'])
    need(output['installed'] is True and output['root'] == str(ROOT)
         and output['receipt'] == pin('qualification-package-install-02.json'),
         'staged original native stdout does not bind installed receipt')
    manifest = json.loads(data['frozen-preparation-manifest.json'])
    expected = {row['path']: {key: row[key] for key in ('bytes', 'sha256')} for row in manifest['files']}
    expected['frozen-preparation-manifest.json'] = {key: pin('frozen-preparation-manifest.json')[key]
                                                 for key in ('bytes', 'sha256')}
    need(installed['schema'] == 'hepta-r35-qualification-package-install/v1'
         and installed['root'] == str(ROOT) and installed['file_count'] == len(expected) == 39
         and installed['files'] == expected and installed['expanded_file_bytes'] == 1383630
         and installed['archive_bytes'] == 354738
         and installed['archive_sha256'] == '7303e1ded7ac4aab5f02c5240b1e6211bbaf7ca8cd7ebe19d686546842366dba'
         and installed['original_minimum_free_bytes'] == 3 * 1024**3
         and installed['free_bytes_before_install'] == 6835855360,
         'original frozen package installation differs')
    need(all(installed[key] is False for key in ('qualification_started', 'source_materialized',
              'cache_moved', 'cache_deleted', 'production_services_modified')),
         'installation unexpectedly performed preparation or qualification')
    for name in ('file_count', 'expanded_file_bytes', 'archive_sha256', 'free_bytes_before_install',
                 'qualification_started', 'cache_moved', 'cache_deleted'):
        need(output[name] == installed[name], 'original installation stdout/report disagree: ' + name)
    need(history['staged_install'] == {'job_id': install_job, 'succeeded': True, 'exit_code': 0,
         'files': 39, 'expanded_bytes': 1383630, 'free_bytes_before': 6835855360,
         'qualification_started': False}, 'derived history disagrees with original installation')

    upload = read('package-upload-receipts-01.json')
    chunks = [json.loads(raw) for raw in upload['original_chunk_responses']]
    commit = json.loads(upload['original_commit_response'])
    need(upload['schema'] == 'hepta-r35-package-upload-original-receipts/v1'
         and upload['expected_version'] == 'absent'
         and upload['size'] == installed['archive_bytes'] and upload['sha256'] == installed['archive_sha256']
         and upload['path'] == installed['archive_path']
         and len(chunks) == 6 and [row['next_offset'] for row in chunks] == [
             65536, 131072, 196608, 262144, 327680, 354738]
         and all(row['visible'] is False and row['upload_id'] == upload['upload_id'] for row in chunks)
         and commit['committed'] is True and commit['reused'] is False
         and commit['size'] == upload['size'] and commit['sha256'] == upload['sha256']
         and commit['version'] == installed['archive_version'],
         'original chunk/commit receipts disagree with the installed package')

    launch = read('qualification-start-01.json')
    need(launch['audit_recorded'] is True and launch['reused'] is False
         and launch['job']['id'] == ACTUAL['qualification_job_id'] == '1a1af619097-fc05-6813'
         and launch['job']['launch_state'] == 'launched' and launch['launch']['ok'] is True
         and launch['job']['cwd'] == str(ROOT)
         and [launch['job']['executable'], *launch['job']['args']] == manifest['single_authorized_launch_argv']
         and history['first_qualification']['job_id'] == ACTUAL['qualification_job_id']
         and history['first_qualification']['automatic_retry_requested'] is False,
         'actual original qualification start differs from the frozen launch')
    return {
        'original_install': {'job_id': original_job, 'recorded_launch_state': 'launch_unknown',
            'native_terminal_available': False, 'terminal_state': None, 'exit_code': None,
            'complete_original_status_and_read_errors_preserved': True},
        'read_only_reconciliation': {'job_id': recon_job, 'original_observed_result': recon,
            'native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)}
                               for name, raw in recon_streams.items()}},
        'staged_install': {'job_id': install_job, 'reported_succeeded': True,
            'receipt': pin('qualification-package-install-02.json'),
            'native_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)}
                               for name, raw in install_streams.items()},
            'package_members': 39, 'expanded_file_bytes': 1383630,
            'qualification_started_by_installer': False},
        'separate_chunked_delivery': {'chunks': len(chunks), 'bytes': upload['size'], 'sha256': upload['sha256']},
        'first_qualification_job_id': ACTUAL['qualification_job_id'],
        'installation_unknown_is_not_a_qualification_retry': True,
        'cause_of_original_transport_failure_established': False,
        'selected_original_files': 15,
        'large_original_stdin_body_in_archive': False,
        'large_original_stdin_identity_retained_separately': external_payload,
        'original_derived_history_kept_with_its_at_capture_pending_qualification_state': True,
        'installer_reconciliation_or_workload_reexecuted': False,
    }


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original R35 qualification may be archived')
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
    result['installation_preparation'] = installation
    result['native_original_logs'] = {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in native.items()}
    return result



def collect(root, kind):
    actual = require_sealed()
    need(kind == 'qualification', 'this script archives only completed R35 qualification')
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
    need(kind == 'qualification', 'this script archives only completed R35 qualification')
    need(all(name in data for name in REQUIRED), 'missing original R35 preparation/qualification input')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == expected
             for name, expected in PINNED.items()), 'a frozen original R35 input or receipt differs')
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
    need(prep.get('schema') == 'hepta-x230-r35-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and prep.get('first_actual_r35_qualification_required') is True
         and prep.get('qualification_started') is True
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and prep.get('production_services_modified') is False
         and prep.get('source_baseline') == BASELINE_COMMIT
         and 'prior_preparation_failure' not in prep
         and prep['input_binding'] == identity('qualification-input.json')
         and prep['candidate_patch'] == identity('candidate/candidate.patch')
         and prep['qualification_report_sha256'] == sha(data['qualification-01/report.json']),
         'the actual first R35 preparation did not close successfully')
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
    need(inputs['schema'] == 'hepta-r35-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['git_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-x230-r35-candidate/v1'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['patch_path'] == 'candidate.patch'
         and candidate['patch_sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['added_paths'] == candidate['removed_paths'] == []
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and candidate['new_test_functions'] == [],
         'R35 input differs from the frozen accepted-R24 three-file candidate')
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
    need(frozen['schema'] == 'hepta-x230-r35-source-package/v1'
         and frozen['baseline_commit'] == BASELINE_COMMIT and frozen['compile_input_count'] == 220
         and set(frozen['changed_compile_paths']) == CHANGED_PATHS and len(frozen['files']) == 28,
         'frozen R35 candidate manifest differs')
    for pin in frozen['files']:
        name = 'candidate/' + pin['path']
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name]),
             'frozen candidate member differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/manifest.json'} | {'candidate/' + pin['path'] for pin in frozen['files']},
         'candidate manifest is not the exact 29-member frozen selection')
    for name, field in (('candidate/input.json', 'candidate_input'), ('candidate/manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'accepted R24 source copy plus the frozen R35 patch; R34 supplies build cache only'
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-x230-r35-cache-owner-closure/v1' and closure['sealed'] is True
         and closure['required_missing_bindings'] == []
         and closure['closure_is_not_performance_adoption'] is True
         and closure['r34_observation_performance_passed'] is False
         and closure['r34_lifecycle_abba_executed'] is False
         and prep['cache_owner_closure']['inputs'] == closure['inputs']
         and prep['cache_owner_closure']['observation_performance_passed'] is False
         and prep['cache_owner_closure']['r34_adoption_claimed'] is False
         and prep['cache_owner_closure']['rejection_reasons'] == ['C8 regression gate']
         and closure['lifecycle_materialization_started'] is False
         and closure['lifecycle_materializer_job_id'] is None
         and closure['capacity_build_or_campaign_started_by_coordinator'] is False
         and prep['cache_owner_closure']['lifecycle_materialization_started'] is False
         and prep['cache_owner_closure']['lifecycle_materializer_job_id'] is None
         and prep['cache_owner_closure']['normal_lifecycle_started'] is False
         and prep['cache_owner_closure']['capacity_build_or_campaign_started_by_coordinator'] is False
         and prep['cache_transferred_by_rename'] is True and prep['cache_to_transfer'] == closure['cache_path']
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'R34 cache-only origin, rejected performance history or rename receipt differs')
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
            'preparation_history': 'first R35 preparation and first actual eight-stage qualification',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'compiler_source_files': len(final_map), 'qualification_harness_files': len(qualified['harness_after']),
            'compressed_original_log_files': len(logs), 'native_original_logs': native_logs,
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'cache_owner_original_references': closure['inputs'], 'cache_owner_originals_copied': False,
            'r34_performance_adoption_claimed': False, 'tests_reexecuted': False,
            'original_test_audit_reexecuted': False, 'test_binary_hashes_recomputed': False,
            'performance_adoption_evaluated': False}


def create_archive(root, kind):
    require_sealed()
    need(kind == 'qualification', 'this script archives only completed R35 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-r35-qualification-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
                need(manifest['schema'] == 'hepta-r35-qualification-evidence-archive/v1'
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
