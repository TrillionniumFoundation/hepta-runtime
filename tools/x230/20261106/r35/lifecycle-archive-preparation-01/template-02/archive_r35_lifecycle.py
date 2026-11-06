#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R35 normal lifecycle evidence, including failed attempts.

Fixed reports, logs, tools and inputs only. No tests, benchmarks, SSH or archived
programs are executed. Failed and successful workflow/gate outcomes stay distinct.
Creation is create-only; local verification is bounded and does not extract files.
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
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
EXTERNAL_PREFIX = 'external/r16/'
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
REFERENCE_SHA = '96fa3ff43180ec0e922c4b6373ec9d7a902037d97ae06d9a774ebf318d9f1f2c'
QUALIFICATION_ARCHIVE_SHA = 'a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a'
CI_ARCHIVE_SHA = 'f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f'
ACTUAL = None
HOLDER_JOB = ACTUAL['holder_job_id'] if ACTUAL is not None else None
SEALED = ACTUAL is not None
STAGES = ('lifecycle-tool-tests', 'normal-lifecycle-abba')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'profile.json', 'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SELECTED_DIRS = ('lifecycle-campaign-01', 'lifecycle-abba-01', 'lifecycle-tool-tests-01', 'tools-01', 'lifecycle-tools-01')
EXTERNAL_DIRS = ()
OPTIONAL_FILES = ()
FROZEN = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
FROZEN_PREFIX = 'external/frozen-jobs/'
PROTOCOL_REFERENCE_SHA = 'c9fd58c7aaebd51f60f1a2fdc3a01c52629b41d5a5818be124c79a547735872e'
HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
OBSERVATION_ARCHIVE_SHA = '941e03e20ddcab8baa6049b806e2b447242055abb2f72eefb2a6ed87a9a74b8c'
RESULT_DIRS = ('lifecycle-campaign-01', 'lifecycle-abba-01', 'lifecycle-tool-tests-01')
REQUIRED_DIRS = ('tools-01', 'lifecycle-tools-01')
CORE_FILES = ('lifecycle-holder-native-01.json',
 'lifecycle-holder-read-01.json',
 'lifecycle-holder-report-01.json',
 'lifecycle-materialization-native-01.json',
 'lifecycle-materialization-read-01.json',
 'lifecycle-inputs-01.json',
 'lifecycle-campaign-01/report.json',
 'lifecycle-campaign-01/inputs.json',
 'lifecycle-campaign-01/plan.json',
 'lifecycle-campaign-01/source-inputs.json',
 'lifecycle-campaign-01/baseline-source-inputs.json',
 'lifecycle-campaign-01/compiler-monitor.json',
 'lifecycle-campaign-01/compiler-monitor.audit.json',
 'lifecycle-abba-01/report.json',
 'lifecycle-abba-01/plan.json',
 'lifecycle-abba-01/round-index.json',
 'lifecycle-abba-01/summary.json',
 'lifecycle-abba-01/gates.json',
 'lifecycle-tool-tests-01/report.json')
NORMAL_STAGES = tuple(name for n, arm in enumerate('ABBA') for name in (f'canary-{n}-{arm}', f'audit-{n}-{arm}')) + ('summary', 'normal-lifecycle-gates')
LIFECYCLE_PHASES = ('prepare', 'launch', 'before_crash_running', 'after_transport_running', 'after_crash_running', 'same_key_after_crash', 'concurrent_cancel', 'terminal', 'terminal_after_restart', 'same_key_after_cancel', 'cancel_after_terminal')
COUNTER_KEYS = ('native_calls', 'independent_ssh_calls', 'new_starts', 'same_key_lookups', 'cancellations', 'automatic_rpc_retries')
NAMESPACE_PATHS = CORE_FILES + RESULT_DIRS + ('cancel-saturation-01',)

STATIC_PINS = {'campaign-01/compiler-monitor.audit.json': '66c850ff22dbadcd81a385aa4431c437f004b4c26eb61761004a8268088846e2',
 'campaign-01/compiler-monitor.json': '4314521f6e8479cdc5a56941e1335999039d8d03c7919d6ccbfd5714cd892452',
 'campaign-01/report.json': '3923115d1a8ba2aeb2fc00405bcd01f8d0f92e509b23e17ba6413634d47dba00',
 'campaign-01/summary.json': '0845c8ef6fb7d82350b00f594a68eb523c171b539f588ae1b4e7f12fe1aae3ce',
 'campaign-inputs-01.example.json': '27897ee74e6abd9a7aff24359eaa16c86a4b9471eb95b15117721d7eaef059c1',
 'campaign-inputs-01.json': 'eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4',
 'candidate/candidate.patch': '89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a',
 'external/frozen-jobs/1a16a4035ad-b1270-1.json': 'a8982325aea4833461e2b6a76ca83f846b80b99a227298e97a0b279e2d9dfdb8',
 'external/frozen-jobs/1a16a403e55-b1270-2.json': 'bbb8a86161837ff0f197b345c25bc66224e3404473dea2ac46d1f44f3af43609',
 'external/frozen-jobs/1a16a4046ac-b1270-3.json': '4badc323518a6db1567162a2d7ef5d1209aa88375aba201ec6f3aab34bec61a8',
 'external/frozen-jobs/1a16a40534e-b1270-4.json': '79e18b1a42d84f8024b692dfd98a9f06fa1d6886bf5dc230248cfbde674f011c',
 'external/frozen-jobs/1a16a405d21-b1270-5.json': '9c89c598f35f6bc94572852fcc03feed6e8c798ee34db5095bd3b48813562dc6',
 'external/frozen-jobs/1a16a40671b-b1270-6.json': '5b737330fa5a75a458138e1848a044d2a77c062175d8eb9694a510ff20b53cde',
 'external/r16/benchmark-topology.json': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287',
 'lifecycle-inputs-01.example.json': '7b4d6ef124a2ada384100d59fdd71a325ae2f8c162d6ef2656bcbd2a41c9173a',
 'lifecycle-inputs-01.json': '96e728ffe35848497b694a9925e48523d9f468b349da18fb5b40c437329a2a86',
 'lifecycle-tools-01/README.md': 'bf5ece8988afa5a91f01da1df0e1740add1390f6653d32c7bd562d99b11529be',
 'lifecycle-tools-01/allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
 'lifecycle-tools-01/allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
 'lifecycle-tools-01/analyze_lifecycle_gates.py': 'c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553',
 'lifecycle-tools-01/analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
 'lifecycle-tools-01/audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
 'lifecycle-tools-01/cancel_saturation_gate.py': '536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f',
 'lifecycle-tools-01/lifecycle-gate-policy.json': '36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e',
 'lifecycle-tools-01/lifecycle-tools-manifest-01.json': 'eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e',
 'lifecycle-tools-01/observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
 'lifecycle-tools-01/owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
 'lifecycle-tools-01/run_lifecycle_abba_01.py': 'e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84',
 'lifecycle-tools-01/run_lifecycle_tool_tests.py': 'e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d',
 'lifecycle-tools-01/run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
 'lifecycle-tools-01/run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
 'lifecycle-tools-01/run_six_host_cancel_recovery_timed.py': '54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8',
 'lifecycle-tools-01/run_six_host_cancel_saturation.py': 'ae195c895ab58d3bf067e37f30520bf572fd86b6282722dee9a56acc62df85a0',
 'lifecycle-tools-01/source-provenance.json': '58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe',
 'lifecycle-tools-01/status-predicate.json': '5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34',
 'lifecycle-tools-01/summarize_lifecycle_abba_01.py': '9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89',
 'lifecycle-tools-01/test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
 'lifecycle-tools-01/test_r25_lifecycle_tools.py': '1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566',
 'lifecycle-tools-01/test_verify_saturation_extension.py': '10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb',
 'lifecycle-tools-01/verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
 'lifecycle-tools-01/verify_cancel_saturation.py': 'd3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75',
 'lifecycle-tools-01/verify_saturation_extension.py': '23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a',
 'lifecycle-tools-01/x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
 'lifecycle-tools-01/x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4',
 'observation-postflight-01.json': '9a95bf8e9b8de880c15f9fa979f0f4f03dfc0ca1fb50e2270836420f5a97b977',
 'parent-tools-install-01.json': '542fee8a1f146105125e402be5d7892709b76ff29ae273b162ffc4bff4f16bed',
 'preparation.json': '4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc',
 'prepare_qualify.py': '6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4',
 'qualification-01/isolated-tests/summary.json': '10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904',
 'qualification-01/report.json': '5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1',
 'qualification-01/source-map.json': '87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313',
 'qualification-input.json': '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63',
 'qualification-native-read-01.json': '4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043',
 'qualification-postflight-01.json': '99e198adfeecb2f09b25d928a157a5067ef4a10315b1ead52134721665df630d',
 'qualification-terminal-status-01.json': '8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844',
 'rust-ci-01/nextest-output-audit.json': '545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3',
 'rust-ci-01/report.json': 'b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f',
 'rust-ci-native-01.json': 'c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746',
 'rust-ci-native-read-01.json': '31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b',
 'rust-ci-plan-01.json': '4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28',
 'tools-01/compiler-monitor-policy-01.json': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368',
 'tools-01/compiler_monitor.py': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf',
 'tools-01/compiler_state.py': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251',
 'tools-01/install_measurement_tools.py': '1564f7069cab27c6a99806dc07f326d71f8e0da6392fb7b78696c8a2d3ba62f7',
 'tools-01/prepare_campaign_inputs.py': '1449776932b014d70de282d234d82c1a104f3b2f90ddf2c846371d180091f707',
 'tools-01/prepare_lifecycle_inputs.py': '4c2a58793760c106cafbff5ca21813e85372a92391d9c3d3510ba8e46e58210c',
 'tools-01/r35_campaign.py': '3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c',
 'tools-01/r35_lifecycle_campaign.py': '372f880ec4679147b06ae89e0df8ec64be74ac79a171704715e6499e79191e29',
 'tools-01/runner-bundle-manifest.json': '0e1ad9df3ae5caddc4edb47ecf1dbf1f41f3c00ad243c197c34d6c136f0597f4',
 'tools-01/summarize_r25_campaign.py': '2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864',
 'tools-01/validate_compiler_monitor.py': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}
DYNAMIC_REQUIRED = ('lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json')
PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}
REQUIRED = tuple(sorted(set(STATIC_PINS) | set(ACTUAL['sha256'] if ACTUAL is not None else {})))


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


def member_path(path):
    path = PurePosixPath(str(path))
    need(path.is_absolute() and '..' not in path.parts, 'unsafe source identity')
    if path.is_relative_to(PurePosixPath(str(ROOT))):
        return path.relative_to(PurePosixPath(str(ROOT))).as_posix()
    if path.is_relative_to(PurePosixPath(str(FROZEN))):
        return FROZEN_PREFIX + path.relative_to(PurePosixPath(str(FROZEN))).as_posix()
    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R35/R16/frozen mapping')
    return EXTERNAL_PREFIX + path.relative_to(PurePosixPath(str(R16))).as_posix()


def source_path(name):
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name,
         'unsafe selected archive member')
    if name.startswith(FROZEN_PREFIX):
        return FROZEN / name[len(FROZEN_PREFIX):]
    if name.startswith(EXTERNAL_PREFIX):
        return R16 / name[len(EXTERNAL_PREFIX):]
    need(relative.parts[0] != 'external', 'unexpected external source mapping')
    return ROOT / name




def collect():
    require_sealed()
    need(SEALED, 'unsealed R35 lifecycle collector: actual original receipts are missing')
    need(ROOT.resolve(strict=True) == ROOT and R16.resolve(strict=True) == R16
         and FROZEN.resolve(strict=True) == FROZEN, 'indirect source root')
    payloads, excluded, snapshots = {}, {}, {}
    namespace = {name: os.path.lexists(ROOT / name) for name in NAMESPACE_PATHS}
    total = visited = 0

    def file(path, required=False):
        nonlocal total, visited
        relative = member_path(path)
        if relative in payloads:
            return
        visited += 1
        need(visited <= MAX_FILES * 2 + 256, 'source traversal exceeds bounded inventory')
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and path.resolve(strict=True) == path, 'nonregular/link input: ' + relative)
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
        need(total <= MAX_TOTAL and len(payloads) < MAX_FILES, 'selected bytes/files exceed 64 MiB/8192')
        payloads[relative] = data
        snapshots[path] = stamp(info)

    def directory(path, depth=0):
        nonlocal visited
        visited += 1
        need(visited <= MAX_FILES * 2 + 256 and depth <= 32, 'source directory traversal exceeds limits')
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) and path.resolve(strict=True) == path, 'non-directory/symlink input')
        snapshots[path] = stamp(info)
        for child in sorted(path.iterdir()):
            mode = child.lstat().st_mode
            need(not stat.S_ISLNK(mode), 'symlink input: ' + str(child))
            if stat.S_ISDIR(mode):
                if child.name in SKIP_DIRS:
                    excluded[member_path(child) + '/'] = 'excluded source/target/binary/profile/credential subtree'
                else:
                    directory(child, depth + 1)
            else:
                file(child)

    for name in REQUIRED:
        file(source_path(name), required=True)
    for name in CORE_FILES:
        if os.path.lexists(ROOT / name):
            file(ROOT / name, required=True)
    for name in SELECTED_DIRS:
        if os.path.lexists(ROOT / name):
            directory(ROOT / name)
        else:
            need(name not in REQUIRED_DIRS, 'required frozen tools directory absent: ' + name)
    for name in EXTERNAL_DIRS:
        directory(R16 / name)
    for name in OPTIONAL_FILES:
        if os.path.lexists(ROOT / name):
            file(ROOT / name, required=True)
    need(all(stamp(path.lstat()) == value for path, value in snapshots.items()), 'source changed during collection')
    need(namespace == {name: os.path.lexists(ROOT / name) for name in NAMESPACE_PATHS},
         'lifecycle evidence presence changed during collection')
    return payloads, excluded, namespace

# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Source fragment assembled into the collector. No target program is imported.
def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-normal-lifecycle-archive-bindings/v1',
         'unsealed lifecycle collector: actual original receipts required')
    need(type(HOLDER_JOB) is str and HOLDER_JOB and ACTUAL.get('holder_job_id') == HOLDER_JOB,
         'actual lifecycle holder job required')
    pins, sizes = ACTUAL.get('sha256'), ACTUAL.get('bytes')
    need(type(pins) is dict and type(sizes) is dict and set(pins) == set(sizes)
         and {'lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json'} <= set(pins),
         'actual native original identities missing')
    need(all(type(v) is str and len(v) == 64 and all(c in '0123456789abcdef' for c in v) for v in pins.values())
         and all(type(v) is int and 0 <= v <= MAX_FILE for v in sizes.values()),
         'malformed lifecycle original identities')
    need(all(allowed_binding_name(name) for name in pins), 'actual binding escaped fixed lifecycle selection')
    reads = ACTUAL.get('holder_read_members')
    need(type(reads) is list and reads and reads[0] == 'lifecycle-holder-read-01.json'
         and len(reads) == len(set(reads)) and set(reads) <= set(pins),
         'complete original lifecycle holder read pages required')
    need(type(ACTUAL.get('outcomes')) is dict, 'actual reported outcome object required')
    for key in ('workflow_reported_passed', 'parent_reported_adoption_passed',
                'normal_lifecycle_gate_verified', 'normal_lifecycle_gate_passed'):
        need(ACTUAL['outcomes'].get(key) is None or type(ACTUAL['outcomes'][key]) is bool,
             'reported lifecycle outcome must be a boolean or unavailable')


def allowed_binding_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.as_posix() != name or not path.parts:
        return False
    if any(part in SKIP_DIRS for part in path.parts) or path.name in SKIP_FILES:
        return False
    if path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
        return False
    return (name in STATIC_PINS or name in CORE_FILES
            or name.startswith('lifecycle-holder-read-01-page-') and name.endswith('.json')
            and '/' not in name
            or any(name.startswith(directory + '/') for directory in SELECTED_DIRS))


def summary(kind, data, namespace):
    require_sealed()
    need(kind == 'lifecycle' and all(name in data for name in REQUIRED), 'missing fixed lifecycle input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen lifecycle input differs')
    need(all(len(data[name]) == size for name, size in ACTUAL['bytes'].items()), 'actual original byte lengths differ')
    need(set(namespace) == set(NAMESPACE_PATHS) and all(type(v) is bool for v in namespace.values()),
         'invalid captured lifecycle namespace')
    errors, limitations, parse_errors, external = [], [], [], {}

    def check(value, reason):
        if not value:
            errors.append(reason)
        return bool(value)

    def maybe(name):
        if name not in data:
            return None
        try:
            value = json.loads(data[name])
            if not isinstance(value, dict):
                raise ValueError('original is not a JSON object')
            return value
        except (ValueError, UnicodeError, TypeError) as error:
            parse_errors.append({'member': name, 'type': type(error).__name__, 'reason': str(error)[:300]})
            return None

    def identity(name):
        return {'path': str(source_path(name)), 'bytes': len(data[name]), 'sha256': sha(data[name])}

    def binding(value, label, expected_name=None):
        if not isinstance(value, dict) or not {'path', 'bytes', 'sha256'} <= set(value):
            errors.append(label + ': original identity is unavailable or malformed')
            return False
        try:
            name = member_path(value['path'])
        except (ValueError, TypeError):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'outside the fixed archive roots; body not copied'}
            return None
        if expected_name is not None and name != expected_name:
            errors.append(label + ': reported path differs from the original fixed protocol path')
            return False
        if not allowed_binding_name(name):
            external[(str(value.get('path')), str(value.get('sha256')))] = {
                'identity': value, 'scope': 'source/ELF/profile or separately archived prerequisite; body not repeated'}
            return None
        return check(name in data and type(value['bytes']) is int and value['bytes'] == len(data[name])
                     and value['sha256'] == sha(data[name]), label + ': archived original identity differs')

    def walk(value, label):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= set(value):
                binding(value, label)
                return
            for key, child in value.items():
                walk(child, label + '/' + str(key))
        elif isinstance(value, list):
            for number, child in enumerate(value):
                walk(child, label + '/' + str(number))

    parent = maybe('lifecycle-campaign-01/report.json')
    normal = maybe('lifecycle-abba-01/report.json')
    index = maybe('lifecycle-abba-01/round-index.json')
    gates = maybe('lifecycle-abba-01/gates.json')
    descriptive = maybe('lifecycle-abba-01/summary.json')
    tests = maybe('lifecycle-tool-tests-01/report.json')
    monitor = maybe('lifecycle-campaign-01/compiler-monitor.json')
    monitor_audit = maybe('lifecycle-campaign-01/compiler-monitor.audit.json')
    holder = maybe('lifecycle-holder-report-01.json')
    inputs = maybe('lifecycle-inputs-01.json')
    observation = maybe('campaign-01/report.json')
    qualified_map = maybe('qualification-01/source-map.json')
    native = json.loads(data['lifecycle-holder-native-01.json'])
    pages = [json.loads(data[name]) for name in ACTUAL['holder_read_members']]
    native_receipt = terminal(native, HOLDER_JOB)
    native_receipt['original_streams'] = streams_from_reads(native, pages)
    complete_native = (native.get('output_complete') is True and native.get('output_durable') is True
        and native.get('automatic_retry') is False
        and native.get('log_synced') == {'stdout': True, 'stderr': True}
        and native.get('log_errors') == {'stdout': None, 'stderr': None}
        and native.get('log_truncated') == {'stdout': False, 'stderr': False}
        and all(row['seen_equals_stored'] for row in native_receipt['original_streams'].values()))
    native_receipt['all_native_output_completeness_fields_closed'] = complete_native
    materializer_receipt = None
    materializer_native = maybe('lifecycle-materialization-native-01.json')
    materializer_read = maybe('lifecycle-materialization-read-01.json')
    if materializer_native is not None and materializer_read is not None:
        try:
            materializer_receipt = terminal(materializer_native, materializer_native['job_id'])
            materializer_receipt['original_streams'] = streams_from_reads(materializer_native, [materializer_read])
        except (ValueError, KeyError, TypeError) as error:
            errors.append('original materializer terminal/read binding: ' + str(error)[:300])
    elif materializer_native is not None or materializer_read is not None:
        limitations.append('Only one materializer native/read original is present; no complete stream claim.')
    stdout = b''.join(bytes.fromhex(page['stdout']['bytes_hex']) for page in pages)
    completion = None
    try:
        lines = [json.loads(line) for line in stdout.decode().splitlines() if line]
        completion = lines[-1] if lines else None
    except (ValueError, UnicodeError):
        limitations.append('Original holder stdout is retained but is not a complete JSON completion stream.')
    if holder is not None:
        check(holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1', 'holder report schema differs')
        check(holder.get('holder_script_sha256') == HOLDER_SHA, 'holder source identity differs')
        check(holder.get('remote_script_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'holder used a different lifecycle parent source')
        if isinstance(completion, dict):
            check(all(completion.get(key) == holder.get(key) for key in
                      ('passed', 'remote_returncode', 'owned_agent_reaped')),
                  'original holder completion and full report differ')
        elif holder.get('passed') is True:
            errors.append('positive holder report lacks matching original native completion')
    else:
        limitations.append('Full holder report unavailable; original terminal/read bytes remain retained.')

    reported_parent_passed = parent.get('passed') if parent is not None else None
    reported_adoption = parent.get('adoption_passed') if parent is not None else None
    gate_verified = gates.get('verified') if gates is not None else None
    gate_passed = gates.get('passed') if gates is not None else None
    observed_outcomes = {'workflow_reported_passed': reported_parent_passed,
        'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed}
    for key, expected in ACTUAL['outcomes'].items():
        if expected is not None and key in observed_outcomes:
            check(observed_outcomes[key] == expected, 'sealed and captured reported outcome differs: ' + key)
    positive = (reported_parent_passed is True and reported_adoption is True
                and native.get('state') == 'succeeded' and native.get('exit_code') == 0
                and complete_native
                and holder is not None and holder.get('passed') is True
                and holder.get('owned_agent_reaped') is True)
    if reported_parent_passed is True:
        check(positive, 'positive parent report lacks complete original holder/native custody')

    def stages(value, directory, expected_names, require_positive, process_key='owned_process_absent'):
        if value is None:
            return []
        rows = value.get('stages', [])
        if not check(isinstance(rows, list) and len(rows) <= len(expected_names)
                     and all(isinstance(row, dict) for row in rows)
                     and [row.get('name') for row in rows] == list(expected_names[:len(rows)]),
                     directory + ': original stage order/prefix differs'):
            return []
        result = []
        for number, row in enumerate(rows):
            label = directory + '/' + row['name']
            for stream in ('stdout', 'stderr'):
                if stream in row:
                    binding(row[stream], label + ' ' + stream, directory + '/' + row['name'] + '.' + stream)
                elif require_positive:
                    errors.append(label + ': positive stage lacks ' + stream)
            for pin in row.get('output_bindings', []):
                binding(pin, label + ' output')
            if require_positive:
                check(row.get('returncode') == 0 and row.get('waited_and_reaped') is True
                      and row.get(process_key) is True and row.get('owned_process_group_absent') is True
                      and row.get('cleanup_error') is None and row.get('passed', True) is True,
                      label + ': positive stage custody did not close')
            result.append({key: row.get(key) for key in
                ('name', 'passed', 'returncode', 'timed_out', 'waited_and_reaped', process_key,
                 'owned_process_group_absent', 'cleanup_signals', 'cleanup_error', 'error', 'automatic_retry')})
        if require_positive:
            check(len(rows) == len(expected_names), directory + ': positive stage inventory is incomplete')
        return result

    parent_stages = stages(parent, 'lifecycle-campaign-01', STAGES, positive)
    normal_stages = stages(normal, 'lifecycle-abba-01', NORMAL_STAGES, positive, 'proc_absent')
    for name, value in (('parent', parent), ('normal', normal), ('round-index', index),
                        ('normal-gates', gates), ('descriptive-summary', descriptive),
                        ('original-tool-tests', tests), ('compiler-monitor-audit', monitor_audit)):
        if value is not None:
            walk(value, name)
    if parent is not None:
        check(parent.get('schema') == 'hepta-r35-normal-lifecycle-campaign-control/v1', 'LC parent schema differs')
        check(parent.get('launcher_sha256') == STATIC_PINS['tools-01/r35_lifecycle_campaign.py'],
              'LC parent source identity differs')
        check(parent.get('automatic_retries') == 0 and parent.get('production_services_modified') is False,
              'LC parent retry/production scope differs')
        if inputs is not None:
            check(inputs.get('schema') == 'hepta-r25-lifecycle-inputs/v1' and inputs.get('attempt') == '01'
                  and inputs.get('launcher_sha256') == parent.get('launcher_sha256'),
                  'original LC input/parent source differs')
            binding(parent.get('input_receipt'), 'parent input', 'lifecycle-inputs-01.json')
            if 'lifecycle-campaign-01/inputs.json' in data:
                check(data['lifecycle-campaign-01/inputs.json'] == data['lifecycle-inputs-01.json'],
                      'retained parent input copy differs')
        if observation is not None and parent.get('binaries'):
            check(parent['binaries'] == observation.get('binaries'), 'LC/OBS original A/B artifacts differ')
        if positive:
            check(all(parent.get(key) is True for key in ('inputs_unchanged', 'source_inputs_unchanged',
                  'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'observation_gate_verified')),
                  'positive LC lacks original source/input/measurement closure')
            check(observation is not None and observation.get('passed') is True
                  and observation.get('observation_gate_passed') is True,
                  'positive LC lacks its completed OBS prerequisite')
            check(parent.get('source_inputs_sha256') == inputs.get('source_inputs_sha256')
                  == observation.get('source_inputs_sha256')
                  and parent.get('baseline_source_inputs_sha256') == observation.get('baseline_source_inputs_sha256'),
                  'positive LC source digests differ from original OBS')
    snapshots = {}
    for name in ('source-inputs.json', 'baseline-source-inputs.json'):
        member = 'lifecycle-campaign-01/' + name
        value = maybe(member)
        if value is not None:
            snapshots[name] = {'identity': identity(member), 'root': value.get('root'),
                               'file_count': value.get('file_count'), 'sha256': value.get('sha256')}
            if name == 'source-inputs.json' and qualified_map is not None and isinstance(value.get('files'), dict):
                check({key: pin.get('sha256') for key, pin in value['files'].items()} == qualified_map
                      and value.get('file_count') == len(qualified_map) == 220,
                      'LC source snapshot differs from all actual qualified inputs')
    if normal is not None:
        check(normal.get('schema') == 'hepta-r25-lifecycle-abba-control/v1'
              and normal.get('order') == 'ABBA' and normal.get('automatic_retries') == 0,
              'normal LC schema/order/retries differ')
        binding(normal.get('tools_manifest'), 'normal tools manifest', 'lifecycle-tools-01/lifecycle-tools-manifest-01.json')
        if parent is not None and parent.get('binaries'):
            check(normal.get('baseline') == parent['binaries']['A']['hepta-runtime']
                  and normal.get('candidate') == parent['binaries']['B']['hepta-runtime'],
                  'normal LC artifacts differ from its parent')
    if index is not None:
        check(index.get('schema') == 'hepta-r25-lifecycle-round-index/v1'
              and index.get('order') == 'ABBA' and index.get('automatic_retries') == 0,
              'LC round-index schema/order/retries differ')
        if index.get('closed') is True:
            check(index.get('round_count') == 4 and isinstance(index.get('rounds'), list)
                  and len(index['rounds']) == 4, 'closed original LC index is incomplete')
        if normal is not None:
            check(all(index.get(key) == normal.get(key) for key in
                      ('rounds', 'baseline', 'candidate', 'tools_manifest', 'plan')),
                  'normal report/index original identities differ')
    if gates is not None:
        check(gates.get('schema') == 'hepta-r25-lifecycle-gates/v1'
              and type(gates.get('verified')) is bool and type(gates.get('passed')) is bool,
              'normal LC gate schema/outcome shape differs')
        binding(gates.get('round_index'), 'LC gate round index', 'lifecycle-abba-01/round-index.json')
        binding(gates.get('gate_policy'), 'LC gate policy', 'lifecycle-tools-01/lifecycle-gate-policy.json')
    if descriptive is not None and 'lifecycle-abba-01/round-index.json' in data:
        check(descriptive.get('round_index_sha256') == sha(data['lifecycle-abba-01/round-index.json']),
              'descriptive LC summary index hash differs')

    rounds, shutdowns, intentional_crashes, missing_shutdowns = [], [], [], []
    declared = index.get('rounds', []) if index is not None else normal.get('rounds', []) if normal is not None else []
    if not isinstance(declared, list):
        errors.append('original declared LC rounds is not a list')
        declared = []
    if len(declared) > 4:
        errors.append('original declared LC round count exceeds ABBA')
    for number, arm in enumerate('ABBA'):
        directory = 'lifecycle-abba-01/round-%d-%s' % (number, arm)
        raw_name, audit_name = directory + '/report.json', directory + '/independent-summary.json'
        raw, audit = maybe(raw_name), maybe(audit_name)
        declaration = declared[number] if number < len(declared) else None
        if raw is None and audit is None and declaration is None:
            continue
        item = {'index': number, 'arm': arm, 'directory': directory, 'declared_in_original_index': declaration is not None,
                'raw_report_present': raw_name in data, 'raw_report_structured': raw is not None,
                'independent_analysis_present': audit_name in data, 'independent_analysis_structured': audit is not None,
                'reported_raw_passed': raw.get('passed') if raw is not None else None,
                'reported_audit_verified': audit.get('verified') if audit is not None else None}
        if declaration is not None:
            check(isinstance(declaration, dict) and declaration.get('index') == number and declaration.get('arm') == arm
                  and declaration.get('directory') == directory.split('/')[-1],
                  directory + ': original declared round path/order differs')
            if isinstance(declaration, dict):
                binding(declaration.get('report'), directory + ' declared report', raw_name)
                binding(declaration.get('independent_analysis'), directory + ' declared audit', audit_name)
                phases = declaration.get('phase_files', [])
                check(isinstance(phases, list) and len(phases) == 11
                      and {PurePosixPath(p.get('path', '')).name for p in phases if isinstance(p, dict)}
                         == {'phase-' + phase + '.json' for phase in LIFECYCLE_PHASES},
                      directory + ': declared 11-phase inventory differs')
                for pin in phases if isinstance(phases, list) else []:
                    binding(pin, directory + ' original phase',
                            directory + '/' + PurePosixPath(pin.get('path', '')).name)
                item['phase_files_reported'] = len(phases) if isinstance(phases, list) else None
        item['phase_files_captured'] = [phase for phase in LIFECYCLE_PHASES if directory + '/phase-' + phase + '.json' in data]
        if raw is not None:
            if parent is not None and parent.get('binaries'):
                check(raw.get('candidate_sha256') == parent['binaries'][arm]['hepta-runtime']['sha256'],
                      directory + ': raw runtime differs from original arm')
            for phase in ('shutdown', 'after_cancel_shutdown'):
                value = raw.get(phase)
                if not isinstance(value, dict):
                    missing_shutdowns.append(directory + '/' + phase)
                    continue
                capture = value.get('transport_capture', {})
                row = {key: value.get(key) for key in ('exit_code', 'shutdown_method',
                    'observed_descendant_survivors', 'reader_error', 'unmatched_responses')}
                row.update(round=number, arm=arm, phase=phase, reader_eof=capture.get('reader_eof'))
                row['reported_clean_shutdown'] = (row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
                    and row['observed_descendant_survivors'] == [] and row['reader_error'] is None
                    and row['unmatched_responses'] == 0 and row['reader_eof'] is True)
                shutdowns.append(row)
            crash = raw.get('intentional_crash')
            if isinstance(crash, dict):
                intentional_crashes.append({'round': number, 'arm': arm,
                    'reported_fields': {key: crash.get(key) for key in ('exit_code', 'shutdown_method',
                        'observed_descendant_survivors', 'reader_error', 'unmatched_responses')},
                    'full_original_retained_in': raw_name})
        if audit is not None:
            item['original_audit_counts'] = {key: audit.get(key) for key in COUNTER_KEYS}
            item['original_audit_limitations'] = audit.get('not_covered', audit.get('limitations'))
            if raw_name in data:
                check(audit.get('source_sha256') == sha(data[raw_name])
                      and audit.get('source_bytes') == len(data[raw_name]),
                      directory + ': original independent audit source identity differs')
            if raw is not None:
                check(audit.get('candidate_sha256') == raw.get('candidate_sha256'),
                      directory + ': raw/audit candidate identity differs')
            if positive:
                check(raw is not None and raw.get('passed') is True and audit.get('verified') is True
                      and raw.get('automatic_rpc_retries') == audit.get('automatic_rpc_retries') == 0,
                      directory + ': positive original raw/audit closure incomplete')
        elif positive:
            errors.append(directory + ': positive original independent audit missing')
        rounds.append(item)
    counters = {}
    for key in COUNTER_KEYS:
        values = [row.get('original_audit_counts', {}).get(key) for row in rounds]
        counters[key] = sum(values) if values and all(type(value) is int for value in values) else None
    counts = {'captured_round_reports': sum(row['raw_report_present'] for row in rounds),
              'captured_round_audits': sum(row['independent_analysis_present'] for row in rounds),
              'original_declared_rounds': len(declared), 'original_audit_count_sums': counters,
              'count_sums_cover_all_four_round_audits': len(rounds) == 4
                  and all(row['independent_analysis_structured'] for row in rounds)}
    monitor_count = monitor.get('sample_count') if monitor is not None else None
    if monitor is not None:
        check(type(monitor_count) is int and isinstance(monitor.get('samples'), list)
              and monitor_count == len(monitor['samples']), 'LC monitor declared/raw sample count differs')
    if monitor_audit is not None:
        binding(monitor_audit.get('ledger'), 'LC monitor audit ledger', 'lifecycle-campaign-01/compiler-monitor.json')
        if monitor_count is not None:
            check(monitor_audit.get('validation', {}).get('validated_sample_count') == monitor_count,
                  'LC monitor original audit sample count differs')
    expected_count = ACTUAL.get('compiler_monitor_sample_count')
    if expected_count is not None:
        check(monitor_count == expected_count, 'sealed and captured LC monitor count differs')
    if positive:
        check(tests is not None and tests.get('passed') is True and tests.get('tests_run') == 14
              and tests.get('skipped') == tests.get('errors') == tests.get('failures') == 0,
              'positive LC lacks all 14 original tool-test results')
        check(normal is not None and normal.get('passed') is True and normal.get('inputs_unchanged') is True
              and index is not None and index.get('closed') is True and len(rounds) == 4
              and descriptive is not None and descriptive.get('verified') is True
              and gate_verified is True and gate_passed is True,
              'positive LC parent lacks complete original normal ABBA gates')
        check(monitor is not None and monitor_audit is not None
              and monitor_audit.get('validation', {}).get('passed') is True,
              'positive LC parent lacks original compiler-monitor closure')
    failed_comparison_flags = []
    for name, comparison in (gates.get('comparisons', {}) if gates is not None else {}).items():
        if isinstance(comparison, dict):
            for gate_name, passed in comparison.get('gates', {}).items():
                if passed is False:
                    failed_comparison_flags.append({'comparison': name, 'gate': gate_name,
                        'adoption_required': comparison.get('adoption_required'), 'reported_passed': False})
    errors.extend(row['member'] + ': retained original JSON cannot be interpreted' for row in parse_errors)
    return {'kind': kind, 'original_lifecycle_holder_job_id': HOLDER_JOB,
        'workflow_reported_passed': reported_parent_passed, 'parent_reported_adoption_passed': reported_adoption,
        'normal_lifecycle_gate_verified': gate_verified, 'normal_lifecycle_gate_passed': gate_passed,
        'reported_rejection_reasons': gates.get('rejection_reasons', gates.get('failures')) if gates is not None else None,
        'derived_failed_original_comparison_flags': failed_comparison_flags,
        'derived_flags_scope': 'Lists false flags in the original gate report; thresholds and performance are not recomputed.',
        'candidate_adopted_by_archiver': False, 'final_publication_or_adoption_decision': None,
        'original_native_terminal': native_receipt, 'original_holder_completion': completion,
        'original_materializer_terminal': materializer_receipt,
        'original_holder_report': {key: holder.get(key) for key in ('schema', 'passed', 'remote_returncode',
            'holder_script_sha256', 'remote_script_sha256', 'automatic_ssh_retries', 'services_modified',
            'owned_agent_reaped', 'owned_agent_returncode', 'owned_agent_socket_absent_after_context',
            'owned_agent_directory_absent_after_context')} if holder is not None else None,
        'full_Mac_holder_log_bodies_copied_here': False,
        'Mac_holder_log_identities_retained_in_original_holder_report': holder is not None,
        'parent_stages': parent_stages, 'normal_ABBA_stages': normal_stages,
        'tool_tests_reported': {key: tests.get(key) for key in ('schema', 'passed', 'tests_run',
            'skipped', 'errors', 'failures')} if tests is not None else None,
        'counts': counts, 'rounds': rounds, 'original_normal_lifecycle_gates': gates,
        'normal_descriptive_summary': {'identity': identity('lifecycle-abba-01/summary.json'),
            'schema': descriptive.get('schema'), 'verified': descriptive.get('verified')} if descriptive is not None else None,
        'compiler_monitor': {'sample_count': monitor_count,
            'original_ledger_identity': identity('lifecycle-campaign-01/compiler-monitor.json') if monitor is not None else None,
            'original_audit': monitor_audit,
            'reported_parent_monitor': parent.get('compiler_monitor') if parent is not None else None},
        'shutdowns': shutdowns, 'missing_standard_shutdown_evidence': missing_shutdowns,
        'all_observed_standard_shutdowns_clean': all(row['reported_clean_shutdown'] for row in shutdowns) if shutdowns else None,
        'all_four_rounds_and_eight_standard_shutdowns_observed': len(rounds) == 4 and len(shutdowns) == 8,
        'intentional_crashes': intentional_crashes, 'source_snapshots': snapshots,
        'original_parent_error': parent.get('error') if parent is not None else None,
        'original_parent_finalization_error': parent.get('finalization_error') if parent is not None else None,
        'original_normal_error': normal.get('error') if normal is not None else None,
        'original_saturation_verified_field': parent.get('saturated_cancellation_verified') if parent is not None else None,
        'source_and_measurement_flags': {key: parent.get(key) for key in ('inputs_unchanged', 'source_inputs_unchanged',
            'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'automatic_retries',
            'production_services_modified')} if parent is not None else None,
        'captured_namespace_presence': namespace,
        'unavailable_core_originals_at_capture': [name for name in CORE_FILES if name not in data],
        'unarchived_identity_references': list(external.values()),
        'original_json_parse_errors': parse_errors, 'archived_receipt_binding_errors': errors,
        'original_qualification_archive_sha256': QUALIFICATION_ARCHIVE_SHA,
        'original_exact_ci_archive_sha256': CI_ARCHIVE_SHA,
        'original_observation_archive_sha256': OBSERVATION_ARCHIVE_SHA,
        'scope': {'raw_results_modified': False, 'tests_or_benchmarks_rerun': False,
            'original_auditors_reexecuted': False, 'archived_programs_executed': False,
            'separate_saturation_campaign_included': False, 'qualification_ELFs_or_source_trees_repeated': False,
            'known_OBS_success_is_not_lifecycle_success': True, 'limits_and_original_thresholds_changed': False},
        'limitations': limitations}

def create_archive():
    require_sealed()
    need(SEALED and HOLDER_JOB is not None and set(DYNAMIC_REQUIRED) <= set(PINNED)
         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),
         'unsealed R35 lifecycle collector: original receipt identities are still missing')
    base = ROOT / 'lifecycle-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded, namespace = collect()
    compact = summary('lifecycle', data, namespace)
    manifest = {'schema': 'hepta-r35-normal-lifecycle-evidence-archive/v1', 'kind': 'lifecycle',
        'source_root': str(ROOT), 'external_source_root': str(R16), 'external_archive_prefix': EXTERNAL_PREFIX,
        'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,
        'protocol_reference_sha256': PROTOCOL_REFERENCE_SHA,
        'frozen_fixture_source_root': str(FROZEN), 'frozen_fixture_archive_prefix': FROZEN_PREFIX,
        'selected_bytes': sum(map(len, data.values())),
        'limits': {'total_bytes': MAX_TOTAL, 'file_bytes': MAX_FILE, 'files': MAX_FILES},
        'selection': {'required_files': list(REQUIRED), 'r35_directories': list(SELECTED_DIRS),
            'r16_directories': list(EXTERNAL_DIRS), 'optional_r35_files': list(OPTIONAL_FILES)},
        'namespace_state': namespace, 'excluded': excluded,
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
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL, 'archive/sidecars exceed 64 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archived': True, 'kind': 'lifecycle', 'archive': str(outputs[0]), 'bytes': len(archive_raw),
        'sha256': sha(archive_raw), 'manifest_sha256': sha(manifest_raw), 'compact_sha256': sha(compact_raw),
        'original_job_id': HOLDER_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'normal_lifecycle_gate_passed': compact['normal_lifecycle_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors']}


def verify_archive(path, expected_sha):
    require_sealed()
    need(SEALED, 'unsealed R35 lifecycle collector: actual original receipts are missing')
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
                need(manifest['schema'] == 'hepta-r35-normal-lifecycle-evidence-archive/v1'
                     and manifest['kind'] == 'lifecycle'
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
    compact = summary(manifest['kind'], data, manifest['namespace_state'])
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
        'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
        'original_job_id': HOLDER_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'normal_lifecycle_gate_passed': compact['normal_lifecycle_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('lifecycle',))
    mode.add_argument('--verify', type=Path)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    if args.verify is not None:
        need(args.expected_sha256 is not None, '--expected-sha256 from the original archive receipt is required')
        result = verify_archive(args.verify.absolute(), args.expected_sha256)
    else:
        need(args.expected_sha256 is None, '--expected-sha256 is only for verification')
        result = create_archive()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
