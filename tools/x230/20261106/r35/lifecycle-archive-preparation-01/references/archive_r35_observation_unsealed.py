#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R35 ordinary OBS snapshot without rerunning it.

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
REFERENCE_SHA = 'bcd3bc3f0e9606d94be8bbbe45f719dbe4798a540e95f9ca596362f8d4d89f32'
QUALIFICATION_ARCHIVE_SHA = 'a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a'
CI_ARCHIVE_SHA = 'f5f569ccd51d3f2f8cdb11aee115967f0df367a04cf0fd9f50c21a8b5d86d42f'
ACTUAL = None
HOLDER_JOB = ACTUAL['holder_job_id'] if ACTUAL is not None else None
SEALED = ACTUAL is not None
STAGES = ('native-observation', 'native-audit', 'native-boundary', 'boundary-audit',
          'cancel-recovery', 'recovery-audit', 'observation-summary')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SELECTED_DIRS = ('campaign-01', 'tools-01', 'boundary-tools-01', 'lifecycle-tools-01')
EXTERNAL_DIRS = ('measurement-tools', 'boundary-tools', 'r35-cancel-recovery-01')
OPTIONAL_FILES = ('qualification-compact-01.json',)
NAMESPACE_PATHS = ('lifecycle-inputs-01.json', 'lifecycle-campaign-01', 'lifecycle-abba-01',
                   'lifecycle-materialization-native-01.json', 'lifecycle-materialization-read-01.json')

STATIC_PINS = {
 "boundary-tools-01/audit_native_boundary.py": "8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee",
 "boundary-tools-01/capacity-policy.json": "206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3",
 "boundary-tools-01/harness-freeze.json": "77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1",
 "boundary-tools-01/run_native_boundary.py": "2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329",
 "boundary-tools-01/test_native_boundary.py": "cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd",
 "campaign-inputs-01.example.json": "27897ee74e6abd9a7aff24359eaa16c86a4b9471eb95b15117721d7eaef059c1",
 "campaign-inputs-01.json": "eec0348217f6c679d1f965004f1bd8ecded2886fc1c654d45a9ad6ea700391e4",
 "candidate/candidate.patch": "89eed62593e1b3c5a675221d1df998d27aae4b6a0fdfa028e297544838fa049a",
 "external/r16/benchmark-topology.json": "8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287",
 "external/r16/boundary-tools/audit_native_boundary.py": "8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee",
 "external/r16/boundary-tools/capacity-policy.json": "206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3",
 "external/r16/boundary-tools/harness-freeze.json": "77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1",
 "external/r16/boundary-tools/run_native_boundary.py": "2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329",
 "external/r16/boundary-tools/test_native_boundary.py": "cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd",
 "external/r16/measurement-tools/allocator_environment.py": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525",
 "external/r16/measurement-tools/allocator_environment_audit.py": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727",
 "external/r16/measurement-tools/analyze_native_observation.py": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66",
 "external/r16/measurement-tools/audit_native_evidence.py": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28",
 "external/r16/measurement-tools/observation_resources.py": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894",
 "external/r16/measurement-tools/owned_ssh_interruption.py": "1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b",
 "external/r16/measurement-tools/run_native_observation.py": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb",
 "external/r16/measurement-tools/run_six_host_cancel_recovery.py": "698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12",
 "external/r16/measurement-tools/test_native_harness.py": "2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00",
 "external/r16/measurement-tools/verify_cancel_recovery.py": "0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c",
 "external/r16/measurement-tools/x230_observation_benchmark.py": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed",
 "external/r16/measurement-tools/x230_six_running_recovery_canary.py": "6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4",
 "lifecycle-inputs-01.example.json": "7b4d6ef124a2ada384100d59fdd71a325ae2f8c162d6ef2656bcbd2a41c9173a",
 "lifecycle-tools-01/README.md": "bf5ece8988afa5a91f01da1df0e1740add1390f6653d32c7bd562d99b11529be",
 "lifecycle-tools-01/allocator_environment.py": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525",
 "lifecycle-tools-01/allocator_environment_audit.py": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727",
 "lifecycle-tools-01/analyze_lifecycle_gates.py": "c7a861a94a89dd81debb5c055773918d89a1c9c29b699e2e5a0341e51be69553",
 "lifecycle-tools-01/analyze_native_observation.py": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66",
 "lifecycle-tools-01/audit_native_evidence.py": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28",
 "lifecycle-tools-01/cancel_saturation_gate.py": "536ebdc5f2b090a8c007f189a895ed2e19d7b8b7e41530ccba94dd826742ef7f",
 "lifecycle-tools-01/lifecycle-gate-policy.json": "36658346c4e265bf551a1ae1a4c6210bec8e4729f7961302a203008741cd381e",
 "lifecycle-tools-01/lifecycle-tools-manifest-01.json": "eb50cd7ab0376c4b3dc768e8d184fdc23eeaa90c2ce5bdd4b9e9ac551448504e",
 "lifecycle-tools-01/observation_resources.py": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894",
 "lifecycle-tools-01/owned_ssh_interruption.py": "1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b",
 "lifecycle-tools-01/run_lifecycle_abba_01.py": "e01357cfb04f72f1ee1d56747df81b572e55c1528d2941f8dbbb0aa5e9a2ac84",
 "lifecycle-tools-01/run_lifecycle_tool_tests.py": "e3c1e8163249dba14672a3a82b43a2d7b8b4c0802b94b8511bf3db668f865a2d",
 "lifecycle-tools-01/run_native_observation.py": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb",
 "lifecycle-tools-01/run_six_host_cancel_recovery.py": "698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12",
 "lifecycle-tools-01/run_six_host_cancel_recovery_timed.py": "54186d9750952061b54b255a509848ce72a252d676f584dd288edd263883c0d8",
 "lifecycle-tools-01/run_six_host_cancel_saturation.py": "ae195c895ab58d3bf067e37f30520bf572fd86b6282722dee9a56acc62df85a0",
 "lifecycle-tools-01/source-provenance.json": "58d276c8df05dcd95a0a25e6264c3de1b248e8bb821651fb1b52859dd707dbbe",
 "lifecycle-tools-01/status-predicate.json": "5828c7ba2990f38531cce7e1a42b44315ee42278ccaee361ace8d9472a96da34",
 "lifecycle-tools-01/summarize_lifecycle_abba_01.py": "9e050343bb32e7f57148f633ff94bbcfb3a7452b2872ae68404ca642e937af89",
 "lifecycle-tools-01/test_native_harness.py": "2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00",
 "lifecycle-tools-01/test_r25_lifecycle_tools.py": "1845cdb48440a03146e337af7baf916bb9cdb76fb46ea0699f79144cf7197566",
 "lifecycle-tools-01/test_verify_saturation_extension.py": "10f2dcbfa9e2b5c625f22c3edc32c9f8a969509345b20d9b135cebc2235c16fb",
 "lifecycle-tools-01/verify_cancel_recovery.py": "0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c",
 "lifecycle-tools-01/verify_cancel_saturation.py": "d3b6772ddffc711a23aa4aa9566f903c149535a3d3c4cc3466ee73690cbc1e75",
 "lifecycle-tools-01/verify_saturation_extension.py": "23dfd25517b517067a4fbb3f4a3227f12bafff46b828eb05f7bf322596124e6a",
 "lifecycle-tools-01/x230_observation_benchmark.py": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed",
 "lifecycle-tools-01/x230_six_running_recovery_canary.py": "6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4",
 "parent-tools-install-01.json": "542fee8a1f146105125e402be5d7892709b76ff29ae273b162ffc4bff4f16bed",
 "preparation.json": "4770faa3c73ec2e9287fd43154ad5f9b6df149d85767ddb5f18e6aeb153ea1cc",
 "prepare_qualify.py": "6870655895432c8bd3ca266d00eb4a68b3150619352306c997a81ca0487130f4",
 "qualification-01/isolated-tests/summary.json": "10eb5d260f26f15cfea9334ddc6f22456f22dea54ad1b755e118fd49cc67d904",
 "qualification-01/report.json": "5369433b6eb2db62a907593f1b679f968b411d0cde96ce9eabe8e124420cf8e1",
 "qualification-01/source-map.json": "87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313",
 "qualification-input.json": "652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63",
 "qualification-native-read-01.json": "4275444d755edf7b4893827ff2224fa1d70aee529a6ac2e1be4c0c5989a5a043",
 "qualification-postflight-01.json": "99e198adfeecb2f09b25d928a157a5067ef4a10315b1ead52134721665df630d",
 "qualification-terminal-status-01.json": "8b171dde1644b1c9cacfc126be053484a3649031f946c648db7a69f9be404844",
 "rust-ci-01/nextest-output-audit.json": "545fd10013d912be0e9297429b606e376cbea7bac55b62f78f76c881fe1ffba3",
 "rust-ci-01/report.json": "b619804c79479d2bb529e363d8fa48520b8ef9f351a99729ccba77d5510fec5f",
 "rust-ci-native-01.json": "c19d3490b283df287ba2743d3385f26a83144505ef36ccc874e218359cc94746",
 "rust-ci-native-read-01.json": "31a962dfcbc55ce22b4bb81f5fa05aaacf018c13f17d2dc3f3b49e933d30977b",
 "rust-ci-plan-01.json": "4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28",
 "tools-01/compiler-monitor-policy-01.json": "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368",
 "tools-01/compiler_monitor.py": "afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf",
 "tools-01/compiler_state.py": "9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251",
 "tools-01/install_measurement_tools.py": "1564f7069cab27c6a99806dc07f326d71f8e0da6392fb7b78696c8a2d3ba62f7",
 "tools-01/prepare_campaign_inputs.py": "1449776932b014d70de282d234d82c1a104f3b2f90ddf2c846371d180091f707",
 "tools-01/prepare_lifecycle_inputs.py": "4c2a58793760c106cafbff5ca21813e85372a92391d9c3d3510ba8e46e58210c",
 "tools-01/r35_campaign.py": "3707cbc2e3307a29aa6e645afdf8f6da7a5e80d36e90a86d505bd8f18061778c",
 "tools-01/r35_lifecycle_campaign.py": "372f880ec4679147b06ae89e0df8ec64be74ac79a171704715e6499e79191e29",
 "tools-01/runner-bundle-manifest.json": "0e1ad9df3ae5caddc4edb47ecf1dbf1f41f3c00ad243c197c34d6c136f0597f4",
 "tools-01/summarize_r25_campaign.py": "2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864",
 "tools-01/validate_compiler_monitor.py": "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"
}
DYNAMIC_REQUIRED = ('campaign-01/boundary-audit.stderr',
 'campaign-01/boundary-audit.stdout',
 'campaign-01/cancel-recovery.stderr',
 'campaign-01/cancel-recovery.stdout',
 'campaign-01/compiler-monitor.audit.json',
 'campaign-01/compiler-monitor.json',
 'campaign-01/native-audit.stderr',
 'campaign-01/native-audit.stdout',
 'campaign-01/native-boundary.stderr',
 'campaign-01/native-boundary.stdout',
 'campaign-01/native-boundary/independent-summary.json',
 'campaign-01/native-boundary/report.json',
 'campaign-01/native-observation.stderr',
 'campaign-01/native-observation.stdout',
 'campaign-01/native-observation/independent-summary.json',
 'campaign-01/native-observation/report.json',
 'campaign-01/observation-summary.stderr',
 'campaign-01/observation-summary.stdout',
 'campaign-01/recovery-audit.stderr',
 'campaign-01/recovery-audit.stdout',
 'campaign-01/report.json',
 'campaign-01/summary.json',
 'campaign-inputs-01.json',
 'external/r16/r35-cancel-recovery-01/independent-summary.json',
 'external/r16/r35-cancel-recovery-01/report.json',
 'observation-holder-native-01.json',
 'observation-holder-read-01.json',
 'observation-holder-report-01.json',
 'observation-postflight-01.json')
PINNED = {**STATIC_PINS, **(ACTUAL['sha256'] if ACTUAL is not None else {})}
REQUIRED = tuple(sorted(set(STATIC_PINS) | set(DYNAMIC_REQUIRED)))


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
    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R35/R16 mapping')
    return EXTERNAL_PREFIX + path.relative_to(PurePosixPath(str(R16))).as_posix()


def source_path(name):
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name,
         'unsafe selected archive member')
    if name.startswith(EXTERNAL_PREFIX):
        return R16 / name[len(EXTERNAL_PREFIX):]
    need(relative.parts[0] != 'external', 'unexpected external source mapping')
    return ROOT / name


def require_sealed():
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-r35-original-observation-archive-bindings/v1',
         'unsealed R35 collector: actual original receipts are missing')
    need(type(ACTUAL.get('holder_job_id')) is str and ACTUAL['holder_job_id'] and HOLDER_JOB == ACTUAL['holder_job_id'],
         'actual original holder job is missing')
    for key in ('sha256', 'bytes'):
        need(type(ACTUAL.get(key)) is dict and set(ACTUAL[key]) == set(DYNAMIC_REQUIRED),
             'actual receipt identity membership differs')
    need(all(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
             for value in ACTUAL['sha256'].values())
         and all(type(value) is int and 0 <= value <= MAX_FILE for value in ACTUAL['bytes'].values()),
         'malformed actual original identities')
    need(all(type(ACTUAL.get(key)) is bool for key in
         ('workflow_reported_passed', 'observation_gate_passed', 'performance_gates_passed', 'controller_rss_passed'))
         and type(ACTUAL.get('rejection_reasons')) is list, 'actual workflow/gate outcome shape differs')
    counts = ACTUAL.get('native_audit_counts')
    need(type(counts) is dict and set(counts) == {'verified', 'measured_calls', 'warmup_calls',
         'preflight_restart_calls', 'total_calls', 'failed_calls'}
         and type(counts['verified']) is bool
         and all(type(value) is int and value >= 0 for key, value in counts.items() if key != 'verified'),
         'actual native audit counts missing')
    need(type(ACTUAL.get('compiler_monitor_sample_count')) is int and ACTUAL['compiler_monitor_sample_count'] > 0,
         'actual compiler monitor sample count missing')
    need(ACTUAL.get('candidate_adopted') is False and ACTUAL.get('normal_lifecycle_started') is False
         and ACTUAL.get('lifecycle_materialization_started') is False
         and ACTUAL.get('lifecycle_materializer_job_id') is None and ACTUAL.get('normal_lifecycle_job_id') is None
         and ACTUAL.get('normal_lifecycle_state') == 'not_started_at_capture'
         and ACTUAL.get('normal_lifecycle_final_outcome') is None,
         'this collector requires the actual first OBS snapshot before lifecycle launch')


def collect():
    require_sealed()
    need(SEALED, 'unsealed R35 collector: actual original receipts are missing')
    need(ROOT.resolve(strict=True) == ROOT and R16.resolve(strict=True) == R16, 'indirect source root')
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
    for name in SELECTED_DIRS:
        directory(ROOT / name)
    for name in EXTERNAL_DIRS:
        directory(R16 / name)
    for name in OPTIONAL_FILES:
        if os.path.lexists(ROOT / name):
            file(ROOT / name, required=True)
    need(all(stamp(path.lstat()) == value for path, value in snapshots.items()), 'source changed during collection')
    need(namespace == {name: os.path.lexists(ROOT / name) for name in NAMESPACE_PATHS},
         'normal lifecycle output presence changed during collection')
    return payloads, excluded, namespace

def summary(kind, data, namespace):
    require_sealed()
    need(SEALED, 'unsealed R35 collector: actual original receipts are missing')
    need(kind == 'observation' and all(name in data for name in REQUIRED), 'missing fixed observation input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')
    need(all(len(data[name]) == expected for name, expected in ACTUAL['bytes'].items()),
         'actual original input byte lengths differ')
    need(set(namespace) == set(NAMESPACE_PATHS) and all(type(v) is bool for v in namespace.values()),
         'invalid recorded normal-lifecycle namespace inventory')
    read = lambda name: json.loads(data[name])
    parent = read('campaign-01/report.json')
    gates = read('campaign-01/summary.json')
    native = read('campaign-01/native-observation/report.json')
    native_audit = read('campaign-01/native-observation/independent-summary.json')
    boundary = read('campaign-01/native-boundary/report.json')
    recovery = read('external/r16/r35-cancel-recovery-01/report.json')
    monitor = read('campaign-01/compiler-monitor.json')
    monitor_audit = read('campaign-01/compiler-monitor.audit.json')
    postflight = read('observation-postflight-01.json')
    holder = read('observation-holder-report-01.json')
    need(holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1', 'original holder report schema differs')
    need(postflight.get('schema') == 'hepta-r35-observation-postflight/v1'
         and postflight.get('original_observation_job_id') == HOLDER_JOB
         and postflight.get('normal_lifecycle_started') is False
         and postflight.get('lifecycle_materialization_started') is False
         and postflight.get('candidate_adopted') is False
         and postflight.get('normal_lifecycle_state') == 'not_started_at_capture'
         and postflight.get('original_lifecycle_materializer_job_id') is None
         and postflight.get('original_normal_lifecycle_job_id') is None
         and postflight.get('normal_lifecycle_final_outcome') is None,
         'original postflight must retain the actual pre-lifecycle snapshot')
    need(parent.get('schema') == 'hepta-r25-observation-campaign-control/v1' and parent.get('attempt') == '01'
         and parent.get('finished_utc') and type(parent.get('passed')) is bool
         and gates.get('schema') == 'hepta-r25-observation-gates/v1'
         and type(gates.get('observation_gate_passed')) is bool, 'original campaign/gate schema differs')
    errors = []

    def binding(identity, label):
        try:
            name = member_path(identity['path'])
            raw = data[name]
            need(identity['bytes'] == len(raw) and identity['sha256'] == sha(raw), 'identity differs')
        except (KeyError, TypeError, ValueError):
            errors.append(label + ': archived bytes do not match reported identity')

    for key, value in gates['evidence'].items():
        binding(value, 'gate evidence ' + key)
    for key in ('input_receipt', 'summary'):
        binding(parent[key], 'parent ' + key)
    for key in ('ledger', 'independent_audit'):
        binding(parent['compiler_monitor'][key], 'compiler monitor ' + key)
    for key, value in parent['compiler_monitor']['sources'].items():
        binding(value, 'compiler monitor source ' + key)
    if parent.get('observation_gate_passed') != gates['observation_gate_passed']:
        errors.append('parent and gate outcomes differ')
    if parent.get('thresholds') != gates.get('thresholds'):
        errors.append('parent and original gate thresholds differ')

    stages = []
    for index, row in enumerate(parent.get('stages', [])):
        for key in ('stdout', 'stderr'):
            if key in row:
                binding(row[key], 'stage %d %s' % (index, key))
        for value in row.get('output_bindings', []):
            binding(value, 'stage %d output' % index)
        stages.append({key: row.get(key) for key in ('name', 'passed', 'returncode', 'timed_out',
            'waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent',
            'cleanup_signals', 'cleanup_error', 'error', 'elapsed_seconds')})
    if [row['name'] for row in stages] != list(STAGES):
        errors.append('the seven original workflow stages are not all retained')

    cells, failed_calls, shutdowns = [], [], []

    def shutdown(value, label):
        capture = value.get('transport_capture', {})
        row = {key: value.get(key) for key in ('exit_code', 'shutdown_method',
            'observed_descendant_survivors', 'reader_error', 'unmatched_responses')}
        row.update(label=label, reader_eof=capture.get('reader_eof'))
        row['reported_clean_shutdown'] = (row['exit_code'] == 0 and row['shutdown_method'] == 'stdin_eof'
            and row['observed_descendant_survivors'] == [] and row['reader_error'] is None
            and row['unmatched_responses'] == 0 and row['reader_eof'] is True)
        shutdowns.append(row)

    for round_ in native['rounds']:
        for cell in round_['cells']:
            rows = cell['rows']
            good = sum(row.get('okay') is True for row in rows)
            descriptor = {'round': round_['index'], 'arm': round_['version'], 'concurrency': cell['concurrency']}
            cells.append(dict(descriptor, declared_calls=cell['calls'], retained_call_rows=len(rows),
                              declared_successes=cell['successes'], successful_rows=good))
            if cell['calls'] != len(rows) or cell['successes'] != good:
                errors.append('cell declared and raw call counts differ: ' + str(descriptor))
            failed_calls.extend(dict(descriptor, call=row) for row in rows if row.get('okay') is not True)
        for name in ('shutdown', 'restart_shutdown'):
            shutdown(round_.get(name, {}), 'observation round %s %s %s' % (round_['index'], round_['version'], name))
    for name in ('shutdown', 'restart_shutdown'):
        shutdown(boundary.get(name, {}), 'boundary ' + name)
    for name in ('shutdown', 'after_cancel_shutdown'):
        shutdown(recovery.get(name, {}), 'cancel-recovery ' + name)
    counts = {'rounds': len(native['rounds']), 'cells': len(cells),
        'calls': sum(row['retained_call_rows'] for row in cells),
        'successes': sum(row['successful_rows'] for row in cells), 'failed_calls': len(failed_calls)}
    if counts != {'rounds': 4, 'cells': 12, 'calls': 2304, 'successes': 2304, 'failed_calls': 0}:
        errors.append('original fixed ABBA observation call inventory differs')
    if native_audit.get('measured_calls') != counts['calls']:
        errors.append('independent native audit measured-call count differs')

    native_receipts = {}
    for label, prefix, job in (
        ('observation-01', 'observation-holder', HOLDER_JOB),
    ):
        attempt = '01'
        original = read(prefix + '-native-' + attempt + '.json')
        stream = read(prefix + '-read-' + attempt + '.json')
        receipt = terminal(original, job)
        receipt['original_streams'] = streams_from_reads(original, [stream])
        lines = [json.loads(line) for line in stream['stdout']['text'].splitlines() if line]
        receipt['holder_completion'] = lines[-1] if lines else None
        native_receipts[label] = receipt

    holder_completion = native_receipts['observation-01']['holder_completion'] or {}
    if any(holder_completion.get(key) != holder.get(key) for key in ('passed', 'remote_returncode', 'owned_agent_reaped')):
        errors.append('original holder completion and full holder report differ')
    if holder.get('remote_script_sha256') != PINNED['tools-01/r35_campaign.py']:
        errors.append('original holder executed a different parent source')
    for name, identity in postflight.get('originals', {}).items():
        if name in data:
            binding(identity, 'postflight original ' + name)
    if any(namespace.values()):
        errors.append('normal lifecycle/materialization paths exist despite the original unrun postflight')
    if set(postflight.get('normal_lifecycle_paths_absent', [])) != set(NAMESPACE_PATHS[:3]):
        errors.append('original postflight lifecycle absence inventory differs')
    if postflight.get('observation_gate_passed') != gates['observation_gate_passed']:
        errors.append('original postflight and observation gate differ')
    if monitor.get('sample_count') != len(monitor.get('samples', [])):
        errors.append('compiler monitor declared and retained sample counts differ')
    expected_counts = {key: native_audit.get(key) for key in
        ('verified', 'measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')}
    if expected_counts != ACTUAL['native_audit_counts'] or expected_counts != postflight.get('native_audit_counts'):
        errors.append('actual/postflight/native audit counts differ')
    if (parent['passed'] != ACTUAL['workflow_reported_passed']
            or gates['observation_gate_passed'] != ACTUAL['observation_gate_passed']
            or gates.get('performance_gates_passed') != ACTUAL['performance_gates_passed']
            or gates.get('rejection_reasons') != ACTUAL['rejection_reasons']
            or gates['controller_rss'].get('passed') != ACTUAL['controller_rss_passed']
            or postflight.get('performance_gates_passed') != ACTUAL['performance_gates_passed']
            or postflight.get('rejection_reasons') != ACTUAL['rejection_reasons']
            or postflight.get('controller_rss_passed') != ACTUAL['controller_rss_passed']):
        errors.append('actual/postflight/original performance outcome differs')
    if (monitor.get('sample_count') != ACTUAL['compiler_monitor_sample_count']
            or postflight.get('compiler_monitor_sample_count') != ACTUAL['compiler_monitor_sample_count']
            or monitor_audit.get('validation', {}).get('validated_sample_count') != ACTUAL['compiler_monitor_sample_count']):
        errors.append('actual/postflight/compiler monitor sample count differs')
    binding(monitor_audit.get('ledger', {}), 'monitor audit ledger')
    if monitor_audit.get('ledger') != parent['compiler_monitor'].get('ledger'):
        errors.append('parent and monitor audit ledger identities differ')
    if postflight.get('normal_lifecycle_path_presence') != namespace:
        errors.append('postflight and captured lifecycle namespaces differ')
    if not postflight.get('lifecycle_nonlaunch_source'):
        errors.append('original coordinator lifecycle nonlaunch source missing')
    cpu_passed = all(case.get('controller_cpu_regression_gate_passed') is True for case in gates['cases'])
    rss_passed = gates['controller_rss'].get('passed') is True
    gate_passed = gates['observation_gate_passed']
    return {
        'kind': kind, 'original_observation_holder_job_id': HOLDER_JOB,
        'workflow_reported_passed': parent['passed'], 'observation_gate_passed': gate_passed,
        'performance_gates_passed': gates.get('performance_gates_passed'),
        'outcome': 'rejected_by_original_observation_gate' if not gate_passed else 'observation_gate_passed_only',
        'candidate_adopted': False, 'rejection_reasons': gates.get('rejection_reasons'),
        'correctness_verified': gates.get('correctness_verified'), 'evidence_verified': gates.get('evidence_verified'),
        'controller_cpu_gates_passed': cpu_passed, 'controller_rss_gate_passed': rss_passed,
        'cases': gates['cases'], 'controller_rss': gates['controller_rss'], 'thresholds': gates['thresholds'],
        'binary_sha256': gates['binary_sha256'], 'counts': counts, 'cells': cells, 'failed_calls': failed_calls,
        'original_native_audit_counts': {key: native_audit.get(key) for key in
            ('verified', 'measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')},
        'workflow_stages': stages,
        'compiler_monitor': {key: monitor.get(key) for key in ('passed', 'sample_count', 'compiler_records',
            'errors', 'errors_dropped', 'missed_scheduled_slots', 'required_slots_through_parent_end',
            'observed_required_slots', 'covers_parent_lifecycle', 'thread_joined', 'signals_sent',
            'thread_cpu_seconds_per_wall_second', 'statement_scope')},
        'original_compiler_monitor_audit': monitor_audit,
        'shutdowns': shutdowns, 'all_recorded_standard_shutdowns_clean': all(row['reported_clean_shutdown'] for row in shutdowns),
        'original_recovery_intentional_crash': recovery.get('intentional_crash'),
        'boundary_correctness': gates['boundary'], 'cancel_recovery_correctness_canary': gates['lifecycle'],
        'native_receipts': native_receipts,
        'original_holder_report': {key: holder.get(key) for key in ('schema', 'passed',
            'holder_script_sha256', 'remote_script_sha256', 'remote_returncode', 'automatic_ssh_retries',
            'services_modified', 'owned_agent_reaped', 'owned_agent_returncode',
            'owned_agent_directory_absent_after_context', 'owned_agent_socket_absent_after_context')},
        'holder_log_identities_retained_in_full_report': True,
        'mac_holder_log_file_bodies_copied_into_this_archive': False,
        'normal_lifecycle': {'materialization_job_id': None,
            'materialization_native_state': None, 'materialization_native_exit_code': None,
            'materialization_started': False, 'normal_lifecycle_started': False,
            'state': 'not_started_at_capture',
            'disposition': postflight.get('normal_lifecycle_disposition'),
            'nonlaunch_source': postflight.get('lifecycle_nonlaunch_source'),
            'final_outcome': None,
            'original_postflight': {'bytes': len(data['observation-postflight-01.json']),
                                   'sha256': sha(data['observation-postflight-01.json'])},
            'output_presence_observed_during_collection': namespace,
            'performance_ABBA_established': None, 'saturation_established': None},
        'source_and_measurement_flags': {key: parent.get(key) for key in ('inputs_unchanged', 'source_inputs_unchanged',
            'baseline_source_inputs_unchanged', 'measurement_attribution_valid', 'automatic_retries',
            'saturated_cancellation_verified', 'production_services_modified')},
        'quiescence': {key: parent.get('quiescence', {}).get(key) for key in ('seconds_planned', 'passed', 'start_monotonic_ns', 'end_monotonic_ns')},
        'archived_receipt_binding_errors': errors,
        'original_qualification_archive_sha256': QUALIFICATION_ARCHIVE_SHA,
        'original_exact_ci_archive_sha256': CI_ARCHIVE_SHA,
        'scope': {'raw_results_modified': False, 'tests_or_benchmarks_rerun': False,
            'archived_programs_executed': False, 'original_auditors_reexecuted': False,
            'legacy_shared_harness_schemas_retained': True,
            'causal_attribution': 'This original OBS snapshot does not establish causality or final adoption.',
            'hosted_actions_passed': False,
            'qualification_case_logs_and_test_ELFs_repeated_here': False},
    }

def create_archive():
    require_sealed()
    need(SEALED and HOLDER_JOB is not None and set(DYNAMIC_REQUIRED) <= set(PINNED)
         and all(isinstance(value, str) and len(value) == 64 for value in PINNED.values()),
         'unsealed R35 collector: original receipt identities are still missing')
    base = ROOT / 'observation-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded, namespace = collect()
    compact = summary('observation', data, namespace)
    manifest = {'schema': 'hepta-r35-observation-evidence-archive/v1', 'kind': 'observation',
        'source_root': str(ROOT), 'external_source_root': str(R16), 'external_archive_prefix': EXTERNAL_PREFIX,
        'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,
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
    return {'archived': True, 'kind': 'observation', 'archive': str(outputs[0]), 'bytes': len(archive_raw),
        'sha256': sha(archive_raw), 'manifest_sha256': sha(manifest_raw), 'compact_sha256': sha(compact_raw),
        'original_job_id': HOLDER_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'observation_gate_passed': compact['observation_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors']}


def verify_archive(path, expected_sha):
    require_sealed()
    need(SEALED, 'unsealed R35 collector: actual original receipts are missing')
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
                need(manifest['schema'] == 'hepta-r35-observation-evidence-archive/v1'
                     and manifest['kind'] == 'observation'
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
        'observation_gate_passed': compact['observation_gate_passed'], 'counts': compact['counts'],
        'receipt_binding_errors': compact['archived_receipt_binding_errors'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('observation',))
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
