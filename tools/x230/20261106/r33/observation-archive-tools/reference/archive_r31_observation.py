#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Archive the original R31 observation and rejection evidence without rerunning it.

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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r31')
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
EXTERNAL_PREFIX = 'external/r16/'
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
REFERENCE_SHA = 'f1b542cf0abfb7f761c1493bf65c95a446a9d37a8f3ead524a5cfbb470eb4dce'
QUALIFICATION_ARCHIVE_SHA = 'f802c5fed5e3b79773825a12cbe9c888570e3ea19f954009857350e93c8071d2'
CI_ARCHIVE_SHA = '2d2fd850b04e3e31374c0336f48f7e9d66f0589e4d04764e88a5b913444d6c91'
HOLDER_01_JOB = '1a1ae37dda9-fc05-5e42'
HOLDER_02_JOB = '1a1ae66710c-fc05-5f6e'
LIFECYCLE_MATERIALIZATION_JOB = '1a1ae6ce842-fc05-5f8b'
STAGES = ('native-observation', 'native-audit', 'native-boundary', 'boundary-audit',
          'cancel-recovery', 'recovery-audit', 'observation-summary')
SKIP_DIRS = {'source', 'target', 'target-build', 'test-binaries', 'profile', 'profiles',
             '.ssh', 'credentials', 'secrets', 'keys', '.git', '__pycache__'}
SKIP_FILES = {'runtime.json', 'runtime-config.json', 'ssh_config', 'known_hosts',
              'credentials.json', 'secrets.json', 'id_rsa', 'id_ed25519', 'id_ecdsa',
              'agent.sock', 'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
SELECTED_DIRS = ('campaign-01', 'campaign-02', 'tools-01', 'tools-02',
    'boundary-tools-01', 'boundary-tools-02', 'lifecycle-tools-01', 'lifecycle-tools-02')
EXTERNAL_DIRS = ('measurement-tools', 'boundary-tools', 'r31-cancel-recovery-02')
OPTIONAL_FILES = ('campaign-inputs-01.example.json', 'campaign-inputs-02.example.json',
    'lifecycle-inputs-01.example.json', 'qualification-compact-01.json', 'qualification-compact-02.json')
NAMESPACE_PATHS = ('lifecycle-inputs-02.json', 'lifecycle-campaign-02', 'lifecycle-abba-02')

PINNED = {'boundary-tools-02/audit_native_boundary.py': '8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee',
 'boundary-tools-02/capacity-policy.json': '206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3',
 'boundary-tools-02/harness-freeze.json': '77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1',
 'boundary-tools-02/run_native_boundary.py': '2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329',
 'boundary-tools-02/test_native_boundary.py': 'cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd',
 'campaign-01/report.json': '8fb90cf4358b210942343c9da76f40d3c3fe61d751c8c68ab00d65110abc46df',
 'campaign-02/boundary-audit.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/boundary-audit.stdout': '56502823274246d52573854d3cebafd642a0876ec306c5191f3593650dbb1998',
 'campaign-02/cancel-recovery.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/cancel-recovery.stdout': '0a4e9fad26d01198d639fc66f86fa64a1921b0a96763f1eb389460a2b384dcd3',
 'campaign-02/compiler-monitor.audit.json': 'bd6db9a05ea65138b48b8cb619c5279d2d117b7414f047069678bddbbd9fca33',
 'campaign-02/compiler-monitor.json': 'c10b73ccd8483e2426aead543dd42092560c25de742ce702b461d3a05ee1c516',
 'campaign-02/native-audit.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/native-audit.stdout': '6d8ff1d4cdf6662fb0ad4b9c2a91657f0d8672691b6bc770356d0adacc36fc1a',
 'campaign-02/native-boundary.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/native-boundary.stdout': 'c7445b5d8d18641b41c987c355937a0266c8688acb68b2b3d84168fd5d1523b2',
 'campaign-02/native-boundary/independent-summary.json': '50c35ab5bfb3b377da187068bdd1ea5f066091f7db30e15b51bbbfd69aa2ecd4',
 'campaign-02/native-boundary/report.json': '4913df734e923da12fc061dd90367daa15fb2221193c8b180891d57314a682a4',
 'campaign-02/native-observation.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/native-observation.stdout': '286f325f7c943efccb04471f0a877646200f52b0304a96f0812577bde7a15f80',
 'campaign-02/native-observation/independent-summary.json': 'a20748b3734d2095d987a7f2393dd5182ee3aaa579c09d05b9b905f5ed4b3fe6',
 'campaign-02/native-observation/report.json': 'e0c29c5be7967ddcc272955c810bd156b14e6b3491adfba82805ee5a7c2115cf',
 'campaign-02/observation-summary.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/observation-summary.stdout': '3e167ffc61d1d35e6b63d75241087cb51a1648ea69b77f181cda1f753e401d56',
 'campaign-02/recovery-audit.stderr': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
 'campaign-02/recovery-audit.stdout': 'ae31b3cae3736f3cd379974a0535cb033d0dc88c6be063c40adbf81ab89d4d92',
 'campaign-02/report.json': 'd52a34b1b5a5870f1676d1b060744834901bc7982ff967ec82fc492ee89321d1',
 'campaign-02/summary.json': 'a35f08d2ad7afa70bd3e1f806709a355643febff549eba52bbdab91dd74c0b30',
 'campaign-inputs-01.json': 'd9b18804f1e0ced459ef59af53d3245f24bf8bf416b74a9790d9a9280593bfe2',
 'campaign-inputs-02.json': '92058eb2f07217e1b68e934b758181bc98b2f65f4f1797d10e13115f02f6a5f6',
 'external/r16/benchmark-topology.json': '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287',
 'external/r16/boundary-tools/audit_native_boundary.py': '8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee',
 'external/r16/boundary-tools/capacity-policy.json': '206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3',
 'external/r16/boundary-tools/harness-freeze.json': '77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1',
 'external/r16/boundary-tools/run_native_boundary.py': '2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329',
 'external/r16/boundary-tools/test_native_boundary.py': 'cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd',
 'external/r16/measurement-tools/allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
 'external/r16/measurement-tools/allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
 'external/r16/measurement-tools/analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
 'external/r16/measurement-tools/audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
 'external/r16/measurement-tools/observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
 'external/r16/measurement-tools/owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
 'external/r16/measurement-tools/run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
 'external/r16/measurement-tools/run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
 'external/r16/measurement-tools/test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
 'external/r16/measurement-tools/verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
 'external/r16/measurement-tools/x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
 'external/r16/measurement-tools/x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4',
 'external/r16/r31-cancel-recovery-02/independent-summary.json': 'e436aef18388cc8500b1a00d9bfc469e668327c445b9e718bda408af696f6220',
 'external/r16/r31-cancel-recovery-02/report.json': '656a89a6e965ff62a75674c29c36ddc39b7962e444cbfe0b3c4b40d8860e536d',
 'lifecycle-inputs-02.example.json': 'bd8784cdb45425d245fb2a9143c443af0338ba424af568c69ac9e20173a0399a',
 'lifecycle-materialization-native-01.json': 'c1c736016a9d30364091077486c9d061f94a4d5094bbd65b7ff871393bbe379b',
 'lifecycle-materialization-read-01.json': '34ce92c2b5532f3db7983a8e8889ed11cf0aedf36eb25f09a72986146cda3e7f',
 'observation-holder-native-01.json': '33b1f440fa260db903c66d8c4472a19abc0a86d07ec9dfde883a4f481b253e96',
 'observation-holder-native-02.json': '91d9f5cb0307e38d6bc4c2fe4d3f94b8b6e0671515fff7d0fb162a2743d34b2a',
 'observation-holder-read-01.json': '98aa27b2a03a3f9e890030ee288921dbffa18d36ba2cc16023122a714a47c1af',
 'observation-holder-read-02.json': '0bf23e0e59f7ee81d14a3daad0013c0709b4cb9d16171a809ce40b5fa545361c',
 'parent-tools-install-01.json': '8bb0375f3882269c3b74a0127a37615da1442ff223d47b4d6a9d50394a89b3bd',
 'parent-tools-install-02.json': 'a23dc25f1131f1b51fd013524e209e86243656c2c24f18ba57c59eeb047e5fc9',
 'preparation-02.json': '77bdf6f1b008b65dfbedcac24b7ea3026e3946ad4fbff68ca96e5980b660d003',
 'qualification-01/isolated-tests/summary.json': '7e388326114b5be8abfc835cead435de0c597e8b2124442d4e293360937208d6',
 'qualification-01/report.json': '489e62778972d9a8f4b2908c205b23791a968dbf21dc2bdb995350f29305c5a9',
 'qualification-01/source-map.json': 'a4c654bd8b5057fb6884c36172b198eedcfcddab8e2b291155a4e73146707a3f',
 'qualification-terminal-status-01.json': 'f9f6de27c19b015e072f8169e7155783102d9b2ef3bc6ff2d8705927c0016b4e',
 'tools-01/compiler-monitor-policy-01.json': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368',
 'tools-01/compiler_monitor.py': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf',
 'tools-01/compiler_state.py': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251',
 'tools-01/r31_campaign.py': '26b9aa885e049074c2170026ce3bbc9d8a5c2ffed6726899b74f836f9a977e93',
 'tools-01/runner-bundle-manifest.json': '9c77ff5928f1cfec80bb498f44d1aae675bacc7fbf5177c519ad4431536169c6',
 'tools-01/validate_compiler_monitor.py': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2',
 'tools-02/compiler-monitor-policy-01.json': 'ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368',
 'tools-02/compiler_monitor.py': 'afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf',
 'tools-02/compiler_state.py': '9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251',
 'tools-02/prepare_lifecycle_inputs.py': '5d1f2c3289d0e70dbf66249414a4a0b24fb37e81f4556d09858d1db723284be4',
 'tools-02/r31_campaign.py': 'f9ea103c8de54e363ec63c5c63b236187fc461e2ad9a99fe6cbd5a9c287b0854',
 'tools-02/r31_lifecycle_campaign.py': '398293330300dd9c46264a8e20ee02c510ed143d1974cdcd778b1b28247bf525',
 'tools-02/runner-bundle-manifest.json': '6ba2c155317e0bf7caed1c4bd64153667a6f6a58559c1fdd3c81fa05bf05b1c0',
 'tools-02/summarize_r25_campaign.py': '2418bad36fe4aef75d52c5a00c898ff93fef9bb4b6efb10028105143106a1864',
 'tools-02/validate_compiler_monitor.py': 'd2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2'}
REQUIRED = tuple(PINNED) + ('campaign-01/compiler-monitor.json', 'campaign-01/compiler-monitor.audit.json',
    'lifecycle-tools-01/lifecycle-tools-manifest-01.json', 'lifecycle-tools-02/lifecycle-tools-manifest-01.json')


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
    need(path.is_relative_to(PurePosixPath(str(R16))), 'source outside explicit R31/R16 mapping')
    return EXTERNAL_PREFIX + path.relative_to(PurePosixPath(str(R16))).as_posix()


def source_path(name):
    relative = PurePosixPath(name)
    need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name,
         'unsafe selected archive member')
    if name.startswith(EXTERNAL_PREFIX):
        return R16 / name[len(EXTERNAL_PREFIX):]
    need(relative.parts[0] != 'external', 'unexpected external source mapping')
    return ROOT / name


def collect():
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
    need(kind == 'observation' and all(name in data for name in REQUIRED), 'missing fixed observation input')
    need(all(sha(data[name]) == expected for name, expected in PINNED.items()), 'frozen original input differs')
    need(set(namespace) == set(NAMESPACE_PATHS) and all(type(v) is bool for v in namespace.values()),
         'invalid recorded normal-lifecycle namespace inventory')
    read = lambda name: json.loads(data[name])
    parent = read('campaign-02/report.json')
    gates = read('campaign-02/summary.json')
    prior = read('campaign-01/report.json')
    native = read('campaign-02/native-observation/report.json')
    native_audit = read('campaign-02/native-observation/independent-summary.json')
    boundary = read('campaign-02/native-boundary/report.json')
    recovery = read('external/r16/r31-cancel-recovery-02/report.json')
    monitor = read('campaign-02/compiler-monitor.json')
    monitor_audit = read('campaign-02/compiler-monitor.audit.json')
    need(parent.get('schema') == 'hepta-r25-observation-campaign-control/v1' and parent.get('attempt') == '02'
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
        ('observation-01', 'observation-holder', HOLDER_01_JOB),
        ('observation-02', 'observation-holder', HOLDER_02_JOB),
        ('lifecycle-materialization-01', 'lifecycle-materialization', LIFECYCLE_MATERIALIZATION_JOB),
    ):
        attempt = '02' if label == 'observation-02' else '01'
        original = read(prefix + '-native-' + attempt + '.json')
        stream = read(prefix + '-read-' + attempt + '.json')
        receipt = terminal(original, job)
        receipt['original_streams'] = streams_from_reads(original, [stream])
        if label.startswith('observation'):
            lines = [json.loads(line) for line in stream['stdout']['text'].splitlines() if line]
            receipt['holder_completion'] = lines[-1] if lines else None
        else:
            receipt['stderr_text'] = stream['stderr']['text']
            receipt['original_gate_message_present'] = 'normal observation campaign did not close and pass' in stream['stderr']['text']
        native_receipts[label] = receipt

    if monitor.get('sample_count') != len(monitor.get('samples', [])):
        errors.append('compiler monitor declared and retained sample counts differ')
    cpu_passed = all(case.get('controller_cpu_regression_gate_passed') is True for case in gates['cases'])
    rss_passed = gates['controller_rss'].get('passed') is True
    gate_passed = gates['observation_gate_passed']
    return {
        'kind': kind, 'original_observation_holder_job_id': HOLDER_02_JOB,
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
        'prior_observation_preflight_failure': {'job_id': HOLDER_01_JOB, 'reported_passed': prior.get('passed'),
            'error': prior.get('error'), 'stages': prior.get('stages'), 'quiescence_present': 'quiescence' in prior},
        'native_receipts': native_receipts,
        'normal_lifecycle': {'materialization_job_id': LIFECYCLE_MATERIALIZATION_JOB,
            'materialization_native_state': native_receipts['lifecycle-materialization-01']['state'],
            'materialization_native_exit_code': native_receipts['lifecycle-materialization-01']['exit_code'],
            'blocked_by_original_observation_gate': not gate_passed and native_receipts['lifecycle-materialization-01']['original_gate_message_present'],
            'output_presence_observed_during_collection': namespace,
            'performance_ABBA_established': False, 'saturation_established': False},
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
            'causal_attribution': 'No causal diagnosis follows from this single original rejected campaign.',
            'hosted_actions_passed': False,
            'qualification_case_logs_and_test_ELFs_repeated_here': False},
    }

def create_archive():
    base = ROOT / 'observation-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded, namespace = collect()
    compact = summary('observation', data, namespace)
    manifest = {'schema': 'hepta-r31-observation-evidence-archive/v1', 'kind': 'observation',
        'source_root': str(ROOT), 'external_source_root': str(R16), 'external_archive_prefix': EXTERNAL_PREFIX,
        'tool_sha256': sha(Path(__file__).read_bytes()), 'source_reference_sha256': REFERENCE_SHA,
        'selected_bytes': sum(map(len, data.values())),
        'limits': {'total_bytes': MAX_TOTAL, 'file_bytes': MAX_FILE, 'files': MAX_FILES},
        'selection': {'required_files': list(REQUIRED), 'r31_directories': list(SELECTED_DIRS),
            'r16_directories': list(EXTERNAL_DIRS), 'optional_r31_files': list(OPTIONAL_FILES)},
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
        'original_job_id': HOLDER_02_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
        'observation_gate_passed': compact['observation_gate_passed'], 'counts': compact['counts'],
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
                need(manifest['schema'] == 'hepta-r31-observation-evidence-archive/v1'
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
        'original_job_id': HOLDER_02_JOB, 'workflow_reported_passed': compact['workflow_reported_passed'],
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
