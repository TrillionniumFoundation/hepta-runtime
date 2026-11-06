#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create the bounded D1 qualification evidence archive, or verify it locally without extraction.

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

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
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


PINNED = {'cache-owner-closure-inputs.json': {'bytes': 42678, 'sha256': 'cfb1f49ea5c9b15433c5411a9f3c9453fa7220d9e9b800a3aac44c2a0ab69601'}, 'candidate/QUALIFICATION_AND_DIAGNOSTIC_PLAN.md': {'bytes': 13323, 'sha256': '6aebae889a001e9c478dd5b788904b254e877db33b3349f52e1c4d9c9c87ea51'}, 'candidate/README.md': {'bytes': 18696, 'sha256': '26b83e77b496b66654f26db3bd88729f8e3b6641355e87817acb068837d6d9a7'}, 'candidate/baseline-source-map.json': {'bytes': 24156, 'sha256': 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'}, 'candidate/candidate-source-map.json': {'bytes': 24368, 'sha256': '42da71c2097c2c469346b9eed1cbc3a5be4773ee5d3b0a3df87aa72463350723'}, 'candidate/candidate.patch': {'bytes': 64987, 'sha256': '3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523'}, 'candidate/diagnostic-entry.py': {'bytes': 3463, 'sha256': '6dd6d02b1ac1af75ed79dce6ff092c2f047139f63e06016df320104fa6d684c6'}, 'candidate/edit-ledger.json': {'bytes': 13084, 'sha256': 'e28e87f59b24894a0d3df75080ba5d40347129f45bb3e94036517d7657f95f8d'}, 'candidate/independent/agents-addendum-01.json': {'bytes': 3134, 'sha256': '4661362b78ec571708385f356713ab120ffce6752a632f6e63f0f3d5f60936d4'}, 'candidate/independent/independent-review-01.json': {'bytes': 15617, 'sha256': 'ffe610556c2667a498df4c95336f10d05778bdce7ecd86a86a620df7ede1074c'}, 'candidate/input.json': {'bytes': 53222, 'sha256': 'd2c45351d8a11a1f472c06e68689c43e8ab821ee3c93428057de401644fb59cc'}, 'candidate/line-diff-helpers.js': {'bytes': 4148, 'sha256': 'ed92bac45986f2ee3ea4648b49a2a1ea57c27db6af5e62a6506933a676f5b80a'}, 'candidate/materialize_static.py': {'bytes': 11037, 'sha256': 'b337bdf93d342c8205063466217e74efe73841e9431a5be23b81940bd14ca7c7'}, 'candidate/package-manifest.json': {'bytes': 10557, 'sha256': '3f5944705884d1e071f28978fc7ffb911875bf2a93a9c719b2cbe076bbb78fe0'}, 'candidate/recovery-status.json': {'bytes': 502, 'sha256': '630bbbf71f4fd552bc638bbb597193561087895bf98292c1e94a866b05fdc3e3'}, 'candidate/references/AGENTS.md': {'bytes': 5699, 'sha256': '60f96c3186ff0089ce3535100bff48727838bc3a2ff71bead26938a129c93a56'}, 'candidate/references/architecture.md': {'bytes': 5789, 'sha256': 'ee8b940d0aa2dd51ef74d7be2c6a394d1fc8e34e98cc33946b34aab882bf7ede'}, 'candidate/references/diagnostic-plan-01.json': {'bytes': 6320, 'sha256': 'd17dddaa2a562def1e05215919283361e34636a268bc97f680d73b6bd62def50'}, 'candidate/references/qualify.py': {'bytes': 7661, 'sha256': '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'}, 'candidate/references/tool-authoring.md': {'bytes': 2833, 'sha256': 'aba42b64b17432878dcbced7b8071a70962bdd46c273437078cc7c9a992a6af6'}, 'candidate/rust-static-helpers.js': {'bytes': 4725, 'sha256': '1dc6c456f170b6fd14a54b6b74583ca797416a0fd7900dd8d61eeab9845ba02a'}, 'candidate/source-index.json': {'bytes': 58376, 'sha256': 'ca0b16befb8e6712a30361a9ce0030379a5d949b7441bf3d05232e492b913284'}, 'candidate/source/Cargo.toml': {'bytes': 3210, 'sha256': '1bdaba4ffc14e8763b5f11eb042fc79b4ea6b15313c6acf05ec1d611807883bb'}, 'candidate/source/src/main.rs': {'bytes': 11200, 'sha256': '64435a8ecd089a2dd16c1db074dbc452ef01ae070f6bbbbcde4d11088e52d522'}, 'candidate/source/src/mcp/runtime/jobs.rs': {'bytes': 187577, 'sha256': 'baa9186159053909f282e6e2c87ea901b2ad7f3972ddf4a945107008329be25c'}, 'candidate/source/src/mcp/runtime/mod.rs': {'bytes': 5054, 'sha256': '8abaf18c7c90d695e3054db431bf04bbb6002318c6dddfa29c231aa1ec4bd0e7'}, 'candidate/source/src/mcp/runtime/phase_cost.rs': {'bytes': 23399, 'sha256': '7742b05391d59f22048a31a8b130cae860d60f5eb45a21ef1341ab02f80f613c'}, 'candidate/source/src/mcp/runtime/phase_cost_tests.rs': {'bytes': 5265, 'sha256': 'ec2690cc763486450f875fb07991ba146d52186a4df48dcadb0a47860333c5a9'}, 'candidate/source/src/mcp/runtime/ssh.rs': {'bytes': 17056, 'sha256': '32a2230fbd0bd16c2bd963eaa31168e02dcec3f4705a52196f606ed3f216d40c'}, 'candidate/source/src/mcp/runtime/ssh_observation_agent_timeout_tests.rs': {'bytes': 15122, 'sha256': 'd9a10bc0128f563846043113141346c49e7e860109c73116d986c55a61b5d678'}, 'candidate/source/src/mcp/runtime/ssh_observation_maintenance_tests.rs': {'bytes': 19717, 'sha256': '15c35899a91eff5b9b1e2e24efc93f45c4a4f0ce15b419b792f35add4debd65b'}, 'candidate/source/src/mcp/runtime/ssh_observation_pool.rs': {'bytes': 67199, 'sha256': 'f971de30417aff742ec547751b03a4a873b343df90ba1e093bfcc75d96ebbc71'}, 'candidate/source/src/mcp/runtime/ssh_observation_pool_tests.rs': {'bytes': 92474, 'sha256': '2c4842a9a8d313657eaf0e25e1352dc7c505f686a1e0b18dfe75f38c6c990384'}, 'candidate/source/src/mcp/runtime/ssh_observation_validation.rs': {'bytes': 5788, 'sha256': 'b4a5c12f0f4d20c094df3dfe689343d203b1a7d376bcdec994ab57e6d9214567'}, 'candidate/source/src/mcp/server.rs': {'bytes': 119170, 'sha256': '5dafdd79236d87bf117dfc12fe0de474ec647f9ed5517834756b5ab707a1d50c'}, 'candidate/static-execution-receipts.json': {'bytes': 10434, 'sha256': 'ae7d5b0cb92acd927b5b5c55b5c811c7d0286ab1b7cbe24970fcc30b8cd7e371'}, 'candidate/static-review.json': {'bytes': 7060, 'sha256': 'c1bc08486e06d4b992ee822c087a4c4f0c44b6eb1c5d53b611fecc241981cfbc'}, 'candidate/static_local_review.py': {'bytes': 10607, 'sha256': '6c10a287e4b2ef97d57473991942ca434e47bb30176c387429e0b42c05ddc084'}, 'candidate/summarize_trace.py': {'bytes': 15057, 'sha256': 'f6e65c2e206d4aa90143a17893e5e57c158bca9f8eec5f74897b19c3596e32c5'}, 'candidate/transfer-bytes.js': {'bytes': 3977, 'sha256': '50fbb44a4e84a40dcc9505eba2899c5b6cee958900675bed8976311168a93eda'}, 'installation-01.json': {'bytes': 8926, 'sha256': 'be1687e9f4ddf1259d63bd537a881a287b6a1a8f208d909b18b5dcce18d12de6'}, 'installation-provenance/deployment.tar.gz': {'bytes': 334455, 'sha256': 'eb6485c00d81803c2379982374ca6fdf4bf1665d58e5d2f2969ea520f2550e41'}, 'installation-provenance/install_qualification.py': {'bytes': 6110, 'sha256': '205f2a314c1aaed91dd5eeb86c356aef882d1cfb559fbfea0b339277e775edcf'}, 'installation-provenance/installation-native-01.json': {'bytes': 729, 'sha256': 'bd8ddf95f812b2482262c00f29ca6db6d782632f34f09f9de620600ac3c6c811'}, 'installation-provenance/installation-read-01.json': {'bytes': 1046, 'sha256': 'a6043c128a99cceffe79409dc668204801ae7c3ea7a364f5353fadb38bd7f3ad'}, 'installation-provenance/installation-start-01.json': {'bytes': 1216, 'sha256': '2908e8252f4207e051940727d9c761711a6188c3aa635e7be2eefc335379bd01'}, 'installation-provenance/qualification-start-01.json': {'bytes': 1286, 'sha256': '5a50a6a22756a85751207281bb900a421463bdd7d8722aaba423a874a283497d'}, 'launch-command.json': {'bytes': 728, 'sha256': '1e2aaec6c5dd26f7b406fe5592a5f95204f70385f215f4d89363cc8473ea1d71'}, 'owner-closure-provenance/lifecycle-owner-postflight-01.json': {'bytes': 51666, 'sha256': '893171173431137b4e7836089c3a096506530966c736bf17c1779c2b2480b146'}, 'owner-closure-provenance/lifecycle-owner-postflight-native-01.json': {'bytes': 733, 'sha256': '00466ae50384dd5abc6e8124aaa4583bd55d37538ada559c16e25d9cfb0a06e8'}, 'owner-closure-provenance/lifecycle-owner-postflight-read-01-000.json': {'bytes': 50477, 'sha256': '6008709d937e3b458541ed019519cb32fd56154a69ebe2638b7aedf057a1cb79'}, 'owner-closure-provenance/lifecycle-owner-postflight-read-01-001.json': {'bytes': 50226, 'sha256': 'dde5f57fa0cd5e9b22af2829ea4a7e2eb8c3e5dec6030b159ffdc3972565e8a4'}, 'owner-closure-provenance/lifecycle-owner-postflight-read-01-002.json': {'bytes': 41341, 'sha256': '7ee538fb988eb05ea5ce71abaa34441e96b9cc3cf2f9c4bc452cc9bdd62046d8'}, 'owner-closure-provenance/postflight_r35_lifecycle_owner_01.py': {'bytes': 46387, 'sha256': '6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e'}, 'prepare_qualify.py': {'bytes': 47509, 'sha256': '05fcf39aeb418e626ceec048f51c4919bc5ba0b85d180f89c8580cfa2adf876c'}, 'provenance/source-anchor-and-publication-parent.json': {'bytes': 2400, 'sha256': '99d1e7c4faef98fd680aa7136c3d73e163ca3f64e15f75a1704a6394c8c1fd34'}, 'qualification-input.json': {'bytes': 5386, 'sha256': '6035b89808862402a49cb070e4d511dfbf4965ed16399c590ac035bb9690020a'}, 'qualification-package-manifest.json': {'bytes': 9427, 'sha256': 'd13dcedb008d909073a5d5f60215aacd75ea64b63069722207ed2242bb702ebc'}}
REQUIRED = ('cache-owner-closure-inputs.json', 'candidate/QUALIFICATION_AND_DIAGNOSTIC_PLAN.md', 'candidate/README.md', 'candidate/baseline-source-map.json', 'candidate/candidate-source-map.json', 'candidate/candidate.patch', 'candidate/diagnostic-entry.py', 'candidate/edit-ledger.json', 'candidate/independent/agents-addendum-01.json', 'candidate/independent/independent-review-01.json', 'candidate/input.json', 'candidate/line-diff-helpers.js', 'candidate/materialize_static.py', 'candidate/package-manifest.json', 'candidate/recovery-status.json', 'candidate/references/AGENTS.md', 'candidate/references/architecture.md', 'candidate/references/diagnostic-plan-01.json', 'candidate/references/qualify.py', 'candidate/references/tool-authoring.md', 'candidate/rust-static-helpers.js', 'candidate/source-index.json', 'candidate/source/Cargo.toml', 'candidate/source/src/main.rs', 'candidate/source/src/mcp/runtime/jobs.rs', 'candidate/source/src/mcp/runtime/mod.rs', 'candidate/source/src/mcp/runtime/phase_cost.rs', 'candidate/source/src/mcp/runtime/phase_cost_tests.rs', 'candidate/source/src/mcp/runtime/ssh.rs', 'candidate/source/src/mcp/runtime/ssh_observation_agent_timeout_tests.rs', 'candidate/source/src/mcp/runtime/ssh_observation_maintenance_tests.rs', 'candidate/source/src/mcp/runtime/ssh_observation_pool.rs', 'candidate/source/src/mcp/runtime/ssh_observation_pool_tests.rs', 'candidate/source/src/mcp/runtime/ssh_observation_validation.rs', 'candidate/source/src/mcp/server.rs', 'candidate/static-execution-receipts.json', 'candidate/static-review.json', 'candidate/static_local_review.py', 'candidate/summarize_trace.py', 'candidate/transfer-bytes.js', 'installation-01.json', 'installation-provenance/deployment.tar.gz', 'installation-provenance/install_qualification.py', 'installation-provenance/installation-native-01.json', 'installation-provenance/installation-read-01.json', 'installation-provenance/installation-start-01.json', 'installation-provenance/qualification-start-01.json', 'launch-command.json', 'owner-closure-provenance/lifecycle-owner-postflight-01.json', 'owner-closure-provenance/lifecycle-owner-postflight-native-01.json', 'owner-closure-provenance/lifecycle-owner-postflight-read-01-000.json', 'owner-closure-provenance/lifecycle-owner-postflight-read-01-001.json', 'owner-closure-provenance/lifecycle-owner-postflight-read-01-002.json', 'owner-closure-provenance/postflight_r35_lifecycle_owner_01.py', 'prepare_qualify.py', 'provenance/source-anchor-and-publication-parent.json', 'qualification-input.json', 'qualification-package-manifest.json')
FUTURE_PATHS = ('preparation.json',
 'qualification-terminal-status-01.json',
 'qualification-native-read-01.json',
 'qualification-01/report.json',
 'qualification-01/source-map.json',
 'qualification-01/isolated-tests/summary.json',
 'qualification-01/isolated-tests.audit.json')
ACTUAL = {'schema': 'hepta-d1-qualification-archive-actual-pins/v1', 'sealed': True, 'qualification_job_id': '1a1aff8769c-fc05-6d26', 'outcome': 'passed', 'files': {'preparation.json': {'bytes': 103083, 'sha256': 'd76bc4ab72a3c579ee25e5c0381df391e78b6dd046a341b07e1343998829b27e'}, 'qualification-terminal-status-01.json': {'bytes': 731, 'sha256': 'c06e447a3adf5eb6f8afd0533e898a3f6417ce61d52e0a31b66f5277a991f303'}, 'qualification-native-read-01.json': {'bytes': 3809, 'sha256': 'f30107c30707be7926ce6e0ae24d743cd2deacee0f78a8d1d30efd4d9f5d3fa8'}, 'qualification-01/report.json': {'bytes': 83976, 'sha256': '0fd74793651afcf0b24f010d4371a04c422da8fd4711cb288da40cf4d69ee437'}, 'qualification-01/source-map.json': {'bytes': 24368, 'sha256': '98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133'}, 'qualification-01/isolated-tests/summary.json': {'bytes': 6841, 'sha256': '30be482004f6159463564467d52f9088e558318a9408966b938e12cd745ec301'}, 'qualification-01/isolated-tests.audit.json': {'bytes': 1425084, 'sha256': 'c921ea020eb0d14c8634290cd55aef9e6014f734c95b24e68f2bdb331463c184'}}, 'counts': {'passed': 1651, 'failed': 0, 'ignored': 34, 'selected': 1685, 'retries': 0}, 'qualified_binary_sha256': {'hepta-runtime': '1d6f38950eefe34891827b5e0f71cb7b388ddbbb2f3fc339c3a0325e27ef11ad', 'hepta-runtime-jobctl': '0d54006054a67d3c63a3189d8f8610de500d7e36603e3e70d929635d97349862', 'native_process_driver': 'a584aebfbafe9e31ff8f21ebe7407a3c2aeeb953d73bf21d4882e5af96155ddb'}}
BASELINE_COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
CHANGED_PATHS = set(['Cargo.toml', 'src/main.rs', 'src/mcp/runtime/jobs.rs', 'src/mcp/runtime/mod.rs', 'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/phase_cost_tests.rs', 'src/mcp/runtime/ssh.rs', 'src/mcp/runtime/ssh_observation_agent_timeout_tests.rs', 'src/mcp/runtime/ssh_observation_maintenance_tests.rs', 'src/mcp/runtime/ssh_observation_pool.rs', 'src/mcp/runtime/ssh_observation_pool_tests.rs', 'src/mcp/runtime/ssh_observation_validation.rs', 'src/mcp/server.rs'])
ADDED_PATHS = set(['src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/phase_cost_tests.rs'])
BINARY_NAMES = {'hepta-runtime-jobctl', 'native_process_driver', 'hepta-runtime'}
SOURCE_REFERENCE_SHA256 = '78daf8af031efbf4df3a08abda581bc45092c7275d5002dfa4dd8550818feede'
VERIFY_REFERENCE_SHA256 = '2e7542ea4f229ba0ccbff207b080026f31a85c4cc9a3e44e9f28e4daece4f545'


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
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d1-qualification-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True, 'UNSEALED: actual original D1 qualification receipts are required')
    job = ACTUAL.get('qualification_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original D1 native job identity required')
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
    read = lambda name: json.loads(data[name])
    installed = read('installation-01.json')
    package_name = 'qualification-package-manifest.json'
    package = read(package_name)
    need(package['schema'] == 'hepta-d1-first-qualification-preparation-package/v1'
         and package['sealed'] is True and package['host_root'] == str(ROOT)
         and package['file_count_excluding_manifest'] == len(package['files']) == 50,
         'D1 sealed installation package differs')
    members = {row['path']: {'bytes': row['bytes'], 'sha256': row['sha256']}
               for row in package['files']}
    need(len(members) == 50 and package_name not in members, 'duplicate package member')
    members[package_name] = {'bytes': len(data[package_name]), 'sha256': sha(data[package_name])}
    need(installed['schema'] == 'hepta-d1-qualification-create-only-install/v1'
         and installed['root'] == str(ROOT) and installed['member_count'] == 51
         and installed['members'] == members
         and installed['manifest'] == members[package_name]
         and all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == row
                 for name, row in members.items()), 'installed original membership differs')
    need(installed['source_package_unchanged'] is True
         and installed['cache_moved_or_deleted'] is False
         and installed['qualifier_or_compiler_started'] is False
         and installed['automatic_retries'] == 0 and installed['original_archive_preserved'] is True,
         'installation outcome differs')
    archive_name = 'installation-provenance/deployment.tar.gz'
    need(installed['archive'] == {
        'path': '/home/qian/hepta-runtime-optimization-20261106-r35/d1-qualification-deployment-01.tar.gz',
        'bytes': len(data[archive_name]), 'sha256': sha(data[archive_name])}, 'staged archive differs')
    job = '1a1aff7cb4d-fc05-6d1e'
    terminal = read('installation-provenance/installation-native-01.json')
    native_terminal(terminal, job, 'succeeded', 0)
    streams = original_streams(read('installation-provenance/installation-read-01.json'), terminal)
    need(streams['stderr'] == b'' and json.loads(streams['stdout']) == {
        'installation_receipt': {'bytes': len(data['installation-01.json']),
                                 'sha256': sha(data['installation-01.json'])},
        'installed': str(ROOT), 'member_count': 51, 'qualification_started': False},
        'actual installation output differs')
    start = read('installation-provenance/installation-start-01.json')
    need(start['audit_recorded'] is True and start['job']['id'] == job
         and start['job']['host'] == 'x230' and start['job']['executable'] == '/usr/bin/python3'
         and start['job']['env_keys'] == [] and start['job']['launch_state'] == 'launched'
         and start['launch']['ok'] is True and start['reused'] is False,
         'actual original installer launch differs')
    need(start['job']['args'] == ['-B',
        '/home/qian/hepta-runtime-optimization-20261106-r35/install_d1_qualification_01.py',
        '--archive', installed['archive']['path']], 'installer argv differs')
    qstart = read('installation-provenance/qualification-start-01.json')
    launch = read('launch-command.json')
    need(launch['sealed'] is True and launch['host'] == 'x230' and launch['cwd'] == str(ROOT)
         and launch['actual_native_job_id'] is None and launch['executed'] is False,
         'frozen pre-execution launch command differs')
    need(qstart['audit_recorded'] is True and qstart['job']['id'] == ACTUAL['qualification_job_id']
         and qstart['job']['host'] == 'x230' and qstart['job']['env_keys'] == []
         and qstart['job']['cwd'] == str(ROOT) and qstart['job']['launch_state'] == 'launched'
         and qstart['launch']['ok'] is True and qstart['reused'] is False
         and [qstart['job']['executable'], *qstart['job']['args']] == launch['argv'],
         'actual original qualification launch differs')
    return {'installation_job_id': job, 'installation_succeeded': True,
            'original_installed_members': len(members), 'source_package_files': 39,
            'installer_did_not_start_qualification': True,
            'original_qualification_job_id': ACTUAL['qualification_job_id'],
            'diagnostic_environment_absent_at_native_launch': True,
            'originals_reencoded': False, 'installation_reexecuted': False}


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'qualification', 'only the completed original D1 qualification may be archived')
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
    need(kind == 'qualification', 'this script archives only completed D1 qualification')
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
    need(kind == 'qualification', 'this script archives only completed D1 qualification')
    need(all(name in data for name in REQUIRED), 'missing original D1 preparation/qualification input')
    need(all(name in data and {'bytes': len(data[name]), 'sha256': sha(data[name])} == expected
             for name, expected in PINNED.items()), 'a frozen original D1 input or receipt differs')
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
    need(prep.get('schema') == 'hepta-x230-d1-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and 'error' not in prep
         and prep.get('first_actual_d1_qualification_required') is True
         and prep.get('qualification_started') is True
         and type(prep.get('qualification_returncode')) is int and prep['qualification_returncode'] == 0
         and type(prep.get('automatic_retries')) is int and prep['automatic_retries'] == 0
         and prep.get('production_services_modified') is False
         and prep.get('source_baseline') == BASELINE_COMMIT
         and 'prior_preparation_failure' not in prep
         and prep['input_binding'] == identity('qualification-input.json')
         and prep['candidate_patch'] == identity('candidate/candidate.patch')
         and prep['qualification_report_sha256'] == sha(data['qualification-01/report.json']),
         'the actual first D1 preparation did not close successfully')
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
    need(inputs['schema'] == 'hepta-d1-direct-qualification-input/v1'
         and inputs['sealed'] is True and inputs['required_missing_bindings'] == []
         and inputs['baseline_commit'] == inputs['source_construction_parent'] == BASELINE_COMMIT
         and candidate['schema'] == 'hepta-r24-phase-cost-candidate/v1'
         and candidate['baseline_commit'] == candidate['git_parent'] == BASELINE_COMMIT
         and candidate['revision'] == 'recovery-02'
         and candidate['patch_sha256'] == sha(data['candidate/candidate.patch'])
         and candidate['patch_bytes'] == len(data['candidate/candidate.patch'])
         and set(candidate['changed_paths']) == CHANGED_PATHS
         and set(candidate['added_paths']) == ADDED_PATHS
         and len(candidate['new_test_functions']) == 6
         and candidate['performance_acceptance_claim'] is False,
         'D1 input differs from the frozen R24 diagnostic candidate')
    need(prep['source_before_qualification'] == candidate['candidate_compile_inputs'] == qualified['source_input']
         and prep['source_after_qualification'] == qualified['source_tested'] == qualified['source_after'] == final_map
         and len(final_map) == 222 and len(candidate['baseline_compile_inputs']) == 220
         and set(final_map) == set(candidate['candidate_compile_inputs'])
         and set(final_map) - set(candidate['baseline_compile_inputs']) == ADDED_PATHS
         and not set(candidate['baseline_compile_inputs']) - set(final_map)
         and {name for name in final_map if final_map[name] != candidate['baseline_compile_inputs'].get(name)} == CHANGED_PATHS,
         'D1 final actual source maps do not agree')
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
    need(frozen['schema'] == 'hepta-r24-phase-cost-preparation-package/v1'
         and frozen['baseline_commit'] == BASELINE_COMMIT and frozen['diagnostic_name'] == 'D1'
         and frozen['revision'] == 'recovery-02' and frozen['file_count'] == len(frozen['files']) == 38
         and frozen['original_qualifier_all_features'] is True and frozen['original_qualifier_changed'] is False,
         'D1 original 39-file candidate package differs')
    for pin in frozen['files']:
        name = 'candidate/' + pin['path']
        need(name in PINNED and pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name]),
             'frozen candidate original differs: ' + name)
    need({name for name in data if name.startswith('candidate/')} ==
         {'candidate/package-manifest.json'} | {'candidate/' + pin['path'] for pin in frozen['files']},
         'candidate package inventory differs')
    for name, field in (('candidate/input.json', 'candidate_input'),
                        ('candidate/package-manifest.json', 'candidate_manifest')):
        need(inputs[field] == {'path': name, 'bytes': len(data[name]), 'sha256': sha(data[name])}
             and prep['frozen_' + field] == identity(name), 'preparer candidate provenance differs: ' + name)
    need(prep['source_materialization'] == 'accepted R24 source copy plus frozen recovery-02 D1 patch; R35 supplies only closed build cache'
         and prep['diagnostic_name'] == 'D1' and prep['performance_acceptance_claim'] is False
         and prep['diagnostic_environment_absent'] is True and prep['ordinary_supplemental_executed'] is False
         and prep['cache_owner_closure_input'] == identity('cache-owner-closure-inputs.json')
         and inputs['owner_closure_input_sha256'] == sha(data['cache-owner-closure-inputs.json'])
         and closure['schema'] == 'hepta-d1-r35-cache-owner-closure/v1' and closure['sealed'] is True
         and closure['required_missing_bindings'] == [] and closure['closure_is_not_performance_adoption'] is True
         and closure['r35_observation_performance_passed'] is True
         and closure['r35_normal_lifecycle_executed'] is True and closure['r35_normal_lifecycle_adopted'] is False
         and prep['cache_owner_closure']['inputs'] == closure['inputs']
         and prep['cache_owner_closure']['normal_lifecycle_performance_passed'] is False
         and prep['cache_owner_closure']['r35_adoption_claimed'] is False
         and prep['cache_transferred_by_rename'] is True and prep['cache_to_transfer'] == closure['cache_path']
         and prep['cache_deletions'] == prep['new_full_cache_copy_bytes'] == 0,
         'R35 cache-only closed rejected-owner history differs')
    postflight = closure['postflight']
    need(postflight['job_id'] == '1a1afe8986e-fc05-6ca9', 'prior-owner postflight job differs')
    for pin in [postflight['report'], postflight['native'], *postflight['read_pages']]:
        name = 'owner-closure-provenance/' + Path(pin['path']).name
        need(pin['bytes'] == len(data[name]) and pin['sha256'] == sha(data[name]),
             'original prior-owner postflight copy differs')
    proof_name = 'provenance/source-anchor-and-publication-parent.json'
    proof = read(proof_name)
    need(proof['source_construction_anchor'] == BASELINE_COMMIT
         and inputs['published_candidate_commit'] == proof['published_candidate_commit']
         == '5d3fecbeb1d67c288917598f55932e64c878f1e5'
         and inputs['published_candidate_parent'] == proof['actual_git_parent']
         == proof['published_candidate_parent_sha'] == '86155fbf3b89e5a77e2a4aadebd2128c663fe50b'
         and prep['publication_provenance'] == identity(proof_name),
         'source construction anchor/publication parent provenance differs')
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
            'preparation_history': 'first D1 preparation and first actual eight-stage qualification',
            'source_baseline_commit': BASELINE_COMMIT, 'changed_paths': sorted(CHANGED_PATHS),
            'compiler_source_files': len(final_map), 'qualification_harness_files': len(qualified['harness_after']),
            'compressed_original_log_files': len(logs), 'native_original_logs': native_logs,
            'qualified_binary_sha256': binaries, 'qualification_report_sha256': sha(data['qualification-01/report.json']),
            'source_map_sha256': sha(data['qualification-01/source-map.json']),
            'cache_owner_original_references': closure['inputs'], 'cache_owner_originals_copied': False,
            'r35_performance_adoption_claimed': False, 'tests_reexecuted': False,
            'original_test_audit_reexecuted': False, 'test_binary_hashes_recomputed': False,
            'performance_adoption_evaluated': False}


def create_archive(root, kind):
    require_sealed()
    need(kind == 'qualification', 'this script archives only completed D1 qualification')
    base = root / 'qualification-evidence-01'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-d1-qualification-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
                need(manifest['schema'] == 'hepta-d1-qualification-evidence-archive/v1'
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
