#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run one fixed R21 six-host campaign after accepted qualification has ended.

Only new R21 evidence and private fixture resources are written. The immutable
R16 harness stays unchanged. Actual qualification/acceptance/control/runtime
hashes arrive via CLI; no future candidate binary identity is hardcoded.
The Mac stdin bootstrap validates this installed file before exec. Its transport
SHA label is retained as a Mac receipt, never presented as a remote self-hash.
"""
import argparse
import datetime
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time
import traceback

sys.dont_write_bytecode = True
R16 = Path('/home/qian/hepta-runtime-optimization-20261104-r16')
R19 = Path('/home/qian/hepta-runtime-optimization-20261104-r19')
R21 = Path('/home/qian/hepta-runtime-optimization-20261105-r21')
SOURCE = R21 / 'source'
TARGET = R21 / 'target-fresh-01'
TOOLS = R16 / 'measurement-tools'
BOUNDARY_TOOLS = R21 / 'boundary-tools'
ORIGINAL_BOUNDARY_TOOLS = R16 / 'boundary-tools'
CONTROL = R21 / 'campaign-control-01'
NATIVE_OUT = R21 / 'native-observation-01'
BOUNDARY_OUT = R21 / 'native-boundary-01'
LIFECYCLE_OUT = R21 / 'lifecycle-abba-01'
NATIVE_SOCKET = Path('/home/qian/h21n1')
BOUNDARY_SOCKET = Path('/home/qian/h21b1')
LIFECYCLE_SOCKET_PREFIX = Path('/home/qian/h21lc1')
PROFILE = Path('/home/qian/hepta-runtime-optimization-20261023/r11-native-observation-abba-20261103-02/profile/profile.json')
TOPOLOGY = R16 / 'benchmark-topology.json'
FROZEN_JOBS = Path('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
BASELINE = R19 / 'qualification-02/hepta-runtime'
CANDIDATE = R21 / 'qualification-01/hepta-runtime'
PROGRAM = R21 / 'campaign-tools/run_six_host_campaign_01.py'
PLAN = R21 / 'measurement-plan-01.json'
PLAN_SHA = 'aa4ad30b746b267d005c675f81ba634c43cd81a6f5893963445949abaa6e82f6'
BASELINE_SHA = 'adab5f27f89b3cac6adaec916110a48d80697db9667e3bd7ee0fc713fe770a09'
BASELINE_JOBS_SHA = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'
JOBCTL_SHA = '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'
JOBCTL_SOURCE_SHA = 'c22fdcd5bafad3a2123d5817c27fd73e7b5c26001bf1a8bdd6f8dbacabc8b562'
QUALIFIER_SHA = '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'
QUALIFICATION_TOOLS_MANIFEST_SHA = '126976a5005fbbb5b09360d6999c85fd46d14e96e9b7d037c55ea2d40b40cc8d'
LIFECYCLE_TOOLS = R21 / 'lifecycle-tools'
LIFECYCLE_MANIFEST_SHA = '445a325931f2a9147401ea241782a29617480c2047c6d5b760f2e59f9037cb1f'
BASELINE_PINS = {
    'source-freeze-02.json': '31f90b50d22ff8c8ac3a188f1bad47c844b4e2e68784277a87a671c916f7cb6a',
    'qualification-02/report.json': '44a352c14bb83d093058ccbbc2c99fab913ef9af0b3400b00750dc46ad69cc16',
    'independent-acceptance-02.json': '374d6bf3e7201522f8145b105a10c372eaedc5bba9099ca92857367637b65ea9',
    'qualification-02/hepta-runtime': BASELINE_SHA,
    'qualification-02/hepta-runtime-jobctl': JOBCTL_SHA,
    'qualification-02/native_process_driver': '51165c1e38409248f5fdb7da2036ebe5e05eec7576035e95bd4b8e2a5c675530',
}
QUALIFICATION_FILES = {'create_component_chain_01.py': '4a0a72aa649c44d83299eb8bb85ce7d3aa40c3b961ca9b5b0e2cf8ef56a4a610', 'qualify_candidate_01.py': '81b226f6e7d3a529ff2d0040124e661cb5e3316017e5b9c748b58d75bf4aa4c5', 'verify_qualification_01.py': '216eb5e0cb922263d748f6dfefc8db00da88d00e8d021690246d7ab8e7183c95'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
QUIESCENCE_SECONDS = 90


PROFILE_SHA = 'fe1e9551b5b8812ad6ed3da018c282b7261f7caeb2f49e4dcfefba7ff784ab08'

TOPOLOGY_SHA = '8c0767d3318131a7d470d9cde8e327a59ce18adf022c8bc1b1d5a0fa9a865287'

HOSTS = {'ai395', 'mac', 'main', 'pocket4', 'rog', 'x230'}

HARNESS_FILES = {
    'allocator_environment.py': 'f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525',
    'allocator_environment_audit.py': '4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727',
    'analyze_native_observation.py': 'cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66',
    'audit_native_evidence.py': 'b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28',
    'observation_resources.py': 'f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894',
    'owned_ssh_interruption.py': '1989c57f0b944afae1ed759d6529b8f1cc26197e269e2c34c4fd49e43a32aa7b',
    'run_native_observation.py': '7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb',
    'run_six_host_cancel_recovery.py': '698eb7801cde3f2bd5ff202412c0833fc218fd7e912c3c949d2b37fde7a56a12',
    'test_native_harness.py': '2b450175b9e6122248ac1bcb51860aa8a6d3eff55f6ac8c877c0a905e3dd7d00',
    'verify_cancel_recovery.py': '0116652a0b489dc462f005e01d7c943feda9ba784563d7317c92bb5beb9a701c',
    'x230_observation_benchmark.py': '4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed',
    'x230_six_running_recovery_canary.py': '6219bc556b0ac6d142bd4c731466b959e8a410f0b4b55f3d8b303f8fdbfbaaf4',
}

BOUNDARY_FILES = {
    'run_native_boundary.py': '2af83ebba8b7ea5550e7549da795556eb8328622bcfbf563019654e202a53329',
    'audit_native_boundary.py': '8ad8f6d97a5bd2e4850b02cd66fa5d2ac7d237ea0eef043daf9c88d3c9c152ee',
    'test_native_boundary.py': 'cda0bbef1704c374b49cc3cf5ea7b9a873687e547eed5c927bed801cf15156bd',
    'harness-freeze.json': '77ea90d5d2f45ed4d724f087353a3c8e603abcd0a8bd1d4bceb31179bef174b1',
    'capacity-policy.json': '206d1a99abc328948d8df893daa77a862b25de878a8b97379090da7ce84393d3',
}

def need(value, message):
    if not value:
        raise RuntimeError(message)

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def stable_file(path, maximum=128 * 1024 * 1024, retain=False):
    """Full current-byte hash, bounded read, direct path and fd/path stamps."""
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'indirect evidence path: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    chunks, count, hasher = [], 0, hashlib.sha256()
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'unsafe or oversized evidence file: ' + str(path))
        while count <= maximum:
            raw = os.read(fd, min(1024 * 1024, maximum + 1 - count))
            if not raw:
                break
            count += len(raw)
            hasher.update(raw)
            if retain:
                chunks.append(raw)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = lambda info: tuple(getattr(info, name) for name in fields)
        need(count == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'evidence changed while reading: ' + str(path))
    finally:
        os.close(fd)
    entry = {'path': str(path), 'bytes': count, 'sha256': hasher.hexdigest()}
    return entry, b''.join(chunks) if retain else None

def fingerprint(path, expected=None):
    entry, _ = stable_file(path)
    if expected is not None:
        need(entry['sha256'] == expected, 'evidence SHA256 differs: ' + str(path))
    return entry

def document(path, expected=None, maximum=64 * 1024 * 1024):
    entry, raw = stable_file(path, maximum=maximum, retain=True)
    if expected is not None:
        need(entry['sha256'] == expected, 'document SHA256 differs: ' + str(path))
    return json.loads(raw), entry

def safe_relative(name):
    path = Path(name)
    need(isinstance(name, str) and name not in ('', '.') and not path.is_absolute()
         and '..' not in path.parts and path.as_posix() == name, 'unsafe relative binding')
    return path

def snapshot():
    paths = [Path('/proc/loadavg'), Path('/proc/meminfo'), Path('/proc/stat')]
    for pattern in ('cpu[0-9]*/cpufreq/scaling_governor', 'cpu[0-9]*/cpufreq/scaling_cur_freq',
                    'cpu[0-9]*/cpufreq/scaling_min_freq', 'cpu[0-9]*/cpufreq/scaling_max_freq'):
        paths.extend(sorted(Path('/sys/devices/system/cpu').glob(pattern)))
    paths.extend(sorted(Path('/sys/class/thermal').glob('thermal_zone*/temp')))
    paths.extend(sorted(Path('/sys/class/hwmon').glob('hwmon*/temp*_input')))
    values = {}
    for path in paths:
        try:
            values[str(path)] = path.read_text()
        except OSError as error:
            values[str(path)] = {'error': type(error).__name__, 'errno': error.errno}
    return {'utc': utc(), 'monotonic_ns': time.monotonic_ns(), 'values': values,
            'scope': 'read-only diagnostics; no governor or machine settings changed'}

def proc_bytes(path, maximum=4 * 1024 * 1024):
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    need(len(raw) <= maximum, 'process metadata exceeds diagnostic bound')
    return raw

def write_new(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())

def atomic_json(path, value):
    temporary = path.with_suffix('.next')
    write_new(temporary, (json.dumps(value, indent=2) + '\n').encode())
    os.replace(temporary, path)

def finite_positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0

def native_decision(analysis):
    need([item['concurrency'] for item in analysis['cases']] == [1, 8, 16], 'native analysis concurrency differs')
    cases = []
    for item in analysis['cases']:
        left, right = item['arms']['A'], item['arms']['B']
        need(all(finite_positive(arm[key]) for arm in (left, right) for key in ('calls_per_second', 'p95_ms')),
             'invalid aggregate native statistic')
        rate, tail = right['calls_per_second'] / left['calls_per_second'], right['p95_ms'] / left['p95_ms']
        cases.append({'concurrency': item['concurrency'], 'throughput_b_over_a': rate, 'p95_b_over_a': tail,
                      'required_throughput_ratio_min': 0.95, 'required_p95_ratio_max': 1.10,
                      'throughput_passed': rate >= 0.95, 'p95_passed': tail <= 1.10,
                      'passed': rate >= 0.95 and tail <= 1.10})
    return {'cases': cases, 'passed': all(item['passed'] for item in cases),
            'scope': 'preregistered finite-run aggregate regression screen; not a confidence interval'}



def compiler_elf_fingerprint(path, expected_sha256, expected_bytes):
    """Read only three explicit compiler outputs, whose Cargo hardlinks are expected.

    Executed qualification copies and every ordinary evidence/source file keep
    the strict single-link gate. Hash/size are supplied from the just-validated
    qualification copy; no target artifact is executed through this helper.
    """
    allowed = {TARGET / 'release/hepta-runtime', TARGET / 'release/hepta-runtime-jobctl',
               TARGET / 'release/examples/native_process_driver'}
    path = Path(path)
    need(path in allowed and path.resolve() == path and HEX.fullmatch(expected_sha256)
         and type(expected_bytes) is int and 0 < expected_bytes <= 128 * 1024 * 1024,
         'compiler ELF exception is restricted to three exact target paths')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    digestor, count, header = hashlib.sha256(), 0, b''
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1
             and before.st_uid == os.geteuid() and not before.st_mode & (stat.S_ISUID | stat.S_ISGID)
             and before.st_size == expected_bytes, 'unsafe compiler ELF metadata')
        while count <= expected_bytes:
            raw = os.read(fd, min(1024 * 1024, expected_bytes + 1 - count))
            if not raw:
                break
            if not header:
                header = raw[:4]
            count += len(raw)
            digestor.update(raw)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stable = lambda info: tuple(getattr(info, key) for key in fields)
        need(count == expected_bytes and header == b'\x7fELF'
             and stable(before) == stable(os.fstat(fd)) == stable(path.lstat())
             and digestor.hexdigest() == expected_sha256,
             'compiler ELF bytes or link identity changed during read')
    finally:
        os.close(fd)
    return {'path': str(path), 'bytes': count, 'sha256': digestor.hexdigest(),
            'link_count': before.st_nlink, 'scope': 'explicit compiler target ELF only; stable hardlinks allowed'}


def sized_identity(entry):
    return {'size': entry['bytes'], 'sha256': entry['sha256']}


def full_source(root):
    need(root.is_dir() and root.resolve() == root, 'direct source tree required')
    rows = {}
    for path in sorted(root.rglob('*')):
        mode = path.lstat().st_mode
        need(stat.S_ISREG(mode) or stat.S_ISDIR(mode), 'unsupported source entry: ' + str(path))
        if stat.S_ISREG(mode):
            rows[path.relative_to(root).as_posix()] = sized_identity(fingerprint(path))
    return rows


def compile_inputs(rows):
    return {name: row['sha256'] for name, row in rows.items()
            if name in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml') or name.startswith(('src/', 'examples/'))}


def canonical_digest(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def checked_bool_map(value, label):
    need(isinstance(value, dict) and bool(value) and all(v is True for v in value.values()), label)


def exact_zero(value):
    return type(value) is int and value == 0


def process_identity(pid):
    need(type(pid) is int and pid > 1, 'invalid owned PID')
    try:
        raw = proc_bytes(Path('/proc') / str(pid) / 'stat', 65536).decode()
    except FileNotFoundError:
        return None
    tail = raw.rsplit(') ', 1)[1].split()
    return {'pid': pid, 'state': tail[0], 'parent_pid': int(tail[1]), 'start_ticks': int(tail[19])}


def compilation_idle(recorded):
    """Observe completed qualification identities and readable cargo/rustc; never signal them."""
    identities, compilers, wrappers, errors = [], [], [], []
    for expected in recorded:
        current = process_identity(expected['pid'])
        same = current is not None and current['start_ticks'] == expected['start_ticks']
        identities.append({'pid': expected['pid'], 'expected_start_ticks': expected['start_ticks'],
                           'current': current, 'original_identity_absent': not same})
    exact_python = {os.fsencode(path) for path in (
        SOURCE / 'tools/x230/20261028/qualify.py', R21 / 'tools/qualify_candidate_01.py',
        R21 / 'tools/verify_qualification_01.py', R21 / 'tools/create_component_chain_01.py')}
    checked = 0
    for directory in Path('/proc').iterdir():
        if not directory.name.isdecimal():
            continue
        try:
            comm = proc_bytes(directory / 'comm', 65536).decode().strip()
            if comm in ('cargo', 'rustc'):
                current = process_identity(int(directory.name))
                if current is not None:
                    compilers.append({'comm': comm, **current})
            elif comm.startswith('python') and directory.stat().st_uid == os.geteuid():
                argv = proc_bytes(directory / 'cmdline').split(b'\0')
                checked += 1
                if exact_python.intersection(argv):
                    current = process_identity(int(directory.name))
                    if current is not None:
                        wrappers.append({'comm': comm, **current, 'argv_sha256': digest(b'\0'.join(argv))})
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ESRCH):
                errors.append({'pid': int(directory.name), 'type': type(error).__name__, 'errno': error.errno})
    return {'recorded_processes': identities, 'cargo_or_rustc': compilers,
            'matching_qualification_wrappers': wrappers, 'scan_errors': errors,
            'owned_python_processes_checked': checked,
            'idle': all(row['original_identity_absent'] for row in identities) and not compilers and not wrappers and not errors,
            'signals_sent': 0, 'environment_read': False, 'full_argv_retained': False,
            'scope': 'readable process snapshot, not continuous proof of whole-machine inactivity'}


def component_chain_gate(acceptance, freeze, launch, control, plan, inputs):
    """Bind the qualified two-step source chain and its exact retained inputs.

    The final source was directly exercised by the CANCEL component. The STATUS
    component exercised its preceding source; this chain does not relabel that
    earlier measurement as a new final-source cold-process run.
    """
    intermediate = Path('/home/qian/hepta-runtime-optimization-20261105-r20')
    status_sha = '2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7'
    final_sha = '1f1f086e3bc0fc62184ed51949964e1f82e337b87d330225097ae38722e4ac8c'
    status_report_sha = '7223fafebacd13d5debe05f113f314b550f3896156d59e44837225a63f1a7631'
    need(plan['component_chain_schema'] == 'hepta-r21-component-chain/v1'
         and plan['candidate_jobs_sha256'] == plan['cancelprocess']['candidate_jobs_sha256'] == final_sha
         and plan['cancelprocess']['baseline_jobs_sha256'] == status_sha
         and inputs['src/mcp/runtime/jobs.rs'] == final_sha
         and plan['superseded_r20_formal_campaign']['executed'] is False
         and plan['rejected_hash_directions'] == [
             {'buffer_bytes': 4096, 'mechanism_screen_passed': False,
              'report_sha256': 'c8b96746a42c7a70f332be0afd1263093e6e6528d9cc9a2e7275245505dafde1'},
             {'buffer_bytes': 64, 'mechanism_screen_passed': False,
              'report_sha256': '347626e60c950bcaeacafaaa6c863834d9dac0c75524372612cc93f402800d4b'}],
         'final source or superseded/rejected direction contract differs')
    binding = acceptance['component_chain']
    path = R21 / 'component-chain-01.json'
    need(binding['path'] == str(path)
         and binding == freeze['component_chain'] == launch['component_chain'] == control['component_chain'],
         'qualified component-chain bindings differ')
    chain, chain_id = document(path, binding['sha256'])
    need(binding['size'] == chain_id['bytes']
         and binding['schema'] == chain['schema'] == 'hepta-r21-component-chain/v1'
         and chain['root'] == str(R21)
         and binding['baseline_source_sha256'] == chain['baseline_source_sha256'] == BASELINE_JOBS_SHA
         and binding['final_source_sha256'] == chain['final_source_sha256'] == final_sha
         and binding['producer_chain_verified'] is chain['producer_chain_verified'] is True
         and binding['final_was_directly_coldprocess_tested'] is chain['final_was_directly_coldprocess_tested'] is False
         and binding['independent_raw_audits_required_before_adoption'] is chain['independent_raw_audits_required_before_adoption'] is True
         and chain['adoption_assessed'] is False,
         'component-chain identity, validation or measurement scope differs')
    checked_bool_map(chain['checks'], 'component-chain source/producer checks failed')
    baseline_path = R19 / 'source/src/mcp/runtime/jobs.rs'
    status_path = intermediate / 'source/src/mcp/runtime/jobs.rs'
    cancel_path = intermediate / 'cancel-candidate-01/jobs.rs'
    final_path = SOURCE / 'src/mcp/runtime/jobs.rs'
    status_report_path = intermediate / 'coldprocess-probe-01/semantics.json'
    cancel_report_path = intermediate / 'cancelprocess-probe-01/semantics.json'
    status_tool_path = intermediate / 'tools/coldprocess_probe_02.py'
    cancel_tool_path = intermediate / 'cancel-tools-01/cancelprocess_probe_01.py'
    cancel_plan_path = intermediate / 'cancel-tools-01/measurement-plan-01.json'
    expected_refs = {
        baseline_path: BASELINE_JOBS_SHA, status_path: status_sha,
        cancel_path: final_sha, final_path: final_sha,
        status_report_path: status_report_sha,
        cancel_report_path: plan['cancelprocess']['semantics_sha256'],
        status_tool_path: plan['coldprocess_probe_sha256'],
        cancel_tool_path: plan['cancelprocess']['probe_sha256'],
        cancel_plan_path: plan['cancelprocess']['plan_sha256'],
    }
    refs = {str(item): {'path': str(item), **sized_identity(fingerprint(item, expected))}
            for item, expected in sorted(expected_refs.items(), key=lambda row: str(row[0]))}
    need(chain['referenced_files'] == binding['referenced_files'] == list(refs.values())
         and chain['final_source'] == refs[str(final_path)]
         and refs[str(final_path)]['size'] == refs[str(cancel_path)]['size'] == 186546,
         'actual component source/report/tool references differ')
    expected_steps = [
        ('status_lazy_import', 'STATUS_CODE', baseline_path, status_path, status_report_path, status_tool_path),
        ('cancel_lazy_import', 'CANCEL_CODE', status_path, cancel_path, cancel_report_path, cancel_tool_path),
    ]
    need(len(chain['steps']) == 2, 'component-chain transition count differs')
    step_bindings = []
    constant_names = {'PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'START_CODE',
                      'STATUS_CODE', 'READ_CODE', 'CANCEL_CODE'}
    for row, (name, constant, before_path, after_path, report_path, tool_path) in zip(chain['steps'], expected_steps):
        need(row['name'] == name and row['input_source'] == refs[str(before_path)]
             and row['output_source'] == refs[str(after_path)]
             and row['semantics_report'] == refs[str(report_path)] and row['probe_tool'] == refs[str(tool_path)],
             'component-chain step identities differ')
        delta = row['source_delta']
        need(delta['changed_constant'] == constant and delta['outside_constant_bytes_equal'] is True
             and delta['all_six_nonimport_asts_equal'] is True and set(delta['constants']) == constant_names
             and all(value['nonimport_ast_identical'] is True
                     and value['byte_identical'] is (key != constant) for key, value in delta['constants'].items()),
             'component transition changes beyond permitted imports')
        if name == 'cancel_lazy_import':
            need(row['plan'] == refs[str(cancel_plan_path)], 'CANCEL component plan differs')
        step_bindings.append({'name': name, 'input_source_sha256': refs[str(before_path)]['sha256'],
                              'output_source_sha256': refs[str(after_path)]['sha256'],
                              'semantics_report_sha256': refs[str(report_path)]['sha256']})
    need(binding['steps'] == step_bindings, 'flattened qualification chain differs')
    status_report, _ = document(status_report_path, status_report_sha)
    cancel_report, _ = document(cancel_report_path, plan['cancelprocess']['semantics_sha256'])
    need(status_report['schema'] == 'hepta-r20-coldprocess-semantics/v1'
         and status_report['passed'] is status_report['source_stable'] is True
         and status_report['baseline_source_sha256'] == BASELINE_JOBS_SHA
         and status_report['candidate_source_sha256'] == status_sha
         and status_report['probe_tool_sha256'] == plan['coldprocess_probe_sha256']
         and status_report['semantic_cases']['total'] == status_report['semantic_cases']['passed'] == 15
         and status_report['semantic_cases']['failed'] == 0 and status_report['fresh_process_count'] == 352,
         'original STATUS component producer report differs')
    checked_bool_map(status_report['checks'], 'original STATUS semantic checks failed')
    need(cancel_report['schema'] == 'hepta-r20-cancel-mechanism-semantics/v1'
         and cancel_report['passed'] is cancel_report['source_stable'] is cancel_report['complete_required_coverage'] is True
         and cancel_report['baseline_source_sha256'] == status_sha and cancel_report['candidate_source_sha256'] == final_sha
         and cancel_report['probe_tool_sha256'] == plan['cancelprocess']['probe_sha256']
         and cancel_report['plan_sha256'] == plan['cancelprocess']['plan_sha256']
         and cancel_report['mode'] == 'full' and len(cancel_report['cases']) == 17
         and all(row['passed'] is True for row in cancel_report['cases'])
         and cancel_report['actual_fresh_helper_processes'] == cancel_report['actual_helper_records'] == 228
         and cancel_report['actual_owned_target_records'] == cancel_report['real_targets_created'] == 66
         and cancel_report['automatic_retries'] == 0 and cancel_report['error'] is None,
         'original CANCEL component producer report differs')
    return {'chain_file': chain_id, 'qualified_binding': binding,
            'referenced_files': list(refs.values()), 'steps': step_bindings,
            'final_was_directly_coldprocess_tested': False,
            'independent_raw_audits_required_before_adoption': True,
            'hash_buffer_in_final_source': False,
            'superseded_r20_formal_campaign_executed': False}


def gate(args):
    """Bind accepted R21 proof to actual bytes without replaying R19 rejected attempts."""
    need(isinstance(QUALIFICATION_TOOLS_MANIFEST_SHA, str) and HEX.fullmatch(QUALIFICATION_TOOLS_MANIFEST_SHA)
         and set(QUALIFICATION_FILES) == {'qualify_candidate_01.py', 'verify_qualification_01.py', 'create_component_chain_01.py'},
         'R21 qualification tool identities are not frozen; draft cannot run')
    plan, plan_id = document(PLAN, PLAN_SHA)
    need(plan['schema'] == 'hepta-r21-measurement-plan/v1'
         and plan['baseline_commit'] == 'acdd07363cbff335e50c2944e02143d44ab03d6b'
         and plan['baseline_runtime_sha256'] == BASELINE_SHA
         and plan['automatic_performance_retries'] == 0 and plan['production_service_changes'] is False,
         'frozen measurement plan differs')
    need(plan['native']['order'] == 'ABBA' and plan['native']['calls_per_cell'] == 192
         and plan['native']['warmup_calls_per_cell'] == 24 and plan['native']['concurrency'] == [1, 8, 16]
         and plan['native']['workers'] == 2 and plan['native']['malloc_arena_max'] == 1
         and set(plan['native']['hosts']) == HOSTS
         and plan['native']['historical_main_is_distinct_linux_machine'] is True
         and plan['native']['regression_screen'] == {'aggregate_success_rate_b_over_a_min': 0.95, 'pooled_p95_b_over_a_max': 1.10}
         and plan['boundary'] == {'bursts': 2, 'attempts_per_burst': 32, 'successes_and_capacity_refusals_separate': True}
         and plan['lifecycle']['order'] == 'ABBA' and plan['lifecycle']['six_new_jobs_per_round'] == 6
         and plan['lifecycle']['phase_concurrency'] == 6
         and plan['lifecycle']['preserve_original_recovery_canary_behaviour'] is True,
         'fixed campaign dimensions or thresholds differ')

    acceptance, acceptance_id = document(R21 / 'independent-acceptance-01.json', args.expected_acceptance_sha256)
    control, control_id = document(R21 / 'qualification-control-01/report.json', args.expected_control_report_sha256)
    qualification, qualification_id = document(R21 / 'qualification-01/report.json', args.expected_qualification_report_sha256)
    freeze, freeze_id = document(R21 / 'source-freeze-01.json')
    middle, middle_id = document(R21 / 'source-middle-01.json')
    after, after_id = document(R21 / 'source-after-01.json')
    launch, launch_id = document(R21 / 'qualification-launch-01.json')
    outcome, outcome_id = document(R21 / 'qualification-exit-01.json')
    need(acceptance['schema'] == 'hepta-x230-independent-acceptance/v2'
         and acceptance['root'] == str(R21) and acceptance['attempt'] == 1 and acceptance['accepted'] is True,
         'candidate was not independently accepted')
    checked_bool_map(acceptance['checks'], 'independent qualification checks did not all pass')
    need(control['schema'] == 'hepta-x230-qualification-control/v1' and control['root'] == str(R21)
         and control['attempt'] == 1 and control['passed'] is True and control['current_stage'] == 'completed'
         and control.get('finished_utc') and control['automatic_retries'] == 0
         and control['source_full_before_middle_after_equal'] is True
         and control['qualification_report'] == {'path': str(R21 / 'qualification-01/report.json'), **sized_identity(qualification_id)}
         and control['independent_acceptance'] == {'path': str(R21 / 'independent-acceptance-01.json'), **sized_identity(acceptance_id)},
         'qualification controller is not terminal or does not bind actual proof')
    need(qualification['qualified'] is True and qualification['source'] == str(SOURCE)
         and qualification['jobs'] == 2 and qualification['automatic_test_retries'] == 0
         and qualification['service_changes'] is False
         and [row['name'] for row in qualification['stages']] == ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']
         and all(exact_zero(row['returncode']) for row in qualification['stages']),
         'complete fresh qualification did not pass')
    need(acceptance['qualified_report_sha256'] == qualification_id['sha256']
         and acceptance['source_freeze_sha256'] == freeze_id['sha256']
         and acceptance['source_middle_sha256'] == middle_id['sha256']
         and acceptance['source_after_sha256'] == after_id['sha256']
         and launch['source_freeze_sha256'] == freeze_id['sha256']
         and outcome['report_sha256'] == qualification_id['sha256']
         and outcome['source_middle_sha256'] == middle_id['sha256']
         and outcome['source_after_sha256'] == after_id['sha256'], 'qualification source-proof hash chain differs')
    need(outcome['attempt'] == launch['attempt'] == freeze['attempt'] == 1
         and outcome['success'] is True and exact_zero(outcome['returncode'])
         and outcome['source_full_before_middle_after_equal'] is True
         and outcome['source_inputs_before_after_equal'] is True and outcome['automatic_retries'] == 0
         and outcome['qualifier_reaped'] is outcome['qualifier_proc_absent'] is outcome['qualifier_process_group_absent'] is True
         and exact_zero(outcome['qualifier_returncode'])
         and outcome['qualifier_pid'] == launch['qualifier_pid']
         and outcome['qualifier_start_ticks'] == launch['qualifier_start_ticks'],
         'qualification child completion or source stability proof missing')
    need(launch['host'] == os.uname().nodename and launch['user'] == 'qian'
         and launch['environment_policy'] == 'explicit-allowlist/v2-no-wrapper-keys'
         and not any(name in launch['environment'] for name in
                     ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER')),
         'qualification host/account or absent-wrapper contract differs')

    stages = control['stages']
    need([row['name'] for row in stages] == ['fresh-qualification', 'independent-verification'], 'qualification control stage set differs')
    need(stages[0] == outcome['stage'], 'original qualifier child receipt differs')
    recorded, control_streams = [], []
    for row in [*control['toolchain_probes'], *stages]:
        need(exact_zero(row['returncode']) and row['waited_and_reaped'] is row['proc_absent'] is row['process_group_absent'] is True
             and row['timed_out'] is False and row['automatic_retries'] == 0
             and type(row['pid']) is int and row['pid'] > 1
             and type(row['start_ticks']) is int and row['start_ticks'] > 0,
             'qualification owned child not normally reaped')
        recorded.append({'pid': row['pid'], 'start_ticks': row['start_ticks']})
        for stream in ('stdout', 'stderr'):
            path = R21 / 'qualification-control-01' / (row['name'] + '.' + stream)
            actual = fingerprint(path)
            need(row[stream] == {'path': str(path), **sized_identity(actual)}, 'qualification control raw stream differs')
            control_streams.append(actual)

    baseline = {name: fingerprint(R19 / name, expected) for name, expected in BASELINE_PINS.items()}
    baseline_freeze, _ = document(R19 / 'source-freeze-02.json', BASELINE_PINS['source-freeze-02.json'])
    baseline_report, _ = document(R19 / 'qualification-02/report.json', BASELINE_PINS['qualification-02/report.json'])
    baseline_acceptance, _ = document(R19 / 'independent-acceptance-02.json', BASELINE_PINS['independent-acceptance-02.json'])
    need(baseline_report['qualified'] is True and baseline_acceptance['accepted'] is True, 'accepted R19 baseline proof differs')
    checked_bool_map(baseline_acceptance['checks'], 'R19 baseline independent checks failed')
    expected_baseline = {name: sized_identity(value) for name, value in baseline.items()}
    need(acceptance['baseline_bindings'] == freeze['baseline_bindings'] == expected_baseline,
         'qualification did not use this exact R19 baseline')

    source, original = full_source(SOURCE), full_source(R19 / 'source')
    inputs, old_inputs = compile_inputs(source), compile_inputs(original)
    need(len(source) == len(original) == 281 and set(source) == set(original)
         and len(inputs) == len(old_inputs) == 219
         and source == freeze['source_full_before'] == middle['source_full'] == after['source_full']
         and original == baseline_freeze['source_full_before']
         and old_inputs == baseline_report['source_input'] == baseline_report['source_tested'] == baseline_report['source_after']
         and inputs == freeze['source_inputs_before'] == middle['source_inputs'] == after['source_inputs']
         == qualification['source_input'] == qualification['source_tested'] == qualification['source_after'],
         'actual before/middle/after source maps differ')
    need([name for name in source if source[name] != original[name]] == ['src/mcp/runtime/jobs.rs']
         and inputs['src/mcp/runtime/jobs.rs'] == freeze['expected_jobs_sha256'] == plan['candidate_jobs_sha256']
         and old_inputs['src/mcp/runtime/jobs.rs'] == BASELINE_JOBS_SHA
         and inputs['src/bin/jobctl.rs'] == JOBCTL_SOURCE_SHA
         and acceptance['source_full_count'] == 281 and acceptance['source_input_count'] == 219
         and acceptance['changed_paths'] == ['src/mcp/runtime/jobs.rs'], 'candidate changed beyond the frozen one-file scope')
    source_map, source_map_id = document(R21 / 'qualification-01/source-map.json')
    need(source_map == inputs, 'original qualifier source map differs')

    tools_manifest, tools_manifest_id = document(R21 / 'tools/qualification-tools-manifest-01.json', QUALIFICATION_TOOLS_MANIFEST_SHA)
    qualification_tools = {name: fingerprint(R21 / 'tools' / name, expected) for name, expected in QUALIFICATION_FILES.items()}
    need(tools_manifest['files'] == {name: sized_identity(row) for name, row in qualification_tools.items()}
         and freeze['qualifier_sha256'] == launch['qualifier_sha256'] == QUALIFIER_SHA,
         'protected qualification tools differ')
    qualifier = fingerprint(SOURCE / 'tools/x230/20261028/qualify.py', QUALIFIER_SHA)
    component_chain = component_chain_gate(acceptance, freeze, launch, control, plan, inputs)

    names = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
    need(set(qualification['binaries']) == set(acceptance['binaries']) == set(control['binaries']) == names,
         'qualified binary set differs')
    binaries, release = {}, {}
    for name in sorted(names):
        path = R21 / 'qualification-01' / name
        reviewed = acceptance['binaries'][name]
        need(qualification['binaries'][name]['path'] == reviewed['path'] == str(path)
             and qualification['binaries'][name]['sha256'] == reviewed['sha256']
             and control['binaries'][name] == reviewed, 'binary proof rows differ')
        actual = fingerprint(path, reviewed['sha256'])
        need(actual['bytes'] == reviewed['size'], 'actual binary size differs')
        original_path = TARGET / 'release' / ('examples/native_process_driver' if name == 'native_process_driver' else name)
        release[name] = compiler_elf_fingerprint(original_path, actual['sha256'], actual['bytes'])
        need(release[name]['bytes'] == actual['bytes'], 'actual target/copy byte count differs')
        binaries[name] = actual
    need(binaries['hepta-runtime']['sha256'] == args.expected_candidate_sha256
         and binaries['hepta-runtime-jobctl']['sha256'] == JOBCTL_SHA, 'actual candidate runtime/jobctl differs')

    profile, topology = fingerprint(PROFILE, PROFILE_SHA), fingerprint(TOPOLOGY, TOPOLOGY_SHA)
    measurement = {name: fingerprint(TOOLS / name, expected) for name, expected in HARNESS_FILES.items()}
    boundary = {name: fingerprint(BOUNDARY_TOOLS / name, expected) for name, expected in BOUNDARY_FILES.items()}
    original_boundary = {name: fingerprint(ORIGINAL_BOUNDARY_TOOLS / name, expected) for name, expected in BOUNDARY_FILES.items()}
    boundary_freeze, _ = document(BOUNDARY_TOOLS / 'harness-freeze.json')
    need(boundary_freeze['files'] == HARNESS_FILES, 'boundary copy binds another measurement harness')
    frozen_jobs, members = {}, set()
    for path in sorted(FROZEN_JOBS.glob('*.json')):
        job, binding = document(path, maximum=65536)
        need(path.name == job['id'] + '.json' and job['host'] in HOSTS and job['launch_state'] == 'launched'
             and job['execution_mode'] == 'operator' and job['system_jobctl'] is False,
             'historical frozen job identity differs')
        members.add(job['host'])
        frozen_jobs[path.name] = binding
    need(len(frozen_jobs) == 6 and members == HOSTS, 'historical six-job set differs')
    lifecycle = lifecycle_gate()
    return {'measurement_plan': plan_id, 'installed_program_file': fingerprint(PROGRAM),
            'qualification_attempt': 1, 'qualification_control': control_id,
            'qualification': qualification_id, 'independent_acceptance': acceptance_id,
            'source_freeze': freeze_id, 'source_middle': middle_id, 'source_after': after_id,
            'qualification_launch': launch_id, 'qualification_exit': outcome_id,
            'qualification_control_streams': control_streams, 'recorded_qualification_processes': recorded,
            'source_map': source_map_id, 'source_full_files': 281, 'compile_inputs': 219,
            'source_full_map_sha256': canonical_digest(source), 'source_compile_map_sha256': canonical_digest(inputs),
            'baseline_full_map_sha256': canonical_digest(original),
            'baseline': baseline, 'binaries': binaries, 'target_release_binaries': release,
            'qualification_tool_manifest': tools_manifest_id, 'qualification_tools': qualification_tools,
            'qualifier': qualifier, 'component_chain': component_chain,
            'profile': profile, 'topology': topology, 'measurement_tools': measurement,
            'boundary_tools': boundary, 'original_boundary_tools': original_boundary,
            'lifecycle_tools': lifecycle, 'frozen_jobs': frozen_jobs, 'workers': 2, 'arena_max': 1}


def native_metrics(native, analysis):
    """Retain p99 and both chronological neighboring A/B pairs, without adding a gate."""
    rounds = native['rounds']
    need(len(rounds) == 4 and ''.join(row['version'] for row in rounds) == 'ABBA', 'native ABBA rounds differ')
    fields = {'calls_per_second': 'successful_rps', 'controller_cpu_ms_per_call': 'controller_cpu_ms_per_call',
              'p50_ms': 'p50_ms', 'p95_ms': 'p95_ms', 'p99_ms': 'p99_ms'}
    result = []
    for item in analysis['cases']:
        c = item['concurrency']
        cells = [next(cell for cell in row['cells'] if cell['concurrency'] == c) for row in rounds]
        pairs = []
        for left, right in ((0, 1), (3, 2)):
            changes = {}
            for key, source in fields.items():
                a, b = cells[left][source], cells[right][source]
                need(finite_positive(a) and finite_positive(b), 'invalid native pair metric')
                changes[key] = 100 * (b / a - 1)
            pairs.append({'baseline_round': left, 'candidate_round': right, 'change_percent_b_vs_a': changes})
        result.append({'concurrency': c, 'aggregate': item, 'adjacent_pairs': pairs})
    return {'cases': result, 'p99_is_reported_but_not_an_adoption_gate': True,
            'scope': 'one finite shared-host campaign; paired signs and pooled changes are not interchangeable'}


def lifecycle_gate():
    need(isinstance(LIFECYCLE_MANIFEST_SHA, str) and HEX.fullmatch(LIFECYCLE_MANIFEST_SHA),
         'lifecycle tools are not frozen; draft launcher cannot run')
    manifest, manifest_id = document(LIFECYCLE_TOOLS / 'lifecycle-tools-manifest-01.json', LIFECYCLE_MANIFEST_SHA)
    need(manifest['schema'] == 'hepta-r21-lifecycle-tools/v1' and isinstance(manifest['files'], dict)
         and {'run_lifecycle_abba_01.py', 'summarize_lifecycle_abba_01.py'} <= set(manifest['files']),
         'lifecycle tool manifest schema/set differs')
    actual = {}
    for name, expected in sorted(manifest['files'].items()):
        relative = safe_relative(name)
        need(len(relative.parts) == 1 and type(expected['bytes']) is int and expected['bytes'] > 0
             and HEX.fullmatch(expected['sha256']), 'invalid lifecycle source identity')
        row = fingerprint(LIFECYCLE_TOOLS / relative, expected['sha256'])
        need(row['bytes'] == expected['bytes'], 'lifecycle tool byte length differs')
        actual[name] = row
    return {'manifest': manifest_id, 'files': actual}


def run_lifecycle(stage, args, shared, report, save):
    # The helper owns four canary -> original analyzer pairs and its final
    # aggregate stage. Do not rerun the same per-round audits here.
    stage('lifecycle-abba', ['/usr/bin/python3', '-B', str(LIFECYCLE_TOOLS / 'run_lifecycle_abba_01.py'),
          '--baseline', str(BASELINE), '--candidate', str(CANDIDATE),
          '--expected-baseline-sha256', BASELINE_SHA,
          '--expected-candidate-sha256', args.expected_candidate_sha256, *shared,
          '--out', str(LIFECYCLE_OUT), '--socket-prefix', str(LIFECYCLE_SOCKET_PREFIX),
          '--expected-tools-manifest-sha256', LIFECYCLE_MANIFEST_SHA,
          '--workers', '2', '--arena-max', '1'], 3600,
          [LIFECYCLE_OUT / 'report.json', LIFECYCLE_OUT / 'round-index.json', LIFECYCLE_OUT / 'summary.json'])
    control, control_id = document(LIFECYCLE_OUT / 'report.json')
    summary, summary_id = document(LIFECYCLE_OUT / 'summary.json')
    index_id = fingerprint(LIFECYCLE_OUT / 'round-index.json')
    need(control['schema'] == 'hepta-r21-lifecycle-abba-control/v1' and control['passed'] is True
         and control['order'] == 'ABBA' and control['round_count'] == 4
         and control['inputs_unchanged'] is True and control['automatic_retries'] == 0
         and control['baseline'] == fingerprint(BASELINE, BASELINE_SHA)
         and control['candidate'] == fingerprint(CANDIDATE, args.expected_candidate_sha256)
         and control['round_index'] == index_id and control['summary'] == summary_id,
         'lifecycle control or closed index/summary binding differs')
    need(summary['schema'] == 'hepta-r21-lifecycle-abba-summary/v1' and summary['verified'] is True
         and summary['order'] == 'ABBA' and summary['round_count'] == 4
         and summary['total_new_starts'] == 24 and summary['total_same_key_lookups'] == 48
         and summary['total_cancellations'] == 48
         and summary['round_index_sha256'] == index_id['sha256']
         and summary['tools_manifest_sha256'] == LIFECYCLE_MANIFEST_SHA
         and len(control['rounds']) == len(summary['rounds']) == 4,
         'lifecycle ABBA scope or total effects differ')
    rounds, phase_files = [], []
    for number, arm in enumerate('ABBA'):
        row, measured = control['rounds'][number], summary['rounds'][number]
        directory = LIFECYCLE_OUT / f'round-{number}-{arm}'
        raw = fingerprint(directory / 'report.json')
        independent, independent_id = document(directory / 'independent-summary.json')
        binary_sha = BASELINE_SHA if arm == 'A' else args.expected_candidate_sha256
        need(row['index'] == measured['index'] == number and row['arm'] == measured['arm'] == arm
             and row['directory'] == directory.name and row['report'] == raw
             and row['independent_analysis'] == independent_id
             and measured['report_sha256'] == raw['sha256']
             and measured['independent_analysis_sha256'] == independent_id['sha256']
             and measured['candidate_sha256'] == binary_sha
             and measured['new_starts'] == 6 and measured['same_key_lookups'] == measured['cancellations'] == 12
             and measured['phase_count'] == 11 and measured['measured_controller_phase_count'] == 10
             and independent['verified'] is True and independent['candidate_sha256'] == binary_sha
             and independent['source_sha256'] == raw['sha256'],
             'original lifecycle round/analyzer/phase binding differs')
        need(isinstance(row['phase_files'], list) and len(row['phase_files']) == 11, 'lifecycle raw phase files missing')
        seen = set()
        for item in row['phase_files']:
            path = Path(item['path'])
            need(path.is_relative_to(directory) and path not in seen, 'lifecycle phase file escaped/repeated')
            seen.add(path)
            current = fingerprint(path)
            need(item == current, 'actual lifecycle phase file differs')
            phase_files.append(current)
        rounds.append({'index': number, 'arm': arm, 'report': raw, 'independent_analysis': independent_id})
    stages = control['stages']
    expected_names = [name for number, arm in enumerate('ABBA')
                      for name in (f'canary-{number}-{arm}', f'audit-{number}-{arm}')] + ['summary']
    need([row['name'] for row in stages] == expected_names, 'lifecycle internal stage order/count differs')
    process_receipts, streams = [], []
    for row in stages:
        need(exact_zero(row['returncode']) and row['waited_and_reaped'] is row['proc_absent'] is True
             and row['owned_process_group_absent'] is True and row['automatic_retry'] is False
             and type(row['pid']) is int and row['pid'] > 1
             and type(row['start_ticks']) is int and row['start_ticks'] > 0,
             'lifecycle child stage was not successfully reaped')
        current = process_identity(row['pid'])
        need(current is None or current['start_ticks'] != row['start_ticks'], 'lifecycle child identity still present')
        process_receipts.append({'name': row['name'], 'pid': row['pid'], 'start_ticks': row['start_ticks'],
                                 'waited_and_reaped': True, 'original_identity_absent': True})
        for stream in ('stdout', 'stderr'):
            path = Path(row[stream]['path'])
            need(path.is_relative_to(LIFECYCLE_OUT), 'lifecycle stage stream outside its output')
            current = fingerprint(path)
            need(row[stream] == current, 'lifecycle stage raw stream differs')
            streams.append(current)
    report['lifecycle_evidence'] = {'report': control_id, 'round_index': index_id, 'summary': summary_id,
        'rounds': rounds, 'phase_files': phase_files, 'stage_streams': streams,
        'stage_process_receipts': process_receipts, 'order': 'ABBA', 'round_count': 4,
        'new_starts': 24, 'same_key_lookups': 48, 'cancellations': 48,
        'native_total_call_count_is_not_hardcoded': True,
        'scope': 'four bounded C6 lifecycle rounds with original canary semantics and original per-round raw auditor; not maximum sustainable launch throughput'}
    save()


def process_group_absent(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


def stop_owned_stage(child, row, notify):
    """Let the frozen harness clean its private controllers before last-resort kill."""
    cleanup = {'pid': child.pid, 'signals': [], 'grace_seconds': 120,
               'scope': 'this exact Popen child and its newly created process group only',
               'nested_cleanup_delegated_to_frozen_harness': True,
               'escaped_descendants_fully_accounted_for': False}
    row['owned_cleanup'] = cleanup
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
        cleanup['signals'].append({'target': 'direct_child', 'signal': 'SIGINT'})
    deadline, next_notice = time.monotonic() + 120, time.monotonic()
    while child.poll() is None and time.monotonic() < deadline:
        if time.monotonic() >= next_notice:
            notify('owned-cleanup-wait')
            next_notice = time.monotonic() + 15
        time.sleep(0.5)
    if child.poll() is None:
        # The still-owned, unreaped leader anchors this exact new PGID. Once
        # reaped, a numeric PGID alone is not enough authority to send a signal.
        os.killpg(child.pid, signal.SIGTERM)
        cleanup['signals'].append({'target': 'owned_process_group', 'signal': 'SIGTERM'})
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            cleanup['signals'].append({'target': 'owned_process_group', 'signal': 'SIGKILL'})
            cleanup['forced_kill_nested_cleanup_uncertain'] = True
    child.wait(timeout=10)
    cleanup.update(waited_and_reaped=child.returncode is not None,
                   process_group_absent=process_group_absent(child.pid),
                   no_signals_after_leader_reaped=True)


def interrupted(signum, _frame):
    raise InterruptedError('received ' + signal.Signals(signum).name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--launcher-sha256', required=True,
                        help='Mac holder receipt for stdin bootstrap bytes, not a remote self-hash')
    parser.add_argument('--expected-acceptance-sha256', required=True)
    parser.add_argument('--expected-control-report-sha256', required=True)
    parser.add_argument('--expected-qualification-report-sha256', required=True)
    parser.add_argument('--expected-candidate-sha256', required=True)
    args = parser.parse_args()
    need(all(HEX.fullmatch(value) for value in vars(args).values()), 'all startup identities must be lowercase SHA256')
    need(sys.platform == 'linux' and os.geteuid() == 1000, 'wrong execution platform/account')
    need(R21.is_dir() and R21.resolve() == R21, 'reserved R21 root unavailable')
    need(CONTROL.resolve() == CONTROL and not os.path.lexists(CONTROL), 'fresh direct control directory required')
    CONTROL.mkdir(mode=0o700)
    report = {'schema': 'hepta-r21-six-host-campaign/v1', 'started_utc': utc(), 'passed': False,
              'current_stage': 'initial-gate', 'qualification_attempt': 1,
              'mac_stdin_source_sha256': args.launcher_sha256,
              'launcher_identity_scope': 'Mac holder receipt for stdin bootstrap; bootstrap verifies fixed installed launcher bytes before exec; not an independent remote self-hash',
              'expected_startup_hashes': {key: value for key, value in vars(args).items() if key != 'launcher_sha256'},
              'automatic_campaign_retries': 0, 'automatic_stage_retries': 0, 'automatic_rpc_retries': 0,
              'production_service_changes': False, 'builds_started': 0, 'machine_settings_changed': False,
              'stages': [], 'native_regression_screen': None,
              'adoption_decision_made_here': False,
              'scope': 'one finite native observation, C32 overload and C6 lifecycle campaign; not global optimality or maximum launch throughput'}
    initial = None

    def save():
        atomic_json(CONTROL / 'report.json', report)
        atomic_json(CONTROL / 'progress.json', {'schema': 'hepta-r21-campaign-progress/v1',
                    'updated_utc': utc(), 'current_stage': report['current_stage'], 'passed': report['passed'],
                    'stage_count': len(report['stages']), 'stage_pid': report.get('stage_pid'),
                    'stage_elapsed_seconds': report.get('stage_elapsed_seconds'),
                    'quiescence_elapsed_seconds': report.get('quiescence', {}).get('elapsed_seconds'),
                    'error': report.get('error')})

    def unchanged():
        current = gate(args)
        need(current == initial, 'accepted campaign inputs changed')

    def stage(name, command, timeout, artifacts):
        report['current_stage'] = name + ':pre-gate'
        save()
        unchanged()
        idle = compilation_idle(initial['recorded_qualification_processes'])
        need(idle['idle'], 'qualification or compiler conflict before ' + name)
        row = {'name': name, 'argv': command, 'cwd': str(Path(command[2]).parent),
               'script_sha256': fingerprint(command[2])['sha256'], 'timeout_seconds': timeout,
               'before': snapshot(), 'compiler_check_before': idle,
               'start_monotonic_ns': time.monotonic_ns(), 'pre_gate_passed': True,
               'post_gate_passed': False, 'returncode': None, 'automatic_retry': False}
        report['stages'].append(row)
        report['current_stage'] = name
        child, failure = None, None
        stdout_path, stderr_path = CONTROL / (name + '.stdout'), CONTROL / (name + '.stderr')

        def notice(state):
            row['elapsed_seconds'] = (time.monotonic_ns() - row['start_monotonic_ns']) / 1e9
            report['stage_elapsed_seconds'] = row['elapsed_seconds']
            save()
            print(json.dumps({'stage': name, 'state': state, 'elapsed_seconds': row['elapsed_seconds']}), flush=True)

        try:
            save()
            environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'SHELL': '/bin/sh',
                           'HOME': '/home/qian', 'SSH_AUTH_SOCK': os.environ['SSH_AUTH_SOCK'],
                           'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
            with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
                child = subprocess.Popen(command, cwd=Path(command[2]).parent, env=environment,
                                         stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                         start_new_session=True)
                identity = process_identity(child.pid)
                need(identity is not None, 'stage child identity unavailable')
                row.update(pid=child.pid, start_ticks=identity['start_ticks'], process_group=child.pid,
                           started_new_session=True)
                report['stage_pid'] = child.pid
                notice('started')
                deadline, next_notice = time.monotonic() + timeout, time.monotonic() + 15
                while child.poll() is None:
                    if time.monotonic() >= deadline:
                        raise subprocess.TimeoutExpired(command, timeout)
                    if time.monotonic() >= next_notice:
                        notice('running')
                        next_notice = time.monotonic() + 15
                    time.sleep(1)
                row['returncode'] = child.wait()
            row.update(waited_and_reaped=True, proc_path_absent=not Path('/proc', str(child.pid)).exists(),
                       process_group_absent=process_group_absent(child.pid))
            need(exact_zero(row['returncode']) and row['proc_path_absent'] and row['process_group_absent'],
                 name + ' failed or did not release its owned stage process; no retry')
            need(all(path.is_file() for path in artifacts), name + ' did not retain all required artifacts')
        except BaseException as error:
            failure = error
            row['error'] = {'type': type(error).__name__, 'reason': str(error)}
            row['timed_out'] = isinstance(error, subprocess.TimeoutExpired)
            if child is not None:
                try:
                    stop_owned_stage(child, row, notice)
                except BaseException as cleanup_error:
                    row['owned_cleanup_error'] = {'type': type(cleanup_error).__name__, 'reason': str(cleanup_error)}
                row.update(returncode=child.poll(), waited_and_reaped=child.returncode is not None,
                           proc_path_absent=not Path('/proc', str(child.pid)).exists(),
                           process_group_absent=process_group_absent(child.pid))
            try:
                write_new(CONTROL / (name + '.error.txt'), traceback.format_exc().encode())
            except BaseException as write_error:
                row['error_stream_write_error'] = type(write_error).__name__ + ': ' + str(write_error)
        finally:
            row['end_monotonic_ns'] = time.monotonic_ns()
            row['seconds'] = (row['end_monotonic_ns'] - row['start_monotonic_ns']) / 1e9
            row['logs'], row['artifacts'], row['finalization_errors'] = [], [], []
            try:
                row['after'] = snapshot()
                row['compiler_check_after'] = compilation_idle(initial['recorded_qualification_processes'])
                need(row['compiler_check_after']['idle'], 'qualification or compiler conflict after ' + name)
            except BaseException as error:
                row['finalization_errors'].append(type(error).__name__ + ': ' + str(error))
                failure = failure or error
            paths = [('logs', CONTROL / (name + '.' + suffix)) for suffix in ('stdout', 'stderr', 'error.txt')]
            paths.extend(('artifacts', path) for path in artifacts)
            for group, path in paths:
                if not path.exists():
                    continue
                try:
                    row[group].append(fingerprint(path))
                except BaseException as error:
                    row[group].append({'path': str(path), 'error': type(error).__name__ + ': ' + str(error)})
                    failure = failure or error
            report['current_stage'] = name + ':post-gate'
            try:
                unchanged()
                row['post_gate_passed'] = True
            except BaseException as error:
                row['post_gate_error'] = {'type': type(error).__name__, 'reason': str(error)}
                failure = failure or error
            report['stage_pid'] = None
            report['stage_elapsed_seconds'] = row['seconds']
            try:
                save()
            except BaseException as error:
                failure = failure or error
            print(json.dumps({'stage': name, 'returncode': row['returncode'],
                              'post_gate_passed': row['post_gate_passed'], 'seconds': row['seconds']}), flush=True)
        if failure is not None:
            raise failure

    try:
        save()
        for path in (NATIVE_OUT, BOUNDARY_OUT, LIFECYCLE_OUT, NATIVE_SOCKET, BOUNDARY_SOCKET, LIFECYCLE_SOCKET_PREFIX):
            need(path.resolve() == path and not os.path.lexists(path), 'fresh output/socket required: ' + str(path))
        initial = gate(args)
        report['gate'] = initial
        for label, path in (
            ('measurement-plan-01.json', PLAN),
            ('qualification-acceptance-input.json', R21 / 'independent-acceptance-01.json'),
            ('qualification-control-input.json', R21 / 'qualification-control-01/report.json'),
            ('qualification-report-input.json', R21 / 'qualification-01/report.json'),
            ('source-freeze-input.json', R21 / 'source-freeze-01.json'),
            ('source-middle-input.json', R21 / 'source-middle-01.json'),
            ('source-after-input.json', R21 / 'source-after-01.json')):
            _, raw = stable_file(path, maximum=16 * 1024 * 1024, retain=True)
            write_new(CONTROL / label, raw)
        report['boundary_copy_contract'] = {'original': initial['original_boundary_tools'],
            'copied': initial['boundary_tools'], 'all_original_and_copied_sha256_equal': True,
            'source_code_changes': False, 'installation_performed_by_this_launcher': False,
            'raw_output': str(BOUNDARY_OUT), 'explicit_harness_root': str(TOOLS)}
        cooling = {'seconds_required': QUIESCENCE_SECONDS, 'start_monotonic_ns': time.monotonic_ns(),
                   'elapsed_seconds': 0.0, 'before': snapshot(), 'checks': [], 'settings_changed': False,
                   'signals_sent': 0, 'passed': False}
        report['current_stage'] = 'pre-measurement-quiescence'
        report['quiescence'] = cooling
        first_idle = compilation_idle(initial['recorded_qualification_processes'])
        cooling['checks'].append({'elapsed_seconds': 0.0, **first_idle})
        need(first_idle['idle'], 'qualification or compiler process still active; no automatic wait-and-retry')
        save()
        deadline, next_notice = time.monotonic() + QUIESCENCE_SECONDS, time.monotonic() + 15
        while time.monotonic() < deadline:
            time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
            cooling['elapsed_seconds'] = (time.monotonic_ns() - cooling['start_monotonic_ns']) / 1e9
            if time.monotonic() >= next_notice:
                idle = compilation_idle(initial['recorded_qualification_processes'])
                cooling['checks'].append({'elapsed_seconds': cooling['elapsed_seconds'], **idle})
                need(idle['idle'], 'compiler/qualification conflict during quiescence')
                save()
                print(json.dumps({'stage': 'pre-measurement-quiescence',
                                  'elapsed_seconds': cooling['elapsed_seconds']}), flush=True)
                next_notice = time.monotonic() + 15
        cooling['end_monotonic_ns'] = time.monotonic_ns()
        cooling['elapsed_seconds'] = (cooling['end_monotonic_ns'] - cooling['start_monotonic_ns']) / 1e9
        idle = compilation_idle(initial['recorded_qualification_processes'])
        cooling['checks'].append({'elapsed_seconds': cooling['elapsed_seconds'], **idle})
        cooling['after'] = snapshot()
        need(cooling['elapsed_seconds'] >= 90 and idle['idle'], 'quiescence did not complete')
        cooling['passed'] = True
        save()
        unchanged()
        shared = ['--profile-template', str(PROFILE), '--topology', str(TOPOLOGY), '--frozen-jobs', str(FROZEN_JOBS)]
        NATIVE_SOCKET.mkdir(mode=0o700)
        stage('native-observation', ['/usr/bin/python3', '-B', str(TOOLS / 'run_native_observation.py'),
              '--baseline', str(BASELINE), '--candidate', str(CANDIDATE), '--arena-max', '1', *shared,
              '--socket-parent', str(NATIVE_SOCKET), '--out', str(NATIVE_OUT), '--calls', '192',
              '--concurrency', '1', '8', '16', '--workers', '2', '--order', 'ABBA', '--warmup-calls', '24'],
              1800, [NATIVE_OUT / 'report.json'])
        stage('native-independent-audit', ['/usr/bin/python3', '-B', str(TOOLS / 'analyze_native_observation.py'),
              '--report', str(NATIVE_OUT / 'report.json'), '--output', str(NATIVE_OUT / 'independent-summary.json')],
              180, [NATIVE_OUT / 'independent-summary.json'])
        native, native_id = document(NATIVE_OUT / 'report.json')
        analysis, analysis_id = document(NATIVE_OUT / 'independent-summary.json')
        hashes = {'A': BASELINE_SHA, 'B': args.expected_candidate_sha256}
        need(native['passed'] is True and native['binary_sha256'] == hashes and native['tokio_workers'] == 2
             and native['calls_per_cell'] == 192 and native['concurrency'] == [1, 8, 16]
             and native['order'] == 'ABBA' and native['r16_measurement']['balanced_warmup_calls_per_cell'] == 24
             and analysis['verified'] is True and analysis['original_sha256'] == native_id['sha256']
             and analysis['binary_sha256'] == hashes and analysis['failed_calls'] == 0
             and analysis['measured_calls'] == 2304 and analysis['warmup_calls'] == 288
             and analysis['preflight_restart_calls'] == 72 and analysis['total_calls'] == 2664,
             'native evidence differs from fixed protocol')
        report['native_regression_screen'] = native_decision(analysis)
        report['native_metrics'] = native_metrics(native, analysis)
        report['native_evidence'] = {'report': native_id, 'independent_analysis': analysis_id}
        save()  # A performance rejection never suppresses later correctness stages.

        BOUNDARY_SOCKET.mkdir(mode=0o700)
        stage('native-boundary', ['/usr/bin/python3', '-B', str(BOUNDARY_TOOLS / 'run_native_boundary.py'),
              '--binary', str(CANDIDATE), *shared, '--socket-parent', str(BOUNDARY_SOCKET),
              '--out', str(BOUNDARY_OUT), '--bursts', '2', '--harness-root', str(TOOLS)],
              600, [BOUNDARY_OUT / 'report.json'])
        stage('boundary-independent-audit', ['/usr/bin/python3', '-B', str(BOUNDARY_TOOLS / 'audit_native_boundary.py'),
              '--report', str(BOUNDARY_OUT / 'report.json'), '--output', str(BOUNDARY_OUT / 'independent-summary.json'),
              '--harness-root', str(TOOLS)], 180, [BOUNDARY_OUT / 'independent-summary.json'])
        boundary, boundary_id = document(BOUNDARY_OUT / 'independent-summary.json')
        raw_boundary, raw_boundary_id = document(BOUNDARY_OUT / 'report.json')
        need(boundary['evidence_verified'] is True and boundary['diagnostic_passed'] is True
             and boundary['candidate_sha256'] == args.expected_candidate_sha256
             and boundary['report_sha256'] == raw_boundary_id['sha256']
             and boundary['drain_and_recovery_passed'] is True and len(boundary['bursts']) == 2
             and raw_boundary['attempts_per_burst'] == 32 and raw_boundary['tokio_workers'] == 2 and raw_boundary['arena_max'] == 1
             and set(boundary['counts']) <= {'success', 'capacity_rejection', 'other_error'}
             and boundary['counts'].get('other_error', 0) == 0 and sum(boundary['counts'].values()) == 64
             and boundary['classification_policy_sha256'] == BOUNDARY_FILES['capacity-policy.json'],
             'capacity classification, drain or recovery differs')
        report['boundary_evidence'] = {'report': raw_boundary_id, 'independent_analysis': boundary_id,
            'counts': boundary['counts'], 'fixed_rejection_count_required': False,
            'capacity_rejections_count_as_successful_throughput': False}
        save()

        run_lifecycle(stage, args, shared, report, save)
        unchanged()
        final_idle = compilation_idle(initial['recorded_qualification_processes'])
        need(final_idle['idle'], 'compiler conflict at campaign closure')
        report.update(passed=True, current_stage='completed', final_compiler_check=final_idle,
                      all_input_hashes_preserved=True, all_correctness_stages_passed=True,
                      native_regression_screen_passed=report['native_regression_screen']['passed'])
    except BaseException as error:
        report['error'] = {'type': type(error).__name__, 'reason': str(error)}
        report['current_stage'] = 'failed'
        try:
            write_new(CONTROL / 'campaign.error.txt', traceback.format_exc().encode())
        except BaseException as write_error:
            report['error_stream_write_error'] = type(write_error).__name__ + ': ' + str(write_error)
    finally:
        report['finished_utc'] = utc()
        try:
            save()
        except BaseException as finalization_error:
            report['passed'] = False
            print(json.dumps({'finalization_error': type(finalization_error).__name__ + ': ' + str(finalization_error)}), file=sys.stderr, flush=True)
        print(json.dumps({'passed': report['passed'],
                          'native_regression_screen_passed': report.get('native_regression_screen_passed'),
                          'error': report.get('error'), 'report': str(CONTROL / 'report.json'),
                          'progress': str(CONTROL / 'progress.json')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupted)
    raise SystemExit(main())
