#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve one original D2 C1 diagnostic capture with bounded zero-extraction verification.

No original auditor, trace parser, monitor validator, runtime, or archived source
is executed. Failed/partial results retain their original bytes and statements.
ACTUAL is deliberately unsealed until the original holder terminal exists.
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

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
MAC_HOLDER = Path('/Users/qianqi/work/hepta-runtime-d2-c1-holder-02')
MAX_TOTAL = 384 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_MANIFEST = 2 * 1024 * 1024
MAX_FILES = 8192
MAX_TAR = MAX_TOTAL + MAX_MANIFEST + MAX_FILES * 1024 + 1024 * 1024
STAGES = ['native-observation', 'native-audit']
COUNTS = ('measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')
COLLECT_DIRS = ('c1-campaign-02', 'c1-observation-02', 'c1-adapter-evidence-02', 'c1-holder-originals-02')
SKIP_DIRS = {'__pycache__', 'target', 'test-binaries', '.ssh', 'secrets', '.git', 'profile', 'target-build', 'credentials', 'keys'}
SKIP_FILES = {'id_rsa', 'runtime.json', 'id_ecdsa', 'runtime-config.json', 'credentials.json', 'ssh_config', 'id_ed25519', 'agent.sock', 'known_hosts', 'secrets.json'}
PINNED = {"c1-tools-02/compiler-monitor-policy-01.json": {"bytes": 1001, "sha256": "ddb2e03d4a1a1610466a5dc2d1a544f554ad12fc31412483101b48a235402368"}, "c1-tools-02/compiler_monitor.py": {"bytes": 12510, "sha256": "afb514362a9d8dd573b806f0dc87df16bd3a906e4574d10d91bf483b2e76cdcf"}, "c1-tools-02/compiler_state.py": {"bytes": 6243, "sha256": "9da718654db04a646e081d2d719a2d6d4655ffe337bc0e3f906e736e4d77a251"}, "c1-tools-02/d2_prerequisites.py": {"bytes": 59048, "sha256": "2a04eb862c4efe1377a3b78dad33b99f43573d7c91dc66503ad5f08690b17da9"}, "c1-tools-02/pre-execution-clarification-01.json": {"bytes": 3821, "sha256": "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"}, "c1-tools-02/reference/allocator_environment.py": {"bytes": 5879, "sha256": "f5c8e879c540b3f7cb1b7d3a7a0f5002c2f40c1a87963174b0b00470fa3a4525"}, "c1-tools-02/reference/allocator_environment_audit.py": {"bytes": 6709, "sha256": "4b082ce343ae3943e3098baa58af2f5def7198881b9c087d63d88360e9763727"}, "c1-tools-02/reference/analyze_native_observation.py": {"bytes": 8708, "sha256": "cc7f6884d581cd1ced430437350e808de51931c50d12441797205501b20cae66"}, "c1-tools-02/reference/audit_native_evidence.py": {"bytes": 17065, "sha256": "b69f6902d2de81eab41b21506f024c002d2f8264d60e86df6b1086623a77fd28"}, "c1-tools-02/reference/correlate_trace.py": {"bytes": 15615, "sha256": "891f511e80273c5fb4a1a76ff3606b7de90827c3eab5d01bb3e283dba952cd84"}, "c1-tools-02/reference/observation_resources.py": {"bytes": 12382, "sha256": "f3402d51cb37b2fe20f4351b3a81ec5990a9fdaff93a846d21c07ccd557cb894"}, "c1-tools-02/reference/run_native_observation.py": {"bytes": 3279, "sha256": "7606648c99b2ff2bbf0bba58384e8cab609ac3899f838c0b80ba54d6288d20bb"}, "c1-tools-02/reference/summarize_trace.py": {"bytes": 15070, "sha256": "ca0e7e0d7c670daec20e54c6703bc1849f80138224570ef5366abd60079c7927"}, "c1-tools-02/reference/x230_observation_benchmark.py": {"bytes": 37006, "sha256": "4d96f0bf2da2562e788f48be7c37589ab3a513be5f9d8b2d741afe5c08ea9eed"}, "c1-tools-02/validate_compiler_monitor.py": {"bytes": 7055, "sha256": "d2cd009adf1f35a394ffddcc8f8646cc0c1b856b78181ca321ea68f6468218b2"}}
REQUIRED = sorted(PINNED)
RUNTIME_PATHS = ["c1-campaign-inputs-02.json", "c1-prerequisites-02.json", "c1-tools-02/d2_campaign.py", "c1-tools-02/run_c1_phase_cost.py"]
CHANGED_PATHS = {'src/mcp/runtime/phase_cost.rs', 'src/mcp/runtime/ssh_observation_profile.rs'}
CORE_PATHS = ["c1-holder-native-02.json", "c1-holder-report-02.json", "c1-holder-start-02.json", "c1-parent-install-02.json", "c1-campaign-02/report.json", "c1-campaign-02/summary.json", "c1-campaign-02/source-inputs.json", "c1-campaign-02/baseline-source-inputs.json", "c1-campaign-02/compiler-monitor.json", "c1-campaign-02/compiler-monitor.audit.json", "c1-observation-02/report.json", "c1-observation-02/independent-summary.json", "c1-adapter-evidence-02/adapter-report.json", "c1-campaign-inputs-02.json", "c1-prerequisites-02.json", "c1-tools-02/d2_campaign.py", "c1-tools-02/run_c1_phase_cost.py"]
SOURCE_REFERENCE_SHA256 = "7ac7eaf9a5861d5a4cd7e7fe16ebcedab4996551f0ada79a1a3cfb2066495bcc"
VERIFY_REFERENCE_SHA256 = SOURCE_REFERENCE_SHA256
EXTERNAL_EVIDENCE_REFERENCES = {"current_full_prerequisite_document": "/home/qian/hepta-runtime-validation-cost-20261106-d2/c1-prerequisites-02.json", "exact_ci_collection_or_archive": None, "ordinary_archive": None, "qualification_archive": None, "scope": "Current full Q/CI prerequisite bytes and original parent ordinary proof are retained. Separate complete prerequisite collections remain external; no future archive hash is invented and no prerequisite body is revalidated or executed here."}
ACTUAL = {'schema': 'hepta-d2-c1-archive-actual-pins/v1', 'sealed': True, 'holder_original_job_id': '1a1b17c22ac-fc05-7912', 'outcome': 'diagnostic_passed', 'native_read_paths': ['c1-holder-native-read-02-000.json'], 'counts': {'measured_calls': 768, 'warmup_calls': 96, 'preflight_restart_calls': 72, 'total_calls': 936, 'failed_calls': 0}, 'files': {'c1-holder-native-02.json': {'bytes': 729, 'sha256': '53bb106afab53405bfd63a578af881f920182336e269e300ae354e6e776c1b90'}, 'c1-holder-report-02.json': {'bytes': 9074, 'sha256': '81490b6b94eb8b1b71c852e08eab4148fe6c721f0ded6ebb52704de79a3150d1'}, 'c1-holder-start-02.json': {'bytes': 1340, 'sha256': '0c36e474e9b09bc12f5b1a33ba2442143f226e6ddbf8c18589aa54070ea8984b'}, 'c1-parent-install-02.json': {'bytes': 5202, 'sha256': 'c3b401567e2d4568c12bdc5890626d77495cec8faa9da5e9eb48eeec33da01d6'}, 'c1-campaign-02/report.json': {'bytes': 438085, 'sha256': '3e68a352726ed629052210f43b10f0922977d93409edc833897620cd74200dbf'}, 'c1-campaign-02/summary.json': {'bytes': 45021, 'sha256': 'a230b7100ff4c02ae8492d3eccd03c464675a85f97790e8ba6ad4677128e9b89'}, 'c1-campaign-02/source-inputs.json': {'bytes': 35211, 'sha256': '18b631ef2d5f3b6ed5afe05ca7d3140a6126e9554d1ce738a514b7e20b6c7275'}, 'c1-campaign-02/baseline-source-inputs.json': {'bytes': 35206, 'sha256': '30ce8443e15c5661c2be4e128c4c221206a39c83a9e42aaa039fbb990183aadf'}, 'c1-campaign-02/compiler-monitor.json': {'bytes': 167686, 'sha256': 'e0d750da747104a0d8c8a54740bf2f537c4cb2e8253b55ea0c7ef65644104c8a'}, 'c1-campaign-02/compiler-monitor.audit.json': {'bytes': 851, 'sha256': 'd0040d94c23329173891ba9406f7726812e2a10891c8546f31c476e7970c6fb9'}, 'c1-observation-02/report.json': {'bytes': 1259596, 'sha256': '99872439a50f7b833d97224dbac957b665b6c691ffcc56d0fddbd13ef9252371'}, 'c1-observation-02/independent-summary.json': {'bytes': 52996, 'sha256': '77817a6eec834aabe00c3e165119769c9c042c0318fe731f782cc225985c7057'}, 'c1-adapter-evidence-02/adapter-report.json': {'bytes': 8827749, 'sha256': 'd882031e45096ddddee57dd83b580b5dc3ff15ebe2481b9c9a1dd2d109d44807'}, 'c1-campaign-inputs-02.json': {'bytes': 2553, 'sha256': '93071c7efc9f440c055323edb6b99e1c335a3bfcb11063f7130d73691b4a2241'}, 'c1-prerequisites-02.json': {'bytes': 7538, 'sha256': '39ee58937fdb05bd97bde4dc7c9ef1033b5744c7d52b6613bc0368f9af54ed63'}, 'c1-tools-02/d2_campaign.py': {'bytes': 52423, 'sha256': '187db501e760902fcdd7f52f25f64ae7b017d50f9feea89d98cf7952dbdfe3ff'}, 'c1-tools-02/run_c1_phase_cost.py': {'bytes': 33622, 'sha256': '428d76687aa626946e9b069cdf40cd3034b9ed4e71e357a5765e0db07a85102c'}, 'c1-holder-native-read-02-000.json': {'bytes': 1204, 'sha256': '444ffa1fb0d2ac39c33a4166bdc72d3129a5f91e4e5c87bf86ea07878dd4f667'}}}


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


def require_sealed():
    need(not sys.flags.optimize, 'original receipt assertions must be enabled')
    need(type(ACTUAL) is dict and ACTUAL.get('schema') == 'hepta-d2-c1-archive-actual-pins/v1'
         and ACTUAL.get('sealed') is True,
         'UNSEALED: actual original holder terminal/pages and captured C1 receipts are required')
    job = ACTUAL.get('holder_original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual holder job identity is missing')
    need(ACTUAL.get('outcome') in {'diagnostic_passed', 'not_passed'}, 'actual diagnostic outcome missing')
    pages = ACTUAL.get('native_read_paths')
    need(type(pages) is list and 1 <= len(pages) <= 16
         and pages == ['c1-holder-native-read-02-%03d.json' % i for i in range(len(pages))],
         'complete original contiguous holder page inventory required')
    files = ACTUAL.get('files')
    need(type(files) is dict and set(files) == set(CORE_PATHS) | set(pages),
         'actual captured core file inventory differs')
    for name, pin in files.items():
        need(pin is None or (type(pin) is dict and set(pin) == {'bytes', 'sha256'}
             and type(pin['bytes']) is int and 0 <= pin['bytes'] <= MAX_FILE
             and type(pin['sha256']) is str and len(pin['sha256']) == 64
             and set(pin['sha256']) <= set('0123456789abcdef')), 'invalid actual pin: ' + name)
    need(all(files[name] is not None for name in ['c1-holder-native-02.json', *pages, *RUNTIME_PATHS]),
         'actual original holder terminal/pages and installed runtime sources are mandatory')
    if ACTUAL['outcome'] == 'diagnostic_passed':
        need(all(files[name] is not None for name in CORE_PATHS
                 if name != 'c1-holder-start-02.json'), 'successful diagnostic receipts are incomplete')
        counts = ACTUAL.get('counts')
        need(type(counts) is dict and set(counts) == set(COUNTS)
             and all(type(value) is int and value >= 0 for value in counts.values()),
             'actual original native counts are incomplete')
    return ACTUAL


def archived_identity(data, name):
    need(name in data, 'required original is not in the archive: ' + name)
    return {'path': str(ROOT / name), 'bytes': len(data[name]), 'sha256': sha(data[name])}


def match_original(data, pin):
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}, 'exact original identity required')
    path = Path(pin['path'])
    need(path.is_absolute() and path.is_relative_to(ROOT), 'original is outside the fixed C1 source root')
    name = path.relative_to(ROOT).as_posix()
    need(archived_identity(data, name) == pin, 'archived original differs: ' + name)
    return name


def summary(kind, data):
    actual = require_sealed()
    need(kind == 'c1', 'this script only archives the original C1 diagnostic capture')
    for name, pin in {**PINNED, **actual['files']}.items():
        if pin is None:
            need(name not in data, 'original declared absent appeared: ' + name)
        else:
            need(name in data and pin == {'bytes': len(data[name]), 'sha256': sha(data[name])},
                 'frozen original input differs: ' + name)
    native, streams = captured_native(data, 'c1-holder-native-02.json', actual['native_read_paths'],
        actual['holder_original_job_id'], actual['outcome'] == 'diagnostic_passed')
    errors, documents = [], {}
    for name in CORE_PATHS:
        if name in data and name.endswith('.json'):
            try:
                value = json.loads(data[name])
                need(type(value) is dict, 'original JSON root is not an object')
                documents[name] = value
            except (ValueError, TypeError, UnicodeError) as error:
                errors.append({'path': name, 'type': type(error).__name__, 'reason': str(error)[:1000]})

    def checked(label, callback):
        try:
            callback()
        except (KeyError, IndexError, ValueError, TypeError, AssertionError) as error:
            errors.append({'binding': label, 'type': type(error).__name__, 'reason': str(error)[:1500]})

    def relative_capture(directory, pin, filename):
        need(type(pin) is dict and pin.get('file') == filename,
             'original relative capture filename differs')
        observed = archived_identity(data, directory + '/' + filename)
        need(pin.get('bytes') == observed['bytes'] and pin.get('sha256') == observed['sha256'],
             'original relative capture bytes differ')

    parent = documents.get('c1-campaign-02/report.json')
    diagnostic = documents.get('c1-campaign-02/summary.json')
    observation = documents.get('c1-observation-02/report.json')
    audit = documents.get('c1-observation-02/independent-summary.json')
    adapted = documents.get('c1-adapter-evidence-02/adapter-report.json')
    holder = documents.get('c1-holder-report-02.json')
    monitor = documents.get('c1-campaign-02/compiler-monitor.audit.json')
    ledger = documents.get('c1-campaign-02/compiler-monitor.json')
    counts = None if audit is None else {key: audit.get(key) for key in COUNTS}
    need(counts == actual.get('counts'), 'actual captured original native counts differ')
    successful = actual['outcome'] == 'diagnostic_passed'
    stages, closures, traces, holder_logs = [], [], [], []

    installed = documents.get('c1-parent-install-02.json')
    inputs = documents.get('c1-campaign-inputs-02.json')
    prerequisites = documents.get('c1-prerequisites-02.json')
    runtime_sources = {}
    def runtime_binding():
        need(installed is not None and inputs is not None and prerequisites is not None,
             'original installed runtime intent receipts are incomplete')
        need(installed['schema'] == 'hepta-d2-c1-source-install/v1' and installed['target'] == 'x230'
             and installed['installed'] is True and installed['campaign_started'] is False
             and installed['source_or_test_execution'] is False and installed['automatic_retries'] == 0
             and installed['cleanup_or_overwrite_performed'] is False,
             'original source-only installation scope differs')
        expected = set(PINNED) | set(RUNTIME_PATHS)
        rows = installed['files']
        need(type(rows) is list and installed['file_count'] == len(rows) == len(expected) == 19
             and {Path(row['path']).relative_to(ROOT).as_posix() for row in rows} == expected
             and sum(row['bytes'] for row in rows) == installed['payload_bytes'],
             'original nineteen-file runtime installation inventory differs')
        for pin in rows:
            match_original(data, pin)
        need(inputs['schema'] == 'hepta-d2-c1-campaign-inputs/v1' and inputs['sealed'] is True
             and inputs['attempt'] == '02'
             and inputs['launcher_sha256'] == sha(data['c1-tools-02/d2_campaign.py']),
             'original C1 campaign input scope differs')
        need(inputs['prerequisites'] == archived_identity(data, 'c1-prerequisites-02.json')
             and inputs['qualification_binder'] == archived_identity(data, 'c1-tools-02/d2_prerequisites.py')
             and inputs['adapter'] == archived_identity(data, 'c1-tools-02/run_c1_phase_cost.py'),
             'original campaign core identity differs')
        need(prerequisites['schema'] == 'hepta-d2-c1-prerequisites/v1'
             and prerequisites['qualification_sealed'] is True and prerequisites['exact_ci_sealed'] is True,
             'original full prerequisite declaration differs')
        canonical = prerequisites['prerequisite_module']
        need(canonical == {'path': str(ROOT / 'full-prerequisites-01/d2_prerequisites.py'),
             **PINNED['c1-tools-02/d2_prerequisites.py']},
             'original canonical D2 module identity differs')
        runtime_sources.update({name: archived_identity(data, name) for name in RUNTIME_PATHS})
    checked('original installed runtime intent and source identities', runtime_binding)

    if parent is not None:
        def parent_binding():
            need(parent['schema'] == 'hepta-d2-c1-campaign-control/v1'
                 and parent['attempt'] == '02' and parent['automatic_retries'] == 0
                 and parent['candidate_adopted'] is False and parent['performance_acceptance_claim'] is False
                 and parent['normal_lifecycle_started'] is False and parent['capacity_workload_started'] is False,
                 'original parent scope differs')
            need(parent['launcher_sha256'] == sha(data['c1-tools-02/d2_campaign.py']),
                 'original parent transmitted source differs')
            match_original(data, parent['input_receipt'])
            for name in ('prerequisite_inputs', 'qualification_binder', 'adapter', 'source_inputs',
                         'baseline_source_inputs', 'pre_execution_clarification', 'summary'):
                if name in parent:
                    match_original(data, parent[name])
            if successful:
                need(parent['passed'] is True and parent['diagnostic_evidence_passed'] is True
                     and parent['inputs_unchanged'] is True and parent['source_inputs_unchanged'] is True
                     and parent['baseline_source_inputs_unchanged'] is True
                     and parent['qualified_source_maps_match_current_inputs'] is True
                     and parent['measurement_attribution_valid'] is True
                     and parent['quiescence']['passed'] is True and parent.get('finished_utc')
                     and not parent.get('error'), 'original successful parent closure differs')
        checked('parent scope and original identities', parent_binding)
        rows = parent.get('stages', [])
        if type(rows) is list:
            for row in rows:
                if type(row) is not dict:
                    errors.append({'binding': 'stage', 'reason': 'original stage is not an object'})
                    continue
                stages.append({key: row.get(key) for key in ('name', 'returncode', 'passed',
                    'waited_and_reaped', 'owned_process_absent', 'owned_process_group_absent',
                    'cleanup_error', 'independent_controller_cleanup')})
                for stream in ('stdout', 'stderr'):
                    if stream in row:
                        checked('stage ' + str(row.get('name')) + ' ' + stream,
                                lambda row=row, stream=stream: match_original(data, row[stream]))
                for pin in row.get('output_bindings', []):
                    checked('stage original output', lambda pin=pin: match_original(data, pin))
            def stage_binding():
                names = [row['name'] for row in rows]
                need(names == STAGES[:len(names)], 'original stage order is not a prefix')
                if successful:
                    need(names == STAGES and all(row['returncode'] == 0 and row['passed'] is True
                         and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                         and row['owned_process_group_absent'] is True and not row.get('cleanup_error')
                         for row in rows), 'original stage child custody is incomplete')
            checked('original stage custody', stage_binding)
        else:
            errors.append({'binding': 'stages', 'reason': 'original stages are not a list'})
        proof = parent.get('compiler_monitor', {})
        if type(proof) is dict:
            for field in ('ledger', 'independent_audit'):
                if field in proof:
                    checked('compiler monitor ' + field,
                            lambda field=field: match_original(data, proof[field]))

    if monitor is not None:
        def monitor_binding():
            need(monitor['schema'] == 'hepta-r26-compiler-monitor-audit/v1', 'original monitor schema differs')
            match_original(data, monitor['ledger'])
            match_original(data, monitor['validator'])
            if successful:
                need(monitor['validation']['passed'] is True and monitor['monitor_sources_unchanged'] is True
                     and monitor['source_recheck_errors'] == [] and ledger is not None and ledger['passed'] is True
                     and parent['compiler_monitor']['passed'] is True,
                     'original monitor/audit did not close')
        checked('original compiler monitor and audit', monitor_binding)

    if observation is not None:
        def observation_binding():
            need(observation['schema'] == 'hepta-x230-readonly-observation-abba/v2'
                 and observation['order'] == 'ABBA' and observation['concurrency'] == [1]
                 and observation['calls_per_cell'] == 192 and observation['tokio_workers'] == 2,
                 'original C1 matrix protocol differs')
            if successful:
                need(observation['passed'] is True and not observation.get('error')
                     and observation['source_originals_unchanged'] is True
                     and observation['binary_hashes_unchanged'] is True
                     and observation['topology_manifest_unchanged'] is True
                     and observation['binary_sha256']['A'] == observation['binary_sha256']['B'],
                     'original same-ELF matrix did not close')
        checked('original native matrix', observation_binding)
        rounds = observation.get('rounds', [])
        if type(rounds) is list:
            for index, row in enumerate(rounds):
                if type(row) is not dict or index >= 4:
                    errors.append({'binding': 'rounds', 'reason': 'unexpected original round shape'})
                    continue
                arm = 'ABBA'[index]
                for phase, field in (('first', 'shutdown'), ('restart', 'restart_shutdown')):
                    closed = row.get(field)
                    if type(closed) is not dict:
                        continue
                    directory = 'c1-observation-02/round-%d-%s/%s' % (index, arm, phase)
                    closures.append({'round': index, 'arm': arm, 'phase': phase,
                        'exit_code': closed.get('exit_code'), 'shutdown_method': closed.get('shutdown_method'),
                        'observed_descendant_survivors': closed.get('observed_descendant_survivors'),
                        'reader_error': closed.get('reader_error'), 'unmatched_responses': closed.get('unmatched_responses')})
                    def close_binding(closed=closed, directory=directory):
                        capture = closed['transport_capture']
                        relative_capture(directory, capture['raw'], 'transport-responses.jsonl')
                        relative_capture(directory, capture['index'], 'transport-responses.index.jsonl')
                        relative_capture(directory, closed['resources']['trace'], 'resource-samples.jsonl')
                        if successful:
                            need(closed['exit_code'] == 0 and closed['shutdown_method'] == 'stdin_eof'
                                 and closed['observed_descendant_survivors'] == []
                                 and closed['reader_error'] is None and closed['unmatched_responses'] == 0
                                 and capture['reader_eof'] is True and closed['resources']['sampler_error'] is None,
                                 'original controller normal close is incomplete')
                    checked('controller %d/%s raw closure' % (index, phase), close_binding)
        if successful:
            checked('eight original controller closes', lambda: need(len(closures) == 8,
                    'successful original matrix does not contain eight closes'))

    if audit is not None:
        def audit_binding():
            need(audit['schema'] == 'hepta-native-observation-independent-analysis/v3'
                 and audit['original_bytes'] == len(data['c1-observation-02/report.json'])
                 and audit['original_sha256'] == sha(data['c1-observation-02/report.json']),
                 'original native auditor input identity differs')
            if successful:
                need(audit['verified'] is True
                     and counts == dict(zip(COUNTS, (768, 96, 72, 936, 0)))
                     and [case['concurrency'] for case in audit['cases']] == [1]
                     and audit['binary_sha256'] == observation['binary_sha256'],
                     'original auditor did not verify the fixed C1 protocol')
        checked('original native auditor receipt', audit_binding)

    if adapted is not None:
        def adapter_binding():
            need(adapted['schema'] == 'hepta-d2-c1-phase-cost-adapter/v1'
                 and adapted['performance_acceptance_claim'] is False,
                 'original adapter scope differs')
            match_original(data, adapted['adapter_source'])
            if 'original_report' in adapted:
                match_original(data, adapted['original_report'])
            if successful:
                need(adapted['original_returncode'] == 0 and adapted['original_wrapper_returned'] is True
                     and adapted['controller_close_evidence_complete'] is True and adapted['analysis_complete'] is True
                     and adapted['all_trace_reads_after_original_matrix'] is True and adapted['errors'] == []
                     and len(adapted['traces']) == len(adapted['bindings']) == 8
                     and adapted['strict_on_request_bijection_count'] == 468
                     and adapted['measured_on_request_count'] == 384
                     and adapted['validation_whole_cost_field'] == 'inclusive CPU of validation_worker and validation_owner',
                     'original adapter analysis or custody is incomplete')
        checked('original adapter receipt', adapter_binding)
        rows = adapted.get('traces', [])
        if type(rows) is list:
            for index, row in enumerate(rows):
                if type(row) is not dict or index >= 8:
                    errors.append({'binding': 'traces', 'reason': 'unexpected original trace entry'})
                    continue
                binding = row.get('binding', {})
                traces.append({'binding': binding, 'trace': row.get('trace'),
                    'raw_transport': row.get('raw_transport'), 'raw_transport_index': row.get('raw_transport_index'),
                    'selected_on_counts': row.get('selected_on_counts')})
                def trace_binding(row=row, binding=binding, index=index):
                    round_index, phase = index // 2, ('first' if index % 2 == 0 else 'restart')
                    arm = 'ABBA'[round_index]
                    directory = ROOT / 'c1-observation-02' / ('round-%d-%s' % (round_index, arm)) / phase
                    need(binding == adapted['bindings'][index] and binding['round'] == round_index
                         and binding['arm'] == arm and binding['phase'] == phase
                         and binding['mode'] == ('off' if arm == 'A' else 'on')
                         and binding['directory'] == str(directory)
                         and row['trace']['path'] == str(directory / 'phase-cost.trace.jsonl'),
                         'trace binding is outside the original eight slots')
                    for key in ('trace', 'raw_transport', 'raw_transport_index'):
                        match_original(data, row[key])
                    if successful:
                        expected = dict.fromkeys(('preflight', 'warmup', 'measured', 'restart'), 0)
                        if arm == 'B':
                            expected.update({'preflight': 6, 'warmup': 24, 'measured': 192}
                                            if phase == 'first' else {'restart': 12})
                        need(row['selected_on_counts'] == expected,
                             'original selected request category counts differ')
                checked('original trace identity %d' % index, trace_binding)

    if diagnostic is not None:
        def diagnostic_binding():
            need(diagnostic['schema'] == 'hepta-d2-c1-diagnostic-evidence/v1'
                 and diagnostic['performance_acceptance_claim'] is False and diagnostic['candidate_adopted'] is False,
                 'diagnostic summary is not an optimization acceptance')
            for key in ('native_report', 'native_audit', 'adapter_report'):
                match_original(data, diagnostic[key])
            if successful:
                need(diagnostic['evidence_verified'] is True and diagnostic['same_elf'] is True
                     and diagnostic['mode_order'] == ['off', 'on', 'on', 'off']
                     and diagnostic['counts'] == counts
                     and diagnostic['on_trace_request_bijection_count'] == 468
                     and diagnostic['on_measured_request_count'] == 384
                     and diagnostic['validation_whole_cost_field'] == 'inclusive CPU of validation_worker and validation_owner',
                     'original diagnostic summary differs')
        checked('original diagnostic summary', diagnostic_binding)

    if holder is not None:
        def holder_binding():
            need(holder['schema'] == 'hepta-x230-r21-held-agent-campaign/v1', 'original holder schema differs')
            need(holder['remote_script_sha256'] == sha(data['c1-tools-02/d2_campaign.py']),
                 'holder transmitted another parent')
            if successful:
                need(holder['passed'] is True and holder['remote_returncode'] == 0
                     and holder['owned_agent_reaped'] is True
                     and holder['owned_agent_directory_absent_after_context'] is True
                     and holder['owned_agent_socket_absent_after_context'] is True
                     and not holder.get('error'), 'original held-agent custody is incomplete')
            terminal_lines = [json.loads(line) for line in streams['stdout'].splitlines() if line.strip()]
            need(terminal_lines and terminal_lines[-1]['report'] == str(MAC_HOLDER / 'report.json')
                 and terminal_lines[-1]['passed'] == holder['passed']
                 and terminal_lines[-1]['remote_returncode'] == holder['remote_returncode']
                 and terminal_lines[-1]['owned_agent_reaped'] == holder.get('owned_agent_reaped'),
                 'original native completion line and holder report differ')
        checked('original holder and native completion', holder_binding)
        rows = holder.get('log_files', [])
        if type(rows) is list:
            for pin in rows:
                def holder_log_binding(pin=pin):
                    need(type(pin) is dict and set(pin) == {'file', 'bytes', 'sha256'}
                         and type(pin['file']) is str and Path(pin['file']).name == pin['file']
                         and pin['file'] not in {'', '.', '..'}, 'unsafe original holder filename')
                    path = MAC_HOLDER / pin['file']
                    need(path.name not in SKIP_FILES, 'unsafe holder original path')
                    destination = 'c1-holder-originals-02/' + path.name
                    observed = archived_identity(data, destination)
                    need(observed['bytes'] == pin['bytes'] and observed['sha256'] == pin['sha256'],
                         'original Mac holder log copy differs')
                    holder_logs.append({'original': pin, 'original_directory': str(MAC_HOLDER),
                                        'archived': observed})
                    if path.name == 'remote-script.py':
                        need(data[destination] == data['c1-tools-02/d2_campaign.py'],
                             'original transmitted source copy differs')
                checked('original holder log copy', holder_log_binding)
            if successful:
                checked('complete holder log copies', lambda: need(len(holder_logs) == len(rows),
                        'original holder log copy inventory incomplete'))

    source = documents.get('c1-campaign-02/source-inputs.json')
    baseline = documents.get('c1-campaign-02/baseline-source-inputs.json')
    if successful:
        def source_binding():
            need(source is not None and baseline is not None and source['file_count'] == 222
                 and baseline['file_count'] == 222 and len(source['files']) == 222
                 and len(baseline['files']) == 222
                 and source['root'] == str(ROOT / 'source')
                 and baseline['root'] == '/home/qian/hepta-runtime-phase-cost-20261106-d1/source'
                 and set(source['files']) == set(baseline['files'])
                 and {name for name in source['files'] if source['files'][name] != baseline['files'][name]} == CHANGED_PATHS,
                 'original compiler input snapshots differ')
        checked('original source input snapshots', source_binding)
    raw_trace_names = sorted(name for name in data if name.startswith('c1-observation-02/')
                             and name.endswith('/phase-cost.trace.jsonl'))
    expected_trace_names = ['c1-observation-02/round-%d-%s/%s/phase-cost.trace.jsonl' % (i, arm, phase)
                            for i, arm in enumerate('ABBA') for phase in ('first', 'restart')]
    checked('fixed raw trace paths', lambda: need(set(raw_trace_names) <= set(expected_trace_names)
             and (not successful or set(raw_trace_names) == set(expected_trace_names)),
             'raw trace inventory differs from the original eight fixed slots'))
    return {'schema': 'hepta-d2-c1-evidence-summary/v1',
        'original_job_id': actual['holder_original_job_id'], 'outcome': actual['outcome'], 'counts': counts,
        'reported_parent_passed': None if parent is None else parent.get('passed'),
        'reported_diagnostic_evidence_passed': None if parent is None else parent.get('diagnostic_evidence_passed'),
        'reported_adapter_analysis_complete': None if adapted is None else adapted.get('analysis_complete'),
        'reported_native_audit_verified': None if audit is None else audit.get('verified'),
        'captured_originals_binding_verified': not errors, 'receipt_binding_errors': errors,
        'original_holder_terminal': native,
        'original_holder_streams': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in streams.items()},
        'parent_stages': stages, 'original_controller_closures': closures,
        'original_trace_bindings': traces, 'raw_trace_files': [archived_identity(data, name) for name in raw_trace_names],
        'raw_trace_file_count': len(raw_trace_names), 'original_holder_log_copies': holder_logs,
        'original_compiler_monitor': None if parent is None else parent.get('compiler_monitor'),
        'original_monitor_validation': None if monitor is None else monitor.get('validation'),
        'original_monitor_sample_count': None if ledger is None or type(ledger.get('samples')) is not list
            else len(ledger['samples']),
        'original_errors': {name: value.get('error', value.get('errors')) for name, value in documents.items()
                            if value.get('error') or value.get('errors')},
        'original_installed_runtime_sources': runtime_sources,
        'reported_strict_on_request_bijection_count': None if adapted is None else adapted.get('strict_on_request_bijection_count'),
        'reported_on_measured_request_count': None if adapted is None else adapted.get('measured_on_request_count'),
        'reported_validation_whole_cost_field': None if adapted is None else adapted.get('validation_whole_cost_field'),
        'external_prerequisite_references': EXTERNAL_EVIDENCE_REFERENCES,
        'external_prerequisite_bodies_revalidated_here': False,
        'original_native_auditor_reexecuted': False, 'original_trace_parser_reexecuted': False,
        'original_compiler_monitor_validator_reexecuted': False, 'release_or_test_elf_rehashed_here': False,
        'performance_acceptance_claim': False, 'candidate_adopted': False,
        'scope': 'Byte preservation and original receipt reconciliation for the single C1 diagnostic capture; no cost recomputation or new performance gate.'}


def collect(root, kind):
    actual = require_sealed()
    need(kind == 'c1', 'this script archives only the captured original C1 diagnostic')
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
            need(before.st_size <= MAX_FILE, 'file exceeds 32 MiB: ' + relative)
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
        elif not any(name.startswith(prefix + '/') for prefix in COLLECT_DIRS):
            file(root / name, required=True)
    for prefix in COLLECT_DIRS:
        if os.path.lexists(root / prefix):
            directory(root / prefix)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'source changed during collection')
    return payloads, excluded


def create_archive(root, kind):
    require_sealed()
    need(kind == 'c1', 'this script archives only the captured original C1 diagnostic')
    base = root / 'c1-evidence-02'
    outputs = [Path(str(base) + suffix) for suffix in ('.tar.gz', '.manifest.json', '.compact.json')]
    need(not any(os.path.lexists(path) for path in outputs), 'create-only output already exists; no overwrite/retry')
    data, excluded = collect(root, kind)
    compact = summary(kind, data)
    manifest = {'schema': 'hepta-d2-c1-evidence-archive/v1', 'kind': kind, 'source_root': str(root),
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
    need(len(archive_raw) + len(manifest_raw) + len(compact_raw) <= MAX_TOTAL, 'combined archive/sidecars exceed 384 MiB')
    for path, raw in zip(outputs, (archive_raw, manifest_raw, compact_raw)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    return {'archive': str(outputs[0]), 'bytes': len(archive_raw), 'sha256': sha(archive_raw),
            'manifest_sha256': sha(manifest_raw), 'counts': compact['counts'],
            'raw_trace_file_count': compact['raw_trace_file_count'], 'receipt_binding_errors': compact['receipt_binding_errors'], 'outcome': compact['outcome']}


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
             'archive changed while read or exceeded 384 MiB')
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
                need(manifest['schema'] == 'hepta-d2-c1-evidence-archive/v1'
                     and manifest['kind'] == 'c1'
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
                need(total <= MAX_TOTAL, 'total tar payload exceeds 384 MiB')
    need(manifest is not None and set(data) == set(manifest['files'])
         and sum(map(len, data.values())) == manifest['selected_bytes'], 'manifest membership/byte count differs')
    compact = summary(manifest['kind'], data)
    need(compact == manifest['summary'], 'compact summary differs from retained raw receipts')
    return {'verified': True, 'kind': manifest['kind'], 'archive': str(path), 'bytes': len(raw),
            'sha256': sha(raw), 'manifest_sha256': manifest_sha, 'files': len(data), 'selected_bytes': total,
            'original_job_id': compact['original_job_id'], 'counts': compact['counts'],
            'raw_trace_file_count': compact['raw_trace_file_count'], 'receipt_binding_errors': compact['receipt_binding_errors'], 'outcome': compact['outcome'], 'files_extracted': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--kind', choices=('c1',))
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
