#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Independent, offline original-byte audit of the exact incomplete A54 large run.

This reads the completed collector and shared small archives; it launches no
child, imports no producer/evaluator, and never accesses an original fixture.
Every original record body is consumed and checked. Only the bounded control
files/maps are retained locally. A passing audit preserves the failed product
result (candidate warmup failed; sixty planned calls unexecuted); it cannot authorize performance adoption.
"""
import argparse
import base64
from collections import Counter
import contextlib
import gzip
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

BASE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ROOT = BASE / 'a54-native-archive-cohort-r01'
PACK = BASE / 'a54-large-partial-original-evidence-r01'
COLLECTOR = BASE / 'tools/pack_a54_large_partial_original_evidence_r01.py'
COLLECTION_PROTOCOL = BASE / 'tools/a54-large-partial-evidence-collection-r01.protocol.json'
SHARED_SMALL = BASE / 'a54-small-original-evidence-r01.jsonl.gz'
REPORT_SHA = '6cc6ba6c22db109ee10fe84a741ab88ebb2d39e53ce6233e60c70561e7a78c30'
REPORT_BYTES = 144184
DRIVER_SHA = '9f03083dcb6754952ea27ae531dd5f353119704257ffb56e43dcb180052eafc1'
PROTOCOL_SHA = '8f2dcc021dbfdb46317c9c28f1abd5d9b61ccb7a6601e9ae71a5d0e5946c0a3a'
COLLECTOR_SHA = '42d275064ea70b27b5447ad6885ffac2789ee5d886b2196e05f681638e604160'
COLLECTION_PROTOCOL_SHA = '600efdcd8c342f5cdc2482d480d0225c217acc200ea665ca686c70279c571ecb'
COLLECTOR_JOB_ID = '1a179a881e2-96a-1369'
SMALL_SHA = 'cad4bc1ccee3e3433b0cac38c133cdca9615214c0084ae81e8a28cb8015960a1'
SMALL_BYTES = 28981357
FIELD_AUDIT_SHA = 'd9dad1fd33ba5637187e95528e9e6ceb6bd1d6311ee7fd51184d155c45d115e8'
FIELD_AUDIT_BYTES = 57669
COLLECTOR_BYTES = 54828
COLLECTION_PROTOCOL_BYTES = 44735
ORDER = ('A', 'B', 'B', 'A')
STAGES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')
SOURCE_DIRS = {'A': BASE / 'source-r07-recovery-only',
               'B': BASE / 'source-a54-compact-view-r01'}
QUAL_DIRS = {'A': BASE / 'qualification-r07-recovery-only',
             'B': BASE / 'qualification-a54-compact-view-r01'}
SOURCE_COUNTS = {'A': 165, 'B': 175}
SOURCE_MAPS = {'A': '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d',
               'B': '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'}
ELFS = {'A': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb',
        'B': 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'}
QUAL_SHAS = {'A': 'ab3481a57c69177d20f4d4feff31543dbc0a32b6f07892a0553879035b928cc9',
             'B': '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'}
CACHE = '.request-archive-index-v2.redb'
SEAL = '.request-archive-index-seal-v1.json'
GROUPS = (('archive', 'request-archive-v11', 65536), ('hot', 'request-audit', 512))
RECORD_FIELDS = {'request_id', 'owner', 'tool_name', 'state', 'accepted_unix_ms', 'elapsed_ms'}
PUBLIC_SCOPE = {'ownership_scope': 'native_mcp_session_only', 'session_scope': 'native_mcp_session_only',
                'authenticated_chatgpt_caller_isolation': False, 'credential_metadata_resume': False,
                'cross_session_resume': False}
HOST_DTO = {'hosts': [{'name': 'fixture', 'platform': 'linux', 'execution_mode': 'isolated',
                      'operator_tools': False, 'allow_execute': False, 'allow_pty': False,
                      'allow_write': False, 'privileged_actions': []}]}
PRODUCT_ERRORS = ('archive metadata query total deadline exceeded; repeat only the metadata query',
                  'archive index preparing or validation unavailable; repeat only this metadata query')
MEASURED_FAILURES = [5, 6, 7, 8, 9, 10, 13, 14, 15, 17, 18, 19]
HEX = re.compile(r'[0-9a-f]{64}\Z')
CHUNK = 49152
MAX_PACK = 512 * 1024 * 1024
MAX_RECORD_BYTES = 66854936
MAX_LINE = 2 * 1024 * 1024
MAX_SMALL_LINE = 48 * 1024 * 1024
AUDIT_BUDGET = 600


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def canonical(value):
    return compact(value) + b'\n'


def exact(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(right, dict):
        return left.keys() == right.keys() and all(exact(left[key], item) for key, item in right.items())
    if isinstance(right, list):
        return len(left) == len(right) and all(exact(a, b) for a, b in zip(left, right))
    return left == right


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def finite(text):
        value = float(text)
        need(math.isfinite(value), 'nonfinite JSON float')
        return value
    def invalid(_):
        raise ValueError('nonfinite JSON constant')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=invalid)


def is_int(value, minimum=0, maximum=None):
    return type(value) is int and value >= minimum and (maximum is None or value <= maximum)


def is_sha(value):
    return type(value) is str and HEX.fullmatch(value) is not None


def remote_path(value):
    need(type(value) is str and '\\' not in value, 'original path is not a string')
    path = PurePosixPath(value)
    need(path.is_absolute() and str(path) == value and '..' not in path.parts
         and path != BASE and path.is_relative_to(BASE), 'noncanonical or outside original BASE path')
    return path


def relpath(value):
    need(type(value) is str and '\\' not in value, 'invalid relative original path')
    path = PurePosixPath(value)
    need(value not in ('', '.') and not path.is_absolute() and str(path) == value
         and '..' not in path.parts, 'noncanonical relative original path')
    return path


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def identity_check(value, size=None, private=False, directory=False):
    need(type(value) is list and len(value) == 9 and all(is_int(item) for item in value),
         'complete integer stat9 required')
    need(value[3] == 1000 and (stat.S_ISDIR(value[2]) if directory else stat.S_ISREG(value[2])),
         'original UID/type differs')
    if not directory:
        need(value[5] == 1 and (size is None or value[6] == size), 'original nlink/size differs')
    if private:
        need(stat.S_IMODE(value[2]) == (0o700 if directory else 0o600), 'original private mode differs')


def receipt_check(value, path=None, size=None, digest=None, private=False):
    need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256', 'identity'},
         'closed four-field original receipt required')
    remote_path(value['path'])
    need(is_int(value['bytes'], maximum=MAX_PACK) and is_sha(value['sha256']), 'invalid original byte receipt')
    need(path is None or value['path'] == str(path), 'original receipt path differs')
    need(size is None or value['bytes'] == size, 'original byte count differs')
    need(digest is None or value['sha256'] == digest, 'original SHA differs')
    identity_check(value['identity'], value['bytes'], private=private)


def original_match(actual, expected, stat8=False):
    for key in ('path', 'bytes', 'sha256', 'identity'):
        if key in expected:
            value = actual[key]
            if key == 'identity' and stat8:
                value = value[:4] + value[5:]
            need(exact(value, expected[key]), 'original receipt projection differs: ' + actual['path'] + '/' + key)


class Deadline:
    def __init__(self):
        self.start = time.monotonic()
        self.end = self.start + AUDIT_BUDGET

    def check(self):
        need(time.monotonic() < self.end, 'one original 600-second offline audit deadline exceeded')


class LocalInput:
    """One retained local descriptor, independently pinned and fully rehashed."""
    def __init__(self, path, clock, maximum, expected_sha, expected_bytes=None):
        self.path = Path(path)
        self.clock, self.maximum = clock, maximum
        self.stream = None
        need(self.path.is_absolute() and self.path.resolve(strict=True) == self.path,
             'direct absolute input path required')
        before = self.path.lstat()
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            need(stamp(before) == stamp(info) and stat.S_ISREG(info.st_mode)
                 and info.st_nlink == 1 and 0 <= info.st_size <= maximum,
                 'bounded direct single-link local regular input required')
            self.first = stamp(info)
            self.stream = os.fdopen(fd, 'rb')
        except BaseException:
            os.close(fd)
            raise
        try:
            self.receipt = self.hash_all()
            need(is_sha(expected_sha) and self.receipt['sha256'] == expected_sha
                 and (expected_bytes is None or self.receipt['bytes'] == expected_bytes), 'actual local input pin differs')
        except BaseException:
            self.stream.close()
            raise

    def hash_all(self):
        self.clock.check()
        self.stream.seek(0)
        count, digest = 0, hashlib.sha256()
        while True:
            self.clock.check()
            raw = self.stream.read(1024 * 1024)
            if not raw:
                break
            count += len(raw)
            need(count <= self.maximum, 'local input byte bound exceeded')
            digest.update(raw)
        need(count == self.first[6] and self.first == stamp(os.fstat(self.stream.fileno())) == stamp(self.path.lstat()),
             'local input changed during full byte read')
        self.stream.seek(0)
        return {'path': str(self.path), 'bytes': count, 'sha256': digest.hexdigest(), 'identity': self.first}

    def raw(self):
        self.stream.seek(0)
        raw = self.stream.read(self.maximum + 1)
        need(len(raw) == self.receipt['bytes'] and sha(raw) == self.receipt['sha256'], 'same local input bytes required')
        return raw

    def finish(self):
        need(exact(self.hash_all(), self.receipt), 'final full-byte local input fence changed')

    def close(self):
        self.stream.close()


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        need(stream.write(raw) == len(raw), 'partial fresh audit write')
        stream.flush()
        os.fsync(stream.fileno())


def fixed_report(report, field_audit):
    need(type(report) is dict and report['schema'] == 'hepta-a54-native-archive-cohort/v1'
         and report['complete'] is False and report['phase'] == 'failed' and report['passed'] is False
         and report['performance_adopted'] is False
         and report['errors'] == ['FatalExperiment: block failed; remaining block unexecuted']
         and report['observed_measured_write_attempts'] == 20 and report['observed_measured_successes'] == 8
         and report['unexecuted_measured_slots'] == list(range(20, 80)) and len(report['slots']) == 80
         and len(report['waves']) == 32 and len(report['controllers']) == 2,
         'the exact incomplete failed A54 report with sixty unexecuted slots is required')
    need(field_audit['schema'] == 'hepta-a54-large-partial-failure-report-field-audit/v1'
         and field_audit['passed'] is True and field_audit['check_count'] == len(field_audit['checks']) == 475
         and exact(field_audit['original_report'], {'bytes': REPORT_BYTES, 'sha256': REPORT_SHA})
         and field_audit['driver_sha256'] == DRIVER_SHA and field_audit['protocol_sha256'] == PROTOCOL_SHA
         and exact(field_audit['analysis'], report['analysis'])
         and field_audit['complete_original_workload'] is False
         and field_audit['original_performance_passed'] is False
         and field_audit['performance_adoption_authorized'] is False
         and field_audit['raw_wire_fixture_independent_audit_complete'] is False,
         'separately pinned original partial-failure 475-field audit differs')
    need([row['slot'] for row in field_audit['all_actual_measured_failure_slots']] == MEASURED_FAILURES
         and [row['slot'] for row in report['slots'] if row['status'] == 'product_failure'] == MEASURED_FAILURES
         and len(report['analysis']['numeric_gates']) == 16
         and all(value is False for value in report['analysis']['numeric_gates'].values())
         and all(value is None for value in report['analysis']['ratios'].values())
         and field_audit['unexecuted_measured_slots'] == list(range(20, 80))
         and field_audit['candidate_measured_attempts'] == 0,
         'all actual failures and unexecuted work remain distinct; all original gates fail')
    need([row['slot'] for row in report['slots'] if row['write_attempts'] == 1] == list(range(20))
         and all(row['write_attempts'] == 0 and row['sent'] is False and row['response_received'] is False
                 and row['status'] == 'unexecuted' for row in report['slots'][20:])
         and exact(field_audit['candidate_warmup_failure'], report['controllers'][1]['setup'][2]),
         'no candidate measured request or replacement workload was executed')
    need(set(report['qualifications']) == {'A', 'B'}, 'exact two qualified arms required')
    for arm, bundle in report['qualifications'].items():
        need(bundle['source'] == str(SOURCE_DIRS[arm]) and bundle['source_files'] == SOURCE_COUNTS[arm]
             and len(bundle['source_map']) == SOURCE_COUNTS[arm]
             and sha(compact(bundle['source_map'])) == SOURCE_MAPS[arm]
             and bundle['binary']['path'] == str(QUAL_DIRS[arm] / 'hepta-runtime')
             and bundle['binary']['sha256'] == ELFS[arm]
             and bundle['report']['path'] == str(QUAL_DIRS[arm] / 'report.json')
             and bundle['report']['sha256'] == QUAL_SHAS[arm] and set(bundle['logs']) == set(STAGES),
             'actual source/release/qualification binding differs')
    need(len(report['frozen_inputs']) == 13 and report['frozen_inputs'][0]['sha256'] == PROTOCOL_SHA
         and report['frozen_inputs'][1]['sha256'] == DRIVER_SHA, 'actual frozen input order differs')


def fixed_controls(report):
    """Closed original paths derived from the separately pinned actual report."""
    values = {}

    def add(path, expected, category, maximum=32 * 1024 * 1024, identity='stat9'):
        path = str(path)
        remote_path(path)
        need(path not in values, 'duplicate independently derived control')
        values[path] = {'category': category, 'expected': expected,
                        'identity_format': identity, 'maximum': maximum}

    add(ROOT / 'report.json', {'bytes': REPORT_BYTES, 'sha256': REPORT_SHA}, 'actual-report')
    add(ROOT / 'calls.jsonl', report['calls_file'], 'original-journal', 16 * 1024 * 1024)
    copies = ('protocol.original.json', 'harness.original.py', 'small-helper.original.py',
              'native-driver.original.py', 'qualification-chain-loader.original.py',
              'qualification-entry.original.json', 'qualification-worker.original.json')
    for name, row in zip(copies, report['frozen_inputs'][:7]):
        add(ROOT / name, {key: row[key] for key in ('bytes', 'sha256')}, 'original-input-copy')
    for row in report['frozen_inputs']:
        add(row['path'], row, 'original-frozen-input')
    for index, block in enumerate(report['blocks']):
        need(block['index'] == index, 'fixed block index differs')
        for phase in ('before', 'after'):
            row = block['host_' + phase]
            need(row['path'] == str(ROOT / ('block-%d.host-%s.json' % (index, phase))), 'block gate path differs')
            add(row['path'], row, 'original-host-gate')
    for arm, bundle in report['qualifications'].items():
        add(ROOT / (arm + '-qualification.original.json'),
            {key: bundle['report'][key] for key in ('bytes', 'sha256')}, 'original-qualification-copy')
        add(bundle['report']['path'], bundle['report'], 'original-qualification')
        for stage in STAGES:
            row = bundle['logs'][stage]
            need(row['path'] == str(QUAL_DIRS[arm] / (stage + '.log')), 'fixed qualification log path differs')
            add(row['path'], row, 'original-qualification-log')
    for index, controller in enumerate(report['controllers']):
        directory = ROOT / ('controller-%d-%s' % (index, ORDER[index]))
        need(controller['index'] == index and controller['arm'] == ORDER[index]
             and controller['directory'] == str(directory), 'fixed controller path differs')
        for name in ('requests.jsonl', 'responses.jsonl', 'stderr.log'):
            add(directory / name, controller['shutdown']['files'][name], 'original-controller-wire',
                MAX_PACK if name == 'stderr.log' else 16 * 1024 * 1024, 'stat8_without_gid')
        for name in ('runtime.json', 'fixture-generation.json', 'independent-page-oracles.json'):
            add(directory / name, {}, 'original-fixture-control', 1024 * 1024)
        initial = controller['fixture_after_generation']
        add(directory / 'fixture-original-map.jsonl', initial['full_map_file'], 'original-fixture-map', 64 * 1024 * 1024)
        if index == 0:
            add(directory / 'host-before-measured.json', controller['host_before_measured'], 'original-host-gate')
        else:
            need('host_before_measured' not in controller, 'candidate never reached measured host gate')
        state = directory / 'state'
        add(state / '.request-archive-v11-anchor.json', initial['anchor'], 'original-anchor', 2048)
        add(state / 'request-results/.request-results-v2.json', {}, 'native-result-marker', 1024)
        add(state / '.request-results-v2-anchor.json', {}, 'native-result-anchor', 96 * 1024)
        seed = controller['fixture']['seed_id']
        need(is_sha(seed), 'invalid native seed identity')
        add(state / 'request-results-v2/archive' / seed[:2] / (seed + '.json'), {}, 'native-seed-retained-result', 96 * 1024)
        add(state / 'controller.lock', {'bytes': 0, 'sha256': sha(b'')}, 'original-controller-lock', 0)
    need(len(values) == 65, 'independent exact partial original control count differs')
    return values


def optional_controls():
    return {str(ROOT / ('controller-%d-%s' % (index, arm)) / 'state' / SEAL):
            {'category': 'disposable-index-seal', 'expected': {}, 'identity_format': 'stat9', 'maximum': 4096}
            for index, arm in enumerate(ORDER[:2])}


class CapturedControls:
    def __init__(self, directory):
        self.directory = directory
        self.receipts, self.paths = {}, {}

    def target(self, sequence):
        return self.directory / ('control-%03d.original' % sequence)

    def register(self, receipt, local):
        path = receipt['path']
        need(path not in self.receipts, 'duplicate retained control')
        self.receipts[path], self.paths[path] = receipt, local

    def raw(self, path):
        path = str(path)
        need(path in self.receipts, 'missing retained control: ' + path)
        raw = self.paths[path].read_bytes()
        need(len(raw) == self.receipts[path]['bytes'] and sha(raw) == self.receipts[path]['sha256'],
             'locally retained control changed')
        return raw

    def doc(self, path):
        return document(self.raw(path))


def synthetic(number, owners):
    need(is_int(number, 1, 65535), 'synthetic number outside fixed namespace')
    state = ('unknown', 'completed', 'failed')[(number // 16) % 3]
    return {'request_id': '%02x%062x' % (number % 256, number + 1), 'owner': owners[number % 4],
            'tool_name': ('host_list', 'host_health', 'file_info', 'effective_config')[(number // 4) % 4],
            'state': state, 'accepted_unix_ms': 1000000 + number,
            'elapsed_ms': None if state == 'unknown' else 1 + number % 1000}


def strict_record(value):
    need(type(value) is dict and set(value) == RECORD_FIELDS and is_sha(value['request_id'])
         and is_sha(value['owner']) and type(value['tool_name']) is str and value['tool_name']
         and value['state'] in ('unknown', 'completed', 'failed')
         and is_int(value['accepted_unix_ms'], maximum=(1 << 128) - 1)
         and (value['elapsed_ms'] is None or is_int(value['elapsed_ms'], maximum=(1 << 64) - 1)),
         'complete strict six-field metadata record required')


def page_oracle(owned, arguments):
    offset = 0
    if 'after_id' in arguments:
        matches = [index for index, record in enumerate(owned) if record['request_id'] == arguments['after_id']]
        need(len(matches) == 1, 'owned cursor is not unique')
        offset = matches[0] + 1
    page = owned[offset:offset + arguments['limit']]
    return {'requests': [{key: value for key, value in row.items() if key != 'owner'} for row in page],
            'next_after_id': page[-1]['request_id'] if offset + len(page) < len(owned) else None,
            'total': len(owned), 'archive_retention': 'no_automatic_metadata_eviction', 'history_is_live': True,
            'coverage': 'metadata_retained_at_archive_introduction_and_subsequent_admitted_requests',
            'contains_parameters_or_output': False, 'automatic_operation_retry': False, **PUBLIC_SCOPE}


def usage_oracle(owned):
    counts = Counter(row['state'] for row in owned)
    return {'schema': 'hepta-private-usage-v1', 'total_requests': len(owned), 'completed': counts['completed'],
            'failed': counts['failed'], 'unknown': counts['unknown'], 'active': 0,
            'tool_counts': dict(Counter(row['tool_name'] for row in owned)),
            'first_accepted_unix_ms': owned[0]['accepted_unix_ms'], 'last_accepted_unix_ms': owned[-1]['accepted_unix_ms'],
            'retention': 'archive_metadata_not_evicted_with_hot_cache',
            'coverage': 'metadata_retained_at_archive_introduction_and_subsequent_admitted_requests',
            'semantics': 'dispatch_observation_not_transport_delivery_or_business_success',
            'contains_parameters_or_output': False, 'scope': 'same_verified_credential_or_native_session', **PUBLIC_SCOPE}


class FixtureOracle:
    """Consumes all original bodies against the retained ordered original map."""
    def __init__(self, controller, controls, clock):
        self.controller, self.controls, self.clock = controller, controls, clock
        self.index = controller['index']
        self.directory = PurePosixPath(controller['directory'])
        self.state = self.directory / 'state'
        self.seed = controller['fixture']
        self.initial = controller['fixture_after_generation']
        raw = bytes.fromhex(self.seed['native_raw_hex'])
        native = document(raw)
        strict_record(native)
        need(len(raw) <= 2048 and sha(raw) == self.seed['native_raw_sha256']
             and exact(native, self.seed['native_record']) and native['request_id'] == self.seed['seed_id']
             and native['tool_name'] == 'host_list' and native['state'] == 'completed'
             and is_int(native['elapsed_ms']) and native['accepted_unix_ms'] > 1065536,
             'native seed original bytes/schema differs')
        owner = native['owner']
        owners = [owner] + [sha(('hepta-a50-synthetic-owner-v1\0' + owner + '\0' + str(number)).encode()) for number in range(1, 4)]
        need(len(set(owners)) == 4 and exact(owners, self.seed['owners']), 'independent synthetic owners differ')
        self.native_raw, self.native, self.owners = raw, native, owners
        self.names = {}
        for group, _, count in GROUPS:
            numbers = range(1, 65536) if group == 'archive' else range(65025, 65536)
            names = ['%02x%062x.json' % (number % 256, number + 1) for number in numbers]
            name = native['request_id'] + '.json'
            need(name not in names, 'native/synthetic identity collision')
            names.append(name)
            self.names[group] = sorted(names)
            need(len(names) == count, 'full independent namespace count differs')
        self.count = self.bytes = 0
        self.identities, self.contents = hashlib.sha256(), hashlib.sha256()
        self.owner_counts = {'archive': Counter(), 'hot': Counter()}
        self.owned = []
        self.synthetic_hashes = [None] * 65536
        self.map_path = controls.paths[str(self.directory / 'fixture-original-map.jsonl')]
        self.map_stream = self.map_path.open('rb')

    def consume(self, receipt, raw):
        self.clock.check()
        need(self.count < 66048 and len(raw) <= 2048, 'too many or oversized original bodies')
        line = self.map_stream.readline(2049)
        need(line.endswith(b'\n') and len(line) <= 2048, 'complete bounded original map line required')
        row = document(line)
        need(type(row) is list and len(row) == 4 and line == canonical(row), 'canonical original map row required')
        name, digest, size, identity = row
        relpath(name)
        need(is_sha(digest) and is_int(size, 1, 2048), 'map byte fields differ')
        identity_check(identity, size, private=True)
        group, child, offset = ('archive', 'request-archive-v11', self.count) if self.count < 65536 else ('hot', 'request-audit', self.count - 65536)
        expected_name = self.names[group][offset]
        need(name == child + '/' + expected_name, 'full original map order/membership differs')
        expected_receipt = {'path': str(self.state / name), 'bytes': size, 'sha256': digest, 'identity': identity}
        need(exact(receipt, expected_receipt) and len(raw) == size and sha(raw) == digest,
             'actual original body/receipt differs from complete initial map')
        record = document(raw)
        strict_record(record)
        request = expected_name[:-5]
        need(record['request_id'] == request, 'original filename/id differs')
        if request == self.native['request_id']:
            need(raw == self.native_raw and exact(record, self.native), 'native hot/archive raw seed differs')
        else:
            number = int(request[2:], 16) - 1
            expected_record = synthetic(number, self.owners)
            need(exact(record, expected_record) and raw == canonical(expected_record),
                 'complete synthetic original body differs')
            if group == 'hot':
                need(number >= 65025, 'old synthetic record in fixed hot set')
            else:
                need(self.synthetic_hashes[number] is None, 'duplicate synthetic original')
                self.synthetic_hashes[number] = digest
        if group == 'archive' and record['owner'] == self.owners[0]:
            self.owned.append(record)
        self.owner_counts[group][record['owner']] += 1
        self.identities.update(line)
        self.contents.update(canonical(row[:3]))
        self.count += 1
        self.bytes += size

    def finish(self):
        need(self.count == 66048 and self.map_stream.read(1) == b'', 'incomplete or extra original map/body')
        self.map_stream.close()
        need(self.identities.hexdigest() == self.controls.receipts[str(self.directory / 'fixture-original-map.jsonl')]['sha256']
             == self.initial['identity_map_sha256'] and self.contents.hexdigest() == self.initial['content_map_sha256'],
             'complete identity/content original map digests differ')
        expected_counts = {'archive': {owner: 16384 for owner in self.owners}, 'hot': {owner: 128 for owner in self.owners}}
        need(exact({key: dict(value) for key, value in self.owner_counts.items()}, expected_counts)
             and exact(expected_counts, self.initial['owner_counts']), 'all four original owners/counts differ')
        fingerprint = hashlib.sha256()
        for number in range(1, 65536):
            need(is_sha(self.synthetic_hashes[number]), 'missing verified original synthetic body')
            fingerprint.update(canonical([number, self.synthetic_hashes[number]]))
        need(fingerprint.hexdigest() == self.seed['synthetic_creation_fingerprint_sha256'],
             'synthetic creation fingerprint from all original bodies differs')
        self.synthetic_hashes = None
        self.owned.sort(key=lambda value: (value['accepted_unix_ms'], value['request_id']))
        need(len(self.owned) == 16384 and exact(self.owned[-1], self.native), 'full independently verified owned record set differs')
        self.queries = [
            {'name': 'first_1', 'arguments': {'limit': 1}},
            {'name': 'first_32', 'arguments': {'limit': 32}},
            {'name': 'quarter_16', 'arguments': {'limit': 16, 'after_id': self.owned[4095]['request_id']}},
            {'name': 'tail_32', 'arguments': {'limit': 32, 'after_id': self.owned[16381]['request_id']}}]
        self.pages = [page_oracle(self.owned, value['arguments']) for value in self.queries]
        self.usage = usage_oracle(self.owned)
        need(exact(self.queries, self.controller['queries'])
             and self.controls.raw(self.directory / 'fixture-generation.json') == canonical(self.seed)
             and self.controls.raw(self.directory / 'independent-page-oracles.json') == canonical(self.pages),
             'saved generation/cursor/page oracles differ from verified originals')
        labels = ('fixture_after_generation', 'fixture_before_measurement', 'fixture_after_measurement', 'fixture_after_shutdown') if self.index == 0 else ('fixture_after_generation', 'fixture_after_shutdown')
        if self.index == 1:
            need('fixture_before_measurement' not in self.controller and 'fixture_after_measurement' not in self.controller, 'candidate measured witnesses do not exist')
        for label in labels:
            witness = self.controller[label]
            need(witness['complete_record_body_reads'] == 66048, 'original fixture witness was incomplete')
            for field in ('counts', 'owner_counts', 'directories', 'anchor', 'identity_map_sha256', 'content_map_sha256'):
                need(exact(witness[field], self.initial[field]), 'all actually recorded fixture witnesses disagree')
        need(exact(self.initial['counts'], {'archive': 65536, 'hot': 512}), 'original group counts differ')
        self.summary = {'controller': self.index, 'record_count': self.count, 'record_bytes': self.bytes,
                        'identity_map_sha256': self.identities.hexdigest(), 'content_map_sha256': self.contents.hexdigest(),
                        'owners': expected_counts, 'synthetic_creation_fingerprint_sha256': fingerprint.hexdigest(),
                        'owned_records': len(self.owned), 'page_oracles_sha256': sha(canonical(self.pages)),
                        'usage_oracle_sha256': sha(canonical(self.usage)), 'all_original_body_semantics_verified': True}
        self.namespace_proofs = {group: {
            'path': str(self.state / child), 'identity': self.initial['directories'][group]['identity'],
            'count': count, 'sorted_names_lf_sha256': sha(''.join(name + '\n' for name in self.names[group]).encode()),
            'complete_names_basis': 'complete original map plus fixed synthetic/native ID set'}
            for group, child, count in GROUPS}
        self.names, self.owned = None, None
        return self.summary

    def close(self):
        if not self.map_stream.closed:
            self.map_stream.close()


class LargeCapture:
    def __init__(self, report, output, clock):
        self.report, self.clock = report, clock
        self.controls = CapturedControls(output)
        self.header = self.footer = None
        self.specifications = self.control_order = None
        self.files = self.raw_bytes = self.record_count = self.record_bytes = 0
        self.payload = self.frames = 0
        self.stream_digest, self.receipt_digest = hashlib.sha256(), hashlib.sha256()
        self.active = None
        self.fixtures = []

    def admit_header(self, row):
        keys = {'type', 'schema', 'base', 'experiment', 'report_receipt', 'collector_receipt',
                'collection_protocol_receipt', 'original_performance_passed', 'independent_raw_audit_complete',
                'performance_adopted', 'expected_members', 'expected_record_members', 'absent_optional_index_seals',
                'original_control_members', 'control_receipts_before', 'shared_small_evidence',
                'common_original_receipts_before', 'source_directory_before', 'unexecuted_test_elf_stat_only_before',
                'original_directory_before', 'fixture_preflight', 'cache_receipts_before',
                'cache_bodies_intentionally_omitted', 'limits', 'admitted_payload_upper_estimate_bytes', 'started_unix_ns',
                'original_workload_complete', 'planned_measured_calls', 'observed_measured_write_attempts',
                'observed_measured_successes', 'unexecuted_measured_slots'}
        need(set(row) == keys and row['type'] == 'header'
             and row['schema'] == 'hepta-a54-large-partial-original-evidence-jsonl/v1'
             and row['base'] == str(BASE) and row['experiment'] == str(ROOT)
             and row['original_performance_passed'] is False and row['performance_adopted'] is False
             and row['independent_raw_audit_complete'] is False,
             'fixed original capture header differs')
        need(row['original_workload_complete'] is False and row['planned_measured_calls'] == 80
             and row['observed_measured_write_attempts'] == 20 and row['observed_measured_successes'] == 8
             and row['unexecuted_measured_slots'] == list(range(20, 80)),
             'header must preserve the incomplete original planned and observed workload')
        receipt_check(row['report_receipt'], ROOT / 'report.json', REPORT_BYTES, REPORT_SHA, private=True)
        receipt_check(row['collector_receipt'], COLLECTOR, COLLECTOR_BYTES, COLLECTOR_SHA)
        receipt_check(row['collection_protocol_receipt'], COLLECTION_PROTOCOL, COLLECTION_PROTOCOL_BYTES, COLLECTION_PROTOCOL_SHA)
        expected = fixed_controls(self.report)
        self.required_originals = dict(expected)
        optional = optional_controls()
        absent = row['absent_optional_index_seals']
        need(type(absent) is list and absent == sorted(set(absent)) and set(absent) <= set(optional),
             'only explicitly absent known seals may be omitted')
        for path, spec in optional.items():
            if path not in absent:
                expected[path] = spec
        expected[str(COLLECTOR)] = {'category': 'collector-source', 'expected': row['collector_receipt'],
                                    'identity_format': 'stat9', 'maximum': 1024 * 1024}
        expected[str(COLLECTION_PROTOCOL)] = {'category': 'collector-protocol', 'expected': row['collection_protocol_receipt'],
                                             'identity_format': 'stat9', 'maximum': 1024 * 1024}
        need(exact(row['original_control_members'], expected) and len(expected) == 69 - len(absent)
             and row['expected_record_members'] == 132096 and row['expected_members'] == 132096 + len(expected)
             and set(row['control_receipts_before']) == set(expected), 'independent exact member allowlist differs')
        for path, value in row['control_receipts_before'].items():
            receipt_check(value, path, private=remote_path(path).is_relative_to(ROOT))
            spec = expected[path]
            need(value['bytes'] <= spec['maximum'], 'control exceeds original maximum')
            original_match(value, spec['expected'], spec['identity_format'] == 'stat8_without_gid')
        need(exact(row['control_receipts_before'][str(ROOT / 'report.json')], row['report_receipt'])
             and exact(row['control_receipts_before'][str(COLLECTOR)], row['collector_receipt'])
             and exact(row['control_receipts_before'][str(COLLECTION_PROTOCOL)], row['collection_protocol_receipt']),
             'header input/control receipts disagree')
        expected_limits = {'max_payload_bytes': MAX_PACK, 'max_gzip_bytes': MAX_PACK,
                           'max_record_bytes': MAX_RECORD_BYTES, 'chunk_bytes': CHUNK, 'whole_operation_seconds': 600}
        need(exact(row['limits'], expected_limits) and is_int(row['admitted_payload_upper_estimate_bytes'], 1, MAX_PACK)
             and is_int(row['started_unix_ns'], 1), 'original fixed capture bounds differ')
        shared = row['shared_small_evidence']
        receipt_check(shared['receipt'], SHARED_SMALL, SMALL_BYTES, SMALL_SHA)
        need(shared['body_read_here'] is True and shared['required_by_independent_auditor'] is True
             and shared['referenced_source_bodies'] == 340 and shared['referenced_release_elf_bodies'] == 2
             and exact(shared['source_map_compact_sha256'], SOURCE_MAPS) and exact(shared['release_sha256'], ELFS),
             'actual shared source/release package binding differs')
        self.specifications, self.control_order = expected, sorted(expected)
        self.header = row

    def begin_file(self, sequence, category, receipt):
        need(self.active is None and is_int(sequence, 1) and sequence == self.files + 1
             and self.header is not None and self.footer is None and type(category) is str,
             'contiguous unique file sequence required')
        receipt_check(receipt)
        if sequence <= len(self.control_order):
            path = self.control_order[sequence - 1]
            need(receipt['path'] == path and category == self.specifications[path]['category']
                 and exact(receipt, self.header['control_receipts_before'][path]),
                 'sorted original control order/category/receipt differs')
            local = self.controls.target(sequence)
            fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            output = os.fdopen(fd, 'wb')
        else:
            need(category == 'original-fixture-record' and receipt['bytes'] <= 2048 and self.record_count < 132096,
                 'only complete original records may follow closed controls')
            index = self.record_count // 66048
            if index == len(self.fixtures):
                need(self.record_count % 66048 == 0 and len(self.controls.receipts) == len(self.control_order),
                     'original controls must close before first record')
                self.fixtures.append(FixtureOracle(self.report['controllers'][index], self.controls, self.clock))
                print(json.dumps({'phase': 'audit-original-records', 'controller': index}), flush=True)
            local = output = None
        self.active = {'sequence': sequence, 'category': category, 'receipt': receipt, 'count': 0,
                       'digest': hashlib.sha256(), 'chunks': 0, 'local': local, 'output': output,
                       'body': bytearray() if output is None else None}

    def body(self, raw):
        value = self.active
        need(value is not None and len(raw) <= CHUNK
             and value['count'] + len(raw) <= value['receipt']['bytes'], 'bounded complete file body required')
        if value['output'] is None:
            value['body'].extend(raw)
        else:
            need(value['output'].write(raw) == len(raw), 'partial audit control spool write')
        value['count'] += len(raw)
        value['digest'].update(raw)

    def end_file(self):
        value = self.active
        need(value is not None and value['count'] == value['receipt']['bytes']
             and value['digest'].hexdigest() == value['receipt']['sha256'], 'whole original member byte hash differs')
        if value['output'] is not None:
            value['output'].flush()
            value['output'].close()
            self.controls.register(value['receipt'], value['local'])
        else:
            fixture = self.fixtures[self.record_count // 66048]
            fixture.consume(value['receipt'], bytes(value['body']))
            self.record_count += 1
            self.record_bytes += value['count']
            need(self.record_bytes <= MAX_RECORD_BYTES, 'all original record body bytes exceeded fixed bound')
            if self.record_count % 66048 == 0:
                fixture.finish()
        self.files += 1
        self.raw_bytes += value['count']
        need(self.raw_bytes <= MAX_PACK, 'captured raw byte total exceeded bound')
        self.receipt_digest.update(canonical([value['sequence'], value['category'], value['receipt']]))
        self.active = None

    def accept(self, row):
        kind = row.get('type')
        if kind == 'file':
            need(set(row) == {'type', 'sequence', 'category', 'receipt', 'data_base64'}
                 and row['receipt']['bytes'] <= CHUNK and type(row['data_base64']) is str,
                 'closed small member frame required')
            self.begin_file(row['sequence'], row['category'], row['receipt'])
            raw = base64.b64decode(row['data_base64'], validate=True)
            need(base64.b64encode(raw).decode() == row['data_base64'], 'canonical member base64 required')
            self.body(raw)
            self.end_file()
        elif kind == 'file-start':
            need(set(row) == {'type', 'sequence', 'category', 'receipt'} and row['receipt']['bytes'] > CHUNK,
                 'closed large member start required')
            self.begin_file(row['sequence'], row['category'], row['receipt'])
        elif kind == 'file-chunk':
            value = self.active
            need(set(row) == {'type', 'sequence', 'index', 'offset', 'bytes', 'sha256', 'data_base64'}
                 and value is not None and value['receipt']['bytes'] > CHUNK
                 and is_int(row['sequence'], 1) and row['sequence'] == value['sequence']
                 and is_int(row['index']) and row['index'] == value['chunks']
                 and is_int(row['offset']) and row['offset'] == value['count']
                 and is_int(row['bytes'], 1, CHUNK) and is_sha(row['sha256']) and type(row['data_base64']) is str,
                 'contiguous bounded original member chunks required')
            raw = base64.b64decode(row['data_base64'], validate=True)
            need(base64.b64encode(raw).decode() == row['data_base64'] and len(raw) == row['bytes']
                 == min(CHUNK, value['receipt']['bytes'] - value['count']) and sha(raw) == row['sha256'],
                 'complete original chunk bytes/SHA differ')
            self.body(raw)
            value['chunks'] += 1
        elif kind == 'file-end':
            value = self.active
            need(set(row) == {'type', 'sequence', 'chunks', 'receipt'} and value is not None
                 and value['receipt']['bytes'] > CHUNK and is_int(row['sequence'], 1)
                 and row['sequence'] == value['sequence'] and is_int(row['chunks'], 1)
                 and row['chunks'] == value['chunks'] and exact(row['receipt'], value['receipt']),
                 'exact original member terminal frame required')
            self.end_file()
        else:
            raise ValueError('unexpected original capture frame type')

    def admit_footer(self, row):
        need(self.active is None and self.footer is None and row['capture_complete'] is True
             and row['member_count'] == self.files == self.header['expected_members']
             and row['record_member_count'] == self.record_count == 132096
             and row['record_bytes'] == self.record_bytes and row['total_captured_raw_bytes'] == self.raw_bytes
             and row['payload_bytes_before_footer'] == self.payload and row['frames_before_footer'] == self.frames
             and row['frames_before_footer_sha256'] == self.stream_digest.hexdigest()
             and row['ordered_file_receipts_sha256'] == self.receipt_digest.hexdigest(),
             'complete unique footer byte/count/hash ledger differs')
        for name in ('all_collected_bodies_full_byte_reread', 'control_receipts_final_equal_before',
                     'common_original_receipts_final_equal_before', 'source_directory_final_equal_before',
                     'original_directory_final_equal_before', 'cache_full_byte_final_equal_before',
                     'shared_small_full_byte_final_equal_before'):
            need(row[name] is True, 'original full final capture fence incomplete: ' + name)
        for name in ('original_performance_passed', 'independent_raw_audit_complete', 'performance_adopted', 'originals_modified'):
            need(row[name] is False, 'collector scope cannot claim audit/adoption/mutation')
        need(type(row['business_or_child_executions']) is int and row['business_or_child_executions'] == 0
             and type(row['ssh_or_signals']) is int and row['ssh_or_signals'] == 0
             and is_int(row['finished_unix_ns'], self.header['started_unix_ns']), 'collector action/timestamp ledger differs')
        need(row['original_workload_complete'] is False, 'partial footer cannot complete the original workload')
        self.footer = row

    def read(self, source):
        source.stream.seek(0)
        with gzip.GzipFile(fileobj=source.stream, mode='rb') as stream:
            while True:
                self.clock.check()
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                need(raw.endswith(b'\n') and len(raw) <= MAX_LINE and self.payload + len(raw) <= MAX_PACK,
                     'bounded complete capture line/payload required')
                row = document(raw)
                need(type(row) is dict and canonical(row) == raw and self.footer is None,
                     'noncanonical capture frame or bytes after complete footer')
                if self.header is None:
                    self.admit_header(row)
                elif row.get('type') == 'footer':
                    self.admit_footer(row)
                else:
                    self.accept(row)
                self.payload += len(raw)
                self.frames += 1
                self.stream_digest.update(raw)
        need(self.header is not None and self.footer is not None and self.active is None and len(self.fixtures) == 2,
             'truncated capture/footer/CRC or incomplete original fixture inventory')
        return self

    def close(self):
        if self.active is not None and self.active['output'] is not None:
            self.active['output'].close()
        for fixture in self.fixtures:
            fixture.close()


def directory_check(row, path, children, private=True):
    need(type(row) is dict and set(row) == {'path', 'identity', 'entries'} and row['path'] == str(path),
         'closed original directory receipt required')
    identity_check(row['identity'], private=private, directory=True)
    need(type(row['entries']) is list and [item[0] for item in row['entries']] == sorted(children)
         and len(row['entries']) == len(children), 'exact original directory name set differs: ' + str(path))
    for item in row['entries']:
        need(type(item) is list and len(item) == 2 and type(item[0]) is str and item[0] not in ('', '.', '..')
             and '/' not in item[0] and exact(item[1], children[item[0]]), 'original direct child identity linkage differs')


def verify_original_directories(capture):
    header, report, controls = capture.header, capture.report, capture.controls
    inventory = header['original_directory_before']
    need(set(inventory) == {'root', 'controllers', 'states', 'auxiliary_directories'}
         and set(inventory['controllers']) == set(inventory['states']) == set(inventory['auxiliary_directories'])
         == {'0', '1'}, 'both actually started original directory inventories required')
    root_children = {PurePosixPath(path).name: value['identity'] for path, value in controls.receipts.items()
                     if PurePosixPath(path).parent == ROOT}
    caches = header['cache_receipts_before']
    allowed_caches = {str(PurePosixPath(controller['directory']) / 'state' / CACHE) for controller in report['controllers']}
    need(type(caches) is dict and set(caches) <= allowed_caches
         and header['cache_bodies_intentionally_omitted'] == list(caches), 'only exact known disposable cache body omission allowed')
    for path, value in caches.items():
        receipt_check(value, path, private=True)
        need(path not in controls.receipts, 'cache body scope is inconsistent')
    for index, fixture in enumerate(capture.fixtures):
        key, directory, state = str(index), fixture.directory, fixture.state
        row, state_row, auxiliary = inventory['controllers'][key], inventory['states'][key], inventory['auxiliary_directories'][key]
        root_children[directory.name] = row['identity']
        children = {PurePosixPath(path).name: value['identity'] for path, value in controls.receipts.items()
                    if PurePosixPath(path).parent == directory}
        children['state'] = state_row['identity']
        directory_check(row, directory, children)
        expected_aux = {'jobs', 'audit', 'request-results', 'request-results-v2', 'request-results-v2/archive'}
        expected_aux.update('request-results-v2/archive/%02x' % number for number in range(256))
        need(set(auxiliary) == expected_aux, 'complete exact auxiliary result directory set required')
        children = {PurePosixPath(path).name: value['identity'] for path, value in controls.receipts.items()
                    if PurePosixPath(path).parent == state}
        for name in ('jobs', 'audit', 'request-results', 'request-results-v2'):
            children[name] = auxiliary[name]['identity']
        for group, child, _ in GROUPS:
            identity = fixture.initial['directories'][group]['identity']
            identity_check(identity, private=True, directory=True)
            children[child] = identity
        if str(state / CACHE) in caches:
            children[CACHE] = caches[str(state / CACHE)]['identity']
        directory_check(state_row, state, children)
        for name in ('jobs', 'audit'):
            directory_check(auxiliary[name], state / name, {})
        marker = str(state / 'request-results/.request-results-v2.json')
        directory_check(auxiliary['request-results'], state / 'request-results',
                        {'.request-results-v2.json': controls.receipts[marker]['identity']})
        directory_check(auxiliary['request-results-v2'], state / 'request-results-v2',
                        {'archive': auxiliary['request-results-v2/archive']['identity']})
        shard_children = {'%02x' % number: auxiliary['request-results-v2/archive/%02x' % number]['identity'] for number in range(256)}
        directory_check(auxiliary['request-results-v2/archive'], state / 'request-results-v2/archive', shard_children)
        for number in range(256):
            name = 'request-results-v2/archive/%02x' % number
            seed_name = fixture.native['request_id'] + '.json'
            children = {seed_name: controls.receipts[str(state / name / seed_name)]['identity']} if number == int(fixture.native['request_id'][:2], 16) else {}
            directory_check(auxiliary[name], state / name, children)
        proof = {'controller': index, 'record_count': fixture.count, 'record_bytes': fixture.bytes,
                 'identity_map_sha256': fixture.summary['identity_map_sha256'], 'content_map_sha256': fixture.summary['content_map_sha256'],
                 'namespaces': fixture.namespace_proofs, 'expected_owner_counts_from_id_set': fixture.summary['owners'],
                 'full_bodies_read': True, 'estimated_payload_bytes': None}
        need(exact(capture.footer['fixture_capture_and_final_fence'][index], proof),
             'capture final namespace/body proof differs from all independently consumed originals')
        before = dict(header['fixture_preflight'][index])
        need(before.pop('full_bodies_read') is False and is_int(before.pop('estimated_payload_bytes'), 1)
             and exact(before, {k: v for k, v in proof.items() if k not in ('full_bodies_read', 'estimated_payload_bytes')}),
             'initial stat-only fixture inventory differs from all original bodies')
    need(len(header['fixture_preflight']) == len(capture.footer['fixture_capture_and_final_fence']) == 2,
         'exact two actual fixture proofs required')
    directory_check(inventory['root'], ROOT, root_children)


def verify_shared_small(source, capture, clock):
    """Check complete package structure/bytes and independently all 342 common bodies.

    The prior independent small-run semantic audit remains its own proof. This
    routine does not claim to re-execute that audit or its 8,848-wire oracle.
    """
    report, header = capture.report, capture.header
    common = header['common_original_receipts_before']
    expected_common = {}
    for arm, bundle in report['qualifications'].items():
        for relative, digest in bundle['source_map'].items():
            path = str(SOURCE_DIRS[arm] / relpath(relative))
            expected_common[path] = {'sha256': digest}
        expected_common[bundle['binary']['path']] = bundle['binary']
    need(set(common) == set(expected_common) and len(common) == 342, 'complete original common source/release inventory differs')
    for path, expected in expected_common.items():
        receipt_check(common[path], path)
        original_match(common[path], expected)
    source.stream.seek(0)
    first = footer = None
    receipts, common_seen, expanded, raw_bytes = {}, set(), 0, 0
    with gzip.GzipFile(fileobj=source.stream, mode='rb') as stream:
        while True:
            clock.check()
            raw = stream.readline(MAX_SMALL_LINE + 1)
            if not raw:
                break
            expanded += len(raw)
            need(raw.endswith(b'\n') and len(raw) <= MAX_SMALL_LINE and expanded <= MAX_PACK,
                 'shared small bounded complete framing required')
            row = document(raw)
            need(type(row) is dict and footer is None, 'shared small data after footer or invalid row')
            if first is None:
                first = row
                need(row['type'] == 'header' and row['schema'] == 'hepta-a54-small-original-evidence-jsonl/v1'
                     and row['member_count'] == len(row['specifications']) == 2023 and row['base'] == str(BASE)
                     and exact(row['source_counts'], {'r07': 165, 'A54': 175})
                     and exact(row['source_map_compact_sha256'], {'r07': SOURCE_MAPS['A'], 'A54': SOURCE_MAPS['B']})
                     and exact(row['release_sha256'], {'r07': ELFS['A'], 'A54': ELFS['B']}), 'actual shared small header differs')
            elif row.get('type') == 'file':
                need(set(row) == {'type', 'path', 'category', 'receipt', 'data_base64'}, 'closed shared original file frame required')
                path = row['path']
                remote_path(path)
                need(path in first['specifications'] and path not in receipts and len(receipts) < 2023,
                     'duplicate or unlisted shared small member')
                spec = first['specifications'][path]
                need(row['category'] == spec['category'] and type(row['data_base64']) is str, 'shared member category/body differs')
                body = base64.b64decode(row['data_base64'], validate=True)
                need(len(body) <= 32 * 1024 * 1024 and base64.b64encode(body).decode() == row['data_base64'],
                     'bounded canonical shared body required')
                receipt_check(row['receipt'], path, len(body), sha(body))
                original_match(row['receipt'], spec['expected'])
                raw_bytes += len(body)
                need(raw_bytes <= 256 * 1024 * 1024, 'shared total body bound exceeded')
                receipts[path] = row['receipt']
                if path in common:
                    need(exact(row['receipt'], common[path]), 'common original source/release identity differs between packs')
                    common_seen.add(path)
                    if path.endswith('/hepta-runtime'):
                        need(body.startswith(b'\x7fELF'), 'common measured release is not an ELF')
                del body
            else:
                need(row.get('type') == 'footer' and row['capture_complete'] is True and row['member_count'] == len(receipts) == 2023
                     and row['receipts_compact_sha256'] == sha(compact(receipts)) and row['total_raw_bytes'] == raw_bytes
                     and row['all_full_byte_receipts_rechecked'] is True and row['source_bodies_captured'] == 340
                     and row['release_elf_bodies_captured'] == 2
                     and exact(row['block_directory_before'], row['block_directory_after'])
                     and exact(row['source_directory_before'], row['source_directory_after']),
                     'shared full final footer closure differs')
                footer = row
    need(first is not None and footer is not None and set(receipts) == set(first['specifications'])
         and common_seen == set(common), 'missing complete shared original package/source bodies')
    need(exact(header['shared_small_evidence']['common_source_release_body_verification'], {
        'gzip_crc_and_final_footer_verified': True, 'shared_member_frames': 2023,
        'common_full_body_sha_and_identity_checked': 342, 'all_other_small_body_semantics_audited_here': False,
        'independent_small_wire_fixture_audit_still_required': True}), 'collector shared proof scope differs')
    for arm, bundle in report['qualifications'].items():
        inventory = header['source_directory_before'][arm]
        source_root = SOURCE_DIRS[arm]
        expected_files = {str(source_root / relpath(name)) for name in bundle['source_map']}
        seen_files, seen_directories = set(), set()
        need(type(inventory) is dict and '.' in inventory and len(inventory) <= 64, 'bounded complete original source directories required')
        for relative, row in inventory.items():
            path = source_root if relative == '.' else source_root / relpath(relative)
            children = {}
            for name, identity in row['entries']:
                full = str(path / name)
                if stat.S_ISDIR(identity[2]):
                    child_relative = str(PurePosixPath(full).relative_to(source_root))
                    need(child_relative in inventory and exact(identity, inventory[child_relative]['identity']), 'source child directory link differs')
                    children[name] = inventory[child_relative]['identity']
                    seen_directories.add(child_relative)
                else:
                    need(full in expected_files and full not in seen_files, 'extra or duplicate original source member')
                    children[name] = common[full]['identity']
                    seen_files.add(full)
            directory_check(row, path, children, private=False)
        need(seen_files == expected_files and seen_directories == set(inventory) - {'.'}, 'complete source tree differs from full tested map')
        test = header['unexecuted_test_elf_stat_only_before'][arm]
        need(exact(test, {'path': bundle['test_binary']['path'], 'identity': bundle['test_binary']['identity'], 'body_read': False}),
             'unexecuted test ELF must remain explicitly metadata-only')
        identity_check(test['identity'])
    return {'complete_gzip_crc_and_2023_member_byte_hashes': True, 'common_source_bodies': 340,
            'common_release_elf_bodies': 2, 'all_common_original_receipts_equal': True,
            'common_source_tree_full_tested_map_checked': True, 'test_elf_bodies_read': False,
            'other_small_run_wire_fixture_semantics_reaudited_here': False,
            'shared_small_sha256': SMALL_SHA, 'shared_small_bytes': SMALL_BYTES}


def decoded_result(reply):
    """A closed DTO or one of the original explicitly allowed product failures."""
    need(type(reply) is dict and reply.get('jsonrpc') == '2.0'
         and is_int(reply.get('id'), 1, 24) and (('result' in reply) != ('error' in reply)),
         'complete original JSON-RPC result/error envelope required')
    if 'error' in reply:
        error = reply['error']
        need(type(error) is dict and error.get('message') in PRODUCT_ERRORS, 'unexpected raw native RPC error')
        return None, None, error['message']
    result = reply['result']
    need(type(result) is dict and type(result.get('content')) is list and len(result['content']) == 1,
         'one original native text content block required')
    text = result['content'][0]
    need(type(text) is dict and text.get('type') == 'text' and type(text.get('text')) is str,
         'native result text absent')
    error_flag = result.get('isError', False)
    need(type(error_flag) is bool, 'native isError must be a JSON boolean')
    if error_flag:
        need(text['text'] in PRODUCT_ERRORS, 'unexpected raw native tool error')
        return result, None, text['text']
    dto = document(text['text'])
    need(type(dto) is dict, 'native DTO must be a strict JSON object')
    return result, dto, None


def seed_markers(result, request_id, retained=False):
    meta = result.get('_meta')
    need(type(meta) is dict and type(meta.get('io.hepta.runtime/request-v8')) is dict,
         'original native request marker absent')
    marker = meta['io.hepta.runtime/request-v8']
    need(marker.get('request_id') == request_id and marker.get('automatic_retry') is False
         and marker.get('delivery_proven') is False, 'native request ID/delivery semantics differ')
    if not retained:
        ack = meta.get('io.hepta.runtime/retention-v8')
        need(type(ack) is dict and ack.get('audit_completion_durable') is True
             and ack.get('result_state') == 'stored' and ack.get('automatic_retry') is False,
             'native seed original durable completion/result acknowledgement absent')
    return marker


def verify_auxiliary(capture):
    controls, inventory = capture.controls, capture.header['original_directory_before']
    summaries = []
    for index, fixture in enumerate(capture.fixtures):
        state, native = fixture.state, fixture.native
        state_identity = inventory['states'][str(index)]['identity']
        archive_identity = fixture.initial['directories']['archive']['identity']
        anchor = controls.doc(state / '.request-archive-v11-anchor.json')
        need(exact(anchor, {'root_device': state_identity[0], 'root_inode': state_identity[1],
                            'archive_device': archive_identity[0], 'archive_inode': archive_identity[1]}),
             'original flat archive anchor/namespace identity differs')
        need(controls.raw(state / 'controller.lock') == b'', 'original controller flock handle is not empty')
        auxiliary = inventory['auxiliary_directories'][str(index)]
        directory_id = lambda row: {'device': row['identity'][0], 'inode': row['identity'][1]}
        result_anchor_raw = controls.raw(state / '.request-results-v2-anchor.json')
        result_anchor = document(result_anchor_raw)
        expected_anchor = {'schema': 2, 'root': {'device': state_identity[0], 'inode': state_identity[1]},
                           'legacy': directory_id(auxiliary['request-results']),
                           'store': directory_id(auxiliary['request-results-v2']),
                           'archive': directory_id(auxiliary['request-results-v2/archive']),
                           'shards': [directory_id(auxiliary['request-results-v2/archive/%02x' % number]) for number in range(256)]}
        need(exact(result_anchor, expected_anchor), 'full 256-shard native result anchor identities differ')
        marker = controls.doc(state / 'request-results/.request-results-v2.json')
        need(exact(marker, {'schema': 2, 'anchor_sha256': sha(result_anchor_raw)}), 'native result marker/anchor byte hash differs')
        path = state / 'request-results-v2/archive' / native['request_id'][:2] / (native['request_id'] + '.json')
        retained = controls.doc(path)
        need(type(retained) is dict and set(retained) == {'request_id', 'owner', 'tool_name', 'accepted_unix_ms',
             'policy_binding', 'state', 'payload_base64', 'payload_bytes', 'payload_sha256'},
             'closed original retained native result schema differs')
        need(all(exact(retained[key], native[key]) for key in ('request_id', 'owner', 'tool_name', 'accepted_unix_ms'))
             and retained['state'] == 'stored' and is_sha(retained['policy_binding'])
             and type(retained['payload_base64']) is str and is_int(retained['payload_bytes'], 1, 64 * 1024)
             and is_sha(retained['payload_sha256']), 'native retained result identity/state/payload fields differ')
        payload = base64.b64decode(retained['payload_base64'], validate=True)
        need(base64.b64encode(payload).decode() == retained['payload_base64']
             and len(payload) == retained['payload_bytes'] and sha(payload) == retained['payload_sha256'],
             'complete native result payload byte hash differs')
        result = document(payload)
        # The stored original precedes the transport's resultType normalization
        # and retention ACK. Compare its closed business DTO/request ID, never
        # claim its serialized wrapper is byte-identical to the later reply.
        _, dto, error = decoded_result({'jsonrpc': '2.0', 'id': 2, 'result': result})
        need(error is None and exact(dto, HOST_DTO), 'retained native result escaped closed host_list DTO')
        seed_markers(result, native['request_id'], retained=True)
        seal_path = str(state / SEAL)
        seal_summary = {'present': seal_path in controls.receipts, 'cache_body_omitted': str(state / CACHE) in capture.header['cache_receipts_before'],
                        'seal_digest_recomputed_from_cache': False, 'disposable_cache_is_fixture_authority': False}
        if seal_path in controls.receipts:
            seal = controls.doc(seal_path)
            need(type(seal) is dict and set(seal) == {'format', 'binding', 'device', 'inode', 'length', 'sha256'}
                 and seal['format'] in ('hepta-redb-4.4.0-recovery-bit-sha256-v1', 'hepta-redb-4.4.0-recovery-bit-two-part-sha256-v2')
                 and all(is_int(seal[key], maximum=(1 << 64) - 1) for key in ('device', 'inode', 'length'))
                 and is_sha(seal['sha256']) and type(seal['binding']) is list
                 and all(is_int(byte, 0, 255) for byte in seal['binding']), 'original disposable seal shape differs')
            need(bytes(seal['binding']) == compact(['hepta-disk-index-v2', archive_identity[0], archive_identity[1]]),
                 'disposable seal archive identity binding differs')
            seal_summary.update(format=seal['format'], receipt=controls.receipts[seal_path])
        summaries.append({'controller': index, 'native_seed_result_receipt': controls.receipts[str(path)],
                          'payload_sha256': sha(payload), 'closed_native_host_list_dto_verified': True,
                          'result_policy_binding_retained': retained['policy_binding'],
                          'result_policy_binding_reconstructed_from_runtime_defaults': False,
                          'all_result_directory_identities_verified': True, 'index_seal': seal_summary})
    return summaries


def wire_rows(raw, canonical_required=False):
    need(len(raw) <= 16 * 1024 * 1024 and raw.endswith(b'\n'), 'complete bounded original wire required')
    offset, values = 0, []
    for line in raw.splitlines(keepends=True):
        need(line.endswith(b'\n') and len(line) <= 1024 * 1024, 'original message line bound/framing differs')
        value = document(line)
        need(type(value) is dict and value.get('jsonrpc') == '2.0', 'raw native JSON-RPC object required')
        if canonical_required:
            need(canonical(value) == line, 'original once-write request bytes differ from canonical framing')
        values.append({'value': value, 'raw': line, 'offset': offset, 'bytes': len(line), 'sha256': sha(line)})
        offset += len(line)
    need(offset == len(raw), 'original wire was not fully consumed')
    return values


def wire_receipt(row, request, response):
    rpc_id = row['rpc_id']
    need(is_int(rpc_id, 1, 24) and request['value'].get('id') == rpc_id and response['value'].get('id') == rpc_id,
         'original RPC ID route differs')
    for label, wire in (('request', request), ('response', response)):
        for field in ('offset', 'bytes', 'sha256'):
            need(exact(row[label + '_wire_' + field], wire[field]), 'original raw wire offset/count/hash differs')
    need(row['write_attempts'] == 1 and type(row['write_attempts']) is int
         and row['sent'] is True and row['response_received'] is True and row['automatic_retry'] is False
         and row['single_wave_os_write'] is True and row['server_admission_or_cohort_timing_observed'] is False,
         'original once-only RPC attempt/response facts differ')
    registered, started, ended, deadline = (row[key] for key in ('client_pending_registered_monotonic_ns',
        'start_monotonic_ns', 'response_received_monotonic_ns', 'client_deadline_monotonic_ns'))
    need(all(is_int(value, 1) for value in (registered, started, ended, deadline))
         and registered <= started <= ended < deadline and deadline - started == 10_000_000_000
         and type(row['elapsed_ms']) is float and row['elapsed_ms'] == (ended - started) / 1e6
         and type(row['caller_wall_ms']) is float and row['caller_wall_ms'] >= row['elapsed_ms'],
         'original RPC latency or absolute client deadline differs')


def verify_rpc_and_journal(capture):
    report, controls = capture.report, capture.controls
    journal_raw = controls.raw(ROOT / 'calls.jsonl')
    need(journal_raw.endswith(b'\n') and len(journal_raw) <= 16 * 1024 * 1024, 'full original attempt journal required')
    journal = []
    for line in journal_raw.splitlines(keepends=True):
        row = document(line)
        need(type(row) is dict and canonical(row) == line and row.get('journaled') is True, 'canonical original journal row required')
        journal.append(row)
    need(len(journal) == 26, 'exact 26 actually attempted original tool journal rows required')
    expected_journal, summaries, all_pids, failed_slots, setup_failures = [], [], set(), [], []
    for index, fixture in enumerate(capture.fixtures):
        controller, directory = fixture.controller, fixture.directory
        startup, shutdown = controller['startup'], controller['shutdown']
        rpc_count = 24 if index == 0 else 4
        requests = wire_rows(controls.raw(directory / 'requests.jsonl'), canonical_required=True)
        responses = wire_rows(controls.raw(directory / 'responses.jsonl'))
        need(len(requests) == rpc_count + 1 and len(responses) == rpc_count, 'exact actually sent ID-bearing RPCs plus initialized notification required')
        notification = {'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}}
        need(exact(requests[1]['value'], notification), 'single original initialized notification differs')
        id_requests = [row for row in requests if 'id' in row['value']]
        need(len(id_requests) == rpc_count and [row['value']['id'] for row in id_requests] == list(range(1, rpc_count + 1))
             and all(type(row['value']['id']) is int for row in id_requests), 'complete original request IDs/order differs')
        response_map = {}
        response_order = []
        for row in responses:
            rpc_id = row['value'].get('id')
            need(is_int(rpc_id, 1, rpc_count) and rpc_id not in response_map, 'unknown/duplicate original response ID')
            response_map[rpc_id] = row
            response_order.append(rpc_id)
        need(set(response_map) == set(range(1, rpc_count + 1)) and response_order[0] == 1,
             'complete original response ID set/init order required')
        init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-03-26',
                'capabilities': {}, 'clientInfo': {'name': 'hepta-a50-native-archive-cohort', 'version': '1'}}}
        need(exact(id_requests[0]['value'], init) and 'error' not in response_map[1]['value']
             and type(response_map[1]['value'].get('result')) is dict
             and startup['initialize']['okay'] is True and startup['initialize']['status'] == 'succeeded',
             'original initialize request/reply differs')
        wire_receipt(startup['initialize'], id_requests[0], response_map[1])
        init_result = response_map[1]['value']['result']
        need(init_result.get('protocolVersion') == '2025-03-26' and type(init_result.get('capabilities')) is dict,
             'native initialize negotiated protocol differs')
        rows = controller['setup'] + [row for row in report['slots'] if row['controller'] == index and row['write_attempts'] == 1]
        need(len(rows) == rpc_count - 1 and [row['rpc_id'] for row in rows] == list(range(2, rpc_count + 1)), 'fixed original tool call IDs differ')
        need([row['purpose'] for row in rows[:3]] == ['native_seed', 'index_kickoff', 'archive_warmup'], 'fixed original setup order differs')
        expected_journal.extend(rows)
        successful = product_failed = 0
        for rpc_id, row in enumerate(rows, 2):
            if rpc_id == 2:
                tool, arguments, expected = 'host_list', {}, HOST_DTO
            elif rpc_id == 3:
                tool, arguments, expected = 'usage_stats', {}, fixture.usage
            elif rpc_id == 4:
                tool, arguments, expected = 'request_archive', {'limit': 1}, fixture.pages[0]
            else:
                local_slot = rpc_id - 5
                wave = local_slot if local_slot < 4 else 4 + (local_slot - 4) // 4
                position = 0 if local_slot < 4 else (local_slot - 4) % 4
                variant = wave if wave < 4 else (wave - 4 + position) % 4
                planned = {'slot': index * 20 + local_slot, 'controller': index, 'block': index // 2,
                           'arm': ORDER[index], 'wave': wave, 'position': position, 'query_variant': variant,
                           'concurrency': 1 if wave < 4 else 4, 'purpose': 'measured', 'tool': 'request_archive',
                           'automatic_retry': False}
                need(all(exact(row[key], value) for key, value in planned.items()), 'fixed original measured schedule differs')
                tool, arguments, expected = 'request_archive', fixture.queries[variant]['arguments'], fixture.pages[variant]
                need(row['query_name'] == fixture.queries[variant]['name'], 'independent measured cursor name differs')
            need(row['controller'] == index and row['arm'] == ORDER[index] and row['tool'] == tool
                 and exact(row['arguments'], arguments) and row['journaled'] is True, 'tool journal identity/arguments differ')
            request = {'jsonrpc': '2.0', 'id': rpc_id, 'method': 'tools/call', 'params': {'name': tool, 'arguments': arguments}}
            need(exact(id_requests[rpc_id - 1]['value'], request), 'original raw request differs from independent schedule')
            wire_receipt(row, id_requests[rpc_id - 1], response_map[rpc_id])
            result, dto, failure = decoded_result(response_map[rpc_id]['value'])
            if failure is None:
                need(exact(dto, expected) and row['okay'] is True and row['status'] == 'succeeded'
                     and row['dto_sha256'] == sha(canonical(dto)) and 'error' not in row and 'error_type' not in row,
                     'full raw successful DTO/report oracle differs')
                if rpc_id == 2:
                    seed_markers(result, fixture.native['request_id'])
                    need(row['native_request_id'] == fixture.native['request_id'], 'raw seed response/native original identity differs')
                successful += 1
            else:
                need(rpc_id != 2 and (rpc_id != 4 or index == 1) and row['okay'] is False and row['status'] == 'product_failure'
                     and row['error_type'] == 'ProductFailure' and row['error'] == failure and 'dto_sha256' not in row,
                     'raw original product failure must remain an explicit failure')
                product_failed += 1
                if rpc_id in (3, 4):
                    setup_failures.append({'controller': index, 'rpc_id': rpc_id, 'error': failure,
                                           'response_wire_sha256': row['response_wire_sha256']})
                else:
                    failed_slots.append(row['slot'])
            expected_pending = [rpc_id] if rpc_id < 9 else list(range(9 + ((rpc_id - 9) // 4) * 4, 13 + ((rpc_id - 9) // 4) * 4))
            need(exact(row['client_pending_ids_at_write'], expected_pending)
                 and type(row['client_pending_count_at_write']) is int
                 and row['client_pending_count_at_write'] == len(expected_pending), 'exact original pending RPC set differs')
        waves = [row for row in report['waves'] if row['controller'] == index and row['status'] in ('succeeded', 'complete_with_failures')]
        need(len(waves) == (8 if index == 0 else 0), 'only eight baseline waves were actually executed')
        for wave_index, wave in enumerate(waves):
            wave_rows = [row for row in rows[3:] if row['wave'] == wave_index]
            need(wave['wave'] == wave_index and wave['controller'] == index
                 and exact(wave['slot_ids'], [row['slot'] for row in wave_rows])
                 and exact(wave['client_pending_ids_at_write'], [row['rpc_id'] for row in wave_rows])
                 and len(wave_rows) == wave['attempted'] == wave['concurrency'] == wave['client_pending_count_at_write']
                 and wave['successes'] == sum(row['okay'] is True for row in wave_rows)
                 and wave['failures'] == sum(row['okay'] is False for row in wave_rows)
                 and wave['all_original_wave_replies_received'] is True and wave['fatal'] is False
                 and wave['protocol_violations'] == [] and wave['terminal_transport_unknown_slot_ids'] == []
                 and wave['server_cohort_membership_observed'] is False, 'full original wave route/outcome ledger differs')
            need(len({row['start_monotonic_ns'] for row in wave_rows}) == 1
                 and wave['start_monotonic_ns'] <= min(row['start_monotonic_ns'] for row in wave_rows)
                 and wave['end_monotonic_ns'] >= max(row['response_received_monotonic_ns'] for row in wave_rows)
                 and wave['wall_seconds'] == (wave['end_monotonic_ns'] - wave['start_monotonic_ns']) / 1e9,
                 'original same-write wave timestamps differ')
            offsets = [id_requests[row['rpc_id'] - 1] for row in wave_rows]
            need(all(a['offset'] + a['bytes'] == b['offset'] for a, b in zip(offsets, offsets[1:])),
                 'original C4 one-write request packet is not contiguous')
        waited = shutdown['waited']
        pid = startup['pid']
        need(is_int(pid, 2) and pid not in all_pids and waited['pid'] == pid and waited['exit_code'] == 0
             and shutdown['original_child_reaped'] is True and shutdown['method'] == 'stdin_eof'
             and shutdown['errors'] == [] and shutdown['reader_error'] is None and shutdown['unmatched'] == []
             and shutdown['protocol_violations'] == [] and shutdown['raw_stdout_eof_captured'] is True
             and shutdown['reader_stop']['eof_observed'] is True
             and shutdown['reader_stop']['outstanding_original_rpc_ids'] == []
             and shutdown['received_response_ids'] == list(range(1, rpc_count + 1))
             and shutdown['first_termination_signal'] is None,
             'original wait4/EOF/complete response custody proof differs')
        all_pids.add(pid)
        need(controller['status'] == ('complete' if index == 0 else 'failed')
             and controller['errors'] == ([] if index == 0 else [{'where': 'controller', 'error': 'FatalExperiment: one fixed archive warmup failed; no readiness retry'}])
             and controller['original_fixture_unchanged'] is True
             and controller['release_sha256'] == ELFS[ORDER[index]]
             and startup['argv'] == [str(QUAL_DIRS[ORDER[index]] / 'hepta-runtime'), 'mcp', '--runtime-config',
                                     str(directory / 'runtime.json'), '--runtime-audit-group-commit']
             and exact(startup['environment'], {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'RUST_LOG': 'warn',
                                                'SHELL': '/bin/sh', 'TOKIO_WORKER_THREADS': '2'})
             and startup['only_owned_controller_started'] is True and startup['child_signal_mask_changed'] is False,
             'original qualified controller/no-SSH environment differs')
        idle = controller['fixed_idle']
        need(idle['planned_seconds'] == 60 and idle['elapsed_seconds'] >= 60
             and idle['polls'] == idle['queries_during_idle'] == 0, 'original 60-second unpolled idle differs')
        for name in (('process_before_c1', 'process_before_c4', 'process_after_c4_responses') if index == 0 else ()):
            point = controller[name]
            need(point['pid'] == pid and point['birth_ticks'] == startup['birth_ticks']
                 and point['cpu_ticks'] == point['utime_ticks'] + point['stime_ticks']
                 and point['cpu_seconds'] == point['cpu_ticks'] / point['cpu_tick_hz'], 'original CPU endpoint identity differs')
        summaries.append({'controller': index, 'arm': ORDER[index], 'rpc_requests': rpc_count, 'rpc_responses': rpc_count,
                          'initialized_notifications': 1, 'tool_journal_rows': rpc_count - 1,
                          'successful_tool_replies': successful, 'product_failure_replies': product_failed,
                          'actual_response_id_order': response_order, 'original_wait4': waited,
                          'original_stdout_eof_and_all_ids_accounted': True,
                          'wire_receipts': {name: controls.receipts[str(directory / name)] for name in ('requests.jsonl', 'responses.jsonl', 'stderr.log')}})
    need(exact(journal, expected_journal), 'all 26 actual original journal rows/order differ from raw replies/report')
    need(failed_slots == MEASURED_FAILURES and len(setup_failures) == 3
         and sum(row['successful_tool_replies'] for row in summaries) == 11
         and sum(row['product_failure_replies'] for row in summaries) == 15,
         'all measured/setup original failures must remain in complete accounting')
    return {'controllers': summaries, 'original_rpc_requests': 28, 'original_rpc_responses': 28,
            'initialized_notifications': 2, 'tool_journal_rows': 26, 'planned_measured_slots': 80, 'planned_measured_waves': 32,
            'measured_slots': 20, 'measured_waves': 8, 'measured_successes': 8, 'measured_product_failures': 12,
            'measured_unexecuted': 60, 'unexecuted_measured_slots': list(range(20, 80)),
            'measured_failure_slots': failed_slots, 'setup_product_failures': setup_failures,
            'candidate_product_failure_slots': [], 'candidate_measured_attempts': 0, 'client_pending_is_not_server_cohort_proof': True}


def verify_controls(capture, report_raw):
    controls, report = capture.controls, capture.report
    need(controls.raw(ROOT / 'report.json') == report_raw, 'retained raw report differs from actual input report')
    protocol_raw = controls.raw(ROOT / 'protocol.original.json')
    need(sha(protocol_raw) == PROTOCOL_SHA and protocol_raw == controls.raw(report['frozen_inputs'][0]['path'])
         and sha(controls.raw(ROOT / 'harness.original.py')) == DRIVER_SHA, 'original frozen producer/protocol copy differs')
    collection = controls.doc(COLLECTION_PROTOCOL)
    need(collection['schema'] == 'hepta-a54-large-partial-evidence-collection-protocol/v1'
         and exact(collection['original_control_members'], capture.required_originals)
         and exact(collection['optional_control_members'], optional_controls())
         and exact(collection['collector'], {'path': str(COLLECTOR), 'bytes': COLLECTOR_BYTES, 'sha256': COLLECTOR_SHA})
         and exact(collection['shared_small_evidence'], capture.header['shared_small_evidence']['receipt'])
         and collection['whole_operation_seconds'] == 600 and collection['fixture_record_bodies'] == 132096,
         'actual collector protocol source/member binding differs')
    for fixture in capture.fixtures:
        state = fixture.state
        expected = {'state_dir': str(state), 'controller_workspace_roots': [], 'hosts': {
            'fixture': {'ssh_target': 'unused.invalid', 'platform': 'linux', 'execution_mode': 'isolated',
                        'remote_state_dir': str(state / 'unused'), 'allow_execute': False, 'allow_pty': False,
                        'allow_write': False, 'allow_job_network': False, 'privileged_actions': {}}}}
        need(controls.raw(fixture.directory / 'runtime.json') == canonical(expected), 'closed no-effect runtime fixture config differs')
    qualifications = {}
    for arm, bundle in report['qualifications'].items():
        raw = controls.raw(bundle['report']['path'])
        need(raw == controls.raw(ROOT / (arm + '-qualification.original.json')) and sha(raw) == QUAL_SHAS[arm],
             'actual original qualified report/copy differs')
        qualification = document(raw)
        need(qualification['schema'] == 'runtime-candidate-qualification/v1' and qualification['qualified'] is True
             and qualification['source'] == str(SOURCE_DIRS[arm]) and qualification['service_changes'] is False
             and exact(qualification['source_tested'], bundle['source_map'])
             and exact(qualification['source_after'], bundle['source_map'])
             and [row['name'] for row in qualification['stages']] == list(STAGES)
             and all(type(row['returncode']) is int and row['returncode'] == 0 for row in qualification['stages']),
             'original six-stage actual qualification/source proof differs')
        original_match(capture.header['common_original_receipts_before'][bundle['binary']['path']], qualification['binary'])
        for stage in qualification['stages']:
            log = bundle['logs'][stage['name']]
            need(controls.receipts[log['path']]['sha256'] == stage['log_sha256'], 'all six original qualification logs differ')
        qualifications[arm] = {'qualification_sha256': sha(raw), 'source_files': SOURCE_COUNTS[arm],
                               'source_map_compact_sha256': SOURCE_MAPS[arm], 'release_sha256': ELFS[arm],
                               'all_six_original_logs_retained': True, 'test_elf_body_exported': False}
    return qualifications


def verify_capture_receipt(receipt, capture, archive_local):
    need(receipt['schema'] == 'hepta-a54-large-partial-original-evidence-capture-receipt/v1'
         and receipt['passed'] is True and receipt['capture_complete'] is True
         and receipt['output_directory_created'] is True and receipt['errors'] == []
         and receipt['whole_operation_budget_seconds'] == 600 and receipt['full_byte_final_fences_passed'] is True,
         'completed original collector receipt required')
    need(receipt['original_workload_complete'] is False, 'capture receipt cannot complete the original workload')
    receipt_check(receipt['output'], PACK / 'evidence.jsonl.gz', archive_local['bytes'], archive_local['sha256'], private=True)
    need(receipt['members'] == capture.files and receipt['record_members'] == capture.record_count == 132096
         and receipt['record_bytes'] == capture.record_bytes and receipt['total_captured_raw_bytes'] == capture.raw_bytes
         and receipt['jsonl_payload_bytes'] == capture.payload
         and exact(receipt['shared_small_evidence'], capture.header['shared_small_evidence']['receipt'])
         and receipt['common_source_bodies_referenced'] == 340 and receipt['common_release_bodies_referenced'] == 2,
         'collector final output/count ledger differs from entire decoded original stream')
    for name in ('original_performance_passed', 'independent_raw_audit_complete', 'performance_adopted', 'originals_modified'):
        need(receipt[name] is False, 'collector cannot change original performance/audit scope')
    need(type(receipt['business_or_child_executions']) is int and receipt['business_or_child_executions'] == 0
         and type(receipt['ssh_or_signals']) is int and receipt['ssh_or_signals'] == 0
         and receipt['started_unix_ns'] == capture.header['started_unix_ns']
         and receipt['finished_unix_ns'] >= capture.footer['finished_unix_ns']
         and type(receipt['elapsed_seconds']) is float and 0 < receipt['elapsed_seconds'] <= 600,
         'original zero-child collector action/timing ledger differs')


def collector_exit_admission(job_id, exit_code):
    need(job_id == COLLECTOR_JOB_ID and type(exit_code) is int and exit_code == 0,
         'operator-confirmed original collector job and authoritative exit zero required; unknown/nonzero refuses audit')
    return {'operator_job_id': job_id, 'authoritative_exit_code': exit_code,
            'source': 'Root operator supplies the observed completed original collector job result.',
            'independently_observed_by_this_offline_program': False}


def main():
    need(is_sha(COLLECTOR_SHA) and is_sha(COLLECTION_PROTOCOL_SHA)
         and is_int(COLLECTOR_BYTES, 1, MAX_LINE) and is_int(COLLECTION_PROTOCOL_BYTES, 1, MAX_LINE)
         and type(COLLECTOR_JOB_ID) is str and bool(COLLECTOR_JOB_ID),
         'actual completed partial collector bindings required before any evidence access')
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--archive-bytes', type=int, required=True)
    parser.add_argument('--capture-receipt', required=True)
    parser.add_argument('--capture-receipt-sha256', required=True)
    parser.add_argument('--collector-job-id', required=True)
    parser.add_argument('--collector-exit-code', type=int, required=True)
    parser.add_argument('--shared-small', required=True)
    parser.add_argument('--report', required=True)
    parser.add_argument('--field-audit', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    clock, capture, output = Deadline(), None, None
    result = {'schema': 'hepta-a54-large-partial-original-raw-audit/v1', 'passed': False,
              'independent_raw_audit_complete': False, 'original_performance_passed': False,
              'complete_original_workload': False, 'planned_measured_slots': 80, 'actual_measured_attempts': 20,
              'unexecuted_measured_slots': list(range(20, 80)), 'performance_adopted': False, 'errors': [], 'business_or_child_executions': 0,
              'ssh_agent_signals_or_original_mutations': 0, 'started_unix_ns': time.time_ns(),
              'offline_absolute_budget_seconds': AUDIT_BUDGET,
              'authoritative_collector_exit_zero_must_be_verified_by_operator': True,
              'authoritative_collector_exit_observed_by_this_offline_program': False,
              'scope': 'Every captured original record, wire and journal of both actually started controllers, complete partial-capture framing, original custody and full source/release bindings. The original 80-slot workload is incomplete and all sixteen gates fail; the exact partial arithmetic relies on the separately SHA-pinned 475-field audit.'}
    try:
        result['operator_collector_exit_declaration'] = collector_exit_admission(args.collector_job_id, args.collector_exit_code)
        need(is_sha(args.archive_sha256) and is_sha(args.capture_receipt_sha256)
             and is_int(args.archive_bytes, 1, MAX_PACK), 'actual completed archive/receipt pins required')
        with contextlib.ExitStack() as stack:
            inputs = {}
            def source(name, path, maximum, digest, size=None):
                value = LocalInput(path, clock, maximum, digest, size)
                stack.callback(value.close)
                inputs[name] = value
                return value
            report_input = source('report', args.report, REPORT_BYTES, REPORT_SHA, REPORT_BYTES)
            field_input = source('numeric_field_audit', args.field_audit, FIELD_AUDIT_BYTES, FIELD_AUDIT_SHA, FIELD_AUDIT_BYTES)
            report_raw, field_raw = report_input.raw(), field_input.raw()
            report, field_audit = document(report_raw), document(field_raw)
            fixed_report(report, field_audit)
            receipt_input = source('capture_receipt', args.capture_receipt, MAX_LINE, args.capture_receipt_sha256)
            receipt = document(receipt_input.raw())
            archive = source('large_archive', args.archive, MAX_PACK, args.archive_sha256, args.archive_bytes)
            shared = source('shared_small_archive', args.shared_small, 128 * 1024 * 1024, SMALL_SHA, SMALL_BYTES)
            target = Path(args.out)
            need(target.is_absolute() and target.parent.resolve(strict=True) == target.parent and not os.path.lexists(target),
                 'fresh direct absolute audit output required')
            target.mkdir(mode=0o700)
            need(stat.S_IMODE(target.lstat().st_mode) == 0o700, 'fresh audit directory must be private')
            output = target
            bodies = target / 'controls'
            bodies.mkdir(mode=0o700)
            capture = LargeCapture(report, bodies, clock)
            stack.callback(capture.close)
            capture.read(archive)
            verify_capture_receipt(receipt, capture, archive.receipt)
            qualifications = verify_controls(capture, report_raw)
            verify_original_directories(capture)
            shared_summary = verify_shared_small(shared, capture, clock)
            auxiliary = verify_auxiliary(capture)
            wire_summary = verify_rpc_and_journal(capture)
            for value in inputs.values():
                value.finish()
            result.update(passed=True, independent_raw_audit_complete=True,
                complete_stream_gzip_crc_and_unique_footer=True, all_inputs_full_byte_fenced=True,
                files=capture.files, original_record_files=capture.record_count, original_record_bytes=capture.record_bytes,
                all_captured_raw_bytes=capture.raw_bytes, jsonl_payload_bytes=capture.payload, jsonl_frames=capture.frames,
                stream_before_footer_sha256=capture.footer['frames_before_footer_sha256'],
                ordered_file_receipts_sha256=capture.footer['ordered_file_receipts_sha256'],
                original_control_receipts=capture.controls.receipts,
                inputs={name: value.receipt for name, value in inputs.items()},
                fixture_audits=[fixture.summary for fixture in capture.fixtures],
                native_result_auxiliary_audits=auxiliary, wire_journal_audit=wire_summary,
                actual_qualifications=qualifications, shared_source_release_audit=shared_summary,
                original_numeric_analysis=field_audit['analysis'],
                numeric_audit_dependency={'bytes': FIELD_AUDIT_BYTES, 'sha256': FIELD_AUDIT_SHA, 'checks': 475,
                                          'executed_or_rewritten_here': False},
                original_numeric_gates_passed=0, original_numeric_gates_total=16,
                failed_original_numeric_gates=list(field_audit['analysis']['numeric_gates']),
                original_measured_failures=MEASURED_FAILURES,
                seal_cache_digest_recomputed=False,
                original_directory_and_all_256_result_shards_per_controller_checked=True)
    except BaseException as error:
        result['passed'] = result['independent_raw_audit_complete'] = False
        result['errors'].append(type(error).__name__ + ': ' + str(error))
        if capture is not None:
            result['partial_audit_inventory'] = {'fully_closed_files': capture.files,
                'fully_consumed_original_record_bodies': capture.record_count, 'record_bytes': capture.record_bytes,
                'closed_control_files': len(capture.controls.receipts), 'footer_seen': capture.footer is not None,
                'complete_raw_audit_claimed': False}
    result['finished_unix_ns'] = time.time_ns()
    result['elapsed_seconds'] = time.monotonic() - clock.start
    if output is not None:
        try:
            create(output / 'audit.json', (json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n').encode())
        except BaseException as error:
            result['passed'] = result['independent_raw_audit_complete'] = False
            result['errors'].append('audit_write: ' + type(error).__name__ + ': ' + str(error))
    print(json.dumps({'passed': result['passed'], 'independent_raw_audit_complete': result['independent_raw_audit_complete'],
                      'performance_adopted': False, 'errors': result['errors'], 'elapsed_seconds': result['elapsed_seconds'],
                      'audit_path': str(output / 'audit.json') if output is not None else None}, sort_keys=True), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
