#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only capture of all existing originals from the incomplete A54 large attempt.

No benchmark import, subprocess, SSH, signal, retry, repair, or cache mutation.
Only a fresh, separate output directory is written. A collector success is not
a successful performance experiment or the subsequent independent raw audit.
"""
import argparse
import base64
import collections
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ROOT = BASE / 'a54-native-archive-cohort-r01'
OUT = BASE / 'a54-large-partial-original-evidence-r01'
SHARED_SMALL = BASE / 'a54-small-original-evidence-r01.jsonl.gz'
REMOTE_SCRIPT = BASE / 'tools/pack_a54_large_partial_original_evidence_r01.py'
REMOTE_MANIFEST = BASE / 'tools/a54-large-partial-evidence-collection-r01.protocol.json'
REPORT_SHA = '6cc6ba6c22db109ee10fe84a741ab88ebb2d39e53ce6233e60c70561e7a78c30'
PROTOCOL_SHA = '8f2dcc021dbfdb46317c9c28f1abd5d9b61ccb7a6601e9ae71a5d0e5946c0a3a'
HARNESS_SHA = '9f03083dcb6754952ea27ae531dd5f353119704257ffb56e43dcb180052eafc1'
COUNTS = {'A': 165, 'B': 175}
SOURCE_MAPS = {'A': '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d', 'B': '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'}
ELFS = {'A': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb', 'B': 'd2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70'}
SOURCE_DIRS = {'A': BASE / 'source-r07-recovery-only',
               'B': BASE / 'source-a54-compact-view-r01'}
QUAL_DIRS = {'A': BASE / 'qualification-r07-recovery-only',
             'B': BASE / 'qualification-a54-compact-view-r01'}
ORDER = ('A', 'B', 'B', 'A')
GROUPS = (('archive', 'request-archive-v11', 65536), ('hot', 'request-audit', 512))
CACHE = '.request-archive-index-v2.redb'
SEAL = '.request-archive-index-seal-v1.json'
MAX_PAYLOAD = 512 * 1024 * 1024
MAX_GZIP = MAX_PAYLOAD
MAX_RECORD_BYTES = 66854936
CHUNK = 48 * 1024  # Each base64 chunk is at most 65,536 bytes.
BUDGET_SECONDS = 600
HEX = re.compile(r'[0-9a-f]{64}\Z')
STAGES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')
SCHEMA = 'hepta-a54-large-partial-original-evidence-jsonl/v1'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def compact_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def stat8(identity):
    need(type(identity) is list and len(identity) == 9, 'stat9 required before stat8 projection')
    return identity[:4] + identity[5:]


def same_receipt(actual, expected, identity_format='stat9'):
    """Compare only original file fields, retaining the rich proof elsewhere."""
    need(identity_format in ('stat9', 'stat8_without_gid'), 'unknown receipt identity format')
    for key in ('path', 'bytes', 'sha256', 'identity'):
        if key in expected:
            value = actual[key]
            if key == 'identity' and identity_format == 'stat8_without_gid':
                value = stat8(value)
            need(value == expected[key], 'file receipt changed: ' + key + ' ' + actual['path'])


def relative(value):
    need(type(value) is str and value and '\\' not in value, 'invalid relative path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and all(p not in ('.', '..') for p in path.parts)
         and str(path) == value, 'noncanonical relative path')
    return path


def direct(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(BASE) and path.resolve(strict=True) == path,
         'input is not a direct fixed-BASE path: ' + str(path))
    return path


class Deadline:
    def __init__(self):
        self.begin = time.monotonic()
        self.end = self.begin + BUDGET_SECONDS

    def check(self):
        need(time.monotonic() < self.end, 'original 600-second collection deadline exceeded')


class Original:
    """One original descriptor; never follow a link or block opening a FIFO."""
    def __init__(self, path, clock, maximum, dir_fd=None, filename=None):
        clock.check()
        self.path, self.clock, self.maximum = Path(path), clock, maximum
        self.dir_fd, self.filename, self.fd = dir_fd, filename, None
        if dir_fd is None:
            direct(self.path)
            target = self.path
            self.before_path = self.path.lstat()
        else:
            need(type(filename) is str and '/' not in filename and filename not in ('', '.', '..'),
                 'single direct child name required')
            target = filename
            self.before_path = os.stat(filename, dir_fd=dir_fd, follow_symlinks=False)
        try:
            self.fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=dir_fd)
            self.first = os.fstat(self.fd)
            need(stat.S_ISREG(self.first.st_mode) and self.first.st_nlink == 1
                 and self.first.st_uid == 1000 and 0 <= self.first.st_size <= maximum
                 and stamp(self.first) == stamp(self.before_path),
                 'not an unchanged owned bounded regular single-link file: ' + str(self.path))
        except BaseException:
            if self.fd is not None:
                os.close(self.fd)
            raise
        self.count, self.digest = 0, hashlib.sha256()

    def read(self, limit=CHUNK):
        self.clock.check()
        remaining = min(limit, self.maximum + 1 - self.count)
        parts = []
        while remaining:
            self.clock.check()
            raw = os.read(self.fd, remaining)
            if not raw:
                break
            self.count += len(raw)
            need(self.count <= self.maximum, 'file exceeded bounded size: ' + str(self.path))
            self.digest.update(raw)
            parts.append(raw)
            remaining -= len(raw)
        return b''.join(parts)

    def finish(self, expected=None, identity_format='stat9'):
        self.clock.check()
        last = (self.path.lstat() if self.dir_fd is None else
                os.stat(self.filename, dir_fd=self.dir_fd, follow_symlinks=False))
        need(self.count == self.first.st_size and stamp(self.first) == stamp(os.fstat(self.fd)) == stamp(last),
             'original changed during complete descriptor read: ' + str(self.path))
        receipt = {'path': str(self.path), 'bytes': self.count,
                   'sha256': self.digest.hexdigest(), 'identity': stamp(self.first)}
        if expected is not None:
            same_receipt(receipt, expected, identity_format)
        return receipt

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        os.close(self.fd)


def checked(path, clock, expected=None, maximum=32 * 1024 * 1024, keep=False,
            identity_format='stat9', dir_fd=None, filename=None):
    parts = []
    with Original(path, clock, maximum, dir_fd, filename) as original:
        while True:
            raw = original.read()
            if not raw:
                break
            if keep:
                parts.append(raw)
        receipt = original.finish(expected, identity_format)
    return receipt, b''.join(parts) if keep else None


def report_contract(report):
    need(report['schema'] == 'hepta-a54-native-archive-cohort/v1' and report['complete'] is False
         and report['phase'] == 'failed' and report['passed'] is False
         and report['performance_adopted'] is False and report['errors'] == ['FatalExperiment: block failed; remaining block unexecuted']
         and report['observed_measured_write_attempts'] == 20 and report['observed_measured_successes'] == 8
         and report['unexecuted_measured_slots'] == list(range(20, 80)) and len(report['slots']) == 80
         and len(report['waves']) == 32 and len(report['controllers']) == 2,
         'the exact incomplete original failed A54 attempt is required')
    need(report['protocol']['sha256'] == PROTOCOL_SHA and len(report['frozen_inputs']) == 13,
         'original protocol/frozen inputs differ')
    for index, (arm, controller) in enumerate(zip(ORDER, report['controllers'])):
        directory = ROOT / ('controller-%d-%s' % (index, arm))
        need(controller['index'] == index and controller['arm'] == arm
             and controller['directory'] == str(directory) and controller['status'] == ('complete' if index == 0 else 'failed')
             and controller['errors'] == ([] if index == 0 else [{'where': 'controller', 'error': 'FatalExperiment: one fixed archive warmup failed; no readiness retry'}]) and controller['original_fixture_unchanged'] is True,
             'fixed actually started partial-attempt controller differs')
        shutdown = controller['shutdown']
        need(shutdown['original_child_reaped'] is True and shutdown['waited']['exit_code'] == 0
             and shutdown['waited']['pid'] == controller['startup']['pid']
             and shutdown['errors'] == [] and shutdown['reader_error'] is None
             and shutdown['unmatched'] == [] and shutdown['raw_stdout_eof_captured'] is True
             and shutdown['reader_stop']['eof_observed'] is True
             and shutdown['reader_stop']['outstanding_original_rpc_ids'] == []
             and sorted(shutdown['received_response_ids']) == list(range(1, 25 if index == 0 else 5)),
             'both actually started original controllers must already be reaped with complete wire')
        initial = controller['fixture_after_generation']
        for key in (('fixture_before_measurement', 'fixture_after_measurement', 'fixture_after_shutdown') if index == 0 else ('fixture_after_shutdown',)):
            need(all(controller[key][field] == initial[field] for field in
                     ('counts', 'owner_counts', 'directories', 'anchor', 'identity_map_sha256', 'content_map_sha256')),
                 'actually observed original fixture witnesses disagree')
        need(initial['counts'] == {'archive': 65536, 'hot': 512}
             and initial['full_map_file']['path'] == str(directory / 'fixture-original-map.jsonl')
             and initial['full_map_file']['sha256'] == initial['identity_map_sha256'],
             'fixed full original map required')
    need(report['planned_measured_calls'] == 80 and report['planned_waves'] == 32
         and [c['index'] for c in report['controllers']] == [0, 1]
         and [c['arm'] for c in report['controllers']] == ['A', 'B']
         and len(report['blocks']) == 1 and report['blocks'][0]['index'] == 0
         and report['blocks'][0]['controllers'] == [0, 1]
         and report['blocks'][0]['status'] == 'failed', 'exact original planned and actual partial inventory')
    need(sum(s['write_attempts'] for s in report['slots']) == 20
         and sum(s['okay'] for s in report['slots']) == 8
         and all(s['status'] == 'unexecuted' and s['write_attempts'] == 0 and s['okay'] is False
                 for s in report['slots'][20:])
         and len(report['analysis']['numeric_gates']) == 16
         and all(value is False for value in report['analysis']['numeric_gates'].values())
         and report['analysis']['candidate_performance_gates_passed'] is False,
         'all actual failures and sixty unexecuted slots remain failed')
    for index, controller in enumerate(report['controllers']):
        need([s['purpose'] for s in controller['setup']] == ['native_seed', 'index_kickoff', 'archive_warmup']
             and [s['okay'] for s in controller['setup']] == ([True, False, True] if index == 0 else [True, False, False])
             and all(s['write_attempts'] == 1 and s['response_received'] is True for s in controller['setup']),
             'actual once-only setup outcomes must remain unchanged')
        if index == 1:
            need(all(key not in controller for key in ('fixture_before_measurement', 'fixture_after_measurement',
                 'host_before_measured', 'host_before_measured_clear', 'process_before_c1', 'process_before_c4',
                 'process_after_c4_responses', 'c1_process_cpu', 'c4_inclusive_cpu',
                 'c4_response_window_process_cpu', 'all_measured_plus_tail_cpu')),
                 'failed candidate has no invented measured observations')
    for arm, bundle in report['qualifications'].items():
        need(arm in COUNTS and bundle['source_files'] == len(bundle['source_map']) == COUNTS[arm]
             and compact_sha(bundle['source_map']) == SOURCE_MAPS[arm]
             and bundle['source'] == str(SOURCE_DIRS[arm])
             and bundle['binary']['path'] == str(QUAL_DIRS[arm] / 'hepta-runtime')
             and bundle['binary']['sha256'] == ELFS[arm]
             and bundle['report']['path'] == str(QUAL_DIRS[arm] / 'report.json')
             and set(bundle['logs']) == set(STAGES), 'original qualified source/release binding differs')
    need(set(report['qualifications']) == set(COUNTS), 'exact two qualified arms required')


def specifications(report):
    """Only paths observed in the fixed producer and its exact actual report."""
    report_contract(report)
    members = {}

    def add(path, expected, category, maximum=32 * 1024 * 1024, identity_format='stat9'):
        path = Path(path)
        need(path.is_relative_to(BASE) and '..' not in path.parts and str(path) not in members,
             'duplicate or escaping fixed member')
        members[str(path)] = {'category': category, 'expected': expected,
                              'identity_format': identity_format, 'maximum': maximum}

    add(ROOT / 'report.json', {'bytes': 144184, 'sha256': REPORT_SHA}, 'actual-report')
    add(ROOT / 'calls.jsonl', report['calls_file'], 'original-journal', 16 * 1024 * 1024)
    copy_names = ('protocol.original.json', 'harness.original.py', 'small-helper.original.py',
                  'native-driver.original.py', 'qualification-chain-loader.original.py',
                  'qualification-entry.original.json', 'qualification-worker.original.json')
    need(report['frozen_inputs'][0]['sha256'] == PROTOCOL_SHA
         and report['frozen_inputs'][1]['sha256'] == HARNESS_SHA, 'producer input order differs')
    for copied, original in zip(copy_names, report['frozen_inputs'][:7]):
        add(ROOT / copied, {key: original[key] for key in ('bytes', 'sha256')}, 'original-input-copy')
    for original in report['frozen_inputs']:
        add(original['path'], original, 'original-frozen-input')
    for block in report['blocks']:
        for phase in ('before', 'after'):
            original = block['host_' + phase]
            path = ROOT / ('block-%d.host-%s.json' % (block['index'], phase))
            need(original['path'] == str(path), 'block gate path differs')
            add(path, original, 'original-host-gate')
    for arm, bundle in report['qualifications'].items():
        add(ROOT / (arm + '-qualification.original.json'),
            {key: bundle['report'][key] for key in ('bytes', 'sha256')}, 'original-qualification-copy')
        add(bundle['report']['path'], bundle['report'], 'original-qualification')
        for name in STAGES:
            row = bundle['logs'][name]
            need(row['path'] == str(QUAL_DIRS[arm] / (name + '.log')), 'original stage log path differs')
            add(row['path'], row, 'original-qualification-log')
    for controller in report['controllers']:
        directory = Path(controller['directory'])
        for name in ('requests.jsonl', 'responses.jsonl', 'stderr.log'):
            row = controller['shutdown']['files'][name]
            maximum = MAX_PAYLOAD if name == 'stderr.log' else 16 * 1024 * 1024
            add(directory / name, row, 'original-controller-wire', maximum, 'stat8_without_gid')
        for name in ('runtime.json', 'fixture-generation.json', 'independent-page-oracles.json'):
            add(directory / name, {}, 'original-fixture-control', 1024 * 1024)
        initial = controller['fixture_after_generation']
        add(directory / 'fixture-original-map.jsonl', initial['full_map_file'], 'original-fixture-map', 64 * 1024 * 1024)
        if controller['index'] == 0:
            add(directory / 'host-before-measured.json', controller['host_before_measured'], 'original-host-gate')
        add(directory / 'state/.request-archive-v11-anchor.json', initial['anchor'], 'original-anchor', 2048)
        # prepare_at/admit_synchronous_at in the actual A/B request_results
        # source create these exact originals for the one native host_list seed.
        # Synthetic archive records never create additional retained results.
        state = directory / 'state'
        seed_id = controller['fixture']['seed_id']
        add(state / 'request-results/.request-results-v2.json', {}, 'native-result-marker', 1024)
        add(state / '.request-results-v2-anchor.json', {}, 'native-result-anchor', 96 * 1024)
        add(state / 'request-results-v2/archive' / seed_id[:2] / (seed_id + '.json'),
            {}, 'native-seed-retained-result', 96 * 1024)
        # init_runtime opens this fresh file without writing, truncating or
        # unlinking it. It is an empty flock handle, not a process-ID document.
        add(state / 'controller.lock', {'bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()},
            'original-controller-lock', 0)
    need(len(members) == 65, 'fixed actual partial original control member count differs')
    return members


def optional_specifications(report):
    return {str(Path(controller['directory']) / 'state' / SEAL):
            {'category': 'disposable-index-seal', 'expected': {},
             'identity_format': 'stat9', 'maximum': 4096}
            for controller in report['controllers']}


def directory_snapshot(path, names, clock, private=True):
    """Bounded exact names; never open/read an unrecognized child."""
    clock.check()
    path = direct(path)
    first = path.lstat()
    need(stat.S_ISDIR(first.st_mode) and first.st_uid == 1000
         and (not private or stat.S_IMODE(first.st_mode) == 0o700), 'original directory owner/mode differs')
    observed = []
    with os.scandir(path) as entries:
        for entry in entries:
            observed.append(entry.name)
            need(len(observed) <= len(names), 'unexpected extra original directory member: ' + str(path))
    observed.sort()
    need(observed == sorted(names), 'unsupported/missing original directory member: ' + str(path))
    rows = []
    for name in observed:
        clock.check()
        info = (path / name).lstat()
        need(not stat.S_ISLNK(info.st_mode) and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
             'symlink/special original directory member')
        rows.append([name, stamp(info)])
    need(stamp(first) == stamp(path.lstat()), 'original directory changed during inventory')
    return {'path': str(path), 'identity': stamp(first), 'entries': rows}


def source_inventory(root, source_map, clock):
    expected = {str(relative(name)) for name in source_map}
    pending, directories, files = [root], {}, set()
    while pending:
        clock.check()
        path = direct(pending.pop())
        first = path.lstat()
        need(stat.S_ISDIR(first.st_mode) and first.st_uid == 1000, 'foreign qualified directory')
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                names.append(entry.name)
                need(len(names) <= len(expected) + 64, 'qualified directory too large')
        row = directory_snapshot(path, names, clock, private=False)
        for name, identity in row['entries']:
            child = path / name
            if stat.S_ISDIR(identity[2]):
                pending.append(child)
            else:
                need(identity[5] == 1 and identity[3] == 1000, 'foreign/hardlinked qualified source')
                files.add(str(child.relative_to(root)))
        directories[str(path.relative_to(root))] = row
        need(len(files) <= len(expected) and len(directories) + len(pending) <= 64,
             'qualified source inventory exceeds fixed map')
    need(files == expected, 'qualified source inventory is not the complete tested map')
    return directories


def expected_names(seed, group):
    numbers = range(1, 65536) if group == 'archive' else range(65025, 65536)
    values = [('%02x%062x.json' % (number % 256, number + 1)) for number in numbers]
    need(seed['seed_id'] + '.json' not in values, 'native seed collided with synthetic namespace')
    values.append(seed['seed_id'] + '.json')
    return sorted(values)


def namespace_open(path, expected, names, clock):
    clock.check()
    direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stamp(first) == expected['identity'] == stamp(path.lstat())
             and stat.S_ISDIR(first.st_mode) and first.st_uid == 1000
             and stat.S_IMODE(first.st_mode) == 0o700, 'original namespace identity differs')
        actual = []
        with os.scandir(fd) as entries:
            for entry in entries:
                actual.append(entry.name)
                need(len(actual) <= len(names), 'extra original namespace member')
        actual.sort()
        need(actual == names and stamp(first) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'original namespace names/identity differ')
        value = {'path': str(path), 'identity': stamp(first), 'count': len(actual),
                 'sorted_names_lf_sha256': hashlib.sha256(''.join(name + '\n' for name in actual).encode()).hexdigest(),
                 'complete_names_basis': 'complete original map plus fixed synthetic/native ID set'}
        return fd, value
    except BaseException:
        os.close(fd)
        raise


def map_rows(path, expected, clock):
    """Stream the exact retained map, with bounded lines and a full final hash."""
    with Original(path, clock, 64 * 1024 * 1024) as original:
        pending, count = b'', 0
        while True:
            part = original.read()
            pending += part
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                need(0 < len(line) <= 2048, 'invalid original map line size')
                value = document(line)
                need(type(value) is list and len(value) == 4 and canonical(value) == line + b'\n',
                     'noncanonical original map row')
                name, digest, size, identity = value
                relative(name)
                need(type(digest) is str and HEX.fullmatch(digest)
                     and type(size) is int and 0 < size <= 2048
                     and type(identity) is list and len(identity) == 9
                     and all(type(item) is int for item in identity)
                     and identity[6] == size and identity[3] == 1000 and identity[5] == 1
                     and stat.S_ISREG(identity[2]) and stat.S_IMODE(identity[2]) == 0o600,
                     'invalid original map receipt')
                count += 1
                need(count <= 66048, 'too many original map rows')
                yield value, line + b'\n'
            need(len(pending) <= 2048, 'unterminated original map line too large')
            if not part:
                break
        need(not pending and count == 66048, 'incomplete original map')
        original.finish(expected)


def file_frame(sequence, category, receipt, encoded=''):
    return {'type': 'file', 'sequence': sequence, 'category': category,
            'receipt': receipt, 'data_base64': encoded}


def planned_file_bytes(sequence, category, receipt):
    size = receipt['bytes']
    if size <= CHUNK:
        return len(canonical(file_frame(sequence, category, receipt))) + 4 * ((size + 2) // 3)
    total = len(canonical({'type': 'file-start', 'sequence': sequence, 'category': category, 'receipt': receipt}))
    chunks = (size + CHUNK - 1) // CHUNK
    for index in range(chunks):
        length = min(CHUNK, size - index * CHUNK)
        frame = {'type': 'file-chunk', 'sequence': sequence, 'index': index, 'offset': index * CHUNK,
                 'bytes': length, 'sha256': '0' * 64, 'data_base64': ''}
        total += len(canonical(frame)) + 4 * ((length + 2) // 3)
    return total + len(canonical({'type': 'file-end', 'sequence': sequence, 'chunks': chunks, 'receipt': receipt}))


class BoundedGzipTarget:
    def __init__(self, target, clock):
        self.target, self.clock, self.bytes = target, clock, 0

    def write(self, raw):
        self.clock.check()
        need(self.bytes + len(raw) <= MAX_GZIP, 'fixed gzip limit exceeded')
        count = self.target.write(raw)
        need(count == len(raw), 'partial gzip write')
        self.bytes += count
        return count

    def flush(self):
        self.target.flush()


class Frames:
    def __init__(self, stream, clock):
        self.stream, self.clock = stream, clock
        self.payload = self.frame_count = self.files = self.raw_bytes = 0
        self.digest, self.receipt_digest = hashlib.sha256(), hashlib.sha256()

    def write(self, value):
        self.clock.check()
        raw = canonical(value)
        need(self.payload + len(raw) <= MAX_PAYLOAD, 'fixed 512 MiB payload limit exceeded')
        need(self.stream.write(raw) == len(raw), 'partial payload write')
        self.payload += len(raw)
        self.frame_count += 1
        self.digest.update(raw)

    def capture(self, path, category, expected, maximum, dir_fd=None, filename=None):
        sequence = self.files + 1
        with Original(path, self.clock, maximum, dir_fd, filename) as original:
            need(stamp(original.first) == expected['identity'], 'file changed after preflight')
            if expected['bytes'] <= CHUNK:
                chunks = []
                while True:
                    part = original.read()
                    if not part:
                        break
                    chunks.append(part)
                receipt = original.finish(expected)
                self.write(file_frame(sequence, category, receipt, base64.b64encode(b''.join(chunks)).decode()))
            else:
                self.write({'type': 'file-start', 'sequence': sequence, 'category': category, 'receipt': expected})
                index, offset = 0, 0
                while True:
                    part = original.read()
                    if not part:
                        break
                    self.write({'type': 'file-chunk', 'sequence': sequence, 'index': index, 'offset': offset,
                                'bytes': len(part), 'sha256': hashlib.sha256(part).hexdigest(),
                                'data_base64': base64.b64encode(part).decode()})
                    index, offset = index + 1, offset + len(part)
                receipt = original.finish(expected)
                self.write({'type': 'file-end', 'sequence': sequence, 'chunks': index, 'receipt': receipt})
        self.files += 1
        self.raw_bytes += receipt['bytes']
        self.receipt_digest.update(canonical([sequence, category, receipt]))
        return receipt


def fixture_pass(controller, clock, stage, writer=None, start_sequence=0):
    """Preflight stats, capture full bodies, or rehash every original again."""
    directory = Path(controller['directory'])
    initial, seed = controller['fixture_after_generation'], controller['fixture']
    map_receipt = initial['full_map_file']
    identities, content = hashlib.sha256(), hashlib.sha256()
    body_count = body_bytes = estimated = 0
    namespaces, owners = {}, {'archive': collections.Counter(), 'hot': collections.Counter()}
    with contextlib.ExitStack() as stack:
        descriptors, sorted_names = {}, {}
        for group, child, count in GROUPS:
            names = expected_names(seed, group)
            need(len(names) == count, 'fixed namespace count differs')
            path = directory / 'state' / child
            fd, snapshot = namespace_open(path, initial['directories'][group], names, clock)
            stack.callback(os.close, fd)
            descriptors[group], sorted_names[group], namespaces[group] = fd, names, snapshot
        rows = stack.enter_context(contextlib.closing(map_rows(Path(map_receipt['path']), map_receipt, clock)))
        for index, (row, line) in enumerate(rows):
            group, child, offset = ('archive', 'request-archive-v11', index) if index < 65536 else ('hot', 'request-audit', index - 65536)
            name, digest, size, identity = row
            filename = sorted_names[group][offset]
            need(name == child + '/' + filename, 'initial map membership/order differs')
            path = directory / 'state' / name
            expected = {'path': str(path), 'bytes': size, 'sha256': digest, 'identity': identity}
            fd = descriptors[group]
            current = os.stat(filename, dir_fd=fd, follow_symlinks=False)
            need(stamp(current) == identity, 'original full stat9 differs from initial map')
            if stage == 'capture':
                writer.capture(path, 'original-fixture-record', expected, 2048, fd, filename)
            elif stage == 'final':
                checked(path, clock, expected, maximum=2048, dir_fd=fd, filename=filename)
            else:
                need(stage == 'preflight', 'invalid fixture pass')
                estimated += planned_file_bytes(start_sequence + index + 1, 'original-fixture-record', expected)
            identities.update(line)
            content.update(canonical(row[:3]))
            body_count += 1
            body_bytes += size
            request_id = filename[:-5]
            if request_id == seed['seed_id']:
                owner = seed['owners'][0]
            else:
                number = int(request_id[2:], 16) - 1
                need(1 <= number < 65536 and request_id == '%02x%062x' % (number % 256, number + 1),
                     'map contains an invalid synthetic identity')
                owner = seed['owners'][number % 4]
            owners[group][owner] += 1
        for group, child, count in GROUPS:
            fd, after = namespace_open(directory / 'state' / child, initial['directories'][group], sorted_names[group], clock)
            os.close(fd)
            need(after == namespaces[group], 'original namespace changed during fixture pass')
    need(body_count == 66048 and identities.hexdigest() == initial['identity_map_sha256']
         and content.hexdigest() == initial['content_map_sha256']
         and {key: dict(value) for key, value in owners.items()} == initial['owner_counts'],
         'full original map/content/count witnesses differ')
    return {'controller': controller['index'], 'record_count': body_count, 'record_bytes': body_bytes,
            'identity_map_sha256': identities.hexdigest(), 'content_map_sha256': content.hexdigest(),
            'namespaces': namespaces, 'expected_owner_counts_from_id_set': {k: dict(v) for k, v in owners.items()},
            'full_bodies_read': stage != 'preflight', 'estimated_payload_bytes': estimated if stage == 'preflight' else None}


def fixture_inventory(report, members, clock):
    root_names = {Path(path).name for path in members if Path(path).parent == ROOT}
    root_names.update('controller-%d-%s' % (c['index'], c['arm']) for c in report['controllers'])
    inventory = {'root': directory_snapshot(ROOT, root_names, clock), 'controllers': {},
                 'states': {}, 'auxiliary_directories': {}}
    caches = {}
    for controller in report['controllers']:
        path = Path(controller['directory'])
        names = {Path(name).name for name in members if Path(name).parent == path} | {'state'}
        inventory['controllers'][str(controller['index'])] = directory_snapshot(path, names, clock)
        state = path / 'state'
        # Only the source-observed redb cache is eligible for body omission.
        # Results/markers are retained original bodies, and the optional seal
        # is also small enough to capture. Archive v12 intent/anchor are refused.
        names = {'request-archive-v11', 'request-audit', '.request-archive-v11-anchor.json',
                 'request-results', 'request-results-v2', '.request-results-v2-anchor.json',
                 'controller.lock', 'jobs', 'audit'}
        if str(state / SEAL) in members:
            names.add(SEAL)
        if os.path.lexists(state / CACHE):
            names.add(CACHE)
            row, _ = checked(state / CACHE, clock, maximum=MAX_PAYLOAD)
            need(stat.S_IMODE(row['identity'][2]) == 0o600, 'disposable cache mode differs')
            caches[str(state / CACHE)] = row
        inventory['states'][str(controller['index'])] = directory_snapshot(state, names, clock)
        auxiliary = {}
        for name in ('jobs', 'audit'):
            auxiliary[name] = directory_snapshot(state / name, set(), clock)
        auxiliary['request-results'] = directory_snapshot(
            state / 'request-results', {'.request-results-v2.json'}, clock)
        auxiliary['request-results-v2'] = directory_snapshot(state / 'request-results-v2', {'archive'}, clock)
        archive = state / 'request-results-v2/archive'
        auxiliary['request-results-v2/archive'] = directory_snapshot(
            archive, {'%02x' % number for number in range(256)}, clock)
        seed_id = controller['fixture']['seed_id']
        for number in range(256):
            shard = '%02x' % number
            names = {seed_id + '.json'} if shard == seed_id[:2] else set()
            auxiliary['request-results-v2/archive/' + shard] = directory_snapshot(archive / shard, names, clock)
        inventory['auxiliary_directories'][str(controller['index'])] = auxiliary
    return inventory, caches


def common_inputs(report, clock):
    receipts, trees, test_stats = {}, {}, {}
    for arm, bundle in report['qualifications'].items():
        source = SOURCE_DIRS[arm]
        trees[arm] = source_inventory(source, bundle['source_map'], clock)
        for name, digest in sorted(bundle['source_map'].items()):
            path = source / relative(name)
            receipt, _ = checked(path, clock, {'sha256': digest})
            receipts[str(path)] = receipt
        receipt, _ = checked(bundle['binary']['path'], clock, bundle['binary'])
        receipts[receipt['path']] = receipt
        # The measured executable is the release ELF. The unexecuted test ELF
        # remains a qualification receipt; do not pretend its large body was
        # exported or reread in this capture.
        test = bundle['test_binary']
        path = direct(test['path'])
        info = path.lstat()
        need(stamp(info) == test['identity'] and stat.S_ISREG(info.st_mode)
             and info.st_uid == 1000 and info.st_nlink == 1, 'qualification test-ELF metadata changed')
        test_stats[arm] = {'path': str(path), 'identity': stamp(info), 'body_read': False}
    need(len(receipts) == 342, 'all 340 source and two release identities required')
    return receipts, trees, test_stats


def shared_common_bodies(receipt, common, clock):
    """Check the actual shared gzip framing and only its 342 shared bodies.

    The other small-run members still require the independent small raw audit.
    This does not copy any of the shared source or ELF bodies into the large pack.
    """
    seen, common_seen, receipts = set(), set(), {}
    first, footer, plain_bytes = None, None, 0
    with Original(SHARED_SMALL, clock, 128 * 1024 * 1024) as compressed:
        need(stamp(compressed.first) == receipt['identity'], 'shared small pack changed before structural check')
        with gzip.GzipFile(fileobj=compressed, mode='rb') as stream:
            while True:
                clock.check()
                raw = stream.readline(64 * 1024 * 1024 + 1)
                if not raw:
                    break
                plain_bytes += len(raw)
                need(raw.endswith(b'\n') and len(raw) <= 64 * 1024 * 1024 and plain_bytes <= MAX_PAYLOAD,
                     'shared small gzip framing/expanded budget refused')
                value = document(raw)
                need(footer is None, 'shared small has bytes after its complete footer')
                if first is None:
                    first = value
                    need(first['type'] == 'header' and first['schema'] == 'hepta-a54-small-original-evidence-jsonl/v1'
                         and first['member_count'] == 2023 and len(first['specifications']) == 2023
                         and first['source_counts'] == {'r07': 165, 'A54': 175}
                         and first['source_map_compact_sha256'] == {'r07': SOURCE_MAPS['A'], 'A54': SOURCE_MAPS['B']}
                         and first['release_sha256'] == {'r07': ELFS['A'], 'A54': ELFS['B']},
                         'shared small complete-source header differs')
                elif value['type'] == 'file':
                    path = value['path']
                    need(path in first['specifications'] and path not in seen
                         and value['receipt']['path'] == path, 'shared small file membership differs')
                    seen.add(path)
                    receipts[path] = value['receipt']
                    if path in common:
                        same_receipt(value['receipt'], common[path])
                        body = base64.b64decode(value['data_base64'], validate=True)
                        need(len(body) == common[path]['bytes']
                             and hashlib.sha256(body).hexdigest() == common[path]['sha256'],
                             'shared common source/release body differs from current qualified original')
                        common_seen.add(path)
                        del body
                else:
                    need(value['type'] == 'footer' and value['capture_complete'] is True
                         and value['member_count'] == len(seen) == 2023
                         and value['all_full_byte_receipts_rechecked'] is True
                         and value['source_bodies_captured'] == 340 and value['release_elf_bodies_captured'] == 2
                         and value['block_directory_before'] == value['block_directory_after']
                         and value['source_directory_before'] == value['source_directory_after']
                         and value['receipts_compact_sha256'] == compact_sha(receipts),
                         'shared small final complete footer differs')
                    footer = value
        compressed.finish(receipt)
    need(footer is not None and seen == set(first['specifications']) and common_seen == set(common),
         'shared evidence is missing its footer or original source/release bodies')
    return {'gzip_crc_and_final_footer_verified': True, 'shared_member_frames': len(seen),
            'common_full_body_sha_and_identity_checked': len(common_seen),
            'all_other_small_body_semantics_audited_here': False,
            'independent_small_wire_fixture_audit_still_required': True}


def validate_fixture_controls(report, raw_controls):
    for controller in report['controllers']:
        directory = Path(controller['directory'])
        state = directory / 'state'
        expected = {'state_dir': str(state), 'controller_workspace_roots': [], 'hosts': {
            'fixture': {'ssh_target': 'unused.invalid', 'platform': 'linux', 'execution_mode': 'isolated',
                        'remote_state_dir': str(state / 'unused'), 'allow_execute': False, 'allow_pty': False,
                        'allow_write': False, 'allow_job_network': False, 'privileged_actions': {}}}}
        need(raw_controls[str(directory / 'runtime.json')] == canonical(expected), 'fixture-only config differs')
        need(raw_controls[str(directory / 'fixture-generation.json')] == canonical(controller['fixture']),
             'original generation document differs from final report')
        oracles = document(raw_controls[str(directory / 'independent-page-oracles.json')])
        need(type(oracles) is list and len(oracles) == 4, 'all four saved page oracles required')


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        need(stream.write(raw) == len(raw), 'partial fresh output write')
        stream.flush()
        os.fsync(stream.fileno())


def run(args, clock, status):
    need(os.getuid() == os.geteuid() == 1000 and sys.platform == 'linux', 'actual X230 UID 1000 Linux required')
    need(Path(__file__).resolve(strict=True) == REMOTE_SCRIPT and Path(args.manifest) == REMOTE_MANIFEST,
         'fixed collector/manifest execution paths required')
    for digest in (args.manifest_sha256, args.shared_small_sha256):
        need(HEX.fullmatch(digest), 'actual SHA256 CLI pin required')
    need(0 < args.shared_small_bytes <= 128 * 1024 * 1024, 'actual shared-small receipt size required')
    manifest_receipt, raw = checked(REMOTE_MANIFEST, clock, {'sha256': args.manifest_sha256}, keep=True)
    manifest = document(raw)
    need(manifest['schema'] == 'hepta-a54-large-partial-evidence-collection-protocol/v1'
         and manifest['report_sha256'] == REPORT_SHA and manifest['performance_adopted'] is False
         and manifest['output'] == str(OUT) and manifest['whole_operation_seconds'] == BUDGET_SECONDS,
         'fixed collection protocol differs')
    shared_pin = manifest['shared_small_evidence']
    need(shared_pin['path'] == str(SHARED_SMALL) and shared_pin['sha256'] == args.shared_small_sha256
         and shared_pin['bytes'] == args.shared_small_bytes, 'actual shared-small CLI/protocol binding differs')
    script_receipt, _ = checked(REMOTE_SCRIPT, clock, manifest['collector'])
    report_receipt, report_raw = checked(ROOT / 'report.json', clock, {'bytes': 144184, 'sha256': REPORT_SHA}, keep=True)
    report = document(report_raw)
    members = specifications(report)
    need(members == manifest['original_control_members'], 'prepared original member allowlist differs')
    optional = optional_specifications(report)
    need(optional == manifest['optional_control_members'], 'optional seal allowlist differs')
    absent_optional = []
    for path, spec in sorted(optional.items()):
        if os.path.lexists(path):
            members[path] = spec
        else:
            absent_optional.append(path)
    members[str(REMOTE_SCRIPT)] = {'category': 'collector-source', 'expected': script_receipt,
                                  'identity_format': 'stat9', 'maximum': 1024 * 1024}
    members[str(REMOTE_MANIFEST)] = {'category': 'collector-protocol', 'expected': manifest_receipt,
                                    'identity_format': 'stat9', 'maximum': 1024 * 1024}
    need(len(members) == 69 - len(absent_optional),
         'fixed 65 actual originals, two optional seals, and two collector controls required')
    direct(OUT.parent)
    need(not os.path.lexists(OUT), 'fresh capture output directory already exists')
    OUT.mkdir(mode=0o700)
    status['output_directory_created'] = True
    need(stat.S_IMODE(OUT.lstat().st_mode) == 0o700, 'fresh output directory must be private')
    shared, _ = checked(SHARED_SMALL, clock, {'bytes': args.shared_small_bytes,
                                           'sha256': args.shared_small_sha256}, maximum=128 * 1024 * 1024)
    controls, raw_controls = {}, {}
    estimated, sequence = 8 * 1024 * 1024, 0  # Fixed proof/footer budget, never an extra payload allowance.
    for path, spec in sorted(members.items()):
        keep = spec['category'] == 'original-fixture-control'
        receipt, raw = checked(path, clock, spec['expected'], spec['maximum'], keep, spec['identity_format'])
        if Path(path).is_relative_to(ROOT) or spec['category'] in ('native-result-marker', 'native-result-anchor',
                                 'native-seed-retained-result', 'disposable-index-seal'):
            need(stat.S_IMODE(receipt['identity'][2]) == 0o600, 'private original control/result/seal mode differs')
        controls[path] = receipt
        if keep:
            raw_controls[path] = raw
        sequence += 1
        estimated += planned_file_bytes(sequence, spec['category'], receipt)
    validate_fixture_controls(report, raw_controls)
    original_inventory, caches = fixture_inventory(report, members, clock)
    common, source_trees, test_stats = common_inputs(report, clock)
    shared_verification = shared_common_bodies(shared, common, clock)
    initial = []
    for controller in report['controllers']:
        proof = fixture_pass(controller, clock, 'preflight', start_sequence=sequence)
        sequence += proof['record_count']
        estimated += proof['estimated_payload_bytes']
        initial.append(proof)
    record_bytes = sum(row['record_bytes'] for row in initial)
    need(sequence == 132096 + len(members) and record_bytes <= MAX_RECORD_BYTES and estimated <= MAX_PAYLOAD,
         'complete original inventory exceeds fixed count/body/payload budget')
    header = {'type': 'header', 'schema': SCHEMA, 'base': str(BASE), 'experiment': str(ROOT),
              'report_receipt': report_receipt, 'collector_receipt': script_receipt,
              'collection_protocol_receipt': manifest_receipt, 'original_performance_passed': False,
              'original_workload_complete': False, 'planned_measured_calls': 80,
              'observed_measured_write_attempts': 20, 'observed_measured_successes': 8,
              'unexecuted_measured_slots': list(range(20, 80)),
              'independent_raw_audit_complete': False, 'performance_adopted': False,
              'expected_members': sequence, 'expected_record_members': 132096,
              'absent_optional_index_seals': absent_optional,
              'original_control_members': members, 'control_receipts_before': controls,
              'shared_small_evidence': {'receipt': shared, 'body_read_here': True,
                  'common_source_release_body_verification': shared_verification,
                  'required_by_independent_auditor': True, 'referenced_source_bodies': 340,
                  'referenced_release_elf_bodies': 2, 'source_map_compact_sha256': SOURCE_MAPS, 'release_sha256': ELFS},
              'common_original_receipts_before': common, 'source_directory_before': source_trees,
              'unexecuted_test_elf_stat_only_before': test_stats,
              'original_directory_before': original_inventory, 'fixture_preflight': initial,
              'cache_receipts_before': caches, 'cache_bodies_intentionally_omitted': list(caches),
              'limits': {'max_payload_bytes': MAX_PAYLOAD, 'max_gzip_bytes': MAX_GZIP,
                         'max_record_bytes': MAX_RECORD_BYTES, 'chunk_bytes': CHUNK,
                         'whole_operation_seconds': BUDGET_SECONDS},
              'admitted_payload_upper_estimate_bytes': estimated, 'started_unix_ns': status['started_unix_ns']}
    need(len(canonical(header)) <= 2 * 1024 * 1024, 'capture proof header exceeds fixed reserved budget')
    output = OUT / 'evidence.jsonl.gz'
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as target:
        with gzip.GzipFile(fileobj=BoundedGzipTarget(target, clock), mode='wb', filename='', mtime=0,
                           compresslevel=1) as compressed:
            frames = Frames(compressed, clock)
            frames.write(header)
            for path, spec in sorted(members.items()):
                frames.capture(path, spec['category'], controls[path], spec['maximum'])
            captured = []
            for controller in report['controllers']:
                print(json.dumps({'phase': 'capture-original-records', 'controller': controller['index']}), flush=True)
                captured.append(fixture_pass(controller, clock, 'capture', writer=frames))
            need(frames.files == sequence and sum(row['record_bytes'] for row in captured) == record_bytes,
                 'incomplete original body capture')
            final = []
            for controller in report['controllers']:
                print(json.dumps({'phase': 'full-byte-final-fence', 'controller': controller['index']}), flush=True)
                final.append(fixture_pass(controller, clock, 'final'))
            need(final == captured, 'second full original body read differs')
            for path, spec in sorted(members.items()):
                checked(path, clock, controls[path], spec['maximum'])
            common_after, source_after, test_after = common_inputs(report, clock)
            need(common_after == common and source_after == source_trees and test_after == test_stats,
                 'qualified source/release full-byte or directory fence changed')
            inventory_after, caches_after = fixture_inventory(report, members, clock)
            need(inventory_after == original_inventory and caches_after == caches,
                 'original directory/cache receipt changed')
            checked(SHARED_SMALL, clock, shared, maximum=128 * 1024 * 1024)
            # A complete footer exists only after every original body, source,
            # release, map, control, directory, known cache, and shared pack fence.
            footer = {'type': 'footer', 'capture_complete': True, 'member_count': frames.files,
                      'record_member_count': 132096, 'record_bytes': record_bytes,
                      'total_captured_raw_bytes': frames.raw_bytes,
                      'payload_bytes_before_footer': frames.payload, 'frames_before_footer': frames.frame_count,
                      'frames_before_footer_sha256': frames.digest.hexdigest(),
                      'ordered_file_receipts_sha256': frames.receipt_digest.hexdigest(),
                      'all_collected_bodies_full_byte_reread': True, 'fixture_capture_and_final_fence': final,
                      'control_receipts_final_equal_before': True,
                      'common_original_receipts_final_equal_before': True,
                      'source_directory_final_equal_before': True,
                      'original_directory_final_equal_before': True, 'cache_full_byte_final_equal_before': True,
                      'shared_small_full_byte_final_equal_before': True,
                      'original_workload_complete': False,
                      'original_performance_passed': False, 'independent_raw_audit_complete': False,
                      'performance_adopted': False, 'business_or_child_executions': 0, 'ssh_or_signals': 0,
                      'originals_modified': False, 'finished_unix_ns': time.time_ns()}
            need(len(canonical(footer)) <= 2 * 1024 * 1024, 'capture footer exceeds fixed reserved budget')
            frames.write(footer)
        target.flush()
        os.fsync(target.fileno())
    receipt, _ = checked(output, clock, maximum=MAX_GZIP)
    status.update(passed=True, capture_complete=True, output=receipt, members=frames.files,
                  record_members=132096, record_bytes=record_bytes,
                  total_captured_raw_bytes=frames.raw_bytes, jsonl_payload_bytes=frames.payload,
                  original_performance_passed=False, independent_raw_audit_complete=False,
                  performance_adopted=False, shared_small_evidence=shared,
                  common_source_bodies_referenced=340, common_release_bodies_referenced=2,
                  full_byte_final_fences_passed=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--shared-small-sha256', required=True)
    parser.add_argument('--shared-small-bytes', required=True, type=int)
    args = parser.parse_args()
    clock = Deadline()
    status = {'schema': 'hepta-a54-large-partial-original-evidence-capture-receipt/v1', 'passed': False,
              'capture_complete': False, 'output_directory_created': False, 'errors': [],
              'started_unix_ns': time.time_ns(), 'whole_operation_budget_seconds': BUDGET_SECONDS,
              'originals_modified': False, 'business_or_child_executions': 0, 'ssh_or_signals': 0,
              'original_workload_complete': False,
              'original_performance_passed': False, 'independent_raw_audit_complete': False,
              'performance_adopted': False}
    try:
        run(args, clock, status)
    except BaseException as error:
        status['passed'] = status['capture_complete'] = False
        status['errors'].append(type(error).__name__ + ': ' + str(error))
        if status['output_directory_created']:
            path = OUT / 'evidence.jsonl.gz'
            try:
                status['partial_output'] = {'path': str(path), 'exists': os.path.lexists(path),
                    'bytes': path.lstat().st_size if os.path.lexists(path) else 0,
                    'complete_footer_and_authoritative_exit_zero_required': True}
            except BaseException as observation:
                status['errors'].append('partial_observation: ' + type(observation).__name__ + ': ' + str(observation))
    status['finished_unix_ns'] = time.time_ns()
    status['elapsed_seconds'] = time.monotonic() - clock.begin
    if status['output_directory_created']:
        try:
            create(OUT / 'receipt.json', canonical(status))
            fd = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except BaseException as error:
            status['passed'] = status['capture_complete'] = False
            status['errors'].append('final_receipt: ' + type(error).__name__ + ': ' + str(error))
    print(json.dumps(status, sort_keys=True), flush=True)
    return 0 if status['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
