#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Capture only the actual A53 small experiment and its fixed source/ELF inputs.

No subprocess, SSH, signal, benchmark or runtime execution. The sole write is a
new O_EXCL gzip evidence stream outside both original block directories. A
partial stream has no complete footer and cannot pass the offline auditor.
"""
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
ROOT = BASE / 'a53-small-archive-comparison-r01'
ANALYSIS = BASE / 'a53-small-archive-analysis-r01.json'
OUTPUT = BASE / 'a53-small-original-evidence-r01.jsonl.gz'
REPORT_SHA = '7484d98191b7c8be3cd39f7d65e5c42840dbe5be3892aeb8799206da4f16824d'
ANALYSIS_SHA = '12c534872769e6cc81715db4c3a58080b60065defdaebfac8147b8b75488920e'
PROTOCOL_SHA = 'f36f7f9f2deed6e9e9d1e94cbafc7369d3291828d8fc022bf289dba28654760d'
BLOCKS = ('block-0-r07-A53', 'block-1-A53-r07')
COUNTS = {'r07': 165, 'A53': 175}
MAPS = {'r07': '4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d',
        'A53': '91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35'}
ELFS = {'r07': '7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb',
        'A53': '5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6'}
MAX_FILE = 32 * 1024 * 1024
MAX_RAW = 256 * 1024 * 1024
MAX_GZIP = 128 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def compact_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def document(raw):
    def pairs(items):
        answer = {}
        for key, value in items:
            need(key not in answer, 'duplicate JSON key')
            answer[key] = value
        return answer
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def identity(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def direct(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(BASE) and path.resolve(strict=True) == path,
         'input outside direct fixed BASE: ' + str(path))
    return path


def checked(path, expected=None, body=True, maximum=MAX_FILE):
    path = direct(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        first = os.fstat(fd)
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_uid == os.getuid()
             and 0 <= first.st_size <= maximum, 'not owned bounded single-link file: ' + str(path))
        parts, count, digest = [], 0, hashlib.sha256()
        while True:
            part = os.read(fd, 1024 * 1024)
            if not part:
                break
            count += len(part)
            need(count <= maximum, 'file grew above bound')
            digest.update(part)
            if body:
                parts.append(part)
        need(count == first.st_size and identity(first) == identity(os.fstat(fd)) == identity(path.lstat()),
             'file changed during read: ' + str(path))
        receipt = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(), 'identity': identity(first)}
        if expected is not None:
            # Compiler receipts carry extra proof fields; compare the original
            # four file identity fields without discarding the rich originals.
            for key in ('path', 'bytes', 'sha256', 'identity'):
                if key in expected:
                    need(receipt[key] == expected[key], 'original receipt mismatch: ' + key + ' ' + str(path))
        return receipt, b''.join(parts) if body else None
    finally:
        os.close(fd)


def safe_relative(value):
    need(type(value) is str and value and '\\' not in value, 'bad member name')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and '.' not in path.parts
         and str(path) == value, 'noncanonical member name')
    return path


def inventory(root, expected_files):
    """Read one fixed manifest tree; preserve even empty directories."""
    pending, directories, files = [root], {}, set()
    while pending:
        parent = direct(pending.pop())
        before = parent.lstat()
        need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid(), 'foreign/non-directory block entry')
        entries = sorted(os.scandir(parent), key=lambda entry: entry.name)
        rows = []
        for entry in entries:
            current = entry.stat(follow_symlinks=False)
            relative = str(Path(entry.path).relative_to(root))
            need(not stat.S_ISLNK(current.st_mode), 'symlink in original block')
            if stat.S_ISDIR(current.st_mode):
                pending.append(Path(entry.path))
                kind = 'directory'
            else:
                need(stat.S_ISREG(current.st_mode) and current.st_nlink == 1, 'special block entry')
                files.add(relative)
                kind = 'file'
            rows.append({'name': entry.name, 'kind': kind, 'identity': identity(current)})
        need(identity(before) == identity(parent.lstat()), 'directory changed during inventory')
        directories[str(parent.relative_to(root))] = {'identity': identity(before), 'entries': rows}
        need(len(directories) + len(pending) <= 8192 and len(files) <= len(expected_files), 'original inventory exceeds fixed bound')
    need(files == set(expected_files), 'original file inventory differs')
    return directories


class BoundedOutput:
    def __init__(self, target):
        self.target = target
        self.bytes = 0

    def write(self, data):
        need(self.bytes + len(data) <= MAX_GZIP, 'gzip byte limit exceeded')
        count = self.target.write(data)
        need(count == len(data), 'partial gzip write')
        self.bytes += count
        return count

    def flush(self):
        self.target.flush()


def main():
    started = time.time_ns()
    report_receipt, report_raw = checked(ROOT / 'report.json', {'bytes': 134076, 'sha256': REPORT_SHA})
    analysis_receipt, analysis_raw = checked(ANALYSIS, {'bytes': 22085, 'sha256': ANALYSIS_SHA})
    report, analysis = document(report_raw), document(analysis_raw)
    need(report['passed'] is True and report['complete'] is True and report['phase'] == 'complete'
         and report['new_measured_calls'] == 8192 and report['new_total_tool_calls'] == 8848,
         'exact complete actual small experiment required')
    need(analysis['original_report_pin'] == REPORT_SHA and analysis['original_protocol_pin'] == PROTOCOL_SHA
         and analysis['passed'] is True and analysis['report_evaluation_complete'] is True,
         'actual completed numeric evaluation required')
    specs = {}

    def add(path, expected, category):
        path = Path(path)
        need(path.is_absolute() and path.is_relative_to(BASE) and str(path) == str(BASE / safe_relative(str(path.relative_to(BASE)))), 'fixed base member required')
        need(type(expected.get('sha256')) is str and HEX.fullmatch(expected['sha256']), 'member SHA missing')
        row = {'category': category, 'expected': {key: expected[key] for key in ('path', 'bytes', 'sha256', 'identity') if key in expected}}
        if str(path) in specs:
            prior = specs[str(path)]
            need(all(prior['expected'].get(key, value) == value for key, value in row['expected'].items()), 'conflicting duplicate original receipt')
            prior['expected'].update(row['expected'])
            return
        specs[str(path)] = row

    need(len(analysis['input_receipts']) == 21, 'exact original numeric input inventory required')
    for row in analysis['input_receipts']:
        need(Path(row['path']).is_relative_to(ROOT), 'numeric input escapes original experiment')
        add(row['path'], row, 'numeric-input')
    add(ANALYSIS, analysis_receipt, 'original-analysis')
    manifests, directory_before = {}, {}
    for index, stage in enumerate(report['stages']):
        need(index < 2 and stage['name'] == BLOCKS[index] and stage['output'] == str(ROOT / BLOCKS[index])
             and stage['original_artifact_count'] == 827, 'fixed complete block inventory required')
        expected = stage['original_artifacts_manifest']
        need(expected['path'] == str(ROOT / (stage['name'] + '.artifacts.json')), 'manifest path mismatch')
        _, raw = checked(expected['path'], expected)
        members = document(raw)
        need(type(members) is dict and len(members) == 827, 'manifest must contain all 827 original files')
        manifests[stage['name']] = members
        add(expected['path'], expected, 'original-artifact-manifest')
        for relative, row in members.items():
            path = ROOT / stage['name'] / safe_relative(relative)
            need(row['path'] == str(path), 'original member path mismatch')
            add(path, row, 'block-artifact')
        for key in ('stdout', 'stderr'):
            row = stage[key]
            need(row['path'] == str(ROOT / (stage['name'] + '.' + key)), 'block output path mismatch')
            add(row['path'], row, 'block-' + key)
        directory_before[stage['name']] = inventory(ROOT / stage['name'], members)
    need(len(manifests) == 2 and len(specs) == 1678, 'complete fixed small original inventory count differs')
    for key, name in [('driver', 'native-driver.original.py'), ('helper', 'small-helper.original.py'),
                      ('confirmation_driver', 'confirmation-driver.original.py')]:
        expected = {field: report[key][field] for field in ('bytes', 'sha256')}
        add(ROOT / name, expected, 'original-producer')
    source_directory_before = {}
    for arm in ('r07', 'A53'):
        bundle = report['qualifications'][arm]
        need(len(bundle['source_map']) == bundle['source_files'] == COUNTS[arm]
             and bundle['source_map'] == report['final_source_maps'][arm]
             and compact_sha(bundle['source_map']) == MAPS[arm] and bundle['binary']['sha256'] == ELFS[arm],
             'fixed actual qualified inputs differ: ' + arm)
        source = Path(bundle['source'])
        need(source.is_relative_to(BASE) and source != ROOT and not ROOT.is_relative_to(source), 'source path overlaps experiment')
        for relative, sha in bundle['source_map'].items():
            add(source / safe_relative(relative), {'sha256': sha}, 'qualified-source-' + arm)
        add(bundle['binary']['path'], bundle['binary'], 'qualified-release-' + arm)
        source_directory_before[arm] = inventory(source, bundle['source_map'])
    need(len(specs) == 2023, 'all 2023 original/source/ELF members required')
    header = {'type': 'header', 'schema': 'hepta-a53-small-original-evidence-jsonl/v1',
              'base': str(BASE), 'experiment': str(ROOT), 'report_sha256': REPORT_SHA,
              'analysis_sha256': ANALYSIS_SHA, 'protocol_sha256': PROTOCOL_SHA,
              'member_count': len(specs), 'source_counts': COUNTS, 'source_map_compact_sha256': MAPS,
              'release_sha256': ELFS, 'specifications': specs,
              'limits': {'max_file_bytes': MAX_FILE, 'max_total_raw_bytes': MAX_RAW, 'max_gzip_bytes': MAX_GZIP},
              'capture_scope': 'All two fixed block artifact manifests, original companions, complete qualified source and release ELF bodies; no process execution.',
              'started_unix_ns': started}
    need(OUTPUT.parent.resolve(strict=True) == OUTPUT.parent and not OUTPUT.is_relative_to(ROOT), 'direct separate output required')
    fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    receipts, total = {}, 0
    with os.fdopen(fd, 'wb') as target:
        with gzip.GzipFile(fileobj=BoundedOutput(target), mode='wb', filename='', mtime=0) as stream:
            stream.write(canonical(header))
            for path, spec in sorted(specs.items()):
                receipt, raw = checked(path, spec['expected'])
                total += len(raw)
                need(total <= MAX_RAW, 'complete capture raw byte bound exceeded')
                receipts[path] = receipt
                stream.write(canonical({'type': 'file', 'path': path, 'category': spec['category'],
                                        'receipt': receipt, 'data_base64': base64.b64encode(raw).decode()}))
            # Full-byte final fence, not just a second stat or repeated claim.
            for path, receipt in receipts.items():
                checked(path, receipt, body=False)
            directory_after = {name: inventory(ROOT / name, members) for name, members in manifests.items()}
            need(directory_after == directory_before, 'fixed original block directories changed')
            source_directory_after = {arm: inventory(Path(bundle['source']), bundle['source_map'])
                                      for arm, bundle in report['qualifications'].items()}
            need(source_directory_after == source_directory_before, 'fixed qualified source directories changed')
            checked(ROOT / 'report.json', report_receipt, body=False)
            checked(ANALYSIS, analysis_receipt, body=False)
            footer = {'type': 'footer', 'capture_complete': True, 'member_count': len(receipts),
                      'total_raw_bytes': total, 'receipts_compact_sha256': compact_sha(receipts),
                      'all_full_byte_receipts_rechecked': True, 'block_directory_before': directory_before,
                      'block_directory_after': directory_after,
                      'source_directory_before': source_directory_before,
                      'source_directory_after': source_directory_after,
                      'source_bodies_captured': 340, 'release_elf_bodies_captured': 2,
                      'business_or_child_executions': 0, 'ssh_or_signals': 0,
                      'originals_modified': False, 'finished_unix_ns': time.time_ns()}
            stream.write(canonical(footer))
        target.flush()
        os.fsync(target.fileno())
    receipt, _ = checked(OUTPUT, body=False, maximum=MAX_GZIP)
    print(json.dumps({'passed': True, 'output': receipt, 'members': len(receipts),
                      'total_raw_bytes': total, 'originals_modified': False,
                      'business_or_child_executions': 0}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
