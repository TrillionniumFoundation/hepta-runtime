#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind original normal-LC bytes and reported identities; execute no collector.

The original holder terminal and its complete stored read stream are mandatory.
Other original reports may be missing or partial after a failed attempt. Missing
local inputs mean not supplied, never remote absence or successful execution.
Only the template's ACTUAL assignment is replaced in a fresh output directory.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pprint
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = PurePosixPath('/home/qian/hepta-runtime-optimization-20261106-r35')
R16 = PurePosixPath('/home/qian/hepta-runtime-optimization-20261104-r16')
FROZEN = PurePosixPath('/home/qian/hepta-runtime-optimization-20261023/a31-frozen-originals-r01')
TEMPLATE_SHA = '18718efc1b613b9b01c1ec05485c36dda1b83142fefea08a52b157df74d86b65'
HOLDER_SHA = '715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def stamp(info):
    return tuple(getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, "indirect local original")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 8 * 1024 * 1024,
         "unsafe or oversized local original")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        need(stamp(os.fstat(stream.fileno())) == stamp(before), "local original changed before open")
        raw = stream.read(8 * 1024 * 1024 + 1)
        need(len(raw) == before.st_size and stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.lstat()),
             "local original changed while read")
    return raw


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


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


def archive_name(path):
    need(type(path) is str, 'original identity path is not a string')
    value = PurePosixPath(path)
    need(value.is_absolute() and '..' not in value.parts and value.as_posix() == path,
         'noncanonical original remote identity')
    if value.is_relative_to(ROOT):
        return value.relative_to(ROOT).as_posix()
    if value.is_relative_to(FROZEN):
        return 'external/frozen-jobs/' + value.relative_to(FROZEN).as_posix()
    if value.is_relative_to(R16):
        return 'external/r16/' + value.relative_to(R16).as_posix()
    return None


def seal(originals, output):
    template_path = HERE / 'archive_r35_lifecycle.py'
    template = regular(template_path)
    need(sha(template) == TEMPLATE_SHA, 'reviewed unsealed lifecycle collector changed')
    source = template.decode()
    tree = ast.parse(source)
    assignments = {node.targets[0].id: node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)}
    literal = lambda name: ast.literal_eval(assignments[name].value)
    need(literal('ACTUAL') is None, 'template was already sealed')
    static, core, selected = literal('STATIC_PINS'), literal('CORE_FILES'), literal('SELECTED_DIRS')
    skip_dirs, skip_files = literal('SKIP_DIRS'), literal('SKIP_FILES')
    need(originals.is_absolute() and originals.resolve(strict=True) == originals and originals.is_dir(),
         'canonical local original directory required')
    raw_files, documents, local_pins, parse_errors = {}, {}, {}, []
    local_files = list(core) + ['lifecycle-abba-01/round-%d-%s/independent-summary.json' % (n, arm)
                              for n, arm in enumerate('ABBA')]
    extra_pages = sorted(originals.glob('lifecycle-holder-read-01-page-*.json'))
    need(len(extra_pages) < 8192, 'too many original native read pages')
    for number, path in enumerate(extra_pages, 1):
        need(path.name == 'lifecycle-holder-read-01-page-%04d.json' % number,
             'native read page names must be contiguous four-digit indices')
        local_files.append(path.name)
    need(len(local_files) == len(set(local_files)), 'duplicate local original selection')
    for name in local_files:
        path = originals / name
        if not os.path.lexists(path):
            continue
        raw = regular(path)
        raw_files[name] = raw
        need(sum(map(len, raw_files.values())) <= MAX_TOTAL, 'local original payload exceeds 64 MiB')
        local_pins[name] = {'local_path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}
        try:
            document = json.loads(raw)
            need(type(document) is dict, 'original is not a JSON object')
            documents[name] = document
        except (ValueError, TypeError, UnicodeError) as error:
            parse_errors.append({'member': name, 'type': type(error).__name__, 'reason': str(error)[:300]})
    native_name, read_name = 'lifecycle-holder-native-01.json', 'lifecycle-holder-read-01.json'
    need(native_name in documents and read_name in documents, 'original holder native/read JSON required')
    native = documents[native_name]
    job = native.get('job_id')
    need(type(job) is str and re.fullmatch(r'[0-9a-f]+(?:-[0-9a-f]+)+', job) is not None,
         'actual lifecycle holder job missing')
    native_receipt = terminal(native, job)
    read_members = [read_name] + [path.name for path in extra_pages]
    need(all(name in documents for name in read_members), 'original native read page is malformed')
    native_receipt['original_streams'] = streams_from_reads(native, [documents[name] for name in read_members])

    def allowed(name):
        if type(name) is not str:
            return False
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or path.as_posix() != name or not path.parts:
            return False
        if any(part in skip_dirs for part in path.parts) or path.name in skip_files:
            return False
        if path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx'}:
            return False
        return (name in static or name in core or name in read_members
                or any(name.startswith(directory + '/') for directory in selected))

    pins, sizes, excluded = {}, {}, {}

    def add(name, size, digest, origin):
        need(allowed(name) and type(size) is int and 0 <= size <= MAX_FILE
             and type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
             'unsafe original identity: ' + str(name))
        need(name not in static or static[name] == digest, 'actual identity conflicts with frozen input: ' + name)
        need(name not in pins or (pins[name] == digest and sizes[name] == size),
             'original reports disagree about one identity: ' + name)
        pins[name], sizes[name] = digest, size

    for name, raw in raw_files.items():
        add(name, len(raw), sha(raw), 'supplied original bytes')

    def walk(value, origin):
        if isinstance(value, dict):
            if {'path', 'bytes', 'sha256'} <= set(value):
                try:
                    name = archive_name(value['path'])
                except (ValueError, TypeError):
                    name = None
                if name is not None and allowed(name):
                    add(name, value['bytes'], value['sha256'], origin)
                else:
                    key = (str(value.get('path')), str(value.get('sha256')))
                    excluded[key] = {'identity': value,
                        'scope': 'source/ELF/profile or outside fixed selection; body is not read by this sealer'}
                return
            for key, child in value.items():
                walk(child, origin + '/' + str(key))
        elif isinstance(value, list):
            for number, child in enumerate(value):
                walk(child, origin + '/' + str(number))

    for name, value in documents.items():
        walk(value, name)
    schemas = {
        'lifecycle-campaign-01/report.json': 'hepta-r35-normal-lifecycle-campaign-control/v1',
        'lifecycle-abba-01/report.json': 'hepta-r25-lifecycle-abba-control/v1',
        'lifecycle-abba-01/round-index.json': 'hepta-r25-lifecycle-round-index/v1',
        'lifecycle-abba-01/gates.json': 'hepta-r25-lifecycle-gates/v1',
        'lifecycle-inputs-01.json': 'hepta-r25-lifecycle-inputs/v1',
        'lifecycle-holder-report-01.json': 'hepta-x230-r21-held-agent-campaign/v1',
    }
    for name, schema in schemas.items():
        if name in documents:
            need(documents[name].get('schema') == schema, 'original protocol schema differs: ' + name)
    parent = documents.get('lifecycle-campaign-01/report.json')
    holder = documents.get('lifecycle-holder-report-01.json')
    normal = documents.get('lifecycle-abba-01/report.json')
    gates = documents.get('lifecycle-abba-01/gates.json')
    monitor_audit = documents.get('lifecycle-campaign-01/compiler-monitor.audit.json')
    if parent is not None:
        need(parent.get('launcher_sha256') == static['tools-01/r35_lifecycle_campaign.py'],
             'original parent source differs from the installed lifecycle parent')
    if holder is not None:
        need(holder.get('holder_script_sha256') == HOLDER_SHA
             and holder.get('remote_script_sha256') == static['tools-01/r35_lifecycle_campaign.py'],
             'original holder source/remote parent differs')
    outcomes = {
        'workflow_reported_passed': parent.get('passed') if parent is not None else None,
        'parent_reported_adoption_passed': parent.get('adoption_passed') if parent is not None else None,
        'normal_lifecycle_gate_verified': gates.get('verified') if gates is not None else None,
        'normal_lifecycle_gate_passed': gates.get('passed') if gates is not None else None,
    }
    need(all(value is None or type(value) is bool for value in outcomes.values()), 'original outcome is not boolean/null')
    monitor_count = monitor_audit.get('validation', {}).get('validated_sample_count') if monitor_audit else None
    need(monitor_count is None or type(monitor_count) is int and monitor_count >= 0,
         'original monitor sample count is malformed')
    count_keys = ('native_calls', 'independent_ssh_calls', 'new_starts', 'same_key_lookups',
                  'cancellations', 'automatic_rpc_retries')
    round_counts = {}
    for number, arm in enumerate('ABBA'):
        name = 'lifecycle-abba-01/round-%d-%s/independent-summary.json' % (number, arm)
        audit = documents.get(name)
        if audit is not None:
            round_counts[name] = {key: audit.get(key) for key in count_keys}
    actual = {'schema': 'hepta-r35-normal-lifecycle-archive-bindings/v1',
        'holder_job_id': job, 'sha256': dict(sorted(pins.items())), 'bytes': dict(sorted(sizes.items())),
        'holder_read_members': read_members, 'outcomes': outcomes,
        'compiler_monitor_sample_count': monitor_count, 'original_native_terminal': native_receipt,
        'original_round_audit_reported_counts': round_counts,
        'original_normal_reported_passed': normal.get('passed') if normal is not None else None,
        'local_originals': local_pins,
        'local_optional_originals_not_supplied': [name for name in local_files if name not in raw_files],
        'local_absence_is_not_remote_absence': True,
        'unselected_reported_identity_references': list(excluded.values()),
        'local_original_parse_errors': parse_errors,
        'identity_only_remote_bodies_read_by_sealer': False,
        'collector_or_original_auditors_executed': False,
        'future_archive_receipt': None,
        'candidate_adopted_by_sealer': False}
    lines = source.splitlines(keepends=True)
    node = assignments['ACTUAL']
    lines[node.lineno - 1:node.end_lineno] = ['ACTUAL = ' + pprint.pformat(actual, sort_dicts=True, width=120) + '\n']
    sealed_source = ''.join(lines)
    sealed_tree = ast.parse(sealed_source)
    sealed_actual = [node for node in sealed_tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'ACTUAL' for target in node.targets)]
    need(len(sealed_actual) == 1, 'sealed ACTUAL count differs')
    sealed_actual[0].value = ast.Constant(value=None)
    need(ast.dump(tree, include_attributes=False) == ast.dump(sealed_tree, include_attributes=False),
         'sealing changed executable code outside ACTUAL')
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and not os.path.lexists(output), 'create-only sealed output directory required')
    package = {'archive_r35_lifecycle.py': sealed_source.encode(), 'actual-bindings-01.json': encoded(actual)}
    manifest = {'schema': 'hepta-r35-normal-lifecycle-archive-seal/v1', 'sealed': True,
        'template': {'path': str(template_path), 'bytes': len(template), 'sha256': sha(template)},
        'files': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in package.items()},
        'source_change': 'Only ACTUAL filled from original bytes and identity-bearing reports',
        'holder_job_id': job, 'reported_outcomes': outcomes,
        'collector_executed': False, 'original_auditors_reexecuted': False,
        'tests_benchmarks_materializers_or_holders_executed': False,
        'archive_receipt_or_hash': None}
    package['seal-manifest.json'] = encoded(manifest)
    output.mkdir(mode=0o700)
    for name, raw in package.items():
        create(output / name, raw)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--originals', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(seal(args.originals, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
