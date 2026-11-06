#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal an ordinary evidence collector from actual local original bytes only.

This source builder performs no collector, verifier, auditor, compiler or host
execution. All original files remain unmodified; the output directory is new.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
TEMPLATE_SHA256 = 'ee14f25bd93070761ae90ccbc64828c85974a922958f145e411891ba8e272c21'
EXPECTED_JOB_ID = '1a1b1014af6-fc05-74d2'
CORE_PATHS = ["ordinary-native-01.json","ordinary-plan-01.json","ordinary-01/report.json","ordinary-01/source-map.json","ordinary-01/isolated-tests/summary.json","ordinary-01/isolated-tests.audit.json","ordinary-verification-input-01.json","ordinary-postflight-01.json","ordinary-postflight-native-01.json","ordinary-installation-started-01.json","ordinary-installation-01.json"]
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')


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

def read_original(path, snapshots):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect original path')
    initial = path.lstat()
    need(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and initial.st_size <= MAX_FILE,
         'unsafe or oversized original')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stamp(before) == stamp(initial), 'original changed before open')
        raw = stream.read(MAX_FILE + 1)
        need(len(raw) <= MAX_FILE and len(raw) == before.st_size
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'original changed while reading')
    snapshots[path] = stamp(initial)
    return raw


def load_pages(originals, stem, snapshots, data, required):
    names = []
    for number in range(16):
        name = stem + '%03d.json' % number
        path = originals / name
        if not os.path.lexists(path):
            break
        data[name] = read_original(path, snapshots)
        names.append(name)
    need((not required or names)
         and {path.name for path in originals.glob(stem + '*.json')} == set(names),
         'missing, noncontiguous or excessive original native pages')
    return names


def original_object(data, name):
    if name not in data:
        return None
    try:
        result = json.loads(data[name])
        return result if type(result) is dict else None
    except (ValueError, TypeError, UnicodeError):
        return None


def actual_from_originals(originals, snapshots):
    data = {}
    for name in CORE_PATHS:
        path = originals / name
        if os.path.lexists(path):
            data[name] = read_original(path, snapshots)
    native_pages = load_pages(originals, 'ordinary-native-read-01-', snapshots, data, True)
    post_pages = load_pages(originals, 'ordinary-postflight-native-read-01-', snapshots, data, False)
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'actual receipt bytes exceed bound')
    native = original_object(data, 'ordinary-native-01.json')
    need(native is not None and native.get('job_id') == EXPECTED_JOB_ID
         and native.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (native.get('exit_code') is None or type(native.get('exit_code')) is int),
         'actual original ordinary native terminal is required')
    native_stream_pages([json.loads(data[name]) for name in native_pages], native)
    post_native = original_object(data, 'ordinary-postflight-native-01.json')
    post_job = None
    if post_native is not None:
        post_job = post_native.get('job_id')
        need(type(post_job) is str and post_job != EXPECTED_JOB_ID
             and post_native.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
             and post_pages, 'actual postflight native terminal/pages are inconsistent')
        native_stream_pages([json.loads(data[name]) for name in post_pages], post_native)
    else:
        need(not post_pages and 'ordinary-postflight-native-01.json' not in data,
             'postflight native or original pages are malformed or incomplete')
    # A successful producer alone is not a closed ordinary result. Wait for
    # the actual verifier terminal, whether that verification passed or failed.
    producer_success = native.get('state') == 'succeeded' and native.get('exit_code') == 0
    if producer_success:
        need(post_native is not None, 'successful producer is awaiting actual verifier completion')
    postflight = original_object(data, 'ordinary-postflight-01.json')
    report = original_object(data, 'ordinary-01/report.json')
    tests = original_object(data, 'ordinary-01/isolated-tests/summary.json')
    passed = bool(producer_success and post_native is not None
                  and post_native.get('state') == 'succeeded' and post_native.get('exit_code') == 0
                  and postflight is not None and postflight.get('passed') is True
                  and postflight.get('ordinary_five_stages_passed') is True
                  and report is not None and report.get('qualified') is True)
    if passed:
        native_terminal(native, EXPECTED_JOB_ID, 'succeeded', 0)
        native_terminal(post_native, post_job, 'succeeded', 0)
        need(all(name in data for name in CORE_PATHS), 'actual successful original files are incomplete')
        need(postflight.get('schema') == 'hepta-d2-ordinary-supplement-postflight/v1'
             and postflight.get('original_job_id') == EXPECTED_JOB_ID
             and postflight.get('source_maps_unchanged') is True
             and postflight.get('performance_acceptance_claim') is False,
             'actual ordinary postflight shape differs')
    counts = None if tests is None else {key: tests.get(key) for key in COUNTS}
    if passed:
        need(type(counts) is dict and all(type(value) is int and value >= 0 for value in counts.values())
             and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored']
             and postflight['tests'] == counts, 'actual original ordinary counts differ')
    all_names = [*CORE_PATHS, *native_pages, *post_pages]
    actual = {'schema': 'hepta-d2-ordinary-archive-actual-pins/v1', 'sealed': True,
        'producer_original_job_id': EXPECTED_JOB_ID,
        'postflight_original_job_id': post_job,
        'outcome': 'passed' if passed else 'not_passed',
        'native_read_paths': native_pages, 'postflight_native_read_paths': post_pages,
        'counts': counts,
        'files': {name: None if name not in data else {'bytes': len(data[name]), 'sha256': sha(data[name])}
                  for name in all_names}}
    return actual


def with_actual(source, actual):
    tree = ast.parse(source)
    nodes = [node for node in tree.body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == 'ACTUAL' for target in node.targets)]
    need(len(nodes) == 1 and ast.literal_eval(nodes[0].value) is None, 'exact unsealed ACTUAL assignment required')
    lines = source.splitlines(keepends=True)
    node = nodes[0]
    replacement = 'ACTUAL = ' + repr(actual) + '\n'
    result = ''.join(lines[:node.lineno - 1]) + replacement + ''.join(lines[node.end_lineno:])
    sealed_tree = ast.parse(result)
    nodes_after = [node for node in sealed_tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'ACTUAL' for target in node.targets)]
    need(len(nodes_after) == 1 and ast.literal_eval(nodes_after[0].value) == actual,
         'sealed actual assignment differs')
    nodes_after[0].value = ast.Constant(value=None)
    need(ast.dump(tree, include_attributes=False) == ast.dump(sealed_tree, include_attributes=False),
         'sealer changed code beyond ACTUAL')
    return result.encode('utf-8')


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    need(not sys.flags.optimize, 'normal Python assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--originals', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    template, originals, output = (path.absolute() for path in (args.template, args.originals, args.output))
    need(originals.resolve(strict=True) == originals and originals.is_dir(),
         'fixed local actual-original directory required')
    need(output.is_absolute() and output.resolve() == output and not os.path.lexists(output),
         'new create-only sealed output directory required')
    snapshots = {}
    raw = read_original(template, snapshots)
    need(sha(raw) == TEMPLATE_SHA256, 'reviewed collector template SHA256 differs')
    actual = actual_from_originals(originals, snapshots)
    sealed = with_actual(raw.decode('utf-8'), actual)
    actual_raw = encoded(actual)
    manifest = {'schema': 'hepta-d2-ordinary-archive-seal/v1',
        'template': {'bytes': len(raw), 'sha256': sha(raw)},
        'sealed_collector': {'bytes': len(sealed), 'sha256': sha(sealed)},
        'actual_pins': {'bytes': len(actual_raw), 'sha256': sha(actual_raw)},
        'only_actual_assignment_changed': True,
        'actual_original_job_id': EXPECTED_JOB_ID,
        'actual_postflight_job_id': actual['postflight_original_job_id'],
        'outcome': actual['outcome'], 'counts': actual['counts'],
        'collector_or_verifier_executed': False,
        'compiler_auditor_workload_or_host_executed': False,
        'original_bytes_reencoded_or_modified': False,
        'source_outputs_create_only': True}
    manifest_raw = encoded(manifest)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'an original changed during static sealing')
    output.mkdir(mode=0o700)
    for name, body in [('archive_d2_ordinary.py', sealed), ('actual-pins.json', actual_raw),
                       ('seal-manifest.json', manifest_raw)]:
        write_new(output / name, body)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(manifest, sort_keys=True))


if __name__ == '__main__':
    main()
