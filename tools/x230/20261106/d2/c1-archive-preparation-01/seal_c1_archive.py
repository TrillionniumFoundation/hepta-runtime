#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal the C1 collector using actual local original bytes only.

No collector, original auditor/parser/validator, runtime, compiler or host is
called. Missing or failed originals remain accurately missing or failed.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILE = 32 * 1024 * 1024
MAX_TOTAL = 384 * 1024 * 1024
COUNTS = ('measured_calls', 'warmup_calls', 'preflight_restart_calls', 'total_calls', 'failed_calls')
TEMPLATE_SHA256 = '5f2772d86de6f8c5fec2800dc14f1f948225e9b41b9656ab1c623713d5a7bbd3'
CORE_PATHS = ["c1-holder-native-01.json", "c1-holder-report-01.json", "c1-holder-start-01.json", "c1-parent-install-01.json", "c1-campaign-01/report.json", "c1-campaign-01/summary.json", "c1-campaign-01/source-inputs.json", "c1-campaign-01/baseline-source-inputs.json", "c1-campaign-01/compiler-monitor.json", "c1-campaign-01/compiler-monitor.audit.json", "c1-observation-01/report.json", "c1-observation-01/independent-summary.json", "c1-adapter-evidence-01/adapter-report.json", "c1-campaign-inputs-01.json", "c1-prerequisites-01.json", "c1-tools-01/d2_campaign.py", "c1-tools-01/run_c1_phase_cost.py"]

RUNTIME_PATHS = ["c1-campaign-inputs-01.json", "c1-prerequisites-01.json", "c1-tools-01/d2_campaign.py", "c1-tools-01/run_c1_phase_cost.py"]


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


def actual_from_originals(originals, snapshots, expected_job_id):
    need(type(expected_job_id) is str and len(expected_job_id.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in expected_job_id.split('-')),
         'the actual original holder job ID is required')
    data = {}
    for name in CORE_PATHS:
        path = originals / name
        if os.path.lexists(path):
            data[name] = read_original(path, snapshots)
    need(all(name in data for name in RUNTIME_PATHS),
         'actual installed parent/adapter/campaign-input/full-prerequisite originals are required')
    pages = load_pages(originals, 'c1-holder-native-read-01-', snapshots, data, True)
    need(sum(map(len, data.values())) <= MAX_TOTAL, 'captured core receipts exceed bound')
    native = original_object(data, 'c1-holder-native-01.json')
    need(native is not None and native.get('job_id') == expected_job_id
         and native.get('state') in {'succeeded', 'failed', 'cancelled', 'timed_out'}
         and (native.get('exit_code') is None or type(native.get('exit_code')) is int),
         'actual original holder terminal is required')
    native_stream_pages([json.loads(data[name]) for name in pages], native)
    parent = original_object(data, 'c1-campaign-01/report.json')
    audit = original_object(data, 'c1-observation-01/independent-summary.json')
    adapter = original_object(data, 'c1-adapter-evidence-01/adapter-report.json')
    holder = original_object(data, 'c1-holder-report-01.json')
    native_success = native.get('state') == 'succeeded' and native.get('exit_code') == 0
    if native_success:
        # Do not mislabel a successful original as failed merely because a local
        # mirror has not yet received its required original bodies.
        need(all(name in data for name in CORE_PATHS if name != 'c1-holder-start-01.json'),
             'successful holder is awaiting its full actual core receipt mirror')
    passed = bool(native_success and parent is not None and parent.get('passed') is True
        and parent.get('diagnostic_evidence_passed') is True and parent.get('measurement_attribution_valid') is True
        and audit is not None and audit.get('verified') is True
        and adapter is not None and adapter.get('analysis_complete') is True
        and holder is not None and holder.get('passed') is True and holder.get('owned_agent_reaped') is True)
    counts = None if audit is None else {key: audit.get(key) for key in COUNTS}
    if passed:
        native_terminal(native, expected_job_id, 'succeeded', 0)
        need(parent.get('schema') == 'hepta-d2-c1-campaign-control/v1'
             and parent.get('candidate_adopted') is False and parent.get('performance_acceptance_claim') is False
             and audit.get('schema') == 'hepta-native-observation-independent-analysis/v3'
             and adapter.get('schema') == 'hepta-d2-c1-phase-cost-adapter/v1'
             and holder.get('schema') == 'hepta-x230-r21-held-agent-campaign/v1',
             'original diagnostic success scope differs')
        need(type(counts) is dict and all(type(value) is int and value >= 0 for value in counts.values()),
             'actual original diagnostic count shape differs')
        need(counts == dict(zip(COUNTS, (768, 96, 72, 936, 0))),
             'original successful diagnostic did not complete the fixed protocol')
    return {'schema': 'hepta-d2-c1-archive-actual-pins/v1', 'sealed': True,
        'holder_original_job_id': expected_job_id,
        'outcome': 'diagnostic_passed' if passed else 'not_passed',
        'native_read_paths': pages, 'counts': counts,
        'files': {name: None if name not in data else {'bytes': len(data[name]), 'sha256': sha(data[name])}
                  for name in [*CORE_PATHS, *pages]}}


def main():
    need(not sys.flags.optimize, 'normal Python assertions are required')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template', type=Path, required=True)
    parser.add_argument('--originals', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--holder-job-id', required=True)
    args = parser.parse_args()
    template, originals, output = (path.absolute() for path in (args.template, args.originals, args.output))
    need(originals.resolve(strict=True) == originals and originals.is_dir(),
         'fixed local actual-original directory required')
    need(output.is_absolute() and output.resolve() == output and not os.path.lexists(output),
         'new create-only sealed output directory required')
    snapshots = {}
    raw = read_original(template, snapshots)
    need(sha(raw) == TEMPLATE_SHA256, 'reviewed collector template SHA256 differs')
    actual = actual_from_originals(originals, snapshots, args.holder_job_id)
    sealed = with_actual(raw.decode('utf-8'), actual)
    actual_raw = encoded(actual)
    manifest = {'schema': 'hepta-d2-c1-archive-seal/v1',
        'template': {'bytes': len(raw), 'sha256': sha(raw)},
        'sealed_collector': {'bytes': len(sealed), 'sha256': sha(sealed)},
        'actual_pins': {'bytes': len(actual_raw), 'sha256': sha(actual_raw)},
        'only_actual_assignment_changed': True,
        'actual_original_job_id': actual['holder_original_job_id'],
        'outcome': actual['outcome'], 'counts': actual['counts'],
        'collector_or_verifier_executed': False,
        'compiler_auditor_workload_or_host_executed': False,
        'original_bytes_reencoded_or_modified': False,
        'source_outputs_create_only': True}
    manifest_raw = encoded(manifest)
    need(all(stamp(path.lstat()) == expected for path, expected in snapshots.items()),
         'an original changed during static sealing')
    output.mkdir(mode=0o700)
    for name, body in [('archive_d2_c1.py', sealed), ('actual-pins.json', actual_raw),
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
