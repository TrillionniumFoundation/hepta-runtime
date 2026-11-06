#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal a new local R36 evidence collector from exact terminal receipt copies; do not archive or execute workloads."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import stat

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'archive_r36_qualification.py'
TEMPLATE_PIN = {"bytes":48044,"sha256":"9e0f610ed2d056609cb03e421a4f861186f7a0950da56c1e83f643aa089b7ee9"}
ROOT = '/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02'
PATHS = ('preparation.json', 'qualification-terminal-status-01.json', 'qualification-native-read-01.json',
         'qualification-01/report.json', 'qualification-01/source-map.json',
         'qualification-01/isolated-tests/summary.json', 'qualification-01/isolated-tests.audit.json')
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')
STAGES = ('format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release')
LIMIT = 8 * 1024 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def read(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct existing local original required')
    initial = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= LIMIT
             and stamp(before) == stamp(initial), 'unsafe/oversized/changing original')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == before.st_size and len(raw) <= LIMIT
             and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()), 'original changed while read')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    template_raw = read(TEMPLATE)
    need(identity(template_raw) == TEMPLATE_PIN, 'reviewed unsealed collector changed')
    input_raw = read(args.receipts)
    inputs = json.loads(input_raw)
    need(inputs.get('schema') == 'hepta-r36-qualification-archive-seal-input/v1'
         and type(inputs.get('qualification_job_id')) is str
         and type(inputs.get('files')) is dict and set(inputs['files']) == set(PATHS), 'actual original locations are unbound')
    bodies, pins, originals = {}, {}, {}
    for name in PATHS:
        row = inputs['files'][name]
        if row is None:
            pins[name] = None
            continue
        need(type(row) is dict and set(row) == {'local_path', 'bytes', 'sha256'}
             and type(row['local_path']) is str and type(row['bytes']) is int and 0 < row['bytes'] <= LIMIT,
             'actual local receipt identity required: ' + name)
        raw = read(row['local_path'])
        pin = identity(raw)
        need(pin == {key: row[key] for key in ('bytes', 'sha256')}, 'original receipt bytes differ: ' + name)
        bodies[name], pins[name], originals[name] = raw, pin, dict(row, remote_path=ROOT + '/' + name)
    need(all(name in bodies for name in ('preparation.json', 'qualification-terminal-status-01.json',
                                       'qualification-native-read-01.json')), 'original preparation/native/read required')
    terminal = json.loads(bodies['qualification-terminal-status-01.json'])
    need(terminal.get('job_id') == inputs['qualification_job_id']
         and terminal.get('state') in {'succeeded', 'failed'}
         and type(terminal.get('exit_code')) is int
         and ((terminal['exit_code'] == 0) == (terminal['state'] == 'succeeded'))
         and all(terminal.get(key) is True for key in ('output_complete', 'output_durable', 'terminal_publication_confirmed'))
         and all(terminal.get(key) is False for key in ('automatic_retry', 'timed_out', 'cancelled'))
         and terminal.get('terminal_publication_protocol') == 1
         and terminal.get('log_synced') == {'stdout': True, 'stderr': True}
         and terminal.get('log_errors') == {'stdout': None, 'stderr': None}
         and terminal.get('log_truncated') == {'stdout': False, 'stderr': False},
         'actual original native terminal is not closed and durable')
    native = json.loads(bodies['qualification-native-read-01.json'])
    need(native.get('job_id') == terminal['job_id'] and native.get('audit_recorded') is True, 'native read identifies another job')
    for name in ('stdout', 'stderr'):
        counts, row = terminal['log_bytes'][name], native[name]
        raw = bytes.fromhex(row['bytes_hex'])
        need(type(counts['seen']) is int and counts['seen'] == counts['stored'] == len(raw)
             and row['offset'] == 0 and row['eof'] is True and row['size'] == row['next_offset'] == len(raw)
             and row['text'] == raw.decode('utf-8', errors='replace'), 'native stream custody differs')
    prep = json.loads(bodies['preparation.json'])
    qualified = json.loads(bodies['qualification-01/report.json']) if 'qualification-01/report.json' in bodies else None
    tests = json.loads(bodies['qualification-01/isolated-tests/summary.json']) if 'qualification-01/isolated-tests/summary.json' in bodies else None
    counts = None if tests is None else {key: tests.get(key) for key in COUNTS}
    binaries = None if qualified is None else {key: value.get('sha256') for key, value in qualified.get('binaries', {}).items()}
    outcome = 'passed' if terminal['state'] == 'succeeded' else 'failed'
    if outcome == 'passed':
        need(all(name in bodies for name in PATHS), 'successful full qualification requires every original receipt')
        final_map = json.loads(bodies['qualification-01/source-map.json'])
        audit = json.loads(bodies['qualification-01/isolated-tests.audit.json'])
        need(prep.get('schema') == 'hepta-x230-r36-preparation/v1' and prep.get('passed') is True
             and prep.get('finished_utc') and 'error' not in prep and prep.get('qualification_started') is True
             and prep.get('qualification_returncode') == 0
             and prep['qualification_report_sha256'] == pins['qualification-01/report.json']['sha256'],
             'actual preparation did not report a complete successful original qualification')
        need(qualified.get('schema') == 'hepta-x230-composed-qualification/v1'
             and qualified.get('qualified') is True and qualified.get('finished_utc') and 'error' not in qualified
             and qualified['source'] == ROOT + '/source' and qualified['jobs'] == 2
             and qualified['automatic_test_retries'] == 0
             and tuple(row['name'] for row in qualified['stages']) == STAGES
             and all(row['returncode'] == 0 for row in qualified['stages'])
             and len(final_map) == 220 and qualified['source_tested'] == qualified['source_after'] == final_map,
             'actual eight-stage final qualified source differs')
        need(tests.get('success') is True and tests.get('filter') == '' and tests.get('enumeration_errors') == []
             and all(type(value) is int and value >= 0 for value in counts.values())
             and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored']
             and audit.get('success') is True and audit.get('errors') == []
             and all(audit[key] == counts[key] for key in ('passed', 'failed', 'ignored', 'selected'))
             and audit['executed'] == counts['passed']
             and audit['input_sha256']['summary.json'] == pins['qualification-01/isolated-tests/summary.json']['sha256']
             and tests['source_manifest_sha256'] == pins['qualification-01/source-map.json']['sha256'],
             'actual inventory/audit counts or source identities differ')
        need(set(binaries) == {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}, 'actual runtime inventory differs')
    actual = {'schema': 'hepta-r36-qualification-archive-actual-pins/v1', 'sealed': True,
        'qualification_job_id': terminal['job_id'], 'outcome': outcome, 'files': pins,
        'counts': counts, 'qualified_binary_sha256': binaries}
    text = template_raw.decode()
    found = [n for n in ast.parse(text).body if isinstance(n, ast.Assign) and len(n.targets) == 1
             and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'ACTUAL']
    need(len(found) == 1 and isinstance(found[0].value, ast.Constant) and found[0].value.value is None,
         'collector is not the original unsealed template')
    node = found[0]
    lines = text.splitlines(keepends=True)
    lines[node.lineno - 1:node.end_lineno] = ['ACTUAL = ' + pprint.pformat(actual, sort_dicts=True) + '\n']
    sealed = ''.join(lines).encode()
    ast.parse(sealed)
    for name, row in originals.items():
        need(identity(read(row['local_path'])) == pins[name], 'actual receipt changed before local seal')
    need(read(TEMPLATE) == template_raw and read(args.receipts) == input_raw, 'seal inputs changed')
    out = args.out
    need(out.is_absolute() and out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out),
         'fresh absolute output directory required')
    out.mkdir(mode=0o700)
    receipt = {'schema': 'hepta-r36-qualification-archive-local-seal/v1', 'status': 'sealed_not_executed',
        'collector': identity(sealed), 'template': TEMPLATE_PIN, 'actual': actual,
        'original_copies': originals, 'seal_input': identity(input_raw),
        'pending_remote_installation_history_files_must_exist_at_collection': [
  "archive-inputs-01/deployment.tar.gz",
  "archive-inputs-01/install_qualification.py",
  "archive-inputs-01/launch-command.json",
  "archive-inputs-01/installation-native-01.json",
  "archive-inputs-01/installation-read-01.json",
  "archive-inputs-01/installation-start-01.json",
  "archive-inputs-01/qualification-start-01.json"
],
        'archive_executed': False, 'original_installer_or_qualification_or_auditor_executed': False, 'remote_calls': 0}
    for name, raw in (('archive_r36_qualification.py', sealed), ('actual-pins.json', encode(actual)), ('seal-manifest.json', encode(receipt))):
        with (out / name).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps({'sealed': True, 'outcome': outcome, 'counts': counts,
                      'collector': identity(sealed), 'archive_executed': False}, sort_keys=True))


if __name__ == '__main__':
    os.umask(0o077)
    main()
