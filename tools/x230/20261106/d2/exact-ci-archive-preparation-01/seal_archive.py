#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal original local D2 exact-CI receipts; no collector, binder, auditor or host runs."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import stat
import sys
ROOT = Path("/home/qian/hepta-runtime-validation-cost-20261106-d2")
MAX_FILE = 8 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect local original')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= maximum, 'unsafe or oversized local original')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    need(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(path.lstat()),
         'local original changed during read')
    return raw


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


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


# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0

def original(spec):
    need(type(spec) is dict and set(spec) == {'local_path', 'bytes', 'sha256'}
         and type(spec['bytes']) is int and 0 < spec['bytes'] <= MAX_FILE
         and type(spec['sha256']) is str and len(spec['sha256']) == 64
         and set(spec['sha256']) <= set('0123456789abcdef'), 'actual immutable local original required')
    raw = read(spec['local_path'], maximum=MAX_FILE)
    need(identity(raw) == {key: spec[key] for key in ('bytes', 'sha256')}, 'original byte identity differs')
    return raw


def constant(source, name):
    found = [node for node in ast.parse(source).body if isinstance(node, ast.Assign)
             and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    need(len(found) == 1, 'expected one source constant: ' + name)
    return ast.literal_eval(found[0].value)


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(not sys.flags.optimize, 'Python optimized assertions are not supported')
    request_raw = read(args.input.absolute(), maximum=2 * 1024 * 1024)
    request = json.loads(request_raw)
    need(request.get('schema') == 'hepta-d2-exact-ci-archive-seal-request/v1', 'unexpected seal request')
    template_raw = original(request['collector'])
    template = template_raw.decode('utf-8')
    need(constant(template, 'ACTUAL') is None and template.count('\nACTUAL = None\n') == 1,
         'collector must be the unchanged unsealed preparation')
    future = constant(template, 'FUTURE_PATHS')
    count_keys = constant(template, 'COUNT_KEYS')
    commands = constant(template, 'CI_COMMANDS')
    environment = constant(template, 'CI_ENVIRONMENT')
    pinned = constant(template, 'PINNED')
    need(len(pinned) == 19, 'fixed original deployment/Q inventory differs')
    job = request.get('original_job_id')
    need(type(job) is str and len(job.split('-')) == 3
         and all(part and set(part) <= set('0123456789abcdef') for part in job.split('-')),
         'actual original CI job required')
    pages = request.get('read_pages')
    need(type(pages) is list and 1 <= len(pages) <= 16 and len(set(pages)) == len(pages)
         and (pages == ['rust-ci-native-read-01.json']
              or pages == ['rust-ci-native-read-01-%03d.json' % i for i in range(len(pages))]),
         'actual original native read pages required')
    need(type(request.get('originals')) is dict
         and set(request['originals']) == set(future) | set(pages), 'original receipt selection differs')
    raw, pins, doc = {}, {}, {}
    for name, spec in request['originals'].items():
        if spec is None:
            pins[name] = None
        else:
            raw[name] = original(spec)
            pins[name] = identity(raw[name])
            doc[name] = json.loads(raw[name])
    for name in ['rust-ci-native-01.json', 'rust-ci-installation-started-01.json',
                 'rust-ci-installation-01.json', *pages]:
        need(pins[name] is not None, 'complete native/installation originals required')
    terminal = doc['rust-ci-native-01.json']
    need(terminal['state'] in {'succeeded', 'failed'} and type(terminal['exit_code']) is int,
         'the original native CI attempt is not terminal')
    native_terminal(terminal, job, terminal['state'], terminal['exit_code'])
    streams = native_stream_pages([doc[name] for name in pages], terminal)
    passed = terminal['state'] == 'succeeded' and terminal['exit_code'] == 0
    need(passed or (terminal['state'] == 'failed' and terminal['exit_code'] != 0),
         'original terminal outcome and exit status disagree')
    counts = None
    if passed:
        need(all(value is not None for value in pins.values()), 'successful CI requires all actual core originals')
        ci, plan, audit = (doc[name] for name in
                           ('rust-ci-01/report.json', 'rust-ci-plan-01.json', 'rust-ci-01/nextest-output-audit.json'))
        need(ci['schema'] == 'hepta-d2-external-rust-ci/v1' and ci.get('passed') is True
             and ci.get('finished_utc') and not ci.get('error') and ci['automatic_retries'] == 0
             and ci['owned_children_closed'] is True and ci['source_inputs_unchanged'] is True
             and ci['home_unchanged'] is True and ci['hosted_actions_passed'] is False
             and ci['production_services_modified'] is False,
             'original completed CI report is not successful')
        need(ci['plan'] == {'path': str(ROOT / 'rust-ci-plan-01.json'), **pins['rust-ci-plan-01.json']}
             and plan['schema'] == 'hepta-d2-materialized-exact-rust-ci-plan/v1'
             and plan['qualification_job_id'] == ci['original_qualification_job_id']
             and plan['source'] == str(ROOT / 'source') and len(plan['source_files']) == 222,
             'original CI plan binding differs')
        need([row['name'] for row in ci['stages']] == list(commands)
             and ci['explicit_environment'] == plan['environment'] == environment,
             'original six stages/environment differ')
        for row in ci['stages']:
            need(row['argv'] == commands[row['name']] and row['cwd'] == str(ROOT / 'source')
                 and row['returncode'] == 0 and row['passed'] is True and row['timed_out'] is False
                 and row['waited_and_reaped'] is True and row['owned_process_absent'] is True
                 and row['owned_process_group_absent'] is True, 'original CI stage did not close successfully')
        need(ci['nextest_output_audit'] == audit and audit['verified'] is True
             and audit['progress_counter_complete'] is True, 'actual original nextest audit required')
        counts = {name: audit[name] for name in count_keys}
        need(all(type(n) is int and n >= 0 for n in counts.values()) and counts['passed'] > 0
             and counts['failed'] == counts['retries'] == 0
             and counts['selected'] == counts['passed'] + counts['ignored']
             and plan['qualification_counts'] == counts
             and audit['completed_exact_case_count'] == counts['passed'], 'actual CI counts differ')
    actual = {'schema': 'hepta-d2-exact-ci-archive-actual-pins/v1', 'sealed': True,
              'original_job_id': job, 'outcome': 'passed' if passed else 'failed',
              'exit_code': terminal['exit_code'], 'files': pins, 'read_pages': pages, 'counts': counts}
    source = template.replace('\nACTUAL = None\n', '\nACTUAL = ' + pprint.pformat(actual, sort_dicts=True, width=110) + '\n')
    ast.parse(source)
    output = args.output.absolute()
    need(output.resolve() == output and not os.path.lexists(output), 'create-only seal output already exists')
    output.mkdir(mode=0o700)
    source_raw, actual_raw = source.encode(), encoded(actual)
    receipt = {'schema': 'hepta-d2-exact-ci-archive-seal-receipt/v1', 'sealed': True,
               'original_job_id': job, 'outcome': actual['outcome'], 'counts': counts,
               'request': {'path': str(args.input.absolute()), **identity(request_raw)},
               'template': request['collector'], 'sealed_collector': identity(source_raw),
               'actual_pins': identity(actual_raw), 'originals': request['originals'],
               'complete_native_streams': {name: identity(value) for name, value in streams.items()},
               'collector_requires_actual_stage_raw_stream_recheck': True,
               'collector_or_auditor_executed_by_sealer': False,
               'runtime_or_host_called': False, 'performance_acceptance_claim': False}
    for name, value in (('archive_d2_ci.py', source_raw), ('actual-pins.json', actual_raw),
                        ('seal-receipt.json', encoded(receipt))):
        create(output / name, value)
    print(json.dumps({'sealed': True, 'output': str(output), 'collector': identity(source_raw),
                      'actual_pins': identity(actual_raw), 'outcome': actual['outcome']}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
