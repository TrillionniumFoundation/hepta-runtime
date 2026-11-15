#!/usr/bin/env python3
"""Seal a new local R35 CI collector from original completed receipts; never run the collector."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pprint
import re
import stat

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / 'archive_r35_exact_ci.py'
TEMPLATE_PIN = {'bytes': 29915, 'sha256': '9932c7d2f258ba8e0c943110c88286d11cc7c03d5fe137648d40fdf690e426f3'}
ROOT = '/home/qian/hepta-runtime-optimization-20261106-r35'
CI_JOB = '1a1af88c330-fc05-696f'
Q_JOB = '1a1af619097-fc05-6813'
CORE = ('rust-ci-plan-01.json', 'rust-ci-01/report.json', 'rust-ci-native-01.json')
AUDIT = 'rust-ci-01/nextest-output-audit.json'
READ_RE = re.compile(r'rust-ci-native-read-01(?:-[0-9]{3})?\.json\Z')
LIMIT = 8 * 1024 * 1024
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def read_local(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct absolute original required')
    initial = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= LIMIT
             and stamp(before) == stamp(initial), 'unsafe/oversized original')
        raw = stream.read(LIMIT + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'original changed while read')
    return raw


def read_names(names):
    result = sorted(name for name in names if READ_RE.fullmatch(name))
    need(result, 'complete original native process_read receipt(s) are required')
    if 'rust-ci-native-read-01.json' in result:
        need(result == ['rust-ci-native-read-01.json'], 'single and paged native receipts cannot be mixed')
    else:
        need(result == ['rust-ci-native-read-01-%03d.json' % index for index in range(len(result))],
             'native receipt pages must be contiguous from 000')
    return result


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    template_raw = read_local(TEMPLATE)
    need(identity(template_raw) == TEMPLATE_PIN, 'reviewed unsealed collector differs')
    input_raw = read_local(args.receipts)
    inputs = json.loads(input_raw)
    need(inputs.get('schema') == 'hepta-r35-exact-ci-archive-seal-input/v1'
         and inputs.get('ci_job_id') == CI_JOB and type(inputs.get('files')) is dict,
         'actual original CI identity/locations required')
    archive_sha = inputs.get('qualification_archive_sha256')
    need(type(archive_sha) is str and re.fullmatch(r'[0-9a-f]{64}', archive_sha),
         'actual completed qualification archive SHA required')
    read_files = read_names(inputs['files'])
    need(set(inputs['files']) == set(CORE) | {AUDIT} | set(read_files)
         and len(inputs['files']) <= 8192, 'original CI receipt names differ')
    bodies, pins, copies = {}, {}, {}
    for name, row in inputs['files'].items():
        if row is None:
            need(name == AUDIT, 'only genuinely absent later audit may be null')
            pins[name] = None
            continue
        need(type(row) is dict and set(row) == {'local_path', 'bytes', 'sha256'}
             and type(row['local_path']) is str and type(row['bytes']) is int and 0 < row['bytes'] <= LIMIT
             and type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
             'exact original local receipt identity required: ' + name)
        body = read_local(row['local_path'])
        need(identity(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'original differs: ' + name)
        bodies[name], pins[name], copies[name] = body, identity(body), dict(row, remote_path=ROOT + '/' + name)
    need(all(name in bodies for name in CORE) and all(name in bodies for name in read_files),
         'core original plan/report/terminal/read missing; never fabricate a preflight report')
    plan = json.loads(bodies['rust-ci-plan-01.json'])
    report = json.loads(bodies['rust-ci-01/report.json'])
    native = json.loads(bodies['rust-ci-native-01.json'])
    native_view = terminal(native, CI_JOB)
    stream_proof = streams_from_reads(native, [json.loads(bodies[name]) for name in read_files])
    need(plan.get('schema') == 'hepta-r35-materialized-exact-rust-ci-plan/v1'
         and plan.get('attempt') == '01' and plan.get('qualification_job_id') == Q_JOB
         and report.get('schema') == 'hepta-r35-external-rust-ci/v1'
         and report.get('attempt') == '01' and type(report.get('passed')) is bool,
         'original CI plan/report schema or attempt differs')
    audit = report.get('nextest_output_audit')
    counts = None if not isinstance(audit, dict) else {key: audit.get(key) for key in COUNTS}
    actual = {'schema': 'hepta-r35-exact-ci-archive-actual-pins/v1', 'sealed': True,
        'ci_job_id': CI_JOB, 'qualification_archive_sha256': archive_sha, 'files': pins,
        'reported_passed': report['passed'], 'reported_nextest_counts': counts,
        'native_terminal': {key: native.get(key) for key in ('state', 'exit_code')}}
    text = template_raw.decode('utf-8')
    found = [node for node in ast.parse(text).body if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'ACTUAL']
    need(len(found) == 1 and isinstance(found[0].value, ast.Constant) and found[0].value.value is None,
         'unsealed ACTUAL assignment required')
    lines = text.splitlines(keepends=True)
    node = found[0]
    lines[node.lineno - 1:node.end_lineno] = ['ACTUAL = ' + pprint.pformat(actual, sort_dicts=True) + '\n']
    sealed = ''.join(lines).encode()
    ast.parse(sealed)
    for name, row in copies.items():
        need(identity(read_local(row['local_path'])) == pins[name], 'original changed before seal')
    need(read_local(TEMPLATE) == template_raw and read_local(args.receipts) == input_raw, 'seal inputs changed')
    out = args.out
    need(out.is_absolute() and out.parent.resolve(strict=True) == out.parent and not os.path.lexists(out),
         'fresh direct output directory required')
    out.mkdir(mode=0o700)
    seal = {'schema': 'hepta-r35-exact-ci-archive-local-seal/v1', 'status': 'sealed_not_executed',
        'template': TEMPLATE_PIN, 'collector': identity(sealed), 'input': identity(input_raw),
        'actual': actual, 'original_copies': copies, 'native_terminal_view': native_view,
        'original_native_streams': stream_proof, 'qualification_archive_reference_independently_rehashed': False,
        'qualification_archive_reference_source': 'actual original archive digest supplied by coordinator',
        'collector_or_auditor_or_ci_executed': False, 'remote_calls': 0,
        'outcome_scope': 'raw original state preserved; collector later reports binding errors without inventing CI success'}
    for name, raw in [('archive_r35_exact_ci.py', sealed), ('actual-pins.json', encoded(actual)), ('seal-manifest.json', encoded(seal))]:
        with (out / name).open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({'status': 'sealed_not_executed', 'collector': identity(sealed),
                     'original_ci_job': CI_JOB, 'reported_passed': report['passed'],
                     'reported_nextest_counts': counts, 'collector_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
