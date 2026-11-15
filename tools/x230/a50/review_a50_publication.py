#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""A50 source export and offline publication checks; no runtime/build/network calls.

export-source is read-only and prints one bounded transport document. It requires
the caller's independently obtained final qualification/entry/worker SHA pins.
verify-local consumes downloaded originals and that source export; it creates a
new review directory without modifying any original evidence or prepared source.
Neither command claims benchmark adoption or performs a GitHub mutation.
"""

import argparse
import base64
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zlib


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
SOURCE = BASE / 'source-a50-record-batches-r01'
QPATH = BASE / 'qualification-a50-record-batches-r01/report.json'
EPATH = BASE / 'a50-record-batches-entry-r01/entry-report.json'
WPATH = BASE / 'a50-record-batches-entry-r01/worker-report.json'
PARENT_QSHA = '2787841b5242c22e314d46a4e99074fb0b91f04ed4240f230004b5d635c3cd0b'
PARENT_MAP_SHA = 'be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1'
PARENT_OBJECTS_SHA = 'c0ca1f80c2eb2eaebb80bdb8d83dfbf57ce3f2c640364b69c20b0bcb1106c9a6'
PARENT_COMMIT = 'a9ba701676138f7e379dab07b38af27c72c46ed8'
INPUT_MAP_SHA = 'e348cb3fb70a1d9dde8f97d722e65052c2ffba7807d409a2c822d75c314f4dd0'
MANIFEST_SHA = '0ae8e62047cc0948f9e3acf0246db387b77888e0479a47f5eb9ac540bd0a7b9f'
CHANGED = {'src/mcp/runtime/request_archive_content.rs',
           'src/mcp/runtime/request_archive_content_parallel_tests.rs'}
STAGES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')
COMMANDS = (
    ['fmt', '--all'], ['fmt', '--all', '--', '--check'],
    ['clean', '--offline', '--locked', '--package', 'hepta-runtime'],
    ['clippy', '--offline', '--locked', '--all-features', '--all-targets', '--', '-D', 'warnings'],
    ['test', '--offline', '--locked', '--all-features', '--message-format=json-render-diagnostics'],
    ['build', '--offline', '--locked', '--all-features', '--release', '--bins', '--message-format=json-render-diagnostics'],
)
QSCHEMA = 'runtime-candidate-qualification/v1'
ESCHEMA = 'hepta-a50-record-batches-qualification-entry/v1'
WSCHEMA = 'hepta-a50-record-batches-guarded-qualifier-worker/v1'
MAX_JSON = 8 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024
MAX_TOTAL_SOURCE = 32 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def read(path, maximum=MAX_JSON):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, 'direct input path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= maximum, 'bounded single-link regular file required')
        parts, size = [], 0
        while True:
            block = os.read(fd, min(128 * 1024, maximum + 1 - size))
            if not block:
                break
            parts.append(block)
            size += len(block)
            need(size <= maximum, 'input exceeds its fixed bound')
        raw = b''.join(parts)
        need(len(raw) == before.st_size
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'input changed during complete read')
    finally:
        os.close(fd)
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
            'identity': identity(before)}, raw


def fields(receipt):
    return {key: receipt[key] for key in ('path', 'bytes', 'sha256', 'identity')}


def check_documents(q, entry, worker, receipts):
    need(q.get('schema') == QSCHEMA and q.get('qualified') is True
         and q.get('current_stage') == 'complete' and q.get('source') == str(SOURCE)
         and bool(q.get('finished_utc')) and not q.get('error') and not q.get('errors'),
         'A50 qualification is not final successful')
    need([stage['name'] for stage in q['stages']] == list(STAGES)
         and all(type(stage['returncode']) is int and stage['returncode'] == 0 for stage in q['stages']),
         'six successful original stages required')
    source_map = q.get('source_tested')
    need(type(source_map) is dict and len(source_map) == 168 and source_map == q.get('source_after')
         and sha(compact(q['source_input'])) == INPUT_MAP_SHA
         and set(q['source_input']) == set(source_map), 'tested/input/after source maps differ')
    need(entry.get('schema') == ESCHEMA and worker.get('schema') == WSCHEMA,
         'A50 guardian schema differs')
    for key in ('passed', 'qualified', 'guarded_qualification_complete',
                'parent_unchanged_after_attempt', 'reused_dependencies_unchanged'):
        need(entry.get(key) is True, 'A50 entry incomplete: ' + key)
    for key in ('passed', 'strict_fresh_artifacts_verified', 'required_test_coverage_verified',
                'reused_dependencies_unchanged'):
        need(worker.get(key) is True, 'A50 worker incomplete: ' + key)
    need(not entry.get('error') and not entry.get('errors')
         and not worker.get('error') and not worker.get('errors'), 'guardian errors present')
    need([stage['name'] for stage in worker['stages']] == list(STAGES), 'worker stage inventory differs')
    for qualified, guarded, tail in zip(q['stages'], worker['stages'], COMMANDS):
        argv = ['/home/qian/.cargo/bin/cargo', '+1.95.0'] + tail
        need(qualified['command'] == guarded['argv'] == argv
             and guarded.get('executed') is True and guarded.get('execution_count') == 1
             and guarded.get('returncode') == 0 and guarded.get('timeout_seconds') == 1800
             and guarded.get('gate_clear') is True,
             'original stage command, execution or gate summary differs')
    need(entry['source_after'] == source_map, 'final guardian tested source differs')
    for ref in (entry['qualification_report'], worker['qualifier_report'],
                worker['strict_fresh_artifact_evidence']['qualification_report']):
        need(fields(ref) == receipts['qualification'], 'guardian qualification cross-receipt differs')
    need(fields(entry['guarded_worker_report']) == receipts['worker'], 'final worker cross-receipt differs')
    if 'worker_report' in entry:
        need(fields(entry['worker_report']) == receipts['worker'], 'optional final worker receipt differs')
    custody = entry['worker_custody']
    need(custody.get('original_child_reaped') is True
         and type(custody.get('raw_wait_status')) is int and custody['raw_wait_status'] == 0
         and custody.get('returncode') == 0 and custody.get('custody_retained_until_reap') is True
         and custody.get('group_quiet_before_reap') is True
         and custody.get('executed') is True and custody.get('execution_count') == 1
         and custody.get('actual_waitpid') == custody.get('pid')
         and custody.get('original_identity', {}).get('pid') == custody.get('pid')
         and custody.get('pidfd_opened') is True and custody.get('custody_known') is True
         and custody.get('outer_work_budget_exceeded') is False
         and not custody.get('signals') and not custody.get('error') and not custody.get('errors'),
         'original qualification worker completion/custody incomplete')
    for name, stage_name, is_test in (('test_binary', 'test', True), ('binary', 'release', False)):
        need(q[name].get('cached') is False
             and q[name]['compiler_source'] == str(SOURCE / 'src/main.rs'),
             'source-bound fresh artifact declaration missing')
        evidence = worker['strict_fresh_artifact_evidence']['compiler_artifacts'][stage_name]
        event = evidence['original_event']
        stage = next(value for value in q['stages'] if value['name'] == stage_name)
        need(evidence['copied_artifact'] == q[name] and evidence.get('fresh_strictly_false') is True
             and evidence['log']['sha256'] == stage['log_sha256']
             and event.get('fresh') is False and event.get('reason') == 'compiler-artifact'
             and event.get('profile', {}).get('test') is is_test
             and event.get('manifest_path') == str(SOURCE / 'Cargo.toml')
             and event.get('target', {}).get('name') == 'hepta-runtime'
             and event['target'].get('src_path') == q[name]['compiler_source'],
             'strict fresh artifact/event/report binding differs')
    return source_map


def inventory():
    need(SOURCE.resolve(strict=True) == SOURCE, 'source root is not direct')
    result = {}
    for path in sorted(SOURCE.rglob('*')):
        value = path.lstat()
        need(not stat.S_ISLNK(value.st_mode), 'source symlink refused')
        if stat.S_ISREG(value.st_mode):
            result[str(path.relative_to(SOURCE))] = identity(value)
        else:
            need(stat.S_ISDIR(value.st_mode), 'unexpected special source member')
    return result


def git_blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def export_source(args):
    receipts, bodies = {}, {}
    for name, path, expected in (
        ('qualification', QPATH, args.qualification_sha256),
        ('entry', EPATH, args.entry_sha256), ('worker', WPATH, args.worker_sha256)):
        need(re.fullmatch('[0-9a-f]{64}', expected), 'complete caller-supplied final SHA required')
        receipts[name], bodies[name] = read(path)
        need(receipts[name]['sha256'] == expected, 'pinned report bytes differ: ' + name)
    q, entry, worker = (document(bodies[name]) for name in ('qualification', 'entry', 'worker'))
    tested = check_documents(q, entry, worker, receipts)
    need({path for path in tested if tested[path] != q['source_input'][path]} <= CHANGED,
         'formatting changed a source outside the two declared candidate paths')
    before = inventory()
    need(set(before) == set(tested), 'actual source inventory differs from tested map')
    rows, exports, total = [], {}, 0
    for path in sorted(tested):
        receipt, raw = read(SOURCE / path, MAX_SOURCE)
        total += len(raw)
        need(total <= MAX_TOTAL_SOURCE and receipt['identity'] == before[path]
             and receipt['sha256'] == tested[path], 'actual qualified source body differs')
        row = {**receipt, 'path': path, 'git_blob_sha': git_blob(raw)}
        rows.append(row)
        if path in CHANGED:
            raw.decode('utf-8')
            exports[path] = {'bytes': len(raw), 'sha256': sha(raw),
                             'git_blob_sha': row['git_blob_sha'],
                             'base64': base64.b64encode(raw).decode()}
    need(inventory() == before, 'source inventory/identity changed during export')
    for name, receipt in receipts.items():
        need(read(Path(receipt['path']))[0] == receipt, 'original report changed during source export')
    proof = {'schema': 'hepta-a50-qualified-source-export/v1', 'candidate': 'a50',
             'generated_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'source': str(SOURCE), 'source_files': 168, 'source_map': tested,
             'source_map_compact_sha256': sha(compact(tested)),
             'prepared_source_map_compact_sha256': INPUT_MAP_SHA,
             'parent_source_map_compact_sha256': PARENT_MAP_SHA, 'parent_git_commit': PARENT_COMMIT,
             'original_report_receipts': receipts, 'rows': rows, 'changed_exports': exports,
             'all_qualified_sources_sha256_match': True,
             'source_inventory_and_identities_unchanged_during_export': True,
             'export_contains_all_source_bodies': False,
             'actual_source_bodies_read': 168, 'exported_source_bodies': 2,
             'benchmark_or_build_executions': 0, 'file_writes': 0,
             'elf_bodies_read': False, 'stage_log_bodies_read': False,
             'github_tree_read_or_mutated': False}
    raw = compact(proof) + b'\n'
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    print(json.dumps({'schema': 'hepta-a50-source-export-transport/v1',
        'raw_bytes': len(raw), 'raw_sha256': sha(raw),
        'gzip_bytes': len(compressed), 'gzip_sha256': sha(compressed),
        'gzip_base64': base64.b64encode(compressed).decode()}, sort_keys=True), flush=True)


def decode_export(path):
    transport_receipt, raw = read(path)
    value = document(raw)
    if value.get('schema') == 'hepta-a50-source-export-transport/v1':
        compressed = base64.b64decode(value['gzip_base64'], validate=True)
        need(len(compressed) == value['gzip_bytes'] and sha(compressed) == value['gzip_sha256'],
             'compressed source export differs')
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = decoder.decompress(compressed, MAX_JSON + 1)
        need(len(raw) <= MAX_JSON and decoder.eof and not decoder.unused_data
             and not decoder.unconsumed_tail, 'source export gzip is incomplete/oversized/multimember')
        need(len(raw) == value['raw_bytes'] and sha(raw) == value['raw_sha256'],
             'decoded source export differs')
        value = document(raw)
    need(value.get('schema') == 'hepta-a50-qualified-source-export/v1', 'unknown source export schema')
    return value, raw, transport_receipt


def tests_from_log(raw, names):
    text = raw.decode('utf-8')
    pattern = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; '
        r'(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$', re.M)
    summaries = [{'line': match.group(0), 'result': match[1], 'passed': int(match[2]),
        'failed': int(match[3]), 'ignored': int(match[4]), 'measured': int(match[5]),
        'filtered_out': int(match[6]), 'counted_as_top_level': int(match[6]) == 0}
        for match in pattern.finditer(text)]
    top = [row for row in summaries if row['counted_as_top_level']]
    need([(row['passed'], row['failed'], row['ignored'], row['measured']) for row in top]
         == [(18, 0, 0, 0), (1246, 0, 23, 0), (8, 0, 0, 0)]
         and all(row['result'] == 'ok' and row['failed'] == 0 for row in summaries),
         'actual full-test summary differs; do not publish the expected count as a result')
    lines = {name: re.findall(r'^test (?:[^\r\n]*::)?' + re.escape(name) + r' \.\.\. ok$', text, re.M)
             for name in names}
    need(len(lines) == 19 and all(lines.values()), 'missing required successful full-suite test names')
    return {'top_level_passed': 1272, 'top_level_failed': 0, 'top_level_ignored': 23,
        'raw_summary_lines': summaries, 'required_name_count': 19,
        'matching_successful_line_count': sum(map(len, lines.values())),
        'successful_execution_lines': lines,
        'nested_filtered_summaries_excluded': sum(not row['counted_as_top_level'] for row in summaries)}


def create(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def verify_local(args):
    proof, proof_raw, transport_receipt = decode_export(args.source_export)
    manifest_receipt, manifest_raw = read(args.overlay_manifest)
    need(manifest_receipt['sha256'] == MANIFEST_SHA, 'frozen A50 overlay manifest differs')
    manifest = document(manifest_raw)
    records, originals = {}, {}
    for name, filename in (('qualification', 'qualification.json'), ('entry', 'entry-report.json'),
                           ('worker', 'worker-report.json'), ('test_log', 'test.log')):
        records[name], originals[name] = read(args.evidence_dir / filename)
    remote = proof['original_report_receipts']
    for name in ('qualification', 'entry', 'worker'):
        need(all(records[name][key] == remote[name][key] for key in ('bytes', 'sha256')),
             'downloaded original body differs from the source-export binding: ' + name)
    q, entry, worker = (document(originals[name]) for name in ('qualification', 'entry', 'worker'))
    tested = check_documents(q, entry, worker, remote)
    need(tested == proof['source_map'] and sha(compact(tested)) == proof['source_map_compact_sha256']
         and proof['prepared_source_map_compact_sha256'] == INPUT_MAP_SHA,
         'actual tested source export/map differs')
    parent_receipt, parent_raw = read(args.parent_object_map)
    need(parent_receipt['sha256'] == PARENT_OBJECTS_SHA, 'published parent object proof differs')
    parent = document(parent_raw)
    need(parent['qualification_sha256'] == PARENT_QSHA, 'parent object proof qualification differs')
    parent_rows = {row['path']: row for row in parent['rows']}
    rows = {row['path']: row for row in proof['rows']}
    need(len(rows) == len(proof['rows']) == 168 and set(rows) == set(parent_rows) == set(tested),
         'complete source object inventory differs')
    need({path: row['sha256'] for path, row in rows.items()} == tested
         and sha(compact({path: row['sha256'] for path, row in parent_rows.items()})) == PARENT_MAP_SHA,
         'source object hashes differ from the qualified maps')
    changed = {path for path in tested if tested[path] != parent_rows[path]['sha256']}
    need(changed == CHANGED == set(proof['changed_exports']), 'unexpected tested-source change set')
    for path in set(tested) - CHANGED:
        need(all(rows[path][key] == parent_rows[path][key] for key in ('bytes', 'sha256', 'git_blob_sha')),
             'unchanged source Git identity differs: ' + path)
    source_bodies = {}
    for path in sorted(CHANGED):
        export = proof['changed_exports'][path]
        raw = base64.b64decode(export['base64'], validate=True)
        need(len(raw) == export['bytes'] == rows[path]['bytes']
             and sha(raw) == export['sha256'] == rows[path]['sha256']
             and git_blob(raw) == export['git_blob_sha'] == rows[path]['git_blob_sha'],
             'actual changed source export body differs: ' + path)
        source_bodies[path] = raw
    test_stage = next(stage for stage in q['stages'] if stage['name'] == 'test')
    need(records['test_log']['sha256'] == test_stage['log_sha256'], 'original test log SHA differs')
    tests = tests_from_log(originals['test_log'], manifest['new_tests'] + manifest['required_existing_test_coverage'])
    events = []
    for line in originals['test_log'].splitlines():
        try:
            event = document(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if (isinstance(event, dict) and event.get('reason') == 'compiler-artifact'
                and event.get('target', {}).get('name') == 'hepta-runtime'
                and event.get('profile', {}).get('test') is True):
            events.append(event)
    need(len(events) == 1 and events[0].get('fresh') is False
         and events[0].get('manifest_path') == str(SOURCE / 'Cargo.toml')
         and events[0]['target'].get('src_path') == q['test_binary']['compiler_source'],
         'actual test compiler event is not singular fresh=false/source-bound')
    out = args.out.absolute()
    need(not os.path.lexists(out) and out.parent.resolve(strict=True) == out.parent,
         'fresh direct local review output required')
    out.mkdir(mode=0o700)
    for path, raw in source_bodies.items():
        create(out / 'source' / path, raw)
    create(out / 'source-export.original.json', proof_raw)
    create(out / 'source-tested-map.json', compact(tested) + b'\n')
    source_objects = {'schema': 'hepta-qualified-source-git-object-map/v1', 'candidate': 'a50',
        'qualification_path': str(QPATH), 'qualification_sha256': remote['qualification']['sha256'],
        'source': str(SOURCE), 'source_files': 168, 'rows': proof['rows'],
        'all_qualified_sources_sha256_match': True, 'benchmark_or_build_executions': 0,
        'derived_from_exact_read_only_export_sha256': sha(proof_raw)}
    create(out / 'qualified-git-object-map.json', compact(source_objects) + b'\n')
    review = {'schema': 'hepta-a50-local-publication-qualification-review/v1',
        'actual_qualification_and_source_checks_completed': True, 'inputs': records,
        'source_export_transport': transport_receipt, 'source_export_sha256': sha(proof_raw),
        'overlay_manifest': manifest_receipt, 'parent_source_object_map': parent_receipt,
        'source_map_compact_sha256': sha(compact(tested)), 'source_files': 168,
        'changed_source_paths': sorted(CHANGED), 'unchanged_parent_object_rows': 166,
        'formatted_changed_paths': sorted(path for path in tested if tested[path] != q['source_input'][path]),
        'tests': tests, 'original_test_compiler_event': events[0],
        'release_sha256_from_qualified_receipt': q['binary']['sha256'],
        'test_elf_sha256_from_qualified_receipt': q['test_binary']['sha256'],
        'source_publication_inputs': [{**rows[path], 'mode': '100644', 'type': 'blob',
            'local_path': str(out / 'source' / path)} for path in sorted(CHANGED)],
        'scope': {'downloaded_report_and_test_log_bodies_rehashed': True,
            'source_bodies_rehashed_by_read_only_export': 168, 'changed_source_bodies_rehashed_locally': 2,
            'elf_bodies_read_locally': False, 'release_log_body_read_locally': False,
            'raw_host_gate_bodies_read_locally': False, 'github_tree_read_locally': False,
            'credential_review_completed': False, 'performance_results_reviewed': False,
            'performance_adopted': None, 'publication_ready': False}}
    create(out / 'review.json', json.dumps(review, indent=2, sort_keys=True).encode() + b'\n')
    print(json.dumps({'review': str(out / 'review.json'), 'source_files': 168,
        'top_level_tests': tests['top_level_passed'], 'ignored': tests['top_level_ignored'],
        'required_test_names': tests['required_name_count'],
        'publication_ready': False, 'performance_results_reviewed': False}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    export = commands.add_parser('export-source')
    for name in ('qualification', 'entry', 'worker'):
        export.add_argument('--' + name + '-sha256', required=True)
    local = commands.add_parser('verify-local')
    local.add_argument('--evidence-dir', type=Path, required=True)
    local.add_argument('--source-export', type=Path, required=True)
    local.add_argument('--overlay-manifest', type=Path, required=True)
    local.add_argument('--parent-object-map', type=Path, required=True)
    local.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'export-source':
        export_source(args)
    else:
        verify_local(args)


if __name__ == '__main__':
    main()
