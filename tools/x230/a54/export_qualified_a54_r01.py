#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Export actual A54 r01 qualified source/gates/test coverage without launching work.

Run only after the root agent supplies the three actual report SHA256 pins.
Every input is read as a stable direct single-link regular file, with a final
receipt fence. The only write is one new fixed evidence gzip outside the source
tree. No Cargo, test, benchmark, SSH, signal or subprocess operation is present.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat


BASE = Path('/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01')
SOURCE = BASE / 'source-a54-compact-view-r01'
QUALIFICATION = BASE / 'qualification-a54-compact-view-r01/report.json'
PREP = BASE / 'a54-compact-view-entry-r01'
DESTINATION = BASE / 'a54-r01-qualified-source-export-r01.json.gz'
PREPARED_MAP_SHA = '5b128908b61e4a3f5f8c1ed951ec184eddf2a9b79361e6a16d5a80b0ded98d88'
CHANGED = ('src/mcp/runtime/request_archive_codec.rs', 'src/mcp/runtime/request_archive_content.rs',
           'src/mcp/runtime/request_archive_content_tests.rs')
STAGES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')
BUSY = ('cargo', 'cargo-clippy', 'clippy-driver', 'rustc', 'heptabao_server')
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_FILE = 16 * 1024 * 1024
EXPECTED_TESTS = (
    'borrowed_compact_order_matches_owned_keys_across_binary_and_optional_boundaries',
    'serial_borrowed_and_legacy_rows_refuse_every_record_and_stamp_disagreement',
    'malformed_compact_base_never_falls_back_or_hides_behind_a_pending_completion',
    'corrupt_base_order_still_refuses_a_valid_pending_terminal_replacement',
    'legacy_row_json_whitespace_escapes_and_strict_errors_keep_the_original_domain',
    'borrowed_matching_keeps_lowercase_id_domain_and_accepts_decoded_json_escapes',
    'serial_complete_join_checks_another_owners_original_with_both_row_encodings',
)
RETAINED_TESTS = (
    'complete_content_gate_reads_originals_and_refuses_a_different_time_in_the_derived_view',
    'complete_content_gate_joins_pending_additions_and_terminal_replacements_without_writes',
    'complete_content_gate_preserves_an_ignored_old_pending_state',
    'complete_content_gate_refuses_missing_base_and_pending_members',
    'complete_content_gate_refuses_staging_without_removing_either_fixture_file',
    'complete_content_gate_and_cold_phase_refuse_an_already_expired_budget',
    'cold_content_fence_checks_generation_even_without_a_watch_version',
    'cached_content_acceptance_recovers_a_legal_terminal_record_with_the_same_stamp',
    'cached_content_disagreement_is_an_error_instead_of_an_empty_rebuild_request',
    'cold_original_time_conflict_with_a_stale_derived_stamp_is_not_a_rebuild_request',
    'cold_legal_completion_with_a_stale_derived_stamp_still_recovers',
    'cold_original_unknown_does_not_silently_agree_with_a_terminal_derived_row',
)
TEST_PREFIX = 'mcp::runtime::request_audit::index::content::tests::'
FINAL_BINDINGS_READY = True
ACTUAL_QUALIFICATION_SHA = '49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c'
ACTUAL_ENTRY_SHA = 'a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3'
ACTUAL_WORKER_SHA = 'b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90'



def need(value, message):
    if not value:
        raise ValueError(message)


def require_bindings(args):
    need(FINAL_BINDINGS_READY is True, 'A54 actual qualification bindings pending; export refused')
    expected = (ACTUAL_QUALIFICATION_SHA, ACTUAL_ENTRY_SHA, ACTUAL_WORKER_SHA)
    actual = (args.qualification_sha, args.entry_sha, args.worker_sha)
    need(all(type(value) is str and HEX.fullmatch(value) for value in expected)
         and actual == expected, 'all three frozen actual report SHA pins required before export')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def map_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def identity(value):
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns]


def original(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct original path required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= MAX_FILE,
             'bounded single-link regular original required: ' + str(path))
        parts, count = [], 0
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            count += len(part)
            need(count <= MAX_FILE, 'original grew past bound')
            parts.append(part)
        raw = b''.join(parts)
        need(count == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'original changed during read: ' + str(path))
    finally:
        os.close(fd)
    receipt = {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw), 'identity': identity(before)}
    need(expected is None or receipt['sha256'] == expected, 'original SHA differs: ' + str(path))
    return raw, receipt


def source_names():
    need(SOURCE.resolve(strict=True) == SOURCE and SOURCE.is_dir(), 'direct qualified source root required')
    names = set()
    for directory, directories, files in os.walk(SOURCE, followlinks=False):
        for name in directories:
            need(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), 'non-directory/symlink in qualified tree')
        for name in files:
            path = Path(directory) / name
            need(stat.S_ISREG(path.lstat().st_mode), 'nonregular/symlink in qualified tree')
            relative = path.relative_to(SOURCE).as_posix()
            need(relative not in names, 'duplicate qualified path')
            names.add(relative)
    return names


def parse_test_log(raw, source_raw, recorded_results):
    """Read exact libtest records; filtered nested suites never enter totals."""
    names = re.findall(r'^\s*#\[(?:tokio::)?test(?:\([^\]\n]*\))?\]\s*\n\s*(?:async\s+)?fn\s+(\w+)\s*\(',
                       source_raw.decode('utf-8'), re.MULTILINE)
    need(len(names) == len(set(names)) == 19
         and set(names) == set(RETAINED_TESTS) | set(EXPECTED_TESTS),
         'actual formatted A54 source does not retain the 12 existing and seven new frozen tests')
    lines = raw.decode('utf-8').splitlines()
    coverage = []
    for name in EXPECTED_TESTS:
        pattern = re.compile(r'^test ' + re.escape(TEST_PREFIX + name) + r' \.\.\. (.*)$')
        matches = [(index + 1, line, pattern.fullmatch(line)) for index, line in enumerate(lines)
                   if pattern.fullmatch(line)]
        need(len(matches) == 1 and matches[0][2].group(1) == 'ok',
             'new test is missing, duplicated, failed or ignored: ' + name)
        coverage.append({'name': name, 'source': CHANGED[2], 'qualified_name': TEST_PREFIX + name,
                         'line_number': matches[0][0], 'actual_log_line': matches[0][1]})
    result_pattern = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                                r'(\d+) measured; (\d+) filtered out;[^\r\n]*$')
    results = []
    for index, line in enumerate(lines):
        match = result_pattern.fullmatch(line)
        if match:
            results.append({'line_number': index + 1, 'actual_log_line': line,
                            'outcome': match.group(1), 'passed': int(match.group(2)),
                            'failed': int(match.group(3)), 'ignored': int(match.group(4)),
                            'measured': int(match.group(5)), 'filtered_out': int(match.group(6))})
    need(results and [row['actual_log_line'] for row in results] == recorded_results,
         'actual original suite results differ from the qualification report')
    need(all(row['outcome'] == 'ok' and row['failed'] == 0 and row['measured'] == 0 for row in results),
         'failed or measured suite result in the original test log')
    top = [row for row in results if row['filtered_out'] == 0]
    nested = [row for row in results if row['filtered_out'] != 0]
    need(top and sum(row['passed'] for row in top) >= 7, 'complete unfiltered suite totals missing')
    return coverage, {'all_original_results': results, 'top_level_results': top,
                      'filtered_nested_results_excluded_from_totals': nested,
                      'top_level_passed': sum(row['passed'] for row in top),
                      'top_level_failed': sum(row['failed'] for row in top),
                      'top_level_ignored': sum(row['ignored'] for row in top),
                      'new_tests_observed_exactly_once': len(coverage), 'full_log_lines': len(lines)}


def verify_gate(value):
    snapshot = value['snapshot']
    need(type(snapshot['processes']) is list and snapshot['required_fields_present'] is True
         and snapshot['errors'] == [] and {'loadavg', 'stat', 'meminfo', 'uptime'} <= snapshot.keys(),
         'complete original stage snapshot required')
    busy = [row for row in snapshot['processes'] if row['comm'] in BUSY and row['state'] not in ('Z', 'X', 'x')]
    memory = re.findall(r'^MemAvailable:\s+(\d+)\s+kB\s*$', snapshot['meminfo'], flags=re.MULTILINE)
    need(len(memory) == 1 and type(value['mem_available_kib']) is int
         and value['mem_available_kib'] == int(memory[0]) and type(value['disk_available_bytes']) is int
         and value['disk_available_bytes'] >= 0 and value['matching_live_processes'] == busy
         and value['resource_errors'] == [] and value['resource_thresholds'] == {
             'mem_available_kib_min': 2097152, 'disk_available_bytes_min': 2147483648},
         'original stage resource projection differs')
    need(value['clear'] is True and not busy and value['mem_available_kib'] >= 2097152
         and value['disk_available_bytes'] >= 2147483648, 'original stage clear outcome differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-sha', required=True)
    parser.add_argument('--entry-sha', required=True)
    parser.add_argument('--worker-sha', required=True)
    args = parser.parse_args()
    require_bindings(args)
    need(DESTINATION.parent.resolve(strict=True) == DESTINATION.parent and not os.path.lexists(DESTINATION),
         'fresh fixed evidence destination required')
    receipts = []

    def read(path, expected=None):
        raw, receipt = original(path, expected)
        receipts.append(receipt)
        return raw, receipt

    _, self_receipt = read(Path(__file__).absolute())
    qraw, qr = read(QUALIFICATION, args.qualification_sha)
    eraw, er = read(PREP / 'entry-report.json', args.entry_sha)
    wraw, wr = read(PREP / 'worker-report.json', args.worker_sha)
    q, entry, worker = map(json.loads, (qraw, eraw, wraw))
    need(q['schema'] == 'runtime-candidate-qualification/v1' and q['qualified'] is True
         and q['current_stage'] == 'complete' and q['service_changes'] is False
         and not q.get('error') and q['source'] == str(SOURCE), 'actual completed A54 r01 qualification required')
    mapping = q['source_tested']
    need(mapping == q['source_after'] and len(mapping) == 175 and set(mapping) == set(q['source_input'])
         and map_sha(q['source_input']) == PREPARED_MAP_SHA
         and all(type(value) is str and HEX.fullmatch(value) for value in mapping.values()), 'actual A54 source maps differ')
    need(all(mapping[name] == value for name, value in q['source_input'].items() if name not in CHANGED),
         'unrelated parent source changed')
    need(entry['schema'] == 'hepta-a54-compact-view-qualification-entry/v1'
         and entry['qualified'] is True and entry['errors'] == [] and not entry.get('error')
         and entry['candidate_source'] == str(SOURCE) and entry['candidate_source_map'] == q['source_input']
         and entry['parent_and_input_fence_unchanged'] is True and entry['retained_parent_git_blobs_verified'] is True
         and entry['repository_base_commit'] == 'b20bcf02cfe72b3873c5c03180e4028ea673067f'
         and entry['repository_base_tree'] == '84d5caea62cceaf41b59a354185c85439a6fa0e8', 'A54 parent/entry fence differs')
    need(worker['schema'] == 'hepta-a54-compact-view-qualification-worker/v1'
         and worker['passed'] is True and not worker.get('error') and not worker.get('errors')
         and worker['qualifier_report'] == qr, 'A54 original worker/report receipt differs')
    need(tuple(row['name'] for row in q['stages']) == STAGES and len(worker['stages']) == 6,
         'six original stages required')
    for value in (entry, worker):
        env = value['environment']
        need(value['automatic_retry'] is False and value['service_changes'] is False
             and env['stage_umask'] == '022' and env['metadata_trace_enabled'] is False and env['agent_accesses'] == 0
             and all(env['fixed_values'][key] == setting for key, setting in {
                 'CARGO_BUILD_JOBS': '2', 'CARGO_INCREMENTAL': '0',
                 'TOKIO_WORKER_THREADS': '2', 'RUST_TEST_THREADS': '2'}.items()), 'original qualification environment differs')
    need(source_names() == set(mapping), 'actual current source inventory differs')
    sources = {}
    for name, expected in sorted(mapping.items()):
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name,
             'unsafe qualified source name')
        raw, receipt = read(SOURCE / relative, expected)
        if name in CHANGED:
            sources[name] = {**receipt, 'text': raw.decode('utf-8')}
    need(set(sources) == set(CHANGED), 'three changed original source bodies required')
    gates = {}
    for index, (qs, ws) in enumerate(zip(q['stages'], worker['stages'])):
        need(qs['name'] == ws['name'] and qs['command'] == ws['argv']
             and type(qs['returncode']) is int and qs['returncode'] == 0
             and type(ws['returncode']) is int and ws['returncode'] == 0
             and ws['executed'] is True and ws['execution_count'] == 1 and ws['gate_clear'] is True
             and ws['timeout_seconds'] == 1800 and not ws.get('error'), 'guarded original stage differs')
        name = 'stage-%d-%s.host-gate.json' % (index, qs['name'])
        raw, receipt = read(PREP / name, ws['host_gate']['sha256'])
        need(receipt == ws['host_gate'], 'original host gate stat9 receipt differs')
        verify_gate(json.loads(raw))
        gates[name] = {**receipt, 'text': raw.decode('utf-8')}
    log_raw, log_receipt = read(QUALIFICATION.parent / 'test.log', q['stages'][4]['log_sha256'])
    coverage, summary = parse_test_log(log_raw, sources[CHANGED[2]]['text'].encode(), q['stages'][4]['results'])
    for receipt in receipts:
        _, current = original(Path(receipt['path']), receipt['sha256'])
        need(current == receipt, 'original input changed at final export fence')
    need(source_names() == set(mapping), 'source inventory changed at final export fence')
    result = {'schema': 'hepta-a54-r01-qualified-source-export/v1', 'exporter': self_receipt,
              'qualification': qr, 'entry': er, 'worker': wr, 'qualification_sha256': args.qualification_sha,
              'source_files': 175, 'source_map': mapping, 'source_map_compact_sha256': map_sha(mapping),
              'prepared_source_map_compact_sha256': PREPARED_MAP_SHA,
              'sources': sources, 'stages': gates, 'new_test_coverage': coverage,
              'test_log': log_receipt, 'test_log_summary': summary,
              'binary_declared_by_qualification': q['binary'], 'test_binary_declared_by_qualification': q['test_binary'],
              'source_bodies_rehashed': 175, 'changed_source_bodies_exported': 3, 'host_gate_bodies_exported': 6,
              'artifact_bodies_rehashed_by_this_export': False, 'original_test_log_body_retained_at_original_path': True,
              'all_inputs_unchanged_through_export_read_fence': True, 'input_receipts': receipts,
              'runtime_executions': 0, 'performance_adoption_claimed': False,
              'scope': 'Actual source and original qualification/test evidence export only; no new runtime, performance or multi-host acceptance run.'}
    plain = canonical(result)
    packed = gzip.compress(plain, mtime=0)
    fd = os.open(DESTINATION, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(packed)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(DESTINATION.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({'path': str(DESTINATION), 'bytes': len(packed), 'sha256': sha(packed),
                      'uncompressed_bytes': len(plain), 'uncompressed_sha256': sha(plain),
                      'new_tests': len(coverage), 'top_level_passed': summary['top_level_passed'],
                      'top_level_ignored': summary['top_level_ignored'],
                      'source_map_compact_sha256': map_sha(mapping), 'runtime_executions': 0}), flush=True)


if __name__ == '__main__':
    main()
