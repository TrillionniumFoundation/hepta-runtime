#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Verify a complete actual A55 export and extract its exact source/log bodies.

All actual report pins and the already frozen exporter manifest are mandatory.
Only local originals are read. No exporter, Rust, runtime or child is launched.
Expected test counts are never substituted for the complete observed test log.
"""
import argparse
import ast
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import types


ROOT = Path(__file__).resolve().parents[2]
BASE = '/home/qian/hepta-runtime-optimization-20261023/a41-phase-timing-20261025-r01'
VALIDATOR = ROOT / 'ci-audit/a55/actual_qualification_support_r01.py'
VALIDATOR_SHA = '2455ff42cb2ff2a6d6607063970c4fa4d294a51a32ebd83af62207991e975b66'
EXPORT_TEMPLATE = ROOT / 'recovery-review/a55-qualification/export-pending-r01/export_qualified_a55_r01.py'
EXPORT_TEMPLATE_SHA = '4b2d6b12f07e8e394f3c9fe605e5971e5265705d82475f99038b5549484de871'
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_BYTES = 2 * 1024 * 1024
STAGES = ('format', 'fmt-check', 'clean-package', 'clippy', 'test', 'release')


def need(value, message):
    if not value:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def json_value(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def constants(raw, names):
    result = {}
    for node in ast.parse(raw).body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names):
            name = node.targets[0].id
            need(name not in result, 'duplicate frozen exporter assignment')
            result[name] = ast.literal_eval(node.value)
    need(set(result) == set(names), 'missing frozen exporter assignment')
    return result


def receipt(row):
    need(set(row) == {'path', 'bytes', 'sha256', 'identity'}
         and type(row['path']) is str and Path(row['path']).is_absolute()
         and '..' not in Path(row['path']).parts and type(row['bytes']) is int
         and 0 <= row['bytes'] <= 16 * 1024 * 1024
         and type(row['sha256']) is str and HEX.fullmatch(row['sha256']),
         'original receipt shape differs')
    value = row['identity']
    need(type(value) is list and len(value) == 9 and all(type(x) is int for x in value)
         and stat.S_ISREG(value[2]) and value[5] == 1 and value[6] == row['bytes'],
         'original stat9 regular/single-link/length receipt differs')


def original_test_log(raw, sources, frozen, recorded_results):
    """Independently reconstruct declarations, exact rows and all suite totals."""
    retained, prefixes = frozen['RETAINED_TESTS'], frozen['TEST_PREFIX']
    new, expanded = frozen['EXPECTED_TESTS'], frozen['EXPECTED_EXTENDED_TESTS']
    need(len(new) == 5 and len(expanded) == 6 and set(retained) == set(prefixes),
         'frozen new/expanded test contract differs')
    declarations = {}
    for source, expected in retained.items():
        names = re.findall(r'^\s*#\[(?:tokio::)?test(?:\([^\]\n]*\))?\]\s*\n\s*(?:async\s+)?fn\s+(\w+)\s*\(',
                           sources[source]['text'], re.MULTILINE)
        added = {row['name'] for row in new if row['source'] == source}
        need(len(names) == len(set(names)) and set(names) == set(expected) | added,
             'actual formatted test declarations differ')
        declarations[source] = {'retained': len(expected), 'new': len(added),
                                'total': len(names), 'names': names}
    need(sum(row['retained'] for row in declarations.values()) == 69
         and sum(row['total'] for row in declarations.values()) == 74,
         'complete selected test declaration inventory differs')
    lines = raw.decode('utf-8').splitlines()

    def coverage(cases):
        output = []
        for row in cases:
            source, name, qualified = row['source'], row['name'], row['qualified_name']
            need(name in declarations[source]['names'] and qualified == prefixes[source] + name,
                 'test source/name/module identity differs')
            pattern = re.compile(r'^test ' + re.escape(qualified) + r' \.\.\. (.*)$')
            matches = [(index + 1, line, pattern.fullmatch(line)) for index, line in enumerate(lines)
                       if pattern.fullmatch(line)]
            need(len(matches) == 1 and matches[0][2].group(1) == 'ok',
                 'new/expanded test missing, duplicated, failed or ignored')
            output.append({**row, 'line_number': matches[0][0], 'actual_log_line': matches[0][1]})
        return output

    new_coverage, expanded_coverage = coverage(new), coverage(expanded)
    pattern = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
                         r'(\d+) measured; (\d+) filtered out;[^\r\n]*$')
    results = []
    for index, line in enumerate(lines):
        match = pattern.fullmatch(line)
        if match:
            results.append({'line_number': index + 1, 'actual_log_line': line,
                            'outcome': match.group(1), 'passed': int(match.group(2)),
                            'failed': int(match.group(3)), 'ignored': int(match.group(4)),
                            'measured': int(match.group(5)), 'filtered_out': int(match.group(6))})
    need(results and [row['actual_log_line'] for row in results] == recorded_results,
         'whole original log results differ from actual qualification')
    need(all(row['outcome'] == 'ok' and row['failed'] == row['measured'] == 0 for row in results),
         'failed/measured original suite result')
    top = [row for row in results if row['filtered_out'] == 0]
    nested = [row for row in results if row['filtered_out'] != 0]
    need(top and sum(row['passed'] for row in top) >= len(new), 'unfiltered suite results missing')
    summary = {'all_original_results': results, 'top_level_results': top,
               'filtered_nested_results_excluded_from_totals': nested,
               'top_level_passed': sum(row['passed'] for row in top),
               'top_level_failed': sum(row['failed'] for row in top),
               'top_level_ignored': sum(row['ignored'] for row in top),
               'new_tests_observed_exactly_once': len(new_coverage),
               'extended_tests_observed_exactly_once': len(expanded_coverage),
               'test_source_declarations': declarations, 'full_log_lines': len(lines)}
    return new_coverage, expanded_coverage, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-sha', required=True)
    parser.add_argument('--expected-bytes', type=int, required=True)
    parser.add_argument('--job-id', required=True)
    parser.add_argument('--download-receipt', type=Path, required=True)
    parser.add_argument('--download-receipt-sha', required=True)
    parser.add_argument('--export-freeze', type=Path, required=True)
    parser.add_argument('--export-freeze-sha', required=True)
    for name in ('qualification', 'entry', 'worker'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha', required=True)
    args = parser.parse_args()
    inputs = {}

    def read(path, expected):
        path = Path(path).absolute()
        need(type(expected) is str and HEX.fullmatch(expected), 'independent SHA pin required')
        need(path.resolve(strict=True) == path and path.is_file(), 'direct local original required')
        raw = path.read_bytes()
        need(len(raw) <= MAX_BYTES and digest(raw) == expected, 'local original identity differs')
        need(path not in inputs or inputs[path] == raw, 'local input changed between reads')
        inputs[path] = raw
        return raw

    validator_raw = read(VALIDATOR, VALIDATOR_SHA)
    validator = types.ModuleType('a55_download_actual_qualification_validator')
    validator.__file__ = str(VALIDATOR)
    exec(compile(validator_raw, str(VALIDATOR), 'exec'), validator.__dict__)
    reports = {name: json_value(read(getattr(args, name), getattr(args, name + '_sha')))
               for name in ('qualification', 'entry', 'worker')}
    actual = validator.actual_bindings(args)
    need(actual is not None and actual['ready'] is True, 'actual qualified source required')
    q, worker = reports['qualification'], reports['worker']
    freeze = json_value(read(args.export_freeze, args.export_freeze_sha))
    need(freeze['schema'] == 'hepta-a55-qualified-source-export-freeze/v1'
         and freeze['ready'] is True and freeze['export_executed'] is False
         and freeze['template_sha256'] == EXPORT_TEMPLATE_SHA
         and freeze['actual_bindings'] == {k: v for k, v in actual.items() if k != 'tested_map'},
         'actual exporter freeze/qualification binding differs')
    exporter = freeze['script']
    exporter_raw = read(args.export_freeze.parent / Path(exporter['path']).name, exporter['sha256'])
    need(len(exporter_raw) == exporter['bytes'], 'actual exporter length differs')
    template_raw = read(EXPORT_TEMPLATE, EXPORT_TEMPLATE_SHA)
    restored = exporter_raw.decode()
    need(len(freeze['binding_changes']) == 4, 'only four exporter bindings allowed')
    for row in reversed(freeze['binding_changes']):
        need(restored.count(row['after']) == 1, 'unique exporter binding inverse required')
        restored = restored.replace(row['after'], row['before'])
    need(restored.encode() == template_raw, 'exporter differs beyond reviewed actual bindings')
    names = ('CHANGED', 'EXPECTED_TESTS', 'EXPECTED_EXTENDED_TESTS', 'RETAINED_TESTS', 'TEST_PREFIX',
             'FINAL_BINDINGS_READY', 'ACTUAL_QUALIFICATION_SHA', 'ACTUAL_ENTRY_SHA', 'ACTUAL_WORKER_SHA',
             'PREPARED_MAP_SHA')
    frozen = constants(exporter_raw, names)
    need(frozen['FINAL_BINDINGS_READY'] is True and all(
        frozen['ACTUAL_' + name.upper() + '_SHA'] == getattr(args, name + '_sha')
        for name in ('qualification', 'entry', 'worker')), 'frozen exporter actual three pins differ')

    packed = read(args.archive, args.expected_sha)
    need(len(packed) == args.expected_bytes, 'whole original gzip length differs')
    with gzip.GzipFile(fileobj=io.BytesIO(packed), mode='rb') as stream:
        plain = stream.read(MAX_BYTES + 1)
        need(len(plain) <= MAX_BYTES and stream.read(1) == b'', 'unexpected expanded export size')
    value = json_value(plain)
    need(value['schema'] == 'hepta-a55-r01-qualified-source-export/v1', 'export schema differs')
    mapping = actual['tested_map']
    compact_sha = digest(json.dumps(mapping, sort_keys=True, separators=(',', ':')).encode())
    need(len(mapping) == 175 and value['source_map'] == mapping == q['source_after']
         and compact_sha == value['source_map_compact_sha256'] == actual['tested_map_sha']
         and value['prepared_source_map_compact_sha256'] == frozen['PREPARED_MAP_SHA'] == actual['prepared_map_sha'],
         'actual complete175 source maps differ')
    receipts = value['input_receipts']
    need(len(receipts) == 186 and len({row['path'] for row in receipts}) == 186,
         'exact original export input coverage differs')
    for row in receipts:
        receipt(row)
    by_path = {row['path']: row for row in receipts}
    source_root = BASE + '/source-a55-cstr-scan-r01/'
    source_receipts = {row['path'][len(source_root):]: row for row in receipts
                       if row['path'].startswith(source_root)}
    need(set(source_receipts) == set(mapping), '175 source receipt membership differs')
    for name, expected in mapping.items():
        need(source_receipts[name]['sha256'] == expected, 'source original receipt differs')
    report_paths = {'qualification': BASE + '/qualification-a55-cstr-scan-r01/report.json',
                    'entry': BASE + '/a55-cstr-scan-entry-r01/entry-report.json',
                    'worker': BASE + '/a55-cstr-scan-entry-r01/worker-report.json'}
    for name, path in report_paths.items():
        need(value[name] == by_path[path] and value[name]['sha256'] == actual['reports'][name]['sha256']
             and value[name]['bytes'] == actual['reports'][name]['bytes'], 'export actual report receipt differs')
    need(value['qualification'] == worker['qualifier_report']
         and value['qualification_sha256'] == actual['reports']['qualification']['sha256'],
         'worker qualifier receipt differs')
    need(value['exporter'] == by_path[exporter['path']]
         and all(value['exporter'][key] == exporter[key] for key in ('path', 'bytes', 'sha256')),
         'actual exporter self receipt differs')
    need(set(value['sources']) == set(frozen['CHANGED']) == set(validator.CHANGED)
         and len(value['sources']) == 8, 'exact eight changed sources differ')
    payloads, rows = {}, []
    for name, item in sorted(value['sources'].items()):
        raw = item['text'].encode('utf-8')
        need({k: v for k, v in item.items() if k != 'text'} == source_receipts[name]
             and len(raw) == item['bytes'] and digest(raw) == mapping[name], 'actual postfmt source body differs')
        payloads[ROOT / 'runtime-a55-qualified' / name] = raw
        rows.append({'path': name, 'bytes': len(raw), 'sha256': digest(raw),
                     'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()})
    docs = ROOT / 'runtime-resume/docs/experiments/x230/a55'
    need(tuple(stage['name'] for stage in worker['stages']) == STAGES and len(value['stages']) == 6,
         'six original stage gate bodies required')
    gate_paths = []
    for index, stage in enumerate(worker['stages']):
        name = 'stage-%d-%s.host-gate.json' % (index, stage['name'])
        item = value['stages'][name]
        raw = item['text'].encode('utf-8')
        need({k: v for k, v in item.items() if k != 'text'} == stage['host_gate'] == by_path[item['path']]
             and digest(raw) == item['sha256'] and len(raw) == item['bytes'], 'host gate original body differs')
        gate = json_value(raw)
        need(gate['clear'] is True and gate['resource_errors'] == [] and gate['matching_live_processes'] == [],
             'host gate did not pass')
        gate_paths.append(item['path'])
        payloads[docs / 'qualification-stages' / name] = raw
    log_receipt = value['test_log']
    log_raw = value['test_log_text'].encode('utf-8')
    need(log_receipt['path'] == BASE + '/qualification-a55-cstr-scan-r01/test.log'
         and log_receipt == by_path[log_receipt['path']]
         and len(log_raw) == log_receipt['bytes'] and digest(log_raw) == log_receipt['sha256'] == q['stages'][4]['log_sha256'],
         'complete original test log body identity differs')
    new_coverage, expanded_coverage, summary = original_test_log(
        log_raw, value['sources'], frozen, q['stages'][4]['results'])
    need(new_coverage == value['new_test_coverage'] and expanded_coverage == value['extended_test_coverage']
         and summary == value['test_log_summary'], 'independent full original log reconstruction differs')
    need(set(by_path) == {exporter['path'], *report_paths.values(), *gate_paths, log_receipt['path'],
                         *(source_root + name for name in mapping)}, 'closed186 original input set differs')
    need(value['binary_declared_by_qualification'] == q['binary']
         and value['test_binary_declared_by_qualification'] == q['test_binary']
         and value['source_files'] == value['source_bodies_rehashed'] == 175
         and value['changed_source_bodies_exported'] == 8 and value['host_gate_bodies_exported'] == 6
         and value['artifact_bodies_rehashed_by_this_export'] is False
         and value['original_test_log_body_retained_at_original_path'] is True
         and value['original_test_log_body_exported'] is True
         and value['runtime_executions'] == 0 and value['performance_adoption_claimed'] is False
         and value['all_inputs_unchanged_through_export_read_fence'] is True, 'export scope differs')
    download = json_value(read(args.download_receipt, args.download_receipt_sha))
    info, status = download['info'], download['operator_status']
    need(info['path'] == freeze['destination'] and info['size'] == len(packed)
         and info['sha256'] == digest(packed) and status['job_id'] == args.job_id
         and status['state'] == 'succeeded' and type(status['exit_code']) is int and status['exit_code'] == 0
         and status['output_complete'] is True and status['timed_out'] is False
         and status['cancelled'] is False, 'actual export job/download metadata differs')
    offset = 0
    for chunk in download['chunks']:
        end = chunk['next_offset']
        need(chunk['path'] == info['path'] and chunk['size'] == len(packed)
             and chunk['version'] == info['version'] and chunk['offset'] == offset
             and type(end) is int and offset < end <= min(offset + 65536, len(packed))
             and chunk['eof'] is (end == len(packed))
             and digest(packed[offset:end]) == chunk['chunk_sha256'], 'version-fenced download chunk differs')
        offset = end
    need(offset == len(packed), 'download chunks do not cover the whole gzip')
    stdout = json_value(download['operator_stdout'])
    need(stdout == {'path': info['path'], 'bytes': len(packed), 'sha256': digest(packed),
                    'uncompressed_bytes': len(plain), 'uncompressed_sha256': digest(plain),
                    'new_tests': len(new_coverage), 'extended_tests': len(expanded_coverage),
                    'top_level_passed': summary['top_level_passed'],
                    'top_level_ignored': summary['top_level_ignored'],
                    'source_map_compact_sha256': compact_sha, 'runtime_executions': 0},
         'actual exporter complete stdout differs')
    result = {'schema': 'hepta-a55-qualified-source-export-download-verification/v1', 'passed': True,
              'operator_export_job': args.job_id, 'original_gzip': {'bytes': len(packed), 'sha256': digest(packed)},
              'expanded_json': {'bytes': len(plain), 'sha256': digest(plain)}, 'download': download,
              'all_175_source_receipts_match_actual_qualification': True, 'postfmt_sources': rows,
              'source_map_compact_sha256': compact_sha, 'stage_gate_count': 6,
              'new_tests_verified': len(new_coverage), 'expanded_tests_verified': len(expanded_coverage),
              'retained_test_declarations': 69, 'actual_original_test_log_summary': summary,
              'top_level_passed': summary['top_level_passed'], 'top_level_ignored': summary['top_level_ignored'],
              'filtered_nested_results_not_recounted': len(summary['filtered_nested_results_excluded_from_totals']),
              'full_original_test_log_downloaded': True, 'complete_test_log': log_receipt,
              'qualification_validator_sha256': VALIDATOR_SHA, 'export_freeze_sha256': args.export_freeze_sha,
              'performance_adoption_claimed': False, 'remote_execution_performed_by_this_verifier': False}
    payloads.update({docs / 'qualified-source-export.original.json.gz': packed,
                     docs / 'qualified-source-export.download-verification.json': canonical(result),
                     docs / 'new-test-coverage.json': canonical(new_coverage),
                     docs / 'expanded-test-coverage.json': canonical(expanded_coverage),
                     docs / 'qualification-test.original.log': log_raw,
                     docs / 'source-publication-rows.original.json': canonical(rows),
                     docs / 'source-tested-map.json': canonical(mapping)})
    need(all(path.read_bytes() == raw for path, raw in inputs.items()), 'local input changed at final fence')
    need(all(not os.path.lexists(path) for path in payloads), 'fresh extraction destinations required')
    for path, raw in payloads.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        need(path.parent.resolve(strict=True) == path.parent, 'direct extraction directory required')
        with path.open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'passed': True, 'postfmt_sources': rows, 'tests': summary['top_level_passed'],
                      'ignored': summary['top_level_ignored'], 'new_tests': len(new_coverage),
                      'expanded_tests': len(expanded_coverage), 'receipt_bytes': len(canonical(result)),
                      'receipt_sha256': digest(canonical(result))}))


if __name__ == '__main__':
    main()
