#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve failed archive r02, including its historical partial analysis.

This is a local, create-only evidence transformation. It does not import the
experiment runner/analyzer, execute a workload, or calculate relative gains.
"""
from collections import Counter, defaultdict
import gzip
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'a27-archive-r02-failed-actual'
ARCHIVE = ROOT / 'a27-archive-r02-failed-actual.tar.gz'
TRANSFER = ROOT / 'a27-archive-r02-failure-transfer.json'
OUT = ROOT / 'a27-archive-r02-failed-publication-r01'
ARCHIVE_SHA = '3636c02e6e86db9b59105154e6bd357f07daa0dec0fd1c9e331cac066d54f2c3'
TRANSFER_SHA = 'a21c2f41b419ce0a985dc6be78d53a2c1dbd2e681bde384d47406d2cc48eb2e7'
PLAN_SHA = 'f52465a8773520c380b8f20e3875d877cccc1564611a8005ed3a89ad9211a559'
DEPS = {
    'build_x230_a26_series_evidence_r02': ('a26-series-tools', '610b7c95dfa46b25e677b29095f0b813c1074aefef4f8a101910b95b2978748f'),
    'build_x230_evidence': ('a25-evidence-tools', 'd868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb'),
    'build_x230_six_running_evidence': ('a25-evidence-tools', 'e079b19be97815bb8c4a41891fa995e40e1e353425b7e909bb814a65a3359c52'),
}
RUN = 'archive-probe-run-r02/'
ANALYSIS = 'archive-probe-analysis-r02/analysis.json'
INVENTORY = 'a27-archive-r02-failure-inventory.json'


def need(value, message):
    if not value:
        raise ValueError(message)


def receipt(name, raw):
    return {'file': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    need(len(sys.argv) == 1 and not os.path.lexists(OUT), 'fresh fixed publication output required')
    sys.dont_write_bytecode = True
    dependencies = {}
    for name, (folder, expected) in DEPS.items():
        path = ROOT / folder / (name + '.py')
        need(path == path.resolve(), 'indirect sanitizer dependency refused')
        raw = path.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, 'frozen sanitizer changed')
        dependencies[name] = raw
    sys.path[:0] = [str(ROOT / 'a26-series-tools'), str(ROOT / 'a25-evidence-tools')]
    module = importlib.import_module('build_x230_a26_series_evidence_r02')
    for name, (folder, _) in DEPS.items():
        need(Path(sys.modules[name].__file__).resolve() == ROOT / folder / (name + '.py'),
             'unexpected imported sanitizer')
    source_bytes = Path(__file__).read_bytes()
    archive_receipt, archive_bytes = module.read_file(ARCHIVE)
    need(archive_receipt['bytes'] == 496313 and archive_receipt['sha256'] == ARCHIVE_SHA,
         'pinned original archive differs')
    transfer_receipt, transfer_raw = module.read_file(TRANSFER)
    need(transfer_receipt['bytes'] == 8008 and transfer_receipt['sha256'] == TRANSFER_SHA,
         'pinned terminal/transfer proof differs')
    transfer = module.decode(transfer_raw)
    offset, versions = 0, set()
    for row in transfer['chunks']:
        need(row['offset'] == offset and row['size'] == len(archive_bytes), 'transfer interval differs')
        next_offset = row['next_offset']
        need(offset < next_offset <= len(archive_bytes) and row['chunk_sha256'] ==
             module.sha(archive_bytes[offset:next_offset]), 'transfer chunk hash differs')
        need(row['eof'] is (next_offset == len(archive_bytes)), 'transfer EOF differs')
        versions.add(row['version'])
        offset = next_offset
    need(offset == len(archive_bytes) and len(versions) == 1 and len(transfer['chunks']) == 8,
         'incomplete or mixed-version transfer')
    terminal = transfer['run_terminal']
    need(terminal['state'] == 'failed' and terminal['exit_code'] == 1 and
         terminal['cancelled'] is False and terminal['timed_out'] is False and
         terminal['output_complete'] is True, 'native failed terminal proof differs')
    need(transfer['comparison_valid'] is False and transfer['candidate_adopted'] is False and
         transfer['runtime_source_changed'] is False, 'transfer scope differs')

    raw_files, original_receipts, values, formats = {}, {}, {}, {}
    for path in sorted(SOURCE.rglob('*')):
        need(not path.is_symlink(), 'indirect extracted member refused')
        if path.is_dir():
            continue
        name = path.relative_to(SOURCE).as_posix()
        bound, raw = module.read_file(path)
        need(not bound['retention_limit_exceeded'], 'complete evidence input exceeds parsing limit')
        raw_files[name], original_receipts[name] = raw, bound
        if path.suffix == '.json':
            values[name], formats[name] = module.decode(raw), {'format': 'JSON'}
        elif path.suffix == '.jsonl' or path.name.endswith('.stdout.log'):
            records = [module.decode(line) for line in raw.splitlines()]
            values[name], formats[name] = records, {'format': 'JSONL', 'rows': len(records),
                                                   'final_newline': raw.endswith(b'\n')}
        elif path.suffix in ('.log', '.rs'):
            lines = raw.decode('utf-8').splitlines(keepends=True)
            values[name], formats[name] = lines, {
                'format': 'UTF-8 text lines', 'lines': len(lines),
                'line_terminators_retained': True, 'final_newline': raw.endswith(b'\n'),
                'source_view_not_an_exact_compilable_source_claim': path.suffix == '.rs'}
        else:
            raise ValueError('unrecognized complete input format')
    need(len(raw_files) == 323 and sum(map(len, raw_files.values())) == 7547613,
         'complete extracted file inventory differs')
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        need(len(names) == len(set(names)) == 323 and set(names) == set(raw_files),
             'archive and extracted path sets differ')
        for member in members:
            path = PurePosixPath(member.name)
            need(member.isfile() and not path.is_absolute() and '..' not in path.parts,
                 'nonregular or unsafe archive member')
            stream = archive.extractfile(member)
            need(stream is not None and stream.read() == raw_files[member.name],
                 'archive member and extracted bytes differ')

    inventory = values[INVENTORY]
    need(set(inventory['artifacts']) == set(raw_files) - {INVENTORY},
         'original inventory omits or adds an artifact')
    for name, declared in inventory['artifacts'].items():
        raw = raw_files[name]
        need(declared == {'bytes': len(raw), 'sha256': module.sha(raw)}, 'inventory receipt differs')
    plan = values[RUN + 'plan.json']
    need(module.sha(raw_files[RUN + 'plan.json']) == PLAN_SHA, 'frozen plan differs')
    specs = {spec['id']: spec for spec in plan['cells']}
    need(len(specs) == len(plan['cells']) == 536, 'planned cell set differs')
    series, analysis = values[RUN + 'series.json'], values[ANALYSIS]
    need(series['plan_sha256'] == analysis['plan_sha256'] == PLAN_SHA and
         analysis['series_sha256'] == module.sha(raw_files[RUN + 'series.json']),
         'historical series/analysis bindings differ')
    need(series['passed'] is False and series['complete'] is False and series['adopted'] is False and
         series['automatic_retries'] == 0 and series['inputs_unchanged'] is True,
         'historical failed series scope differs')
    need(analysis['verified'] is False and analysis['comparison_valid'] is False and
         analysis['diagnostic_performance_gate_passed'] is False and analysis['adopted'] is False,
         'historical failed analysis scope differs')
    for declared in (series['artifact_hashes'], analysis['artifact_hashes']):
        for name, bound in declared.items():
            raw = raw_files[RUN + name]
            need(bound == {'bytes': len(raw), 'sha256': module.sha(raw)},
                 'series/analysis artifact byte binding differs')
    need(values[RUN + 'inputs-before.json'] == values[RUN + 'inputs-after.json'],
         'bound inputs-before/after dictionaries differ')

    groups, stream_summary, query_rows, setup_rows, process_summary = {}, {}, [], [], []
    for size in (16384, 65536):
        for arm in ('A', 'B'):
            prefix = RUN + f'size-{size}/arm-{arm}/'
            name = prefix + 'stdout.jsonl'
            records = values[name]
            by_sequence = defaultdict(list)
            for row in records:
                if row.get('event') in ('cell_started', 'query', 'cell_complete'):
                    by_sequence[row['sequence']].append(row)
            groups[size, arm] = by_sequence
            queries = [row for row in records if row.get('event') == 'query']
            setup = [row for row in records if row.get('event') == 'setup_query']
            query_rows.extend(queries)
            setup_rows.extend(setup)
            summary = {'JSONL_records': len(records),
                       'event_counts': dict(Counter(row['event'] for row in records)),
                       'observed_query_rows': len(queries),
                       'observed_failed_query_rows': sum(row['passed'] is not True for row in queries),
                       'setup_query_rows': len(setup),
                       'setup_failed_query_rows': sum(row['passed'] is not True for row in setup),
                       'last_event': records[-1]['event'], 'all_lines_parsed': True}
            declared = inventory['stdout_streams'][name[len(RUN):]]
            need(declared['json_rows'] == len(records) and declared['query_rows'] == len(queries) and
                 declared['query_failed_rows'] == summary['observed_failed_query_rows'] and
                 declared['setup_query_rows'] == len(setup) and declared['setup_failed_rows'] ==
                 summary['setup_failed_query_rows'] and declared['unparsed_lines'] == [],
                 'stdout counts differ from original inventory')
            stream_summary[name] = summary
            process = values[prefix + 'process.json']
            need(process in series['processes'] and process in inventory['processes'],
                 'process receipts differ between original records')
            need(process['stdout_events_read'] == len(records) and process['cleanup_errors'] == [] and
                 process['stdout_reader_errors'] == [], 'recorded child/reader completion differs')
            resource = values[prefix + 'resource-final.json']
            need(process['resources'] == resource, 'process and resource-final receipts differ')
            errors = values[prefix + 'resource-errors.jsonl']
            error_raw = raw_files[prefix + 'resource-errors.jsonl']
            need(resource['error_log_receipt'] == {'bytes': len(error_raw), 'rows': len(errors),
                 'sha256': module.sha(error_raw)}, 'complete sampler error log byte receipt differs')
            snap = resource['snapshot']
            need(resource['complete_error_log_verified'] is True and
                 resource['scope_ends_before_final_original_verification'] is True and
                 snap['error_count'] == snap['error_log_rows_written'] == len(errors) == 0 and
                 snap['error_log_complete'] is True and snap['error_log_finalized'] is True and
                 snap['sampler_thread_stopped'] is True, 'sampler completeness differs')
            complete = [row for row in records if row.get('event') == 'complete']
            if size == 16384:
                need(process['returncode'] == 0 and process['passed'] is True and
                     process['full_expected_work_completed'] is True and
                     process['sigint_attempted'] is False and len(complete) == 1 and
                     process['teardown_events'] == complete, '16K child completion differs')
                end = complete[0]
                need(end['passed'] is True and end['originals_unchanged'] is True and
                     end['final_input_sha256'] == end['original_input_sha256'] ==
                     process['ready']['input_sha256'], '16K final original hash proof differs')
            else:
                need(process['returncode'] == (1 if arm == 'A' else -2) and
                     process['passed'] is False and process['full_expected_work_completed'] is False and
                     process['sigint_attempted'] is True and process['sigint_forwarded'] is True and
                     complete == process['teardown_events'] == [], '64K incomplete teardown differs')
            process_summary.append({
                'rows': size, 'arm': arm, 'returncode': process['returncode'],
                'recorded_passed': process['passed'],
                'full_expected_work_completed': process['full_expected_work_completed'],
                'sigint_attempted': process['sigint_attempted'],
                'sigint_forwarded': process['sigint_forwarded'],
                'complete_event_present': bool(complete),
                'final_original_hash_verification_present': bool(complete),
                'sampler_finalized_and_stopped': True, 'resource_error_rows': len(errors),
                'sampler_scope_ends_before_final_original_verification': True})

    cells = {name.rsplit('/', 1)[1][:-5]: value for name, value in values.items()
             if name.startswith(RUN + 'cells/') and name.endswith('.json')}
    need(len(cells) == 273 and set(cells) == {spec['id'] for spec in plan['cells'][:273]},
         'recorded cell receipt set differs')
    need([row['id'] for row in series['cells']] == [spec['id'] for spec in plan['cells']],
         'series planned cell order differs')
    coverage, phases = [], Counter()
    for spec, series_cell in zip(plan['cells'], series['cells']):
        events = groups[spec['rows'], spec['arm']].get(spec['sequence'], [])
        rows = [row for row in events if row['event'] == 'query']
        endings = [row for row in events if row['event'] == 'cell_complete']
        item = {'spec': spec, 'raw_series_status': series_cell['status'],
                'raw_series_passed': series_cell['passed'], 'observed_query_rows': len(rows),
                'observed_failed_query_rows': sum(row['passed'] is not True for row in rows)}
        if spec['id'] in cells:
            cell = cells[spec['id']]
            need(cell['spec'] == spec and cell['events'] == events and len(endings) == 1 and
                 cell['check']['complete'] == endings[0] and cell['check']['query_rows'] ==
                 len(rows) == spec['calls'] == 8, 'cell receipt and complete stdout events differ')
            passed = cell['check']['passed'] is True
            need(passed is (spec['id'] != 'cell-0272') and series_cell['passed'] is passed and
                 series_cell['status'] == ('completed' if passed else 'started'),
                 'recorded pass/fail boundary differs')
            item.update(state='recorded_passed' if passed else 'recorded_failed',
                        recorded_check_passed=passed, complete_event_present=True)
            phases[spec['phase']] += 1
        else:
            need(not events and series_cell['status'] == 'not_run' and series_cell['passed'] is False,
                 'unrecorded cell has an unexpected start or status')
            item.update(state='not_run', complete_event_present=False)
        coverage.append(item)
    need(len(query_rows) == 2184 and len(setup_rows) == 8 and
         sum(row['passed'] is not True for row in query_rows) == 2 and
         all(row['passed'] is True for row in setup_rows), 'query/setup inventory differs')
    need(Counter(row['status'] for row in series['cells']) ==
         {'completed': 272, 'started': 1, 'not_run': 263}, 'raw series status counts differ')
    failed_rows = [row for row in query_rows if row['passed'] is not True]
    need(all(row['error'] == 'archive index preparing or validation unavailable; repeat only this metadata query'
             for row in failed_rows), 'observed failure category differs')
    need(inventory['comparison_valid'] is False and inventory['candidate_adopted'] is False and
         inventory['actual_overflow_directly_observed'] is False, 'inventory scope differs')

    values['transfer-status.json'], raw_files['transfer-status.json'] = transfer, transfer_raw
    formats['transfer-status.json'] = {'format': 'JSON'}
    original_receipts['transfer-status.json'] = transfer_receipt
    seeds, jobs, loadavg_paths = [], set(), []
    def discover(value, label, path=()):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == 'job_id' or key.endswith('_job_id')) and isinstance(item, str):
                    jobs.add(item)
                    seeds.append({'identity': item})
                if key == 'owned_pid' and type(item) is int:
                    seeds.append({'pid': item})
                if key in ('loadavg_before', 'loadavg_after') and isinstance(item, str):
                    fields = item.split()
                    need(len(fields) == 5 and fields[-1].isdigit(), 'loadavg field differs')
                    seeds.append({'pid': int(fields[-1])})
                    loadavg_paths.append((label, path + (key,), item))
                discover(item, label, path + (key,))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                discover(item, label, path + (index,))
    for label, value in values.items():
        discover(value, label)
    sanitizer = module.CompleteSanitizer({'documents': values, 'identity_discovery_seeds': seeds})
    transformations, structural = [], Counter()
    extra_identity = {'device', 'inode', 'st_dev', 'st_ino', 'st_uid', 'st_gid', 'job_id', 'owned_pid'}

    def fixed_key(key, item, parent):
        byte_count = key == 'bytes' and type(item) is int and module.HEX256.fullmatch(str(parent.get('sha256', '')))
        error_number = key == 'errno' and type(item) is int and {
            'pid', 'birth_ticks', 'stage', 'error_type', 'message'}.issubset(parent)
        return 'SHA-256 byte receipt' if byte_count else 'resource-error errno' if error_number else None

    def opaque_key(key, label, path):
        lower = key.lower()
        version = label == 'transfer-status.json' and len(path) == 2 and path[0] == 'chunks' and key == 'version'
        return (lower in extra_identity or lower.endswith('_job_id') or lower == 'stamp' or
                lower.endswith('_stamp') or version or lower in sanitizer.private_keys or
                lower in sanitizer.opaque_keys or 'base64' in lower or lower.endswith('_hex'))

    def mapped_keys(value):
        mapped = {key: key if fixed_key(key, item, value) else sanitizer.string(key)
                  for key, item in value.items()}
        multiplicity = Counter(mapped.values())
        return {key: ('<opaque-key:' + sanitizer.opaque_receipt(key)['canonical_value_sha256'] + '>'
                      if multiplicity[pk] > 1 else pk) for key, pk in mapped.items()}

    def convert(value, label, path=()):
        if isinstance(value, dict):
            mapping, result = mapped_keys(value), {}
            for key, item in value.items():
                pk = mapping[key]
                context = fixed_key(key, item, value)
                if context and sanitizer.string(key) != key:
                    transformations.append({'document': label, 'path': list(path + (pk,)),
                        'policy': 'fixed numeric schema key retained despite crate-name user heuristic',
                        'original_key': sanitizer.opaque_receipt(key), 'public_key': pk,
                        'value': item, 'context': context})
                    structural['fixed_numeric_schema_key_overrides'] += 1
                elif pk.startswith('<opaque-key:'):
                    transformations.append({'document': label, 'path': list(path),
                        'policy': 'collision-safe opaque key', 'original_key': sanitizer.opaque_receipt(key),
                        'public_key': pk})
                    structural['collision_safe_key_aliases'] += 1
                need(pk not in result, 'sanitized key collision remains')
                count_exception = key == 'identity' and path and path[-1] == 'readable_fields' and type(item) is int
                if count_exception:
                    result[pk] = item
                    transformations.append({'document': label, 'path': list(path + (pk,)),
                        'policy': 'numeric readable-field coverage counter retained', 'value': item})
                    structural['numeric_readable_fields_identity_overrides'] += 1
                elif opaque_key(key, label, path):
                    result[pk] = sanitizer.opaque_receipt(item)
                    transformations.append({'document': label, 'path': list(path + (pk,)),
                        'policy': 'existing opaque_receipt', 'value_receipt': result[pk]})
                    structural['opaque_fields'] += 1
                else:
                    result[pk] = convert(item, label, path + (pk,))
                structural['dictionary_keys_retained'] += 1
            need(len(result) == len(value), 'dictionary entry lost')
            return result
        if isinstance(value, list):
            structural['list_rows_retained'] += len(value)
            return [convert(item, label, path + (index,)) for index, item in enumerate(value)]
        if isinstance(value, str):
            structural['strings_transformed_by_frozen_policy'] += 1
            return sanitizer.string(value)
        structural['numeric_boolean_null_values_unchanged'] += 1
        return value

    public = {name: convert(value, name) for name, value in values.items()}
    for name, path, original in loadavg_paths:
        transformed = public[name]
        for key in path:
            transformed = transformed[key]
        need(original.split()[:4] == transformed.split()[:4] and transformed.split()[-1] == '<pid>',
             'loadavg measurement fields or PID adaptation differs')
        transformations.append({'document': name, 'path': list(path), 'policy': 'loadavg final PID marker',
            'original_complete_string': sanitizer.opaque_receipt(original), 'first_four_fields_preserved': True})

    checked = Counter()
    def audit(original, target, label, path=()):
        if isinstance(original, dict):
            mapping = mapped_keys(original)
            need(isinstance(target, dict) and len(target) == len(original) and
                 set(target) == set(mapping.values()), 'dictionary shape changed')
            for key, item in original.items():
                pk = mapping[key]
                count_exception = key == 'identity' and path and path[-1] == 'readable_fields' and type(item) is int
                if opaque_key(key, label, path) and not count_exception:
                    need(target[pk] == sanitizer.opaque_receipt(item), 'opaque field hash binding differs')
                    checked['opaque_fields_hash_bound'] += 1
                else:
                    if type(item) in (int, float, bool) or item is None:
                        need(not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', key) or pk == key,
                             'a fixed numeric schema key was obscured')
                    audit(item, target[pk], label, path + (pk,))
                checked['dictionary_entries_preserved'] += 1
        elif isinstance(original, list):
            need(isinstance(target, list) and len(original) == len(target), 'list rows changed')
            for index, (item, new) in enumerate(zip(original, target)):
                audit(item, new, label, path + (index,))
            checked['list_rows_preserved'] += len(original)
        elif isinstance(original, str):
            need(target == sanitizer.string(original), 'string differs from frozen policy')
            checked['string_leaves_checked'] += 1
        else:
            need(type(original) is type(target) and original == target, 'numeric/boolean/null value changed')
            checked['nonopaque_numeric_boolean_null_leaves_equal'] += 1
    for name in values:
        audit(values[name], public[name], name)
    for name in stream_summary:
        old = [row for row in values[name] if row.get('event') == 'query']
        new = [row for row in public[name] if row.get('event') == 'query']
        need(old == new, 'query row or metric changed')
        old_setup = [row for row in values[name] if row.get('event') == 'setup_query']
        new_setup = [row for row in public[name] if row.get('event') == 'setup_query']
        for old_row, new_row in zip(old_setup, new_setup):
            need({k: v for k, v in old_row.items() if k != 'raw_response'} ==
                 {k: v for k, v in new_row.items() if k != 'raw_response'} and
                 new_row['raw_response'] == sanitizer.opaque_receipt(old_row['raw_response']),
                 'setup metric or opaque response binding changed')
    for cell_id, cell in cells.items():
        target = public[RUN + 'cells/' + cell_id + '.json']
        need(cell == target, 'cell metrics/events/checks/resources/specification changed')
    historical_sections = ('all_cold_guard_shapes', 'all_kind_shapes', 'equal_call_mixed_shapes',
                           'cell_checks', 'gate', 'errors', 'raw_series_errors')
    for key in historical_sections:
        need(analysis[key] == public[ANALYSIS][key], 'historical analysis section changed')
    need(structural['numeric_readable_fields_identity_overrides'] == 5370,
         'numeric sampler coverage counter inventory differs')

    bundle = {'schema': 'hepta-a27-failed-archive-complete-public-evidence/v1',
        'original_archive_published': False,
        'files': {name: {**formats[name], 'value': public[name]} for name in sorted(public)}}
    plain = module.canonical(bundle)
    need(all(job.encode() not in plain for job in jobs), 'original job identity remains')
    need(module.common.Sanitizer.private_path.search(plain.decode()) is None and
         re.search(r'/proc/[0-9]+(?:/|\b)', plain.decode()) is None, 'private path or proc PID remains')
    summary = {
        'schema': 'hepta-a27-failed-archive-publication-scope/v1',
        'publication_integrity_passed': True, 'experiment_completed_successfully': False,
        'raw_series_complete': series['complete'], 'raw_series_passed': series['passed'],
        'historical_analysis_verified': analysis['verified'], 'comparison_valid': False,
        'historical_diagnostic_performance_gate_passed': analysis['diagnostic_performance_gate_passed'],
        'historical_analyzer_partial_and_relative_metrics_retained': True,
        'historical_analysis_is_not_recomputed_by_publication': True,
        'new_relative_performance_recomputation': False, 'candidate_adopted': False,
        'successful_subset_or_local_guard_not_used_for_adoption': True,
        'native_terminal': {'state': terminal['state'], 'exit_code': terminal['exit_code'],
            'output_complete': terminal['output_complete'], 'cancelled': terminal['cancelled'],
            'timed_out': terminal['timed_out']},
        'planned_cells': 536, 'recorded_cell_receipts': 273, 'recorded_passed_cells': 272,
        'recorded_failed_cells': 1, 'not_run_cells': 263,
        'raw_series_cell_status_counts': dict(Counter(row['status'] for row in series['cells'])),
        'recorded_cells_by_phase': dict(phases), 'stdout_query_rows': 2184,
        'passed_query_rows': 2182, 'failed_query_rows': 2,
        'setup_query_rows': 8, 'passed_setup_query_rows': 8,
        'failed_cell_id': 'cell-0272', 'failed_cell_dimensions': specs['cell-0272'],
        'all_failed_query_rows': failed_rows,
        'query_rows_in_cell_receipts_duplicate_stdout_rows': True,
        'stdout_streams': stream_summary, 'process_completion': process_summary,
        'all_four_sampler_error_logs_finalized': True, 'resource_error_jsonl_rows': 0,
        'complete_sampling_logs_do_not_supply_missing_64K_final_original_hashes': True,
        'bound_input_files_before_after_equal': True,
        'bound_helper_input_hashes_are_distinct_from_final_fixture_original_hashes': True,
        'all_recorded_nonopaque_metrics_and_flags_retained': True,
        'all_273_cell_objects_equal_after_sanitization': True,
        'historical_analysis_sections_exactly_preserved': list(historical_sections),
        'actual_overflow_directly_observed': False,
        'inotify_limits_read_only': public[INVENTORY]['inotify_limits_read_only'],
        'direct_watch_version_or_overflow_cause_inferred_by_publication': False,
        'new_workload_run': False, 'remote_calls': False, 'runtime_source_changed': False,
        'raw_inputs_modified': False, 'original_fixtures_deleted_by_publication': False,
    }
    outputs = {}
    def compressed(name, value):
        data, uncompressed = module.compressed(value)
        need(gzip.decompress(data) == module.canonical(value), 'complete gzip roundtrip differs')
        outputs[name] = data
        return {**receipt(name, data), **uncompressed}
    bundle_bound = compressed('complete-evidence.sanitized.json.gz', bundle)
    inventory_bound = compressed('redaction-inventory.complete.sanitized.json.gz', transformations)
    coverage_bound = compressed('planned-cell-coverage.complete.json.gz', coverage)
    analysis_bound = compressed('analysis.complete.sanitized.json.gz', public[ANALYSIS])
    outputs['summary.json'] = module.canonical(summary)
    outputs['build_failed_publication.py'] = source_bytes
    outputs['README.md'] = b'''# Archive experiment r02: complete publication of a failed run

The native run ended failed, exit 1, with complete captured output. It was not
cancelled by the outer controller and did not hit its outer timeout. The fixed
536-cell plan produced 273 cell receipts: 272 passed and one failed, followed
by 263 not-run cells. The original series labels the failed cell `started`;
that status is preserved even though its receipt contains a cell_complete
event and all eight query rows.

All 2,184 cell-query rows remain, including the two failed metadata queries.
The eight setup queries are separate and all passed. Cell receipts duplicate
stdout events and must not be added to the stdout row total. Cell-0272 is the
baseline A arm at 65,536 records, concurrency four, usage warmup: six passed
and two returned the original metadata-unavailable error. No retry is added.

Both 16,384-record child processes exited zero and emitted complete events
with matching original/final fixture hashes. At 65,536 records A exited 1
and B exited -2; both record sigint_forwarded and neither has a complete
event or final original-fixture hash witness. All four sampler error logs
are finalized, stopped and hash-verified, with zero recorded error JSONL
rows. Sampling ends before final original verification, so its completeness
cannot replace that missing 64K witness. The source/helper inputs-before and
inputs-after agree; those inputs are distinct from fixture originals.

The frozen historical analyzer did calculate and retain partial grouped
and relative metrics, including some true local guard fields. They remain
unchanged in both the complete bundle and the separate full analysis view.
Its overall verified, comparison_valid and diagnostic-performance-gate
verdicts are false. This publication performs no new performance calculation,
does not select the successful 16K subset, and does not use any partial guard
as adoption authority. The candidate is unadopted and runtime source unchanged.

All 323 regular archive members plus the separate terminal/transfer proof
are retained as complete parsed JSON, JSONL records or UTF-8 text lines.
Every original byte hash and all fixed-version transfer chunks are verified.
The six Rust text files are complete sanitized views bound to original bytes,
not a claim that the transformed text is exact compilable source. The private
raw archive and actual identities are not public artifacts. Source/binary
receipts are preserved; binary bodies outside this downloaded archive were
not independently reread locally.

The unchanged frozen A26 CompleteSanitizer supplies string transformations
and opaque hash receipts. Explicit, recorded schema rules cover job/owned
process IDs, transfer versions, file/process stamp aliases, collision-safe
dictionary keys, and loadavg's last PID while retaining its first four fields.
Numeric readable_fields.identity coverage counters stay numeric. Fixed bytes
keys accompanying SHA-256 receipts and errno keys in resource-error rows
keep their technical names despite the generic Cargo crate-name heuristic.
Opaque response/command fields remain present with exact canonical receipts;
they are not decoded for public disclosure. No row, failure, local guard,
sampling scope flag, missing value, or teardown result is dropped.

Read-only inotify limits remain as recorded. Neither direct watch-version
state nor an overflow was observed by this experiment, so this package does
not establish either as the cause. Follow-on phase or branch diagnostics are
separate experiments and are not incorporated here. No workload, remote
operation, runtime change, fixture cleanup, or analyzer rerun is performed
by this create-only publication transformation.
'''
    for name, original in raw_files.items():
        path = TRANSFER if name == 'transfer-status.json' else SOURCE / name
        bound, raw = module.read_file(path)
        need(bound == original_receipts[name] and raw == original, 'raw input changed during publication')
    need(module.read_file(ARCHIVE)[0] == archive_receipt, 'pinned raw archive changed')
    for name, (folder, _) in DEPS.items():
        need((ROOT / folder / (name + '.py')).read_bytes() == dependencies[name], 'sanitizer changed')
    need(Path(__file__).read_bytes() == source_bytes, 'transform source changed')
    manifest = {
        'schema': 'hepta-a27-failed-archive-publication/v1', 'publication_revision': 'r01',
        'publication_integrity_passed': True, 'comparison_valid': False, 'candidate_adopted': False,
        'new_relative_performance_recomputation': False,
        'historical_analyzer_partial_and_relative_metrics_retained': True,
        'original_archive': {**receipt(ARCHIVE.name, archive_bytes), 'published': False},
        'original_transfer_status': receipt(TRANSFER.name, transfer_raw),
        'fixed_transfer_chunks_verified': len(transfer['chunks']),
        'archive_members_and_extracted_bytes_match': True, 'archive_member_count': 323,
        'inventory_file_receipts_verified': 322,
        'original_inputs': [receipt(name, raw) for name, raw in sorted(raw_files.items())],
        'frozen_sanitizer_dependencies': [receipt(name + '.py', raw) for name, raw in dependencies.items()],
        'transform_source': receipt('build_failed_publication.py', source_bytes),
        'complete_evidence': bundle_bound, 'complete_redaction_inventory': inventory_bound,
        'complete_coverage': coverage_bound, 'complete_historical_analysis': analysis_bound,
        'preservation_counts': dict(structural), 'recursive_equivalence_checks': dict(checked),
        'all_2184_stdout_query_objects_equal_after_sanitization': True,
        'all_8_setup_metrics_equal_and_raw_response_hash_bound': True,
        'all_273_cell_objects_equal_after_sanitization': True,
        'all_5370_numeric_readable_fields_identity_counters_retained': True,
        'historical_analysis_sections_exactly_preserved': list(historical_sections),
        'identity_discovery_job_value_count': len(jobs),
        'no_original_discovered_job_identity_in_public_bundle': True,
        'remote_binary_bodies_rehashed_locally': False,
        'new_workload_run': False, 'raw_inputs_modified': False, 'remote_calls': False,
        'public_files': [receipt(name, raw) for name, raw in outputs.items()]}
    outputs['publication-receipt.json'] = module.canonical(manifest)
    OUT.mkdir(mode=0o700)
    for name, raw in outputs.items():
        module.create_only(OUT / name, raw)
        need((OUT / name).read_bytes() == raw, 'public file readback differs')
    fd = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'publication_integrity_passed': True, 'comparison_valid': False,
        'files': [receipt(name, raw) for name, raw in outputs.items()]}, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
