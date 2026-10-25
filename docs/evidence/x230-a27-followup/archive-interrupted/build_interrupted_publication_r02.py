#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Preserve the interrupted archive experiment; never evaluate relative gains."""
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
SOURCE = ROOT / 'a27-archive-r01-interrupted-actual'
ARCHIVE = ROOT / 'a27-archive-r01-interrupted-actual.tar.gz'
TRANSFER = ROOT / 'a27-archive-r01-interruption-transfer.json'
OUT = ROOT / 'a27-archive-r01-interrupted-publication-r02'
ARCHIVE_SHA = 'caa0f342860612732c699d914d95c682a93b816bbb6c8c3c184a8f7d61e00247'
TRANSFER_SHA = 'ddd7f73425f98ac07d66406605574136f76896a28cc8a02cf6151ffc8fc558ac'
PLAN_SHA = 'a39e1896f9fff31dcc49ca6517795dd120be0076ff5ec2285c2766a3c15535bc'
DEPS = {
    'build_x230_a26_series_evidence_r02': ('a26-series-tools', '610b7c95dfa46b25e677b29095f0b813c1074aefef4f8a101910b95b2978748f'),
    'build_x230_evidence': ('a25-evidence-tools', 'd868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb'),
    'build_x230_six_running_evidence': ('a25-evidence-tools', 'e079b19be97815bb8c4a41891fa995e40e1e353425b7e909bb814a65a3359c52'),
}
RUN = 'archive-probe-run-r01/'


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
        data = path.read_bytes()
        need(hashlib.sha256(data).hexdigest() == expected, 'frozen sanitizer changed')
        dependencies[name] = data
    sys.path[:0] = [str(ROOT / 'a26-series-tools'), str(ROOT / 'a25-evidence-tools')]
    module = importlib.import_module('build_x230_a26_series_evidence_r02')
    for name, (folder, _) in DEPS.items():
        need(Path(sys.modules[name].__file__).resolve() == ROOT / folder / (name + '.py'),
             'unexpected imported sanitizer')
    source_bytes = Path(__file__).read_bytes()
    archive_receipt, archive_bytes = module.read_file(ARCHIVE)
    need(archive_receipt['bytes'] == 417477 and archive_receipt['sha256'] == ARCHIVE_SHA,
         'pinned original archive differs')
    transfer_receipt, transfer_raw = module.read_file(TRANSFER)
    need(transfer_receipt['sha256'] == TRANSFER_SHA, 'pinned transfer proof differs')
    transfer = module.decode(transfer_raw)
    offset, versions = 0, set()
    for row in transfer['transfer']:
        need(row['offset'] == offset and row['size'] == len(archive_bytes), 'transfer interval differs')
        next_offset = row['next_offset']
        need(offset < next_offset <= len(archive_bytes) and row['chunk_sha256'] ==
             module.sha(archive_bytes[offset:next_offset]), 'transfer chunk hash differs')
        need(row['eof'] is (next_offset == len(archive_bytes)), 'transfer EOF differs')
        versions.add(row['version'])
        offset = next_offset
    need(offset == len(archive_bytes) and len(versions) == 1, 'incomplete or mixed-version transfer')
    terminal = transfer['terminal']
    need(terminal['state'] == 'cancelled' and terminal['cancelled'] is True and
         terminal['exit_code'] == -15 and terminal['output_complete'] is True and
         terminal['timed_out'] is False, 'native cancellation proof differs')

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
        elif path.name.endswith('.log'):
            text = raw.decode('utf-8')
            values[name], formats[name] = text.splitlines(keepends=True), {
                'format': 'UTF-8 text lines', 'lines': len(text.splitlines(keepends=True)),
                'line_terminators_retained': True, 'final_newline': raw.endswith(b'\n')}
        else:
            raise ValueError('unrecognized complete input format')
    need(len(raw_files) == 102 and sum(map(len, raw_files.values())) == 6104475,
         'complete extracted file inventory differs')
    with tarfile.open(ARCHIVE, 'r:gz') as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        need(len(names) == len(set(names)) == 102 and set(names) == set(raw_files),
             'archive and extracted path sets differ')
        for member in members:
            path = PurePosixPath(member.name)
            need(member.isfile() and not path.is_absolute() and '..' not in path.parts,
                 'nonregular or unsafe archive member')
            stream = archive.extractfile(member)
            need(stream is not None and stream.read() == raw_files[member.name],
                 'archive member and extracted bytes differ')

    inventory_name = 'a27-archive-r01-interruption-inventory.json'
    inventory = values[inventory_name]
    need(module.sha(raw_files[RUN + 'plan.json']) == PLAN_SHA, 'frozen plan differs')
    plan = values[RUN + 'plan.json']
    specs = {spec['id']: spec for spec in plan['cells']}
    need(len(specs) == len(plan['cells']) == 536, 'planned cell set differs')
    need(set(inventory['artifacts']) == {name[len(RUN):] for name in raw_files if name.startswith(RUN)},
         'original interruption inventory omits or adds a run artifact')
    for name, declared in inventory['artifacts'].items():
        raw = raw_files[RUN + name]
        need(declared == {'bytes': len(raw), 'sha256': module.sha(raw)}, 'inventory original receipt differs')
    need(RUN + 'series.json' not in raw_files and RUN + 'inputs-after.json' not in raw_files,
         'unexpected final receipt must be reviewed')

    groups, stream_summary, query_rows = {}, {}, []
    for arm in ('A', 'B'):
        name = RUN + f'size-16384/arm-{arm}/stdout.jsonl'
        records = values[name]
        by_sequence = defaultdict(list)
        for row in records:
            if row.get('event') in ('cell_started', 'query', 'cell_complete'):
                by_sequence[row['sequence']].append(row)
        groups[arm] = by_sequence
        queries = [row for row in records if row.get('event') == 'query']
        query_rows.extend(queries)
        summary = {'JSONL_records': len(records), 'event_counts': dict(Counter(row['event'] for row in records)),
                   'observed_query_rows': len(queries),
                   'observed_failed_query_rows': sum(row['passed'] is not True for row in queries),
                   'last_event': records[-1]['event'], 'all_lines_parsed': True}
        declared = inventory['stdout_streams'][name[len(RUN):]]
        need(declared['json_rows'] == len(records) and declared['query_rows'] == len(queries)
             and declared['query_failed_rows'] == summary['observed_failed_query_rows']
             and declared['unparsed_lines'] == [], 'stdout counts differ from original inventory')
        stream_summary[name] = summary
    cells = {name.rsplit('/', 1)[1][:-5]: value for name, value in values.items()
             if name.startswith(RUN + 'cells/') and name.endswith('.json')}
    need(len(cells) == 81 and set(cells) == {spec['id'] for spec in plan['cells'][:81]},
         'complete cell receipt set differs')
    coverage, complete_query_rows, complete_phase_counts = [], 0, Counter()
    for spec in plan['cells']:
        events = groups.get(spec['arm'], {}).get(spec['sequence'], []) if spec['rows'] == 16384 else []
        rows = [row for row in events if row['event'] == 'query']
        complete = [row for row in events if row['event'] == 'cell_complete']
        item = {'spec': spec, 'observed_query_rows': len(rows),
                'observed_failed_query_rows': sum(row['passed'] is not True for row in rows)}
        if spec['id'] in cells:
            cell = cells[spec['id']]
            need(cell['spec'] == spec and cell['events'] == events and len(complete) == 1
                 and cell['check']['complete'] == complete[0]
                 and cell['check']['query_rows'] == len(rows) == spec['calls'],
                 'complete cell and stdout events differ')
            item.update(state='complete_receipt', recorded_check_passed=cell['check']['passed'])
            complete_query_rows += len(rows)
            complete_phase_counts[spec['phase']] += 1
        elif events:
            need(len([row for row in events if row['event'] == 'cell_started']) == 1 and not complete,
                 'incomplete cell boundary differs')
            item['state'] = 'started_without_complete_receipt'
        else:
            item['state'] = 'no_start_observed_in_preserved_streams'
        coverage.append(item)
    incomplete = [item for item in coverage if item['state'] == 'started_without_complete_receipt']
    need(len(query_rows) == 9256 and complete_query_rows == 9216 and len(incomplete) == 1
         and incomplete[0]['spec']['id'] == 'cell-0081' and incomplete[0]['observed_query_rows'] == 40,
         'independent complete/partial query inventory differs')
    need(sum(row['passed'] is not True for row in query_rows) == 0,
         'observed failure count differs from supplied inventory; preserve and review')
    error_logs = {name: value for name, value in values.items() if name.endswith('/resource-errors.jsonl')}
    need(len(error_logs) == 2 and sum(map(len, error_logs.values())) == 2, 'resource error inventory differs')

    values['transfer-status.json'] = transfer
    formats['transfer-status.json'] = {'format': 'JSON'}
    raw_files['transfer-status.json'] = transfer_raw
    original_receipts['transfer-status.json'] = transfer_receipt
    seeds, jobs, loadavg_paths = [], set(), []
    def discover(value, label, path=()):
        if isinstance(value, dict):
            for key, item in value.items():
                if (key == 'job_id' or key.endswith('_job_id')) and isinstance(item, str):
                    jobs.add(item)
                    seeds.append({'identity': item})
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
    extra_identity = {'device', 'inode', 'st_dev', 'st_ino', 'st_uid', 'st_gid', 'job_id'}
    def convert(value, label, path=()):
        if isinstance(value, dict):
            mapped = {}
            for key, item in value.items():
                fixed_byte_count = (key == 'bytes' and type(item) is int
                                    and module.HEX256.fullmatch(str(value.get('sha256', ''))) is not None)
                fixed_error_number = (key == 'errno' and type(item) is int
                                      and label.endswith('/resource-errors.jsonl')
                                      and {'pid', 'birth_ticks', 'stage', 'error_type', 'message'}.issubset(value))
                if fixed_byte_count or fixed_error_number:
                    mapped[key] = key
                    if sanitizer.string(key) != key:
                        transformations.append({'document': label, 'path': list(path + (key,)),
                            'policy': 'fixed numeric schema key retained despite crate-name user heuristic',
                            'original_key': sanitizer.opaque_receipt(key), 'public_key': key,
                            'value': item, 'context': 'SHA-256 byte receipt' if fixed_byte_count else 'resource-error errno'})
                        structural['fixed_numeric_schema_key_overrides'] += 1
                else:
                    mapped[key] = sanitizer.string(key)
            multiplicity = Counter(mapped.values())
            result = {}
            for key, item in value.items():
                pk = mapped[key]
                if multiplicity[pk] > 1:
                    bound = sanitizer.opaque_receipt(key)
                    pk = '<opaque-key:' + bound['canonical_value_sha256'] + '>'
                    transformations.append({'document': label, 'path': list(path),
                                            'policy': 'collision-safe opaque key',
                                            'original_key': bound, 'public_key': pk})
                need(pk not in result, 'sanitized key collision remains')
                lower = key.lower()
                count_exception = key == 'identity' and path and path[-1] == 'readable_fields' and type(item) is int
                version = label == 'transfer-status.json' and len(path) == 2 and path[0] == 'transfer' and key == 'version'
                identity = lower in extra_identity or lower.endswith('_job_id') or lower == 'stamp' or lower.endswith('_stamp') or version
                if count_exception:
                    result[pk] = item
                    transformations.append({'document': label, 'path': list(path + (pk,)),
                                            'policy': 'numeric readable-field coverage counter retained', 'value': item})
                elif identity or lower in sanitizer.private_keys or lower in sanitizer.opaque_keys or 'base64' in lower or lower.endswith('_hex'):
                    result[pk] = sanitizer.opaque_receipt(item)
                    transformations.append({'document': label, 'path': list(path + (pk,)),
                                            'policy': 'existing opaque_receipt', 'value_receipt': result[pk]})
                    structural['opaque_fields'] += 1
                else:
                    result[pk] = convert(item, label, path + (pk,))
                structural['dictionary_keys_retained'] += 1
            need(len(value) == len(result), 'dictionary entry lost')
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
    need(structural['fixed_numeric_schema_key_overrides'] == 159, 'numeric schema override inventory differs')
    for name, path, original in loadavg_paths:
        transformed = public[name]
        for key in path:
            transformed = transformed[key]
        need(original.split()[:4] == transformed.split()[:4] and transformed.split()[-1] == '<pid>',
             'loadavg measurement fields or PID adaptation differs')
        transformations.append({'document': name, 'path': list(path), 'policy': 'loadavg final PID marker',
                                'original_complete_string': sanitizer.opaque_receipt(original),
                                'first_four_fields_preserved': True})
    # A decisive identity-free workload check: every query dictionary remains
    # byte-for-byte canonical-equivalent, including latency, flags and errors.
    for arm in ('A', 'B'):
        name = RUN + f'size-16384/arm-{arm}/stdout.jsonl'
        old = [row for row in values[name] if row.get('event') == 'query']
        new = [row for row in public[name] if row.get('event') == 'query']
        need(old == new, 'query row or metric was changed by redaction')
    for cell_id, cell in cells.items():
        target = public[RUN + 'cells/' + cell_id + '.json']
        need(cell['events'] == target['events'] and cell['check'] == target['check'],
             'cell metric/event/check content was changed')
        need(all(cell[key] == target[key] for key in ('resource_before', 'resource_after', 'spec')),
             'cell resource snapshot, scope flag or planned dimensions were changed')

    bundle = {'schema': 'hepta-a27-interrupted-archive-complete-public-evidence/v1',
              'original_archive_published': False,
              'files': {name: {**formats[name], 'value': public[name]} for name in sorted(public)}}
    plain = module.canonical(bundle)
    need(all(job.encode() not in plain for job in jobs), 'original job identity remains')
    need(module.common.Sanitizer.private_path.search(plain.decode()) is None
         and re.search(r'/proc/[0-9]+(?:/|\b)', plain.decode()) is None, 'private path or proc PID remains')
    # Preserve every input file and text/JSONL row; malformed input is refused
    # above instead of silently omitting the final line or a failed record.
    summary = {
        'schema': 'hepta-a27-interrupted-archive-scope/v1', 'publication_integrity_passed': True,
        'experiment_complete': False, 'comparison_valid': False, 'relative_performance_computed': False,
        'performance_gate_evaluated': False, 'candidate_adopted': False,
        'interruption': {'native_state': terminal['state'], 'native_exit_code': terminal['exit_code'],
                         'native_output_complete': terminal['output_complete'],
                         'native_timed_out': terminal['timed_out'],
                         'decision_basis_reported_by_root': 'absolute completion rate; 74/536 cells after approximately 30 minutes against the 90-minute outer budget',
                         'relative_arm_results_used_for_decision': False,
                         'decision_snapshot_is_distinct_from_final_preservation_inventory': True},
        'planned_cells': 536, 'complete_cell_receipts': 81, 'complete_cells_by_phase': dict(complete_phase_counts),
        'complete_cell_query_rows': 9216, 'stdout_query_rows_observed': 9256,
        'partial_cell_observed_query_rows': 40, 'observed_failed_query_rows': 0,
        'partial_cell': incomplete[0], 'cells_with_no_start_observed': 454,
        'observed_fixture_size': 16384, 'no_65536_fixture_start_observed': True,
        'stdout_streams': stream_summary, 'resource_error_rows_preserved': 2,
        'complete_native_log_capture_is_not_complete_experiment_evidence': True,
        'series_json_present': False, 'inputs_after_present': False,
        'sampler_finalization_proved': False, 'final_original_fixture_hashes_verified': False,
        'per_child_graceful_drain_proved': False,
        'original_fixtures_deleted_by_publication': False,
        'query_rows_in_cell_receipts_duplicate_stdout_rows': True,
        'raw_metric_values_retained_without_relative_aggregation': True,
        'new_workload_run': False, 'remote_calls': False,
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
    outputs['summary.json'] = module.canonical(summary)
    outputs['build_interrupted_publication_r02.py'] = source_bytes
    notes = '''# Interrupted archive experiment r01: preserved, not evaluated

The run was deliberately cancelled. Its native job ended cancelled with exit
-15 and complete captured output; it did not hit its outer timeout. Root
reported the decision as based only on absolute completion rate: 74 of 536
cells after about 30 minutes against a 90-minute budget. That earlier decision
snapshot is distinct from the later preservation inventory of 81 complete
cell receipts. No relative performance is computed or selected here.

The complete evidence bundle preserves every original file's parsed JSON,
every JSONL record, and every text-log line, including original newline
information. It contains all 102 archive members plus the separate fixed-
version transfer/status proof. Original byte hashes are retained. The raw
archive itself is private and is not a publication artifact.

There are 81 complete cell receipts: twelve warmups and 69 measured cells,
containing 9,216 query rows. The original stdout streams retain 9,256 query
rows: the extra forty belong to cell-0081, which has a start but no completion
record. Zero failed query rows were observed. This does not certify unrecorded
requests or the eventual result of unfinished work. Cell receipts repeat
stdout rows and must not be added to the stdout total. Only the 16,384-record
fixture's A/B streams are present; no 65,536-record fixture start is observed.
The coverage file retains all 536 planned cells without performance ranking.

No final series.json, inputs-after receipt, finalized sampler result, final
original-fixture hash verification, or per-child graceful-drain witness is
present. The two observed resource-error JSONL rows remain complete records,
but they are not a finalized whole-run sampling report. Native output_complete
and the systemd observation cannot supply the missing experiment/child
completion proofs. No fixture was deleted or relaunched for publication.

Every query row, cell event, cell check, cell specification and both recorded
resource snapshots are compared directly with their public counterparts.
Absolute latency, CPU and resource values remain in the
complete record without calculating relative gains, evaluating gates, or
adopting a candidate. The frozen full-scale plan remains unchanged. This
interruption is neither a performance win nor proof of a correctness failure.

The frozen A26 sanitizer supplies all string and opaque-value transformations.
Explicit context handles identity/stamp fields, job IDs, fixed file versions,
loadavg's final PID token and collision-safe opaque dictionary keys. Numeric
readable_fields.identity coverage counters would remain numeric, if present.
The fixed integer keys bytes (with a SHA-256 receipt) and errno (in a resource
error row) retain their schema names: Cargo crate names otherwise cause the
unchanged generic user-discovery rule to obscure these technical labels.
All such adaptations are listed in the complete redaction inventory. The first
local publication attempt is retained unchanged and is not for publication;
this r02 corrects only that schema-label issue, without rerunning the experiment.
Credential
or raw response fields use hash receipts; they are never decoded for public
exposure. No input, frozen package, runtime, or remote host is modified.
'''
    outputs['README.md'] = notes.encode()
    # Confirm the complete source snapshot and frozen implementation again.
    for name, original in raw_files.items():
        path = TRANSFER if name == 'transfer-status.json' else SOURCE / name
        bound, data = module.read_file(path)
        need(bound == original_receipts[name] and data == original, 'raw input changed during publication')
    need(module.read_file(ARCHIVE)[0] == archive_receipt, 'pinned raw archive changed')
    for name, (folder, _) in DEPS.items():
        need((ROOT / folder / (name + '.py')).read_bytes() == dependencies[name], 'sanitizer changed')
    need(Path(__file__).read_bytes() == source_bytes, 'transform source changed')
    manifest = {'schema': 'hepta-a27-interrupted-archive-publication/v1',
        'publication_integrity_passed': True, 'comparison_valid': False, 'performance_gate_evaluated': False,
        'relative_performance_computed': False, 'candidate_adopted': False,
        'publication_revision': 'r02',
        'prior_unpublished_attempt': {'directory': 'a27-archive-r01-interrupted-publication',
            'publication_receipt_sha256': 'ee6cdb8aa800c3131932b73b94e98df45ea1d1a78d6c3eaacf6b90c15686bbed',
            'changed_or_overwritten': False, 'publish': False,
            'reason': 'Inherited crate-name user heuristic obscured 157 fixed bytes keys and two errno keys; values and rows were retained.'},
        'original_archive': {**receipt(ARCHIVE.name, archive_bytes), 'published': False},
        'original_transfer_status': receipt(TRANSFER.name, transfer_raw),
        'fixed_transfer_chunks_verified': len(transfer['transfer']),
        'archive_members_and_extracted_bytes_match': True,
        'original_inputs': [receipt(name, raw) for name, raw in sorted(raw_files.items())],
        'frozen_sanitizer_dependencies': [receipt(name + '.py', raw) for name, raw in dependencies.items()],
        'transform_source': receipt('build_interrupted_publication_r02.py', source_bytes),
        'complete_evidence': bundle_bound, 'complete_redaction_inventory': inventory_bound,
        'complete_coverage': coverage_bound, 'preservation_counts': dict(structural),
        'all_9256_stdout_query_rows_equal_after_sanitization': True,
        'all_81_cell_events_and_checks_equal_after_sanitization': True,
        'all_162_cell_resource_snapshots_equal_after_sanitization': True,
        'all_81_complete_cell_specs_equal_after_sanitization': True,
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
