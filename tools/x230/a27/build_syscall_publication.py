#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Publish the one completed syscall experiment without running a workload.

Uses the frozen A26 CompleteSanitizer unchanged. Inputs and outputs are fixed
relative to this script; publication is create-only and raw inputs are retained.
"""

from collections import Counter
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parent
SOURCE = HERE / 'evidence'
DESTINATION = HERE / 'publication'
DEPENDENCIES = {
    'build_x230_a26_series_evidence_r02': (
        'a26-series-tools', '610b7c95dfa46b25e677b29095f0b813c1074aefef4f8a101910b95b2978748f'),
    'build_x230_evidence': (
        'a25-evidence-tools', 'd868f8aab6db0b8d35fd38116241355660758a1e4b336b64cda3f7b945ffa4fb'),
    'build_x230_six_running_evidence': (
        'a25-evidence-tools', 'e079b19be97815bb8c4a41891fa995e40e1e353425b7e909bb814a65a3359c52'),
}
INPUT_HASHES = {
    'plan.json': 'ae726e0ae7d436a4f918b3296d7becd4f687238041516b5f85c9609d55ea1268',
    'report.json': '912e2eb36d70563be51c0a1e66b0d2a9301cfee897259b1a73505aab84660450',
    'review.json': '025a96212f67709c768157376135d0974b48c024051f45cc442fd7eeb8e3f5cb',
}
HOSTS = {'ai395', 'mac', 'main', 'pocket4', 'rog', 'x230'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_receipt(name, raw):
    return {'file': name, 'bytes': len(raw), 'sha256': sha(raw),
            'git_blob_sha1': hashlib.sha1(
                b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def main():
    need(len(sys.argv) == 1, 'no command or path overrides accepted')
    need(not DESTINATION.exists(), 'publication already exists; never overwrite an attempt')
    sys.dont_write_bytecode = True
    dependency_raw = {}
    for name, (directory, expected) in DEPENDENCIES.items():
        path = WORKSPACE / directory / (name + '.py')
        need(path == path.resolve(), 'indirect dependency path refused')
        raw = path.read_bytes()
        need(sha(raw) == expected, 'frozen sanitizer dependency changed')
        dependency_raw[name] = raw
    sys.path[:0] = [str(WORKSPACE / 'a26-series-tools'), str(WORKSPACE / 'a25-evidence-tools')]
    module = importlib.import_module('build_x230_a26_series_evidence_r02')
    for name, (directory, _) in DEPENDENCIES.items():
        need(Path(sys.modules[name].__file__).resolve() ==
             WORKSPACE / directory / (name + '.py'), 'unexpected sanitizer module')

    originals = {}
    input_receipts = {}
    values = {}
    for name, expected in INPUT_HASHES.items():
        receipt, raw = module.read_file(SOURCE / name)
        need(not receipt['retention_limit_exceeded'] and receipt['sha256'] == expected,
             'fixed original input changed or exceeded complete-read limit')
        originals[name], input_receipts[name] = raw, receipt
        values[name] = module.decode(raw)
    plan, report, review = [values[name] for name in ('plan.json', 'report.json', 'review.json')]
    job_ids = plan['original_jobs']
    need(isinstance(job_ids, list) and len(job_ids) == len(set(job_ids)) == 6
         and all(isinstance(value, str) and len(value) >= 6 for value in job_ids),
         'expected six original job identities')
    groups = {'preflight': report['preflight'], 'instrumented_cell/rows': report['instrumented_cell']['rows'],
              'final_observations': report['final_observations']}
    need({key: len(rows) for key, rows in groups.items()} ==
         {'preflight': 6, 'instrumented_cell/rows': 96, 'final_observations': 12},
         'complete original row counts differ')
    for rows in groups.values():
        need(all(isinstance(row, dict) and row.get('job_id') in job_ids for row in rows),
             'unexpected row identity')
        need({row['host'] for row in rows} == HOSTS, 'six host aliases not represented')
    need(review['observations'] == sum(map(len, groups.values())) == 114,
         'observation total does not match the complete rows')
    commands = report['trace_commands']
    need(isinstance(commands, list) and commands and all(
        isinstance(command, list) and command and all(isinstance(arg, str) for arg in command)
        for command in commands), 'trace command inventory malformed')

    # The unchanged sanitizer does not classify job_id/original_jobs itself.
    # Generic identity discovery seeds activate its existing string policy;
    # this seed object is not inserted into or substituted for raw evidence.
    seed = {'documents': values, 'identity_discovery_seeds': [{'identity': value} for value in job_ids]}
    sanitizer = module.CompleteSanitizer(seed)
    public = {name: sanitizer(value) for name, value in values.items()}
    # This source names the argv container trace_commands, not argv. Give each
    # complete argv row its explicit existing opaque context; keep row order.
    public['report.json']['trace_commands'] = [
        sanitizer({'argv': command})['argv'] for command in commands]

    structural = {}
    opaque_fields = []

    def walk(original, transformed, path, counts, document):
        if document == 'report.json' and len(path) == 2 and path[0] == 'trace_commands':
            need(transformed == sanitizer.opaque_receipt(original), 'argv receipt mismatch')
            opaque_fields.append({'document': document, 'path': list(path),
                                  'policy': 'existing opaque argv receipt',
                                  'value': transformed})
            counts['opaque_subtrees_replaced'] += 1
        elif isinstance(original, dict):
            need(isinstance(transformed, dict) and len(original) == len(transformed),
                 'dictionary key count changed')
            counts['object_nodes'] += 1
            counts['dictionary_keys'] += len(original)
            need({sanitizer.string(key) for key in original} == set(transformed),
                 'dictionary key set changed outside sanitizer policy')
            for key, value in original.items():
                public_key = sanitizer.string(key)
                lower = key.lower()
                if (lower in sanitizer.private_keys or lower in sanitizer.opaque_keys
                        or 'base64' in lower or lower.endswith('_hex')):
                    need(transformed[public_key] == sanitizer.opaque_receipt(value),
                         'identity or opaque receipt mismatch')
                    opaque_fields.append({'document': document, 'path': list(path + (public_key,)),
                                          'policy': 'unchanged CompleteSanitizer classified field',
                                          'value': transformed[public_key]})
                    counts['opaque_subtrees_replaced'] += 1
                else:
                    walk(value, transformed[public_key], path + (public_key,), counts, document)
        elif isinstance(original, list):
            need(isinstance(transformed, list) and len(original) == len(transformed),
                 'list row count changed')
            counts['list_nodes'] += 1
            counts['list_items'] += len(original)
            for index, (value, target) in enumerate(zip(original, transformed)):
                walk(value, target, path + (index,), counts, document)
        elif isinstance(original, str):
            need(transformed == sanitizer.string(original), 'string transformed outside existing policy')
            counts['string_values_exact_policy'] += 1
        else:
            need(type(original) is type(transformed) and original == transformed,
                 'numeric, boolean or null evidence value changed')
            counts['nonstring_values_unchanged'] += 1

    for name, value in values.items():
        counts = Counter()
        walk(value, public[name], (), counts, name)
        structural[name] = dict(counts)

    row_counts = {}
    public_groups = {'preflight': public['report.json']['preflight'],
                     'instrumented_cell/rows': public['report.json']['instrumented_cell']['rows'],
                     'final_observations': public['report.json']['final_observations']}
    for name, rows in groups.items():
        original_counts = {'rows': len(rows), 'passed': sum(row.get('okay') is True for row in rows),
                           'failed_or_not_passed': sum(row.get('okay') is not True for row in rows),
                           'isError_true': sum(row.get('isError') is True for row in rows),
                           'automatic_retry_true': sum(row.get('automatic_retry') is True for row in rows)}
        target = public_groups[name]
        target_counts = {'rows': len(target), 'passed': sum(row.get('okay') is True for row in target),
                         'failed_or_not_passed': sum(row.get('okay') is not True for row in target),
                         'isError_true': sum(row.get('isError') is True for row in target),
                         'automatic_retry_true': sum(row.get('automatic_retry') is True for row in target)}
        need(original_counts == target_counts, 'observation result counts changed')
        row_counts[name] = original_counts

    historical_flags = []
    def find_flags(value, path=()):
        if isinstance(value, dict):
            for key, item in value.items():
                if 'lower_bound' in key:
                    historical_flags.append({'path': list(path + (key,)),
                                             'original_and_public_value': item,
                                             'endorsed_by_this_publication': False})
                find_flags(item, path + (key,))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                find_flags(item, path + (index,))
    find_flags(public['report.json'])
    need(len(historical_flags) == 2 and all(row['original_and_public_value'] is True
                                         for row in historical_flags), 'historical flag inventory changed')

    output_raw = {name.replace('.json', '.complete.sanitized.json'): module.canonical(value)
                  for name, value in public.items()}
    combined = b'\n'.join(output_raw.values())
    need(all(value.encode() not in combined for value in job_ids), 'original job identity remained')
    need(all(value.encode() not in combined for value in sanitizer.private_values),
         'discovered private identity remained')
    need(module.common.Sanitizer.private_path.search(combined.decode()) is None,
         'private filesystem path remained')
    # Re-read raw inputs and dependency bytes before first output is created.
    for name, raw in originals.items():
        current, fresh = module.read_file(SOURCE / name)
        need(current == input_receipts[name] and fresh == raw, 'original input changed during publication')
    for name, (directory, _) in DEPENDENCIES.items():
        need((WORKSPACE / directory / (name + '.py')).read_bytes() == dependency_raw[name],
             'sanitizer implementation changed during publication')

    notes = '''# A27 syscall publication: interpretation limits

These are complete sanitized copies of the original plan, report and review.
All 114 observation rows remain: six preflight checks, 96 instrumented calls,
and twelve final checks. Their result/error/retry flags, metric values, times,
resource counters and retained sampling-error entries remain unchanged.
Identity or opaque payload fields use the frozen A26 sanitizer policy and
hash receipts; the publication receipt binds both original and public bytes.

Two original flags remain true in the report:
`instrumented_cell.sampled_tree_cpu_seconds_delta_is_lower_bound` and
`shutdown_wrapper.resources.sampled_peaks_and_tree_cpu_are_lower_bounds`.
They are historical producer assertions, not valid guarantees endorsed here.
Cross-process samples are incomplete and not simultaneous. Differences of
sampled lifetime CPU counters are estimates and need not be rigorous lower
bounds for the corresponding cell interval. This publication records the
limitation separately rather than rewriting those original evidence flags.

The inherited helper tracked the strace wrapper as its root process. Its
`controller_cpu_seconds`, `controller_cpu_ms_per_call`, controller RSS/FD
fields and same-PID CPU-source text must not be read as isolated runtime CPU
or resource measurements. The plan's wrapper warning and review's explicit
interpretation flags remain present. Descendant aggregates and syscall
counts cover instrumented activity; they do not repair this attribution.

The syscall trace covers the complete traced controller lifetime including
local descendants. Instrumentation changes timing. Syscall error counts
are not RPC failures, and a futex syscall-time percentage is not a runtime
CPU fraction. This is neither a throughput comparison nor a user-space CPU
profile. There is one retained resource-sampling error in the original
report; its complete sanitized text remains present. Retaining that array
does not prove that all unsampled processes or unavailable fields were seen.

The six original job IDs are discovered from the source plan and bound to
full canonical hash receipts. The unchanged sanitizer replaces their string
occurrences with its existing private-identity markers. The original
`trace_commands` list keeps its order and row count, while each complete argv
row becomes the existing opaque argv receipt. No base64 or command payload
is decoded, no observation is replayed, and no raw evidence is modified.
'''
    output_raw['PUBLICATION_NOTES.md'] = notes.encode()
    publication = {
        'schema': 'hepta-x230-a27-syscall-publication/v1',
        'publication_integrity_passed': True,
        'new_workload_run': False, 'remote_calls': False, 'raw_inputs_modified': False,
        'runtime_modified': False, 'performance_comparison': False,
        'builder': file_receipt(Path(__file__).name, Path(__file__).read_bytes()),
        'sanitizer_implementation_modified': False,
        'sanitizer_dependencies': [file_receipt(name + '.py', raw) for name, raw in dependency_raw.items()],
        'original_inputs': [file_receipt(name, raw) for name, raw in originals.items()],
        'public_artifacts': [file_receipt(name, raw) for name, raw in output_raw.items()],
        'preservation': {'all_original_dictionary_keys_and_nonopaque_list_rows_retained': True,
                         'all_nonidentity_numeric_boolean_null_values_unchanged': True,
                         'all_observation_rows_retained': True,
                         'metric_failure_and_retry_values_unchanged': True,
                         'timestamps_retained': True,
                         'structure_checks': structural, 'observation_counts': row_counts,
                         'sampling_error_entries_retained': len(report['shutdown_wrapper']['resources']['errors'])},
        'identity_discovery': {'source': 'plan.json/original_jobs',
                               'method': 'generic identity seeds supplied to unchanged CompleteSanitizer',
                               'exact_unique_values': len(job_ids),
                               'six_original_values_absent_from_all_public_artifacts': True,
                               'ordered_value_receipts': [sanitizer.opaque_receipt(value) for value in job_ids]},
        'opaque_replacements': opaque_fields,
        'historical_invalid_lower_bound_flags': historical_flags,
        'interpretation': {'original_flags_preserved_without_endorsement': True,
                           'controller_named_resource_fields_refer_to_strace_wrapper': True,
                           'wrapper_CPU_is_not_runtime_CPU': True,
                           'all_timing_instrumented': True,
                           'syscall_error_counts_are_not_RPC_failures': True,
                           'no_user_space_CPU_attribution': True},
    }
    receipt_raw = module.canonical(publication)
    need(all(value.encode() not in receipt_raw for value in job_ids), 'identity leaked through receipt')
    need(module.common.Sanitizer.private_path.search(receipt_raw.decode()) is None,
         'private filesystem path leaked through receipt')
    output_raw['publication-receipt.json'] = receipt_raw
    DESTINATION.mkdir(mode=0o700)
    for name, raw in output_raw.items():
        module.create_only(DESTINATION / name, raw)
    descriptor = os.open(DESTINATION, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    for name, raw in output_raw.items():
        need((DESTINATION / name).read_bytes() == raw, 'public artifact final read mismatch')
    print(json.dumps({'publication_integrity_passed': True,
                      'artifacts': [file_receipt(name, raw) for name, raw in output_raw.items()]},
                     indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
