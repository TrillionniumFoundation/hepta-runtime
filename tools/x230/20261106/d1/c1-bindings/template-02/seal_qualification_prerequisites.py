#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal Q-only prerequisite identities from local originals; never import the binder."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
JOB_ID = '1a1aff8769c-fc05-6d26'
BINDER_SHA = '11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7'
HEX = re.compile('[0-9a-f]{64}\\Z')
MAXIMUM = 8 * 1024 * 1024


def need(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'indirect local path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= MAXIMUM,
             'unsafe local original')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAXIMUM + 1)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
        stamp = lambda row: tuple(getattr(row, name) for name in fields)
        need(len(raw) == before.st_size and len(raw) <= MAXIMUM and
             stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()), 'local original changed')
    finally:
        os.close(fd)
    return raw


def identity(raw, path):
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    need(read(path) == raw, 'create-only local output changed')


def main():
    need(not sys.flags.optimize, 'normal Python execution required')
    parser = argparse.ArgumentParser()
    parser.add_argument('--actual', type=Path, required=True)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    binder_raw = read(directory / 'd1_prerequisites.py')
    need(len(binder_raw) == 53934 and hashlib.sha256(binder_raw).hexdigest() == BINDER_SHA,
         'frozen corrected binder differs')
    tree = ast.parse(binder_raw)
    names = {'PINNED', 'QUALIFICATION_ARTIFACTS', 'CI_ARTIFACTS', 'CHANGED', 'ADDED',
             'STAGES', 'COUNT_KEYS', 'BINARY_NAMES', 'BASELINE_COMMIT'}
    constants = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                 if isinstance(node, ast.Assign) and len(node.targets) == 1
                 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names}
    need(set(constants) == names, 'literal source interface differs')
    example_raw = read(directory / 'prerequisites.unsealed.json')
    result = json.loads(example_raw)
    need(result['schema'] == 'hepta-d1-c1-prerequisites/v1'
         and result['qualification_sealed'] is False and result['exact_ci_sealed'] is False,
         'source example is not unsealed')
    need(set(result['artifact_map']) == set(constants['PINNED']) |
         set(constants['QUALIFICATION_ARTIFACTS']) | set(constants['CI_ARTIFACTS']),
         'fixed artifact set differs')
    raw_static = {}
    for name, pin in constants['PINNED'].items():
        raw = read(args.package / name)
        need(identity(raw, ROOT / name) == pin == result['artifact_map'][name], 'frozen package pin differs: ' + name)
        raw_static[name] = raw
    raw_actual, originals = {}, {}
    for name in [*constants['QUALIFICATION_ARTIFACTS'], 'qualification-native-read-01.json']:
        need(result['artifact_map'].get(name) is None, 'actual identity already exists')
        raw = read(args.actual / name)
        raw_actual[name] = raw
        originals[name] = identity(raw, ROOT / name)
    values = {name: json.loads(raw) for name, raw in raw_actual.items()}
    prep = values['preparation.json']
    report = values['qualification-01/report.json']
    source_map = values['qualification-01/source-map.json']
    summary = values['qualification-01/isolated-tests/summary.json']
    audit = values['qualification-01/isolated-tests.audit.json']
    terminal = values['qualification-terminal-status-01.json']
    page = values['qualification-native-read-01.json']
    need(terminal['job_id'] == page['job_id'] == JOB_ID and terminal['state'] == 'succeeded'
         and type(terminal['exit_code']) is int and terminal['exit_code'] == 0
         and terminal['audit_recorded'] is page['audit_recorded'] is True
         and terminal['output_complete'] is terminal['output_durable'] is True
         and terminal['terminal_publication_confirmed'] is True
         and terminal['terminal_publication_protocol'] == 1
         and terminal['automatic_retry'] is terminal['timed_out'] is terminal['cancelled'] is False,
         'the actual original Q terminal is not complete success')
    streams = {}
    for name in ('stdout', 'stderr'):
        channel = page[name]
        body = bytes.fromhex(channel['bytes_hex'])
        total = terminal['log_bytes'][name]['stored']
        need(type(total) is int and 0 <= total <= 16384 and len(body) == total
             and terminal['log_bytes'][name]['seen'] == total
             and terminal['log_errors'][name] is None and terminal['log_synced'][name] is True
             and terminal['log_truncated'][name] is False
             and channel['offset'] == 0 and channel['size'] == channel['next_offset'] == total
             and channel['eof'] is True and channel['text'] == body.decode('utf-8', errors='replace'),
             'original complete native stream differs: ' + name)
        streams[name] = body
    need(streams['stderr'] == b'', 'qualification stderr is nonempty')
    rows = [json.loads(line) for line in streams['stdout'].splitlines()]
    need(len(rows) == 18, 'original eight-stage stdout shape differs')
    for index, name in enumerate(constants['STAGES']):
        need(rows[index * 2] == {'stage': name, 'state': 'started'}
             and rows[index * 2 + 1]['stage'] == name and rows[index * 2 + 1]['exit'] == 0,
             'native stage stream differs')
    need(rows[-2] == {'qualified': True, 'report': str(ROOT / 'qualification-01/report.json'), 'error': None}
         and rows[-1] == {'passed': True, 'error': None, 'qualification_returncode': 0,
                         'free_bytes_before': prep['free_bytes_before']}, 'native final receipts differ')
    candidate = json.loads(raw_static['candidate/input.json'])
    build_input = json.loads(raw_static['qualification-input.json'])
    closure = json.loads(raw_static['cache-owner-closure-inputs.json'])
    need(prep['schema'] == 'hepta-x230-d1-preparation/v1' and prep['passed'] is True
         and prep['finished_utc'] and not prep.get('error') and prep['qualification_returncode'] == 0
         and prep['qualification_started'] is prep['first_actual_d1_qualification_required'] is True
         and prep['diagnostic_environment_absent'] is True
         and prep['ordinary_supplemental_executed'] is prep['performance_acceptance_claim'] is False
         and prep['automatic_retries'] == 0 and prep['production_services_modified'] is False,
         'actual first preparation did not pass')
    need(build_input['sealed'] is True and build_input['required_missing_bindings'] == []
         and all(build_input[name] is None for name in ('actual_d1_qualification', 'actual_d1_formatted_map',
             'actual_d1_test_counts', 'actual_d1_release_programs')), 'historical preparation inputs changed')
    pinned = constants['PINNED']
    patch = raw_static['candidate/candidate.patch']
    patch_git = hashlib.sha1(b'blob ' + str(len(patch)).encode('ascii') + b'\0' + patch).hexdigest()
    need(patch_git == '3de16de910158951dc17bb8f52883b88dd832d5a'
         and prep['candidate_patch'] == {**pinned['candidate/candidate.patch'], 'git_blob': patch_git}
         and prep['input_binding'] == pinned['qualification-input.json']
         and prep['frozen_candidate_input'] == pinned['candidate/input.json']
         and prep['frozen_candidate_manifest'] == pinned['candidate/package-manifest.json']
         and prep['publication_provenance'] == pinned['provenance/source-anchor-and-publication-parent.json']
         and prep['cache_owner_closure_input'] == pinned['cache-owner-closure-inputs.json']
         and prep['qualification_report_sha256'] == originals['qualification-01/report.json']['sha256'],
         'original preparation input/result identities differ')
    need(report['schema'] == 'hepta-x230-composed-qualification/v1' and report['qualified'] is True
         and report['finished_utc'] and not report.get('error') and report['jobs'] == 2
         and report['automatic_test_retries'] == 0 and report['service_changes'] is False
         and report['source'] == str(ROOT / 'source') and prep['free_bytes_before'] >= 3 * 1024 ** 3
         and prep['process_check']['matched_processes'] == prep['process_check']['compiler_processes'] == [],
         'original qualification success/preflight differs')
    need([row['name'] for row in report['stages']] == constants['STAGES']
         and all(type(row['returncode']) is int and row['returncode'] == 0
                 and HEX.fullmatch(row['stdout_sha256']) and HEX.fullmatch(row['stderr_sha256'])
                 for row in report['stages']), 'actual original eight stages differ')
    for row in report['stages']:
        if row['name'] in ('clippy', 'test-build', 'release'):
            need({'--all-features', '--offline', '--locked'} <= set(row['command']), 'original feature command differs')
    baseline, preformat = candidate['baseline_compile_inputs'], candidate['candidate_compile_inputs']
    need(candidate['baseline_commit'] == candidate['git_parent'] == build_input['baseline_commit']
         == build_input['source_construction_parent'] == prep['source_baseline'] == constants['BASELINE_COMMIT']
         and len(baseline) == 220 and len(preformat) == len(source_map) == 222
         and set(candidate['changed_paths']) == constants['CHANGED']
         and set(candidate['added_paths']) == constants['ADDED']
         and set(preformat) == set(source_map) and set(source_map) - set(baseline) == constants['ADDED']
         and not set(baseline) - set(source_map)
         and {name for name in preformat if preformat[name] != baseline.get(name)} == constants['CHANGED']
         and {name for name in source_map if source_map[name] != baseline.get(name)} == constants['CHANGED']
         and sum(name.endswith('.py') for name in source_map) == 17
         and prep['source_before_qualification'] == report['source_input'] == preformat
         and prep['source_after_qualification'] == report['source_after'] == report['source_tested'] == source_map,
         'actual before/after formatter map does not bind the frozen R24 patch')
    harness = build_input['qualification_harness_sha256']
    need(len(harness) == 19 and report['harness_before'] == report['harness_after']
         == prep['qualification_harness_sha256'] == harness, 'original nineteen harnesses differ')
    counts = {name: summary[name] for name in constants['COUNT_KEYS']}
    need(summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
         and summary['filter'] == '' and summary['enumeration_errors'] == [] and not summary.get('fatal_error')
         and all(type(value) is int and value >= 0 for value in counts.values())
         and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
         and counts['selected'] == counts['passed'] + counts['ignored'], 'actual test counts do not reconcile')
    need(audit['schema'] == 'hepta-isolated-libtest-audit/v1' and audit['success'] is True
         and audit['errors'] == [] and not audit.get('fatal_error') and audit['expected_filter'] == ''
         and audit['evidence'] == str(ROOT / 'qualification-01/isolated-tests')
         and audit['auditor_sha256'] == harness['audit_isolated_tests.py']
         and all(audit[name] == counts[name] for name in ('passed', 'failed', 'ignored', 'selected'))
         and audit['executed'] == counts['passed']
         and audit['input_sha256']['summary.json'] == originals['qualification-01/isolated-tests/summary.json']['sha256']
         and audit['input_sha256']['source-manifest.input'] == summary['source_manifest_sha256']
         == originals['qualification-01/source-map.json']['sha256']
         and audit['binaries'] and all(row['recorded_before_sha256'] == row['current_after_sha256']
                                     and HEX.fullmatch(row['current_after_sha256']) for row in audit['binaries']),
         'original isolated-audit result or its inputs differ')
    owner = prep['cache_owner_closure']
    need(closure['sealed'] is True and closure['required_missing_bindings'] == []
         and owner['inputs'] == closure['inputs'] and owner['postflight'] == closure['postflight']
         and all(owner[key] is True for key in ('qualification_and_exact_ci_succeeded',
             'observation_performance_passed', 'normal_lifecycle_executed', 'normal_lifecycle_workflow_closed',
             'normal_lifecycle_controllers_closed', 'owned_agents_reaped'))
         and owner['normal_lifecycle_performance_passed'] is owner['r35_adoption_claimed']
         is owner['original_auditors_reexecuted'] is False
         and prep['cache_transferred_by_rename'] is True
         and prep['new_full_cache_copy_bytes'] == prep['cache_deletions'] == 0,
         'recorded completed cache-owner/rename statements differ')
    need(set(report['binaries']) == set(constants['BINARY_NAMES']) and
         all(set(row) == {'path', 'sha256'} and row['path'] == str(ROOT / 'qualification-01' / name)
             and HEX.fullmatch(row['sha256']) for name, row in report['binaries'].items()),
         'original retained release identities differ')
    for name in constants['QUALIFICATION_ARTIFACTS']:
        result['artifact_map'][name] = originals[name]
    result.update(qualification_sealed=True, required_missing_qualification_bindings=[],
                  qualification_original_job_id=JOB_ID,
                  qualification_read_pages=[originals['qualification-native-read-01.json']])
    need(result['exact_ci_sealed'] is False and result['exact_ci_original_job_id'] is None
         and result['exact_ci_read_pages'] is None and result['required_missing_exact_ci_bindings']
         and all(result['artifact_map'][name] is None for name in constants['CI_ARTIFACTS'])
         and result['performance_acceptance_claim'] is False, 'future CI/performance claim was introduced')
    output_raw = canonical(result)
    receipt = {'schema': 'hepta-d1-local-q-prerequisite-seal/v1', 'passed': True,
        'qualification_original_job_id': JOB_ID,
        'binder': identity(binder_raw, ROOT / 'rust-ci-prerequisites-01/d1_prerequisites.py'),
        'source_example': identity(example_raw, directory / 'prerequisites.unsealed.json'),
        'sealer': identity(read(Path(__file__).resolve()), Path(__file__).resolve()),
        'output': identity(output_raw, ROOT / 'qualification-prerequisites-01.json'),
        'actual_originals': originals, 'static_originals': constants['PINNED'],
        'tests': counts, 'source_before_count': len(preformat), 'source_after_count': len(source_map),
        'baseline_count': len(baseline), 'changed_paths': sorted(constants['CHANGED']),
        'added_paths': sorted(constants['ADDED']), 'embedded_python_count': 17, 'harness_count': 19,
        'native_streams': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                           for name, raw in streams.items()},
        'candidate_patch_four_field_identity': prep['candidate_patch'],
        'retained_release_identities_from_original_report': report['binaries'],
        'retained_release_bytes_read_locally': False,
        'prior_owner_originals_rehashed_by_this_sealer': False,
        'live_source_cache_or_process_state_checked_locally': False,
        'current_host_rebinding_required_before_ci': True,
        'target_module_imported_or_functions_called': False,
        'qualifier_auditor_ci_or_measurement_reexecuted': False,
        'exact_ci_result_claimed': False, 'performance_acceptance_claim': False}
    receipt_raw = canonical(receipt)
    need(args.output.is_absolute() and args.output.parent.resolve() == args.output.parent,
         'unsafe local output path')
    args.output.mkdir(mode=0o700)
    create(args.output / 'qualification-prerequisites-01.json', output_raw)
    create(args.output / 'seal-receipt-01.json', receipt_raw)
    fd = os.open(args.output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps({'passed': True, 'qualification_prerequisites': receipt['output'],
                      'receipt': identity(receipt_raw, args.output / 'seal-receipt-01.json'),
                      'tests': counts, 'exact_ci_sealed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
