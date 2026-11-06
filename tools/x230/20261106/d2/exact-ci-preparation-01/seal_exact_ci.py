#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal D2 exact-CI tools from actual completed qualification originals.

This local sealer never runs a CI command, materializer, qualifier, host probe,
or measurement. Detailed current host binding remains the Q-only foundation's
read-only task before the original materializer may publish a plan.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

from build_templates import HERE, PINS, ROOT, TOOL_NAMES, encode, identity, prepare_texts, replace_assignments

EXPECTED = {
    'qualification_report': 'qualification-01/report.json',
    'qualification_source_map': 'qualification-01/source-map.json',
    'qualification_isolated_summary': 'qualification-01/isolated-tests/summary.json',
    'qualification_isolated_audit': 'qualification-01/isolated-tests.audit.json',
    'qualification_preparation': 'preparation.json',
    'qualification_terminal_status': 'qualification-terminal-status-01.json',
    'qualification_launcher': 'prepare_qualify.py',
    'qualification_input': 'qualification-input.json',
    'candidate_patch': 'candidate/candidate.patch',
    'frozen_candidate_input': 'candidate/input.json',
    'foundation_binder': 'full-prerequisites-01/d2_prerequisites.py',
    'qualification_prerequisites': 'qualification-prerequisites-01.json',
}
STATIC_IDENTITIES = {
    "qualification_launcher": [
        39590,
        "2e36a1f29f4edd7439c32bc6f6443873dca03d2998381931db67f7034db404fb"
    ],
    "qualification_input": [
        3381,
        "db42905b89941203e06a3e7335b9e689e551abc02f6c154a0accd6f4a4412e0c"
    ],
    "candidate_patch": [
        4524,
        "56c8bebbe71d9fffde1fe561fa1fdb586251a9db1eccd5a101178fd3316d5e4b"
    ],
    "frozen_candidate_input": [
        53275,
        "f3d4743ac331e529db92b0a93256dec455c4b8c0788daa6fd88eec4b2982cd99"
    ]
}


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pins', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(not sys.flags.optimize, 'normal Python guards required')
    pins_raw = args.pins.read_bytes()
    pins = json.loads(pins_raw)
    need(pins['schema'] == 'hepta-d2-exact-rust-ci-actual-pins/v1' and pins['sealed_inputs'] is True,
         'actual completed input identities are required')
    job = pins['qualification_job_id']
    need(type(job) is str and len(job.split('-')) == 3, 'actual original qualification job required')
    need(set(pins['files']) == set(EXPECTED), 'actual input inventory differs')
    template = HERE / 'unsealed-tools/materialize_rust_ci_plan_01.py'
    spec = importlib.util.spec_from_file_location('_d2_unsealed_materializer_definitions', template)
    materializer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(materializer)
    raw, bound = {}, {}
    for label, relative in EXPECTED.items():
        row = pins['files'][label]
        need(isinstance(row, dict) and row['path'] == str(Path(ROOT) / relative), 'actual remote path differs: ' + label)
        need(type(row['bytes']) is int and row['bytes'] > 0 and isinstance(row['sha256'], str)
             and len(row['sha256']) == 64 and row['local_path'], 'unsealed original input: ' + label)
        local_identity, original = materializer.read_file(Path(row['local_path']), retain=True)
        need(identity(original) == {key: row[key] for key in ('bytes', 'sha256')}, 'original bytes differ: ' + label)
        raw[label] = original
        bound[label] = {key: row[key] for key in ('path', 'bytes', 'sha256')}
        if label in STATIC_IDENTITIES:
            need((row['bytes'], row['sha256']) == tuple(STATIC_IDENTITIES[label]), 'frozen D2 construction input changed')
    terminal = json.loads(raw['qualification_terminal_status'])
    materializer.JOB_ID = job
    materializer.verify_terminal(terminal)
    qualified = json.loads(raw['qualification_report'])
    materializer.verify_qualification(qualified)
    source_map = json.loads(raw['qualification_source_map'])
    frozen = json.loads(raw['frozen_candidate_input'])
    need(source_map == qualified['source_after'] == qualified['source_tested'] and len(source_map) == 222,
         'actual formatted source map differs')
    need(qualified['source_input'] == frozen['candidate_compile_inputs'], 'qualification did not start from frozen D2 input')
    baseline = frozen['baseline_compile_inputs']
    need(len(baseline) == 222 and len(frozen['changed_paths']) == 2 and frozen['added_paths'] == [],
         'D2 source construction scope differs')
    need(set(source_map) == set(frozen['candidate_compile_inputs'])
         and {name for name in source_map if source_map[name] != baseline.get(name)} == set(frozen['changed_paths']),
         'formatter changed outside the two D2 paths')
    preparation = json.loads(raw['qualification_preparation'])
    need(preparation['schema'] == 'hepta-x230-d2-preparation/v1' and preparation['passed'] is True
         and preparation['qualification_started'] is True and preparation['qualification_returncode'] == 0
         and preparation['finished_utc'] and not preparation.get('error'), 'D2 preparation is not completed')
    need(preparation['qualification_report_sha256'] == bound['qualification_report']['sha256']
         and preparation['source_before_qualification'] == qualified['source_input']
         and preparation['source_after_qualification'] == source_map,
         'preparation source/report binding differs')
    need(preparation['diagnostic_environment_absent'] is True and preparation['ordinary_supplemental_executed'] is False,
         'original all-features qualification mode differs')
    summary, audit = json.loads(raw['qualification_isolated_summary']), json.loads(raw['qualification_isolated_audit'])
    need(summary['schema'] == 'hepta-isolated-libtest/v1' and summary['success'] is True
         and summary['filter'] == '' and summary['enumeration_errors'] == [] and summary['retries'] == 0,
         'actual isolated suite did not complete')
    counts = {key: summary[key] for key in ('passed', 'failed', 'ignored', 'selected', 'retries')}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
         and counts['selected'] == counts['passed'] + counts['ignored'], 'invalid complete actual counts')
    need(audit['schema'] == 'hepta-isolated-libtest-audit/v1' and audit['success'] is True
         and audit['errors'] == [] and 'fatal_error' not in audit and audit['expected_filter'] == ''
         and all(audit[key] == counts[key] for key in ('passed', 'failed', 'ignored', 'selected'))
         and audit['executed'] == counts['passed'], 'independent audit differs from actual counts')
    need(summary['source_manifest_path'] == str(Path(ROOT) / 'qualification-01/source-map.json')
         and summary['source_manifest_sha256'] == bound['qualification_source_map']['sha256']
         and audit['input_sha256']['summary.json'] == bound['qualification_isolated_summary']['sha256'],
         'isolated summary/audit original input binding differs')
    prerequisite = json.loads(raw['qualification_prerequisites'])
    need(prerequisite['schema'] == 'hepta-d2-c1-prerequisites/v1' and prerequisite['qualification_sealed'] is True
         and prerequisite['exact_ci_sealed'] is False, 'independent Q-only prerequisites required')
    need(prerequisite['prerequisite_module'] == bound['foundation_binder'],
         'Q-only foundation does not bind the exact canonical D2 module')
    binder_ast = ast.parse(raw['foundation_binder'])
    names = {node.name for node in binder_ast.body if isinstance(node, ast.FunctionDef)}
    need({'checked', 'bind_d2_qualification', 'bind_d2_prerequisites'} <= names, 'foundation ABI differs')
    actual = {'JOB_ID': job, 'SOURCE_MAP_SHA': bound['qualification_source_map']['sha256'],
        'ISOLATED_SUMMARY_SHA': bound['qualification_isolated_summary']['sha256'],
        'ISOLATED_AUDIT_SHA': bound['qualification_isolated_audit']['sha256'],
        'QUALIFICATION_REPORT_SHA': bound['qualification_report']['sha256'],
        'PREPARATION_SHA': bound['qualification_preparation']['sha256'],
        'NATIVE_TERMINAL_SHA': bound['qualification_terminal_status']['sha256'],
        'PARENT_SHA': bound['foundation_binder']['sha256'],
        'QUALIFICATION_BINDINGS_SHA': bound['qualification_prerequisites']['sha256'], 'FROZEN_COUNTS': counts}
    need(set(actual) == set(PINS), 'actual pin set differs')
    tools = prepare_texts()
    tools['materialize_rust_ci_plan_01.py'] = replace_assignments(
        tools['materialize_rust_ci_plan_01.py'].decode(), {key: repr(value) for key, value in actual.items()}).encode()
    tool_ids = {name: identity(tools[name]) for name in TOOL_NAMES}
    manifest = {'schema': 'hepta-d2-exact-rust-ci-tools/v1', 'attempt': '01',
        'actual_qualification_job_id': job, 'qualification_report': bound['qualification_report'],
        'actual_pins': actual, 'files': tool_ids, 'executed': False, 'hosted_actions_passed': False}
    tools['package-manifest-01.json'] = encode(manifest)
    launcher_spec = {'actual_pins': actual, 'qualification_report': bound['qualification_report'],
                     'tools': tool_ids, 'manifest': identity(tools['package-manifest-01.json'])}
    tools['launch_exact_rust_ci_01.py'] = replace_assignments(
        tools['launch_exact_rust_ci_01.py'].decode(), {'SPEC': repr(launcher_spec)}).encode()
    for name, value in tools.items():
        if name.endswith('.py'):
            ast.parse(value)
    files = {'tools/' + name: value for name, value in tools.items()}
    files['prerequisites/d2_prerequisites.py'] = raw['foundation_binder']
    files['qualification-prerequisites-01.json'] = raw['qualification_prerequisites']
    files['actual-pins.json'] = pins_raw
    manifest = {'schema': 'hepta-d2-exact-rust-ci-sealed-delivery/v1', 'status': 'sealed_not_executed',
        'root': ROOT, 'actual_qualification_job_id': job, 'qualification_counts': counts,
        'compiler_input_count': 222, 'actual_inputs': bound,
        'files': {name: identity(value) for name, value in tools.items()},
        'foundation': bound['foundation_binder'], 'qualification_prerequisites': bound['qualification_prerequisites'],
        'qualified_feature_selection': 'original all-features with diagnostic mode unset',
        'ci_executed': False, 'campaign_executed': False, 'ordinary_supplemental_executed': False,
        'hosted_actions_passed': False, 'performance_acceptance_claim': False,
        'detailed_preparation_validation': 'The same reviewed Q-only foundation checks actual preparation, native original pages, formatter map and current artifacts before the materializer can publish a plan.',
        'cache_owner_guard': 'Do not rerun the preparation-only pre-rename cache scan; use the bound completed rename and original custody evidence.'}
    files['seal-manifest.json'] = encode(manifest)
    files['launch-command.json'] = encode({'schema': 'hepta-d2-exact-rust-ci-launch-command/v1',
        'argv': ['/usr/bin/python3', '-B', '-u', ROOT + '/rust-ci-tools-01/launch_exact_rust_ci_01.py',
                 '--launcher-sha256', identity(tools['launch_exact_rust_ci_01.py'])['sha256']],
        'cwd': ROOT, 'actual_ci_job_id': None, 'executed': False})
    need(not os.path.lexists(args.output), 'fresh sealed output directory required')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, value in files.items():
        path = args.output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(value)
    need(all((args.output / name).read_bytes() == value for name, value in files.items()), 'sealed bytes differ')
    print(json.dumps({'sealed_output': str(args.output), 'files': len(files),
                      'qualification_job_id': job, 'qualification_counts': counts,
                      'manifest': identity(files['seal-manifest.json']), 'ci_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
