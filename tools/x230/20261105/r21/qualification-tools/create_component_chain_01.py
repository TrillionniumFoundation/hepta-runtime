#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind the two measured source transitions without claiming a final cold run.

The same frozen policy is re-evaluated on actual files before qualification and
by the independent post-build verifier. Full raw replay receipts are a separate
required adoption condition; this creator performs no workload or compilation.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-r21')
R20 = Path('/home/qian/hepta-runtime-optimization-20261105-r20')
R19 = Path('/home/qian/hepta-runtime-optimization-20261104-r19')
BASELINE_SHA = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'
STATUS_SHA = '2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7'
FINAL_SHA = '1f1f086e3bc0fc62184ed51949964e1f82e337b87d330225097ae38722e4ac8c'
STATUS_REPORT_SHA = '7223fafebacd13d5debe05f113f314b550f3896156d59e44837225a63f1a7631'
CANCEL_REPORT_SHA = 'a2ae38a6ca341a5691b106866fdafadb24221d959c1f914e608adc67ec8ce8f0'
STATUS_TOOL_SHA = '8ccb6bd17032792be189a87386dabaefe4fdd2251b582834734c717a9e63b79a'
CANCEL_TOOL_SHA = 'ae5d82307c4ab36ff6b37e76deeaf0b71259f8c852ac4a2e8ae333a111731daa'
CANCEL_PLAN_SHA = 'a44c750c4b0efc67123b02085194628062884be72d40c0830e6fe85e201c8c96'
CONSTANTS = ('PRIVATE_DIRECTORY_CODE', 'BOUND_OBSERVATION_CODE', 'START_CODE',
             'STATUS_CODE', 'READ_CODE', 'CANCEL_CODE')


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_uid', 'st_mode',
                 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, expected=None):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'noncanonical component input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 16 * 1024 * 1024,
             'unsafe/oversize component input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'component input changed')
        digest = sha(raw)
        need(expected is None or digest == expected, 'component input SHA differs: ' + str(path))
        return raw, {'path': str(path), 'size': len(raw), 'sha256': digest}
    finally:
        os.close(fd)


class RemoveImports(ast.NodeTransformer):
    def visit_Import(self, node):
        return None

    def visit_ImportFrom(self, node):
        return None


def verify_transition(before, after, changed):
    a, b = before.decode(), after.decode()
    matches = []
    for text in (a, b):
        found = {}
        for name in CONSTANTS:
            values = list(re.finditer(r'const ' + name + r': &str = r#"(.*?)"#;', text, re.S))
            need(len(values) == 1, 'missing/duplicate Python source constant')
            found[name] = values[0]
        matches.append(found)
    old, new = matches
    need(a[:old[changed].start(1)] == b[:new[changed].start(1)]
         and a[old[changed].end(1):] == b[new[changed].end(1):], 'source changes outside permitted constant')
    rows = {}
    for name in CONSTANTS:
        left, right = old[name].group(1), new[name].group(1)
        need((left == right) == (name != changed), 'unexpected Python constant change')
        left_ast = ast.dump(RemoveImports().visit(ast.parse(left)), include_attributes=False)
        right_ast = ast.dump(RemoveImports().visit(ast.parse(right)), include_attributes=False)
        need(left_ast == right_ast, 'non-import Python semantics changed')
        rows[name] = {'before_sha256': sha(left.encode()), 'after_sha256': sha(right.encode()),
                      'byte_identical': left == right, 'nonimport_ast_identical': True}
    return {'changed_constant': changed, 'outside_constant_bytes_equal': True,
            'all_six_nonimport_asts_equal': True, 'constants': rows}


def inspect_inputs(root=ROOT):
    need(Path(root) == ROOT, 'reserved R21 root required')
    refs = {}

    def load(path, expected):
        raw, row = read(path, expected)
        need(str(path) not in refs or refs[str(path)] == row, 'component reference changed')
        refs[str(path)] = row
        return raw, row

    baseline, baseline_id = load(R19 / 'source/src/mcp/runtime/jobs.rs', BASELINE_SHA)
    status, status_id = load(R20 / 'source/src/mcp/runtime/jobs.rs', STATUS_SHA)
    cancel, cancel_id = load(R20 / 'cancel-candidate-01/jobs.rs', FINAL_SHA)
    final, final_id = load(ROOT / 'source/src/mcp/runtime/jobs.rs', FINAL_SHA)
    need(len(baseline) == 186456 and len(status) == 186514 and len(cancel) == len(final) == 186546
         and final == cancel, 'source length/final exact-byte association differs')
    status_delta = verify_transition(baseline, status, 'STATUS_CODE')
    cancel_delta = verify_transition(status, cancel, 'CANCEL_CODE')
    status_raw, status_report_id = load(R20 / 'coldprocess-probe-01/semantics.json', STATUS_REPORT_SHA)
    cancel_raw, cancel_report_id = load(R20 / 'cancelprocess-probe-01/semantics.json', CANCEL_REPORT_SHA)
    status_report, cancel_report = json.loads(status_raw), json.loads(cancel_raw)
    _, status_tool_id = load(R20 / 'tools/coldprocess_probe_02.py', STATUS_TOOL_SHA)
    _, cancel_tool_id = load(R20 / 'cancel-tools-01/cancelprocess_probe_01.py', CANCEL_TOOL_SHA)
    _, cancel_plan_id = load(R20 / 'cancel-tools-01/measurement-plan-01.json', CANCEL_PLAN_SHA)
    need(status_report['schema'] == 'hepta-r20-coldprocess-semantics/v1'
         and status_report['passed'] is status_report['source_stable'] is True
         and status_report['baseline_source_sha256'] == BASELINE_SHA
         and status_report['candidate_source_sha256'] == STATUS_SHA
         and status_report['probe_tool_sha256'] == STATUS_TOOL_SHA
         and status_report['checks'] and all(value is True for value in status_report['checks'].values())
         and status_report['semantic_cases']['total'] == status_report['semantic_cases']['passed'] == 15
         and status_report['semantic_cases']['failed'] == 0 and status_report['fresh_process_count'] == 352
         and status_report['automatic_retries'] == 0, 'STATUS producer evidence differs')
    need(cancel_report['schema'] == 'hepta-r20-cancel-mechanism-semantics/v1'
         and cancel_report['passed'] is cancel_report['source_stable'] is cancel_report['complete_required_coverage'] is True
         and cancel_report['baseline_source_sha256'] == STATUS_SHA
         and cancel_report['candidate_source_sha256'] == FINAL_SHA
         and cancel_report['probe_tool_sha256'] == CANCEL_TOOL_SHA and cancel_report['plan_sha256'] == CANCEL_PLAN_SHA
         and cancel_report['mode'] == 'full' and len(cancel_report['cases']) == 17
         and all(row['passed'] is True for row in cancel_report['cases'])
         and cancel_report['actual_fresh_helper_processes'] == cancel_report['actual_helper_records'] == 228
         and cancel_report['actual_owned_target_records'] == cancel_report['real_targets_created'] == 66
         and cancel_report['automatic_retries'] == 0 and cancel_report['error'] is None,
         'CANCEL producer evidence differs')
    for row in refs.values():
        need(read(Path(row['path']), row['sha256'])[1] == row, 'component input changed after chain inspection')
    return {'schema': 'hepta-r21-component-chain/v1', 'root': str(ROOT),
            'baseline_source_sha256': BASELINE_SHA, 'final_source_sha256': FINAL_SHA,
            'final_source': final_id, 'producer_chain_verified': True,
            'final_was_directly_coldprocess_tested': False,
            'independent_raw_audits_required_before_adoption': True, 'adoption_assessed': False,
            'steps': [
                {'name': 'status_lazy_import', 'input_source': baseline_id, 'output_source': status_id,
                 'semantics_report': status_report_id, 'probe_tool': status_tool_id, 'source_delta': status_delta},
                {'name': 'cancel_lazy_import', 'input_source': status_id, 'output_source': cancel_id,
                 'semantics_report': cancel_report_id, 'probe_tool': cancel_tool_id, 'plan': cancel_plan_id,
                 'source_delta': cancel_delta}],
            'referenced_files': [refs[key] for key in sorted(refs)],
            'checks': {'actual_producer_reports_pinned_and_passed': True,
                       'intermediate_source_links_exact': True,
                       'only_STATUS_then_CANCEL_constant_changed': True,
                       'all_nonimport_python_asts_equal': True,
                       'all_other_Rust_and_READ_source_bytes_preserved': True,
                       'actual_final_source_equals_measured_CANCEL_candidate_bytes': True,
                       'all_sources_reports_tools_and_plan_stable': True},
            'scope': 'Producer semantics and actual source transitions before fresh full qualification; independent raw replay and final six-host acceptance remain separate adoption gates.'}


def validate_chain(path, expected_sha, expected_jobs, root=ROOT):
    raw, identity = read(path, expected_sha)
    value = json.loads(raw)
    actual = inspect_inputs(root)
    need(value == actual and expected_jobs == actual['final_source_sha256'], 'component chain or final source differs')
    return {**identity, 'schema': value['schema'], 'baseline_source_sha256': value['baseline_source_sha256'],
            'final_source_sha256': value['final_source_sha256'],
            'steps': [{'name': row['name'], 'input_source_sha256': row['input_source']['sha256'],
                       'output_source_sha256': row['output_source']['sha256'],
                       'semantics_report_sha256': row['semantics_report']['sha256']} for row in value['steps']],
            'referenced_files': value['referenced_files'], 'producer_chain_verified': True,
            'final_was_directly_coldprocess_tested': False,
            'independent_raw_audits_required_before_adoption': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--expected-jobs-sha256', required=True)
    args = parser.parse_args()
    need(args.root.absolute() == ROOT and args.expected_jobs_sha256 == FINAL_SHA, 'R21 final source arguments differ')
    output = ROOT / 'component-chain-01.json'
    need(not os.path.lexists(output), 'component chain must be a new file')
    value = inspect_inputs(ROOT)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    os.umask(0o077)
    with output.open('xb') as stream:
        stream.write(raw)
    need(output.read_bytes() == raw, 'component-chain write/readback differs')
    print(json.dumps({'producer_chain_verified': True, 'path': str(output), 'size': len(raw), 'sha256': sha(raw),
                      'final_source_sha256': FINAL_SHA, 'final_was_directly_coldprocess_tested': False}))


if __name__ == '__main__':
    main()
