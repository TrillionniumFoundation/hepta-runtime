#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal actual local D2 Q/CI original identities without executing their binders.

The remote original materializer/ordinary launcher/parent still performs the
complete fresh read-only proof before use. This tool runs no compiler, auditor,
workload or host request, and never modifies original receipt bytes.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
MODULE = ROOT / 'full-prerequisites-01/d2_prerequisites.py'
MODULE_BYTES = 59048
MODULE_SHA256 = '2a04eb862c4efe1377a3b78dad33b99f43573d7c91dc66503ad5f08690b17da9'
HEX = re.compile(r'[0-9a-f]{64}\Z')
JOB = re.compile(r'[0-9a-f]{11,16}-[0-9a-f]{4}-[0-9a-f]{4}\Z')
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect local original')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= maximum, 'unsafe or oversized local original')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    need(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(path.lstat()),
         'local original changed during read')
    return raw


def original(value, expected_path):
    need(type(value) is dict and set(value) == {'local_path', 'runtime_pin'},
         'actual local original and runtime identity required')
    pin = value['runtime_pin']
    need(type(pin) is dict and set(pin) == {'path', 'bytes', 'sha256'}
         and pin['path'] == str(expected_path) and type(pin['bytes']) is int and pin['bytes'] > 0
         and isinstance(pin['sha256'], str) and HEX.fullmatch(pin['sha256']),
         'runtime original identity differs')
    raw = read(value['local_path'])
    need(identity(raw) == {key: pin[key] for key in ('bytes', 'sha256')}, 'original bytes differ')
    return pin, raw


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def native_pages(request, prefix, terminal, foundation):
    job = request['original_job_id']
    need(isinstance(job, str) and JOB.fullmatch(job), 'actual original native job required')
    foundation.native_terminal(terminal, job)
    need(terminal['audit_recorded'] is True, 'actual native terminal audit record required')
    pages = request['native_read_pages']
    need(isinstance(pages, list) and 1 <= len(pages) <= 16, 'all original native pages required')
    pins, values, names = [], [], set()
    basename = 'qualification-native-read-01' if prefix == 'qualification' else 'rust-ci-native-read-01'
    for value in pages:
        path = Path(value['runtime_pin']['path'])
        need(path.parent == ROOT and path.name not in names
             and re.fullmatch(re.escape(basename) + r'(?:-[0-9]{3})?\.json', path.name),
             'native original page path or uniqueness differs')
        names.add(path.name)
        pin, raw = original(value, path)
        pins.append(pin)
        values.append(json.loads(raw))
    streams = foundation.native_stream_pages(values, terminal)
    return pins, {name: identity(raw) for name, raw in streams.items()}


def validate_q(doc, ids, foundation):
    report = doc['qualification-01/report.json']
    prep = doc['preparation.json']
    source = doc['qualification-01/source-map.json']
    tests = doc['qualification-01/isolated-tests/summary.json']
    audit = doc['qualification-01/isolated-tests.audit.json']
    need(report['schema'] == 'hepta-x230-composed-qualification/v1'
         and report.get('qualified') is True and report.get('finished_utc') and not report.get('error')
         and report['source'] == str(ROOT / 'source') and report['jobs'] == 2
         and report['automatic_test_retries'] == 0 and report['service_changes'] is False,
         'original qualification did not close successfully')
    need([row['name'] for row in report['stages']] == foundation.STAGES
         and all(row['returncode'] == 0 for row in report['stages']), 'original eight stages did not all pass')
    need(prep['schema'] == 'hepta-x230-d2-preparation/v1' and prep.get('passed') is True
         and prep.get('finished_utc') and not prep.get('error')
         and prep['qualification_started'] is True and prep['qualification_returncode'] == 0
         and prep['qualification_report_sha256'] == ids['qualification-01/report.json']['sha256']
         and prep['source_before_qualification'] == report['source_input']
         and prep['source_after_qualification'] == report['source_tested'] == report['source_after'] == source
         and len(source) == 222 and len(prep['qualification_harness_sha256']) == 19
         and prep['diagnostic_environment_absent'] is True and prep['ordinary_supplemental_executed'] is False,
         'original preparation does not bind the actual successful qualification')
    need(tests['schema'] == 'hepta-isolated-libtest/v1' and tests.get('success') is True
         and tests['filter'] == '' and tests['enumeration_errors'] == [] and not tests.get('fatal_error'),
         'actual complete test summary did not pass')
    counts = {name: tests[name] for name in COUNTS}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
         and counts['selected'] == counts['passed'] + counts['ignored'], 'actual counts are inconsistent')
    need(audit['schema'] == 'hepta-isolated-libtest-audit/v1' and audit.get('success') is True
         and audit['errors'] == [] and not audit.get('fatal_error') and audit['expected_filter'] == ''
         and all(audit[name] == counts[name] for name in ('passed', 'failed', 'ignored', 'selected'))
         and audit['executed'] == counts['passed']
         and audit['input_sha256']['summary.json'] == ids['qualification-01/isolated-tests/summary.json']['sha256']
         and audit['input_sha256']['source-manifest.input'] == ids['qualification-01/source-map.json']['sha256']
         == tests['source_manifest_sha256'], 'actual original audit or input identity differs')
    return counts


def validate_ci(doc, foundation, q):
    report, plan, audit = (doc[name] for name in (
        'rust-ci-01/report.json', 'rust-ci-plan-01.json', 'rust-ci-01/nextest-output-audit.json'))
    need(report['schema'] == 'hepta-d2-external-rust-ci/v1' and report.get('passed') is True
         and report.get('finished_utc') and not report.get('error')
         and report['automatic_retries'] == 0 and report['production_services_modified'] is False
         and report['owned_children_closed'] is True and report['source_inputs_unchanged'] is True
         and report['home_unchanged'] is True and report['hosted_actions_passed'] is False
         and report['original_qualification_job_id'] == q['qualification_original_job_id'],
         'actual exact CI did not close successfully')
    need(plan['schema'] == 'hepta-d2-materialized-exact-rust-ci-plan/v1'
         and plan['qualification_job_id'] == q['qualification_original_job_id']
         and plan['qualification'] == q['artifact_map']['qualification-01/report.json']
         and plan['source_map'] == q['artifact_map']['qualification-01/source-map.json']
         and len(plan['source_files']) == 222 and q['prerequisite_module'] in plan['input_bindings'],
         'actual CI plan is not bound to the original qualification/canonical module')
    need([row['name'] for row in report['stages']] == list(foundation.CI_COMMANDS), 'original CI stage inventory changed')
    for row in report['stages']:
        need(row['argv'] == foundation.CI_COMMANDS[row['name']] and row['cwd'] == str(ROOT / 'source')
             and row['returncode'] == 0 and row['passed'] is True and row['waited_and_reaped'] is True
             and row['owned_process_absent'] is True and row['owned_process_group_absent'] is True
             and row['timed_out'] is False, 'an actual original CI stage did not close once')
    counts = plan['qualification_counts']
    need(report['nextest_output_audit'] == audit and audit['verified'] is True
         and {name: audit[name] for name in COUNTS} == counts
         and counts['failed'] == counts['retries'] == 0
         and report['structured_inventory']['verified'] is True
         and report['structured_inventory']['case_inventory_sha256'] == audit['case_inventory_sha256']
         == plan['expected_nextest']['case_inventory_sha256'], 'actual nextest output/inventory audit differs')
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize, 'normal Python assertion guards required')
    request_raw = read(args.input.absolute())
    request = json.loads(request_raw)
    need(request['schema'] == 'hepta-d2-prerequisites-seal-request/v1'
         and request['sealed_inputs'] is True and request['purpose'] in {'qualification', 'exact_ci'},
         'actual prerequisite source identities remain unsealed')
    module_id, module_raw = original(request['module'], MODULE)
    need(identity(module_raw) == {'bytes': MODULE_BYTES, 'sha256': MODULE_SHA256}, 'reviewed module differs')
    ast.parse(module_raw)
    foundation = types.ModuleType('_d2_local_pure_receipt_helpers')
    foundation.__file__ = str(Path(request['module']['local_path']).resolve())
    exec(compile(module_raw, foundation.__file__, 'exec'), foundation.__dict__)
    purpose = request['purpose']
    names = foundation.QUALIFICATION_ARTIFACTS if purpose == 'qualification' else foundation.CI_ARTIFACTS
    need(set(request['originals']) == set(names), 'actual original artifact inventory differs')
    ids, doc = {}, {}
    for name in names:
        ids[name], raw = original(request['originals'][name], ROOT / name)
        doc[name] = json.loads(raw)
    terminal_name = 'qualification-terminal-status-01.json' if purpose == 'qualification' else 'rust-ci-native-01.json'
    pages, streams = native_pages(request, purpose, doc[terminal_name], foundation)
    if purpose == 'qualification':
        counts = validate_q(doc, ids, foundation)
        value = {'schema': 'hepta-d2-c1-prerequisites/v1', 'qualification_sealed': True,
            'exact_ci_sealed': False, 'prerequisite_module': module_id,
            'artifact_map': {**foundation.PINNED, **ids, **{name: None for name in foundation.CI_ARTIFACTS}},
            'qualification_original_job_id': request['original_job_id'], 'qualification_read_pages': pages,
            'exact_ci_original_job_id': None, 'exact_ci_read_pages': None,
            'required_missing_qualification_bindings': [],
            'required_missing_exact_ci_bindings': list(foundation.CI_ARTIFACTS) + ['exact_ci_original_job_id', 'exact_ci_read_pages'],
            'performance_acceptance_claim': False}
        target_name = 'qualification-prerequisites-01.json'
        inherited = None
    else:
        inherited, qraw = original(request['qualification_foundation'], ROOT / 'qualification-prerequisites-01.json')
        value = json.loads(qraw)
        need(value['schema'] == 'hepta-d2-c1-prerequisites/v1' and value['qualification_sealed'] is True
             and value['exact_ci_sealed'] is False and value['prerequisite_module'] == module_id,
             'original Q-only foundation required')
        counts = validate_ci(doc, foundation, value)
        need(doc['rust-ci-01/report.json']['plan'] == ids['rust-ci-plan-01.json'], 'actual CI report binds another plan')
        value['artifact_map'].update(ids)
        value['exact_ci_sealed'] = True
        value['exact_ci_original_job_id'] = request['original_job_id']
        value['exact_ci_read_pages'] = pages
        value['required_missing_exact_ci_bindings'] = []
        target_name = 'ordinary-prerequisites-01.json'
    foundation._foundation(value, require_ci=(purpose == 'exact_ci'))
    output_raw = encoded(value)
    receipt = {'schema': 'hepta-d2-prerequisite-local-seal/v1', 'purpose': purpose,
        'source_request': identity(request_raw), 'module': module_id, 'originals': ids,
        'native_read_pages': pages, 'native_streams': streams, 'original_job_id': request['original_job_id'],
        'actual_counts': counts, 'inherited_q_foundation': inherited,
        'output': dict(path=str(ROOT / target_name), **identity(output_raw)),
        'current_remote_artifacts_checked': False, 'fresh_remote_binder_required_before_use': True,
        'bind_d2_qualification_executed': False, 'bind_d2_prerequisites_executed': False,
        'compiler_auditor_or_workload_executed': False, 'host_calls': 0}
    need(not os.path.lexists(args.output), 'fresh local output directory required')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in ((target_name, output_raw), ('seal-receipt.json', encoded(receipt)),
                      ('actual-seal-request.json', request_raw)):
        with (args.output / name).open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps({'output': receipt['output'], 'purpose': purpose, 'actual_counts': counts,
                      'target_binders_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
