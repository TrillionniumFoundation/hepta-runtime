#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Validate original ordinary results; never build, test, re-audit or measure.

verify_ordinary(inputs, bind, foundation, prerequisite_proof) is import-safe.
The caller must obtain prerequisite_proof by the reviewed full foundation in
the same invocation, and bind must read stable original bytes and keep pins.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import stat
import types

ROOT = Path('/home/qian/hepta-runtime-phase-cost-20261106-d1')
TOOLS = ROOT / 'ordinary-tools-01'
OUT = ROOT / 'ordinary-01'
QUALIFICATION = ROOT / 'qualification-01'
FOUNDATION = ROOT / 'rust-ci-prerequisites-01/d1_prerequisites.py'
FOUNDATION_BYTES = 53934
FOUNDATION_SHA = '11875566eefa5532495d4411974faa2232a4339d3fd4ee1acae230c7394daba7'
ORIGINAL_QUALIFIER_SHA = '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'
ORDINARY_QUALIFIER_SHA = '7b84265d7cbccab2ed22e6471e38252c441a9df3e4148db8c392abf898fa07a3'
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build',
          'isolated-tests', 'audit-isolated-tests', 'release']
PROGRAMS = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
COUNTS = ('passed', 'failed', 'ignored', 'selected', 'retries')
HEX = re.compile(r'[0-9a-f]{64}')


def need(value, message):
    if not value:
        raise ValueError(message)


def verify_ordinary(inputs, bind, foundation, prerequisite_proof):
    """Read and verify one actual attempt; return proof, not a new result."""
    need(not sys.flags.optimize, 'original receipt assertions must be enabled')
    need(inputs.get('schema') == 'hepta-d1-ordinary-verification-input/v1'
         and inputs.get('sealed_inputs') is True
         and inputs.get('performance_acceptance_claim') is False,
         'actual ordinary inputs remain unsealed')
    proof = prerequisite_proof
    need(proof.get('passed') is True and proof['exact_ci']['passed'] is True,
         'a freshly validated original Q/CI proof is required')
    originals = {}

    def pinned(value, expected_path=None, retain=False, maximum=128 * 1024 * 1024):
        need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'},
             'exact original path/byte/SHA identity required')
        path = Path(value['path'])
        need(path.is_absolute() and path.is_relative_to(ROOT)
             and (expected_path is None or path == expected_path)
             and type(value['bytes']) is int and value['bytes'] >= 0
             and isinstance(value['sha256'], str) and HEX.fullmatch(value['sha256']),
             'unsafe or incomplete original identity')
        result = bind(path, expected=value, maximum=maximum, retain=retain)
        found = result[0] if retain else result
        need(found == value, 'reader returned a different original')
        if str(path) in originals:
            need(originals[str(path)] == found, 'one original has inconsistent pins')
        originals[str(path)] = found
        return result

    def document(name, path):
        pin, raw = pinned(inputs[name], path, retain=True)
        value = json.loads(raw)
        need(type(value) is dict, 'expected original object: ' + name)
        return pin, raw, value

    foundation_pin = pinned(inputs['foundation'], FOUNDATION)
    need(foundation_pin['bytes'] == FOUNDATION_BYTES
         and foundation_pin['sha256'] == FOUNDATION_SHA, 'reviewed foundation differs')
    prerequisite_pin, prerequisite_raw = pinned(
        inputs['prerequisites'], ROOT / 'ordinary-prerequisites-01.json', retain=True)
    prerequisite = json.loads(prerequisite_raw)
    need(prerequisite['qualification_sealed'] is True and prerequisite['exact_ci_sealed'] is True
         and prerequisite['qualification_original_job_id'] == proof['qualification']['original_job_id']
         and prerequisite['exact_ci_original_job_id'] == proof['exact_ci']['original_job_id'],
         'ordinary prerequisite does not identify the current full proof')
    plan_pin, plan_raw, plan = document('plan', ROOT / 'ordinary-plan-01.json')
    report_pin, _, report = document('report', OUT / 'report.json')
    map_pin, map_raw = pinned(inputs['source_map'], OUT / 'source-map.json', retain=True)
    source_map = json.loads(map_raw)
    summary_pin, _, summary = document('isolated_summary', OUT / 'isolated-tests/summary.json')
    audit_pin, _, audit = document('isolated_audit', OUT / 'isolated-tests.audit.json')
    terminal_pin, _, terminal = document('native_terminal', ROOT / 'ordinary-native-01.json')
    job_id = inputs.get('original_job_id')
    need(isinstance(job_id, str) and re.fullmatch(r'[0-9a-f]+-[0-9a-f]+-[0-9a-f]+', job_id)
         and job_id not in {proof['qualification']['original_job_id'], proof['exact_ci']['original_job_id']},
         'distinct actual ordinary native job identity required')
    foundation.native_terminal(terminal, job_id)
    pages, page_pins = [], []
    need(isinstance(inputs['native_read_pages'], list) and 1 <= len(inputs['native_read_pages']) <= 16,
         'complete original native read pages required')
    for index, page_pin in enumerate(inputs['native_read_pages']):
        expected = ROOT / ('ordinary-native-read-%03d.json' % index)
        actual, raw = pinned(page_pin, expected, retain=True)
        page_pins.append(actual)
        pages.append(json.loads(raw))
    streams = foundation.native_stream_pages(pages, terminal)

    qualifier = pinned(plan['ordinary_qualifier'], TOOLS / 'qualify_ordinary_01.py')
    original = pinned(plan['original_qualifier'], ROOT / 'source/tools/x230/20261028/qualify.py')
    need(qualifier['sha256'] == ORDINARY_QUALIFIER_SHA
         and original['sha256'] == ORIGINAL_QUALIFIER_SHA, 'ordinary derivation source differs')
    pinned(plan['launcher'], TOOLS / 'launch_ordinary_01.py')
    pinned(plan['manifest'], TOOLS / 'package-manifest-01.json')
    verifier_pin = pinned(plan['result_verifier'], TOOLS / 'verify_ordinary_01.py')
    need(plan['schema'] == 'hepta-d1-ordinary-supplement-plan/v1'
         and plan['executed'] is False
         and plan['foundation'] == foundation_pin and plan['prerequisites'] == prerequisite_pin
         and plan['qualification'] == proof['qualification']['qualification']
         and plan['source_map'] == proof['qualification']['source_map']
         and plan['source'] == str(ROOT / 'source')
         and plan['source_files'] == proof['source_tested'] == source_map
         and len(source_map) == 222 and plan['package_features'] == []
         and plan['dependency_defaults_changed'] is False and plan['no_default_features_switch'] is False
         and plan['diagnostic_environment_absent'] is True
         and plan['feature_executables_preserved_separately'] is True
         and plan['original_eight_stages_retained'] is True and plan['automatic_retries'] == 0
         and plan['exact_removed_arguments'] == ['--all-features'] * 3
         and plan['original_free_bytes_threshold'] == 3 * 1024 ** 3
         and plan['free_bytes_before'] >= plan['original_free_bytes_threshold']
         and plan['ordinary_native_job_id'] is None and plan['ordinary_result'] is None
         and plan['ordinary_counts'] is None and plan['ordinary_release_programs'] is None
         and plan['performance_acceptance_claim'] is False,
         'ordinary launch intent differs from the reviewed supplement')
    expected_launch = ['/usr/bin/python3', '-B', '-u', str(TOOLS / 'qualify_ordinary_01.py'),
        '--source', str(ROOT / 'source'), '--output', str(OUT), '--target', str(ROOT / 'target-build'),
        '--cargo-home', '/home/qian/hepta-runtime-optimization-20261023/cargo-home-a32-a33-r02',
        '--jobs', '2']
    need(plan['command'] == expected_launch and plan['output'] == str(OUT)
         and plan['target'] == str(ROOT / 'target-build'), 'ordinary invocation differs')
    need(report['schema'] == 'hepta-x230-composed-qualification/v1'
         and report.get('qualified') is True and report.get('finished_utc') and not report.get('error')
         and report['source'] == str(ROOT / 'source') and report['jobs'] == 2
         and report['automatic_test_retries'] == 0 and report['service_changes'] is False
         and report['source_input'] == report['source_tested'] == report['source_after'] == source_map,
         'ordinary eight-stage result failed or formatter/source changed the qualified 222-map')
    need(report['harness_before'] == report['harness_after'] == proof['qualification']['qualification_harness']
         and len(report['harness_after']) == 19, 'the nineteen original harnesses differ')
    _, qraw = pinned(proof['qualification']['qualification'], QUALIFICATION / 'report.json', retain=True)
    qualified = json.loads(qraw)
    need([row['name'] for row in report['stages']] == STAGES
         == [row['name'] for row in qualified['stages']], 'original eight-stage sequence differs')
    stage_proofs = []
    for row, original_row in zip(report['stages'], qualified['stages']):
        command = [str(OUT) + arg[len(str(QUALIFICATION)):]
                   if arg == str(QUALIFICATION) or arg.startswith(str(QUALIFICATION) + '/') else arg
                   for arg in original_row['command'] if arg != '--all-features']
        need(row['command'] == command and type(row['returncode']) is int and row['returncode'] == 0
             and isinstance(row['seconds'], (int, float)) and math.isfinite(row['seconds']) and row['seconds'] >= 0,
             'ordinary stage changed more than the feature selection/output location')
        logs = {}
        for stream in ('stdout', 'stderr'):
            name = 'cargo-no-run.jsonl' if row['name'] == 'test-build' and stream == 'stdout' else row['name'] + '.' + stream
            value = bind(OUT / name, expected=row[stream + '_sha256'], maximum=128 * 1024 * 1024)
            originals[value['path']] = value
            logs[stream] = value
        stage_proofs.append({'name': row['name'], 'command': command, 'returncode': 0,
                             'original_seconds': row['seconds'], 'logs': logs})
    need(summary['schema'] == 'hepta-isolated-libtest/v1' and summary.get('success') is True
         and summary.get('filter') == '' and summary.get('enumeration_errors') == [] and not summary.get('fatal_error'),
         'complete ordinary test inventory did not pass')
    counts = {key: summary[key] for key in COUNTS}
    need(all(type(value) is int and value >= 0 for value in counts.values())
         and counts['passed'] > 0 and counts['failed'] == counts['retries'] == 0
         and counts['selected'] == counts['passed'] + counts['ignored'], 'ordinary dynamic counts do not reconcile')
    need(audit['schema'] == 'hepta-isolated-libtest-audit/v1' and audit.get('success') is True
         and audit.get('errors') == [] and audit.get('expected_filter') == '' and not audit.get('fatal_error')
         and audit['evidence'] == str(OUT / 'isolated-tests')
         and audit['auditor_sha256'] == report['harness_after']['audit_isolated_tests.py']
         and all(audit[key] == counts[key] for key in ('passed', 'failed', 'ignored', 'selected'))
         and audit['executed'] == counts['passed'] and audit['binaries'],
         'ordinary full-inventory original audit did not pass')
    names = {'summary.json', 'cargo-artifacts.jsonl', 'source-manifest.input', 'commands.jsonl', 'tests.jsonl'}
    need(set(audit['input_sha256']) == names
         and audit['input_sha256']['summary.json'] == summary_pin['sha256']
         and audit['input_sha256']['source-manifest.input'] == map_pin['sha256'] == summary['source_manifest_sha256'],
         'ordinary audit inputs do not bind the actual source map and summary')
    for name, digest in audit['input_sha256'].items():
        value = bind(OUT / 'isolated-tests' / name, expected=digest, maximum=128 * 1024 * 1024)
        originals[value['path']] = value
    for binary in audit['binaries']:
        path = Path(binary['path'])
        need(path.parent == OUT / 'test-binaries'
             and binary['recorded_before_sha256'] == binary['current_after_sha256'],
             'original ordinary test binary custody differs')
        value = bind(path, expected=binary['current_after_sha256'], maximum=128 * 1024 * 1024)
        originals[value['path']] = value
    artifact_pin, artifact_raw = bind(OUT / 'cargo-no-run.jsonl',
        expected=stage_proofs[4]['logs']['stdout'], maximum=128 * 1024 * 1024, retain=True)
    own_artifacts = [event for line in artifact_raw.splitlines()
                     if (event := json.loads(line)).get('reason') == 'compiler-artifact'
                     and event.get('manifest_path') == str(ROOT / 'source/Cargo.toml')]
    need(own_artifacts and all(event.get('features') == [] for event in own_artifacts),
         'ordinary test artifacts select a different package feature set')
    need(set(plan['qualification_feature_programs']) == set(report['binaries']) == PROGRAMS,
         'ordinary or preserved feature executable set differs')
    feature_after, ordinary_programs = {}, {}
    for name in sorted(PROGRAMS):
        before = plan['qualification_feature_programs'][name]
        feature_after[name] = pinned(before, QUALIFICATION / name)
        need(feature_after[name] == proof['binaries'][name], 'preserved feature executable changed')
        value = report['binaries'][name]
        need(value['path'] == str(OUT / name) and HEX.fullmatch(value['sha256']),
             'ordinary release executable has a different preserved location')
        found = bind(OUT / name, expected=value['sha256'], maximum=128 * 1024 * 1024)
        ordinary_programs[name] = found
        originals[found['path']] = found

    expected_stdout = [{'phase': 'execute_original_ordinary_qualification',
        'plan_sha256': hashlib.sha256(plan_raw).hexdigest(), 'automatic_retries': 0, 'preserved_feature_executables': 3}]
    for row in report['stages']:
        expected_stdout.extend([{'stage': row['name'], 'state': 'started'},
                                {'stage': row['name'], 'exit': 0, 'seconds': row['seconds']}])
    expected_stdout.append({'qualified': True, 'report': str(OUT / 'report.json'), 'error': None})
    need(streams['stderr'] == b'' and [json.loads(line) for line in streams['stdout'].splitlines()] == expected_stdout,
         'complete original native stdout/stderr does not reconcile with the launcher plan and eight actual stages')
    return {'schema': 'hepta-d1-ordinary-supplement-validation/v1', 'passed': True,
        'original_job_id': job_id, 'native_terminal': terminal_pin, 'native_read_pages': page_pins,
        'native_streams': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                           for name, raw in streams.items()},
        'foundation': foundation_pin, 'prerequisites': prerequisite_pin, 'verifier': verifier_pin,
        'original_q_job_id': proof['qualification']['original_job_id'],
        'original_exact_ci_job_id': proof['exact_ci']['original_job_id'],
        'plan': plan_pin, 'report': report_pin, 'isolated_summary': summary_pin, 'isolated_audit': audit_pin,
        'source_maps_unchanged': True, 'qualification_source_map': proof['qualification']['source_map'],
        'ordinary_source_map': map_pin, 'source_files': source_map, 'compiler_input_count': 222,
        'original_qualification_harness_count': 19, 'ordinary_eight_stages_passed': True, 'stages': stage_proofs,
        'tests': counts, 'ordinary_package_features': [], 'dependency_defaults_changed': False,
        'qualified_feature_programs_before': plan['qualification_feature_programs'],
        'qualified_feature_programs_after': feature_after, 'ordinary_programs': ordinary_programs,
        'originals': originals, 'original_auditors_reexecuted': False, 'automatic_retries': 0,
        'new_compile_or_workload_started': False, 'performance_acceptance_claim': False}


def main():
    # Bootstrap only the previously reviewed fixed foundation. This entry is a
    # read-only verifier apart from its new evidence report and compact stdout.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--verifier-sha256', required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize and sys.platform == 'linux' and os.geteuid() != 0,
         'original non-root Linux verification required')
    need(Path(__file__).resolve() == TOOLS / 'verify_ordinary_01.py', 'fixed verifier location required')
    # Reuse the launcher's already reviewed stable-reader functions by source
    # extraction at package generation; they are independent definitions here.
    own = stable_raw(Path(__file__).resolve())
    need(hashlib.sha256(own).hexdigest() == args.verifier_sha256, 'verifier byte identity differs')
    foundation_raw = stable_raw(FOUNDATION)
    need(len(foundation_raw) == FOUNDATION_BYTES and hashlib.sha256(foundation_raw).hexdigest() == FOUNDATION_SHA,
         'reviewed foundation byte identity differs')
    foundation = types.ModuleType('d1_ordinary_readonly_foundation')
    foundation.__file__ = str(FOUNDATION)
    exec(compile(foundation_raw, str(FOUNDATION), 'exec'), foundation.__dict__)
    bindings = []
    def bind(path, expected=None, retain=False, maximum=128 * 1024 * 1024):
        result = foundation.checked(path, expected=expected, maximum=maximum, retain=retain)
        bindings.append(result[0] if retain else result)
        return result
    input_path = Path(args.input)
    need(input_path == ROOT / 'ordinary-verification-input-01.json', 'fixed verification input path required')
    input_pin, input_raw = bind(input_path, expected=args.input_sha256, retain=True)
    inputs = json.loads(input_raw)
    need(inputs.get('sealed_inputs') is True, 'actual ordinary result pins remain unsealed')
    _, prerequisite_raw = bind(ROOT / 'ordinary-prerequisites-01.json', expected=inputs['prerequisites'], retain=True)
    proof = foundation.bind_d1_prerequisites(json.loads(prerequisite_raw), bind)
    validation = verify_ordinary(inputs, bind, foundation, proof)
    bind(TOOLS / 'verify_ordinary_01.py', expected=args.verifier_sha256)
    for row in bindings:
        need(foundation.checked(Path(row['path'])) == row, 'an original changed during ordinary verification')
    report = {'schema': 'hepta-d1-ordinary-supplement-postflight/v1', **validation,
              'validation_schema': validation['schema'], 'verification_input': input_pin,
              'all_input_bindings': bindings, 'report_written_create_only': True}
    report['schema'] = 'hepta-d1-ordinary-supplement-postflight/v1'
    output = ROOT / 'ordinary-postflight-01.json'
    body = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
    need(len(body) <= 16 * 1024 * 1024, 'bounded ordinary postflight output exceeded')
    with output.open('xb') as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'verified': True, 'original_job_id': validation['original_job_id'],
                      'report': {'path': str(output), 'bytes': len(body),
                                 'sha256': hashlib.sha256(body).hexdigest()},
                      'compiler_or_workload_started': False}, sort_keys=True))
    return 0


def stable_raw(path):
    need(path.resolve(strict=True) == path, 'indirect reviewed input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
             and 0 < before.st_size <= 16 * 1024 * 1024, 'unsafe or oversized reviewed input')
        body = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(len(body) == before.st_size and all(getattr(before, k) == getattr(after, k)
         == getattr(path.lstat(), k) for k in fields), 'reviewed input changed during read')
    return body


if __name__ == '__main__':
    sys.exit(main())
