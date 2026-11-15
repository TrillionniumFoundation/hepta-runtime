#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Create one D1 qualification package from actual original custody bytes.

Local preparation only. This never calls a host API, moves a build cache, runs
the qualifier, or creates a future qualification/ELF/measurement result.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
OWNER = '/home/qian/hepta-runtime-optimization-20261106-r35'
ROOT = '/home/qian/hepta-runtime-phase-cost-20261106-d1'
POSTFLIGHT_FILES = {
    'lifecycle-owner-postflight-01.json': (51666, '893171173431137b4e7836089c3a096506530966c736bf17c1779c2b2480b146'),
    'lifecycle-owner-postflight-native-01.json': (733, '00466ae50384dd5abc6e8124aaa4583bd55d37538ada559c16e25d9cfb0a06e8'),
    'lifecycle-owner-postflight-read-01-000.json': (50477, '6008709d937e3b458541ed019519cb32fd56154a69ebe2638b7aedf057a1cb79'),
    'lifecycle-owner-postflight-read-01-001.json': (50226, 'dde5f57fa0cd5e9b22af2829ea4a7e2eb8c3e5dec6030b159ffdc3972565e8a4'),
    'lifecycle-owner-postflight-read-01-002.json': (41341, '7ee538fb988eb05ea5ce71abaa34441e96b9cc3cf2f9c4bc452cc9bdd62046d8'),
}


def identity(raw, path=None):
    value = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return {'path': str(path), **value} if path is not None else value


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-package', required=True)
    parser.add_argument('--postflight-originals', required=True)
    parser.add_argument('--publication-provenance', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--seal', action='store_true', help='bind the verified actual prior-owner inputs; D1 results remain null')
    args = parser.parse_args()
    assert not sys.flags.optimize
    candidate_root, owner_root, publication_path, output = [Path(value).absolute() for value in
        (args.candidate_package, args.postflight_originals, args.publication_provenance, args.output)]
    assert not os.path.lexists(output)
    tool_raw = (HERE / 'prepare_qualify.py').read_bytes()
    ast.parse(tool_raw)
    generation = json.loads((HERE / 'helper-reuse-static.json').read_bytes())
    assert identity(tool_raw) == generation['generated_preparer']
    # Import definitions only. No __main__ block or host-reading preparation
    # function runs. postflight_bytes consumes the supplied original bytes.
    spec = importlib.util.spec_from_file_location('_d1_preparation_definitions', HERE / 'prepare_qualify.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    def read(path, size, digest):
        return module.read_bound({'path': str(path), 'bytes': size, 'sha256': digest})
    frozen_raw = read(candidate_root / 'package-manifest.json', 10557,
                      '3f5944705884d1e071f28978fc7ffb911875bf2a93a9c719b2cbe076bbb78fe0')
    frozen = json.loads(frozen_raw)
    files = {'candidate/package-manifest.json': frozen_raw}
    assert frozen['file_count'] == len(frozen['files']) == 38
    assert {p.relative_to(candidate_root).as_posix() for p in candidate_root.rglob('*') if p.is_file()} == {
        'package-manifest.json', *(row['path'] for row in frozen['files'])}
    for row in frozen['files']:
        path = Path(row['path'])
        assert not path.is_absolute() and '..' not in path.parts
        key = 'candidate/' + row['path']
        assert key not in files
        files[key] = read(candidate_root / path, row['bytes'], row['sha256'])
    candidate = json.loads(files['candidate/input.json'])
    assert candidate['baseline_count'] == 220 and candidate['candidate_count'] == 222
    assert len(candidate['changed_paths']) == 13 and len(candidate['added_paths']) == 2
    assert candidate['qualifier_selection'] == {
        'original_qualifier_unmodified': True, 'original_all_features': True,
        'qualified_release_kind': 'feature-enabled diagnostic ELF with diagnostic environment absent',
        'ordinary_supplemental_feature_set': [], 'no_default_features_switch': False}
    actual = {name: read(owner_root / name, *pin) for name, pin in POSTFLIGHT_FILES.items()}
    report_name = 'lifecycle-owner-postflight-01.json'
    native_name = 'lifecycle-owner-postflight-native-01.json'
    page_names = ['lifecycle-owner-postflight-read-01-%03d.json' % number for number in range(3)]
    report_identity = identity(actual[report_name], Path(OWNER) / report_name)
    owner = module.postflight_bytes(actual[report_name], actual[native_name],
                                   [actual[name] for name in page_names], report_identity)
    prior_raw = read(HERE / 'references/qualification-input-r35.json', 3742,
                     '652541a8f461af9cc7dccd80b5989ffd6e151a8885dea4cc4675f2d054a8be63')
    prior = json.loads(prior_raw)
    assert prior['baseline_commit'] == module.BASELINE_COMMIT
    assert prior['qualification_harness_sha256'] == owner['qualification_harness_sha256']
    assert len(prior['qualification_harness_sha256']) == 19
    proof_raw = read(publication_path, 2400,
                     '99d1e7c4faef98fd680aa7136c3d73e163ca3f64e15f75a1704a6394c8c1fd34')
    proof = json.loads(proof_raw)
    assert proof['source_construction_anchor'] == module.BASELINE_COMMIT
    assert proof['actual_git_parent'] == proof['published_candidate_parent_sha'] == '86155fbf3b89e5a77e2a4aadebd2128c663fe50b'
    assert proof['published_candidate_commit'] == '5d3fecbeb1d67c288917598f55932e64c878f1e5'
    assert all(row['identical'] is True and row['source_anchor_sha'] == row['actual_git_parent_sha']
               for row in proof['compiler_input_root_bindings'])
    closure = {
        'schema': 'hepta-d1-r35-cache-owner-closure/v1', 'sealed': args.seal,
        'required_missing_bindings': [] if args.seal else ['actual_postflight_report_native_pages_and_original_inputs'],
        'cache_owner': OWNER, 'cache_path': OWNER + '/target-build',
        'closure_is_not_performance_adoption': True,
        'r35_observation_performance_passed': True, 'r35_normal_lifecycle_executed': True,
        'r35_normal_lifecycle_adopted': False,
        'postflight': {'job_id': module.OWNER_POSTFLIGHT_JOB,
            'report': report_identity if args.seal else None,
            'native': identity(actual[native_name], Path(OWNER) / native_name) if args.seal else None,
            'read_pages': [identity(actual[name], Path(OWNER) / name) for name in page_names] if args.seal else None},
        'inputs': owner['originals'] if args.seal else None,
        'host_files_rechecked_during_local_seal': False,
        'future_preparer_must_recheck_all_originals_current_source_and_cache_processes': True,
    }
    closure_raw = encode(closure)
    qualification = {
        'schema': 'hepta-d1-direct-qualification-input/v1', 'sealed': args.seal,
        'required_missing_bindings': [] if args.seal else ['actual_cache_owner_closure_input_sha256'],
        'baseline_commit': module.BASELINE_COMMIT, 'source_construction_parent': module.BASELINE_COMMIT,
        'published_candidate_commit': proof['published_candidate_commit'], 'published_candidate_parent': proof['actual_git_parent'],
        'publication_provenance': identity(proof_raw, 'provenance/source-anchor-and-publication-parent.json'),
        'candidate_catalog_git_blob': 'e100bf52d1b6d4c28113a17bd777c67d98c144e0',
        'candidate_input': identity(files['candidate/input.json'], 'candidate/input.json'),
        'candidate_manifest': identity(frozen_raw, 'candidate/package-manifest.json'),
        'baseline_qualification': prior['baseline_qualification'],
        'qualification_harness_sha256': prior['qualification_harness_sha256'],
        'owner_closure_input_sha256': identity(closure_raw)['sha256'] if args.seal else None,
        'preparation_tool': identity(tool_raw, 'prepare_qualify.py'),
        'source_rule': {'baseline_inputs': 220, 'candidate_inputs': 222, 'changed_paths': candidate['changed_paths'],
                        'added_paths': candidate['added_paths'], 'unchanged_inputs': 209,
                        'formatter_may_change_only_listed_paths': True, 'source_is_not_R35': True},
        'cache_rule': 'rename only the real closed R35 target-build after the original process and 3 GiB guards; no cache copy or deletion',
        'qualification_rule': {'original_eight_stages': module.STAGES, 'original_harness_count': 19, 'jobs': 2,
            'minimum_free_bytes': 3 * 1024**3, 'original_all_features': True, 'diagnostic_environment': 'absent',
            'qualified_release_kind': 'feature-enabled diagnostic ELF; mode unset',
            'ordinary_supplemental_run_by_this_preparer': False,
            'ordinary_supplemental_package_feature_set': [], 'no_default_features_switch': False,
            'automatic_retries': 0, 'original_qualifier_changed': False},
        'actual_d1_qualification': None, 'actual_d1_formatted_map': None,
        'actual_d1_test_counts': None, 'actual_d1_release_programs': None,
        'performance_acceptance_claim': False,
    }
    if args.seal:
        module.ready_inputs(qualification, closure)
    files['prepare_qualify.py'] = tool_raw
    files['qualification-input.json'] = encode(qualification)
    files['cache-owner-closure-inputs.json'] = closure_raw
    files['provenance/source-anchor-and-publication-parent.json'] = proof_raw
    for name, raw in actual.items():
        files['owner-closure-provenance/' + name] = raw
    files['owner-closure-provenance/postflight_r35_lifecycle_owner_01.py'] = read(
        HERE / 'references/postflight_r35_lifecycle_owner_01.py', 46387,
        '6b03c0025b2bffc0f0552e53e95d7867a45fbb78ebf05d601172cddf91434c7e')
    command = ['/usr/bin/python3', '-B', '-u', ROOT + '/prepare_qualify.py',
               '--input-sha256', identity(files['qualification-input.json'])['sha256'],
               '--owner-closure-sha256', identity(closure_raw)['sha256']]
    files['launch-command.json'] = encode({'schema': 'hepta-d1-qualification-launch-command/v1',
        'sealed': args.seal, 'host': 'x230', 'argv': command, 'cwd': ROOT,
        'must_have_absent_environment_keys': list(module.DIAGNOSTIC_ENV),
        'automatic_retries': 0, 'actual_native_job_id': None, 'executed': False})
    package = {'schema': 'hepta-d1-first-qualification-preparation-package/v1',
        'sealed': args.seal, 'host_root': ROOT,
        'files': [identity(raw, name) for name, raw in sorted(files.items())],
        'file_count_excluding_manifest': len(files), 'total_bytes_excluding_manifest': sum(map(len, files.values())),
        'actual_prior_owner_postflight_job_id': module.OWNER_POSTFLIGHT_JOB,
        'original_native_pages_retained': 3, 'source_package_unchanged': True,
        'runtime_or_qualifier_or_cargo_executed_by_sealer': False,
        'host_recheck_executed_by_sealer': False, 'd1_qualification_result': None,
        'ordinary_supplemental_result': None, 'diagnostic_result': None, 'performance_acceptance_claim': False}
    files['qualification-package-manifest.json'] = encode(package)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in sorted(files.items()):
        create(output / name, raw)
    # Read back every newly created original byte stream. No source/runtime
    # code, auditor, fixture, compiler, or remote process is executed here.
    assert all((output / name).read_bytes() == raw for name, raw in files.items())
    print(json.dumps({'output': str(output), 'sealed': args.seal, 'files': len(files),
                      'total_bytes': sum(map(len, files.values())),
                      'preparer': identity(tool_raw), 'qualification_input': identity(files['qualification-input.json']),
                      'cache_owner_input': identity(closure_raw),
                      'manifest': identity(files['qualification-package-manifest.json']),
                      'd1_qualification_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
