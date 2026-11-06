#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Seal actual ordinary launch/result identities locally; never execute tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path('/home/qian/hepta-runtime-validation-cost-20261106-d2')
TOOLS = ROOT / 'ordinary-tools-01'
FOUNDATION_SHA = '2a04eb862c4efe1377a3b78dad33b99f43573d7c91dc66503ad5f08690b17da9'
FOUNDATION_BYTES = 59048
QUALIFIER_SHA = '07a6ebae6b2579c1935c1b64abce9ff50be5f58e83faeb30be622a52d27aed51'
ORIGINAL_SHA = '95717717fd5421f2e31dbce24e2f8821696f57d779ce93e988ed66764159552d'
HEX = re.compile(r'[0-9a-f]{64}')
JOB = re.compile(r'[0-9a-f]+-[0-9a-f]+-[0-9a-f]+')
FOUNDATION_KEYS = set([
    "cache-owner-closure-inputs.json",
    "candidate/baseline-source-map.json",
    "candidate/candidate-source-map.json",
    "candidate/candidate.patch",
    "candidate/input.json",
    "candidate/package-manifest.json",
    "candidate/source/src/mcp/runtime/phase_cost.rs",
    "candidate/source/src/mcp/runtime/ssh_observation_profile.rs",
    "candidate/summarize_trace_d2.py",
    "preparation.json",
    "prepare_qualify.py",
    "provenance/native-audit-native-read-000.json",
    "provenance/native-audit-native.json",
    "provenance/native-audit-start.json",
    "qualification-01/isolated-tests.audit.json",
    "qualification-01/isolated-tests/summary.json",
    "qualification-01/report.json",
    "qualification-01/source-map.json",
    "qualification-input.json",
    "qualification-package-manifest.json",
    "qualification-terminal-status-01.json",
    "rust-ci-01/nextest-output-audit.json",
    "rust-ci-01/report.json",
    "rust-ci-native-01.json",
    "rust-ci-plan-01.json"
])
RESULT_PATHS = {
 'plan': ROOT / 'ordinary-plan-01.json',
 'report': ROOT / 'ordinary-01/report.json',
 'source_map': ROOT / 'ordinary-01/source-map.json',
 'isolated_summary': ROOT / 'ordinary-01/isolated-tests/summary.json',
 'isolated_audit': ROOT / 'ordinary-01/isolated-tests.audit.json',
 'native_terminal': ROOT / 'ordinary-native-01.json',
}


def need(value, message):
    if not value:
        raise ValueError(message)


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, 'indirect local input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= 16 * 1024 * 1024, 'unsafe or oversized local input')
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    stamp = lambda value: tuple(getattr(value, key) for key in fields)
    need(len(raw) == before.st_size and stamp(before) == stamp(after) == stamp(path.lstat()),
         'local input changed during read')
    return raw


def pin(value, expected_path):
    need(type(value) is dict and set(value) == {'path', 'bytes', 'sha256'}
         and value['path'] == str(expected_path) and type(value['bytes']) is int and value['bytes'] > 0
         and isinstance(value['sha256'], str) and HEX.fullmatch(value['sha256']), 'actual original identity required')
    return value


def local_original(value, expected_path):
    need(type(value) is dict and set(value) == {'local_path', 'runtime_pin'}, 'actual local/raw binding required')
    expected = pin(value['runtime_pin'], expected_path)
    raw = read(value['local_path'])
    need(identity(raw) == {key: expected[key] for key in ('bytes', 'sha256')}, 'original local bytes differ')
    return expected, raw


def create(path, raw):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def launch(request, templates):
    foundation, foundation_raw = local_original(request['foundation'], ROOT / 'full-prerequisites-01/d2_prerequisites.py')
    need(foundation['bytes'] == FOUNDATION_BYTES and foundation['sha256'] == FOUNDATION_SHA,
         'the reviewed prerequisite foundation differs')
    prerequisites, prerequisites_raw = local_original(request['prerequisites'], ROOT / 'ordinary-prerequisites-01.json')
    value = json.loads(prerequisites_raw)
    need(value['schema'] == 'hepta-d2-c1-prerequisites/v1'
         and value['qualification_sealed'] is True and value['exact_ci_sealed'] is True
         and value['required_missing_qualification_bindings'] == value['required_missing_exact_ci_bindings'] == []
         and value['performance_acceptance_claim'] is False, 'actual full Q/CI prerequisite is incomplete')
    need(isinstance(value['qualification_original_job_id'], str) and JOB.fullmatch(value['qualification_original_job_id'])
         and isinstance(value['exact_ci_original_job_id'], str) and JOB.fullmatch(value['exact_ci_original_job_id'])
         and value['qualification_original_job_id'] != value['exact_ci_original_job_id'], 'distinct actual Q/CI jobs required')
    need(value['prerequisite_module'] == foundation, 'full prerequisite binds another canonical module')
    need(set(value['artifact_map']) == FOUNDATION_KEYS, 'full prerequisite artifact inventory differs')
    for name, declared in value['artifact_map'].items():
        pin(declared, ROOT / name)
    for key in ('qualification_read_pages', 'exact_ci_read_pages'):
        need(isinstance(value[key], list) and 1 <= len(value[key]) <= 16, 'complete actual Q/CI page identities required')
        for row in value[key]:
            need(Path(row['path']).parent == ROOT, 'native read original location differs')
            pin(row, Path(row['path']))
    original = read(templates / 'references/qualify.py')
    qualifier = read(templates / 'unsealed-tools/qualify_ordinary_01.py')
    verifier = read(templates / 'unsealed-tools/verify_ordinary_01.py')
    launcher = read(templates / 'unsealed-tools/launch_ordinary_01.py')
    need(identity(original)['sha256'] == ORIGINAL_SHA and identity(qualifier)['sha256'] == QUALIFIER_SHA,
         'ordinary qualifier templates differ')
    need(launcher.count(b'SPEC = None\n') == 1, 'unsealed launcher placeholder differs')
    manifest = {'schema': 'hepta-d2-ordinary-tools/v1', 'sealed': True,
        'original_qualifier': identity(original), 'qualifier': identity(qualifier), 'verifier': identity(verifier),
        'self_hash_bound_by_external_launch_argument': True,
        'supplement_stages': ['clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release'],
        'source_map_count': 222, 'ordinary_result': None, 'ordinary_executed': False}
    manifest_raw = encoded(manifest)
    spec = {'sealed': True, 'manifest': identity(manifest_raw), 'foundation': foundation, 'prerequisites': prerequisites}
    launcher = launcher.replace(b'SPEC = None\n', ('SPEC = ' + repr(spec) + '\n').encode())
    files = {
        'tools/launch_ordinary_01.py': launcher, 'tools/qualify_ordinary_01.py': qualifier,
        'tools/verify_ordinary_01.py': verifier, 'tools/package-manifest-01.json': manifest_raw,
        'ordinary-prerequisites-01.json': prerequisites_raw,
    }
    command = {'schema': 'hepta-d2-ordinary-native-launch/v1', 'executed': False,
        'cwd': str(ROOT), 'argv': ['/usr/bin/python3', '-B', '-u', str(TOOLS / 'launch_ordinary_01.py'),
                                 '--launcher-sha256', identity(launcher)['sha256']],
        'native_timeout_seconds': 7200, 'automatic_retries': 0,
        'diagnostic_environment_keys_must_be_absent': ['HEPTA_RUNTIME_PHASE_COST_MODE',
            'HEPTA_RUNTIME_PHASE_COST_OUTPUT', 'HEPTA_RUNTIME_PHASE_COST_ELF_SHA256'],
        'ordinary_original_job_id': None, 'ordinary_result': None}
    files['launch-command.json'] = encoded(command)
    metadata = {'foundation': foundation, 'prerequisites': prerequisites,
        'qualification_original_job_id': value['qualification_original_job_id'],
        'exact_ci_original_job_id': value['exact_ci_original_job_id'],
        'runtime_full_foundation_validation_required_before_exec': True,
        'original_qualifier_executed_by_sealer': False}
    return files, metadata


def result(request):
    seal_spec = request['launch_seal']
    need(type(seal_spec) is dict and set(seal_spec) == {'local_path', 'bytes', 'sha256'}, 'actual launch seal identity required')
    seal_raw = read(seal_spec['local_path'])
    need(identity(seal_raw) == {key: seal_spec[key] for key in ('bytes', 'sha256')}, 'launch seal original differs')
    seal = json.loads(seal_raw)
    need(seal['schema'] == 'hepta-d2-ordinary-input-seal/v1' and seal['purpose'] == 'launch'
         and seal['ordinary_executed_by_sealer'] is False, 'original ordinary launch seal required')
    need(set(request['originals']) == set(RESULT_PATHS), 'actual ordinary original inventory differs')
    inputs = {'schema': 'hepta-d2-ordinary-verification-input/v1', 'sealed_inputs': True,
        'performance_acceptance_claim': False, 'foundation': seal['metadata']['foundation'],
        'prerequisites': seal['metadata']['prerequisites']}
    raw_documents = {}
    for name, path in RESULT_PATHS.items():
        declared, raw = local_original(request['originals'][name], path)
        inputs[name] = declared
        raw_documents[name] = json.loads(raw)
    terminal = raw_documents['native_terminal']
    job = request['original_job_id']
    need(isinstance(job, str) and JOB.fullmatch(job) and terminal['job_id'] == job
         and terminal['state'] == 'succeeded' and type(terminal['exit_code']) is int and terminal['exit_code'] == 0
         and terminal['terminal_publication_confirmed'] is True
         and terminal['output_complete'] is True and terminal['output_durable'] is True,
         'an actual successful ordinary terminal original is required')
    need(raw_documents['report'].get('qualified') is True
         and raw_documents['isolated_summary'].get('success') is True
         and raw_documents['isolated_audit'].get('success') is True,
         'actual ordinary report/summary/audit did not pass')
    need(isinstance(request['native_read_pages'], list) and 1 <= len(request['native_read_pages']) <= 16,
         'actual complete native page originals are required')
    inputs['original_job_id'], inputs['native_read_pages'] = job, []
    for index, value in enumerate(request['native_read_pages']):
        declared, raw = local_original(value, ROOT / ('ordinary-native-read-01-%03d.json' % index))
        need(json.loads(raw)['job_id'] == job, 'ordinary read page job differs')
        inputs['native_read_pages'].append(declared)
    input_raw = encoded(inputs)
    verifier = seal['files']['tools/verify_ordinary_01.py']
    command = {'schema': 'hepta-d2-ordinary-readonly-verification-launch/v1', 'executed': False,
        'cwd': str(ROOT), 'argv': ['/usr/bin/python3', '-B', str(TOOLS / 'verify_ordinary_01.py'),
            '--input', str(ROOT / 'ordinary-verification-input-01.json'),
            '--input-sha256', identity(input_raw)['sha256'], '--verifier-sha256', verifier['sha256']],
        'automatic_retries': 0, 'verification_original_job_id': None, 'verification_result': None}
    return {'ordinary-verification-input-01.json': input_raw, 'verification-command.json': encoded(command)}, {
        'original_ordinary_job_id': job, 'launch_seal': identity(seal_raw),
        'runtime_full_original_stream_source_test_and_elf_validation_required': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--templates', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    request_raw = read(args.input.absolute())
    request = json.loads(request_raw)
    need(request.get('schema') == 'hepta-d2-ordinary-seal-request/v1'
         and request.get('sealed_inputs') is True and request.get('purpose') in {'launch', 'result'},
         'future ordinary inputs are not sealed')
    need(not os.path.lexists(args.output), 'original local seal destination exists')
    files, metadata = launch(request, args.templates.resolve()) if request['purpose'] == 'launch' else result(request)
    files['actual-seal-request.json'] = request_raw
    manifest = {'schema': 'hepta-d2-ordinary-input-seal/v1', 'purpose': request['purpose'],
        'ordinary_executed_by_sealer': False, 'compiler_or_test_executed_by_sealer': False,
        'host_api_or_binder_executed_by_sealer': False, 'performance_acceptance_claim': False,
        'source_input': identity(request_raw), 'metadata': metadata,
        'files': {name: identity(raw) for name, raw in sorted(files.items())}}
    files['seal-manifest.json'] = encoded(manifest)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, raw in sorted(files.items()):
        create(args.output / name, raw)
    print(json.dumps({'sealed': request['purpose'], 'files': len(files),
                      'seal_manifest': identity(files['seal-manifest.json']), 'ordinary_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
