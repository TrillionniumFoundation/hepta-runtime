"""Bind additive RawValue parity to the shared HIA Value owner and locked Rust."""
from __future__ import annotations

import json
import math
from pathlib import Path

FOLDER = 'serde-json-raw-value-rust-oracle'
TEST = 'test_serde_json_raw_value.py'
CONTROL_TEST = 'test_serde_json_raw_value_evidence.py'
EVIDENCE_REPORT = 'serde-json-raw-value-evidence-controls.json'
EXTENSION_FILES = ('raw_value_cases.py', TEST)
CASES = 6325
CALLS = 6335
CORPUS_IDENTITY = {'categories': {'8MiB-raw-node-arena': 1,
                '8MiB-raw-whitespace': 1,
                'array': 10,
                'changed-key-is-ordinary': 30,
                'escaped-first-key': 30,
                'extra-raw-member': 2,
                'independent-depth-budgets': 36,
                'invalid-inner': 8,
                'invalid-overwritten-inner': 8,
                'later-key-is-ordinary': 1,
                'maximum-representable-context-chain': 1,
                'nested': 10,
                'nested-contexts': 14,
                'nested-parent-key-custody': 1,
                'non-string-raw-field': 5,
                'object': 10,
                'raw-not-number': 4,
                'raw-source-plus-one-context': 1,
                'recovery-after-refusal': 9,
                'refusal-output-atomicity': 9,
                'root': 10,
                'valid-overwritten-inner': 1,
                'whitespace-inner': 10,
                'wrapped-number-projection/integer-boundary': 655,
                'wrapped-number-projection/long-decimal': 960,
                'wrapped-number-projection/numeric-fixed': 39,
                'wrapped-number/integer-boundary': 655,
                'wrapped-number/long-decimal': 960,
                'wrapped-number/numeric-fixed': 39,
                'wrapped-value/integer-unicode-structures': 512,
                'wrapped-value/object-key-byte': 128,
                'wrapped-value/stable-last-wins-btree': 64,
                'wrapped-value/string-byte': 128,
                'wrapped-value/unicode-boundary': 7,
                'wrapped-value/unicode-encoding': 14,
                'wrapped-value/value-byte-deletion': 95,
                'wrapped-value/value-byte-insertion': 300,
                'wrapped-value/value-byte-replacement': 1045,
                'wrapped-value/value-decimal-boundaries': 440,
                'wrapped-value/value-depth': 16,
                'wrapped-value/value-fixed': 29,
                'wrapped-value/value-invalid': 27},
 'native_output_bytes': 17192750,
 'native_output_sha256': '5390af59e1d063d3b7bc2cb1ed54bc93363ea94a0a4cec9e958a43319addca23',
 'requests_bytes': 61854093,
 'requests_sha256': '061f1b813480c8a707776b7e2af9a6d5459d449b92db83c583421e9762d7780f'}
CONTROL_COUNTS = {'actual_capture': 1, 'completion_refusals': 10,
                  'source_refusals': 4, 'corpus_refusals': 14}


def check_corpus(root: Path, output: Path, report: dict) -> dict:
    from hia_native_json_qualification import (check_module, digest, regular, relative,
                                               same_json, source_inputs, stream_identity)
    root, output = root.resolve(), output.resolve()
    manifest = check_module(root, 'serde_json', relative(output, report['modules']['serde_json']['manifest']))
    folder = output / FOLDER
    metadata = json.loads(regular(folder / 'native-corpus.json'))
    extensions = {name: digest(regular(root / 'tests/hia_native' / name)) for name in EXTENSION_FILES}
    expected = {'schema': 'hepta.runtime.raw-value-native-corpus.v1',
                'status': 'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED', 'cases': CASES,
                'actual_native_calls': CALLS, 'source_sha256': manifest['source_sha256'],
                'image_sha256': manifest['image_sha256'], 'qualification_inputs': source_inputs(root),
                'extension_inputs': extensions, **CORPUS_IDENTITY}
    if any(not same_json(metadata.get(key), value) for key, value in expected.items()):
        raise ValueError('RawValue exported corpus differs from the complete pinned shared-owner domain')
    elapsed = metadata.get('native_seconds')
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed <= 0:
        raise ValueError('RawValue actual native elapsed time is invalid')
    for prefix, name in (('requests', 'requests.hex'), ('native_output', 'native-output.txt')):
        if metadata.get(prefix + '_file') != name:
            raise ValueError('RawValue corpus member escaped its declared name')
        actual_hash, size, count = stream_identity(folder / name)
        if (actual_hash != CORPUS_IDENTITY[prefix + '_sha256']
                or size != CORPUS_IDENTITY[prefix + '_bytes'] or count != CASES):
            raise ValueError('RawValue complete exported corpus bytes differ')
    return metadata


def native_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    from hia_native_json_qualification import (CORPUS_FILES, build_evidence, completed_suite,
                                               digest, regular, same_json, source_inputs, stream_identity)
    root, output = root.resolve(), output.resolve()
    check, summary = completed_suite(root, output, report, completed, TEST, 3)
    built = build_evidence(root, output, report, 'serde_json')
    metadata = check_corpus(root, output, report)
    if not same_json(metadata, summary):
        raise ValueError('RawValue corpus is not the actual completed native stdout')
    artifacts = dict(built['artifact_sha256'])
    artifacts[TEST + '.stdout'] = check['stdout_sha256']
    artifacts[TEST + '.stderr'] = check['stderr_sha256']
    corpus = {}
    for name in CORPUS_FILES:
        path = output / FOLDER / name
        corpus[path.relative_to(output).as_posix()] = (digest(regular(path)) if name == 'native-corpus.json'
                                                       else stream_identity(path)[0])
    return {'schema': 'hepta.runtime.raw-value-native-evidence.v1', 'status': 'PASS',
            'owner': built, 'qualification_inputs': source_inputs(root),
            'extension_inputs': metadata['extension_inputs'], 'corpus': CORPUS_IDENTITY,
            'tests': {TEST: {key: check[key] for key in ('stdout_sha256', 'stderr_sha256')}},
            'artifact_sha256': artifacts, 'corpus_sha256': corpus,
            'actual_native_calls': CALLS, 'actual_elf_runs': 0, 'captured_reference_cases': CASES,
            'native_cases_added_by_replay': 0, 'production_activated': False, 'whole_runtime_replaced': False}


def qualification_evidence(root: Path, output: Path, report: dict, completed) -> dict:
    from hia_native_json_qualification import completed_suite, digest, regular, same_json, source_inputs
    evidence = native_evidence(root, output, report, completed)
    check, summary = completed_suite(root, output, report, completed, CONTROL_TEST, 4)
    stored = regular(output / EVIDENCE_REPORT)
    expected = {'schema': 'hepta.runtime.raw-value-evidence-controls.v1', 'status': 'PASS',
                'synthetic_receipt_controls': True, 'new_native_calls': 0,
                'source_inputs': source_inputs(root), 'counts': CONTROL_COUNTS}
    if not same_json(summary, json.loads(stored)) or not same_json(summary, expected):
        raise ValueError('RawValue strict evidence controls did not complete their declared domain')
    evidence['evidence_controls'] = summary['counts']
    evidence['corpus_sha256'][EVIDENCE_REPORT] = digest(stored)
    evidence['artifact_sha256'][CONTROL_TEST + '.stdout'] = check['stdout_sha256']
    evidence['artifact_sha256'][CONTROL_TEST + '.stderr'] = check['stderr_sha256']
    return evidence


def check_original(root: Path, output: Path, report: dict, expected: dict, build: dict, completed) -> None:
    from hia_native_json_qualification import completed_reference_process, digest, regular, same_json
    evidence = qualification_evidence(root, output, report, completed)
    if not same_json(evidence, report.get('json_evidence', {}).get('raw_value')):
        raise ValueError('RawValue native evidence changed before original replay verification')
    name = 'serde-json-raw-value-rust-compare'
    check, stdout, stderr = completed_reference_process(output, report, name)
    native = regular(output / FOLDER / 'native-output.txt')
    fields = {'schema': 'hepta.runtime.raw-value-original-rust-comparison.v1', 'status': 'PASS',
              'component': 'serde_json', 'cases': CASES,
              'requests_sha256': CORPUS_IDENTITY['requests_sha256'],
              'native_output_sha256': CORPUS_IDENTITY['native_output_sha256'],
              'original_output_sha256': digest(stdout), 'executable_sha256': build['executable_sha256'],
              'reference_build': build, 'stdout_sha256': check['stdout_sha256'],
              'stderr_sha256': check['stderr_sha256'], 'native_cases_added_by_replay': 0,
              'production_activated': False, 'whole_runtime_replaced': False}
    if (check.get('command') != [str(output / build['executable'])] or stderr or stdout != native
            or type(check.get('timeout_seconds')) is not int or check['timeout_seconds'] != 180
            or check.get('stdin_sha256') != CORPUS_IDENTITY['requests_sha256']
            or type(check.get('stdin_bytes')) is not int
            or check['stdin_bytes'] != CORPUS_IDENTITY['requests_bytes']
            or not same_json(expected, json.loads(regular(output / FOLDER / 'rust-comparison.json')))
            or any(not same_json(expected.get(key), value) for key, value in fields.items())):
        raise ValueError('RawValue full actual original replay or retained bytes differ')


def compare_original(root: Path, output: Path, report: dict, build: dict, *, completed,
                     record_check, environment) -> dict:
    from hia_native_json_qualification import completed_reference_process, digest, regular, same_json
    evidence = qualification_evidence(root, output, report, completed)
    if not same_json(evidence, report.get('json_evidence', {}).get('raw_value')):
        raise ValueError('RawValue completed native evidence changed before original replay')
    folder = output / FOLDER
    wire = regular(folder / 'requests.hex')
    expected = regular(folder / 'native-output.txt')
    name = 'serde-json-raw-value-rust-compare'
    row = record_check(output, report, name=name, command=[str(output / build['executable'])],
                       input_bytes=wire, env=environment(), timeout=180)
    if row.stderr or row.stdout != expected:
        raise ValueError('RawValue original locked serde replay differs')
    check, stdout, stderr = completed_reference_process(output, report, name)
    check.update(stdin_sha256=digest(wire), stdin_bytes=len(wire))
    if not same_json(evidence, qualification_evidence(root, output, report, completed)):
        raise ValueError('RawValue inputs changed during original replay')
    result = {'schema': 'hepta.runtime.raw-value-original-rust-comparison.v1', 'status': 'PASS',
              'component': 'serde_json', 'cases': CASES, 'requests_sha256': digest(wire),
              'native_output_sha256': digest(expected), 'original_output_sha256': digest(stdout),
              'executable_sha256': build['executable_sha256'], 'reference_build': build,
              'stdout_sha256': check['stdout_sha256'], 'stderr_sha256': check['stderr_sha256'],
              'reference_kind': 'original locked serde_json Value/Number with raw_value and float_roundtrip',
              'native_cases_added_by_replay': 0, 'production_activated': False, 'whole_runtime_replaced': False}
    with (folder / 'rust-comparison.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + '\n')
    check_original(root, output, report, result, build, completed)
    return result
