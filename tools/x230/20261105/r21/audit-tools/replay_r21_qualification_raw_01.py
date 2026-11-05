#!/usr/bin/env python3
"""Replay the frozen isolated-test audit with two path maps and five ELF witnesses.

No ELF body is present locally. The original audit function is unchanged; its
digest dependency receives only the five exact accepted remote ELF witnesses.
Every other digest is computed from complete, authenticated local archive bytes.
No test, compiler, remote command or original auditor main is executed.
"""
import argparse
import ast
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import traceback

REMOTE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261105-r21')
MANIFEST_SHA = '6ee71d14762655ee7a473a673edf0ee22d8153de7d23780250676b167b505abc'
EXTRACTOR_SHA = 'a65660e5a3c16f339f4a127b3c1e2cf5ab5efc853c7a8a974cbaf6c7ee7f98c5'
AUDITOR_SHA = '736b2dcc85fbd5214b855813b6c1f0ceed3dedc1cc0957e709a9ee6cb0110c40'
VERIFIER_SHA = '216eb5e0cb922263d748f6dfefc8db00da88d00e8d021690246d7ab8e7183c95'
PINS = {
    'qualification-control-01/report.json': 'e664d6c75572d590df4537fc47cfddc1b66b7f1aeba100a5b7e542bcdf43e1b1',
    'independent-acceptance-01.json': '950a3e0d905e12937fa94ed4f9c4ad138e4797e5e4276abc19bc6c208a2a59a1',
    'qualification-01/report.json': '301e50f699d7a967d977add6d8da6872a3e09cedaabf1b0366658f6cf26af06a',
}
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path).absolute()
    before = path.lstat()
    need(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
         'noncanonical or nonregular local evidence')
    raw = path.read_bytes()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(len(raw) == before.st_size and all(getattr(before, k) == getattr(path.lstat(), k) for k in fields),
         'local evidence changed while reading')
    return raw


def binding(path):
    raw = read(path)
    return {'path': str(Path(path).absolute()), 'bytes': len(raw), 'sha256': sha(raw)}


def safe_relative(name):
    path = PurePosixPath(name)
    need(isinstance(name, str) and name and not path.is_absolute() and path.as_posix() == name
         and all(p not in ('', '.', '..') for p in path.parts), 'unsafe manifest path')
    return path


def run(args, result):
    root = args.qualification_root.absolute()
    need(root.resolve() == root and root.is_dir() and not args.output.absolute().is_relative_to(root),
         'canonical input and separate fresh output required')
    checks = result['checks']
    export_raw = read(args.export_binding)
    need(sha(export_raw) == args.expected_export_binding_sha256, 'export binding SHA differs')
    exported = json.loads(export_raw)
    need(exported['schema'] == 'hepta-r21-qualification-export-binding/v1' and exported['passed'] is True
         and exported['tool']['sha256'] == EXTRACTOR_SHA
         and exported['ordinary_file_count'] == 3364 and exported['archive_member_count'] == 3365
         and exported['omitted_elf_count'] == 8 and exported['local_evidence_root'] == str(root)
         and exported['checks'] and all(v is True for v in exported['checks'].values()),
         'complete export binding did not pass')
    result['export_binding'] = binding(args.export_binding)
    manifest_raw = read(root / '_export-manifest.json')
    need(sha(manifest_raw) == MANIFEST_SHA, 'embedded manifest SHA differs')
    manifest = json.loads(manifest_raw)
    need(manifest['schema'] == 'hepta-r21-qualification-export/v1', 'export manifest schema differs')
    files = {row['path']: row for row in manifest['files']}
    omissions = {row['original_path']: row for row in manifest['omitted_elf_bytes']}
    need(len(files) == len(manifest['files']) == 3364 and len(omissions) == 8, 'manifest cardinality differs')
    for name, row in files.items():
        relative = safe_relative(name)
        need(row['original_path'] == str(REMOTE / relative), 'manifest original path differs')
    need({p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
         == set(files) | {'_export-manifest.json'}, 'restored file set differs')

    def local_bytes(name):
        name = str(safe_relative(name))
        expected = files[name]
        raw = read(root / name)
        need(len(raw) == expected['size'] and sha(raw) == expected['sha256'], 'archived bytes differ: ' + name)
        return raw

    for name in files:
        local_bytes(name)
    checks['all_3364_payloads_and_exact_manifest_bound_before_replay'] = True
    documents = {}
    for name, expected in PINS.items():
        raw = local_bytes(name)
        need(sha(raw) == expected, 'actual qualification document differs')
        documents[name] = json.loads(raw)
    control = documents['qualification-control-01/report.json']
    accepted = documents['independent-acceptance-01.json']
    qualification = documents['qualification-01/report.json']
    need(control['passed'] is True and control['current_stage'] == 'completed'
         and accepted['accepted'] is True and qualification['qualified'] is True
         and len(accepted['checks']) == 31 and all(v is True for v in accepted['checks'].values()),
         'original actual qualification is not accepted')
    accepted_tests = {row['path']: row for row in accepted['retained_test_binaries']}
    need(len(accepted_tests) == 5 and set(accepted_tests) <= set(omissions), 'five ELF witnesses absent')
    for path, row in accepted_tests.items():
        need(PurePosixPath(path).parent == REMOTE / 'qualification-01/test-binaries'
             and omissions[path]['sha256'] == row['sha256'], 'retained ELF witness differs from acceptance')
    checks['five_exact_remote_elf_witnesses_match_actual_acceptance'] = True
    result['binary_hash_scope'] = 'The five current_after_sha256 values used internally by the original audit come from complete remote export witnesses matched to actual acceptance, not local ELF byte reads.'
    result['binary_witnesses'] = [{'original_path': path, 'remote_full_sha256': row['sha256'],
        'remote_full_bytes': omissions[path]['size'], 'local_payload_read': False}
        for path, row in sorted(accepted_tests.items())]

    verifier_raw = local_bytes('tools/verify_qualification_01.py')
    need(sha(verifier_raw) == VERIFIER_SHA, 'frozen verifier source differs')
    pure_names = {'require', 'stage_commands', 'validate_root_artifacts'}
    pure_defs = [node for node in ast.parse(verifier_raw).body
                 if isinstance(node, ast.FunctionDef) and node.name in pure_names]
    need({node.name for node in pure_defs} == pure_names, 'verifier pure definitions absent')
    v = {'Path': Path}
    exec(compile(ast.Module(body=pure_defs, type_ignores=[]), 'frozen-verifier-pure-definitions', 'exec'), v)
    need([row['name'] for row in qualification['stages']] == STAGES
         and [row['command'] for row in qualification['stages']] == v['stage_commands'](Path(REMOTE / 'source'), Path(REMOTE / 'qualification-01'))
         and all(type(row['returncode']) is int and row['returncode'] == 0 for row in qualification['stages']),
         'eight original stage commands or exits differ')
    for row in qualification['stages']:
        name = row['name']
        stdout = 'cargo-no-run.jsonl' if name == 'test-build' else name + '.stdout'
        need(sha(local_bytes('qualification-01/' + stdout)) == row['stdout_sha256']
             and sha(local_bytes('qualification-01/' + name + '.stderr')) == row['stderr_sha256'],
             'original stage stream differs')
    checks['eight_original_stage_commands_and_all_stream_hashes_match'] = True
    events = [json.loads(line) for line in local_bytes('qualification-01/cargo-no-run.jsonl').splitlines() if line.strip()]
    roots, tests = v['validate_root_artifacts'](events, Path(REMOTE / 'source'), Path(REMOTE / 'target-fresh-01'))
    retained = [json.loads(line) for line in local_bytes('qualification-01/retained-artifacts.jsonl').splitlines() if line.strip()]
    transformed = []
    for event in events:
        row = dict(event)
        if event in tests:
            kept = str(REMOTE / 'qualification-01/test-binaries' / PurePosixPath(event['executable']).name)
            need(kept in accepted_tests and event['target']['name'] == accepted_tests[kept]['target'], 'retained artifact target differs')
            row['executable'] = kept
        transformed.append(row)
    need(retained == transformed, 'original/retained artifact JSONL transformation differs')
    result['root_artifacts'] = [{'target': row['target']['name'], 'kind': row['target']['kind'],
                                'test': row['profile']['test'], 'fresh': row['fresh']} for row in roots]
    checks['fresh_root_artifacts_and_retained_five_test_mapping_match'] = True

    auditor_name = 'source/tools/x230/20261028/audit_isolated_tests.py'
    auditor_raw = local_bytes(auditor_name)
    need(sha(auditor_raw) == AUDITOR_SHA, 'frozen isolated auditor source differs')
    parsed = ast.parse(auditor_raw)
    body = [node for node in parsed.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign))
            or isinstance(node, ast.FunctionDef) and node.name != 'main']
    audit_def = next(node for node in body if isinstance(node, ast.FunctionDef) and node.name == 'audit')
    namespace = {}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(root / auditor_name), 'exec'), namespace)
    result['frozen_audit_source'] = {'path': auditor_name, 'sha256': AUDITOR_SHA,
        'audit_function_source_sha256': sha(ast.get_source_segment(auditor_raw.decode(), audit_def).encode()),
        'function_and_support_bodies_modified': False, 'main_executed': False}
    text_map = {str(REMOTE / 'qualification-01' / name): 'qualification-01/' + name
                for name in ('retained-artifacts.jsonl', 'source-map.json')}
    original_digest_requests, elf_digest_requests = [], []

    def bounded_digest(path):
        path = Path(path)
        key = str(path)
        if key in accepted_tests:
            elf_digest_requests.append(key)
            return omissions[key]['sha256']
        if key in text_map:
            name = text_map[key]
            original_digest_requests.append({'original_path': key, 'archived_relative_path': name})
            return sha(local_bytes(name))
        need(path.is_absolute() and path.is_relative_to(root), 'unmapped external digest request: ' + key)
        return sha(local_bytes(path.relative_to(root).as_posix()))

    namespace['digest'] = bounded_digest
    original = json.loads(local_bytes('qualification-01/isolated-tests.audit.json'))
    need(original['schema'] == 'hepta-isolated-libtest-audit/v1' and original['success'] is True
         and original['expected_filter'] == '' and original['errors'] == []
         and 'fatal_error' not in original and original['auditor_sha256'] == AUDITOR_SHA,
         'original isolated audit did not pass')
    derived = {'errors': [], 'binaries': [], 'commands': []}
    namespace['audit'](root / 'qualification-01/isolated-tests', '', derived)
    need(derived['errors'] == [] and {k: derived[k] for k in ('passed', 'failed', 'ignored', 'selected', 'executed')}
         == {'passed': 1637, 'failed': 0, 'ignored': 33, 'selected': 1670, 'executed': 1637},
         'complete original raw test audit rejected')
    need(Counter(elf_digest_requests) == Counter({path: 2 for path in accepted_tests})
         and Counter(row['original_path'] for row in original_digest_requests) == Counter({path: 1 for path in text_map}),
         'frozen audit digest dependency request scope changed')
    comparisons = {key: value == original[key] for key, value in derived.items()}
    need(all(comparisons.values()) and len(derived['commands']) == 1647, 'deterministic original/replayed audit fields differ')
    checks['all_3294_gzip_streams_original_inventories_exact_cases_and_deterministic_fields_match'] = True
    result['deterministic_field_comparisons'] = comparisons
    result['counts'] = {key: derived[key] for key in ('passed', 'failed', 'ignored', 'selected', 'executed')}
    result['raw_command_count'] = len(derived['commands'])
    result['raw_stream_count'] = 2 * len(derived['commands'])
    result['two_original_text_path_maps'] = original_digest_requests
    result['remote_elf_digest_dependency_calls'] = dict(Counter(elf_digest_requests))
    # Preserve original audit schema fields as a projection, with an explicit
    # remote-witness boundary. No new result is written over the original.
    result['frozen_audit_deterministic_projection'] = derived
    result['original_audit'] = {'path': str(REMOTE / 'qualification-01/isolated-tests.audit.json'),
                               **files['qualification-01/isolated-tests.audit.json']}
    for name in files:
        local_bytes(name)
    need(read(root / '_export-manifest.json') == manifest_raw and read(args.export_binding) == export_raw,
         'original metadata changed during replay')
    checks['all_original_payloads_manifest_and_export_binding_unchanged'] = True
    result.update(passed=True, source_binding_assessed=False, adoption_assessed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-root', type=Path, required=True)
    parser.add_argument('--export-binding', type=Path, required=True)
    parser.add_argument('--expected-export-binding-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'fresh output required')
    result = {'schema': 'hepta-r21-qualification-raw-offline-replay/v1', 'passed': False, 'checks': {},
              'tool_sha256': sha(Path(__file__).read_bytes()), 'workloads_started': False, 'remote_calls': 0,
              'rust_tests_executed': False, 'local_ELF_payloads_read': False,
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        run(args, result)
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    result['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'passed': result['passed'], 'output': binding(args.output), 'error': result.get('error')}, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
