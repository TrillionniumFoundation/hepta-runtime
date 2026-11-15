#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Freeze reviewed A50 local source/protocol payloads; never run qualification.

Only local files under this runtime-tools directory are read or written. The
reviewed draft wrapper may be finalized once; all new payloads use exclusive
creation. No host observer, Cargo command, remote API or qualifier main is used.
"""
import argparse
import ast
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import types


ROOT = Path(__file__).resolve().parent
WRAPPER = ROOT / 'qualify_a50_record_batches_r01.py'
OVERLAY = ROOT / 'a50-source-overlay'
PARENT = ROOT / 'a48-evidence/qualification'
NAMES = {
    'bundle': 'a50-record-batches-source-r01.json',
    'compressed': 'a50-record-batches-source-r01.json.gz',
    'protocol': 'a50-record-batches-qualification-r01.protocol.json',
    'preparation': 'a50-record-batches-preparation-r01.json',
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def map_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def read(path, expected=None):
    require(path.resolve(strict=True) == path and path.is_file(), 'local direct file required')
    require(path.stat().st_nlink == 1 and path.stat().st_size <= 1024 * 1024,
            'local bounded single-link input required')
    raw = path.read_bytes()
    require(expected is None or sha(raw) == expected, 'reviewed local input SHA differs: ' + str(path))
    return raw


def receipt(path, raw):
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def definitions(raw, path):
    namespace = {'__name__': 'a50_local_preparation_definitions', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), namespace)
    return namespace


def create(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reviewed-draft-sha256', required=True)
    parser.add_argument('--reviewed-overlay-sha256', required=True)
    parser.add_argument('--review-note', required=True)
    args = parser.parse_args()
    require(all(re.fullmatch(r'[0-9a-f]{64}', value) for value in (
        args.reviewed_draft_sha256, args.reviewed_overlay_sha256)), 'exact reviewed SHA values required')
    require(args.review_note.strip(), 'record the actual review scope')
    for name in NAMES.values():
        require(not os.path.lexists(ROOT / name), 'create-only preparation output already exists: ' + name)
    draft_raw = read(WRAPPER, args.reviewed_draft_sha256)
    draft = definitions(draft_raw, WRAPPER)
    require(draft['FINAL_BINDINGS_READY'] is False, 'only the unexecuted draft can be finalized')
    manifest_raw = read(OVERLAY / 'manifest.json', args.reviewed_overlay_sha256)
    manifest = json.loads(manifest_raw)
    qraw = read(PARENT / 'qualification.json', draft['PARENT_Q_SHA'])
    q = json.loads(qraw)
    for file, digest, length in (
        ('entry-report.json', draft['PARENT_ENTRY_SHA'], draft['PARENT_ENTRY_BYTES']),
        ('worker-report.json', draft['PARENT_WORKER_SHA'], draft['PARENT_WORKER_BYTES']),
    ):
        require(len(read(PARENT / file, digest)) == length, 'parent guardian length differs')
    parent = q['source_after']
    require(q['schema'] == draft['PARENT_SCHEMA'] and q['qualified'] is True
            and q['current_stage'] == 'complete' and q['source_tested'] == parent
            and len(parent) == draft['PARENT_FILES'] == 168
            and map_sha(parent) == draft['PARENT_MAP_SHA'], 'actual ordinary A48 parent differs')
    require(manifest['schema'] == 'hepta-runtime-a50-source-overlay/v1'
            and manifest['parent_source_map_sha256'] == draft['PARENT_MAP_SHA']
            and manifest['parent_qualification_report_sha256'] == draft['PARENT_Q_SHA']
            and manifest['source_files'] == 168
            and manifest['parent_commit'] == draft['PARENT_GIT_COMMIT'],
            'reviewed overlay parent or scope differs')
    required = manifest['new_tests'] + manifest['required_existing_test_coverage']
    require(manifest['new_tests'] and len(required) == len(set(required))
            and draft['PARENT_REQUIRED_TESTS'] <= set(manifest['required_existing_test_coverage'])
            and all(type(name) is str and re.fullmatch(r'[a-z][a-z0-9_]*', name) for name in required),
            'reviewed new/old full-suite test coverage differs')
    changed = {row['path']: row for row in manifest['changed_files']}
    require(len(changed) == len(manifest['changed_files']) == len(draft['CHANGED'])
            and set(changed) == draft['CHANGED'], 'exact two existing overlay files required')
    candidate, contents = dict(parent), {}
    for name, row in sorted(changed.items()):
        require(name in parent and '..' not in Path(name).parts and not Path(name).is_absolute(),
                'overlay path is not an existing parent member')
        body = read(OVERLAY / name, row['sha256'])
        parent_body = read(PARENT / 'source' / name, parent[name])
        require(len(body) == row['bytes'] and row['parent_sha256'] == parent[name]
                and len(parent_body) == row['parent_bytes'] and row['sha256'] != parent[name],
                'overlay body/parent receipt differs')
        candidate[name] = row['sha256']
        contents[name] = {'bytes': len(body), 'sha256': sha(body),
                          'parent_sha256': parent[name],
                          'data_base64': base64.b64encode(body).decode('ascii')}
    candidate_raw = read(OVERLAY / 'candidate-source-map.json')
    require(json.loads(candidate_raw) == candidate and len(candidate) == 168
            and map_sha(candidate) == manifest['candidate_source_map_sha256'],
            'complete 168-member candidate map differs')
    listed_map = manifest['candidate_source_map_file']
    require(listed_map['path'] == 'candidate-source-map.json'
            and listed_map['bytes'] == len(candidate_raw) and listed_map['sha256'] == sha(candidate_raw),
            'author candidate map file receipt differs')
    bundle = {'schema': draft['BUNDLE_SCHEMA'], 'attempt': draft['ATTEMPT'],
              'parent_source': str(draft['PARENT']),
              'parent_qualification': {'path': str(draft['PARENT_Q']), 'sha256': draft['PARENT_Q_SHA'],
                                       'bytes': draft['PARENT_Q_BYTES']},
              'parent_source_map': parent, 'candidate_source_map': candidate,
              'changed_files': contents,
              'overlay_manifest': {'bytes': len(manifest_raw), 'sha256': sha(manifest_raw),
                  'data_base64': base64.b64encode(manifest_raw).decode('ascii')}}
    bundle_raw = canonical(bundle)
    compressed_raw = gzip.compress(bundle_raw, compresslevel=9, mtime=0)
    bindings = {'FINAL_BINDINGS_READY': True, 'CANDIDATE_MAP_SHA': map_sha(candidate),
                'BUNDLE_SHA': sha(bundle_raw), 'BUNDLE_BYTES': len(bundle_raw),
                'COMPRESSED_SHA': sha(compressed_raw), 'COMPRESSED_BYTES': len(compressed_raw),
                'OVERLAY_MANIFEST_SHA': sha(manifest_raw), 'OVERLAY_MANIFEST_BYTES': len(manifest_raw)}
    final = draft_raw.decode()
    for name, value in bindings.items():
        expected = 'False' if name == 'FINAL_BINDINGS_READY' else 'None'
        final, count = re.subn(r'^' + name + r' = ' + expected + r'$',
                              name + ' = ' + repr(value), final, flags=re.MULTILINE)
        require(count == 1, 'draft binding is not uniquely unset: ' + name)
    final_raw = final.encode()
    original_ast, normalized = ast.parse(draft_raw), ast.parse(final_raw)
    for node in normalized.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in bindings):
            node.value = ast.Constant(False if node.targets[0].id == 'FINAL_BINDINGS_READY' else None)
    require(ast.dump(normalized, include_attributes=False) == ast.dump(original_ast, include_attributes=False),
            'local finalization changed code outside frozen binding literals')
    frozen = definitions(final_raw, WRAPPER)
    frozen['check_final_bindings']()
    legacy_raw = read(ROOT / 'prepare_qualify_a44_owner_barrier_r01.py', frozen['LEGACY_SHA'])
    read(ROOT / 'qualify_a43_a46.py', frozen['SHARED_SHA'])
    old_raw = read(ROOT / 'a44-owner-barrier-qualification-r01.protocol.json', frozen['LEGACY_PROTOCOL_SHA'])
    stage_node = next(node for node in ast.parse(legacy_raw).body
                      if isinstance(node, ast.Assign) and len(node.targets) == 1
                      and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'STAGES')
    core = types.SimpleNamespace(CARGO='/home/qian/.cargo/bin/cargo',
                                 TARGET=frozen['BASE'] / 'target', STAGES=ast.literal_eval(stage_node.value))
    protocol_raw = canonical(frozen['policy'](core, json.loads(old_raw)))
    artifacts = {'bundle': bundle_raw, 'compressed': compressed_raw, 'protocol': protocol_raw}
    # Recheck every reviewed input before any final payload publication.
    read(WRAPPER, args.reviewed_draft_sha256)
    read(OVERLAY / 'manifest.json', args.reviewed_overlay_sha256)
    for name, row in changed.items():
        read(OVERLAY / name, row['sha256'])
    read(OVERLAY / 'candidate-source-map.json', sha(candidate_raw))
    for key, body in artifacts.items():
        create(ROOT / NAMES[key], body)
    temporary = WRAPPER.with_name(WRAPPER.name + '.a50-final.next')
    create(temporary, final_raw)
    os.replace(temporary, WRAPPER)
    report = {'schema': 'hepta-a50-record-batches-local-preparation/v1',
              'status': 'frozen_prepared_not_executed', 'review_note': args.review_note,
              'reviewed_draft': receipt(WRAPPER, draft_raw),
              'overlay_manifest': receipt(OVERLAY / 'manifest.json', manifest_raw),
              'parent_map_sha256': frozen['PARENT_MAP_SHA'],
              'parent_report': receipt(frozen['PARENT_Q'], qraw),
              'parent_git_commit': frozen['PARENT_GIT_COMMIT'],
              'parent_git_tree': frozen['PARENT_GIT_TREE'],
              'candidate_input_map_sha256': map_sha(candidate), 'source_files': 168,
              'changed_existing_files': len(contents), 'candidate_input_is_unformatted': True,
              'qualification_must_bind_actual_post_format_map': True,
              'full_suite_required_test_count': len(required),
              'remote_executions': 0, 'qualification_executions': 0, 'benchmark_executions': 0,
              'source_tree_mutations': 0, 'no_old_driver_report_or_source_modified': True,
              'local_validation_scope': 'Reviewed input SHA checks, complete overlay/map recomputation, deterministic single-member gzip, binding-only AST normalization and protocol construction; no main, observer, Cargo, test or remote execution.',
              'artifacts': {WRAPPER.name: receipt(WRAPPER, final_raw),
                  **{NAMES[key]: receipt(ROOT / NAMES[key], body) for key, body in artifacts.items()}}}
    create(ROOT / NAMES['preparation'], canonical(report))
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({'preparation': str(ROOT / NAMES['preparation']),
                      'wrapper_sha256': sha(final_raw), 'protocol_sha256': sha(protocol_raw),
                      'qualification_executions': 0}), flush=True)


if __name__ == '__main__':
    main()
