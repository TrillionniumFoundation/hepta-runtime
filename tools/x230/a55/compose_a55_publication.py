#!/usr/bin/python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compose A55 publication from actual r01 qualification and eight postfmt files.

The A54 parent is the captured, fully checked 34b961 commit / 797878 tree.
Exactly 167 unchanged compiler blobs are inherited and eight actual formatted
bodies are rehashed. An optional captured final commit/tree must match all 175
compiler paths, modes and blob IDs. This is local validation only; it never calls
GitHub, changes source, compiles, starts a child or runs a runtime. Without the
three actual reports and eight actual qualified bodies, preparation is refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import types


ROOT = Path(__file__).resolve().parents[2]
BINDER = ROOT / 'recovery-review/a55-qualification/freeze_acceptance_bindings.py'
BINDER_SHA = 'c272afab2c9a58656224322ca502cd1e2ab4a3f628ee9611b1392074d606c3d4'
PARENT_COMMIT = '34b961941a211025f2083b9fd24470de32cb5b2f'
PARENT_TREE = '797878008d5ae6d8035766e53a3f6619b76a38c1'
PARENT_TESTED_MAP_SHA = '7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176'
PARENT_GIT_MAP_SHA = 'e368fa01d47104de5ebc3c56efcb6da91c4f589e75df49bbf1dedf5a67f4c774'
CHANGED = {'src/mcp/runtime/request_archive_store.rs', 'src/mcp/runtime/request_archive_content_tests.rs', 'src/mcp/runtime/request_archive_index.rs', 'src/mcp/runtime/request_archive_store_tests.rs', 'src/mcp/runtime/request_audit.rs', 'src/mcp/runtime/request_audit_tests.rs', 'src/mcp/runtime/request_archive_content.rs', 'src/mcp/runtime/request_metadata_trace.rs'}
ADDED = set()
PINS = {'parent_manifest': ('recovery-review/a54-qualification/published-34b96194/compiler-publication-manifest.json', '90f94d0b99b376ee01b3a7e3ca7fb43b983195ad42dab8b39b0596226ec3358f'), 'parent_git_map': ('recovery-review/a54-qualification/published-34b96194/a54-expected-git-blob-map.json', 'f2e9c328182b5dfffa72223374e573443104f2ef9a56fa7ea350834a7488034c'), 'parent_tested_map': ('recovery-review/a54-qualification/published-34b96194/a54-tested-source-map.json', 'caecddb1c64ba2ac377d32f7d6880b85fe7d0013ea62931672ae16098efacf4c'), 'parent_commit': ('a54-publication-staging/github-commit.captured.json', '09193432bc51da03902eb4f8ac3d7314412467af60b715077073bdb24d489b22'), 'parent_tree': ('a54-publication-staging/github-tree.captured.json', '58ca6b0ebf6f73d6d6b1c6cca79adc248c4f902fc0eda390f25f61f1cddda737')}


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def load_binder():
    need(BINDER.resolve(strict=True) == BINDER, 'direct frozen local binder required')
    raw = BINDER.read_bytes()
    need(sha(raw) == BINDER_SHA and len(raw) < 128 * 1024, 'reviewed local binder changed')
    module = types.ModuleType('a55_publication_actual_evidence')
    module.__file__ = str(BINDER)
    exec(compile(raw, str(BINDER), 'exec'), module.__dict__)
    return module


def capture_tree(common, commit, tree, expected_commit, expected_blobs, expected_modes=None,
                 expected_tree=None, required_parent=None):
    need(common.HEX40.fullmatch(expected_commit) and commit['sha'] == expected_commit
         and tree['truncated'] is False, 'captured commit is wrong or tree is truncated')
    commit_tree = commit.get('tree', commit.get('commit', {}).get('tree'))
    need(type(commit_tree) is dict and common.HEX40.fullmatch(commit_tree['sha'])
         and commit_tree['sha'] == tree['sha'], 'captured commit/tree identity differs')
    need(expected_tree is None or tree['sha'] == expected_tree, 'pinned parent tree differs')
    if required_parent is not None:
        need([row['sha'] for row in commit['parents']] == [required_parent],
             'final publication must directly extend the bound A54 commit')
    observed, all_names = {}, set()
    need(type(tree['tree']) is list, 'complete captured GitHub tree required')
    for item in tree['tree']:
        name = item['path']
        need(type(name) is str and name not in all_names, 'duplicate path in captured tree')
        all_names.add(name)
        if item['type'] == 'tree':
            continue
        if common.compiler_path(name):
            need(item['type'] == 'blob' and item['mode'] in ('100644', '100755')
                 and common.HEX40.fullmatch(item['sha']), 'invalid compiler entry in captured tree')
            observed[name] = {'mode': item['mode'], 'git_blob_sha1': item['sha']}
    missing = sorted(set(expected_blobs) - set(observed))
    extra = sorted(set(observed) - set(expected_blobs))
    mismatch = sorted(name for name in set(expected_blobs) & set(observed)
                      if observed[name]['git_blob_sha1'] != expected_blobs[name])
    mode_mismatch = [] if expected_modes is None else sorted(
        name for name in set(expected_blobs) & set(observed) if observed[name]['mode'] != expected_modes[name])
    need(not (missing or extra or mismatch or mode_mismatch), 'full compiler tree differs: ' + json.dumps(
        {'missing': missing, 'extra': extra, 'blob_changed': mismatch, 'mode_changed': mode_mismatch}))
    return {'performed': True, 'passed': True, 'commit_sha': commit['sha'], 'tree_sha': tree['sha'],
            'full_tree_checked': True, 'captured_tree_entries': len(tree['tree']),
            'compiler_files': len(observed), 'git_blob_map_compact_sha256': sha(compact(expected_blobs)),
            'modes': {name: row['mode'] for name, row in observed.items()},
            'mode_map_compact_sha256': sha(compact({name: row['mode'] for name, row in observed.items()})),
            'capture_representation': 'Serialized captured GitHub API objects; not original HTTP wire bytes',
            'network_calls_made_by_this_check': 0}


def qualified_names(root):
    need(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(),
         'direct actual qualified export root required')
    names = set()
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            need(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), 'indirect directory in qualified export')
        for name in files:
            path = Path(directory) / name
            need(stat.S_ISREG(path.lstat().st_mode), 'nonregular file in qualified export')
            names.add(path.relative_to(root).as_posix())
    need(names == CHANGED, 'exactly eight actual postfmt source files are required')
    return names


def compose(args):
    binder = load_binder()
    common, validator, inputs, actual, docs = binder.load_actual(args)
    inputs.read(BINDER, BINDER_SHA)
    need(args.out.is_absolute() and args.out.parent.resolve(strict=True) == args.out.parent
         and not os.path.lexists(args.out), 'fresh direct publication output required')
    parent = {key: common.document(inputs.read(ROOT / path, expected)) for key, (path, expected) in PINS.items()}
    parent_map, parent_git = parent['parent_tested_map'], parent['parent_git_map']
    common.validate_map(parent_map, 175, common.HEX64)
    common.validate_map(parent_git, 175, common.HEX40)
    need(set(parent_map) == set(parent_git) and sha(compact(parent_map)) == PARENT_TESTED_MAP_SHA
         and sha(compact(parent_git)) == PARENT_GIT_MAP_SHA, 'bound A54 parent maps differ')
    prior = parent['parent_manifest']
    need(prior['passed'] is True and prior['final_a54_github_tree_verified'] is True
         and prior['all_local_inputs_unchanged_at_end'] is True
         and prior['github_tree_check']['commit_sha'] == PARENT_COMMIT
         and prior['github_tree_check']['tree_sha'] == PARENT_TREE,
         'actual earlier A54 publication verification missing')
    parent_check = capture_tree(common, parent['parent_commit'], parent['parent_tree'],
                                PARENT_COMMIT, parent_git, expected_tree=PARENT_TREE)
    q, entry = docs['qualification'], docs['entry']
    tested = q['source_tested']
    common.validate_map(tested, 175, common.HEX64)
    need(entry['parent_source_map'] == parent_map and entry['parent_git_source_blob_map'] == parent_git,
         'actual qualification retained parent differs from published A54 tree')
    need(set(tested) == set(parent_map) | ADDED and set(common.delta(parent_map, tested)) == CHANGED,
         'A55 compiler delta differs from the eight reviewed files')
    inherited = set(tested) - CHANGED
    need(len(inherited) == 167 and all(tested[name] == parent_map[name] for name in inherited),
         'all 167 inherited source SHA256 identities must match A54')
    qualified_names(args.qualified_source)
    rows, git_map, modes = [], dict(parent_git), dict(parent_check['modes'])
    for name in sorted(CHANGED):
        row = common.body(inputs, args.qualified_source, name, tested[name])
        mode = parent_check['modes'].get(name, '100644')
        row.update(mode=mode, qualified_stage='A55-r01', prepared_sha256=q['source_input'][name],
                   formatter_changed=q['source_input'][name] != tested[name],
                   parent_tested_sha256=parent_map.get(name), parent_git_blob_sha1=parent_git.get(name))
        rows.append(row)
        git_map[name], modes[name] = row['git_blob_sha1'], mode
    common.validate_map(git_map, 175, common.HEX40)
    need(set(modes) == set(git_map), 'complete expected mode map required')
    supplied = [getattr(args, key) for key in ('github_tree', 'github_tree_sha256',
        'github_commit', 'github_commit_sha256', 'expected_commit')]
    final_check = {'performed': False, 'passed': False, 'reason': 'No captured final A55 commit/tree supplied'}
    if any(value is not None for value in supplied):
        need(all(value is not None for value in supplied), 'complete final captured GitHub bindings required')
        tree = common.document(inputs.read(args.github_tree, args.github_tree_sha256))
        commit = common.document(inputs.read(args.github_commit, args.github_commit_sha256))
        final_check = capture_tree(common, commit, tree, args.expected_commit, git_map, modes,
                                   required_parent=PARENT_COMMIT)
    inputs.unchanged()
    qualified_names(args.qualified_source)
    manifest = {'schema': 'hepta-a55-qualified-compiler-publication/v1', 'passed': True,
        'qualification_attempt': 'r01', 'actual_qualification': actual,
        'performance_adopted': False, 'github_writes': 0, 'github_calls': 0,
        'builds_or_runtime_executions': 0, 'source_writes': 0,
        'a54_parent': {'commit_sha': PARENT_COMMIT, 'tree_sha': PARENT_TREE,
            'compiler_files': 175, 'tested_map_compact_sha256': PARENT_TESTED_MAP_SHA,
            'git_blob_map_compact_sha256': PARENT_GIT_MAP_SHA,
            'actual_qualified_retained_parent_git_blobs_verified': True,
            'captured_full_tree_check': parent_check},
        'a54_to_a55_updates': rows,
        'expected_a55_git_blob_map_compact_sha256': sha(compact(git_map)),
        'expected_a55_mode_map_compact_sha256': sha(compact(modes)),
        'final_a55_github_tree_verified': final_check['performed'] and final_check['passed'],
        'github_tree_check': final_check,
        'coverage': {'final_compiler_files': 175, 'actual_postfmt_changed_bodies_rehashed': 8,
            'inherited_unchanged_a54_blob_ids': 167, 'all_175_bodies_rehashed_in_this_local_check': False,
            'inherited_body_basis': 'Actual qualified SHA256 equality and captured A54 full-tree blob IDs; the original A55 entry separately rehashed all retained parent bodies on X230.',
            'all_175_expected_modes_recorded': True, 'all_175_published_modes_checked': final_check['performed']},
        'all_local_inputs_unchanged_at_end': True, 'input_receipts': list(inputs.receipts.values())}
    outputs = {'compiler-publication-manifest.json': canonical(manifest),
               'a55-tested-source-map.json': canonical(tested),
               'a55-expected-git-blob-map.json': canonical(git_map),
               'a55-expected-mode-map.json': canonical(modes),
               'a55-source-publish-rows.json': canonical(rows)}
    return outputs, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--qualified-source', type=Path, required=True)
    for name in ('qualification', 'entry', 'worker'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha', required=True)
    parser.add_argument('--github-tree', type=Path)
    parser.add_argument('--github-tree-sha256')
    parser.add_argument('--github-commit', type=Path)
    parser.add_argument('--github-commit-sha256')
    parser.add_argument('--expected-commit')
    args = parser.parse_args()
    outputs, manifest = compose(args)
    os.mkdir(args.out, 0o700)
    for name, raw in outputs.items():
        with (args.out / name).open('xb') as stream:
            stream.write(raw)
    print(json.dumps({'passed': True, 'out': str(args.out), 'compiler_files': 175,
        'actual_formatted_bodies_rehashed': 8, 'inherited_a54_blobs': 167,
        'final_a55_github_tree_verified': manifest['final_a55_github_tree_verified'],
        'manifest_sha256': sha(outputs['compiler-publication-manifest.json'])}))


if __name__ == '__main__':
    main()
