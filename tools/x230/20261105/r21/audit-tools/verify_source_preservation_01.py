#!/usr/bin/env python3
"""Verify a supplied nonrecursive publication root preserves the published R19 source.

Offline only. The input is the decoded GitHub tree API object, not an MCP
envelope. Only docs/tools root identities may change. This neither fetches leaf
bytes nor checks a new commit/ref or additions inside the two allowed subtrees.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import traceback

REPOSITORY = 'TrillionniumFoundation/hepta-runtime'
BASELINE_COMMIT = 'acdd07363cbff335e50c2944e02143d44ab03d6b'
BASELINE_ROOT = '09af147be5591314cabade42d5707ca1736c6312'
BASELINE_SRC = '3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20'
BASELINE_EXAMPLES = '08a04977815f59ef6c4cf77398f04a6c73e3ff03'
ROOT_API_SHA = 'b661eb3b2123d1ae03c70c5da1379305925ea2c47ae715ae44aa05ea3bf28f43'
SOURCE_PROOF_SHA = '1b8fbf0126d2f78e1c588df7812aeb8a332398cfcfb2294cea9764e72d6f18f3'
PUBLISHED_BINDING_SHA = 'f175e38465bf625e1ee867a7c7d99604b68220b27e0729943d6cb384e44d17d3'
ALLOWED_ROOT_CHANGES = {'docs', 'tools'}
MODES = {'040000': 'tree', '100644': 'blob', '100755': 'blob', '120000': 'blob', '160000': 'commit'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


class Reader:
    def __init__(self):
        self.inputs = {}

    def read(self, path, expected=None):
        path = path.absolute()
        before = path.lstat()
        need(path.resolve() == path and stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
             'noncanonical or nonregular input')
        raw = path.read_bytes()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stamp = tuple(getattr(before, key) for key in fields)
        need(len(raw) == before.st_size and stamp == tuple(getattr(path.lstat(), key) for key in fields),
             'input changed while reading')
        digest = hashlib.sha256(raw).hexdigest()
        need(expected is None or digest == expected, 'pinned input SHA256 differs: ' + str(path))
        self.inputs[path] = (raw, stamp)
        return json.loads(raw, object_pairs_hook=pairs)

    def stable(self):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        return all(path.read_bytes() == raw and tuple(getattr(path.lstat(), key) for key in fields) == stamp
                   for path, (raw, stamp) in self.inputs.items())

    def identities(self):
        return [{'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for path, (raw, _) in self.inputs.items()]


def root_tree(value):
    need(value.get('truncated') is False and re.fullmatch('[0-9a-f]{40}', value.get('sha', '')),
         'a complete decoded tree API object is required')
    entries = {}
    for row in value['tree']:
        name, mode, kind, digest = (row[key] for key in ('path', 'mode', 'type', 'sha'))
        need(isinstance(name, str) and name not in ('', '.', '..') and '/' not in name and '\0' not in name
             and name not in entries, 'root API is recursive or contains an invalid/duplicate name')
        need(mode in MODES and MODES[mode] == kind and re.fullmatch('[0-9a-f]{40}', digest),
             'invalid Git entry mode/type/SHA')
        entry = {'mode': mode, 'type': kind, 'sha': digest}
        if kind == 'blob':
            need(type(row.get('size')) is int and row['size'] >= 0, 'blob size missing or invalid')
            entry['size'] = row['size']
        entries[name] = entry
    contents = b''.join(('40000' if row['mode'] == '040000' else row['mode']).encode()
                        + b' ' + name.encode() + b'\0' + bytes.fromhex(row['sha'])
                        for name, row in sorted(entries.items(),
                            key=lambda item: (item[0] + ('/' if item[1]['type'] == 'tree' else '')).encode()))
    digest = git_hash('tree', contents)
    need(digest == value['sha'], 'API root SHA differs from recomputed Git object')
    return entries, digest


def selected_trees(rows):
    children = {}
    for row in rows:
        parts = PurePosixPath(row['path']).parts
        for n in range(1, len(parts)):
            parent, name = '/'.join(parts[:n - 1]), parts[n - 1]
            entry = ('40000', None)
            need(children.setdefault(parent, {}).get(name, entry) == entry, 'Git file/directory collision')
            children[parent][name] = entry
        parent, name = '/'.join(parts[:-1]), parts[-1]
        need(name not in children.setdefault(parent, {}), 'duplicate Git leaf')
        children[parent][name] = (row['mode'], row['git_blob_sha1'])
    result = {}
    for parent in sorted(children, key=lambda s: len(PurePosixPath(s).parts), reverse=True):
        entries = []
        for name, (mode, object_id) in children[parent].items():
            if mode == '40000':
                object_id = result['/'.join(filter(None, (parent, name)))]
            entries.append((name, mode, object_id))
        contents = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(object_id)
                            for name, mode, object_id in sorted(entries, key=lambda row: (row[0] + ('/' if row[1] == '40000' else '')).encode()))
        result[parent] = git_hash('tree', contents)
    return {name: result[name] for name in ('src', 'src/mcp', 'src/mcp/runtime', 'examples')}


def verify(args, result):
    reader = Reader()
    baseline = reader.read(args.baseline_root_api, ROOT_API_SHA)
    old, old_sha = root_tree(baseline)
    need(old_sha == BASELINE_ROOT and old['src']['sha'] == BASELINE_SRC
         and old['examples']['sha'] == BASELINE_EXAMPLES, 'published baseline root differs')
    proof = reader.read(args.r19_source_proof, SOURCE_PROOF_SHA)
    published = reader.read(args.r19_published_binding, PUBLISHED_BINDING_SHA)
    need(proof['schema'] == 'hepta-r19-qualified-source-binding/v1' and proof['verified'] is True
         and proof['source_input_count'] == 219 and proof['checks'] and all(v is True for v in proof['checks'].values()),
         'closed R19 source proof did not pass')
    commit = json.loads(published['commit_response']['content'], object_pairs_hook=pairs)
    need(commit['sha'] == BASELINE_COMMIT and commit['tree']['sha'] == BASELINE_ROOT
         and published['tree_response']['truncated'] is False
         and published['checks'] and all(v is True for v in published['checks'].values()),
         'retained actual R19 commit/tree binding differs')
    leaves = proof['qualified_inputs']
    observed = {row['path']: row for row in published['tree_response']['compiled_input_entries']}
    need(len(leaves) == len({row['path'] for row in leaves}) == len(observed) == 219,
         'R19 compiler input set differs')
    for row in leaves:
        name = row['path']
        need(name in ('Cargo.lock', 'Cargo.toml', 'rustfmt.toml') or name.startswith(('src/', 'examples/')),
             'unexpected compiler input selection')
        actual = observed[name]
        need(actual['type'] == 'blob' and (actual['sha'], actual['size'], actual['mode'])
             == (row['git_blob_sha1'], row['bytes'], row['mode']), 'inherited Git leaf association differs')
        if '/' not in name:
            need(old[name] == {'mode': row['mode'], 'type': 'blob', 'sha': row['git_blob_sha1'], 'size': row['bytes']},
                 'root compiler input differs from closed source proof')
    trees = selected_trees(leaves)
    need(trees == proof['recomputed_trees'] and trees['src'] == BASELINE_SRC
         and trees['examples'] == BASELINE_EXAMPLES, 'inherited selected Git trees differ')
    actual = reader.read(args.actual_root_api)
    current, new_sha = root_tree(actual)
    need(new_sha == args.expected_new_tree, 'actual root differs from explicitly expected new tree')
    need(set(current) == set(old), 'publication added or removed a root entry')
    need(all(current[name]['type'] == 'tree' and current[name]['mode'] == '040000'
             for name in ALLOWED_ROOT_CHANGES), 'docs/tools root entries must remain directories')
    changed = sorted(name for name in old if current[name] != old[name])
    need(set(changed) <= ALLOWED_ROOT_CHANGES, 'a protected root entry changed')
    need(current['src']['sha'] == BASELINE_SRC and current['examples']['sha'] == BASELINE_EXAMPLES,
         'R19 source or examples tree changed')
    need(reader.stable(), 'input evidence changed during verification')
    result.update(verified=True, passed=True, repository=REPOSITORY,
        baseline_commit=BASELINE_COMMIT, baseline_root_tree=BASELINE_ROOT,
        expected_new_root_tree=args.expected_new_tree, recomputed_new_root_tree=new_sha,
        root_entry_count=len(current), changed_root_entries=changed,
        allowed_root_changes=sorted(ALLOWED_ROOT_CHANGES),
        preserved_root_entries={name: current[name] for name in sorted(current) if name not in ALLOWED_ROOT_CHANGES},
        source_input_count=219, source_bytes_downloaded_by_this_tool=0,
        inherited_compiler_leaf_associations=219, inherited_selected_trees_recomputed=trees,
        inherited_qualified_inputs_sha256=hashlib.sha256(json.dumps(leaves, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        inputs=reader.identities(),
        checks={'both_root_Git_objects_recomputed': True, 'actual_new_root_matches_expected_SHA': True,
                'root_names_and_all_protected_entries_preserved': True, 'src_and_examples_equal_published_R19': True,
                'closed_R19_219_leaf_associations_match_retained_actual_Git_entries': True,
                'inherited_selected_trees_recomputed': True, 'all_input_evidence_unchanged': True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-root-api', 'r19-source-proof', 'r19-published-binding', 'actual-root-api', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-new-tree', required=True)
    args = parser.parse_args()
    need(re.fullmatch('[0-9a-f]{40}', args.expected_new_tree), 'expected new Git tree SHA must be explicit')
    need(not os.path.lexists(args.output), 'fresh output required')
    result = {'schema': 'hepta-r21-publication-source-preservation/v1', 'verified': False, 'passed': False,
              'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'remote_calls': 0, 'git_mutations': 0, 'tests_or_workloads_run': False,
              'final_commit_or_ref_checked': False, 'adoption_assessed': False,
              'scope': 'Merkle equality of protected root entries plus inherited published R19 source-leaf associations. No 219-leaf byte redownload and no check of additive-only changes within docs/tools.'}
    try:
        verify(args, result)
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    result['created_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    raw = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(raw)
    print(json.dumps({'verified': result['verified'], 'output': str(args.output.absolute()),
                      'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'error': result.get('error')}))
    return 0 if result['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
