#!/usr/bin/env python3
"""Bind an actually accepted R20 qualification to all 219 published Git inputs.

Offline only. Missing/incomplete qualification fails closed. This does not build,
run tests, rerun workloads, publish Git objects, or claim a local ELF read.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import traceback

REPOSITORY = 'TrillionniumFoundation/hepta-runtime'
PARENT_COMMIT = 'acdd07363cbff335e50c2944e02143d44ab03d6b'
PARENT_TREE = '09af147be5591314cabade42d5707ca1736c6312'
PARENT_SRC = '3aa8c9aadbf42b6a0ebdac3954bd1e64b4055e20'
BASELINE_SHA = 'c9080de8aa9a35f7495aa2822a1495d297903900ae0f0de26d7b0c86d043d3c9'
CANDIDATE_SHA = '2f751c09a9a29bebb0cda0a9bd2bb522d145ee8183740ed1442d77666ee44aa7'
CANDIDATE_BLOB = '1e640c2d8162bf214f26dd6bb7ebec9468b36468'
CANDIDATE_SRC = '7e5e1984bd5c0df2c0e2fc4179c30e7622d145a5'
BASELINE_PROOF_SHA = '1b8fbf0126d2f78e1c588df7812aeb8a332398cfcfb2294cea9764e72d6f18f3'
PUBLISHED_BINDING_SHA = 'f175e38465bf625e1ee867a7c7d99604b68220b27e0729943d6cb384e44d17d3'
BASELINE_FREEZE_SHA = '31f90b50d22ff8c8ac3a188f1bad47c844b4e2e68784277a87a671c916f7cb6a'
JOBCTL_SHA = '61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62'
TOOLS_SHA = 'a827290f1706a3ae5dd66478feab993193cf408a1f31710bf12b864eceeb2d8d'
SEMANTIC_SHA = '7223fafebacd13d5debe05f113f314b550f3896156d59e44837225a63f1a7631'
COLD_AUDIT_SHA = '9979f4e4ae891058947cf6132bd1ecb2a07382e98e4a9ece96961baf0142037a'
COLD_MANIFEST_SHA = '82fd69812404ef8d132f8ad6e37365b89ac9b573f2eed73d70a103c45afc1a2d'
REMOTE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261105-r20')
BASELINE_REMOTE = PurePosixPath('/home/qian/hepta-runtime-optimization-20261104-r19/source')
STAGES = ['format', 'fmt-check', 'harness-tests', 'clippy', 'test-build', 'isolated-tests', 'audit-isolated-tests', 'release']


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=pairs)


def fingerprint(path):
    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and path.resolve() == path, 'nonregular/noncanonical input: ' + str(path))
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class Reader:
    def __init__(self):
        self.seen = {}

    def read(self, path, expected=None):
        path = Path(path).absolute()
        if path not in self.seen:
            before = fingerprint(path); raw = path.read_bytes()
            need(fingerprint(path) == before and len(raw) == before[3], 'input changed during read')
            self.seen[path] = (before, raw)
        raw = self.seen[path][1]
        if expected is not None:
            need(sha(raw) == expected, 'input SHA256 differs: ' + str(path))
        return raw

    def doc(self, path, expected=None):
        return decode(self.read(path, expected))

    def binding(self, path):
        raw = self.read(path)
        return {'path': str(Path(path).absolute()), 'bytes': len(raw), 'sha256': sha(raw)}

    def stable(self):
        return all(fingerprint(p) == before and p.read_bytes() == raw for p, (before, raw) in self.seen.items())


def selected(path):
    return path in ('Cargo.lock', 'Cargo.toml', 'rustfmt.toml') or path.startswith(('src/', 'examples/'))


def validate_map(mapping, total, full=False):
    need(isinstance(mapping, dict) and len(mapping) == total, 'source inventory count')
    for name, row in mapping.items():
        p = PurePosixPath(name)
        need(not p.is_absolute() and p.as_posix() == name and all(x not in ('', '.', '..') for x in name.split('/')), 'invalid source path')
        digest = row['sha256'] if full else row
        need(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'invalid source SHA256')
        if full:
            need(set(row) == {'size', 'sha256'} and type(row['size']) is int and row['size'] >= 0, 'invalid full source row')


def tree_hashes(rows):
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
    # The artificial top level contains only compiler inputs; it is not a repo root.
    return {name: result[name] for name in ('src', 'src/mcp', 'src/mcp/runtime', 'examples')}


def bind(args, result):
    reader = Reader(); checks = result['checks']; root = args.qualification_root.absolute()
    need(root.resolve() == root and root.is_dir(), 'qualification evidence root is not canonical')
    need(not args.output.absolute().is_relative_to(root), 'output must not alter qualification evidence')
    prior = reader.doc(args.baseline_source_proof, BASELINE_PROOF_SHA)
    published = reader.doc(args.published_commit_binding, PUBLISHED_BINDING_SHA)
    need(prior['schema'] == 'hepta-r19-qualified-source-binding/v1' and prior['verified'] is True
         and prior['source_input_count'] == 219 and all(v is True for v in prior['checks'].values()), 'published R19 proof failed')
    commit = decode(published['commit_response']['content'])
    need(commit['sha'] == PARENT_COMMIT and commit['tree']['sha'] == PARENT_TREE
         and all(v is True for v in published['checks'].values()), 'actual published commit/root binding')
    leaves = prior['qualified_inputs']; need(len(leaves) == 219 and len({r['path'] for r in leaves}) == 219, 'R19 leaf count')
    prior_map = {r['path']: r['sha256'] for r in leaves}; validate_map(prior_map, 219)
    published_rows = published['tree_response']['compiled_input_entries']
    need(published['tree_response']['truncated'] is False and len(published_rows) == 219
         and len({r['path'] for r in published_rows}) == 219, 'actual Git input inventory')
    actual = {r['path']: r for r in published_rows}
    for row in leaves:
        need(row['mode'] in ('100644', '100755') and selected(row['path']), 'Git mode/input selection')
        remote = actual[row['path']]
        need(remote['type'] == 'blob' and (remote['sha'], remote['size'], remote['mode']) ==
             (row['git_blob_sha1'], row['bytes'], row['mode']), 'R19 Git leaf differs: ' + row['path'])
    baseline_trees = tree_hashes(leaves)
    need(baseline_trees == prior['recomputed_trees'] and baseline_trees['src'] == PARENT_SRC
         and published['tree_response']['src']['sha'] == PARENT_SRC, 'published src tree reconstruction')
    checks['all_219_prior_sha_size_mode_git_blobs_match_actual_R19_commit'] = True
    candidate = reader.read(args.candidate_source, CANDIDATE_SHA)
    need(len(candidate) == 186514 and git_hash('blob', candidate) == CANDIDATE_BLOB, 'candidate Git blob')
    derived = []
    for row in leaves:
        entry = {key: row[key] for key in ('path', 'mode', 'bytes', 'sha256', 'git_blob_sha1')}
        changed = row['path'] == 'src/mcp/runtime/jobs.rs'
        if changed:
            need(row['sha256'] == BASELINE_SHA and row['git_blob_sha1'] == 'af9960abb23fcc2d8d44dde47badc6c99c3afd8e', 'prior jobs identity')
            entry.update(bytes=len(candidate), sha256=sha(candidate), git_blob_sha1=CANDIDATE_BLOB)
        entry['source_blob_association'] = 'current_frozen_candidate_bytes' if changed else 'inherited_exact_published_R19_qualified_input'
        derived.append(entry)
    expected_map = {r['path']: r['sha256'] for r in derived}; validate_map(expected_map, 219)
    candidate_trees = tree_hashes(derived)
    need(candidate_trees['src'] == CANDIDATE_SRC and candidate_trees['examples'] == baseline_trees['examples'], 'candidate selected Git trees')
    need([p for p in expected_map if expected_map[p] != prior_map[p]] == ['src/mcp/runtime/jobs.rs'], 'candidate source change set')
    checks['candidate_git_blob_and_trees_recomputed_only_jobs_changed'] = True
    cold = reader.doc(args.cold_audit, COLD_AUDIT_SHA)
    cold_manifest = reader.doc(args.cold_manifest_binding, COLD_MANIFEST_SHA)
    semantic = reader.doc(args.semantic_report, SEMANTIC_SHA)
    need(cold['passed'] is cold_manifest['passed'] is semantic['passed'] is True
         and all(v is True for v in cold['checks'].values()) and all(v is True for v in cold_manifest['checks'].values())
         and cold['counts']['fresh_processes'] == 352 and cold['source_sha256']['candidate'] == CANDIDATE_SHA
         and cold_manifest['inputs']['audit_receipt']['sha256'] == COLD_AUDIT_SHA
         and cold['source_report_bindings']['semantics.json']['sha256'] == SEMANTIC_SHA
         and semantic['candidate_source_sha256'] == CANDIDATE_SHA, 'complete original cold evidence binding')
    checks['full_352_process_cold_audit_and_840_member_manifest_bound'] = True
    report_path, acceptance_path, control_path = (root / p for p in
        ('qualification-01/report.json', 'independent-acceptance-01.json', 'qualification-control-01/report.json'))
    report = reader.doc(report_path, args.expected_qualification_report_sha256)
    acceptance = reader.doc(acceptance_path, args.expected_acceptance_sha256)
    control = reader.doc(control_path, args.expected_control_sha256)
    docs = {name: reader.doc(root / name) for name in
            ('preparation.json', 'source-freeze-01.json', 'source-middle-01.json', 'source-after-01.json',
             'qualification-launch-01.json', 'qualification-exit-01.json', 'qualification-01/source-map.json')}
    prep, freeze, middle, after, launch, outcome, source_map = (docs[name] for name in
        ('preparation.json', 'source-freeze-01.json', 'source-middle-01.json', 'source-after-01.json',
         'qualification-launch-01.json', 'qualification-exit-01.json', 'qualification-01/source-map.json'))
    need(report['qualified'] is True and acceptance['accepted'] is True and control['passed'] is True
         and control['current_stage'] == 'completed' and acceptance['checks'] and all(v is True for v in acceptance['checks'].values()),
         'actual qualification/independent acceptance/control not passed')
    need(acceptance['schema'] == 'hepta-x230-independent-acceptance/v2' and control['schema'] == 'hepta-x230-qualification-control/v1'
         and acceptance['attempt'] == control['attempt'] == 1, 'qualification receipt schemas')
    need(control['qualification_report'] == {'path': str(REMOTE / 'qualification-01/report.json'),
         'size': len(reader.read(report_path)), 'sha256': sha(reader.read(report_path))}
         and control['independent_acceptance'] == {'path': str(REMOTE / 'independent-acceptance-01.json'),
         'size': len(reader.read(acceptance_path)), 'sha256': sha(reader.read(acceptance_path))}, 'control/report hash links')
    need(acceptance['qualified_report_sha256'] == outcome['report_sha256'] == sha(reader.read(report_path)), 'qualification report hash links')
    checks['actual_passed_qualification_acceptance_control_hashes_bound'] = True
    need(freeze['schema'] == 'hepta-x230-source-freeze/v2' and middle['schema'] == 'hepta-x230-source-middle/v1'
         and after['schema'] == 'hepta-x230-source-after/v1' and launch['schema'] == 'hepta-x230-qualification-launch/v2'
         and outcome['schema'] == 'hepta-x230-qualification-exit/v2', 'freeze/middle/after/launch/exit schema')
    need(freeze['source'] == middle['source'] == after['source'] == report['source'] == str(REMOTE / 'source')
         and freeze['baseline_source'] == str(BASELINE_REMOTE) and freeze['expected_jobs_sha256'] == CANDIDATE_SHA, 'source paths')
    maps = [freeze['source_inputs_before'], middle['source_inputs'], after['source_inputs'], source_map,
            report['source_input'], report['source_tested'], report['source_after']]
    for mapping in maps:
        validate_map(mapping, 219); need(mapping == expected_map, 'qualified 219 map differs from Git derivation')
    full = freeze['source_full_before']; validate_map(full, 281, full=True)
    need(full == middle['source_full'] == after['source_full'] and
         {p: r['sha256'] for p, r in full.items() if selected(p)} == expected_map, '281 source snapshots differ')
    for row in derived:
        need(full[row['path']] == {'size': row['bytes'], 'sha256': row['sha256']}, 'qualified input byte size differs')
    need(prep['schema'] == 'hepta-r20-source-preparation/v1' and prep['passed'] is True and prep['source_file_count'] == 281
         and prep['original_source_unchanged'] is True and prep['baseline_commit'] == PARENT_COMMIT
         and prep['baseline_freeze_sha256'] == BASELINE_FREEZE_SHA, 'baseline source preparation')
    need(len(prep['files']) == 281 and len({r['path'] for r in prep['files']}) == 281, 'preparation source count')
    baseline_full = {r['path']: {'size': r['size'], 'sha256': r['sha256']} for r in prep['files']}
    validate_map(baseline_full, 281, full=True)
    need(set(baseline_full) == set(full) and {p: r['sha256'] for p, r in baseline_full.items() if selected(p)} == prior_map
         and [p for p in sorted(full) if full[p] != baseline_full[p]] == ['src/mcp/runtime/jobs.rs'], '281 full-tree change set')
    need(freeze['preparation_sha256'] == sha(reader.read(root / 'preparation.json'))
         and acceptance['source_input_count'] == 219 and acceptance['source_full_count'] == 281
         and acceptance['changed_paths'] == ['src/mcp/runtime/jobs.rs'], 'source/preparation count receipts')
    checks['all_seven_219_maps_equal_qualified_source_and_Git_inputs'] = True
    checks['all_three_281_snapshots_equal_and_only_jobs_differs_from_R19'] = True
    for key, filename in [('source_freeze_sha256', 'source-freeze-01.json'), ('source_middle_sha256', 'source-middle-01.json'), ('source_after_sha256', 'source-after-01.json')]:
        need(acceptance[key] == sha(reader.read(root / filename)), 'acceptance source snapshot hash')
    need(launch['source_freeze_sha256'] == sha(reader.read(root / 'source-freeze-01.json'))
         and outcome['source_middle_sha256'] == sha(reader.read(root / 'source-middle-01.json'))
         and outcome['source_after_sha256'] == sha(reader.read(root / 'source-after-01.json')), 'source snapshot hash chain')
    need(middle['observed_during_qualifier'] is True and middle['baseline_full_unchanged'] is after['baseline_full_unchanged'] is True
         and middle['qualifier_pid'] == launch['qualifier_pid'] == outcome['qualifier_pid']
         and middle['qualifier_start_ticks'] == launch['qualifier_start_ticks'] == outcome['qualifier_start_ticks'], 'live source midpoint and process binding')
    need(outcome['success'] is True and outcome['returncode'] == outcome['qualifier_returncode'] == 0
         and outcome['qualifier_reaped'] is outcome['qualifier_proc_absent'] is outcome['qualifier_process_group_absent'] is True
         and outcome['source_full_before_after_equal'] is outcome['source_full_before_middle_after_equal'] is outcome['source_inputs_before_after_equal'] is True
         and outcome['automatic_retries'] == 0, 'qualifier successful exit/stability')
    need(freeze['attempt'] == launch['attempt'] == outcome['attempt'] == 1 and
         launch['target_asserted_nonexistent'] is launch['target_created_empty'] is launch['output_asserted_nonexistent'] is True
         and launch['automatic_retries'] == 0 and launch['environment_policy'] == 'explicit-allowlist/v2-no-wrapper-keys'
         and 'RUSTC_WORKSPACE_WRAPPER' not in launch['environment'] and 'RUSTC_WRAPPER' not in launch['environment'], 'fresh qualification environment')
    need(report['jobs'] == 2 and report['automatic_test_retries'] == 0 and report['service_changes'] is False
         and [s['name'] for s in report['stages']] == STAGES and all(type(s['returncode']) is int and s['returncode'] == 0 for s in report['stages']),
         'eight qualification stages not successful')
    need([r['name'] for r in control['stages']] == ['fresh-qualification', 'independent-verification']
         and all(r['returncode'] == 0 and r['waited_and_reaped'] is True and r['timed_out'] is False for r in control['stages']), 'wrapper stage completion')
    checks['eight_stages_fresh_target_live_snapshot_and_successful_exit_bound'] = True
    manifest_path = root / 'tools/qualification-tools-manifest-01.json'
    tools = reader.doc(manifest_path, TOOLS_SHA)
    need(tools['schema'] == 'hepta-x230-qualification-tools/v1' and set(tools['files']) == {'qualify_candidate_01.py', 'verify_qualification_01.py'}, 'tools manifest')
    for name, identity in tools['files'].items():
        raw = reader.read(root / 'tools' / name, identity['sha256']); need(len(raw) == identity['size'], 'qualification tool size')
    tool_binding = {'path': str(REMOTE / 'tools/qualification-tools-manifest-01.json'), 'size': len(reader.read(manifest_path)),
                    'sha256': TOOLS_SHA, 'files': tools['files']}
    need(freeze['tools_manifest'] == launch['tools_manifest'] == acceptance['tools_manifest'] == tool_binding, 'qualification tool binding')
    semantic_binding = {'path': str(REMOTE / 'coldprocess-probe-01/semantics.json'), 'size': len(reader.read(args.semantic_report)),
                        'sha256': SEMANTIC_SHA, 'schema': semantic['schema'], 'candidate_source_sha256': CANDIDATE_SHA,
                        'baseline_source_sha256': BASELINE_SHA, 'probe_tool_sha256': semantic['probe_tool_sha256'], 'passed': True, 'checks': semantic['checks']}
    need(freeze['semantic'] == launch['semantic'] == acceptance['semantic'] == semantic_binding, 'cold semantics/qualification binding')
    need(freeze['cargo_configurations'] == launch['cargo_configurations'] == middle['cargo_configurations'] == after['cargo_configurations'], 'Cargo configuration fingerprints differ')
    checks['frozen_tools_cold_semantics_and_Cargo_configuration_bindings_equal'] = True
    expected_binaries = {'hepta-runtime', 'hepta-runtime-jobctl', 'native_process_driver'}
    need(set(report['binaries']) == set(acceptance['binaries']) == set(control['binaries']) == expected_binaries, 'three release binaries')
    binaries = {}
    for name in sorted(expected_binaries):
        a, r = acceptance['binaries'][name], report['binaries'][name]
        path = str(REMOTE / 'qualification-01' / name)
        need(a == control['binaries'][name] and a['path'] == r['path'] == path and a['sha256'] == r['sha256']
             and re.fullmatch('[0-9a-f]{64}', a['sha256']) and type(a['size']) is int and a['size'] > 0, 'release binary receipt differs')
        binaries[name] = {**a, 'original_build_path': str(REMOTE / 'target-fresh-01/release' /
                         ('examples/native_process_driver' if name == 'native_process_driver' else name)),
                         'local_ELF_bytes_read': False}
    need(binaries['hepta-runtime-jobctl']['sha256'] == JOBCTL_SHA and acceptance['checks']['jobctl_release_identical_to_baseline'] is True,
         'strict baseline jobctl release identity')
    checks['three_actual_release_paths_hashes_sizes_and_strict_jobctl_identity_bound'] = True
    need(reader.stable(), 'source proof input changed while reading')
    checks['all_local_evidence_stable'] = True
    result.update(passed=True, verified=True, repository=REPOSITORY, baseline_commit=PARENT_COMMIT,
        baseline_root_tree=PARENT_TREE, baseline_src_tree=PARENT_SRC, baseline_trees_recomputed=baseline_trees,
        candidate_trees_recomputed=candidate_trees, candidate_jobs_git_blob=CANDIDATE_BLOB,
        source_input_count=219, source_full_count=281, changed_paths=['src/mcp/runtime/jobs.rs'], unchanged_input_count=218,
        qualification_report_sha256=sha(reader.read(report_path)), independent_acceptance_sha256=sha(reader.read(acceptance_path)),
        source_map_sha256=sha(reader.read(root / 'qualification-01/source-map.json')),
        qualified_inputs=derived, binaries=binaries, independent_acceptance_checks=acceptance['checks'],
        inputs={str(p): reader.binding(p) for p in sorted(reader.seen)},
        final_publication_commit=None, final_git_commit_verified=False, adoption_assessed=False,
        limitations=['The 218 unchanged SHA256-to-Git-blob associations come from the exact published R19 source proof and actual Git tree entries; these leaf bytes were not freshly fetched here.',
                     'The changed jobs.rs bytes are locally rehashed. This proof binds the actual passed remote qualification and its before/during/after source receipts; it does not rerun Rust tests.',
                     'Release ELF bytes remain on X230. Paths, sizes and hashes are bound to the original qualification and independent acceptance, not a local binary read.',
                     'Only selected source subtrees are derived. Final publication root, commit and adoption remain separate decisions.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qualification-root', 'baseline-source-proof', 'published-commit-binding', 'candidate-source',
                 'cold-audit', 'cold-manifest-binding', 'semantic-report', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-qualification-report-sha256', 'expected-acceptance-sha256', 'expected-control-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    need(not os.path.lexists(args.output), 'output must be fresh')
    result = {'schema': 'hepta-r20-qualified-source-binding/v1', 'passed': False, 'verified': False, 'checks': {},
              'tool_sha256': sha(Path(__file__).read_bytes()), 'workloads_started': False, 'remote_calls': 0}
    try:
        bind(args, result)
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()}
    result['created_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    encoded = (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()
    with args.output.open('xb') as stream:
        stream.write(encoded)
    print(json.dumps({'passed': result['passed'], 'output': str(args.output.absolute()), 'sha256': sha(encoded),
                      'checks': len(result['checks']), 'error': result.get('error')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
