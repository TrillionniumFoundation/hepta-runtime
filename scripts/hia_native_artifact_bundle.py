# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Transport a completed aggregate without uploading its immutable inputs twice.

The native artifact and every original shard remain independently retained by
the same workflow invocation. This transport adds only aggregate/control bytes
and a complete, externally hashed reconstruction index. It does not execute or
replace any semantic qualification. Restoration requires every original source
artifact and checks every byte before installing its recorded ordinary mode.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hia_native_pipeline as p
import hia_native_rust_pipeline as r

MANIFEST = 'aggregate-bundle.json'
SCHEMA = 'hepta.runtime.aggregate-artifact-bundle.v1'
COLLECTION_SCHEMA = 'hepta.runtime.original-collection-bundle.v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    return p.file_identity(path)


def valid_identity(row):
    require(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
        and type(row['bytes']) is int and row['bytes'] >= 0
        and type(row['sha256']) is str and p.SHA256.fullmatch(row['sha256'])
        and type(row['mode']) is int and 0 <= row['mode'] <= 0o777,
        'bundle file identity differs')


def source_name(head, invocation, group):
    require(type(head) is str and re.fullmatch(r'[0-9a-f]{40}', head)
        and type(invocation) is str and re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*', invocation),
        'bundle must name the exact workflow head, run and attempt')
    return (f'hia-native-complete-{head}-{invocation}' if group == 'native'
        else f'hia-original-shard-{head}-{invocation}-{group}')


def source_maps(output, head, invocation, native_sha, shards):
    """Bind origins to the exact seals supplied by successful workflow jobs."""
    require(set(shards) == set(r.groups()) and len(shards) == len(r.groups()),
        'bundle requires every declared original shard')
    sources, origins = {}, {}

    def add(name, row, origin, member):
        p.relative_path(name)
        p.relative_path(member)
        valid_identity(row)
        require(name not in origins, 'bundle sources overlap or replace evidence')
        origins[name] = {'identity': row, 'origin': origin, 'member': member}

    def pin(group, path, expected):
        require(type(expected) is str and p.SHA256.fullmatch(expected)
            and p.digest(path) == expected, 'bundle source seal differs from workflow output')
        sources[group] = {'artifact': source_name(head, invocation, group),
            'seal_sha256': expected}
        return p.read_json(path)

    native_path = p.owned(output, r.NATIVE_SEAL)
    native = pin('native', native_path, native_sha)
    require(set(native) == {'schema', 'context', 'files', 'directories', 'groups'}
        and native['schema'] == 'hepta.runtime.original-native.v1'
        and native['context']['invocation'] == invocation
        and native['context']['checkout_head'] == head
        and native['groups'] == {k: list(v) for k, v in r.groups().items()},
        'bundle native seal belongs to another source or invocation')
    require(r.NATIVE_REPORT in native['files'] and 'result.json' not in native['files']
        and r.NATIVE_SEAL not in native['files'], 'bundle native inventory is malformed')
    for name, row in native['files'].items():
        add(name, row, 'native', name)
    add(r.NATIVE_SEAL, identity(native_path), 'native', r.NATIVE_SEAL)
    baseline = p.read_json(p.owned(output, r.NATIVE_REPORT))
    for group in r.groups():
        folder = 'original-qualification-shards/' + group + '/'
        seal_path = p.owned(output, folder + r.SHARD_SEAL)
        seal = pin(group, seal_path, shards[group])
        require(set(seal) == {'schema', 'binding', 'files', 'directories', 'report_sha256'}
            and seal['schema'] == 'hepta.runtime.original-shard.v1'
            and seal['binding'] == r.shard_binding(group, native_sha, invocation),
            'bundle original shard belongs to another invocation or recipe group')
        report_path = p.owned(output, folder + r.SHARD_REPORT)
        require(p.digest(report_path) == seal['report_sha256'], 'bundle original report differs')
        for name, row in seal['files'].items():
            require(name not in {'result.json', r.NATIVE_SEAL}
                and not name.startswith('original-qualification-shards/'),
                'bundle original source replaces aggregate or seal custody')
            add(name, row, group, 'data/' + name)
        add(folder + r.SHARD_SEAL, identity(seal_path), group, r.SHARD_SEAL)
        add(folder + r.SHARD_REPORT, identity(report_path), group, r.SHARD_REPORT)
    return sources, origins, baseline


def export(output, destination, head, invocation, native_sha, shards, *, collection=False):
    require(not destination.exists() and not destination.is_symlink(), 'bundle destination is create-only')
    require(output != destination and output not in destination.parents,
        'bundle payload must be outside the immutable evidence tree')
    sources, origins, baseline = source_maps(output, head, invocation, native_sha, shards)
    report = p.read_json(p.owned(output, 'result.json'))
    expected_status = r.COLLECTED_STATUS if collection else 'PASS'
    expected_phase = r.COLLECTED_PHASE if collection else 'complete'
    require(report.get('status') == expected_status and report.get('phase') == expected_phase
        and report.get('native_components_status') == 'PASS'
        and report.get('rust_comparison_status') == ('PARTIAL' if collection else 'PASS')
        and report.get('source_sha256') == baseline.get('source_sha256')
        and set(report.get('original_rust_comparisons', {})) == {key for keys in r.groups().values() for key in keys}
        and all(report.get(name) is False for name in
            ('production_activated', 'whole_runtime_replaced', 'old_stack_removal_qualified')),
        'bundle requires its exact collection stage without expanding migration claims')
    require(report.get('original_qualification_pipeline') == {
        'schema': 'hepta.runtime.original-pipeline.v1', 'invocation': invocation,
        'native_sha256': native_sha, 'shards': shards,
        'recipes': [key for keys in r.groups().values() for key in keys]},
        'bundle aggregate lacks the complete workflow-produced source bindings')
    if collection:
        require(not any(row.get('name') in r.CONTROLS for row in report.get('checks', []))
            and not (output / 'regex-evidence-controls.json').exists(),
            'pending collection cannot import completed controls or claim qualification')
    else:
        require([row.get('name') for row in report.get('checks', [])[-len(r.CONTROLS):]] == list(r.CONTROLS),
            'bundle aggregate omitted its quiescent evidence controls')
        for row in report['checks'][-len(r.CONTROLS):]:
            r.validate_process(output, row)
        # This is a transport byte check. The preceding workflow steps performed
        # every semantic admission and all fourteen regex mutation controls.
        regex = p.read_json(p.owned(output, 'regex-evidence-controls.json'))
        require(regex.get('schema') == 'hepta.runtime.regex-evidence-controls.v1'
            and regex.get('status') == 'PASS' and regex.get('negative_control_count') == 14
            and len(regex.get('negative_controls', [])) == 14
            and regex.get('actual_baseline_admissions') == 6
            and regex.get('source_and_artifacts_restored') is True
            and regex.get('actual_process_report_sha256') == p.digest(output / 'result.json'),
            'bundle requires completed regex evidence controls')
    files, directories = p.inventory(output)
    require(set(origins) <= set(files), 'bundle is missing retained source evidence')
    for name, origin in origins.items():
        require(files[name] == origin['identity'], 'bundle source evidence changed: ' + name)
    destination.mkdir(mode=0o700, parents=True)
    data = destination / 'data'
    data.mkdir(mode=0o700)
    rows, saved = {}, 0
    for name, row in files.items():
        if name in origins:
            origin = origins[name]
            rows[name] = {**row, 'origin': origin['origin'], 'member': origin['member']}
            saved += row['bytes']
        else:
            target = data / p.relative_path(name)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(p.owned(output, name), target)
            target.chmod(row['mode'])
            require(identity(target) == row, 'bundle payload changed while copying')
            rows[name] = {**row, 'origin': 'aggregate', 'member': 'data/' + name}
    value = {'schema': COLLECTION_SCHEMA if collection else SCHEMA, 'head': head, 'invocation': invocation,
        'sources': sources, 'files': rows,
        'root_mode': stat.S_IMODE(output.lstat().st_mode),
        'directories': {name: stat.S_IMODE((output / name).lstat().st_mode) for name in directories},
        'semantic_checks_executed_by_transport': 0,
        'full_evidence_bytes': sum(row['bytes'] for row in files.values()),
        'bytes_referenced_in_retained_artifacts': saved}
    validate_manifest(value)
    (destination / MANIFEST).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    # Inspect all copied bytes once more; no cache or evidence member is omitted.
    actual, _ = p.inventory(data)
    expected = {name: {key: row[key] for key in ('bytes', 'sha256', 'mode')}
        for name, row in rows.items() if row['origin'] == 'aggregate'}
    require(actual == expected, 'bundle aggregate payload is incomplete')
    return {'status': 'COLLECTION_BUNDLE_EXPORTED' if collection else 'BUNDLE_EXPORTED',
        'sha256': p.digest(destination / MANIFEST),
        'complete_files': len(rows), 'payload_files': len(expected),
        'full_evidence_bytes': value['full_evidence_bytes'],
        'bytes_referenced_in_retained_artifacts': saved, 'semantic_checks_executed': 0}


def validate_manifest(value):
    require(type(value) is dict and set(value) == {'schema', 'head', 'invocation', 'sources', 'files',
        'directories', 'root_mode', 'semantic_checks_executed_by_transport', 'full_evidence_bytes',
        'bytes_referenced_in_retained_artifacts'} and value['schema'] in (SCHEMA, COLLECTION_SCHEMA)
        and type(value['semantic_checks_executed_by_transport']) is int
        and value['semantic_checks_executed_by_transport'] == 0, 'unknown bundle schema or claims')
    require(type(value['root_mode']) is int and 0 <= value['root_mode'] <= 0o777,
        'bundle root mode differs')
    require(type(value['sources']) is dict and set(value['sources']) == {'native', *r.groups()},
        'bundle source artifact registry differs')
    for group, row in value['sources'].items():
        require(type(row) is dict and set(row) == {'artifact', 'seal_sha256'}
            and row['artifact'] == source_name(value['head'], value['invocation'], group)
            and type(row['seal_sha256']) is str and p.SHA256.fullmatch(row['seal_sha256']),
            'bundle source artifact identity differs')
    require(type(value['files']) is dict and value['files'] and type(value['directories']) is dict,
        'bundle complete inventory is absent')
    for name, row in value['files'].items():
        p.relative_path(name)
        require(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode', 'origin', 'member'},
            'bundle file projection differs')
        valid_identity({key: row[key] for key in ('bytes', 'sha256', 'mode')})
        require(row['origin'] in {'aggregate', *value['sources']}, 'bundle file has unknown origin')
        p.relative_path(row['member'])
        require(row['origin'] != 'aggregate' or row['member'] == 'data/' + name,
            'bundle aggregate path differs')
    for name, mode in value['directories'].items():
        p.relative_path(name)
        require(type(mode) is int and 0 <= mode <= 0o777 and name not in value['files'],
            'bundle directory mode or kind differs')
    for name in (*value['files'], *value['directories']):
        parent = Path(name).parent
        while parent != Path('.'):
            require(parent.as_posix() in value['directories'], 'bundle omits a parent directory')
            parent = parent.parent
    full = sum(row['bytes'] for row in value['files'].values())
    saved = sum(row['bytes'] for row in value['files'].values() if row['origin'] != 'aggregate')
    require(type(value['full_evidence_bytes']) is int and value['full_evidence_bytes'] == full
        and type(value['bytes_referenced_in_retained_artifacts']) is int
        and value['bytes_referenced_in_retained_artifacts'] == saved, 'bundle byte totals differ')


def restore(bundle, sources, destination, expected, *, collection=False):
    require(type(expected) is str and p.SHA256.fullmatch(expected)
        and p.digest(p.owned(bundle, MANIFEST)) == expected, 'bundle differs from its workflow-produced SHA256')
    value = p.read_json(bundle / MANIFEST)
    validate_manifest(value)
    require(value['schema'] == (COLLECTION_SCHEMA if collection else SCHEMA),
        'bundle qualification stage differs; pending collection is not a completed aggregate')
    require(not destination.exists() and not destination.is_symlink(), 'restoration is create-only')
    require(set(path.name for path in bundle.iterdir()) == {MANIFEST, 'data'}, 'bundle has undeclared members')
    roots = {'aggregate': bundle}
    sealed_members = set()

    def member(name, group, source, pin):
        row = value['files'].get(name)
        require(row == {**pin, 'origin': group, 'member': source},
            'bundle omits or remaps a sealed source member: ' + name)
        require(name not in sealed_members, 'bundle sealed sources overlap')
        sealed_members.add(name)

    for group, row in value['sources'].items():
        root = sources / p.relative_path(row['artifact'])
        require(root.is_dir() and not root.is_symlink() and root.resolve() == root.absolute(),
            'bundle source artifact is missing or crosses a symlink')
        seal = r.NATIVE_SEAL if group == 'native' else r.SHARD_SEAL
        require(p.digest(p.owned(root, seal)) == row['seal_sha256'], 'bundle source artifact seal differs')
        roots[group] = root
        document = p.read_json(root / seal)
        if group == 'native':
            require(document.get('schema') == 'hepta.runtime.original-native.v1'
                and document.get('context', {}).get('invocation') == value['invocation']
                and document.get('context', {}).get('checkout_head') == value['head']
                and document.get('groups') == {k: list(v) for k, v in r.groups().items()},
                'bundle native source belongs to another invocation')
            prefix = ''
        else:
            require(document.get('schema') == 'hepta.runtime.original-shard.v1'
                and document.get('binding') == r.shard_binding(group,
                    value['sources']['native']['seal_sha256'], value['invocation']),
                'bundle original source belongs to another invocation')
            prefix = 'original-qualification-shards/' + group + '/'
        require(set(document['directories']) <= set(value['directories']),
            'bundle omits sealed source directories')
        for name, pin in document['files'].items():
            member(name, group, name if group == 'native' else 'data/' + name, pin)
        for leaf in ((r.NATIVE_SEAL,) if group == 'native' else (r.SHARD_SEAL, r.SHARD_REPORT)):
            name = prefix + leaf
            actual = identity(p.owned(root, leaf))
            declared = value['files'].get(name, {})
            # The artifact ZIP loses mode bits. The external aggregate digest
            # binds its recorded mode; the source seal still binds every byte.
            actual['mode'] = declared.get('mode')
            member(name, group, leaf, actual)
        if group != 'native':
            require(p.digest(p.owned(root, r.SHARD_REPORT)) == document['report_sha256'],
                'bundle original source report differs')
    require(sealed_members == {name for name, row in value['files'].items() if row['origin'] != 'aggregate'},
        'bundle references an unsealed source member')
    # Verify all requested bytes before creating the output. ZIP transport may
    # have lost mode bits; only the hashed complete index supplies restored modes.
    for name, row in value['files'].items():
        path = p.owned(roots[row['origin']], row['member'])
        require(path.stat().st_size == row['bytes'] and p.digest(path) == row['sha256'],
            'bundle source member bytes differ: ' + name)
    payload, _ = p.inventory(bundle / 'data')
    require(set(payload) == {name for name, row in value['files'].items() if row['origin'] == 'aggregate'},
        'bundle payload has missing or extra members')
    destination.mkdir(mode=0o700, parents=True)
    for name in sorted(value['directories'], key=lambda item: (item.count('/'), item)):
        (destination / name).mkdir(mode=0o700)
    for name, row in value['files'].items():
        target = destination / name
        shutil.copyfile(p.owned(roots[row['origin']], row['member']), target)
        target.chmod(row['mode'])
        require(identity(target) == {key: row[key] for key in ('bytes', 'sha256', 'mode')},
            'restored member changed while copying')
    for name in sorted(value['directories'], key=lambda item: (-item.count('/'), item)):
        (destination / name).chmod(value['directories'][name])
    destination.chmod(value['root_mode'])
    return {'status': 'COLLECTION_BUNDLE_RESTORED' if collection else 'BUNDLE_RESTORED',
        'files': len(value['files']),
        'full_evidence_bytes': value['full_evidence_bytes'], 'semantic_checks_executed': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('export', 'export-collection', 'restore'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--destination', required=True, type=Path)
    parser.add_argument('--head')
    parser.add_argument('--invocation')
    parser.add_argument('--native-sha256')
    parser.add_argument('--shard-sha256', action='append', default=[])
    parser.add_argument('--sources', type=Path)
    parser.add_argument('--expected-sha256')
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    if args.phase in ('export', 'export-collection'):
        shards = {}
        for item in args.shard_sha256:
            key, sep, digest = item.partition('=')
            require(sep == '=' and key not in shards, 'each original source SHA must occur once')
            shards[key] = digest
        result = export(args.output.absolute(), args.destination.absolute(), args.head,
            args.invocation, args.native_sha256, shards, collection=args.phase == 'export-collection')
    else:
        require(args.sources is not None, 'restore requires retained source artifacts')
        result = restore(args.output.absolute(), args.sources.absolute(),
            args.destination.absolute(), args.expected_sha256)
    if args.github_output and 'sha256' in result:
        with args.github_output.open('a') as stream:
            stream.write('sha256=' + result['sha256'] + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
