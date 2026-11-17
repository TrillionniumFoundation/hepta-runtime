# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Materialize one original public reference from selected, exact source files."""
from pathlib import Path, PurePosixPath
import json
import tomllib

from public_lifecycle_registry import encoded, regular, require, sha


def inputs(root):
    root = Path(root)
    index = json.loads(regular(root / 'tests/hia_native/public_lifecycle/reference.json'))
    require(index['schema'] == 'hepta.public-lifecycle.original-project.v2'
            and index['bin'] == 'hia-public-async-original'
            and len(index['files']) == 42 and len(index['original_blocks']) == 315
            and index['locked_packages'] == 140
            and index['all_actual_original_functions_unchanged'] is True
            and all(index[k] is False for k in ('async_cancellation_qualified',
                                              'production_activated', 'whole_runtime_replaced')),
            'original public reference domain changed')
    files = {}
    for name, row in index['files'].items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name,
                'unconfined reference target')
        source = Path(row['source'])
        require(not source.is_absolute() and '..' not in source.parts, 'unconfined reference input')
        raw = regular(root / source)
        require((len(raw), sha(raw)) == (row['bytes'], row['sha256']), 'reference source changed: ' + name)
        files[name] = raw
    for row in index['original_blocks']:
        source = regular(root / row['source'])
        require(sha(source) == row['source_sha256'], 'whole original source changed')
        fragment = source[row['offset']:row['offset'] + row['bytes']]
        target = files[row['target']]
        require(len(fragment) == row['bytes'] and sha(fragment) == row['sha256']
                and fragment == target[row['target_offset']:row['target_offset'] + row['bytes']],
                'complete original function block differs')
    lock = tomllib.loads(files['Cargo.lock'].decode())
    require(sum('checksum' in p for p in lock['package']) == 140, 'locked package domain changed')
    return index, files


def prepare(root, project):
    index, files = inputs(root)
    project = Path(project)
    project.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, raw in files.items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    receipt = dict(schema='hepta.public-lifecycle.original-project.v2',
                   index_sha256=sha(regular(Path(root) / 'tests/hia_native/public_lifecycle/reference.json')),
                   files={k:dict(bytes=len(v), sha256=sha(v)) for k,v in files.items()},
                   original_blocks=315, locked_packages=140,
                   actual_outer_call_tool_included=True, original_index_present_branch_qualified=False)
    (project / 'reference-inputs.json').write_bytes(encoded(receipt))
    check(root, project)
    return receipt


def check(root, project):
    _, expected = inputs(root)
    project = Path(project)
    names = set()
    for path in project.rglob('*'):
        require(not path.is_symlink(), 'reference source symlink refused')
        if path.is_dir():
            continue
        require(path.is_file(), 'reference source special file refused')
        names.add(path.relative_to(project).as_posix())
    require(names == set(expected) | {'reference-inputs.json'}, 'reference project file domain differs')
    for name, raw in expected.items():
        require(regular(project / name) == raw, 'materialized original changed: ' + name)
    receipt = json.loads(regular(project / 'reference-inputs.json'))
    require(receipt == dict(schema='hepta.public-lifecycle.original-project.v2',
        index_sha256=sha(regular(Path(root) / 'tests/hia_native/public_lifecycle/reference.json')),
        files={k:dict(bytes=len(v), sha256=sha(v)) for k,v in expected.items()},
        original_blocks=315, locked_packages=140, actual_outer_call_tool_included=True,
        original_index_present_branch_qualified=False), 'original project receipt differs')
    return receipt
