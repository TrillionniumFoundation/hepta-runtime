# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fixed real ArchiveStamp and three-method cache source graphs."""
from pathlib import Path
import json
from result_storage_registry import COMPILER, COMPILER_IMAGE, encoded, manifest_image, regular, require, sha

PROFILE = 'native/audit_stamp_profile.json'
PROFILE_SHA = '8922645d123b091c3bac4f653477fa8257578b8f578e623867a8bc37709b435a'
HARNESS = 'tests/hia_native/audit_stamp_harness'
REFERENCES = 'tests/hia_native/audit_stamp_reference'


def profile(root):
    raw = regular(Path(root) / PROFILE)
    require(sha(raw) == PROFILE_SHA, 'fixed Stamp profile changed')
    value = json.loads(raw)
    require(value['schema'] == 'hepta.audit-stamp.fixed-profile.v1'
        and value['compiler_commit'] == COMPILER and value['compiler_sha256'] == COMPILER_IMAGE
        and set(value['owners']) == {'stamp', 'cache_stamp'}
        and len(value['modules']) == 5 and set(value['graphs']) == {'stamp', 'cache_stamp'}
        and value['scripted_children'] is False and value['cold_snapshot_admitted'] is False,
        'Stamp compilation domain differs')
    return value


def build_sources(root):
    root = Path(root);fixed = profile(root)
    names = {PROFILE, 'scripts/audit_stamp_registry.py', 'scripts/build_audit_stamp_graphs.py',
        'scripts/audit_stamp_pack_child.py', 'scripts/hia_native_build.py',
        'scripts/hia_native_loader.py', 'scripts/generate_hia_transport.py',
        'scripts/result_storage_registry.py', 'scripts/build_result_storage.py'}
    names.update(fixed['original_sources'])
    names.update(row['source'] for row in fixed['modules'].values())
    names.update(row['layout'] for row in fixed['graphs'].values())
    for aliases in fixed['frozen_input_aliases'].values():
        for expected in aliases.values():
            raw = regular(root / expected['source'])
            require(sha(raw) == expected['projected_sha256'], 'frozen Stamp input changed')
            if not expected['portable_path_projection_only']:
                require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
                    'frozen Stamp input bytes changed')
            names.add(expected['source'])
    for graph in fixed['graphs'].values():
        raw = regular(root / graph['layout'])
        require(sha(raw) == graph['layout_sha256'], 'fixed Stamp graph layout changed')
        for name, expected in json.loads(raw)['prefix_sources'].items():
            raw = regular(root / name)
            require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
                'fixed Stamp syscall boundary changed')
            names.add(name)
    for stem in fixed['owners'].values():
        path = 'native/' + stem + '_composition.json';names.add(path)
        names.add('native/' + stem + '_abi.md')
        names.update(row['source'] for row in json.loads(regular(root / path))['imports'])
    for name, expected in fixed['original_sources'].items():
        raw = regular(root / name)
        require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
            'unchanged original Stamp source differs')
    return {name: sha(regular(root / name)) for name in sorted(names)}


def graph_order(graph, layout):
    order = layout['image_order']
    require(graph['direct_append'] is False and isinstance(order, list)
        and len(order) in {2, 3} and len(set(order)) == len(order)
        and set(order) == set(graph['members']) == set(layout['call_holes']),
        'fixed Stamp graph member set differs')
    return [graph['members'][name] for name in order]
