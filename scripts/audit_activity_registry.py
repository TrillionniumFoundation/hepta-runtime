# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Closed source graph for activity, delayed publication and scripted hot cache."""
from pathlib import Path
import json
from result_storage_registry import COMPILER, COMPILER_IMAGE, encoded, manifest_image, regular, require, sha

PROFILE = 'native/audit_activity_profile.json'
PROFILE_SHA = 'ecea8836741cdc590aa8496bdd97dbda9dc628d0ea3d53ec9ca1cfc11dba93b2'
HARNESS = 'tests/hia_native/activity_harness'
REFERENCES = 'tests/hia_native/activity_reference'

def profile(root):
    raw = regular(Path(root) / PROFILE)
    require(sha(raw) == PROFILE_SHA, 'fixed activity profile changed')
    value = json.loads(raw)
    require(value['schema'] == 'hepta.audit-activity.fixed-profile.v1'
        and value['compiler_commit'] == COMPILER and value['compiler_sha256'] == COMPILER_IMAGE
        and len(value['owners']) == 3 and len(value['modules']) == 4 and len(value['graphs']) == 2,
        'activity compilation domain differs')
    return value

def build_sources(root):
    root = Path(root);fixed = profile(root)
    names = {PROFILE, 'scripts/audit_activity_registry.py', 'scripts/build_audit_activity.py',
        'scripts/audit_activity_pack_child.py', 'scripts/hia_native_build.py',
        'scripts/hia_native_loader.py', 'scripts/generate_hia_transport.py',
        'scripts/result_storage_registry.py'}
    names.update(fixed['original_sources'])
    names.update(row['source'] for row in fixed['modules'].values())
    names.update(row['layout'] for row in fixed['graphs'].values())
    for graph in fixed['graphs'].values():
        for name, expected in json.loads(regular(root / graph['layout']))['prefix_sources'].items():
            raw = regular(root / name)
            require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
                'fixed activity thread boundary source changed')
            names.add(name)
    for stem in fixed['owners'].values():
        path = 'native/' + stem + '_composition.json';names.add(path)
        names.add('native/' + stem + '_abi.md')
        names.update(row['source'] for row in json.loads(regular(root / path))['imports'])
    for name, expected in fixed['original_sources'].items():
        raw = regular(root / name)
        require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
            'unchanged original activity source differs')
    return {name: sha(regular(root / name)) for name in sorted(names)}

def graph_order(graph, layout):
    require(graph['direct_append'] is True and set(graph['members']) == {'activity'},
        'fixed activity carrier member set differs')
    return [graph['members']['activity']]
