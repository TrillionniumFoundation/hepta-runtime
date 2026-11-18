# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Closed input graph for readiness and the independently qualified audit owners."""
from pathlib import Path
import json

from result_storage_registry import COMPILER, COMPILER_IMAGE, encoded, manifest_image, regular, require, sha

PROFILE = 'native/audit_readiness_profile.json'
PROFILE_SHA = '2f3107d6ba4e9d137e6eed1fe130d435f4d8df8931990e54f1c4dbe0c9087231'
HARNESS = 'tests/hia_native/audit_harness'
REFERENCES = 'tests/hia_native/audit_reference'


def profile(root):
    raw = regular(Path(root) / PROFILE)
    require(sha(raw) == PROFILE_SHA, 'fixed audit readiness profile changed')
    value = json.loads(raw)
    require(value['schema'] == 'hepta.audit-readiness.fixed-profile.v1'
        and value['compiler_commit'] == COMPILER and value['compiler_sha256'] == COMPILER_IMAGE
        and len(value['owners']) == 9 and len(value['modules']) == 22 and len(value['graphs']) == 7,
        'audit readiness compilation domain differs')
    return value


def build_sources(root):
    root = Path(root);fixed = profile(root)
    names = {PROFILE, 'scripts/audit_readiness_registry.py', 'scripts/build_audit_readiness.py',
        'scripts/audit_readiness_pack_child.py', 'scripts/hia_native_build.py',
        'scripts/hia_native_loader.py', 'scripts/generate_hia_transport.py',
        'scripts/result_storage_registry.py', 'scripts/build_result_storage.py',
        'scripts/result_storage_words.py', 'native/filter_packer.hepta',
        'native/serde_json.hepta', 'native/result_storage_value.hepta',
        'native/result_storage_value_composition.json', 'native/request_retention.hepta',
        'native/request_retention_composition.json'}
    names.update(fixed['original_sources'])
    names.update(row['source'] for row in fixed['modules'].values())
    names.update(row['layout'] for row in fixed['graphs'].values())
    for row in fixed['graphs'].values():
        layout = json.loads(regular(root / row['layout']))
        for name, expected in layout.get('prefix_sources', {}).items():
            raw = regular(root / name)
            require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
                'fixed thread boundary source changed')
            names.add(name)
    for stem in set(fixed['owners'].values()) | {'request_store_acquire'}:
        name = 'native/' + stem + '_composition.json';names.add(name)
        names.update(row['source'] for row in json.loads(regular(root / name))['imports'])
        document = 'native/' + stem + '_abi.md'
        if (root / document).exists():
            names.add(document)
    for name, expected in fixed['original_sources'].items():
        raw = regular(root / name)
        require((len(raw), sha(raw)) == (expected['bytes'], expected['sha256']),
            'unchanged original source differs')
    return {name: sha(regular(root / name)) for name in sorted(names)}


def graph_order(graph, layout):
    logical = ['lock'] if graph['direct_append'] else layout['image_order']
    require(set(logical) == set(graph['members']), 'fixed graph member set differs')
    return [graph['members'][name] for name in logical]
