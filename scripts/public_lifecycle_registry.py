# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""One selected source per image in the serial public lifecycle graph."""
from pathlib import Path
import hashlib
import json

COMPILER = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
COMPILER_IMAGE = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
GRAPH_SHA = 'a05a7e624ac1b363388cbad1e09e023d88d7131e74c2b4bbaefa3b78ed0cb242'
TESTS = ('test_public_lifecycle_bridge.py', 'test_public_lifecycle_normal.py')
sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'not a regular input: ' + str(path))
    return path.read_bytes()


def graph(root):
    root = Path(root)
    raw = regular(root / 'native/public_lifecycle_graph.json')
    require(sha(raw) == GRAPH_SHA, 'public lifecycle graph changed')
    value = json.loads(raw)
    require(value['schema'] == 'hepta.public-lifecycle.canonical-graph.v1'
            and value['compiler_commit'] == COMPILER and value['compiler_sha256'] == COMPILER_IMAGE,
            'public lifecycle compiler or schema changed')
    order = value['image_order']
    require(len(order) == len(set(order)) == len(value['modules']) == 71,
            'public lifecycle image domain changed')
    require(set(value['modules']) == set(order) and len(value['roles']) == 86
            and set(value['roles'].values()) == set(order), 'public role aliases changed')
    for role, row in value['modules'].items():
        path = Path(row['source'])
        require(not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'native',
                'unconfined module source')
        require(sha(regular(root / path)) == row['source_sha256'], 'selected HIA source changed: ' + role)
    for key in ('adapter', 'metadata'):
        require(sha(regular(root / value[key + '_source'])) == value[key + '_source_sha256'],
                'selected native source changed: ' + key)
    require(sha(regular(root / value['packer']['source'])) == value['packer']['source_sha256'],
            'selected packer source changed')
    require(value['scope']['production_activated'] is False and value['scope']['whole_runtime_replaced'] is False,
            'unqualified public activation')
    return value


def source_pins(root):
    root = Path(root)
    value = graph(root)
    reference = json.loads(regular(root / 'tests/hia_native/public_lifecycle/reference.json'))
    names = {row['source'] for row in value['modules'].values()}
    names.update((value['packer']['source'], value['adapter_source'], value['metadata_source'],
                  'native/public_lifecycle_graph.json', 'native/public_lifecycle_abi.md',
                  'scripts/hia_native_build.py', 'scripts/hia_native_loader.py',
                  'scripts/hia_native_public_registry_qualification.py',
                  'scripts/public_registry_registry.py', 'Cargo.lock'))
    names.update(row['source'] for row in reference['files'].values())
    names.update(row['source'] for row in reference['original_blocks'])
    for pattern in ('public_lifecycle*.py', 'build_public_lifecycle.py',
                    'hia_native_public_lifecycle*.py'):
        names.update(p.relative_to(root).as_posix() for p in (root / 'scripts').glob(pattern))
    names.update(p.relative_to(root).as_posix() for p in
                 (root / 'tests/hia_native/public_lifecycle').rglob('*') if p.is_file())
    names.update('tests/hia_native/' + name for name in (*TESTS, 'compare_public_lifecycle_original.py'))
    return {name: sha(regular(root / name)) for name in sorted(names)}
