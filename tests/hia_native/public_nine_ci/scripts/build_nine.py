#!/usr/bin/env python3
"""Compile and pack the public nine-tool candidate; no Rust is invoked.

Default is a fresh79 build. Optional development reuse is explicit and every
member is checked against current source, profile, compiler and image bytes.
It is never described as a fresh or independent cold qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time

sys.dont_write_bytecode = True
SHA = lambda data: hashlib.sha256(data).hexdigest()
B3 = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('hepta', 'source', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--bootstrap', type=Path)
    parser.add_argument('--reuse-manifest', type=Path)
    parser.add_argument('--private-fixture', action='store_true')
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True)
    build = output / 'build'
    if args.bootstrap is not None:
        bootstrap = args.bootstrap.resolve(strict=True)
        receipt = json.loads((bootstrap / 'bootstrap.json').read_bytes())
        assert receipt['generation_sha256'] == B3
        for label in ('B1', 'B2', 'B3'):
            assert SHA((bootstrap / (label + '.image.bin')).read_bytes()) == B3
        build.mkdir()
        shutil.copytree(bootstrap, build / 'bootstrap')
    sys.path.insert(0, str(source / 'scripts'))
    from public_nine_build import MEMBERS, build_runtime_mcp
    reuse = {}
    if args.reuse_manifest is not None:
        path = args.reuse_manifest.resolve(strict=True)
        raw = path.read_bytes()
        prior = json.loads(raw)
        assert prior['status'] == 'PASS' and prior['physical_images'] == 75
        available = {(r['source_sha256'], r['buffer_profile']): r for r in prior['members']}
        for name, owner, profile in MEMBERS:
            key = SHA((source / 'native' / (owner + '.hepta')).read_bytes()), profile
            if key in available:
                reuse[name] = available[key]['manifest']
        reuse_receipt = {'manifest': str(path), 'manifest_sha256': SHA(raw),
                         'selected_members': sorted(reuse)}
        (output / 'reuse.json').write_text(json.dumps(reuse_receipt, sort_keys=True, indent=2) + '\n')
    started = time.monotonic()
    manifest = build_runtime_mcp(args.hepta.resolve(strict=True), build,
        name='public-nine-private' if args.private_fixture else 'public-nine',
        source_root=source, manifests=reuse or None, private_fixture=args.private_fixture)
    metadata = json.loads(manifest.read_bytes())
    assert metadata['physical_images'] == 79 and len(metadata['members']) == 79
    fresh = sum(r['fresh_compile'] is True for r in metadata['members'])
    assert fresh == 79 - len(reuse)
    elf = manifest.parent / metadata['elf']
    assert SHA(elf.read_bytes()) == metadata['elf_sha256']
    result = {
        'schema': 'hepta.runtime.public-nine-source-build.v1', 'status': 'NATIVE_BUILD_PASS',
        'manifest': str(manifest), 'manifest_sha256': SHA(manifest.read_bytes()),
        'elf': str(elf), 'elf_bytes': elf.stat().st_size, 'elf_sha256': metadata['elf_sha256'],
        'physical_images': 79, 'fresh_member_compiles': fresh, 'checked_reused_members': len(reuse),
        'bootstrap_reused': args.bootstrap is not None, 'fresh_hia_link_and_pack': True,
        'private_fixture': args.private_fixture, 'rust_executed': False,
        'ordinary_public_route_qualified': False, 'complete_sdk_frontend': False,
        'full_136_route_qualified': False, 'fresh_cold_qualified': False,
        'production_activated': False, 'old_path_removed': False,
        'elapsed_seconds': time.monotonic() - started,
    }
    (output / 'BUILD.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
