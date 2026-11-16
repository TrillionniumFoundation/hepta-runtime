#!/usr/bin/env python3
"""Populate a CI-only Cargo cache, rejecting every dependency outside the target lock."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import sys
import tomllib
import traceback

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    args = parser.parse_args()
    assert os.environ.get('CI') == 'true', 'Cargo execution for this recipe is authorized only in CI'
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source)
    sys.path.insert(0, str(source / 'scripts'))
    from source_check import verify
    from exact_rust_build import Recorder, put, sha
    verify(source)
    output.mkdir(parents=True)
    project = output / 'oracle'
    shutil.copytree(source / 'oracle', project)
    target_lock = (source / 'target/Cargo.lock').read_bytes()
    (project / 'Cargo.lock').write_bytes(target_lock)
    (output / 'target-lock-seed.toml').write_bytes(target_lock)
    rust_bin = args.rust_bin.resolve(strict=True)
    rec = Recorder(output, 'processes', {
        'PATH': str(rust_bin) + os.pathsep + os.environ.get('PATH', ''),
        'RUSTC': str(rust_bin / 'rustc'),
        'CARGO_TARGET_DIR': str(output / 'unused-target')})
    report = {'schema': 'hepta.g5.ninth-ci-cache.v2', 'status': 'RUNNING',
              'target_lock_sha256': sha(target_lock), 'rust_compilation_executed': False,
              'fixture_executed': False, 'all_retained_exactly_match_target': False}
    put(output / 'summary.json', report)
    try:
        version = rec.run('rustc-version', [rust_bin / 'rustc', '--version', '--verbose'])
        assert version.decode().splitlines()[0].startswith('rustc 1.95.0 ')
        # The full application's lock must be pruned for this smaller macro fixture.
        # Metadata performs resolution/download only; no crate is compiled or run.
        raw = rec.run('metadata-online-for-cache', [rust_bin / 'cargo', 'metadata',
            '--format-version', '1'], cwd=project)
        metadata = json.loads(raw)
        (output / 'metadata.json').write_bytes(raw)
        pins = {(p['name'], p['version'], p.get('source')): p.get('checksum')
                for p in tomllib.loads(target_lock.decode())['package'] if p.get('source')}
        lock_raw = (project / 'Cargo.lock').read_bytes()
        retained = []
        for package in tomllib.loads(lock_raw.decode())['package']:
            if not package.get('source'):
                assert package['name'] == 'g5-target-text-editor-catalog-oracle'
                continue
            key = package['name'], package['version'], package['source']
            assert key in pins and pins[key] == package['checksum'], key
            retained.append({k: package[k] for k in ['name', 'version', 'source', 'checksum']})
        assert any(row['name'] == 'rmcp-macros' and row['version'] == '3.9.0' for row in retained)
        assert {p['name'] for p in metadata['packages'] if not p.get('source')} == {'g5-target-text-editor-catalog-oracle'}
        rec.run('fetch-locked', [rust_bin / 'cargo', 'fetch', '--locked'], cwd=project)
        assert (project / 'Cargo.lock').read_bytes() == lock_raw
        assert not (output / 'unused-target').exists()
        report.update(status='PASS', all_retained_exactly_match_target=True,
            fixture_lock_sha256=sha(lock_raw), retained_registry_packages=retained,
            fresh_build_will_rederive_lock_offline=True)
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc())
        raise
    finally:
        put(output / 'summary.json', report)
    print(json.dumps({k: v for k, v in report.items() if k != 'retained_registry_packages'}, sort_keys=True))


if __name__ == '__main__':
    main()
