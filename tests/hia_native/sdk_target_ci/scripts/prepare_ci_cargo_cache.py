#!/usr/bin/env python3
"""Fetch the five exact fixture closures before offline CI builds; no compilation."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import traceback


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    checker = load('_sdk_ci_dependencies', source / 'scripts/ci_source_dependencies.py')
    checked = checker.verify(source)
    deps = json.loads((source / 'ci/dependencies.json').read_bytes())
    helper = load('_sdk_exact_rust', source / 'scripts/exact_rust_build.py')
    output = args.output.resolve()
    assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True)
    rust_bin = args.rust_bin.resolve(strict=True)
    env = {'PATH': str(rust_bin) + os.pathsep + os.environ.get('PATH', ''),
           'RUSTC': str(rust_bin / 'rustc'), 'CARGO_TARGET_DIR': str(output / 'unused-build-target')}
    recorder = helper.Recorder(output, 'evidence/processes', env)
    report = {'schema': 'hepta.sdk-exact-ci-cache-preparation.v1', 'status': 'RUNNING',
              'source_manifest_sha256': sha((source / 'source-manifest.json').read_bytes()),
              'source_check': checked, 'compiled': False, 'fixtures': [],
              'offline_qualification_performed': False, 'full_sdk_qualified': False}
    try:
        version = recorder.run('rustc-version', [rust_bin / 'rustc', '--version', '--verbose'])
        assert version.decode().splitlines()[0].startswith('rustc 1.95.0 ')
        target = (source / 'g5/target/Cargo.lock').read_bytes()
        for spec in deps['rust_projects']:
            original = source / spec['root'] / spec['project']
            project = output / 'projects' / spec['id']
            project.mkdir(parents=True)
            for filename in ['Cargo.toml', *spec['rust_sources']]:
                destination = project / filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(original / filename, destination)
            lock = (source / spec['seed_lock']).read_bytes()
            retained = checker.verify_lock_subset(target, lock, spec['binary'])
            (project / 'Cargo.lock').write_bytes(lock)
            recorder.run('fetch-' + spec['id'], [rust_bin / 'cargo', 'fetch', '--locked'],
                         cwd=project, timeout=900)
            assert (project / 'Cargo.lock').read_bytes() == lock
            report['fixtures'].append({'id': spec['id'], 'seed_lock_sha256': sha(lock),
                                       'retained_registry_packages': len(retained)})
        assert not (output / 'unused-build-target').exists()
        report['status'] = 'PASS'
    except BaseException:
        report.update(status='FAIL', failure=traceback.format_exc())
        raise
    finally:
        helper.put(output / 'evidence/summary.json', report)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
