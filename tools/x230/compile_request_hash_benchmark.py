#!/usr/bin/env python3
"""Compile the standalone writer benchmark with A19's actual cached release rlibs.

No cargo invocation, network, runtime launch, or benchmark execution. The input
must be the completed qualification release.log containing Cargo JSON artifacts.
Refuse missing/ambiguous artifacts rather than guessing among cache variants.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-log', required=True, type=Path)
    parser.add_argument('--source', type=Path, default=Path(__file__).with_name('request_hash_benchmark.rs'))
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--rustup', default=str(Path.home() / '.cargo/bin/rustup'))
    parser.add_argument('--toolchain', default='1.95.0')
    args = parser.parse_args()
    required = ('anyhow', 'libc', 'ring', 'serde', 'serde_json', 'sha2')
    artifacts = {name: set() for name in required}
    for line in args.release_log.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get('reason') != 'compiler-artifact':
            continue
        name = record.get('target', {}).get('name')
        profile = record.get('profile', {})
        if name not in artifacts or profile.get('test') is not False or str(profile.get('opt_level')) != '3':
            continue
        artifacts[name].update(Path(value).resolve() for value in record.get('filenames', []) if value.endswith('.rlib'))
    for name, matches in artifacts.items():
        if len(matches) != 1:
            raise SystemExit(f'{name}: expected one optimized release rlib from this build, found {sorted(map(str, matches))}')
    libraries = {name: next(iter(matches)) for name, matches in artifacts.items()}
    for name, path in libraries.items():
        if not path.is_file():
            raise SystemExit(f'{name}: cached release rlib is unavailable: {path}')
    dependency_dirs = {path.parent for path in libraries.values()}
    if len(dependency_dirs) != 1:
        raise SystemExit('release rlibs belong to different dependency directories; refuse mixed caches')
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    if not output.parent.is_dir():
        raise SystemExit(f'output parent must already exist: {output.parent}')
    command = [args.rustup, 'run', args.toolchain, 'rustc', '--edition=2021',
               '-C', 'opt-level=3', '-C', 'codegen-units=1', '-C', 'lto=fat',
               '-C', 'panic=abort', '-C', 'overflow-checks=off',
               '-L', f'dependency={next(iter(dependency_dirs))}']
    for name in required:
        command += ['--extern', f'{name}={libraries[name]}']
    command += [str(source), '-o', str(output)]
    print(json.dumps({'schema': 'hepta-request-hash-benchmark-build/v1',
                      'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                      'rustc_command': shlex.join(command),
                      'release_log': str(args.release_log.resolve()),
                      'rlibs': {name: str(path) for name, path in libraries.items()}}, sort_keys=True), flush=True)
    subprocess.run(command, check=True)
    print(json.dumps({'compiled_binary': str(output),
                      'binary_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                      'benchmark_executed': False}, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
