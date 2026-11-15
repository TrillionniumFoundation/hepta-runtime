#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Restore exact published tool bytes into a fresh directory; execute no tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


def need(value, message):
    if not value:
        raise RuntimeError(message)


def relative(value):
    path = PurePosixPath(value)
    need(value and str(path) == value and not path.is_absolute()
         and not any(part in ('.', '..') for part in path.parts)
         and '\\' not in value and '\x00' not in value, 'unsafe relative package path')
    return path


def read_original(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'direct source required')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_size <= 1024 * 1024, 'bounded regular source required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    current = path.lstat()
    need(all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields)
         and len(raw) == before.st_size, 'source changed during read')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    repository, output = args.repository.absolute(), args.out.absolute()
    need(repository.resolve(strict=True) == repository and repository.is_dir(), 'direct full repository required')
    need(output.parent.resolve(strict=True) == output.parent and not os.path.lexists(output), 'fresh direct output required')
    raw_manifest = read_original(here / 'replay-files.json')
    manifest = json.loads(raw_manifest)
    need(manifest['schema'] == 'hepta-r36-publication-replay-files/v1'
         and 0 < len(manifest['files']) <= 128, 'unexpected replay manifest')
    prepared = {}
    for target, row in sorted(manifest['files'].items()):
        relative(target)
        source = relative(row['path'])
        need(row['kind'] in ('repository', 'published'), 'unknown source kind')
        if row['kind'] == 'repository':
            need(str(source).startswith('tools/x230/'), 'repository reference escaped reviewed tool tree')
        path = (repository if row['kind'] == 'repository' else here).joinpath(*source.parts)
        raw = read_original(path)
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'], 'reviewed source bytes differ')
        prepared[target] = raw
    need(sum(map(len, prepared.values())) <= 4 * 1024**2, 'replay package exceeds fixed size bound')
    need(read_original(here / 'replay-files.json') == raw_manifest, 'replay manifest changed')
    output.mkdir(mode=0o700)
    for target, raw in prepared.items():
        path = output.joinpath(*relative(target).parts)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('xb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    receipt = {'schema': 'hepta-r36-replay-materialization/v1', 'files': len(prepared),
               'replay_manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
               'bytes': sum(map(len, prepared.values())), 'commands_executed': 0,
               'runtime_or_benchmark_executed': False, 'qualification_or_performance_inferred': False}
    with (output / 'materialization-receipt.json').open('x') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps(receipt), flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    main()
