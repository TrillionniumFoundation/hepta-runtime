#!/usr/bin/env python3
"""Execute the unchanged Rust view owners against the retained native corpus."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import lzma
from pathlib import Path
import subprocess
import threading
import time


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--requests', type=Path, required=True)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    compiler = parser.add_mutually_exclusive_group(required=True)
    compiler.add_argument('--rustc', type=Path)
    compiler.add_argument('--binary', type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    args.output.mkdir(mode=0o700, exist_ok=False)
    names = ['source', 'requests', 'expected', 'metadata']
    if args.binary:
        names.append('binary')
    before = {name: identity(getattr(args, name)) for name in names}
    metadata = json.loads(args.metadata.read_bytes())
    assert before['source']['sha256'] == metadata['oracle_sha256']
    if args.binary:
        executable = args.binary
        compiler_text, flags, compile_exit = None, [], 0
    else:
        executable = args.output / 'original-view.elf'
        compiler = subprocess.run([str(args.rustc), '--version'], check=True, capture_output=True, timeout=15)
        compiler_text = compiler.stdout.decode().strip()
        flags = ['--edition=2021', '-O', '-C', 'overflow-checks=off']
        compilation = subprocess.run([str(args.rustc), *flags, str(args.source), '-o', str(executable)],
                                     capture_output=True, timeout=90)
        (args.output / 'compile.stdout').write_bytes(compilation.stdout)
        (args.output / 'compile.stderr').write_bytes(compilation.stderr)
        assert compilation.returncode == 0, compilation.stderr.decode()
        compile_exit = compilation.returncode
    if args.expected.suffix == '.gz':
        expected_open = gzip.open
    elif args.expected.suffix == '.xz':
        expected_open = lzma.open
    else:
        raise ValueError('expected native output must use a declared gzip or xz container')
    failure, feed_result = [], {}
    process = None
    actual_hash, expected_hash = hashlib.sha256(), hashlib.sha256()
    actual_bytes = expected_bytes = count = 0
    with (args.output / 'run.stderr').open('xb') as stderr:
        process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=stderr)
        def feed():
            try:
                digest, size = hashlib.sha256(), 0
                with gzip.open(args.requests, 'rb') as source:
                    while chunk := source.read(1 << 20):
                        digest.update(chunk)
                        size += len(chunk)
                        process.stdin.write(chunk)
                process.stdin.close()
                feed_result.update(sha256=digest.hexdigest(), bytes=size)
            except BaseException as error:
                failure.append(repr(error))
        feeder = threading.Thread(target=feed, daemon=True)
        feeder.start()
        try:
            with expected_open(args.expected, 'rb') as expected, gzip.open(args.output / 'rust-output.txt.gz', 'xb') as saved:
                for expected_line in expected:
                    actual = process.stdout.readline()
                    count += 1
                    actual_hash.update(actual)
                    expected_hash.update(expected_line)
                    actual_bytes += len(actual)
                    expected_bytes += len(expected_line)
                    saved.write(actual)
                    if actual != expected_line:
                        raise AssertionError({'case': count, 'native_sha256': sha(expected_line),
                            'rust_sha256': sha(actual), 'native_bytes': len(expected_line),
                            'rust_bytes': len(actual), 'rust_preview': actual[:180].decode(errors='replace')})
                assert process.stdout.read(1) == b'', 'original oracle returned extra output'
            feeder.join(timeout=10)
            assert not feeder.is_alive() and not failure, failure
            assert process.wait(timeout=10) == 0
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    assert (args.output / 'run.stderr').read_bytes() == b''
    assert count == metadata['cases']
    assert feed_result == {'sha256': metadata['requests_sha256'], 'bytes': metadata['requests_bytes']}
    assert actual_bytes == expected_bytes == metadata['native_output_bytes']
    assert actual_hash.hexdigest() == expected_hash.hexdigest() == metadata['native_output_sha256']
    after = {name: identity(getattr(args, name)) for name in names}
    assert before == after
    result = {'status': 'PASS', 'cases': count, 'seconds': time.monotonic() - started,
              'compiler': compiler_text, 'compile_flags': flags,
              'compile_exit_code': compile_exit, 'run_exit_code': process.returncode,
              'compiled_by_qualification_recipe': args.binary is not None,
              'raw_output_bytes': actual_bytes, 'native_and_rust_output_sha256': actual_hash.hexdigest(),
              'inputs_before': before, 'inputs_after': after,
              'executable': identity(executable), 'requests': feed_result,
              'driver': identity(Path(__file__)), 'comparison': 'exact bytes for every complete output line',
              'original_function_bodies_unchanged': True,
              'fixture_boundary': 'typed endpoint and independent read snapshots; original range/file/cache/result gate functions',
              'whole_view_migrated': False}
    (args.output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
