#!/usr/bin/env python3
"""Build and test a source-pinned runtime candidate without changing services."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError(f'source symlink: {path}')
        if path.is_file():
            result[str(path.relative_to(root))] = digest(path)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target-dir', type=Path, required=True)
    parser.add_argument('--cargo', default='cargo')
    parser.add_argument('--toolchain', default='1.95.0')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    report = {'schema': 'runtime-candidate-qualification/v1', 'qualified': False,
              'source': str(source), 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'stages': [], 'source_input': sources(source), 'service_changes': False}
    env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()),
               CARGO_BUILD_JOBS=str(args.jobs), CARGO_INCREMENTAL='0',
               TOKIO_WORKER_THREADS='2', RUST_TEST_THREADS='2')
    cargo = [args.cargo, '+' + args.toolchain]

    def save():
        path = output / 'report.json.next'
        with path.open('w') as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path, output / 'report.json')
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def stage(name, argv):
        report['current_stage'] = name
        save()
        log = output / (name + '.log')
        started = time.monotonic()
        with log.open('xb') as stream:
            result = subprocess.run(cargo + argv, cwd=source, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=1800)
            stream.flush()
            os.fsync(stream.fileno())
        row = {'name': name, 'command': cargo + argv, 'returncode': result.returncode,
               'seconds': time.monotonic() - started, 'log_sha256': digest(log)}
        if name == 'test':
            row['results'] = [line for line in log.read_text().splitlines()
                              if line.startswith('test result:')]
        report['stages'].append(row)
        save()
        print(json.dumps(row), flush=True)
        if result.returncode:
            raise RuntimeError(f'{name} failed with exit {result.returncode}')
        return log

    def artifact(log, is_test):
        found = []
        for line in log.read_text().splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (value.get('reason') == 'compiler-artifact'
                    and value.get('target', {}).get('name') == 'hepta-runtime'
                    and value.get('profile', {}).get('test') is is_test):
                found.append(value)
        if len(found) != 1 or Path(found[0]['manifest_path']) != source / 'Cargo.toml':
            raise RuntimeError('compiler artifact does not match candidate source')
        original = Path(found[0]['executable'])
        destination = output / ('hepta-runtime-tests' if is_test else 'hepta-runtime')
        shutil.copy2(original, destination)
        fd = os.open(destination, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return {'sha256': digest(destination), 'path': str(destination),
                'compiler_source': found[0]['target']['src_path'], 'cached': found[0]['fresh']}

    try:
        stage('format', ['fmt', '--all'])
        report['source_tested'] = sources(source)
        stage('fmt-check', ['fmt', '--all', '--', '--check'])
        stage('clippy', ['clippy', '--offline', '--locked', '--all-features', '--all-targets', '--', '-D', 'warnings'])
        tests = stage('test', ['test', '--offline', '--locked', '--all-features', '--message-format=json-render-diagnostics'])
        report['test_binary'] = artifact(tests, True)
        release = stage('release', ['build', '--offline', '--locked', '--all-features', '--release', '--bins', '--message-format=json-render-diagnostics'])
        report['binary'] = artifact(release, False)
        report['source_after'] = sources(source)
        if report['source_after'] != report['source_tested']:
            raise RuntimeError('candidate source changed during qualification')
        report['qualified'] = True
        report['current_stage'] = 'complete'
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


if __name__ == '__main__':
    main()
