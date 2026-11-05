#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Build and execute the fixed source-extracted R24/serializer mechanism once."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time
import traceback

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-b96-r27-component')
TOOLS = Path('/home/qian/hepta-runtime-optimization-20261105-r25/tools')
SOURCE = TOOLS / 'b96_r27_serializer_bench.rs'
DEPS = Path('/home/qian/hepta-runtime-optimization-20261105-r25/target-build-02/release/deps')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24/source/src/mcp/runtime/ssh.rs')
BASE_SHA = '4db25902c01d1a501f699ca26c9a70af49860127c625a9e0ff402572ad3e9829'


def identity(path):
    assert path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
    st = path.stat()
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    after = path.stat()
    assert (st.st_ino, st.st_size, st.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns)
    return {'path': str(path), 'bytes': st.st_size, 'sha256': digest}


def active_compilers():
    active = []
    for p in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = p.read_text().strip()
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld'):
                raw = (p.parent / 'stat').read_text()
                fields = raw[raw.rfind(')') + 2:].split()
                if fields[0] not in ('Z', 'X', 'x'):
                    active.append({'pid': int(p.parent.name), 'name': name, 'state': fields[0]})
        except FileNotFoundError:
            continue
    return active


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--launcher-sha256', required=True)
    args = parser.parse_args()
    launch = identity(Path(__file__).resolve())
    source = identity(SOURCE)
    assert source['sha256'] == args.source_sha256
    assert launch['sha256'] == args.launcher_sha256
    assert identity(BASE)['sha256'] == BASE_SHA
    assert not active_compilers(), 'Another compiler is active; no component run started'
    ROOT.mkdir(mode=0o700)
    report = {'schema': 'hepta-r27-serializer-component/v1', 'passed': False,
              'scope': 'Source-extracted preparation with identical fixed command stub; not RPC/RSS/lifecycle qualification',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source': source, 'launcher': launch, 'accepted_baseline_source': identity(BASE),
              'production_source_modified': False, 'automatic_retries': 0, 'stages': []}
    previous_handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)}

    def interrupted(number, _frame):
        raise InterruptedError('Component interrupted by signal ' + str(number))

    for number in previous_handlers:
        signal.signal(number, interrupted)

    def save():
        (ROOT / 'report.next').write_text(json.dumps(report, indent=2) + '\n')
        os.replace(ROOT / 'report.next', ROOT / 'report.json')

    def run(name, argv, limit=300):
        row = {'name': name, 'argv': argv, 'returncode': None}
        report['stages'].append(row)
        save()
        start = time.monotonic()
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
        with (ROOT / (name + '.stdout')).open('xb') as out, (ROOT / (name + '.stderr')).open('xb') as err:
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     cwd=ROOT, start_new_session=True)
            try:
                row['returncode'] = child.wait(timeout=limit)
            except BaseException:
                if child.poll() is None:
                    try:
                        if os.getpgid(child.pid) == child.pid:
                            os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    child.wait(timeout=10)
                    row['cleanup_reaped'] = True
                except subprocess.TimeoutExpired:
                    row['cleanup_reaped'] = False
                raise
            finally:
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                row.update(seconds=time.monotonic() - start,
                           waited_child_cpu_seconds=after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                           stdout=identity(ROOT / (name + '.stdout')), stderr=identity(ROOT / (name + '.stderr')))
                save()
        assert row['returncode'] == 0, name + ' failed; original logs retained'
        print(json.dumps({'stage': name, 'returncode': row['returncode'], 'seconds': row['seconds']}), flush=True)

    try:
        dependencies = {}
        product_fingerprint = DEPS.parent / '.fingerprint/hepta-runtime-edfb8cc1d486112f/lib-hepta_runtime.json'
        product_metadata = json.loads(product_fingerprint.read_text())
        product_deps = {row[1]: row[3] for row in product_metadata['deps']}
        report['product_dependency_fingerprint'] = identity(product_fingerprint)
        for name in ('anyhow', 'serde', 'serde_json', 'libc'):
            matches = []
            for path in sorted(DEPS.glob('lib' + name + '-*.rlib')):
                tag = path.name[len('lib' + name + '-'):-len('.rlib')]
                fingerprint = DEPS.parent / '.fingerprint' / (name + '-' + tag) / ('lib-' + name)
                if fingerprint.is_file() and int.from_bytes(bytes.fromhex(fingerprint.read_text().strip()), 'little') == product_deps[name]:
                    matches.append(path)
            assert len(matches) == 1, (name, [str(p) for p in matches])
            dependencies[name] = identity(matches[0])
        report['dependencies'] = dependencies
        compiler = ['/home/qian/.cargo/bin/rustc', '+1.95.0']
        run('compiler-version', compiler + ['-Vv'])
        common = ['--edition=2021', '-C', 'opt-level=3', '-C', 'debuginfo=0', '-C', 'panic=abort',
                  '-L', 'dependency=' + str(DEPS)]
        for name, row in dependencies.items():
            common += ['--extern', name + '=' + row['path']]
        for mode, extra in [('time', []), ('alloc', ['--cfg', 'count_allocations'])]:
            run('build-' + mode, compiler + common + extra + [str(SOURCE), '-o', str(ROOT / ('serializer-' + mode))])
        report['binaries'] = {name: identity(ROOT / ('serializer-' + name)) for name in ('time', 'alloc')}
        assert not active_compilers(), 'Another compiler started before component measurement'
        run('timing', [str(ROOT / 'serializer-time')], 180)
        assert not active_compilers(), 'Concurrent compilation observed after timing; no adoption conclusion'
        run('allocation', [str(ROOT / 'serializer-alloc')], 120)
        for name, expected in dependencies.items():
            assert identity(Path(expected['path'])) == expected, 'Dependency changed: ' + name
        assert identity(SOURCE) == source and identity(Path(__file__).resolve()) == launch
        samples = [json.loads(line) for line in (ROOT / 'timing.stdout').read_text().splitlines()]
        allocations = [json.loads(line) for line in (ROOT / 'allocation.stdout').read_text().splitlines()]
        assert len([r for r in samples if r['kind'] == 'timing']) == 48
        assert len([r for r in samples if r['kind'] == 'case' and r['byte_equivalent']]) == 6
        assert len([r for r in allocations if r['kind'] == 'allocation']) == 12
        assert len([r for r in allocations if r['kind'] == 'case' and r['byte_equivalent']]) == 6
        report['summary'] = [r for r in samples if r['kind'] == 'summary']
        assert len(report['summary']) == 6
        report['allocation'] = [r for r in allocations if r['kind'] == 'allocation']
        report['passed'] = True
    except BaseException as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        (ROOT / 'exception.txt').write_text(traceback.format_exc())
    finally:
        report['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        print(json.dumps({'passed': report['passed'], 'error': report.get('error'), 'report': identity(ROOT / 'report.json')}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
