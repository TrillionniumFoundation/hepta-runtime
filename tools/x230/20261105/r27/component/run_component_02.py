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

ROOT = Path('/home/qian/hepta-runtime-optimization-20261105-b96-r27-component-02')
TOOLS = Path('/home/qian/hepta-runtime-optimization-20261105-r25/tools')
SOURCE = TOOLS / 'b96_r27_serializer_bench.rs'
DEPS = Path('/home/qian/hepta-runtime-optimization-20261105-r26/target-build/release/deps')
PRODUCT_FINGERPRINT_SHA = 'ed3d18008e23932331e4f6422e9935cc13f172522a75cfaa56785c41f359c6ee'
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


def active_work():
    # Scheduling evidence only, not an access-control or whole-interval proof.
    blocked, limited, errors = [], [], []
    for directory in Path('/proc').glob('[0-9]*'):
        pid = int(directory.name)
        if pid == os.getpid():
            continue
        try:
            raw = (directory / 'stat').read_text()
            fields = raw[raw.rfind(')') + 2:].split()
            if fields[0] in ('Z', 'X', 'x'):
                continue
            name = (directory / 'comm').read_text().strip()
            reasons = []
            if name in ('cargo', 'rustc', 'rust-lld', 'ld.lld', 'nextest', 'cargo-nextest', 'tar', 'gzip', 'xz', 'zstd'):
                reasons.append('compiler_test_or_archive')
            if directory.stat().st_uid == os.getuid():
                argv = (directory / 'cmdline').read_bytes().split(b'\0')
                for item in argv[:6]:
                    value = item.decode('utf-8', 'replace')
                    if value.startswith('/home/qian/hepta-runtime'):
                        base = Path(value).name
                        if any(word in base for word in ('campaign', 'benchmark', 'phase', 'qualify', 'qualification', 'archive', 'export', 'isolated', 'monitor', 'rust_ci')):
                            reasons.append('active_hepta_work:' + base)
                try:
                    executable = os.readlink(directory / 'exe')
                    if '/hepta-runtime-optimization-20261105-' in executable:
                        reasons.append('active_private_candidate_or_test_binary')
                except FileNotFoundError:
                    pass
                except PermissionError:
                    if name in ('(sd-pam)', 'sshd', 'gpg-agent', 'ssh-agent'):
                        limited.append({'pid': pid, 'name': name, 'field': 'exe', 'visible_comm_and_cmdline_checked': True})
                    else:
                        raise
            if reasons:
                blocked.append({'pid': pid, 'name': name, 'reasons': reasons})
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            errors.append({'pid': pid, 'reason': 'unclassified_process_permission_denied'})
    print(json.dumps({'quiescence_guard': {'unix_ns': time.time_ns(), 'blocked': blocked,
                     'limited_service_details': limited, 'read_errors': errors,
                     'quiet_snapshot': not blocked and not errors}}), flush=True)
    return blocked + errors


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
    assert not active_work(), 'Other compiler, test, campaign or archive work is active; no component run started'
    ROOT.mkdir(mode=0o700)
    report = {'schema': 'hepta-r27-serializer-component/v1', 'passed': False,
              'scope': 'Source-extracted preparation with identical fixed command stub; not RPC/RSS/lifecycle qualification',
              'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'source': source, 'launcher': launch, 'accepted_baseline_source': identity(BASE),
              'production_source_modified': False, 'automatic_retries': 0, 'stages': [],
              'attempt': '02', 'prior_attempt': {'job_id': '1a1ab85c2c3-fc05-4e78',
              'report_sha256': 'f3ed69b104573fa4f2c667a4a165cf18c58b0f63e87e646d7af0a008e3511f6d',
              'disposition': 'failed before any compiler or sample because the old cache fingerprint was absent'},
              'dependency_cache_scope': 'R26 third-party release dependencies only; no Hepta library linked',
              'guard_scope': 'Before-build, before-timing and after-timing process snapshots; not continuous exclusivity proof'}
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
        product_raw = product_fingerprint.read_bytes()
        assert hashlib.sha256(product_raw).hexdigest() == PRODUCT_FINGERPRINT_SHA
        (ROOT / 'qualified-product-fingerprint.json').write_bytes(product_raw)
        product_metadata = json.loads(product_raw)
        product_deps = {row[1]: row[3] for row in product_metadata['deps']}
        report['product_dependency_fingerprint'] = identity(product_fingerprint)
        assert report['product_dependency_fingerprint']['sha256'] == PRODUCT_FINGERPRINT_SHA
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
        assert not active_work(), 'Competing work observed before component measurement'
        run('timing', [str(ROOT / 'serializer-time')], 180)
        assert not active_work(), 'Competing work observed after timing; no adoption conclusion'
        run('allocation', [str(ROOT / 'serializer-alloc')], 120)
        for name, expected in dependencies.items():
            assert identity(Path(expected['path'])) == expected, 'Dependency changed: ' + name
        assert identity(product_fingerprint) == report['product_dependency_fingerprint']
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
