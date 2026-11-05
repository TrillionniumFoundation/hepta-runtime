#!/usr/bin/env python3
"""Unexecuted X230 metadata handoff; never builds, installs, or benchmarks Rust."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

OUT = Path('/home/qian/hepta-runtime-optimization-20261105-b96-compiler-preflight-01')
BASE = Path('/home/qian/hepta-runtime-optimization-20261105-r24')
SOURCE = BASE / 'source'
SYSROOT = Path('/home/qian/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu')
RUSTC = SYSROOT / 'bin/rustc'
PROFDATA = SYSROOT / 'lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata'
TARGET = 'x86_64-unknown-linux-gnu'
COMMIT = 'baab4def80be7af015b2e7a594cb302f66c4130e'
REPORT_SHA = 'bf0c5814d28b163e4a90405026cd4d90e399370d1f910f8ac48cb580af1e4971'
MAP_SHA = 'c3415beaf7697b3eb07a763ef24f424138de80af31acfd6c224cf682f3c67cbd'
PUBLICATION_SHA = '38866c01fac54133c8a88e25bee90ea4a551e7273614f493bf44522a8273d3ca'
RUNTIME_SHA = 'bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13'
VERSION_SHA = '4fdff2578428e9c5c08ddd7a0d3079c1a106b1cdaa46e73e46f7cd32b0fb9cad'
STREAM_LIMIT = 256 * 1024
CHILD_TIMEOUT = 10.0
# Direct executables only: no inherited environment, rustup shim, Cargo or shell.
CHILD_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def stamp(value):
    return tuple(getattr(value, key) for key in
                 ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def identity(path, expected=None, limit=512 * 1024 * 1024, keep=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         'non-canonical input: ' + str(path))
    raw, digest, count = [], hashlib.sha256(), 0
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
             'input type/size outside bound: ' + str(path))
        while block := stream.read(65536):
            count += len(block)
            need(count <= limit, 'input grew beyond bound: ' + str(path))
            digest.update(block)
            if keep:
                raw.append(block)
        need(stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(path.lstat()),
             'input changed during read: ' + str(path))
    value = {'path': str(path), 'bytes': count, 'sha256': digest.hexdigest(),
             'device': before.st_dev, 'inode': before.st_ino, 'uid': before.st_uid,
             'mode': oct(stat.S_IMODE(before.st_mode)), 'mtime_ns': before.st_mtime_ns}
    need(expected is None or value['sha256'] == expected, 'input SHA differs: ' + str(path))
    return value, b''.join(raw)


def new_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb')


def save_json(path, value):
    with new_file(path) as stream:
        stream.write((json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode())
        stream.flush()
        os.fsync(stream.fileno())


def command(report, name, argv):
    row = {'name': name, 'argv': argv, 'timeout_seconds': CHILD_TIMEOUT,
           'per_stream_limit_bytes': STREAM_LIMIT, 'started_utc': utc(),
           'returncode': None, 'child_pid': None, 'child_reaped': False,
           'capture_complete': False, 'error': None}
    report['commands'].append(row)
    paths = {key: OUT / (name + '.' + key) for key in ('stdout', 'stderr')}
    proc, error = None, None
    started = time.monotonic()
    try:
        with new_file(paths['stdout']) as stdout, new_file(paths['stderr']) as stderr:
            sinks = {'stdout': stdout, 'stderr': stderr}
            stored = {'stdout': 0, 'stderr': 0}
            seen = {'stdout': 0, 'stderr': 0}
            with selectors.DefaultSelector() as selector:
                try:
                    proc = subprocess.Popen(argv, shell=False, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            cwd=OUT, env=CHILD_ENV, start_new_session=True)
                    row['child_pid'] = proc.pid
                    for key, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, key)
                    deadline, drain_deadline = started + CHILD_TIMEOUT, None
                    while selector.get_map():
                        now = time.monotonic()
                        if drain_deadline is not None and now >= drain_deadline:
                            break
                        if error is None and now >= deadline:
                            error = 'subprocess timeout'
                        if error is not None and drain_deadline is None:
                            if proc.poll() is None:
                                proc.kill()
                            drain_deadline = now + 2.0
                        for event, _ in selector.select(0.05):
                            block = os.read(event.fileobj.fileno(), 16384)
                            if not block:
                                selector.unregister(event.fileobj)
                                event.fileobj.close()
                                continue
                            key = event.data
                            seen[key] += len(block)
                            accepted = block[:max(0, STREAM_LIMIT - stored[key])]
                            sinks[key].write(accepted)
                            stored[key] += len(accepted)
                            if len(accepted) != len(block):
                                error = 'subprocess output limit exceeded'
                    row['capture_complete'] = not selector.get_map() and seen == stored
                    row['returncode'] = proc.wait(timeout=2.0)
                finally:
                    if proc is not None:
                        if proc.poll() is None:
                            proc.kill()
                        try:
                            row['returncode'] = proc.wait(timeout=2.0)
                            row['child_reaped'] = True
                        finally:
                            for stream in (proc.stdout, proc.stderr):
                                if stream is not None:
                                    stream.close()
                    for stream in sinks.values():
                        stream.flush()
                        os.fsync(stream.fileno())
            row['bytes_observed'], row['bytes_saved'] = seen, stored
        need(error is None, error)
        need(row['capture_complete'], 'subprocess capture incomplete')
        need(row['returncode'] == 0, 'subprocess returned nonzero')
    except BaseException as exc:
        row['error'] = type(exc).__name__ + ': ' + str(exc)[:500]
        raise
    finally:
        row['elapsed_seconds'] = time.monotonic() - started
        for key, path in paths.items():
            if path.exists():
                row[key] = identity(path, limit=STREAM_LIMIT)[0]
    return paths['stdout'].read_bytes()


def bound_inputs(report):
    def bound(name, expected):
        item, raw = identity(BASE / name, expected, 1024 * 1024, True)
        report['bound_receipts'].append(item)
        return json.loads(raw)
    qualified = bound('qualification-01/report.json', REPORT_SHA)
    source_map = bound('qualification-01/source-map.json', MAP_SHA)
    publication = bound('final-publication-readback.json', PUBLICATION_SHA)
    need(qualified['qualified'] is True and qualified['finished_utc'], 'R24 is not qualified')
    need(qualified['source_tested'] == qualified['source_after'] == source_map,
         'qualified source map binding differs')
    need(publication['commit'] == COMMIT and publication['verified'] is True
         and publication['candidate_adopted'] is True
         and publication['qualification_report_sha256'] == REPORT_SHA, 'R24 acceptance binding differs')
    need(len(source_map) == 220, 'R24 compiler input count differs')
    current, cargo, total = {}, {}, 0
    for relative, expected in sorted(source_map.items()):
        path = Path(relative)
        need(not path.is_absolute() and '..' not in path.parts and '.' not in path.parts,
             'unsafe bound source map path')
        item, _ = identity(SOURCE / path, expected, 16 * 1024 * 1024)
        current[relative] = item['sha256']
        total += item['bytes']
        if relative in ('Cargo.toml', 'Cargo.lock', 'rustfmt.toml'):
            cargo[relative] = item
    need(current == source_map, 'current R24 compiler inputs differ')
    report['source'] = {'path': str(SOURCE), 'matched_bound_files': len(current),
                        'bound_source_bytes': total, 'cargo_inputs': cargo,
                        'scope': 'Known 220 input files only; no user Cargo config or effective build flags inferred.'}
    report['repository_cargo_config'] = {}
    for relative in ('.cargo/config', '.cargo/config.toml'):
        path = SOURCE / relative
        report['repository_cargo_config'][relative] = (
            {'exists': True, 'identity': identity(path, limit=1024 * 1024)[0],
             'contents_saved': False, 'bound_by_old_source_map': False}
            if os.path.lexists(path) else {'exists': False})
    runtime = BASE / 'qualification-01/hepta-runtime'
    need(qualified['binaries']['hepta-runtime'] == {'path': str(runtime), 'sha256': RUNTIME_SHA},
         'runtime qualification binding differs')
    report['runtime'] = identity(runtime, RUNTIME_SHA)[0]


def main():
    report = {'schema': 'hepta-x230-compiler-metadata-preflight/v1', 'started_utc': utc(),
              'passed': False, 'metadata_only': True, 'accepted_commit': COMMIT,
              'bound_receipts': [], 'commands': [], 'automatic_retries': 0,
              'build_or_benchmark_executed': False, 'tools_installed': False,
              'configuration_modified': False, 'compiler_variant_qualified': False}
    created = False
    try:
        need(len(sys.argv) == 1, 'this fixed metadata probe accepts no arguments')
        need(OUT.parent.resolve(strict=True) == OUT.parent, 'output parent is not canonical')
        OUT.mkdir(mode=0o700)
        created = True
        info = OUT.lstat()
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
             'fresh output directory ownership/mode differs')
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('SIGTERM')))
        report['runner'] = identity(Path(__file__).resolve())[0]
        uname = os.uname()
        report['platform'] = {key: getattr(uname, key) for key in ('sysname', 'release', 'version', 'machine')}
        need(uname.sysname == 'Linux' and uname.machine == 'x86_64', 'not the expected X230 platform')
        report['affinity_cpus'] = sorted(os.sched_getaffinity(0))
        report['logical_cpu_count'] = os.cpu_count()
        with open('/proc/cpuinfo', 'rb') as stream:
            cpuinfo = stream.read(1024 * 1024 + 1)
        need(len(cpuinfo) <= 1024 * 1024, 'CPU metadata exceeds bound')
        fields = {'processor', 'vendor_id', 'cpu family', 'model', 'model name', 'stepping', 'flags'}
        report['cpu'] = [{k.strip(): v.strip() for line in block.splitlines()
                          if ':' in line for k, v in [line.split(':', 1)] if k.strip() in fields}
                         for block in cpuinfo.decode('ascii', errors='strict').strip().split('\n\n')]
        need(report['cpu'] and all('model name' in row and 'flags' in row for row in report['cpu']),
             'CPU model/flags metadata missing')
        disk = os.statvfs(OUT)
        report['disk'] = {'path': str(OUT), 'available_bytes': disk.f_bavail * disk.f_frsize,
                          'total_bytes': disk.f_blocks * disk.f_frsize, 'available_inodes': disk.f_favail}
        bound_inputs(report)
        report['rustc'] = identity(RUSTC)[0]
        version = command(report, 'rustc-version', [str(RUSTC), '-Vv'])
        need(hashlib.sha256(version).hexdigest() == VERSION_SHA, 'exact recorded Rust1.95.0 -Vv differs')
        sysroot = command(report, 'rustc-sysroot', [str(RUSTC), '--print', 'sysroot'])
        need(sysroot.decode().strip() == str(SYSROOT), 'selected compiler sysroot differs')
        default_cfg = command(report, 'toolchain_default', [str(RUSTC), '--target', TARGET, '--print', 'cfg'])
        native = command(report, 'native', [str(RUSTC), '--target', TARGET, '-C', 'target-cpu=native', '--print', 'cfg'])
        command(report, 'target-cpus', [str(RUSTC), '--target', TARGET, '--print', 'target-cpus'])
        report['cfg_comparison'] = {'toolchain_default_definition': 'No target-cpu override; only this metadata invocation, not historical Cargo flags.',
                                     'native_only_lines': sorted(set(native.decode().splitlines()) - set(default_cfg.decode().splitlines()))}
        report['llvm_profdata'] = {'path': str(PROFDATA), 'available': False}
        if PROFDATA.exists():
            report['llvm_profdata'].update(available=True, identity=identity(PROFDATA)[0])
            version = command(report, 'llvm-profdata-version', [str(PROFDATA), '--version'])
            report['llvm_profdata']['reports_llvm_22_1_2'] = 'LLVM version 22.1.2' in version.decode(errors='replace')
        else:
            report['llvm_profdata']['reason'] = 'Unavailable at the one selected sysroot path; no installation or search.'
        need(identity(RUSTC)[0] == report['rustc'], 'compiler changed during metadata commands')
        report['passed'] = True
    except BaseException as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)[:1000]
    report['finished_utc'] = utc()
    try:
        if created:
            save_json(OUT / 'report.json', report)
        else:
            # Never overwrite an existing attempt or choose an unrequested output directory.
            print(json.dumps(report), file=sys.stderr)
    except BaseException as exc:
        print(json.dumps({'passed': False, 'report_write_error': type(exc).__name__ + ': ' + str(exc)[:500]}), file=sys.stderr)
        return 1
    print(json.dumps({'passed': report['passed'], 'report': str(OUT / 'report.json') if created else None}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
