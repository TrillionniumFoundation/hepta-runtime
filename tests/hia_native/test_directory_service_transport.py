"""Actual ELF controls for the private startup and request transport boundary."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_service_support import configuration, exclusive, require, words

LIMIT = 8 << 20
FRAME_LIMIT = 2 * LIMIT + 72
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
STARTUP_CASES = ('magic', 'mode', 'presence', 'absent-length', 'oversize',
    'short-header', 'short-payload', 'trailing', 'regular-fd', 'write-only-fd')
WIRE_CASES = ('zero-length', 'short-length', 'over-limit', 'short-prefix', 'short-body',
    'magic', 'zero-command', 'unknown-command', 'zero-id', 'payload-length')
TYPED_CASES = ('old-magic', 'reserved', 'presence', 'path-length', 'absent-metadata', 'path-over-limit')


def framed(command, identifier, payload=b''):
    raw = words(b'HMDCTL01', command, identifier, len(payload)) + payload
    return struct.pack('<Q', len(raw)) + raw


def caller(path=b'child', metadata=None):
    return words(b'HMDCRQ02', len(path), int(metadata is not None), len(metadata or b''), 0) + path + (metadata or b'')


def events(raw):
    rows = []; at = 0
    while at < len(raw):
        require(len(raw) - at >= 8, 'truncated actual event prefix')
        count, = struct.unpack_from('<Q', raw, at); at += 8
        require(40 <= count <= 134217768 and count <= len(raw) - at, 'actual event length differs')
        item = raw[at:at + count]; at += count
        require(item[:8] == b'HMDCTR01', 'actual event magic differs')
        kind, identifier, code, size = struct.unpack_from('<4Q', item, 8)
        require(kind in (1, 2, 3, 4) and code <= 0xffffffff and size == len(item) - 40,
                'actual event fields differ')
        rows.append((kind, identifier, code, item[40:]))
    return rows


def result_tag(row):
    kind, identifier, code, payload = row
    require(kind == 2 and code == len(payload) and payload[:8] == b'HMDCRS01'
            and len(payload) >= 32, 'actual caller response differs')
    tag, reserved, size = struct.unpack_from('<3Q', payload, 8)
    require(tag in (0, 1) and reserved == 0 and size == len(payload) - 32,
            'actual caller response fields differ')
    return tag


def run_case(settings, report, group, name, startup, wire, *, kind='pipe', fragmented=False,
             expected_exit=0, expected_events=None, await_events=0):
    base = settings.output / 'fixtures' / (group + '-' + name)
    work, config, environment = configuration(base, fence=True)
    snapshot_read = snapshot_write = None
    if kind == 'regular':
        path = base / 'startup.bin'; path.write_bytes(startup)
        private = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    else:
        snapshot_read, snapshot_write = os.pipe2(os.O_CLOEXEC)
        private = snapshot_write if kind == 'write-only' else snapshot_read
    try:
        os.fstat(4)
    except OSError:
        reserve = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
        require(reserve == 4, 'startup descriptor reservation differs')
    else:
        reserve = None
    def arrange():
        os.dup2(private, 4, inheritable=True)
        if private != 4:
            os.close(private)
    process = None
    started = time.monotonic()
    written_startup = bytearray()
    try:
        process = subprocess.Popen([str(settings.binary), '--runtime-config', str(config),
            '--session-root', str(work)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=tuple({4, private}), preexec_fn=arrange,
            env={'PATH': '', 'USER': 'operator', **environment})
    finally:
        if reserve is not None:
            os.close(reserve)
        if kind == 'regular':
            os.close(private)
        elif kind == 'write-only':
            os.close(snapshot_read); os.close(snapshot_write); snapshot_write = None
        else:
            os.close(snapshot_read)
    try:
        if snapshot_write is not None:
            try:
                at = 0
                while at < len(startup):
                    end = min(len(startup), at + (3 if fragmented else len(startup)))
                    n = os.write(snapshot_write, startup[at:end])
                    require(n > 0, 'startup write made no progress')
                    written_startup.extend(startup[at:at + n]); at += n
            except BrokenPipeError:
                require(expected_exit == 111, 'valid startup pipe broke')
            finally:
                os.close(snapshot_write)
        if await_events:
            # EOF is an actual outer-future drop. Keep stdin open until the
            # intended responses finish, including across invalid requests.
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            at = parsed = count = 0; captured = bytearray()
            deadline = time.monotonic() + 30
            while at < len(wire) or count < await_events:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'open transport completion deadline')
                readable, writable, _ = select.select([process.stdout],
                    [process.stdin] if at < len(wire) else [], [], remaining)
                require(readable or writable, 'open transport made no progress')
                if writable:
                    at += os.write(process.stdin.fileno(), wire[at:at + (7 if fragmented else 65536)])
                if readable:
                    part = os.read(process.stdout.fileno(), 65536)
                    require(part, 'open transport exited before completion')
                    captured.extend(part)
                    while len(captured) - parsed >= 8:
                        n, = struct.unpack_from('<Q', captured, parsed)
                        require(40 <= n <= 134217768, 'open event length differs')
                        if len(captured) - parsed < 8 + n:
                            break
                        parsed += 8 + n; count += 1
            process.stdin.close(); process.stdin = None
            tail, stderr = process.communicate(timeout=30)
            stdout = bytes(captured) + tail
        else:
            stdout, stderr = process.communicate(wire, timeout=30)
        require(process.returncode == expected_exit and not stderr,
                ('transport termination differs', group, name, process.returncode, stderr))
        require(not Path('/proc', str(process.pid)).exists(), 'transport process was not reaped')
        rows = events(stdout)
        if expected_events is not None:
            require(rows == expected_events, ('transport events differ', group, name, rows))
        for path in (base / 'authority/.owner.lock', base / 'state/controller.lock',
                     base / 'state/controller.owner.lock'):
            if path.exists():
                with path.open('rb') as fd:
                    require(exclusive(fd), 'transport exit leaked an owned lock')
        children = sorted(os.fsencode(x.name).hex() for x in work.iterdir())
        record = dict(group=group, case=name, status='PASS', pid=process.pid,
            exit_code=process.returncode, reaped=True, snapshot_kind=kind,
            startup_hex=startup.hex(), written_startup_hex=written_startup.hex(),
            stdin_bytes=len(wire), stdin_sha256=SHA(wire), stdout_hex=stdout.hex(),
            stderr_hex=stderr.hex(), actual_events=len(rows), workspace_entries_hex=children,
            elapsed_seconds=time.monotonic() - started)
        # Large input bytes survive in gzip without bloating the JSON receipt.
        import gzip
        prefix = settings.output / (group + '-' + name)
        with gzip.GzipFile(filename=str(prefix) + '.stdin.gz', mode='xb', mtime=0) as stream:
            stream.write(wire)
        record['stdin_gzip'] = prefix.name + '.stdin.gz'
        raw = Path(str(prefix) + '.stdin.gz').read_bytes()
        record['stdin_gzip_sha256'] = SHA(raw)
        report['cases'].append(record)
        return rows, work
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill(); process.wait()
        raise
    finally:
        # Only this closed process's own fixture is retired; receipts retain
        # the complete private startup, wire, returned bytes and effect names.
        if process is not None and process.poll() is not None:
            shutil.rmtree(base)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.manifest = args.manifest.resolve(strict=True)
    metadata = json.loads(args.manifest.read_bytes())
    args.binary = args.manifest.parent / metadata['executable']
    require(SHA(args.binary.read_bytes()) == metadata['elf_sha256'], 'transport actual ELF differs')
    args.output = args.output.resolve(); args.output.mkdir(parents=True, exist_ok=False)
    sources = {p.name: SHA(p.read_bytes()) for p in
               (Path(__file__), Path(__file__).with_name('directory_service_support.py'))}
    report = dict(schema='hepta.directory-service.private-transport.v1', status='FAIL',
        cases=[], source_sha256=sources, elf_sha256=metadata['elf_sha256'],
        original_executions=0, production_activated=False, whole_runtime_replaced=False,
        expected_domains=dict(startup=list(STARTUP_CASES), wire=list(WIRE_CASES),
            typed=list(TYPED_CASES), boundary=['fragmented', 'exact-max-frame']))
    good = words(b'HMDINIT1', 0, 0, 0)
    def save():
        (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    try:
        cases = [b'BADINIT1' + good[8:], words(b'HMDINIT1', 2, 0, 0),
            words(b'HMDINIT1', 0, 2, 0), words(b'HMDINIT1', 0, 0, 1) + b'x',
            words(b'HMDINIT1', 0, 1, LIMIT + 1), good[:-1],
            words(b'HMDINIT1', 0, 1, 3) + b'{}', good + b'x', good, good]
        for name, startup in zip(STARTUP_CASES, cases, strict=True):
            kind = 'regular' if name == 'regular-fd' else 'write-only' if name == 'write-only-fd' else 'pipe'
            run_case(args, report, 'startup', name, startup, b'', kind=kind,
                expected_exit=111, expected_events=[])
        cases = [struct.pack('<Q', 0), struct.pack('<Q', 31), struct.pack('<Q', FRAME_LIMIT + 1),
            struct.pack('<Q', 32)[:-1], struct.pack('<Q', 32) + b'x' * 31,
            struct.pack('<Q', 32) + words(b'BADCTL01', 1, 1, 0), framed(0, 1), framed(4, 1),
            framed(1, 0), struct.pack('<Q', 32) + words(b'HMDCTL01', 1, 1, 1)]
        for name, wire in zip(WIRE_CASES, cases, strict=True):
            run_case(args, report, 'wire', name, good, wire, expected_exit=111, expected_events=[])
        cases = [b'HMDCRQ01' + caller()[8:], words(b'HMDCRQ02', 1, 0, 0, 1) + b'x',
            words(b'HMDCRQ02', 1, 2, 0, 0) + b'x', words(b'HMDCRQ02', 2, 0, 0, 0) + b'x',
            words(b'HMDCRQ02', 1, 0, 1, 0) + b'xy', words(b'HMDCRQ02', LIMIT + 1, 0, 0, 0)]
        for name, payload in zip(TYPED_CASES, cases, strict=True):
            rows, _ = run_case(args, report, 'typed', name, good,
                framed(1, 1, payload) + framed(1, 2, caller(b'following')), await_events=4)
            require(len(rows) == 4 and rows[:2] == [(1, 1, 0, b''), (2, 1, 0xffffffff, b'')]
                    and rows[2] == (1, 2, 0, b'') and result_tag(rows[3]) == 0,
                    'typed refusal did not preserve following request')
            require(report['cases'][-1]['workspace_entries_hex'] == [b'following'.hex()],
                    'typed refusal changed the filesystem')
        rows, _ = run_case(args, report, 'boundary', 'fragmented', good,
            framed(1, 1, caller(b'fragmented')), fragmented=True, await_events=2)
        require(len(rows) == 2 and rows[0] == (1, 1, 0, b'') and result_tag(rows[1]) == 0,
                'fragmented stream differs')
        metadata_bytes = b'{"x":"' + b'a' * (LIMIT - 8) + b'"}'
        require(len(metadata_bytes) == LIMIT, 'maximum metadata fixture differs')
        wire = framed(1, 1, caller(b' ' * LIMIT, metadata_bytes))
        require(len(wire) == FRAME_LIMIT + 8, 'maximum frame fixture differs')
        rows, _ = run_case(args, report, 'boundary', 'exact-max-frame', words(b'HMDINIT1', 1, 0, 0), wire,
                           await_events=2)
        require(len(rows) == 2 and rows[0] == (1, 1, 0, b'') and result_tag(rows[1]) == 1
                and report['cases'][-1]['workspace_entries_hex'] == [], 'maximum valid transport frame differs')
        require(len(report['cases']) == 28 and SHA(args.binary.read_bytes()) == metadata['elf_sha256'],
                'transport fixed domain or artifact changed')
        report['source_unchanged'] = sources == {n: SHA(Path(__file__).with_name(n).read_bytes()) for n in sources}
        require(report['source_unchanged'], 'transport source changed')
        report.update(status='PASS', native_processes=28,
            test_summary=dict(tests_run=4, failures=0, errors=0, skipped=0,
                              expected_failures=0, unexpected_successes=0))
    except BaseException as error:
        report['error'] = repr(error); raise
    finally:
        save()
    print(json.dumps({k: v for k, v in report.items() if k not in ('cases', 'source_sha256', 'expected_domains')}))


if __name__ == '__main__':
    main()
