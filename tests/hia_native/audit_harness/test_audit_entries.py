"""Compare actual native and original filesystem effects in owned directories."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
import select
import traceback

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def setup(root, row):
    root.mkdir(mode=0o700)
    for name, spec in row['files'].items():
        assert '/' not in name and name not in ('.', '..')
        path = root / name;kind = spec['kind']
        if kind == 'hardlink':continue
        if kind == 'file':path.write_bytes(bytes.fromhex(spec['data']))
        elif kind == 'directory':path.mkdir()
        elif kind == 'fifo':os.mkfifo(path)
        elif kind == 'socket':
            previous = os.open('.', os.O_PATH | os.O_CLOEXEC)
            try:
                os.chdir(root)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:server.bind('.socket-setup')
                os.rename('.socket-setup', name)
            finally:
                os.fchdir(previous);os.close(previous)
        elif kind == 'symlink':path.symlink_to(spec['target'])
        else:raise AssertionError(spec)
        if kind != 'symlink':path.chmod(spec['mode'])
    for name, spec in row['files'].items():
        if spec['kind'] == 'hardlink':os.link(root / spec['target'], root / name, follow_symlinks=False)
    root.chmod(row.get('directory_mode', 0o700))


def snapshot(root, prior=None):
    rows = {};identities = {}
    for name in sorted(os.listdir(root)):
        path = root / name;value = path.lstat();identity = (value.st_dev, value.st_ino)
        identities[name] = identity
        record = dict(mode=value.st_mode, uid=value.st_uid, gid=value.st_gid, links=value.st_nlink)
        if stat.S_ISREG(value.st_mode):
            record['bytes'] = value.st_size
            try:
                data = path.read_bytes();record['sha256'] = SHA(data);assert len(data) == value.st_size
            except PermissionError as error:record['content_read_errno'] = error.errno
        if stat.S_ISLNK(value.st_mode):record['target'] = os.readlink(path)
        if prior is not None:record['same_inode_as_before'] = identity == prior[name] if name in prior else None
        rows[name] = record
    for name, record in rows.items():record['aliases'] = sorted(n for n, identity in identities.items() if identity == identities[name])
    directory = root.stat()
    return dict(directory_mode=directory.st_mode, directory_uid=directory.st_uid, directory_gid=directory.st_gid,
        entries=rows), identities


def parse(raw):
    position = 0;rows = []
    while position < len(raw):
        assert position + 4 <= len(raw)
        code = struct.unpack_from('<I', raw, position)[0];position += 4
        size = code if code <= 1 << 20 else 0
        assert position + size <= len(raw)
        body = raw[position:position + size];position += size
        if size:
            assert size >= 32
            magic, diagnostic, errno, count = struct.unpack_from('<8s3Q', body)
            assert magic == b'HRAER001' and count <= 512
            offset = 32;keys = []
            for index in range(count):
                length = struct.unpack_from('<Q', body, offset)[0];offset += 8
                assert 256 <= length <= 512 and offset + length <= len(body)
                part = body[offset:offset + length];offset += length
                assert part[:8] == b'HRAJJ001'
                low, high = struct.unpack_from('<2Q', part, 24)
                start, length = struct.unpack_from('<2Q', part, 64)
                identifier = part[start:start + length].decode()
                keys.append((low + (high << 64), identifier))
            assert offset == size and keys == sorted(keys)
            assert diagnostic == 0 or count == 0
            rows.append(dict(code=code, diagnostic=diagnostic, errno=errno, records=count,
                result_bytes=size - 32, output_sha256=SHA(body), sorted_u128_and_ids=True))
        else:
            assert code in (0xffffffff, 0xfffffffe)
            rows.append(dict(code=code, result_bytes=0))
    return rows


def run_one(executable, root, directory, row, wire):
    directory.mkdir(mode=0o700);setup(root, row)
    before, identities = snapshot(root)
    pins = []
    try:
        for name, identity in identities.items():
            if len(identities) > 64 and not (name.startswith('.') or name.endswith('.json')):continue
            fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
            pins.append((name, fd, identity))
        started = time.monotonic()
        command = [str(executable), str(root)]
        supervised = 'supervisor' in row
        if supervised:
            (directory / 'kernel-config.json').write_bytes(ENCODE(row['supervisor']))
            command = [sys.executable, '-I', '-B', str(Path(__file__).with_name('audit_entries_supervisor.py')),
                '--fixture', str(root), '--config', str(directory / 'kernel-config.json'),
                '--log', str(directory / 'kernel.json'), '--', str(executable), str(root)]
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, PATH='', HEPTA_REQUEST_AUDIT_TRACE='0'),
            umask=row.get('umask', 0o077))
        timed = False;stdout = bytearray();observations = []
        def exact(count):
            data = bytearray();deadline = time.monotonic() + 15
            while len(data) != count:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired(process.args, 15)
                chunk = os.read(process.stdout.fileno(), count - len(data))
                assert chunk, (process.poll(), bytes(data))
                data.extend(chunk)
            return bytes(data)
        try:
            offset = 0;previous_identities = identities
            for operation in row['operations']:
                raw = bytes.fromhex(operation);framed = struct.pack('<Q', len(raw)) + raw
                assert wire[offset:offset + len(framed)] == framed;offset += len(framed)
                process.stdin.write(framed);process.stdin.flush()
                header = exact(4);code = struct.unpack('<I', header)[0]
                body = exact(code) if code <= 1 << 20 else b''
                assert code <= 1 << 20 or code in (0xffffffff, 0xfffffffe)
                stdout.extend(header + body)
                snapshot_now, current_identities = snapshot(root, previous_identities)
                for name, identity in current_identities.items():
                    if previous_identities.get(name) != identity:
                        fd = os.open(root / name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
                        value = os.fstat(fd);assert (value.st_dev, value.st_ino) == identity
                        pins.append((name, fd, identity))
                previous_identities = current_identities
                descriptors = []
                actual_pid = int((directory / 'kernel.pid').read_text()) if supervised else process.pid
                for descriptor in sorted(Path('/proc').joinpath(str(actual_pid), 'fd').iterdir(), key=lambda p: int(p.name)):
                    try:
                        target = os.readlink(descriptor)
                        if target == str(root) or target.startswith(str(root) + '/'):
                            value = descriptor.stat()
                            descriptors.append(dict(target=target[len(str(root)):], mode=value.st_mode,
                                uid=value.st_uid, gid=value.st_gid, identity=[value.st_dev, value.st_ino]))
                    except FileNotFoundError:pass
                identity = root.stat()
                assert len(descriptors) == 1 and descriptors[0]['target'] == ''
                assert descriptors[0]['identity'] == [identity.st_dev, identity.st_ino]
                observed_descriptors = [{k: v for k, v in d.items() if k != 'identity'} for d in descriptors]
                observations.append(dict(snapshot=snapshot_now, descriptors=observed_descriptors,
                    actual_kernel_directory_identity_verified=True, no_record_or_scan_fd_before_response=True))
            assert offset == len(wire)
            process.stdin.close();process.stdin = None
            extra, stderr = process.communicate(timeout=15);assert not extra
        except BaseException:
            process.kill();tail, stderr = process.communicate();stdout.extend(tail)
            (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
            (directory / 'partial-observations.json').write_bytes(ENCODE(observations))
            raise
        stdout = bytes(stdout)
        (directory / 'stdout.bin').write_bytes(stdout);(directory / 'stderr.bin').write_bytes(stderr)
        after, _ = snapshot(root, identities)
        for name, fd, identity in pins:
            observed = os.fstat(fd);assert (observed.st_dev, observed.st_ino) == identity
        receipt = dict(command=[str(executable), str(root)], pid=process.pid, exit_code=process.returncode,
            reaped=True, timed_out=timed, timeout_seconds=15, elapsed_seconds=time.monotonic() - started,
            stdin_bytes=len(wire), stdin_sha256=SHA(wire), stdout_bytes=len(stdout), stdout_sha256=SHA(stdout),
            stderr_bytes=len(stderr), stderr_sha256=SHA(stderr), umask=row.get('umask', 0o077),
            path_environment_empty=True, initial_inodes_held_through_after_snapshot=len(pins),
            identity_custody_verified=True)
        result = dict(process=receipt, before=before, after=after, observations=observations)
        if supervised:
            observer = json.loads((directory / 'kernel.json').read_bytes())
            assert observer['status'] == 'PASS' and observer['all_selected_faults_reached']
            assert observer['child_reaped'] and observer['exit_code'] == 0
            if row.get('forbid_directory_sync'):assert observer['counts'].get('sync_directory', 0) == 0
            selected = [e for e in observer['events'] if e['completion'] != 'kernel_continue']
            result['selected_kernel_holding'] = [dict(kind=e['kind'], ordinal=e['ordinal'],
                completion=e['completion'], held_files=e['held_files']) for e in selected]
        (directory / 'observation.json').write_bytes(ENCODE(result))
        assert process.returncode == 0 and not timed and not stderr, receipt
        result['replies'] = parse(stdout)
        assert len(result['replies']) == len(row['operations'])
        return result, stdout
    finally:
        for _, fd, _ in pins:os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('native', 'oracle', 'output'):parser.add_argument('--' + key, required=True, type=Path)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from audit_entries_cases import cases
    report = dict(schema='hepta.request-audit.bounded-entries-comparison.v1', status='FAIL', cases=[],
        production_activated=False, whole_runtime_replaced=False, old_stack_removal_qualified=False,
        result_storage_closed=False, archive_anchoring_closed=False, audit_storage_closed=False,
        public_request_dispatch_qualified=False, exact_serde_diagnostics_qualified=False)
    save = lambda: (out / 'result.json').write_bytes(ENCODE(report))
    save();started = time.monotonic()
    try:
        native, oracle = args.native.resolve(strict=True), args.oracle.resolve(strict=True)
        images = {str(path): dict(bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in (native, oracle)}
        report['executables'] = images
        definitions = list(cases());assert len({r['name'] for r in definitions}) == len(definitions)
        (out / 'cases.json').write_bytes(ENCODE(definitions))
        requests = 0
        for index, row in enumerate(definitions):
            directory = out / f'{index:04d}';directory.mkdir(mode=0o700)
            wire = b''.join(struct.pack('<Q', len(bytes.fromhex(raw))) + bytes.fromhex(raw) for raw in row['operations'])
            (directory / 'stdin.bin').write_bytes(wire)
            original, old_bytes = run_one(oracle, directory / 'original/fixture', directory / 'original', row, wire)
            actual, new_bytes = run_one(native, directory / 'native/fixture', directory / 'native', row, wire)
            equal = old_bytes == new_bytes and original['before'] == actual['before'] and original['after'] == actual['after'] and original['observations'] == actual['observations']
            record = dict(index=index, name=row['name'], passed=equal, requests=len(row['operations']),
                original=original, native=actual)
            report['cases'].append(record);save();assert equal, (index, row['name'])
            requests += len(row['operations'])
        assert images == {str(path): dict(bytes=path.stat().st_size, sha256=SHA(path.read_bytes())) for path in (native, oracle)}
        report.update(status='PASS', compared_cases=len(definitions), original_requests=requests,
            native_requests=requests, actual_native_processes=len(definitions), actual_original_processes=len(definitions),
            complete_output_bytes_equal=True, actual_held_descriptors_verified=True,
            observations_per_implementation=requests, metadata_contents_links_and_inode_changes_equal=True,
            elapsed_seconds=time.monotonic() - started, executables_unchanged=True)
    except BaseException as error:
        report['error'] = repr(error);(out / 'failure.txt').write_text(traceback.format_exc());raise
    finally:save()
    print(json.dumps({key: value for key, value in report.items() if key not in ('cases', 'executables')}, sort_keys=True))


if __name__ == '__main__':
    main()
