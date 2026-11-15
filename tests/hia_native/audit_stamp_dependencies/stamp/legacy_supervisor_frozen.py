# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification-only syscall observer for one explicitly forked fixture owner.

Only this process's direct child is traced. Unselected syscalls run unchanged.
Short controls reduce the real read/write/getrandom request; they never synthesize
file bytes or entropy. Close-error controls let the kernel retire the descriptor first.
"""
from pathlib import Path
import argparse
import ctypes
import errno
import hashlib
import json
import os
import signal
import stat
import sys
import time
import traceback


class Registers(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        'r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax',
        'rcx', 'rdx', 'rsi', 'rdi', 'orig_rax', 'rip', 'cs', 'eflags', 'rsp', 'ss',
        'fs_base', 'gs_base', 'ds', 'es', 'fs', 'gs')]


def signed(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def descriptor(value):
    value &= 0xffffffff
    return value - (1 << 32) if value >= 1 << 31 else value


def target(pid, descriptor):
    try:
        low = descriptor & 0xffffffff
        low = low - (1 << 32) if low >= 1 << 31 else low
        return os.readlink(f'/proc/{pid}/fd/{low}')
    except FileNotFoundError:
        return None


def cstring(pid, pointer):
    descriptor = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
    try:
        data = os.pread(descriptor, 4096, pointer)
    finally:
        os.close(descriptor)
    assert b'\0' in data
    return os.fsdecode(data.split(b'\0', 1)[0])


def path_at(pid, directory, pointer):
    name = cstring(pid, pointer)
    if name.startswith('/'):
        return name
    base = os.readlink(f'/proc/{pid}/cwd') if descriptor(directory) == -100 else target(pid, directory)
    return None if base is None else os.path.join(base, name) if name else base


def held_files(pid, fixture):
    result = []
    for entry in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            name = os.readlink(entry)
            if name != str(fixture) and not name.startswith(str(fixture) + '/'):
                continue
            value = entry.stat()
            result.append(dict(target=name[len(str(fixture)):], mode=value.st_mode,
                uid=value.st_uid, gid=value.st_gid, links=value.st_nlink))
        except FileNotFoundError:
            pass
    return sorted(result, key=lambda item: (item['target'], item['mode'], item['links']))


ARCHIVE = 'request-archive-v11'
ANCHOR = '.request-archive-v11-anchor.json'


def memory(pid, pointer, count):
    fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
    try:
        value = os.pread(fd, count, pointer)
        assert len(value) == count
        return value
    finally:
        os.close(fd)


def libc_startup_callsite(pid, registers):
    pointer = int(registers.rip)
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        low, high = (int(part, 16) for part in fields[0].split('-'))
        if low <= pointer - 2 and pointer < high:
            assert len(fields) == 6 and 'x' in fields[1]
            path = Path(fields[5])
            assert path.name == 'libc.so.6' and path.is_file() and not fields[5].endswith(' (deleted)')
            image = path.read_bytes()
            offset = int(fields[2], 16) + pointer - low
            assert memory(pid, pointer - 2, 2) == image[offset - 2:offset] == b'\x0f\x05'
            return dict(image_path=str(path), image_bytes=len(image), image_sha256=hashlib.sha256(image).hexdigest(),
                return_file_offset=offset, instruction_hex=image[max(0, offset - 32):offset + 32].hex(),
                mapping_permissions=fields[1], observed_before_fixture_root_open=True)
    raise AssertionError('startup getrandom instruction has no verified libc executable mapping')


def classify(pid, registers, fixture, roles):
    number = int(registers.orig_rax)
    fd = descriptor(registers.rdi)
    role = roles.get(fd)
    event = dict(syscall=number)
    if number == 318:
        size, flags = int(registers.rsi), int(registers.rdx)
        if (size, flags) == (8, 1):
            assert 'root' not in roles.values(), 'libc startup entropy is not a business-effect domain'
            return dict(event, kind='libc_startup_random', requested_bytes=size, flags=flags,
                        fault_domain=False, callsite=libc_startup_callsite(pid, registers))
        if (size, flags) == (16, 4):
            return dict(event, kind='standard_library_seed', requested_bytes=size, flags=flags,
                        fault_domain=False, profile='rust-1.95.0-hashmap-16-GRND_INSECURE')
        assert flags == 0 and 0 <= size <= 32, ('unexpected getrandom domain', size, flags)
        return dict(event, kind='entropy_probe' if size == 0 else 'entropy_fill',
                    requested_bytes=size, flags=flags, fault_domain=True)
    if number == 294:
        return dict(event, kind='events_init', flags=int(registers.rdi))
    if number == 254 and role == 'events':
        path = cstring(pid, registers.rsi)
        assert path.startswith('/proc/self/fd/') and path.rsplit('/', 1)[1].isdigit()
        pinned = int(path.rsplit('/', 1)[1])
        assert roles.get(pinned) in ('pin', 'legacy')
        return dict(event, kind='watch_add', mask=int(registers.rdx), target=target(pid, pinned))
    if number == 255 and role == 'events':
        return dict(event, kind='watch_remove', wd=descriptor(registers.rsi))
    if number in (0, 17) and role in ('events', 'anchor', 'urandom'):
        return dict(event, kind=role + '_read', requested_bytes=int(registers.rdx),
                    offset=int(registers.r10) if number == 17 else None)
    if number == 1 and role == 'temporary':
        return dict(event, kind='temporary_write', requested_bytes=int(registers.rdx))
    if number == 7 and int(registers.rsi) == 1:
        import struct
        polled, events, revents = struct.unpack('<ihh', memory(pid, registers.rdi, 8))
        if roles.get(polled) == 'random':
            return dict(event, kind='random_poll', events=events, revents=revents,
                        timeout=descriptor(registers.rdx))
    if number in (2, 257):
        if number == 2:
            name = cstring(pid, registers.rdi)
            path = name if name.startswith('/') else str(Path(os.readlink(f'/proc/{pid}/cwd')) / name)
            flags, directory = int(registers.rsi), -100
        else:
            name = cstring(pid, registers.rsi)
            path = path_at(pid, registers.rdi, registers.rsi)
            flags, directory = int(registers.rdx), fd
        if path == str(fixture) and directory == -100:
            return dict(event, kind='root_open', flags=flags)
        if path in ('/dev/random', '/dev/urandom') and directory == -100:
            return dict(event, kind=path[5:] + '_open', flags=flags)
        if role == 'root' and number == 257:
            if name == ARCHIVE:
                return dict(event, kind='legacy_open', flags=flags, name=name)
            if name == ANCHOR:
                return dict(event, kind='anchor_open', flags=flags, name=name)
            if name.startswith('.archive-anchor-') and name.endswith('.tmp'):
                suffix = name[16:-4]
                assert len(suffix) == 64 and all(c in '0123456789abcdef' for c in suffix)
                return dict(event, kind='temporary_open', flags=flags, name=name)
        if role == 'legacy' and name == '.':
            return dict(event, kind='scan_open', flags=flags, name=name)
    if number == 258 and role == 'root':
        name = cstring(pid, registers.rsi)
        assert name == ARCHIVE
        return dict(event, kind='archive_mkdir', name=name, mode=int(registers.rdx))
    if number == 74 and role in ('root', 'temporary'):
        return dict(event, kind=role + '_sync')
    if number == 265 and role == 'root':
        source, destination = cstring(pid, registers.rsi), cstring(pid, registers.r10)
        assert roles.get(descriptor(registers.rdx)) == 'root' and destination == ANCHOR
        assert source.startswith('.archive-anchor-') and source.endswith('.tmp')
        return dict(event, kind='anchor_link', source=source, destination=destination, flags=int(registers.r8))
    if number == 263 and role == 'root':
        name = cstring(pid, registers.rsi)
        assert name.startswith('.archive-anchor-') and name.endswith('.tmp')
        return dict(event, kind='temporary_unlink', name=name, flags=int(registers.rdx))
    if number == 72:
        if role == 'legacy' and registers.rsi == 1030:
            return dict(event, kind='pin_duplicate', minimum=int(registers.rdx))
        if role == 'scan' and registers.rsi == 3:
            return dict(event, kind='scan_flags', argument=int(registers.rdx))
    if number == 3 and role is not None:
        return dict(event, kind=role + '_close')
    if number == 217 and role == 'scan':
        return dict(event, kind='scan_read', requested_bytes=int(registers.rdx))
    if number == 5 and role in ('root', 'legacy', 'anchor', 'scan', 'pin'):
        return dict(event, kind=role + '_metadata')
    if number in (262, 332):
        flags = registers.r10 if number == 262 else registers.rdx
        probe = (registers.rdi == 0 and registers.rsi == 0 and flags == 0
                 and ((number == 332 and registers.r10 == 4095 and registers.r8 == 0) or number == 262))
        if probe and 'root' in roles.values():
            return dict(event, kind='statx_probe' if number == 332 else 'statat_probe',
                        metadata_flags=0, metadata_null_path=True,
                        metadata_null_buffer=(registers.r8 if number == 332 else registers.rdx) == 0)
        if role in ('root', 'legacy', 'anchor', 'scan', 'pin') and flags & 4096:
            return dict(event, kind=role + '_metadata', metadata_flags=int(flags),
                        metadata_null_path=registers.rsi == 0)
        if role == 'root' and flags == 256 and cstring(pid, registers.rsi) == ANCHOR:
            return dict(event, kind='anchor_named', metadata_flags=int(flags), metadata_null_path=False)
    return None


def track_roles(roles, event, registers, actual_result):
    kind = event['kind']
    if actual_result >= 0:
        if kind.endswith('_open') or kind in ('events_init', 'pin_duplicate'):
            role = {'events_init': 'events', 'pin_duplicate': 'pin'}.get(kind, kind[:-5])
            roles[actual_result] = role
        elif kind.endswith('_close'):
            roles.pop(descriptor(registers.rdi), None)


def mutate(fixture, mutation, event):
    from test_legacy import ARCHIVE, ANCHOR, write_anchor
    action = mutation['action']
    if action == 'unlink-anchor':
        (fixture / ANCHOR).unlink()
    elif action == 'replace-archive':
        (fixture / ARCHIVE).rename(fixture / 'old-archive')
        (fixture / ARCHIVE).mkdir(mode=0o700)
    elif action == 'create-anchor':
        write_anchor(fixture)
    elif action == 'create-temporary-collision':
        assert event['kind'] == 'temporary_open'
        path = fixture / event['name']
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            assert os.write(descriptor, b'other-writer-owned') == 18
        finally:
            os.close(descriptor)
    else:
        raise AssertionError(mutation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('fixture', 'config', 'log'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    fixture = args.fixture.resolve(strict=True)
    assert len(command) == 2 and Path(command[1]).resolve(strict=True) == fixture
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    config = json.loads(args.config.read_bytes())
    assert set(config) == {'faults'}
    assert all(row['kind'] not in ('standard_library_seed', 'libc_startup_random') for row in config['faults'])
    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    parent = os.getpid()
    pid = os.fork()
    if pid == 0:
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os.write(2, ('owned parent-death guard failed: errno=' + str(ctypes.get_errno()) + '\n').encode())
            os._exit(75)
        if libc.ptrace(0, 0, 0, 0) != 0:
            os.write(2, ('owned PTRACE_TRACEME refused: errno=' + str(ctypes.get_errno()) + '\n').encode())
            os._exit(75)
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execve(command[0], command, dict(os.environ, PATH=''))
    args.log.with_suffix('.pid').write_text(str(pid))
    report = dict(schema='hepta.audit-legacy-owned-kernel-observer.v1', status='FAIL',
        command=command, pid=pid, configuration=config, direct_owned_child_only=True,
        semantic_emulation=False, events=[])
    started = time.monotonic()
    wait_status, entering, pending = None, True, None
    counts, fired, roles = {}, set(), {}

    def trace(request, address=0, data=0):
        ctypes.set_errno(0)
        result = libc.ptrace(request, pid, address, data)
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(), 'owned ptrace')
        return result

    def registers():
        value = Registers()
        trace(12, 0, ctypes.byref(value))
        return value

    def next_stop():
        nonlocal wait_status
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    wait_status = status
                return status
            if time.monotonic() - started >= args.timeout:
                raise TimeoutError('owned legacy child deadline')
            time.sleep(0.0001)

    try:
        status = next_stop()
        assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP, ('owned startup status', status)
        trace(0x4200, 0, 1 | 16 | (1 << 20))
        trace(24)
        while True:
            status = next_stop()
            if wait_status is not None:
                break
            assert os.WIFSTOPPED(status)
            stop_signal, event_code = os.WSTOPSIG(status), status >> 16
            if stop_signal == signal.SIGTRAP and event_code == 4:
                trace(24)
                continue
            if stop_signal != signal.SIGTRAP | 0x80:
                trace(24, 0, stop_signal)
                continue
            value = registers()
            if entering:
                pending = None
                event = classify(pid, value, fixture, roles)
                if event is not None:
                    kind = event['kind']
                    counts[kind] = counts.get(kind, 0) + 1
                    event.update(ordinal=counts[kind], completion='kernel_continue',
                                 held_files=held_files(pid, fixture))
                    selected = [(index, fault) for index, fault in enumerate(config['faults'])
                        if index not in fired and kind == fault['kind'] and counts[kind] == fault.get('ordinal', 1)]
                    assert len(selected) <= 1
                    fault = selected[0][1] if selected else None
                    if fault is not None:
                        fired.add(selected[0][0])
                        assert sum(key in fault for key in ('errno', 'short_limit', 'zero', 'mutation', 'kill')) == 1
                        if 'errno' in fault:
                            assert 0 < fault['errno'] < 4096
                            if kind.endswith('_close'):
                                event['completion'] = 'actual_kernel_close_then_injected_errno'
                            else:
                                value.orig_rax = (1 << 64) - 1
                                trace(13, 0, ctypes.byref(value))
                                event['completion'] = 'injected_errno_before_kernel_effect'
                        elif 'short_limit' in fault:
                            assert kind in ('events_read', 'scan_read', 'anchor_read', 'urandom_read', 'temporary_write', 'entropy_fill')
                            size = value.rsi if kind == 'entropy_fill' else value.rdx
                            assert 0 < fault['short_limit'] < size
                            if kind == 'entropy_fill': value.rsi = fault['short_limit']
                            else: value.rdx = fault['short_limit']
                            trace(13, 0, ctypes.byref(value))
                            event.update(completion='bounded_actual_kernel_transfer', actual_request_bytes=fault['short_limit'])
                        elif fault.get('zero'):
                            assert kind in ('events_read', 'scan_read', 'anchor_read', 'urandom_read', 'temporary_write')
                            value.orig_rax = (1 << 64) - 1
                            trace(13, 0, ctypes.byref(value))
                            event['completion'] = 'injected_zero_without_bytes'
                        elif 'mutation' in fault:
                            if not fault.get('after'): mutate(fixture, fault['mutation'], event)
                            event['completion'] = ('mutated_owned_fixture_after_kernel_effect' if fault.get('after')
                                else 'mutated_owned_fixture_before_kernel_effect')
                        elif fault.get('kill'):
                            assert fault.get('after') is True
                            event['completion'] = 'actual_sigkill_after_completed_kernel_effect'
                        else:
                            raise AssertionError(fault)
                    report['events'].append(event)
                    pending = (event, fault)
                entering = False
            else:
                if pending is not None:
                    event, fault = pending
                    event['actual_kernel_result'] = signed(value.rax)
                    track_roles(roles, event, value, signed(value.rax))
                    if fault is not None:
                        if 'errno' in fault:
                            if event['kind'].endswith('_close'):
                                assert signed(value.rax) == 0, 'close fault must follow actual kernel retirement'
                            value.rax = (1 << 64) - fault['errno']
                            trace(13, 0, ctypes.byref(value))
                        elif fault.get('zero'):
                            value.rax = 0
                            trace(13, 0, ctypes.byref(value))
                        elif 'short_limit' in fault:
                            assert -4095 <= signed(value.rax) <= fault['short_limit']
                        elif 'mutation' in fault and fault.get('after'):
                            mutate(fixture, fault['mutation'], event)
                    event['delivered_result'] = signed(value.rax)
                    if fault is not None and (fault.get('kill') or fault.get('kill_after')):
                        assert signed(value.rax) >= 0
                        os.kill(pid, signal.SIGKILL)
                        ended, wait_status = os.waitpid(pid, 0)
                        assert ended == pid and os.WIFSIGNALED(wait_status) and os.WTERMSIG(wait_status) == signal.SIGKILL
                        event.update(actual_sigkill_sent=True, actual_sigkill_reaped=True)
                        break
                pending = None
                entering = True
            trace(24)
        assert fired == set(range(len(config['faults']))), (fired, config)
        assert counts.get('standard_library_seed', 0) <= 1
        assert counts.get('libc_startup_random', 0) <= 1
        report.update(status='PASS', counts=counts, all_selected_faults_reached=True,
            exit_code=os.waitstatus_to_exitcode(wait_status), child_reaped=True)
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        if wait_status is None:
            os.kill(pid, signal.SIGKILL)
            _, wait_status = os.waitpid(pid, 0)
        report.update(child_reaped=True, exit_code=os.waitstatus_to_exitcode(wait_status),
                      elapsed_seconds=time.monotonic() - started)
        args.log.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    code = os.waitstatus_to_exitcode(wait_status)
    raise SystemExit(128 - code if code < 0 else code)


if __name__ == '__main__':
    main()


