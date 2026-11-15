# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Qualification-only syscall observer for one explicitly forked fixture owner.

Only this process's direct child is traced. Unselected syscalls run unchanged.
Short-read controls reduce the real read/pread request; they never synthesize
file bytes. Close-error controls let the kernel retire the descriptor first.
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


def classify(pid, registers, fixture, roles):
    number = int(registers.orig_rax)
    fd = descriptor(registers.rdi)
    role = roles.get(fd)
    event = dict(syscall=number)
    if number == 294:
        return dict(event, kind='events_init', flags=int(registers.rdi))
    if number == 254 and role == 'events':
        path = cstring(pid, registers.rsi)
        assert path.startswith('/proc/self/fd/') and path.rsplit('/', 1)[1].isdigit()
        pin = int(path.rsplit('/', 1)[1]);assert roles.get(pin) in ('pin', 'root', 'borrow')
        return dict(event, kind='watch_add', mask=int(registers.rdx), target=target(pid, pin))
    if number == 255 and role == 'events':
        return dict(event, kind='watch_remove', wd=signed(registers.rsi & 0xffffffff))
    if number == 0 and role == 'events':
        return dict(event, kind='events_read', requested_bytes=int(registers.rdx))
    if number == 257:
        path = path_at(pid, registers.rdi, registers.rsi)
        if path == str(fixture) and fd == -100:
            return dict(event, kind='root_open', flags=int(registers.rdx))
        if role in ('root', 'borrow'):
            name = cstring(pid, registers.rsi)
            if name == '.':
                return dict(event, kind='scan_open', flags=int(registers.rdx), name=name)
            if len(name) == 4 and name[0] == 'd' and name[1:].isdigit():
                return dict(event, kind='borrow_open', flags=int(registers.rdx), name=name)
    if number == 72:
        if role in ('root', 'borrow') and registers.rsi == 1030:
            return dict(event, kind='pin_duplicate', minimum=int(registers.rdx))
        if role == 'scan' and registers.rsi == 3:
            return dict(event, kind='scan_flags', argument=int(registers.rdx))
    if number == 3 and role is not None:
        return dict(event, kind=role + '_close')
    if number == 217 and role == 'scan':
        return dict(event, kind='scan_read', requested_bytes=int(registers.rdx))
    if number == 5 and role in ('root', 'borrow', 'scan'):
        return dict(event, kind='scan_metadata' if role == 'scan' else 'held_metadata')
    if number in (262, 332):
        flags = registers.r10 if number == 262 else registers.rdx
        probe = (registers.rdi == 0 and registers.rsi == 0 and flags == 0
                 and ((number == 332 and registers.r10 == 4095 and registers.r8 == 0) or number == 262))
        if probe and 'root' in roles.values():
            return dict(event, kind='statx_probe' if number == 332 else 'statat_probe',
                        metadata_flags=0, metadata_null_path=True,
                        metadata_null_buffer=(registers.r8 if number == 332 else registers.rdx) == 0)
        if role in ('root', 'borrow') and flags & 4096:
            return dict(event, kind='held_metadata', metadata_flags=int(flags),
                        metadata_null_path=registers.rsi == 0)
    return None


def track_roles(roles, event, registers, actual_result):
    kind = event['kind']
    if actual_result >= 0:
        if kind in ('root_open', 'borrow_open', 'scan_open', 'events_init', 'pin_duplicate'):
            roles[actual_result] = {'root_open':'root', 'borrow_open':'borrow', 'scan_open':'scan',
                                    'events_init':'events', 'pin_duplicate':'pin'}[kind]
        elif kind.endswith('_close'):
            roles.pop(descriptor(registers.rdi), None)


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
    report = dict(schema='hepta.namespace-owned-kernel-observer.v1', status='FAIL',
        command=command, pid=pid, configuration=config, direct_owned_child_only=True,
        semantic_emulation=False, events=[])
    started = time.monotonic()
    wait_status, stopped, entering, pending = None, False, True, None
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
                raise TimeoutError('owned namespace child deadline')
            time.sleep(0.0001)

    try:
        status = next_stop()
        assert os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP, ('owned startup status', status)
        trace(0x4200, 0, 1 | 16 | (1 << 20))  # TRACESYSGOOD, TRACEEXEC, EXITKILL.
        trace(24)
        while True:
            status = next_stop()
            if wait_status is not None:
                break
            assert os.WIFSTOPPED(status)
            stop_signal = os.WSTOPSIG(status)
            event_code = status >> 16
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
                    selected = []
                    for index, fault in enumerate(config['faults']):
                        if index not in fired and kind == fault['kind'] and counts[kind] == fault.get('ordinal', 1):
                            fired.add(index)
                            selected.append(fault)
                    assert len(selected) <= 1
                    fault = selected[0] if selected else None
                    if fault is not None:
                        if 'errno' in fault:
                            assert 0 < fault['errno'] < 4096
                            if kind.endswith('_close'):
                                event['completion'] = 'actual_kernel_close_then_injected_errno'
                            else:
                                value.orig_rax = (1 << 64) - 1
                                trace(13, 0, ctypes.byref(value))
                                event['completion'] = 'injected_errno_before_kernel_effect'
                        elif 'short_limit' in fault:
                            assert kind in ('events_read', 'scan_read')
                            assert 0 < fault['short_limit'] < value.rdx
                            value.rdx = fault['short_limit']
                            trace(13, 0, ctypes.byref(value))
                            event.update(completion='bounded_actual_kernel_read', actual_request_bytes=value.rdx)
                        elif fault.get('zero'):
                            assert kind in ('events_read', 'scan_read')
                            value.orig_rax = (1 << 64) - 1
                            trace(13, 0, ctypes.byref(value))
                            event['completion'] = 'injected_eof_without_file_bytes'
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
                                assert signed(value.rax) == 0, 'close fault must follow a real successful retirement'
                            value.rax = (1 << 64) - fault['errno']
                            trace(13, 0, ctypes.byref(value))
                        elif fault.get('zero'):
                            value.rax = 0
                            trace(13, 0, ctypes.byref(value))
                        elif 'short_limit' in fault:
                            assert -4095 <= signed(value.rax) <= fault['short_limit']
                    event['delivered_result'] = signed(value.rax)
                pending = None
                entering = True
            trace(24)
        assert fired == set(range(len(config['faults']))), (fired, config)
        report.update(status='PASS', counts=counts, all_selected_faults_reached=True,
            exit_code=os.waitstatus_to_exitcode(wait_status), child_reaped=True)
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc())
        raise
    finally:
        if wait_status is None:
            os.kill(pid, signal.SIGKILL)
            _, wait_status = os.waitpid(pid, 0)
            report['child_reaped'] = True
            report['exit_code'] = os.waitstatus_to_exitcode(wait_status)
        report['child_reaped'] = True
        report['exit_code'] = os.waitstatus_to_exitcode(wait_status)
        report['elapsed_seconds'] = time.monotonic() - started
        args.log.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    code = os.waitstatus_to_exitcode(wait_status)
    raise SystemExit(128 - code if code < 0 else code)


if __name__ == '__main__':
    main()
