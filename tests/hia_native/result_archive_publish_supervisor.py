# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Qualification only: supervise direct syscalls of one owned native child.

The child installs an unprivileged seccomp notification filter before exec.
Ordinary operations continue in the kernel. Selected tests inject EINTR or
change their own temporary fixture just before a read. No file-read semantics
or native output are implemented by this supervisor.
"""
import argparse
import array
import ctypes
import errno
import json
import os
from pathlib import Path
import select
import socket
import sys
import signal
import resource
import time
import hashlib
import traceback

class Filter(ctypes.Structure):
    _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),("jf",ctypes.c_ubyte),("k",ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_=[("length",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
class Data(ctypes.Structure):
    _fields_=[("nr",ctypes.c_int),("arch",ctypes.c_uint),("ip",ctypes.c_uint64),("args",ctypes.c_uint64*6)]
class Notification(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("pid",ctypes.c_uint),("flags",ctypes.c_uint),("data",Data)]
class Response(ctypes.Structure):
    _fields_=[("id",ctypes.c_uint64),("value",ctypes.c_int64),("error",ctypes.c_int),("flags",ctypes.c_uint)]

def signed(value):
    return value - (1 << 64) if value >= 1 << 63 else value


def cstring(pid, pointer):
    if pointer == 0:return ''
    fd = os.open('/proc/' + str(pid) + '/mem', os.O_RDONLY | os.O_CLOEXEC)
    try:
        raw = os.pread(fd, 4096, pointer)
        assert b'\0' in raw
        return os.fsdecode(raw.split(b'\0', 1)[0])
    finally:os.close(fd)


def descriptor(pid, number):
    try:return os.readlink('/proc/' + str(pid) + '/fd/' + str(signed(number)))
    except FileNotFoundError:return None


def path_at(pid, directory, pointer):
    path = cstring(pid, pointer)
    if path.startswith('/'):return path
    base = os.readlink('/proc/' + str(pid) + '/cwd') if signed(directory) == -100 else descriptor(pid, directory)
    if base is None:return None
    return os.path.join(base, path) if path else base


def classify(note, fixture):
    number, args, pid = note.data.nr, note.data.args, note.pid
    path = None;action = None
    if number == 257:
        path = path_at(pid, args[0], args[1]);action = 'open'
    elif number in (5, 0, 1, 3, 74):
        path = descriptor(pid, args[0]);action = {5: 'stat', 0: 'read', 1: 'write', 3: 'close', 74: 'sync'}[number]
    elif number in (262, 332):
        path = path_at(pid, args[0], args[1]);action = 'stat'
    elif number in (263, 264, 265):
        path = path_at(pid, args[0], args[1]);action = {263: 'unlink', 264: 'rename', 265: 'link'}[number]
    if path is None:return None
    deleted = path.endswith(' (deleted)')
    if deleted:path = path[:-10]
    if path == '/dev/urandom':role = 'random';name = path
    elif path == str(fixture):role = 'directory';name = '.'
    elif path.startswith(str(fixture) + '/'):
        name = path[len(str(fixture)) + 1:]
        role = 'temporary' if name.endswith('.tmp') else 'record' if name.endswith('.json') else 'other'
    else:return None
    event = dict(kind=action + '_' + role, syscall=number, name=name, descriptor_deleted=deleted)
    if number in (0, 1):event['requested_bytes'] = int(args[2])
    if number == 257:event.update(flags=int(args[2]), mode=int(args[3]))
    if number == 1:
        value = os.stat('/proc/' + str(pid) + '/fd/' + str(args[0]))
        event['file_bytes_before_kernel_write'] = value.st_size
        if value.st_size:
            with open('/proc/' + str(pid) + '/fd/' + str(args[0]), 'rb') as file:
                raw = file.read(98305)
            event['file_sha256_before_kernel_write'] = hashlib.sha256(raw).hexdigest()
    return event


def mutate(fixture, mutation, event):
    from result_archive_metadata_cases import ANCHOR, MARKER, encoded
    action = mutation['action']
    if action == 'create_temporary':
        assert event['kind'] == 'open_temporary'
        path = fixture / event['name'];raw = b'concurrent temporary'
    elif action == 'create_anchor':
        path = fixture / ANCHOR;raw = b'other anchored history'
    elif action == 'remove_temporary':
        assert event['kind'] == 'link_temporary'
        (fixture / event['name']).unlink();return
    elif action == 'create_marker':
        path = fixture / MARKER
        raw = encoded(dict(schema=2, anchor_sha256=mutation.get('binding', 'a1' * 32)))
    else:raise AssertionError(mutation)
    with path.open('xb') as file:file.write(raw)
    path.chmod(0o600)


def child_bytes(pid, address, size):
    with open('/proc/' + str(pid) + '/mem', 'rb', buffering=0) as memory:
        raw = os.pread(memory.fileno(), size, address)
    assert len(raw) == size
    return raw


def held_files(pid, fixture):
    result = []
    for entry in (Path('/proc') / str(pid) / 'fd').iterdir():
        try:target = os.readlink(entry)
        except FileNotFoundError:continue
        if target.startswith(str(fixture) + '/'):
            value = entry.stat()
            result.append(dict(descriptor=int(entry.name), path=target[len(str(fixture)) + 1:],
                device=value.st_dev, inode=value.st_ino, links=value.st_nlink, bytes=value.st_size))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('fixture', 'config', 'log'):parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    fixture = args.fixture.resolve(strict=True)
    assert len(command) == 2 and Path(command[1]).resolve(strict=True) == fixture
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    config = json.loads(args.config.read_bytes())
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    libc = ctypes.CDLL(None, use_errno=True)
    expected_parent = os.getpid()
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if 'file_size_limit' in config:
                limit = config['file_size_limit'];resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            if libc.prctl(1, 9, 0, 0, 0):raise OSError(ctypes.get_errno(), 'PR_SET_PDEATHSIG')
            if os.getppid() != expected_parent:os._exit(75)
            if libc.prctl(38, 1, 0, 0, 0):raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
            rows = [Filter(0x20, 0, 0, 0)]
            for number in (0, 1, 3, 5, 74, 257, 262, 263, 264, 265, 332):
                rows.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)])
            rows.append(Filter(0x06, 0, 0, 0x7fff0000))
            instructions = (Filter * len(rows))(*rows);program = Program(len(rows), instructions)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:raise OSError(ctypes.get_errno(), 'seccomp notification unavailable')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            os.execve(command[0], command, dict(os.environ, PATH=''))
        except BaseException as error:
            os.write(2, (str(error) + '\n').encode());os._exit(75)
    child.close()
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9);os.waitpid(pid, 0);raise RuntimeError('owned child could not install listener')
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4));parent.close()
    descriptors = array.array('i');descriptors.frombytes(ancillary[0][2][:4]);listener = descriptors[0]
    events = [];counts = {};fired = set();wait_status = None;started = time.monotonic()
    random_pointer = None;random_bytes = None;temporary_names = []
    report = dict(schema='hepta.request-archive.publish-kernel-observer.v1', status='FAIL', command=command,
        pid=pid, events=events, configuration=config, semantic_emulation=False)
    try:
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:wait_status = status;break
            assert time.monotonic() - started < args.timeout, 'owned kernel child deadline'
            if not select.select([listener], [], [], 0.02)[0]:continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):continue
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
            assert note.pid == pid
            answer = Response(note.id, 0, 0, 1)
            withheld = False
            event = classify(note, fixture)
            if event:
                kind = event['kind'];counts[kind] = counts.get(kind, 0) + 1
                event.update(ordinal=counts[kind], completion='kernel_continue')
                if kind == 'read_random':
                    random_pointer = int(note.data.args[1])
                    assert int(note.data.args[2]) == 32
                if kind == 'close_random' and random_pointer is not None:
                    random_bytes = child_bytes(pid, random_pointer, 32)
                    event['random_bytes_after_read'] = random_bytes.hex()
                if kind == 'open_temporary':
                    name = event['name']
                    assert random_bytes is not None and name == '.result-anchor-' + random_bytes.hex() + '.tmp'
                    assert name not in temporary_names
                    temporary_names.append(name)
                    event['name_equals_actual_random_bytes'] = True
                if kind in ('write_temporary', 'sync_temporary', 'link_temporary', 'unlink_temporary', 'sync_directory', 'close_temporary', 'write_record', 'sync_record'):
                    event['held_fixture_files'] = held_files(pid, fixture)

                for index, fault in enumerate(config.get('faults', [])):
                    if index in fired or kind != fault['kind'] or counts[kind] != fault.get('ordinal', 1):continue
                    fired.add(index)
                    if 'errno' in fault:
                        answer.error = -fault['errno'];answer.flags = 0;event['completion'] = 'injected_errno'
                    elif fault.get('zero_write'):
                        assert kind in ('write_temporary', 'write_record');answer.value = 0;answer.flags = 0;event['completion'] = 'injected_write_zero'
                    elif fault.get('zero_read'):
                        assert kind == 'read_random';answer.value = 0;answer.flags = 0;event['completion'] = 'injected_read_eof'
                    elif 'mutation' in fault:
                        mutate(fixture, fault['mutation'], event);event['completion'] = 'mutated_owned_fixture_then_kernel_continue'
                    elif fault.get('kill'):
                        # Keep the selected syscall blocked until the owned child dies.
                        # Continuing it after SIGKILL races signal delivery and can
                        # execute the very effect this crash boundary must exclude.
                        withheld = True
                        os.kill(pid, signal.SIGKILL);event['completion'] = 'killed_owned_child_before_kernel_effect'
                        event['notification_continuation_withheld'] = True
                    else:raise AssertionError(fault)
                events.append(event)
            if not withheld and libc.ioctl(listener, 0xc0182101, ctypes.byref(answer)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_SEND')
        assert fired == set(range(len(config.get('faults', [])))), (fired, config)
        report.update(status='PASS', counts=counts, all_selected_faults_reached=True,
            exit_code=os.waitstatus_to_exitcode(wait_status), child_reaped=True, temporary_names=temporary_names,
            actual_random_bytes_verified_before_each_temporary_open=True)
    except BaseException as error:
        report.update(error=repr(error), traceback=traceback.format_exc());raise
    finally:
        os.close(listener)
        if wait_status is None:
            os.kill(pid, 9);_, wait_status = os.waitpid(pid, 0)
        report['elapsed_seconds'] = time.monotonic() - started
        args.log.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    code = os.waitstatus_to_exitcode(wait_status)
    raise SystemExit(128 - code if code < 0 else code)


if __name__ == '__main__':
    main()
