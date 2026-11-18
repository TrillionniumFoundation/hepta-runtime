#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Hold one actual owned worker syscall while its native parent deadline runs.

This is a test-only seccomp notification hold, distinct from the separate
empty-pipe kernel-block probe. Ordinary calls continue in the kernel. The
supervisor computes no file result, digest, HIA completion or MCP response.
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
import time

ROOT = Path(os.environ.get('HIA_RUNTIME_REPO', Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(ROOT / 'tests/hia_native'))
from io_fault_supervisor import Filter, Program, Notification, Response


def process_identity(pid):
    try:
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        return {'state': fields[0], 'start_ticks': int(fields[19])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--held-state', required=True, type=Path)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--mode', required=True, choices=('read', 'flistxattr', 'map_failure',
                        'pipe_failure', 'fork_failure', 'clock_failure', 'pdeath_failure', 'closed_stderr'))
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert len(command) == 3 and command[1] == '--local-read-profile'
    root = Path(command[2])
    relative = args.fixture.relative_to(root)
    assert root.is_dir() and args.fixture.is_file()
    assert ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
    retained_root = root.with_name(root.name + '.retained')
    assert not retained_root.exists()
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
            instructions = [Filter(0x20, 0, 0, 0)]
            for number in (0, 3, 5, 9, 57, 157, 196, 228, 257, 293):
                instructions.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)])
            instructions.append(Filter(0x06, 0, 0, 0x7fff0000))
            filters = (Filter * len(instructions))(*instructions)
            program = Program(len(instructions), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), 'seccomp notification unavailable')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            if args.mode == 'closed_stderr':
                os.close(2)
            os.execve(command[0], command, dict(os.environ))
        except BaseException as error:
            os.write(2, (str(error) + '\n').encode())
            os._exit(75)
    child.close()
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise RuntimeError('owned service could not install seccomp notification')
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    parent.close()
    descriptors = array.array('i')
    descriptors.frombytes(ancillary[0][2][:4])
    listener = descriptors[0]
    args.held_state.write_text(json.dumps({'service': pid, 'mode': args.mode,
                                         'stderr_closed': args.mode == 'closed_stderr'}, sort_keys=True) + '\n')
    events = []
    file_owners, stated_fds = set(), set()
    reads = {}
    pending = None
    held_once = False
    fault_injected = False
    wait_status = None
    try:
        while True:
            if pending is not None:
                identity = ctypes.c_uint64(pending['notification'])
                if libc.ioctl(listener, 0x40082102, ctypes.byref(identity)):
                    error = ctypes.get_errno()
                    if error == errno.ENOENT:
                        events.append({'event': 'held_notification_cancelled', 'worker': pending['worker'],
                                       'at_monotonic': time.monotonic()})
                        pending = None
                    elif error != errno.EINTR:
                        raise OSError(error, 'SECCOMP_IOCTL_NOTIF_ID_VALID')
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                wait_status = status
                break
            if not select.select([listener], [], [], .05)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
            answer = Response(note.id, 0, 0, 1)
            if 0x400000 <= note.data.ip < 0x500000:
                nr = note.data.nr
                owner = int(note.pid)
                descriptor = int(note.data.args[0])
                selected_fault = (
                    (args.mode == 'map_failure' and nr == 9 and owner == pid
                     and note.data.args[1] == 8523776 and note.data.args[3] == 0x21)
                    or (args.mode == 'pipe_failure' and nr == 293 and owner == pid)
                    or (args.mode == 'fork_failure' and nr == 57 and owner == pid)
                    or (args.mode == 'clock_failure' and nr == 228 and owner == pid and descriptor == 1)
                    or (args.mode == 'pdeath_failure' and nr == 157 and owner != pid
                        and descriptor == 1 and note.data.args[1] == 9))
                if selected_fault and not fault_injected:
                    error = {'map_failure': errno.ENOMEM, 'pipe_failure': errno.EMFILE,
                             'fork_failure': errno.EAGAIN, 'clock_failure': errno.EIO,
                             'pdeath_failure': errno.EPERM}[args.mode]
                    answer.error = -error
                    answer.flags = 0
                    fault_injected = True
                    event = {'event': 'guard_setup_fault', 'mode': args.mode,
                             'syscall': nr, 'owner': owner, 'error': error}
                    events.append(event)
                    marker = dict(event, service=pid, kind='injected guard syscall errno')
                    if owner != pid:
                        identity = process_identity(owner)
                        if identity is None:
                            raise RuntimeError('owned worker vanished before setup fault')
                        marker.update(worker=owner, worker_start_ticks=identity['start_ticks'])
                    args.held_state.write_text(json.dumps(marker, sort_keys=True) + '\n')
                if nr == 257 and note.data.args[2] == 0xa0800:
                    file_owners.add(owner)
                    events.append({'event': 'admitted_file_open', 'owner': owner})
                if nr == 5:
                    stated_fds.add((owner, descriptor))
                if nr == 3:
                    stated_fds.discard((owner, descriptor))
                file_read = nr == 0 and owner in file_owners and (owner, descriptor) in stated_fds
                if file_read:
                    reads[owner] = reads.get(owner, 0) + 1
                    events.append({'event': 'file_read', 'owner': owner,
                                   'read_number': reads[owner], 'capacity': int(note.data.args[2])})
                selected = ((args.mode == 'read' and file_read and reads[owner] == 2)
                            or (args.mode == 'flistxattr' and nr == 196
                                and owner in file_owners and (owner, descriptor) in stated_fds))
                if selected and not held_once:
                    if owner == pid:
                        raise RuntimeError('inspection effect did not run in a separate native worker')
                    identity = process_identity(owner)
                    if identity is None:
                        raise RuntimeError('owned inspection worker vanished before hold')
                    root.rename(retained_root)
                    root.mkdir()
                    replacement = root / relative
                    replacement.parent.mkdir(parents=True, exist_ok=True)
                    replacement.write_bytes(b'replacement root must never become authorized')
                    pending = {'notification': int(note.id), 'worker': owner}
                    held_once = True
                    marker = {**pending, 'service': pid, 'worker_start_ticks': identity['start_ticks'],
                              'syscall': nr, 'mode': args.mode, 'held_at_monotonic': time.monotonic(),
                              'root_rebound': True, 'kind': 'actual syscall held by kernel notification'}
                    args.held_state.write_text(json.dumps(marker, sort_keys=True) + '\n')
                    events.append({'event': 'held_worker_syscall', **marker})
                    # No response is supplied. The real native parent must
                    # cancel this owned worker and produce its own HIA result.
                    continue
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(answer)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_SEND')
    finally:
        os.close(listener)
        if wait_status is None:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            _, wait_status = os.waitpid(pid, 0)
        args.log.write_text(json.dumps({'events': events, 'held_once': held_once, 'fault_injected': fault_injected,
                                       'service_exit': os.waitstatus_to_exitcode(wait_status)},
                                      sort_keys=True) + '\n')
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))


if __name__ == '__main__':
    main()
