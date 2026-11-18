#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Qualification only: inject faults/races into one owned static ELF's syscalls.

All ordinary calls continue in the kernel. No HIA result, digest, metadata or
MCP response is computed here. Only explicitly selected failures and mutations
of the supplied temporary fixture are introduced.
"""
import argparse, array, ctypes, errno, json, os, select, socket, sys
from pathlib import Path

sys.path.insert(0, str(Path(os.environ.get('HIA_RUNTIME_REPO', Path(__file__).resolve().parents[2])) / 'tests/hia_native'))
from io_fault_supervisor import Filter, Program, Notification, Response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--fixture', required=True, type=Path)
    parser.add_argument('--mode', required=True, choices=['eintr', 'hash_change', 'metadata_replace',
        'metadata_symlink', 'capture_gap', 'capture_change', 'parent_rebind', 'getxattr_error',
        'flistxattr_error', 'close_precedence'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert len(command) == 3 and command[1] == '--local-read-profile'
    assert ctypes.sizeof(Notification) == 80 and ctypes.sizeof(Response) == 24
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
            instructions = [Filter(0x20, 0, 0, 0)]
            for number in (0, 3, 5, 193, 196, 257):
                instructions.extend([Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)])
            instructions.append(Filter(0x06, 0, 0, 0x7fff0000))
            filters = (Filter * len(instructions))(*instructions)
            program = Program(len(instructions), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), 'seccomp notification unavailable')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            os.execve(command[0], command, dict(os.environ))
        except BaseException as error:
            os.write(2, (str(error) + '\n').encode())
            os._exit(75)
    child.close()
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise RuntimeError('owned child could not install seccomp notification')
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    parent.close()
    descriptors = array.array('i')
    descriptors.frombytes(ancillary[0][2][:4])
    listener = descriptors[0]
    events = []
    file_reads = stats = target_opens = failed_closes = 0
    file_owner = None
    stated_fds = set()
    read_failed = False
    wait_status = None
    try:
        while True:
            ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                wait_status = status
                break
            if not select.select([listener], [], [], .1)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
            answer = Response(note.id, 0, 0, 1)
            if 0x400000 <= note.data.ip < 0x500000:
                nr = note.data.nr
                event = dict(syscall=nr, mode='continue')
                descriptor = (int(note.pid), int(note.data.args[0]))
                if nr == 5:
                    stated_fds.add(descriptor)
                if nr == 3:
                    stated_fds.discard(descriptor)
                # A guarded inspection forks while the original service reads
                # its result pipe. Bind file reads to the owner observed at the
                # admitted file-open boundary, so IPC never becomes a fake file
                # read or consumes a selected fault. The unguarded prototype
                # simply observes the service itself as this owner.
                # The worker closes stdio, so a real file can reuse fd 0/1/2.
                if nr == 0 and descriptor in stated_fds and note.pid == file_owner:
                    file_reads += 1
                    event.update(count=int(note.data.args[2]), file_read=file_reads)
                    if file_reads == 1:
                        if args.mode == 'eintr':
                            answer.error = -errno.EINTR
                            answer.flags = 0
                            event['mode'] = 'injected_eintr'
                        elif args.mode == 'hash_change':
                            args.fixture.write_bytes(b'changed while hashing')
                            event['mode'] = 'changed_fixture_before_kernel_read'
                        elif args.mode == 'close_precedence':
                            answer.error = -errno.EIO
                            answer.flags = 0
                            read_failed = True
                            event['mode'] = 'injected_read_eio'
                if nr == 5:
                    stats += 1
                    event['stat'] = stats
                    if (args.mode, stats) in [('capture_gap', 6), ('capture_change', 7)]:
                        os.chmod(args.fixture, 0o2751)
                        event['mode'] = 'changed_mode_before_capture_stat'
                if nr == 257:
                    # This controlled session inspects one file. Distinguish
                    # file opens from directory walks by the admitted flags;
                    # no child address or private memory is read by the test.
                    if note.data.args[2] == 0xa0800:
                        target_opens += 1
                        if target_opens == 1:
                            file_owner = note.pid
                        if note.pid != file_owner:
                            raise RuntimeError('file inspection changed owner during one request')
                        event['target_open'] = target_opens
                        if target_opens == 2 and args.mode in ('metadata_replace', 'metadata_symlink'):
                            previous = args.fixture.with_name(args.fixture.name + '.previous')
                            args.fixture.rename(previous)
                            if args.mode == 'metadata_replace':
                                args.fixture.write_bytes(b'replacement')
                            else:
                                args.fixture.symlink_to(previous)
                            event['mode'] = 'replaced_name_before_metadata_reopen'
                        if target_opens == 2 and args.mode == 'parent_rebind':
                            old = args.fixture.parent
                            old.rename(old.with_name(old.name + '.previous'))
                            old.mkdir()
                            args.fixture.write_bytes(b'rebound pathname')
                            event['mode'] = 'rebound_parent_before_metadata_reopen'
                if nr in (193, 196) and args.mode == {193: 'getxattr_error', 196: 'flistxattr_error'}[nr]:
                    answer.error = -errno.EIO
                    answer.flags = 0
                    event['mode'] = 'injected_xattr_eio'
                if nr == 3 and read_failed and failed_closes < 2:
                    failed_closes += 1
                    answer.error = -[errno.EACCES, errno.EBADF][failed_closes - 1]
                    answer.flags = 0
                    event.update(mode='injected_finalizer_error', error=-answer.error)
                events.append(event)
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(answer)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_SEND')
    finally:
        os.close(listener)
        if wait_status is None:
            os.kill(pid, 9)
            _, wait_status = os.waitpid(pid, 0)
        args.log.write_text(json.dumps(events, sort_keys=True) + '\n')
    raise SystemExit(os.waitstatus_to_exitcode(wait_status))


if __name__ == '__main__':
    main()
