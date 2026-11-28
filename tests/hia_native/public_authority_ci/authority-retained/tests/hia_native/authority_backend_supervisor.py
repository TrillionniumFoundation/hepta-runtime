"""Observe fixed startup effects of one owned authority ELF process.

Only declared fixture failures replace syscall completions. Ordinary reads,
entropy, file metadata, polling and closes execute in the Linux kernel.
"""
from pathlib import Path
import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
import select
import signal
import socket
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from authority_loader_supervisor import Filter, Program, Notification, Response


def cleanup_snapshot(pid, executable):
    """Inspect only this owned, blocked-at-exit fixture; never emit raw bytes."""
    raw = executable.read_bytes()
    provenance = json.loads((Path(__file__).resolve().parents[2] / 'native/authority_packer_provenance.json').read_bytes())
    at = provenance['metadata_offset']
    assert raw[at:at + 8] == b'HIAMOD01' and struct.unpack_from('<Q', raw, at + 8)[0] == 9
    mappings = []
    for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
        fields = line.split()
        if len(fields) == 5 and fields[1] == 'rw-p':
            lo, hi = (int(value, 16) for value in fields[0].split('-'))
            mappings.append((lo, hi))
    bases = [lo for lo, hi in mappings if hi - lo == 8388608 and (lo + 8392704, lo + 16781312) in mappings]
    assert len(bases) == 1, 'private mapping shape differs'
    base = bases[0]
    spans = [(0, 8388608), (8392704, 8388608)]
    for index in range(9):
        offset, size = struct.unpack_from('<2Q', raw, at + 64 + index * 128 + 32)
        spans.append((offset, size))
    descriptor_offsets = [16916480 + 328, 16916480 + 336, 16916480 + 368]
    memory = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
    try:
        inspected = 0
        for offset, size in spans:
            for start in range(0, size, 65536):
                width = min(65536, size - start)
                assert os.pread(memory, width, base + offset + start) == bytes(width), 'private cleanup left nonzero bytes'
                inspected += width
        for offset in descriptor_offsets:
            assert struct.unpack('<q', os.pread(memory, 8, base + offset))[0] == -1, 'private descriptor was not retired'
    finally:
        os.close(memory)
    return {'module_count': 9, 'private_workspaces_zero': True, 'transport_input_output_zero': True,
            'private_descriptor_slots_retired': True, 'inspected_bytes': inspected + 24}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', required=True, type=Path)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--mode', required=True, choices=['observe', 'owner_open_error',
        'owner_read_error', 'entropy_fail_1', 'entropy_fail_2', 'entropy_fail_3',
        'entropy_fail_4', 'entropy_fallback'])
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    executable = Path(command[0]).resolve(strict=True)
    executable_sha = hashlib.sha256(executable.read_bytes()).hexdigest()
    identity = None
    if args.fixture is not None:
        st = args.fixture.stat()
        assert st.st_uid == os.geteuid()
        identity = st.st_dev, st.st_ino
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
            numbers = [0, 3, 5, 7, 60, 107, 257, 318]
            raw = [Filter(0x20, 0, 0, 0)]
            raw += [Filter(0x15, len(numbers) - i, 0, nr) for i, nr in enumerate(numbers)]
            raw += [Filter(0x06, 0, 0, 0x7fff0000), Filter(0x06, 0, 0, 0x7fc00000)]
            filters = (Filter * len(raw))(*raw)
            program = Program(len(raw), filters)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), 'seccomp notifications unavailable')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            os.execve(str(executable), command, dict(os.environ))
        except BaseException as error:
            os.write(2, (str(error) + '\n').encode())
            os._exit(75)
    child.close()
    listener, status = None, None
    events, fired, probed, fills, cleanup = [], False, False, 0, None
    started = time.monotonic()
    try:
        if not select.select([parent], [], [], 5)[0]:
            raise RuntimeError('owned authority process could not install its observer')
        message, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
        assert message == b'L' and len(ancillary) == 1
        descriptors = array.array('i')
        descriptors.frombytes(ancillary[0][2][:4])
        listener = descriptors[0]
        parent.close()
        while True:
            ended, value = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = value
                break
            if time.monotonic() - started > 15:
                raise RuntimeError('owned authority fixture exceeded its test deadline')
            if not select.select([listener], [], [], .05)[0]:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
            assert note.pid == pid and note.data.arch == 0xc000003e
            response = Response(note.id, 0, 0, 1)
            nr, values = note.data.nr, note.data.args
            action = None
            if nr == 60:
                assert cleanup is None
                cleanup = cleanup_snapshot(pid, executable)
                cleanup['exit_code'] = int(values[0])
            elif nr == 257:
                if values[2] == 0xa0800:
                    action = 'token_open'
                elif values[2] == 0x80000:
                    memory = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
                    try:
                        name = os.pread(memory, 32, int(values[1])).split(b'\0', 1)[0]
                    finally:
                        os.close(memory)
                    if name == b'/dev/urandom':
                        action = 'entropy_urandom_open' if probed else 'owner_open'
                    elif name == b'/dev/random':
                        action = 'entropy_random_open'
            elif nr == 318:
                if values[1] == 0:
                    action, probed = 'entropy_probe', True
                else:
                    action = 'entropy_fill'
                    fills += 1
            elif nr == 107:
                action = 'effective_uid'
            elif nr == 7:
                action = 'entropy_poll'
            elif nr in (0, 3, 5):
                fd = int(values[0])
                kind = None
                try:
                    link = os.readlink(f'/proc/{pid}/fd/{fd}')
                    if link == '/dev/urandom':
                        kind = 'entropy_urandom' if probed else 'owner'
                    elif link == '/dev/random':
                        kind = 'entropy_random'
                    elif identity is not None:
                        observed = os.stat(f'/proc/{pid}/fd/{fd}')
                        if (observed.st_dev, observed.st_ino) == identity:
                            kind = 'token'
                except FileNotFoundError:
                    pass
                if kind:
                    action = kind + {0: '_read', 3: '_close', 5: '_stat'}[nr]
            if action:
                event = {'action': action, 'syscall': nr, 'effect': 'kernel_continue'}
                if nr in (0, 257, 318):
                    event['requested_bytes' if nr == 0 else 'flags' if nr == 257 else 'entropy_bytes'] = int(values[2 if nr != 318 else 1])
                wanted = (args.mode == 'owner_open_error' and action == 'owner_open'
                          or args.mode == 'owner_read_error' and action == 'owner_read'
                          or args.mode.startswith('entropy_fail_') and action == 'entropy_fill'
                          and fills == int(args.mode[-1]))
                if not fired and (wanted or args.mode == 'entropy_fallback' and action == 'entropy_probe'):
                    failure = errno.ENOSYS if args.mode == 'entropy_fallback' else errno.EIO
                    response.error, response.flags = -failure, 0
                    event.update(effect='injected_errno', errno=failure)
                    fired = True
                events.append(event)
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(response)) and ctypes.get_errno() != errno.ENOENT:
                raise OSError(ctypes.get_errno(), 'SECCOMP_IOCTL_NOTIF_SEND')
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
        if listener is not None:
            os.close(listener)
        parent.close()
        args.log.write_text(json.dumps({'schema': 'hepta.runtime.authority-backend.kernel-trace.v1',
            'mode': args.mode, 'events': events, 'fault_fired': fired,
            'native_cleanup': cleanup,
            'exit_code': os.waitstatus_to_exitcode(status), 'owned_process_reaped': True,
            'executable_sha256': executable_sha,
            'executable_unchanged': hashlib.sha256(executable.read_bytes()).hexdigest() == executable_sha},
            sort_keys=True, separators=(',', ':')) + '\n')
    assert args.mode == 'observe' or fired, 'predeclared startup fault did not occur'
    raise SystemExit(os.waitstatus_to_exitcode(status))


if __name__ == '__main__':
    main()
