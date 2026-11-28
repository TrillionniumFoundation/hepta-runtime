"""Qualification-only syscall controls over one owned lock service process.

Every observed path comes from that child.  The listener allows ordinary
kernel effects and records explicit injected completions separately.  Startup
activity is retained, but the original owner epoch begins at its first stdin
read.  No arbitrary PID or third-party filesystem target is accepted.
"""
from __future__ import annotations
import argparse
import array
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import sys
import time

class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
class Data(ctypes.Structure):
    _fields_ = [('nr', ctypes.c_int), ('arch', ctypes.c_uint), ('ip', ctypes.c_uint64), ('args', ctypes.c_uint64 * 6)]
class Notification(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('pid', ctypes.c_uint), ('flags', ctypes.c_uint), ('data', Data)]
class Response(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('value', ctypes.c_int64), ('error', ctypes.c_int), ('flags', ctypes.c_uint)]
class IoVec(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def cstring(libc, pid, address, readers):
    value = bytearray()
    while True:
        size = min(256, 4096 - ((address + len(value)) & 4095))
        target = ctypes.create_string_buffer(size)
        local = IoVec(ctypes.addressof(target), size)
        remote = IoVec(address + len(value), size)
        count = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
        if count <= 0:
            first = ctypes.get_errno()
            try:
                fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY | os.O_CLOEXEC)
                try:
                    raw = os.pread(fd, size, address + len(value))
                finally:
                    os.close(fd)
                readers.add('owned-proc-mem-pread')
            except OSError as error:
                raise OSError(first, 'reading the owned key syscall path') from error
            if not raw:
                raise OSError(errno.EIO, 'empty owned key process memory')
        else:
            raw = target.raw[:count]
            readers.add('owned-process-vm-readv')
        end = raw.find(b'\0')
        if end >= 0:
            return bytes(value) + raw[:end]
        value.extend(raw)

def supervise(executable, fixture, config, log, timeout, original_transport=False):
    executable = Path(executable).resolve(strict=True)
    fixture = Path(fixture).resolve(strict=True)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_readv.argtypes = [ctypes.c_int, ctypes.POINTER(IoVec), ctypes.c_ulong,
        ctypes.POINTER(IoVec), ctypes.c_ulong, ctypes.c_ulong]
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    raw_input = sys.stdin.buffer.read()
    assert len(raw_input) >= 160
    first_length, first_tag = struct.unpack_from('<QQ', raw_input)
    first_end = 16 + first_length
    assert first_tag == 1 and 64 <= first_length <= 1048576 and first_end <= len(raw_input) - 80
    second_length, second_tag = struct.unpack_from('<QQ', raw_input, first_end)
    assert (second_length, second_tag) == (64, 2) and first_end + 80 == len(raw_input)
    first_frame, second_frame = raw_input[:first_end], raw_input[first_end:]
    input_read, input_write = os.pipe()
    # These fixed kernel fixtures have short paths.  Retain the complete
    # service domain in its separate suite, and prevent this supervisor from
    # blocking before it can service the first owned seccomp notification.
    assert len(first_frame) <= os.fpathconf(input_write, 'PC_PIPE_BUF')
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    output_read, output_write = os.pipe()
    error_read, error_write = os.pipe()
    started = time.monotonic()
    pid = os.fork()
    if pid == 0:
        parent.close()
        os.close(output_read)
        os.close(error_read)
        try:
            os.close(input_write)
            os.dup2(input_read, 0)
            os.close(input_read)
            os.dup2(output_write, 1)
            os.dup2(error_write, 2)
            os.close(output_write)
            os.close(error_write)
            os.chdir(fixture)
            for component in config.get('cwd_parts', []):
                os.chdir(bytes.fromhex(component))
            if config.get('unlink_cwd'):
                assert config.get('cwd_parts')
                parent_fd = os.open(b'..', os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.rmdir(bytes.fromhex(config['cwd_parts'][-1]), dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            if libc.prctl(38, 1, 0, 0, 0):
                raise OSError(ctypes.get_errno(), 'PR_SET_NO_NEW_PRIVS')
            code = [Filter(0x20, 0, 0, 0)]
            for number in (0, 1, 3, 5, 8, 72, 79, 89, 217, 257, 262, 269, 439):
                code.extend((Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)))
            code.append(Filter(0x06, 0, 0, 0x7fff0000))
            instructions = (Filter * len(code))(*code)
            program = Program(len(code), instructions)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0:
                raise OSError(ctypes.get_errno(), 'seccomp notification unavailable')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            os.execve(executable, [str(executable)] + (["--kernel-stream"] if original_transport else []), dict(os.environ))
        except BaseException as error:
            os.write(2, (str(error) + '\n').encode())
            os._exit(75)
    child.close()
    os.close(input_read)
    assert os.write(input_write, first_frame) == len(first_frame)
    sent_drop = False
    verified_threads = {pid}
    os.close(output_write)
    os.close(error_write)
    if not select.select([parent], [], [], 5)[0]:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise RuntimeError('owned key child did not install its listener')
    _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
    parent.close()
    fds = array.array('i')
    fds.frombytes(ancillary[0][2][:4])
    listener = fds[0]
    os.set_blocking(output_read, False)
    os.set_blocking(error_read, False)
    outputs, errors = bytearray(), bytearray()
    events, counts, readers = [], {}, set()
    status = None
    failure = None
    active = False

    def drain(fd, target):
        try:
            raw = os.read(fd, 65536)
        except BlockingIOError:
            return False
        if raw:
            target.extend(raw)
            return True
        return False

    try:
        while True:
            if time.monotonic() - started > timeout:
                raise TimeoutError('owned canonical-key invocation exceeded its unchanged deadline')
            if not sent_drop and len(outputs) >= (76 if original_transport else 84):
                assert len(outputs) == (76 if original_transport else 84)
                code_at = 8 if original_transport else 16
                assert struct.unpack_from('<Q', outputs)[0] == 1 and struct.unpack_from('<I', outputs, code_at)[0] == 64
                assert outputs[code_at + 4:code_at + 12] == b'HRFLKR01'
                offset = 0
                while offset < len(second_frame):
                    offset += os.write(input_write, second_frame[offset:])
                os.close(input_write); input_write = -1; sent_drop = True
            ended, wait = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = wait
                while drain(output_read, outputs):
                    pass
                while drain(error_read, errors):
                    pass
                break
            ready, _, _ = select.select([listener, output_read, error_read], [], [], 0.01)
            if output_read in ready:
                drain(output_read, outputs)
            if error_read in ready:
                drain(error_read, errors)
            if listener not in ready:
                continue
            note = Notification()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(ctypes.get_errno(), 'receiving owned key notification')
            assert note.data.arch == 0xc000003e
            if note.pid != pid:
                thread_status = Path(f'/proc/{pid}/task/{note.pid}/status').read_text()
                values = {line.split(':', 1)[0]: line.split(':', 1)[1].strip() for line in thread_status.splitlines() if ':' in line}
                assert int(values['Tgid']) == pid and int(values['Pid']) == note.pid
            verified_threads.add(note.pid)
            nr, args = note.data.nr, list(note.data.args)
            response = Response(note.id, 0, 0, 1)
            if nr == 0 and args[0] == 0:
                active = True
            event = {'syscall': nr, 'pid': note.pid, 'ip': note.data.ip,
                'domain': 'owner' if active and nr not in (0, 1) else 'transport' if active else 'startup',
                'completion': 'kernel_continue'}
            kind = None
            if event['domain'] == 'owner':
                if nr == 79:
                    kind = 'getcwd'
                    event['capacity'] = args[1]
                elif nr == 89:
                    kind = 'readlink'
                    event.update(path_hex=cstring(libc, note.pid, args[0], readers).hex(), capacity=args[2])
                elif nr in (262, 269, 439, 257):
                    kind = {262: 'stat_at', 269: 'access_old', 439: 'access', 257: 'open_parent'}[nr]
                    event.update(path_hex=cstring(libc, note.pid, args[1], readers).hex(),
                        dirfd=ctypes.c_int(args[0]).value)
                    if nr == 262:
                        event['flags'] = args[3]
                    elif nr in (269, 439):
                        event['mode'] = args[2]
                        if nr == 439:
                            event['flags'] = args[3]
                    else:
                        event['flags'] = args[2]
                elif nr in (3, 5, 8, 72, 217):
                    kind = {3: 'close', 5: 'fstat', 8: 'rewind', 72: 'fcntl', 217: 'getdents'}[nr]
                    event['fd'] = args[0]
                    if nr == 72:
                        event['command'] = args[1]
                        if args[1] == 2:
                            event['value'] = args[2]
                    elif nr == 8:
                        event.update(offset=args[1], whence=args[2])
                    elif nr == 217:
                        event['capacity'] = args[2]
                assert kind is not None
                ordinal = counts.get(kind, 0) + 1
                counts[kind] = ordinal
                event.update(kind=kind, ordinal=ordinal)
                for fault in config.get('faults', []):
                    if fault['kind'] != kind or fault.get('ordinal', 1) != ordinal:
                        continue
                    assert response.flags == 1
                    if 'errno' in fault:
                        response.error = -fault['errno']
                        response.flags = 0
                        event.update(completion='injected_errno_without_kernel_effect', errno=fault['errno'])
                    elif 'return' in fault:
                        value = args[2] if fault['return'] == 'readlink_capacity' and nr == 89 else fault['return']
                        assert type(value) is int and value >= 0
                        response.value = value
                        response.flags = 0
                        event.update(completion='injected_value_without_kernel_effect', value=value)
                    else:
                        raise ValueError('undefined key syscall control')
            events.append(event)
            if libc.ioctl(listener, 0xc0182101, ctypes.byref(response)):
                raise OSError(ctypes.get_errno(), 'replying to owned key notification')
        assert sent_drop, 'second operation was not admitted after first complete result'
        for fault in config.get('faults', []):
            matched = [event for event in events if event.get('kind') == fault['kind'] and event.get('ordinal') == fault.get('ordinal', 1)]
            assert len(matched) == 1 and matched[0]['completion'].startswith('injected_'), fault
    except BaseException as error:
        failure = repr(error)
        raise
    finally:
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
        if input_write != -1:
            os.close(input_write)
        os.close(listener)
        os.close(output_read)
        os.close(error_read)
        report = {'schema': 'hepta.runtime.file-lock-service-kernel-trace.v1',
            'status': 'PASS' if failure is None and os.waitstatus_to_exitcode(status) == 0 else 'FAIL',
            'executable_sha256': sha(executable.read_bytes()), 'fixture': str(fixture),
            'config': config, 'original_transport': original_transport, 'input_sha256': sha(raw_input),
            'input_bytes': len(raw_input), 'drop_after_complete_first_result': sent_drop,
            'owned_thread_ids': sorted(verified_threads), 'events': events, 'counts': counts, 'memory_readers': sorted(readers),
            'owner_epoch': 'first-read-on-stdin-before-any-owner-syscall', 'exit_code': os.waitstatus_to_exitcode(status),
            'stdout_bytes': len(outputs), 'stdout_sha256': sha(outputs),
            'stderr_bytes': len(errors), 'stderr_sha256': sha(errors),
            'elapsed': time.monotonic() - started, 'failure': failure}
        Path(log).write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        os.write(1, outputs)
        os.write(2, errors)
    return os.waitstatus_to_exitcode(status)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--original-transport', action='store_true')
    args = parser.parse_args()
    raise SystemExit(supervise(args.executable, args.fixture, json.loads(args.config.read_bytes()), args.log, args.timeout, args.original_transport))
