"""Own every traced process in one real write-chain qualification session.

Seccomp notifications hold actual filesystem syscalls. Cancellation is sent
through the trusted caller transport; no request result or HIA continuation is
fabricated. Explicit errno/zero controls are recorded apart from kernel effects.
"""
from __future__ import annotations
import array
import ctypes
import errno
import gzip
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import stat
import struct
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from batch_write_trace_common import packet, json_bytes, snapshot


class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
class Data(ctypes.Structure):
    _fields_ = [('nr', ctypes.c_int), ('arch', ctypes.c_uint), ('ip', ctypes.c_uint64), ('args', ctypes.c_uint64 * 6)]
class Note(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('pid', ctypes.c_uint), ('flags', ctypes.c_uint), ('data', Data)]
class Response(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('value', ctypes.c_int64), ('error', ctypes.c_int), ('flags', ctypes.c_uint)]
class IOV(ctypes.Structure):
    _fields_ = [('base', ctypes.c_void_p), ('length', ctypes.c_size_t)]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def memory(libc, pid, address, size):
    target = ctypes.create_string_buffer(size)
    a, b = IOV(ctypes.addressof(target), size), IOV(address, size)
    count = libc.process_vm_readv(pid, ctypes.byref(a), 1, ctypes.byref(b), 1, 0)
    if count != size:
        raise OSError(ctypes.get_errno(), 'owned process memory read')
    return target.raw


def cstring(libc, pid, address):
    if address == 0: return None
    output = bytearray()
    for _ in range(32769):
        count = min(256, 4096 - ((address + len(output)) & 4095))
        raw = memory(libc, pid, address + len(output), count)
        stop = raw.find(b'\0')
        if stop >= 0: return bytes(output) + raw[:stop]
        output.extend(raw)
    raise ValueError('qualified canonical path span exceeded')


def fd_path(tid, descriptor):
    try: return os.fsencode(os.readlink('/proc/' + str(tid) + '/fd/' + str(descriptor)))
    except FileNotFoundError: return None


def normalized(events):
    return [{key: value for key, value in row.items() if key not in
             ('pid', 'tid', 'tgid', 'ppid', 'ip', 'args', 'fd', 'raw_index')}
            for row in events]


def supervise(binary, fixture, config, destination, timeout=20):
    binary = Path(binary).resolve(strict=True)
    fixture = Path(fixture).resolve(strict=True)
    destination = Path(destination); destination.mkdir()
    base = os.fsencode(fixture)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.process_vm_readv.argtypes = [ctypes.c_int, ctypes.POINTER(IOV), ctypes.c_ulong,
                                    ctypes.POINTER(IOV), ctypes.c_ulong, ctypes.c_ulong]
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    ir, iw = os.pipe(); out_r, out_w = os.pipe(); err_r, err_w = os.pipe()
    started = time.monotonic(); supervisor_pid = os.getpid(); pid = os.fork()
    if pid == 0:
        try:
            parent.close(); os.close(iw); os.close(out_r); os.close(err_r)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != supervisor_pid:
                os._exit(75)
            os.setsid(); os.dup2(ir, 0); os.dup2(out_w, 1); os.dup2(err_w, 2)
            for descriptor in (ir, out_w, err_w): os.close(descriptor)
            os.chdir(fixture); os.umask(config.get('umask', 0o022))
            if config.get('blocked_cancel'):
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
            if 'file_size_limit' in config:
                size = config['file_size_limit']
                resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            assert libc.prctl(38, 1, 0, 0, 0) == 0
            rows = [Filter(0x20, 0, 0, 0)]
            for number in (0, 1, 3, 5, 8, 72, 79, 82, 87, 89, 90, 217, 257, 262, 269, 332, 439):
                rows.extend((Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x7fc00000)))
            rows.append(Filter(0x06, 0, 0, 0x7fff0000))
            instructions = (Filter * len(rows))(*rows); program = Program(len(rows), instructions)
            listener = libc.syscall(317, 1, 8, ctypes.byref(program))
            if listener < 0: raise OSError(ctypes.get_errno(), 'seccomp notification listener')
            os.set_inheritable(listener, False)
            child.sendmsg([b'L'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [listener]))])
            os.execve(binary, [str(binary)], {'PATH': ''})
        except BaseException as error:
            os.write(2, (repr(error) + '\n').encode()); os._exit(75)
    child.close(); os.close(ir); os.close(out_w); os.close(err_w)
    os.set_blocking(out_r, False); os.set_blocking(err_r, False)
    stdout = bytearray(); stderr = bytearray(); wire = bytearray(); frames = []; normalized_output = bytearray()
    raw_events = []; events = []; verified = {}; counts = {}; matches = {}
    status = None; failure = None; listener = None; held = None; cancel_ack = None
    next_step = 0; consumed = 0; input_closed = False; epoch = False
    response_tags = set(); parallel = config.get('parallel')
    parallel_keys = 0; queued_cancel_sent = False; parallel_started = False
    controls = [{'type': 'fault', **value} for value in config.get('faults', [])]
    if config.get('cancel'): controls.append({'type': 'cancel', **config['cancel']})
    if parallel: controls.append({'type': 'hold', **parallel['hold']})
    calls = config['steps']
    protected_open_paths = set()
    for step in calls:
        path = base + b'/' + bytes.fromhex(step.get('path_hex', b'target'.hex()))
        parent_path, file_name = path.rsplit(b'/', 1)
        protected_open_paths.add(path.hex())
        protected_open_paths.add((parent_path + b'/.octofs_tmp_' + file_name + b'.tmp').hex())

    def send_step():
        nonlocal next_step
        assert next_step < len(calls)
        step = calls[next_step]; next_step += 1
        path = base + b'/' + bytes.fromhex(step.get('path_hex', b'target'.hex()))
        if 'before_hex' in step:
            with open(path, 'wb') as handle: handle.write(bytes.fromhex(step['before_hex']))
        if 'mode' in step: os.chmod(path, step['mode'])
        frame = packet(step, path)
        message = struct.pack('<QQ', len(frame), next_step) + frame
        assert os.write(iw, message) == len(message)
        wire.extend(message)

    def drain(descriptor, target):
        while True:
            try: data = os.read(descriptor, 65536)
            except BlockingIOError: return
            if not data: return
            target.extend(data)

    def send(note, response):
        if libc.ioctl(listener, 0xc0182101, ctypes.byref(response)):
            raise OSError(ctypes.get_errno(), 'owned notification completion')

    def release_held(reason):
        nonlocal held
        note, response, row, at = held
        row['held_seconds'] = time.monotonic() - at
        row['release_reason'] = reason
        send(note, response); held = None

    try:
        if not select.select([parent], [], [], 5)[0]:
            raise TimeoutError('owned child listener setup')
        _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4)); parent.close()
        descriptors = array.array('i'); descriptors.frombytes(ancillary[0][2][:4]); listener = descriptors[0]
        send_step()
        while True:
            if time.monotonic() - started > timeout:
                raise TimeoutError('owned batch-write kernel deadline')
            ended, waiting = os.waitpid(pid, os.WNOHANG)
            if ended:
                status = waiting; drain(out_r, stdout); drain(err_r, stderr)
            while len(stdout) - consumed >= 20:
                tag, tid, code = struct.unpack_from('<QQI', stdout, consumed)
                size = code if code < 0xffff0000 else 0
                if len(stdout) - consumed < 20 + size: break
                frame = bytes(stdout[consumed + 20:consumed + 20 + size]); consumed += 20 + size
                assert 1 <= tag <= len(calls) and tag not in response_tags and tid > 0
                if parallel is None: assert tag == len(frames) + 1
                response_tags.add(tag)
                frames.append(dict(tag=tag, tid=tid, code=code, output_hex=frame.hex()))
                normalized_output.extend(struct.pack('<QI', tag, code) + frame)
                if held is not None and 'cancel' in config and tag == config['cancel'].get('tag', 2):
                    if config['cancel'].get('synchronous'):
                        raise AssertionError('synchronous original section acknowledged cancellation before release')
                    assert code == 0xfffffff7
                    cancel_ack = dict(tag=tag, code=code, effect_still_held=True,
                                      root_alive=status is None, elapsed=time.monotonic() - started)
                    held[2]['cancellation_ack_before_effect_release'] = True
                if held is not None and 'cancel' in config and tag == config['cancel'].get('release_after_tag', config['cancel'].get('tag', 2)):
                    release_held('completed-response-' + str(tag))
                if parallel and held is not None:
                    if parallel['mode'] in ('cache-race', 'independent') and tag == parallel['end']:
                        held[2]['other_request_completed_before_release'] = tag
                        release_held('other-cache-transition-complete' if parallel['mode'] == 'cache-race'
                                     else 'independent-file-complete')
                    if parallel['mode'] == 'queued-cancel' and tag == parallel['cancel_tag']:
                        assert queued_cancel_sent and code == 0xfffffff7
                        cancel_ack = dict(tag=tag, code=code, effect_still_held=True,
                            queued_request_completed_before_guard_release=True)
                        held[2]['queued_cancel_ack'] = tag
                        send_step()
                if parallel is None:
                    if next_step < len(calls): send_step()
                elif next_step <= parallel['after'] or len(response_tags) >= parallel['end']:
                    if next_step < len(calls): send_step()
            if held is not None and 'cancel' in config and config['cancel'].get('synchronous'):
                if time.monotonic() - held[3] >= 0.05:
                    assert len(frames) < config['cancel'].get('tag', 2)
                    cancel_ack = dict(tag=config['cancel'].get('tag', 2), effect_still_held=True,
                        no_early_response=True, minimum_hold_seconds=0.05)
                    release_held('synchronous-section-must-finish')
            if held is not None and parallel:
                age = time.monotonic() - held[3]
                if parallel['mode'] == 'serialized' and parallel_keys >= parallel['end'] - parallel['after'] - 1 and age >= 0.05:
                    held[2]['queued_key_completions'] = parallel_keys
                    release_held('all-other-callers-reached-held-lock')
                if parallel['mode'] == 'queued-cancel':
                    if not queued_cancel_sent and parallel_keys >= 1 and age >= 0.05:
                        message = struct.pack('<QQ', 0xffffffffffffffff, parallel['cancel_tag'])
                        assert os.write(iw, message) == len(message); wire.extend(message)
                        queued_cancel_sent = True; held[2]['queued_cancel_sent'] = parallel['cancel_tag']
                    if cancel_ack is not None and parallel_keys >= 2 and age >= 0.10:
                        held[2]['queued_key_completions'] = parallel_keys
                        release_held('canceled-waiter-removed-before-guard-release')
            if len(frames) == len(calls) and held is None and not input_closed:
                os.close(iw); input_closed = True
            if status is not None: break
            ready, _, _ = select.select([listener, out_r, err_r], [], [], 0.01)
            if out_r in ready: drain(out_r, stdout)
            if err_r in ready: drain(err_r, stderr)
            if listener not in ready: continue
            note = Note()
            if libc.ioctl(listener, 0xc0502100, ctypes.byref(note)):
                if ctypes.get_errno() in (errno.EINTR, errno.ENOENT): continue
                raise OSError(ctypes.get_errno(), 'owned notification receive')
            if note.pid not in verified:
                info = Path('/proc/' + str(note.pid) + '/status').read_text()
                fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip() for line in info.splitlines() if ':' in line}
                tgid, ppid = int(fields['Tgid']), int(fields['PPid'])
                assert tgid == pid or ppid == pid, ('notification escaped the owned process tree', tgid, ppid, pid)
                verified[note.pid] = dict(tgid=tgid, ppid=ppid)
            a = list(note.data.args); nr = note.data.nr
            raw = dict(pid=pid, tid=note.pid, nr=nr, ip=note.data.ip, args=a, epoch=epoch)
            if nr == 0 and a[0] == 0:
                assert (fd_path(note.pid, 0) or b'').startswith(b'pipe:[')
                epoch = True
            row = None
            def owned(path):
                return path is not None and (path == base or path.startswith(base + b'/'))
            if epoch:
                if nr in (257, 262, 332, 269, 439):
                    path = cstring(libc, note.pid, a[1])
                    if path is None and nr in (262, 332) and a[0] == 0:
                        row = dict(kind='stat_probe' if nr == 262 else 'statx_probe')
                    elif path == b'' and nr in (262, 332) and owned(fd_path(note.pid, a[0])):
                        row = dict(kind='fd_stat' if nr == 262 else 'fd_statx',
                            path_hex=fd_path(note.pid, a[0]).hex(), fd=a[0], flags=a[3] if nr == 262 else a[2])
                        if nr == 332: row['mask'] = a[3]
                    elif owned(path):
                        row = dict(kind={257: 'open', 262: 'path_stat', 332: 'path_statx', 269: 'access_old', 439: 'access'}[nr],
                            path_hex=path.hex(), dirfd=ctypes.c_int(a[0]).value,
                            flags=a[2] if nr in (257, 332) else a[3] if nr in (262, 439) else 0)
                        if nr == 257: row['mode'] = a[3]
                        if nr == 332: row['mask'] = a[3]
                        if nr in (269, 439): row['access_mode'] = a[2]
                elif nr in (82, 87, 89, 90):
                    path = cstring(libc, note.pid, a[0])
                    if owned(path):
                        row = dict(kind={82: 'rename', 87: 'unlink', 89: 'readlink', 90: 'chmod'}[nr], path_hex=path.hex())
                        if nr == 82: row['destination_hex'] = cstring(libc, note.pid, a[1]).hex()
                        if nr == 89: row['count'] = a[2]
                        if nr == 90: row['mode'] = a[1]
                elif nr in (0, 1, 3, 5, 8, 72, 217):
                    path = fd_path(note.pid, a[0])
                    if owned(path):
                        row = dict(kind={0: 'read', 1: 'write', 3: 'close', 5: 'fd_stat', 8: 'rewind', 72: 'fcntl', 217: 'getdents'}[nr],
                            path_hex=path.hex(), fd=a[0])
                        if nr in (0, 1, 217): row['count'] = a[2]
                        if nr == 1: row['bytes_sha256'] = sha(memory(libc, note.pid, a[1], a[2]))
                        if nr == 72: row.update(command=a[1], arg=a[2])
                elif nr == 79:
                    row = dict(kind='getcwd', count=a[1])
            response = Response(note.id, 0, 0, 1)
            retain = False
            if row is not None:
                kind = row['kind']; key = (next_step, kind)
                if held is not None and parallel and parallel['mode'] not in ('cache-race', 'independent'):
                    # Batch performs exists() before the lock; a target open/read may only
                    # follow acquisition. Do not misclassify that permitted metadata call.
                    if kind == 'open' and row.get('path_hex') in protected_open_paths:
                        raise AssertionError('another batch read/write passed the still-held original file lock')
                    if kind == 'readlink' and row.get('path_hex') == (base + b'/target').hex():
                        parallel_keys += 1
                counts[key] = counts.get(key, 0) + 1
                row.update(pid=pid, tid=note.pid, ip=note.data.ip, args=a, raw_index=len(raw_events),
                    admission_epoch=next_step, ordinal=counts[key], **verified[note.pid])
                for index, control in enumerate(controls):
                    if control.get('tag', 2) != next_step or control['kind'] != kind: continue
                    suffix = control.get('path')
                    if suffix is not None and row.get('path_hex') != (base + b'/' + suffix.encode()).hex(): continue
                    matches[index] = matches.get(index, 0) + 1
                    if matches[index] != control.get('nth', 1): continue
                    assert response.flags == 1 and not retain
                    row['control'] = control; row['control_index'] = index
                    if control['type'] == 'fault':
                        if 'errno' in control: response = Response(note.id, 0, -control['errno'], 0)
                        elif control.get('zero'): response = Response(note.id, 0, 0, 0)
                        else: raise ValueError('undefined completion control')
                    elif control['type'] == 'cancel':
                        assert held is None and cancel_ack is None
                        message = struct.pack('<QQ', 0xffffffffffffffff, control.get('tag', 2))
                        assert os.write(iw, message) == len(message); wire.extend(message)
                        row['cancellation_sent'] = True
                        held = (note, response, row, time.monotonic()); retain = True
                    else:
                        assert control['type'] == 'hold' and parallel and not parallel_started
                        assert held is None
                        held = (note, response, row, time.monotonic()); retain = True
                        parallel_started = True
                        if parallel['mode'] == 'queued-cancel': send_step()
                        else:
                            while next_step < parallel['end']: send_step()
                events.append(row)
            raw['completion'] = dict(value=response.value, error=response.error, flags=response.flags, held=retain)
            raw_events.append(raw)
            if not retain: send(note, response)
        assert os.waitstatus_to_exitcode(status) == 0 and consumed == len(stdout)
        assert len(frames) == len(calls) and held is None
        assert events and epoch
        for index, control in enumerate(controls):
            assert len([row for row in events if row.get('control_index') == index]) == 1, ('control not reached', control)
        if config.get('cancel'): assert cancel_ack is not None
        if parallel: assert parallel_started
    except BaseException as error:
        failure = repr(error)
        if status is None:
            try: os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError: pass
            _, status = os.waitpid(pid, 0)
        drain(out_r, stdout); drain(err_r, stderr)
    finally:
        if not input_closed:
            try: os.close(iw)
            except OSError: pass
        for descriptor in (out_r, err_r, listener):
            if descriptor is not None:
                try: os.close(descriptor)
                except OSError: pass
    with gzip.open(destination / 'filesystem.bin.gz', 'xb', compresslevel=1) as stream:
        final_files = snapshot(fixture, stream, len(frames))
    result = dict(schema='hepta.runtime.batch-write-kernel-process.v1',
        status='PASS' if failure is None else 'FAIL', failure=failure, executable=str(binary),
        binary_sha256=sha(binary.read_bytes()), config=config, fixture=str(fixture),
        exit_code=os.waitstatus_to_exitcode(status), elapsed_seconds=time.monotonic() - started,
        verified_process_tree={str(key): value for key, value in verified.items()},
        raw_events=raw_events, events=events, normalized_events=normalized(events),
        frames=frames, cancel_ack=cancel_ack, final_files=final_files,
        actual_requests=len(frames), actual_kernel_effects=sum(row.get('control', {}).get('type') != 'fault' for row in events),
        injected_completions=sum(row.get('control', {}).get('type') == 'fault' for row in events))
    for name, raw in [('requests.bin', wire), ('stdout.bin', stdout), ('stderr.bin', stderr), ('normalized.bin', normalized_output)]:
        (destination / name).write_bytes(raw)
        result[name] = dict(bytes=len(raw), sha256=sha(raw))
    (destination / 'result.json').write_bytes(json_bytes(result))
    return result
