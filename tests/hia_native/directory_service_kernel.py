"""Trace only owned, hash-pinned programs at real mkdir/flock boundaries.

No syscall arguments, result registers, memory or business responses are changed.
Holding a traced mkdir entry distinguishes Future drop from worker cancellation.
"""
from pathlib import Path
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import shutil
import signal
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from directory_service_support import configuration, exclusive, require, words

LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.ptrace.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
LIBC.ptrace.restype = ctypes.c_long
WALL = 0x40000000
OPTIONS = 1 | 2 | 4 | 8 | 16 | 0x100000
CASES = ('soft-cancel', 'outer-drop', 'eof-drain', 'parent-death', 'pending-drop', 'pending-soft')
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def ptrace(request, tid, address=0, data=0):
    ctypes.set_errno(0)
    value = LIBC.ptrace(request, tid, address, data)
    if value == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), 'owned syscall observation failed')
    return value


def syscall_info(tid):
    data = ctypes.create_string_buffer(128)
    require(ptrace(0x420e, tid, len(data), ctypes.byref(data)) >= 24, 'short syscall observation')
    if data.raw[0] == 1:
        return 1, struct.unpack_from('<7Q', data.raw, 24)
    if data.raw[0] == 2:
        return 2, struct.unpack_from('<q', data.raw, 24)[0]
    raise AssertionError('unexpected syscall stop')


def cstring(tid, address):
    output = bytearray()
    for offset in range(0, 4096, 8):
        raw = (ptrace(2, tid, address + offset) & ((1 << 64) - 1)).to_bytes(8, 'little')
        if 0 in raw:
            output.extend(raw[:raw.index(0)])
            return bytes(output)
        output.extend(raw)
    raise AssertionError('fixed owned pathname exceeds observation bound')


def observe(binary, variant, mode, root, output):
    base = root / (variant + '-' + mode)
    work, config, environment = configuration(base, fence=True)
    target = work / 'held-effect'
    following = work / 'following-effect'
    descriptor = os.open(base / 'authority/.owner.lock', os.O_RDONLY | os.O_CLOEXEC)
    if mode.startswith('pending-'):
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    input_read, input_write = os.pipe2(os.O_CLOEXEC)
    output_read, output_write = os.pipe2(os.O_CLOEXEC)
    error_read, error_write = os.pipe2(os.O_CLOEXEC)
    startup_read, startup_write = os.pipe2(os.O_CLOEXEC)
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        try:
            # Preserve every source before assigning fixed 0/1/2/4; no inherited
            # authority lock or descriptor is accidentally retained in the child.
            kept = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 16)
                    for fd in (input_read, output_write, error_write, startup_read)]
            for source, destination in zip(kept, (0, 1, 2, 4)):
                os.dup2(source, destination, inheritable=True)
            for name in os.listdir('/proc/self/fd'):
                fd = int(name)
                if fd not in (0, 1, 2, 4):
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            ptrace(0, 0)
            os.execve(binary, [os.fsencode(binary), b'--runtime-config', os.fsencode(config),
                b'--session-root', os.fsencode(work)], {'PATH':'', 'USER':'operator', **environment})
        except BaseException as error:
            os.write(2, (repr(error) + '\n').encode())
            os._exit(76)
    for fd in (input_read, output_write, error_write, startup_read):
        os.close(fd)
    os.write(startup_write, words(b'HMDINIT1', 0, 0, 0))
    os.close(startup_write)
    for fd in (output_read, error_read):
        os.set_blocking(fd, False)
    live = {pid}
    announced = {pid}
    deferred_stops = {}
    exits, pending = {}, {}
    events, replies = [], []
    incoming, outgoing, errors = bytearray(), bytearray(), bytearray()
    cursor = 0
    closed = False
    held = None
    worker_tid = None
    held_seen = False
    resumed = False
    mkdir_returned = False
    cancellation_sent = False
    cancellation_ack = False
    cancellation_observed = False
    following_sent = False
    following_done = False
    original_done = False
    blocked_tid = None
    blocked_observed = False
    pending_released = False
    record_after_cancel = False
    parent_killed = False
    syscall_stops = 0

    def send(command, identifier, payload=b''):
        raw = words(b'HMDCTL01', command, identifier, len(payload)) + payload
        raw = struct.pack('<Q', len(raw)) + raw
        require(os.write(input_write, raw) == len(raw), 'short qualification write')
        incoming.extend(raw)
        events.append({'kind':'private_input', 'command':command, 'id':identifier})

    def begin(identifier, name):
        raw = name.encode()
        send(1, identifier, words(b'HMDCRQ02', len(raw), 0, 0, 0) + raw)

    def close_input():
        nonlocal closed
        require(not closed, 'stdin closed twice')
        os.close(input_write)
        closed = True
        events.append({'kind':'stdin_eof'})

    def collect():
        nonlocal cursor, cancellation_ack, following_done, original_done
        for fd, sink in ((output_read, outgoing), (error_read, errors)):
            while True:
                try:
                    raw = os.read(fd, 65536)
                except BlockingIOError:
                    break
                if not raw:
                    break
                sink.extend(raw)
        while len(outgoing) - cursor >= 8:
            n = struct.unpack_from('<Q', outgoing, cursor)[0]
            require(40 <= n <= 134217768, 'kernel observation response bound')
            if len(outgoing) - cursor < n + 8:
                break
            raw = bytes(outgoing[cursor + 8:cursor + 8 + n])
            cursor += n + 8
            require(raw[:8] == b'HMDCTR01', 'kernel observation response magic')
            kind, identifier, code, count = struct.unpack_from('<4Q', raw, 8)
            require(count == n - 40, 'kernel observation response shape')
            payload = raw[40:]
            replies.append({'kind':kind, 'id':identifier, 'code':code, 'payload_hex':payload.hex()})
            events.append({'kind':'private_output', 'event':kind, 'id':identifier, 'code':code})
            if kind in (3, 4):
                require(identifier == 1 and code == 0 and not payload and cancellation_sent,
                        'cancellation acknowledgment differs')
                cancellation_ack = True
            elif kind == 1:
                require(code == 0 and not payload and identifier in (1, 2), 'begin acknowledgment differs')
            elif kind == 2 and identifier == 1:
                require(code == 0 and not payload, 'cancelled call published a business result')
                original_done = True
            elif kind == 2 and identifier == 2:
                require(code == len(payload) and payload[:8] == b'HMDCRS01', 'following call response')
                tag, reserved, size = struct.unpack_from('<3Q', payload, 8)
                require(tag == 0 and reserved == 0 and size == len(payload) - 32, 'following call result')
                result = json.loads(payload[32:])
                require(result == {'created':True, 'exists_as_directory':True, 'path':str(following)}, 'following actual effect differs')
                following_done = True
            else:
                raise AssertionError(('unexpected private response', replies[-1]))

    try:
        got, status = os.waitpid(pid, 0)
        if not (got == pid and os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGTRAP):
            collect()
            raise AssertionError(('owned trace startup failed', status, errors.decode(errors='replace')))
        require(Path(f'/proc/{pid}/exe').resolve() == binary, 'trace target executable differs')
        ptrace(0x4200, pid, 0, OPTIONS)
        ptrace(24, pid)
        begin(1, 'held-effect')
        while live:
            require(time.monotonic() - start < 45, ('fixed observer deadline', events, errors.decode(errors='replace')))
            collect()
            if mode.startswith('pending-') and blocked_tid is not None and not blocked_observed:
                try:
                    raw = Path(f'/proc/{blocked_tid}/syscall').read_text()
                except FileNotFoundError:
                    raw = ''
                if raw.startswith('73 '):
                    blocked_observed = True
                    events.append({'kind':'actual_kernel_flock_block', 'tid':blocked_tid,
                        'syscall':raw.strip(), 'wchan':Path(f'/proc/{blocked_tid}/wchan').read_text().strip()})
                    send(3 if mode == 'pending-drop' else 2, 1)
                    cancellation_sent = True
            if cancellation_ack and not cancellation_observed:
                if mode.startswith('pending-'):
                    require(blocked_observed and not target.exists(), 'pending effect already occurred')
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                    pending_released = True
                    events.append({'kind':'cancelled_while_worker_blocked_then_unlocked', 'outer_drop':mode == 'pending-drop'})
                    cancellation_observed = True
                    if mode == 'pending-drop':
                        close_input()
                else:
                    available = exclusive(descriptor)
                    require(available == (mode == 'outer-drop') and not target.exists(), 'permit lifetime at cancellation differs')
                    events.append({'kind':'after_cancel_before_actual_mkdir', 'exclusive_available':available,
                        'directory_exists':False, 'worker_tid':worker_tid})
                    cancellation_observed = True
                    if mode == 'outer-drop':
                        begin(2, 'following-effect'); following_sent = True
                    else:
                        ptrace(24, held); held = None; resumed = True
            if mode == 'outer-drop' and following_done and held is not None:
                require(not target.exists() and following.is_dir() and exclusive(descriptor), 'following call did not progress while cancelled worker remained held')
                events.append({'kind':'new_call_completed_before_old_worker_resumed', 'old_directory_exists':False,
                    'new_directory_exists':True, 'exclusive_available':True})
                ptrace(24, held); held = None; resumed = True
            if mode == 'eof-drain' and held is not None and closed and not cancellation_observed and exclusive(descriptor):
                require(Path(f'/proc/{pid}').exists() and not target.exists(), 'EOF did not retain the submitted worker')
                events.append({'kind':'eof_released_permit_but_parent_retained_worker', 'exclusive_available':True})
                cancellation_observed = True
                ptrace(24, held); held = None; resumed = True
            if mode in ('soft-cancel', 'outer-drop') and mkdir_returned and target.is_dir() and exclusive(descriptor):
                ready = original_done or (variant == 'original' and mode == 'outer-drop')
                if ready and not following_sent:
                    require(mode == 'soft-cancel', 'unexpected following order')
                    begin(2, 'following-effect'); following_sent = True
                if ready and following_done and not closed:
                    close_input()
            if mode == 'pending-soft' and mkdir_returned and original_done and target.is_dir() and exclusive(descriptor) and not closed:
                close_input()
            tid, status = os.waitpid(-1, WALL | os.WNOHANG)
            if tid == 0:
                time.sleep(0.0002)
                continue
            if tid not in live:
                # Linux may report an auto-attached child's initial SIGSTOP
                # before the corresponding parent fork/clone event. Keep it
                # stopped; only that later kernel event can authorize resuming.
                require(os.WIFSTOPPED(status) and os.WSTOPSIG(status) == signal.SIGSTOP
                        and status >> 16 == 0, ('unknown observed child', tid, status))
                state = dict(line.split(':', 1) for line in Path(f'/proc/{tid}/status').read_text().splitlines() if ':' in line)
                require(int(state['TracerPid']) == os.getpid(), 'provisional child is not traced by this observer')
                live.add(tid)
                deferred_stops[tid] = status
                events.append({'kind':'deferred_initial_stop', 'tid':tid})
                continue
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                live.remove(tid)
                exits[tid] = os.waitstatus_to_exitcode(status)
                pending.pop(tid, None)
                continue
            require(os.WIFSTOPPED(status), 'unexpected wait state')
            stop_signal, ptrace_event = os.WSTOPSIG(status), status >> 16
            delivery = 0
            if ptrace_event in (1, 2, 3):
                child = ctypes.c_ulonglong()
                ptrace(0x4201, tid, 0, ctypes.byref(child))
                require(child.value not in announced, 'duplicate observed child')
                announced.add(child.value)
                live.add(child.value)
                events.append({'kind':'actual_task_created', 'parent':tid, 'tid':child.value, 'event':ptrace_event})
                if child.value in deferred_stops:
                    deferred_stops.pop(child.value)
                    ptrace(24, child.value)
            elif ptrace_event == 4:
                pending.pop(tid, None)
                events.append({'kind':'actual_exec', 'tid':tid, 'executable':os.readlink(f'/proc/{tid}/exe')})
            elif stop_signal == signal.SIGSTOP and tid != pid:
                pass
            elif stop_signal == (signal.SIGTRAP | 0x80):
                syscall_stops += 1
                kind, arguments = syscall_info(tid)
                if kind == 1:
                    pending[tid] = arguments
                    number = arguments[0]
                    if number == 73 and arguments[2] == 1 and mode.startswith('pending-') and blocked_tid is None:
                        try:
                            is_lock = os.readlink(f'/proc/{tid}/fd/{arguments[1]}') == str(base / 'authority/.owner.lock')
                        except OSError:
                            is_lock = False
                        if is_lock:
                            blocked_tid = tid
                    if number == 257 and cancellation_observed and cstring(tid, arguments[2]) == b'.owner.json':
                        record_after_cancel = True
                        events.append({'kind':'actual_owner_record_open_after_cancel', 'tid':tid})
                    if number == 258 and cstring(tid, arguments[2]) == b'held-effect':
                        require(arguments[3] == 0o700 and os.readlink(f'/proc/{tid}/fd/{arguments[1]}') == str(work), 'observed mkdir authority differs')
                        require(not exclusive(descriptor) and not target.exists(), 'effect lacks actual shared permit')
                        worker_tid = tid
                        if not mode.startswith('pending-'):
                            require(not held_seen, 'selected mkdir observed twice')
                            held, held_seen = tid, True
                            events.append({'kind':'held_actual_mkdirat_entry', 'tid':tid, 'number':258, 'mode':448,
                                'exclusive_available':False, 'parent_fd_path':str(work)})
                            if mode == 'parent-death':
                                os.kill(pid, signal.SIGKILL); parent_killed = True
                                events.append({'kind':'actual_parent_sigkill', 'pid':pid})
                            elif mode == 'eof-drain':
                                close_input()
                            else:
                                send(2 if mode == 'soft-cancel' else 3, 1)
                                cancellation_sent = True
                            continue
                else:
                    entry = pending.pop(tid, None)
                    if entry is not None and entry[0] == 258 and tid == worker_tid:
                        require(arguments == 0 and (resumed or mode == 'pending-soft'), 'actual mkdir result differs')
                        mkdir_returned = True
                        events.append({'kind':'actual_mkdirat_return', 'tid':tid, 'value':arguments})
            elif stop_signal == signal.SIGCHLD:
                delivery = signal.SIGCHLD
            elif stop_signal == signal.SIGKILL and parent_killed:
                delivery = signal.SIGKILL
            else:
                raise AssertionError(('unexpected owned task signal', tid, stop_signal, ptrace_event))
            ptrace(24, tid, 0, delivery)
        collect()
        require(cursor == len(outgoing), 'unparsed output bytes')
        if mode == 'parent-death':
            require(parent_killed and exits[pid] == -9 and not target.exists(), 'parent-death cleanup differs')
            require(set(exits.values()) <= {0, -9} and exits.get(worker_tid) == -9, 'owned worker survived parent death')
        else:
            require(closed and set(exits.values()) == {0}, ('nonzero actual process exit', exits, errors.decode(errors='replace')))
            if mode == 'pending-drop':
                require(blocked_observed and cancellation_ack and pending_released and record_after_cancel and not target.exists(), 'cancelled submitted fence worker did not complete validation')
            else:
                require(mkdir_returned and target.is_dir() and stat_mode(target) == 0o700, 'submitted effect did not finish')
            if mode in ('soft-cancel', 'outer-drop'):
                require(held_seen and cancellation_observed and following_done, 'cancellation/recovery domain incomplete')
            elif mode == 'eof-drain':
                require(held_seen and cancellation_observed and resumed, 'EOF drain domain incomplete')
            elif mode == 'pending-soft':
                require(blocked_observed and cancellation_ack and pending_released and original_done, 'pending soft cancellation domain incomplete')
        require(exclusive(descriptor), 'actual permit leaked at process termination')
        require(not live and not deferred_stops and set(exits) == announced
                and all(not Path('/proc', str(tid)).exists() for tid in exits), 'owned tracee not reaped')
        return {'status':'PASS', 'case':mode, 'variant':variant, 'elapsed_seconds':time.monotonic()-start,
            'binary_sha256':sha(binary.read_bytes()), 'events':events, 'replies':replies,
            'exit_statuses':exits, 'all_owned_tasks_reaped':True, 'syscall_stops':syscall_stops,
            'syscall_mutations':0, 'held_mkdir_entry':held_seen, 'mkdir_returned':mkdir_returned,
            'kernel_blocked_fence':blocked_observed, 'record_validation_after_cancel':record_after_cancel,
            'input_sha256':sha(incoming), 'input_bytes':len(incoming), 'output_sha256':sha(outgoing),
            'output_bytes':len(outgoing), 'stderr_sha256':sha(errors), 'stderr_bytes':len(errors)}
    except BaseException:
        for tid in live:
            try:
                os.kill(tid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        while live:
            try:
                tid, status = os.waitpid(-1, WALL)
            except ChildProcessError:
                break
            if os.WIFSTOPPED(status):
                try:
                    ptrace(24, tid, 0, signal.SIGKILL)
                except OSError:
                    pass
            else:
                live.discard(tid)
        collect()
        raise
    finally:
        if not closed:
            os.close(input_write)
        for fd in (output_read, error_read, descriptor):
            os.close(fd)
        prefix = output / (variant + '-' + mode)
        for suffix, raw in (('stdin',incoming), ('stdout',outgoing), ('stderr',errors)):
            prefix.with_suffix('.'+suffix).write_bytes(raw)
        prefix.with_suffix('.events.json').write_text(json.dumps(events, indent=2, sort_keys=True)+'\n')
        # Complete traces and fixed owned path observations survive; open fixture
        # directories are never exported as an artifact of a running service.
        if not live:
            shutil.rmtree(base)


def stat_mode(path):
    return path.stat().st_mode & 0o7777


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--native-sha256', required=True)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--original-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    fixtures = args.output / 'fixtures'; fixtures.mkdir(mode=0o700)
    binaries = [(args.native.resolve(strict=True),'native',args.native_sha256),
                (args.original.resolve(strict=True),'original',args.original_sha256)]
    for path, _, pin in binaries:
        require(sha(path.read_bytes()) == pin, 'actual ELF pin differs')
    require(LIBC.prctl(36, 1, 0, 0, 0) == 0, 'qualification subreaper unavailable')
    report = {'schema':'hepta.directory-service.actual-kernel-lifecycle.v1', 'status':'FAIL',
        'cases':[], 'source_sha256':{Path(__file__).name:sha(Path(__file__).read_bytes()),
            'directory_service_support.py':sha(Path(__file__).with_name('directory_service_support.py').read_bytes())},
        'expected_cases':list(CASES), 'syscall_mutations':0, 'production_activated':False, 'whole_runtime_replaced':False}
    def save():
        (args.output/'report.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
    try:
        for mode in CASES:
            for path, variant, pin in binaries:
                report['cases'].append(observe(path, variant, mode, fixtures, args.output))
                require(sha(path.read_bytes()) == pin, 'actual ELF changed during observation')
                save()
        require(len(report['cases']) == 12, 'complete lifecycle case count differs')
        report['status'] = 'PASS'
        report['test_summary'] = dict(tests_run=6, failures=0, errors=0, skipped=0, expected_failures=0, unexpected_successes=0)
        report['native_processes'] = report['original_processes'] = 6
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        save()
    print(json.dumps({k:v for k,v in report.items() if k not in ('cases','source_sha256')}))


if __name__ == '__main__':
    main()
