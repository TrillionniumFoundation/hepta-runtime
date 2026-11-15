# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Account-owned persistent PTY and complete output archive; no network listener.
The daemon, terminal and log belong to the target login, not the MCP controller.
No input text is written to metadata; the application still controls terminal echo.
"""
import errno
import fcntl
import hashlib
import json
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import termios
import time

MAX_RPC = 256 * 1024
PAGE = 16 * 1024


def atomic(path, value):
    tmp = path.with_name(path.name + '.tmp-' + str(os.getpid()))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, ensure_ascii=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if tmp.exists(): tmp.unlink()


def load(path):
    try: return json.loads(path.read_text())
    except FileNotFoundError: return None


def boot():
    if sys.platform == 'linux':
        return pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return subprocess.check_output(['/usr/sbin/sysctl', '-n', 'kern.boottime'], text=True, timeout=3).strip()


def private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise PermissionError('terminal state must be a private account-owned directory')
    return path


def socket_path(job):
    root = private_dir(pathlib.Path('/tmp') / ('hepta-terminal-' + str(os.getuid())))
    return root / (hashlib.sha256(str(job.resolve()).encode()).hexdigest()[:32] + '.sock')


def recv_json(conn):
    data = bytearray()
    while len(data) <= MAX_RPC:
        block = conn.recv(min(65536, MAX_RPC + 1 - len(data)))
        if not block: break
        data.extend(block)
        if b'\n' in block: break
    if len(data) > MAX_RPC or not data.endswith(b'\n'):
        raise ValueError('invalid or oversized terminal RPC')
    return json.loads(data)


def request_daemon(job, q):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(str(socket_path(job)))
        conn.sendall(json.dumps(q, ensure_ascii=True).encode() + b'\n')
        value = recv_json(conn)
    if 'error' in value: raise RuntimeError(value['error'])
    return value


def status(job):
    final = load(job / 'exit.json')
    if final: return final
    started = load(job / 'started.json')
    if not started:
        return {'state': 'launch_unknown', 'output_complete': False, 'reason': 'no start acknowledgement; do not launch another identity'}
    if started['boot'] != boot():
        return {'state': 'lost', 'output_complete': False, 'reason': 'target_reboot', 'pid': started['pid']}
    try: return request_daemon(job, {'op': 'status'})
    except (OSError, ValueError, RuntimeError):
        final = load(job / 'exit.json')
        return final or {'state': 'lost', 'output_complete': False, 'reason': 'terminal_owner_unreachable', 'pid': started['pid']}


def read_page(job, q):
    state = status(job)
    path = job / 'output.log'
    offset = int(q.get('offset') or 0)
    limit = max(1, min(PAGE, int(q.get('limit') or PAGE)))
    raw = bool(q.get('raw_bytes', False))
    try:
        with path.open('rb') as stream:
            size = os.fstat(stream.fileno()).st_size
            if not 0 <= offset <= size: raise ValueError('terminal cursor outside retained archive')
            stream.seek(offset)
            data = stream.read(min(limit + 3, size - offset))
    except FileNotFoundError:
        size, data = 0, b''
        if offset: raise ValueError('terminal cursor outside empty archive')
    end = min(limit, len(data))
    finished = state['state'] != 'running'
    if not raw:
        while True:
            candidate = data[:end]
            try:
                candidate.decode('utf-8')
                break
            except UnicodeDecodeError as exc:
                if exc.reason == 'unexpected end of data':
                    if exc.start:
                        end = exc.start
                        break
                    if end < len(data):
                        end += 1
                        continue
                    if not finished: end = 0
                break
    data = data[:end]
    try:
        text, lossy = data.decode('utf-8'), False
    except UnicodeDecodeError:
        text, lossy = data.decode('utf-8', 'replace'), True
    return {'offset': offset, 'next_offset': offset + len(data), 'available_end': size,
            'bytes_hex': data.hex(), 'text': text, 'text_is_lossy': lossy,
            'utf8_pending': not raw and not finished and not data and offset < size,
            'truncated_before_offset': False, 'storage': 'target_archive',
            'archive_path': str(path), 'chunk_sha256': hashlib.sha256(data).hexdigest(),
            'output_complete': state.get('output_complete', False), 'status': state}


def start(job, q, source):
    private_dir(job)
    with (job / 'launch.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        old = load(job / 'request.json')
        request = q['request']
        if old:
            if old != request: raise ValueError('terminal identity is bound to a different request')
            return {'reused': True, 'status': status(job)}
        # Persist intent before launch; a missing acknowledgement never means retry a new process.
        atomic(job / 'request.json', request)
        helper = job / 'owner.py'
        fd = os.open(helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, 'w') as stream: stream.write(source)
        env = os.environ.copy()
        env.setdefault('XDG_RUNTIME_DIR', '/run/user/' + str(os.getuid()))
        env.setdefault('DBUS_SESSION_BUS_ADDRESS', 'unix:path=' + env['XDG_RUNTIME_DIR'] + '/bus')
        user_bus = pathlib.Path(env['XDG_RUNTIME_DIR']) / 'bus'
        if sys.platform == 'linux' and user_bus.exists() and shutil.which('systemd-run'):
            result = subprocess.run(['systemd-run', '--user', '--quiet', '--collect',
                                     '--unit=hepta-terminal-' + request['session_id'],
                                     '--property=KillMode=control-group', '--', sys.executable,
                                     str(helper), '--daemon', str(job)], env=env, capture_output=True, timeout=10)
            if result.returncode:
                raise RuntimeError('systemd launch was not acknowledged; reconcile this identity: ' + result.stderr.decode(errors='replace')[-1000:])
        else:
            if not request.get('allow_detached_fallback', False):
                raise RuntimeError('user manager unavailable and detached fallback not authorized')
            subprocess.Popen([sys.executable, str(helper), '--daemon', str(job)],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True, close_fds=True, env=env)
        for _ in range(80):
            if (job / 'started.json').exists() or (job / 'exit.json').exists():
                return {'reused': False, 'status': status(job)}
            time.sleep(.05)
        return {'reused': False, 'status': status(job)}


def daemon(job):
    req = load(job / 'request.json')
    os.umask(0o077)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = socket_path(job)
    # Never unlink somebody else's live listener or retry an ambiguous previous launch.
    sock.bind(str(path))
    os.chmod(path, 0o600)
    sock.listen(8)
    sock.setblocking(False)
    output = open(job / 'output.log', 'xb', buffering=0)
    pid, master = pty.fork()
    if pid == 0:
        try:
            sock.close()
            output.close()
            if req.get('cwd'): os.chdir(req['cwd'])
            env = os.environ.copy(); env.update(req.get('env', {}))
            env['TERM'] = env.get('TERM') or 'xterm-256color'
            os.execvpe(req['executable'], [req['executable'], *req.get('args', [])], env)
        except BaseException as exc:
            os.write(2, (str(exc) + '\n').encode())
            os._exit(127)
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', req.get('rows', 24), req.get('cols', 120), 0, 0))
    os.set_blocking(master, False)
    started = {'pid': pid, 'owner_pid': os.getpid(), 'boot': boot(), 'state': 'running',
               'output_complete': False, 'created_unix_ms': int(time.time()*1000)}
    atomic(job / 'started.json', started)
    error, eof, exited, close_at = None, False, None, None
    seen, stored = 0, 0
    receipts = {}
    def current():
        return {**started, 'bytes_seen': seen, 'bytes_stored': stored, 'capture_error': error}
    try:
        while True:
            if exited is None:
                waited, wait_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    exited = (os.waitstatus_to_exitcode(wait_status), time.monotonic())
            if exited is not None and (eof or time.monotonic() - exited[1] >= 2): break
            if close_at is not None and exited is None and time.monotonic() - close_at > 2:
                try: os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError: pass
                except PermissionError:
                    close_at = None
                    error = error or 'close requires separately authorized target signal'
            readable, _, _ = select.select(([master] if not eof else []) + [sock], [], [], .05)
            if master in readable:
                try:
                    data = os.read(master, 65536)
                    if not data: eof = True
                    seen += len(data)
                    if error is None:
                        try:
                            pending = memoryview(data)
                            while pending:
                                n = output.write(pending)
                                if not n: raise OSError('archive write made no progress')
                                stored += n; pending = pending[n:]
                        except OSError as exc: error = 'archive write: ' + str(exc)
                except OSError as exc:
                    if exc.errno == errno.EIO: eof = True
                    elif exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        error = 'terminal read: ' + str(exc); eof = True
            if sock in readable:
                conn, _ = sock.accept()
                with conn:
                    conn.settimeout(3)
                    try:
                        q = recv_json(conn)
                        op = q['op']
                        if op == 'status': reply = current()
                        elif op == 'write':
                            if exited is not None or close_at is not None: raise ValueError('terminal no longer accepts input')
                            data = q['data'].encode('utf-8')
                            if len(data) > 65536: raise ValueError('input exceeds 64 KiB')
                            key = q.get('request_id')
                            if key is not None and (not isinstance(key, str) or not 1 <= len(key) <= 128): raise ValueError('invalid input request identity')
                            if key and key in receipts:
                                if receipts[key][0] != hashlib.sha256(data).digest(): raise ValueError('input key reused with different bytes')
                                reply = {**receipts[key][1], 'reused': True}
                            else:
                                if len(receipts) >= 10000: raise ValueError('input receipt capacity reached; start a new terminal')
                                n, deadline = 0, time.monotonic() + 2
                                while n < len(data):
                                    _, writable, _ = select.select([], [master], [], max(0, deadline-time.monotonic()))
                                    if not writable: break
                                    n += os.write(master, data[n:])
                                reply = {'bytes_written': n, 'complete': n == len(data), 'reused': False}
                                if key: receipts[key] = (hashlib.sha256(data).digest(), dict(reply))
                        elif op == 'close':
                            if close_at is None:
                                try:
                                    os.killpg(pid, signal.SIGTERM)
                                    close_at = time.monotonic()
                                except ProcessLookupError:
                                    close_at = time.monotonic()
                                except PermissionError:
                                    raise PermissionError('terminal child changed UID; use an explicitly authorized host_signal for PID ' + str(pid))
                            reply = {'result': 'close_requested'}
                        elif op == 'resize':
                            rows, cols = int(q['rows']), int(q['cols'])
                            if not 1 <= rows <= 500 or not 1 <= cols <= 1000: raise ValueError('invalid terminal size')
                            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
                            reply = {'rows': rows, 'cols': cols}
                        else: raise ValueError('unknown terminal operation')
                    except Exception as exc:
                        reply = {'error': type(exc).__name__ + ': ' + str(exc)}
                    try: conn.sendall(json.dumps(reply).encode() + b'\n')
                    except OSError: pass  # Missing acknowledgements never repeat terminal input.
        if not eof: error = error or 'output drain deadline exceeded'
        try: os.fsync(output.fileno())
        except OSError as exc: error = error or 'archive sync: ' + str(exc)
        atomic(job / 'exit.json', {**current(), 'state': 'exited', 'exit_code': exited[0],
                                  'output_complete': error is None and eof and seen == stored,
                                  'capture_error': error, 'closed': close_at is not None})
    finally:
        output.close(); os.close(master); sock.close()
        path.unlink(missing_ok=True)


def main(source=None):
    if len(sys.argv) == 3 and sys.argv[1] == '--daemon':
        daemon(pathlib.Path(sys.argv[2])); return
    q = json.load(sys.stdin)
    job = pathlib.Path(q['job_dir'])
    if not job.is_absolute() or '..' in job.parts: raise ValueError('invalid terminal state path')
    op = q['op']
    if op == 'start': value = start(job, q, source or pathlib.Path(__file__).read_text())
    else:
        private_dir(job)
        req = load(job / 'request.json')
        if not req or req['session_id'] != q['session_id']: raise ValueError('unknown terminal identity')
        if op == 'read': value = read_page(job, q)
        elif op == 'status': value = status(job)
        elif op == 'close' and status(job)['state'] != 'running': value = {'result': 'already_exited'}
        else: value = request_daemon(job, q)
    print(json.dumps(value, ensure_ascii=True))


if __name__ == '__main__':
    try: main(globals().get('HEPTA_HELPER_SOURCE'))
    except Exception as exc:
        print(type(exc).__name__ + ': ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
