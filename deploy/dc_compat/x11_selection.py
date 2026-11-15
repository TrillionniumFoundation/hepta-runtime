# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Private, persistent GTK3 X11 selection transactions; no text/key replay.

Only the helper opens an explicitly configured X display. A restored selection
is a lazy offer owned by that helper, not the original application's ownership.
Owner observations do not constitute an atomic compare-and-set or a coherent
cross-format snapshot of an uncooperative source. GTK buffers each INCR target
before delivering it; the snapshot budget is checked before publication.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dc_compat.clipboard_transaction import ClipboardTransactionError
from dc_compat.processes import _private_root, _publish, _read_file

CONTROL_TARGETS = frozenset(('TARGETS', 'TIMESTAMP', 'MULTIPLE', 'SAVE_TARGETS'))
UNSAFE_TARGETS = frozenset(('DELETE', 'INSERT_SELECTION', 'INSERT_PROPERTY',
    'PIXMAP', 'BITMAP', 'DRAWABLE', 'WINDOW', 'COLORMAP', 'CLIENT_WINDOW'))
TEXT_TARGETS = ('UTF8_STRING', 'text/plain;charset=utf-8', 'text/plain')
MAX_MESSAGE = 1024 * 1024
PROTOCOL = 2


def _identity(value):
    if not isinstance(value, str) or len(value) != 32 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Invalid transaction identity')
    return value


def _process_start(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError('Invalid process identity')
    raw = Path('/proc', str(pid), 'stat').read_text()
    return int(raw[raw.rindex(')') + 2:].split()[19])


def _file_identity(path, mode, kind):
    info = Path(path).lstat()
    if (not kind(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != mode or not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1):
        raise ValueError('Unsafe private selection resource')
    return {'device': info.st_dev, 'inode': info.st_ino}


def _server_identity(display, authority):
    # An XID alone survives neither an X server restart nor display-number reuse.
    # This local-only backend deliberately refuses servers without the usual
    # server PID lock and filesystem socket instead of guessing their identity.
    import re
    match = re.fullmatch(r':([0-9]+)(?:\.([0-9]+))?', display)
    if not match:
        raise ValueError('An explicit local numeric X display is required')
    number = int(match.group(1))
    lock = Path('/tmp', '.X' + str(number) + '-lock')
    fd = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64:
            raise ValueError('Unsafe X server PID lock')
        raw = os.read(fd, 65)
        pid = int(raw.strip())
        lock_identity = {'device': info.st_dev, 'inode': info.st_ino}
    finally:
        os.close(fd)
    endpoint = Path('/tmp/.X11-unix', 'X' + str(number))
    info = endpoint.lstat()
    if not stat.S_ISSOCK(info.st_mode):
        raise ValueError('X server socket unavailable')
    return {'display': display, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'pid': pid, 'starttime': _process_start(pid), 'lock': lock_identity,
        'socket': {'device': info.st_dev, 'inode': info.st_ino},
        'authority': dict(_file_identity(authority, 0o600, stat.S_ISREG), path=str(authority))}


def _snapshot_offer(root, identity, budget, binding):
    """Validate every private byte before an explicit restoration can publish."""
    _identity(identity)
    if not isinstance(binding, dict) or set(binding) != {'server', 'state'}:
        raise ValueError('Snapshot restoration needs a verified current server/state binding')
    folder = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
    try:
        info = os.fstat(folder)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Unsafe private snapshot folder')
        row = json.loads(_read_file(folder, 'snapshot.json', MAX_MESSAGE))
        if row.get('version') != 2 or row.get('complete') is not True or row.get('binding') != binding:
            raise ValueError('Incomplete snapshot or different X server/state identity')
        entries = row.get('entries')
        if (not isinstance(entries, dict) or len(entries) > 256 or type(row.get('source_empty')) is not bool
                or bool(entries) == row['source_empty'] or type(row.get('source_owner')) is not int
                or row['source_owner'] < 0 or row['source_empty'] != (row['source_owner'] == 0)
                or type(row.get('source_epoch')) is not int or row['source_epoch'] < 0):
            raise ValueError('Invalid complete snapshot metadata')
        files, total = {'snapshot.json'}, 0
        for target, item in entries.items():
            if (not isinstance(target, str) or not target or '\x00' in target or len(target.encode()) > 1024
                    or target in CONTROL_TARGETS | UNSAFE_TARGETS or not isinstance(item, dict)
                    or not isinstance(item.get('type'), str) or not item['type'] or '\x00' in item['type'] or len(item['type'].encode()) > 1024
                    or item['type'] in UNSAFE_TARGETS or item.get('format') not in (8, 16, 32)
                    or type(item.get('bytes')) is not int or item['bytes'] < 0
                    or not isinstance(item.get('file'), str)
                    or item['file'] != 'format-' + str(len(files) - 1).zfill(6) + '.bin'):
                raise ValueError('Invalid typed snapshot entry')
            unit = {8: 1, 16: 2, 32: ctypes.sizeof(ctypes.c_long)}[item['format']]
            if item['bytes'] % unit or total + item['bytes'] > budget:
                raise ValueError('Snapshot size/format budget refused')
            raw = _read_file(folder, item['file'], budget)
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item.get('sha256'):
                raise ValueError('Private snapshot bytes changed')
            total += len(raw); files.add(item['file'])
        if set(os.listdir(folder)) != files:
            raise ValueError('Unexpected private snapshot members')
        return {'kind': 'original', 'backup_id': identity, 'entries': entries,
            'source_owner': row['source_owner'], 'epoch': row['source_epoch'], 'empty': row['source_empty']}
    finally:
        os.close(folder)


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def _receipt(identity):
    return {'transaction_id': identity, 'phase': 'created', 'paste_attempted': False,
        'clipboard_publication_attempted': False, 'original_bytes_snapshot_complete': False,
        'original_bytes_offer_restored': False, 'original_owner_restored': False,
        'atomic_compare_and_set_available': False, 'target_input_verified': False,
        'transfer_consumer_identity_known': False, 'consumer_completion_confirmed': False,
        'backup_retained': False, 'automatic_retry': False, 'transfers': []}


def _paste_metadata(value):
    if not isinstance(value, dict):
        return {}
    booleans = ('submitted', 'replayed', 'target_input_verified', 'owned_keys_released', 'global_keymap_modified')
    result = {k: value[k] for k in booleans if type(value.get(k)) is bool}
    if value.get('input_outcome') in ('not_submitted', 'submitted', 'unknown_or_partial'):
        result['input_outcome'] = value['input_outcome']
    if type(value.get('key_events_submitted')) is int and value['key_events_submitted'] >= 0:
        result['key_events_submitted'] = value['key_events_submitted']
    return result


class X11Selection:
    """Synchronous wrapper; GTK and lazy selection ownership live in a child.

    paste_callback(keys, preflight=True) must validate without submitting input.
    Its preflight=False call is made at most once. Neither timeout nor cancellation
    kills a helper serving original data. receipt(txid) only reads metadata.
    """
    def __init__(self, config=None, display=None, env=None, state_path=None, budget=None):
        config = dict(config or {})
        self.display = display or config.get('display')
        self.env = dict(env or os.environ)
        self.state_path = Path(state_path or config.get('clipboard_state_dir', ''))
        self.budget = budget if budget is not None else config.get('clipboard_max_snapshot_bytes', 32 * 1024 * 1024)
        self.timeout = float(config.get('clipboard_timeout_seconds', 8))
        self.python = config.get('gui_python', '/usr/bin/python3')
        self.persistent = config.get('clipboard_persistent_daemon', True)
        if type(self.persistent) is not bool:
            raise ValueError('clipboard_persistent_daemon must be boolean')
        if (not self.display or not isinstance(self.display, str) or not self.display.startswith(':')
                or not self.state_path.is_absolute() or type(self.budget) is not int or self.budget < 0
                or not 0 < self.timeout <= 120):
            raise ValueError('Explicit local X display, absolute private snapshot directory and valid budget/timeout required')
        self.env.update(DISPLAY=self.display, GDK_BACKEND='x11', GTK_USE_PORTAL='0',
                        NO_AT_BRIDGE='1', GTK_IM_MODULE='simple', PYTHONDONTWRITEBYTECODE='1')
        self.env.pop('WAYLAND_DISPLAY', None)
        self.env.pop('PYTHONPATH', None); self.env.pop('PYTHONHOME', None)
        if config.get('xauthority'):
            self.env['XAUTHORITY'] = str(config['xauthority'])
        authority = Path(self.env.get('XAUTHORITY', ''))
        if not authority.is_absolute():
            raise ValueError('Explicit absolute private Xauthority is required')
        info = authority.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('Owned regular 0600 Xauthority is required')
        self.root_fd = _private_root(self.state_path)
        self.root_identity = (os.fstat(self.root_fd).st_dev, os.fstat(self.root_fd).st_ino)
        self.proc = None
        self.lock = threading.RLock()
        self.pending, self.pending_lock = {}, threading.Lock()
        self.last_transaction_id = None
        self.log = None
        self.reader_thread = None
        self.confirmed_closed = False
        self.detached = False
        self.client_id = uuid.uuid4().hex
        self.daemon = None

    def _guard(self):
        fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in self.state_path.parts[1:]:
                new = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = new
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) != self.root_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise RuntimeError('Private X11 snapshot directory changed')
        finally:
            os.close(fd)

    def _reader(self):
        try:
            while True:
                line = self.proc.stdout.readline(MAX_MESSAGE + 1)
                if not line or len(line) > MAX_MESSAGE or not line.endswith(b'\n'):
                    break
                value = json.loads(line)
                with self.pending_lock:
                    target = self.pending.get(value.get('id'))
                if target is not None:
                    target.put(value)
        except Exception:
            pass
        finally:
            with self.pending_lock:
                waiting = list(self.pending.values())
            for target in waiting:
                try:
                    target.put_nowait({'error': 'helper_connection_lost'})
                except queue.Full:
                    pass

    def _ensure(self):
        self._guard()
        if getattr(self, 'persistent', False):
            return self._ensure_daemon()
        if self.proc is not None:
            if self.proc.poll() is not None:
                raise RuntimeError('Original selection helper exited; no automatic replacement')
            return
        self.log = os.fdopen(os.open('helper-' + uuid.uuid4().hex + '.log',
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=self.root_fd), 'wb', buffering=0)
        config = {'display': self.display, 'state_path': str(self.state_path),
                  'budget': self.budget, 'timeout': self.timeout}
        ready = queue.Queue(1)
        self.pending['ready'] = ready
        self.proc = subprocess.Popen([self.python, '-I', '-B', str(Path(__file__).resolve()),
            '--helper', _json(config).decode()], env=self.env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=self.log, start_new_session=True)
        self.reader_thread = threading.Thread(target=self._reader, name='x11-selection-receipts', daemon=True)
        self.reader_thread.start()
        try:
            result = ready.get(timeout=self.timeout)
            if result.get('status') != 'ready':
                raise RuntimeError('X11 selection helper initialization refused')
        finally:
            self.pending.pop('ready', None)

    def _rpc(self, operation, **params):
        if getattr(self, 'persistent', False):
            return self._socket_rpc(operation, **params)
        identity = uuid.uuid4().hex
        answer = queue.Queue(1)
        with self.pending_lock:
            self.pending[identity] = answer
        try:
            self.proc.stdin.write(_json(dict(params, id=identity, op=operation)) + b'\n')
            self.proc.stdin.flush()
            reply = answer.get(timeout=self.timeout * 3 + 3)
            if 'error' in reply:
                raise RuntimeError('Selection helper refused or lost its private channel')
            return reply
        finally:
            with self.pending_lock:
                self.pending.pop(identity, None)

    def _binding(self):
        return {'server': _server_identity(self.display, self.env['XAUTHORITY']),
                'state': {'device': self.root_identity[0], 'inode': self.root_identity[1]}}

    def _manager_env(self):
        # systemctl must reach the user manager, never the private desktop bus.
        runtime = Path('/run/user', str(os.getuid()))
        _file_identity(runtime, 0o700, stat.S_ISDIR)
        env = dict(self.env, XDG_RUNTIME_DIR=str(runtime),
                   DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(runtime / 'bus'))
        return env

    def _unit_identity(self, unit):
        if (not isinstance(unit, str) or not unit.startswith('hepta-x11-selection-')
                or not unit.endswith('.service') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in unit)):
            raise ValueError('Invalid owned selection unit')
        result = subprocess.run(['systemctl', '--user', 'show', unit,
            '--property=MainPID', '--property=InvocationID', '--property=ActiveState'],
            env=self._manager_env(), capture_output=True, timeout=self.timeout, check=True)
        values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        pid = int(values.get('MainPID', '0'))
        invocation = values.get('InvocationID', '')
        if values.get('ActiveState') != 'active' or len(invocation) != 32:
            raise ValueError('Persistent selection unit is not active')
        return {'main_pid': pid, 'main_starttime': _process_start(pid), 'invocation_id': invocation}

    def _unit_stopped(self, unit):
        if (not isinstance(unit, str) or not unit.startswith('hepta-x11-selection-')
                or not unit.endswith('.service') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in unit)):
            raise ValueError('Invalid pending selection unit')
        result = subprocess.run(['systemctl', '--user', 'show', unit, '--property=LoadState',
            '--property=ActiveState', '--property=MainPID'], env=self._manager_env(),
            capture_output=True, timeout=self.timeout, check=False)
        values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
        if (values.get('LoadState') not in ('not-found', 'loaded')
                or values.get('ActiveState') not in ('inactive', 'failed') or values.get('MainPID') != '0'):
            raise ValueError('Prior selection launch has not been proven stopped; no replacement')

    def _wait_launch(self, marker):
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            try:
                row = json.loads(_read_file(self.root_fd, 'helper.json', MAX_MESSAGE))
                if row.get('nonce') == marker['nonce']:
                    if row.get('unit') != marker['unit']:
                        raise ValueError('Pending holder unit differs from the submitted launch')
                    self.daemon = self._verify_daemon(row)
                    _publish(self.root_fd, 'launch.json', dict(marker, phase='ready'))
                    return
            except FileNotFoundError:
                pass
            time.sleep(.03)
        raise TimeoutError('Same persistent launch remains unconfirmed; no replacement or input replay')

    def _verify_daemon(self, row):
        self._guard()
        if row != json.loads(_read_file(self.root_fd, 'helper.json', MAX_MESSAGE)):
            raise ValueError('Persistent holder anchor changed')
        if (row.get('version') != PROTOCOL or row.get('status') != 'running'
                or row.get('binding') != self._binding()
                or row.get('source_sha256') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                or row.get('budget') != self.budget or row.get('timeout') != self.timeout):
            raise ValueError('Persistent holder identity/configuration differs; no automatic adoption')
        _identity(row.get('nonce'))
        if _process_start(row.get('pid')) != row.get('starttime'):
            raise ValueError('Persistent holder PID was reused')
        unit = self._unit_identity(row.get('unit'))
        if unit != row.get('unit_identity'):
            raise ValueError('Persistent holder unit was replaced')
        own_cgroup = Path('/proc', str(row['pid']), 'cgroup').read_bytes()
        if own_cgroup != Path('/proc', str(unit['main_pid']), 'cgroup').read_bytes():
            raise ValueError('Holder is outside its independent user unit')
        argv = Path('/proc', str(row['pid']), 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
        if argv[:5] != [os.fsencode(self.python), b'-I', b'-B', os.fsencode(Path(__file__).resolve()), b'--daemon'] or len(argv) != 6:
            raise ValueError('Holder executable/configuration differs')
        launch = json.loads(argv[5])
        expected = {'display': self.display, 'state_path': str(self.state_path), 'budget': self.budget,
            'timeout': self.timeout, 'persistent_daemon': True, 'nonce': row['nonce'],
            'unit': row['unit'], 'binding': row['binding'], 'source_sha256': row['source_sha256']}
        if any(launch.get(key) != value for key, value in expected.items()):
            raise ValueError('Holder arguments do not match the pinned state/profile')
        current = _file_identity(self.state_path / 'control.sock', 0o600, stat.S_ISSOCK)
        if current != row.get('socket_identity'):
            raise ValueError('Persistent control socket was replaced')
        return row

    def _ensure_daemon(self, explicit_recovery=False):
        import fcntl
        if self.detached or self.confirmed_closed or self.root_fd is None:
            raise ValueError('Selection client is closed/detached')
        self._guard()
        fd = os.open('launch.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.root_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError('Unsafe private launch lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self._ensure_daemon_locked(explicit_recovery)
        finally:
            os.close(fd)

    def _ensure_daemon_locked(self, explicit_recovery=False):
        if self.detached or self.confirmed_closed:
            raise ValueError('Selection client is closed/detached')
        if self.daemon is not None:
            try:
                self._verify_daemon(self.daemon)
                return
            except Exception:
                if not explicit_recovery:
                    raise
                self.daemon = None
        try:
            old = json.loads(_read_file(self.root_fd, 'helper.json', MAX_MESSAGE))
        except FileNotFoundError:
            old = None
        if old and old.get('status') != 'closed':
            try:
                self.daemon = self._verify_daemon(old)
                return
            except Exception:
                if not explicit_recovery:
                    raise ValueError('Prior holder unavailable; use explicit restore, never replay input') from None
                # Recovery authorizes a new holder only for this SAME live X
                # server/state. No lost ownership epoch is claimed as known.
                if old.get('binding') != self._binding():
                    raise ValueError('Prior holder belonged to a different X server/state') from None
                try:
                    if _process_start(old['pid']) == old['starttime']:
                        raise ValueError('Prior holder still exists; recovery refuses replacement')
                except FileNotFoundError:
                    pass
                self._unit_stopped(old.get('unit'))
        try:
            marker = json.loads(_read_file(self.root_fd, 'launch.json', MAX_MESSAGE))
        except FileNotFoundError:
            marker = None
        if marker:
            _identity(marker.get('nonce'))
            if (marker.get('version') != PROTOCOL or marker.get('binding') != self._binding()
                    or marker.get('source_sha256') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
                    or marker.get('budget') != self.budget or marker.get('timeout') != self.timeout
                    or marker.get('python') != self.python):
                raise ValueError('Pending selection launch identity differs; no automatic replacement')
            closed = bool(old and old.get('status') == 'closed' and old.get('nonce') == marker['nonce'])
            if not closed and not explicit_recovery:
                return self._wait_launch(marker)
            self._unit_stopped(marker.get('unit'))
            _publish(self.root_fd, 'retired-launch-' + marker['nonce'] + '.json', marker)
        nonce = uuid.uuid4().hex
        unit = 'hepta-x11-selection-' + nonce + '.service'
        logname = 'helper-' + nonce + '.log'
        fd = os.open(logname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=self.root_fd)
        os.close(fd)
        config = {'display': self.display, 'state_path': str(self.state_path), 'budget': self.budget,
            'timeout': self.timeout, 'persistent_daemon': True, 'nonce': nonce, 'unit': unit,
            'binding': self._binding(), 'explicit_recovery': explicit_recovery,
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        marker = {'version': PROTOCOL, 'nonce': nonce, 'unit': unit, 'binding': config['binding'],
                  'source_sha256': config['source_sha256'], 'budget': self.budget,
                  'timeout': self.timeout, 'python': self.python, 'phase': 'submission_pending'}
        _publish(self.root_fd, 'launch.json', marker)
        command = ['systemd-run', '--user', '--quiet', '--collect', '--unit=' + unit,
            '--property=Type=exec', '--property=Restart=no', '--property=UMask=0077',
            '--property=StandardOutput=null', '--property=StandardError=append:' + str(self.state_path / logname)]
        for key in ('DISPLAY', 'XAUTHORITY', 'GDK_BACKEND', 'GTK_USE_PORTAL', 'NO_AT_BRIDGE',
                    'GTK_IM_MODULE', 'PYTHONDONTWRITEBYTECODE', 'LANG', 'LC_ALL',
                    'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CACHE_HOME', 'HEPTA_X11_SELECTION_DIAGNOSTICS'):
            if key in self.env:
                command.append('--setenv=' + key + '=' + self.env[key])
        command += ['--', '/usr/bin/dbus-run-session', '--', self.python, '-I', '-B',
                    str(Path(__file__).resolve()), '--daemon', _json(config).decode()]
        try:
            subprocess.run(command, env=self._manager_env(), capture_output=True, timeout=self.timeout, check=True)
        except BaseException:
            _publish(self.root_fd, 'launch.json', dict(marker, phase='submission_outcome_unknown'))
            raise
        _publish(self.root_fd, 'launch.json', dict(marker, phase='submitted'))
        self._wait_launch(marker)

    def _socket_rpc(self, operation, **params):
        self._verify_daemon(self.daemon)
        identity = uuid.uuid4().hex
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(self.timeout * 3 + 3)
            # /proc/self/fd keeps the pathname short even for long private roots;
            # it resolves to the already pinned directory, without chdir races.
            channel.connect('/proc/self/fd/' + str(self.root_fd) + '/control.sock')
            pid, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid() or pid != self.daemon['pid'] or _process_start(pid) != self.daemon['starttime']:
                raise ValueError('Private holder peer identity mismatch')
            channel.sendall(_json(dict(params, id=identity, op=operation,
                client_id=self.client_id, nonce=self.daemon['nonce'])) + b'\n')
            raw = bytearray()
            while b'\n' not in raw:
                block = channel.recv(min(65536, MAX_MESSAGE + 1 - len(raw)))
                if not block or len(raw) + len(block) > MAX_MESSAGE:
                    raise ValueError('Private holder response malformed/truncated')
                raw.extend(block)
            line, extra = bytes(raw).split(b'\n', 1)
            response = json.loads(line)
            if extra or response.get('id') != identity or response.get('nonce') != self.daemon['nonce'] or 'error' in response:
                raise ValueError('Private holder response refused/mismatched; no replay')
            return response

    def reconnect(self):
        with self.lock:
            self._ensure()
            return self._rpc('status')['result'] if self.persistent else {'persistent_daemon': False, 'helper_alive': True}

    def status(self):
        with self.lock:
            if self.root_fd is None:
                raise ValueError('Selection client is closed/detached')
            if self.persistent:
                self._guard()
                try:
                    row = json.loads(_read_file(self.root_fd, 'helper.json', MAX_MESSAGE))
                except FileNotFoundError:
                    try:
                        marker = json.loads(_read_file(self.root_fd, 'launch.json', MAX_MESSAGE))
                    except FileNotFoundError:
                        marker = None
                    return {'persistent_daemon': True, 'helper_alive': None if marker else False,
                            'recovery_required': bool(marker), 'launch_pending': bool(marker),
                            'server_identity_verified': False, 'automatic_retry': False}
                try:
                    self.daemon = self._verify_daemon(row)
                except Exception:
                    try:
                        marker = json.loads(_read_file(self.root_fd, 'launch.json', MAX_MESSAGE))
                    except FileNotFoundError:
                        marker = None
                    if marker and marker.get('nonce') != row.get('nonce'):
                        return {'persistent_daemon': True, 'helper_alive': None, 'recovery_required': True,
                                'launch_pending': True, 'server_identity_verified': False, 'automatic_retry': False}
                    alive = None
                    try:
                        alive = _process_start(row.get('pid')) == row.get('starttime')
                    except (FileNotFoundError, ProcessLookupError):
                        alive = False
                    except Exception:
                        pass
                    return {'persistent_daemon': True, 'helper_alive': alive,
                            'recovery_required': row.get('status') != 'closed',
                            'server_identity_verified': False, 'automatic_retry': False,
                            'reason': 'holder_identity_unverified_no_automatic_adoption'}
            elif self.proc is None:
                return {'persistent_daemon': False, 'helper_alive': False, 'automatic_retry': False}
            return self._rpc('status')['result']

    def list_backups(self, offset=0, limit=50):
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('Invalid backup page')
        if self.root_fd is None:
            raise ValueError('Selection client is closed/detached')
        self._guard()
        names = sorted(name for name in os.listdir(self.root_fd)
                       if len(name) == 32 and all(c in '0123456789abcdef' for c in name))
        rows = []
        try:
            binding = self._binding()
        except Exception:
            binding = None
        for identity in names[offset:offset + limit]:
            try:
                offer = _snapshot_offer(self.root_fd, identity, self.budget, binding)
                rows.append({'transaction_id': identity, 'complete': True, 'restore_eligible': True,
                    'data_targets': len(offer['entries']), 'bytes': sum(x['bytes'] for x in offer['entries'].values())})
            except Exception:
                rows.append({'transaction_id': identity, 'complete': False, 'restore_eligible': False,
                             'reason': 'snapshot_or_server_identity_unverified'})
        return {'backups': rows, 'total': len(names), 'offset': offset,
            'next_offset': offset + len(rows) if offset + len(rows) < len(names) else None,
            'automatic_restore': False, 'original_owner_restored': False}

    def restore_clipboard(self, transaction_id, expected_owner=0):
        _identity(transaction_id)
        if self.root_fd is None:
            raise ValueError('Selection client is closed/detached')
        if type(expected_owner) is not int or expected_owner != 0:
            raise ValueError('Explicit recovery only accepts an expected empty clipboard owner (0)')
        with self.lock:
            _snapshot_offer(self.root_fd, transaction_id, self.budget, self._binding())
            if self.persistent:
                self._ensure_daemon(explicit_recovery=True)
            else:
                self._ensure()
            return self._rpc('restore_backup', transaction_id=transaction_id, expected_owner=expected_owner)['result']

    def detach(self):
        with self.lock:
            if not self.persistent:
                raise ValueError('Detached continuity requires the persistent daemon mode')
            self.detached = True
            if self.root_fd is not None:
                os.close(self.root_fd); self.root_fd = None
            return {'detached': True, 'persistent_daemon': True,
                    'holder_stopped': False, 'input_replayed': False}

    def _wait_daemon_closed(self):
        end = time.monotonic() + self.timeout
        while time.monotonic() < end:
            try:
                gone = _process_start(self.daemon['pid']) != self.daemon['starttime']
            except (FileNotFoundError, ProcessLookupError):
                gone = True
            if gone:
                self.confirmed_closed = True; self._release_channels()
                return {'closed': True, 'helper_alive': False, 'persistent_daemon': True}
            time.sleep(.02)
        return {'closed': False, 'helper_alive': True, 'close_acknowledged': True,
                'persistent_daemon': True}

    def receipt(self, identity):
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
            raise ValueError('Invalid transaction identity')
        self._guard()
        folder = os.open(self.state_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(folder)
            if ((info.st_dev, info.st_ino) != self.root_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise RuntimeError('Receipt directory changed while reopening')
            return json.loads(_read_file(folder, 'receipt-' + identity + '.json', MAX_MESSAGE))
        finally:
            os.close(folder)

    def _remember(self, receipt):
        # Exists before any IPC submission: even an outcome lost before the
        # helper reads begin retains this same identity for read-only diagnosis.
        self._guard()
        _publish(self.root_fd, 'receipt-' + receipt['transaction_id'] + '.json', receipt)

    def run(self, text, paste_callback, keys=('CTRL', 'V')):
        identity = uuid.uuid4().hex
        receipt = _receipt(identity)
        self.last_transaction_id = identity
        ipc_attempted = False
        with self.lock:
            try:
                if getattr(self, 'confirmed_closed', False):
                    raise ValueError('Selection wrapper has been explicitly closed')
                if getattr(self, 'detached', False):
                    raise ValueError('Selection client has detached; construct a new client to reconnect')
                if (not isinstance(text, str) or '\x00' in text or not callable(paste_callback)
                        or not isinstance(keys, (tuple, list)) or not keys
                        or any(not isinstance(k, str) or not k or '\x00' in k for k in keys)):
                    raise ValueError('Invalid text or paste callback')
                if len(text.encode()) > MAX_MESSAGE // 2:
                    raise ValueError('Temporary text exceeds private protocol bounds')
                keys = tuple(keys)
                # Nothing has touched the selection, including helper startup.
                paste_callback(tuple(keys), preflight=True)
                self._remember(receipt)
                self._ensure()
                ipc_attempted = True
                result = self._rpc('begin', transaction_id=identity, text=text)
                receipt = result['receipt']
                if result.get('status') != 'prepared':
                    raise ClipboardTransactionError(receipt.get('failure_reason', 'snapshot_refused'), receipt)
                armed = self._rpc('arm', transaction_id=identity)
                receipt = armed['receipt']
                if armed.get('status') != 'armed':
                    raise ClipboardTransactionError('publication_or_owner_changed', receipt)
                paste_error = None
                paste_receipt = {}
                try:
                    paste_receipt = _paste_metadata(paste_callback(tuple(keys), preflight=False))
                except BaseException as error:
                    paste_error = type(error).__name__
                    paste_receipt = _paste_metadata(getattr(error, 'receipt', None))
                result = self._rpc('finish', transaction_id=identity, paste_error=paste_error,
                                   paste_receipt=paste_receipt)
                receipt = result['receipt']
                if paste_error or result.get('status') != 'completed':
                    raise ClipboardTransactionError(receipt.get('failure_reason', 'paste_or_restore_refused'), receipt)
                return receipt
            except ClipboardTransactionError:
                raise
            except BaseException:
                # Do not republish, retry a paste, terminate the lazy owner, or
                # claim restoration after an uncertain private-channel outcome.
                try:
                    receipt = self.receipt(identity)
                except Exception:
                    pass
                receipt = dict(receipt, private_channel_outcome_unknown=ipc_attempted)
                raise ClipboardTransactionError('private_channel_or_preflight_refused', receipt) from None

    def _release_channels(self):
        # Never close the IPC/lifetime anchor of a still-running lazy owner.
        if self.proc is not None and self.proc.poll() is None:
            return
        reader = getattr(self, 'reader_thread', None)
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=1)
        for stream in (getattr(self.proc, 'stdin', None), getattr(self.proc, 'stdout', None),
                       getattr(self, 'log', None)):
            if stream is not None:
                stream.close()
        descriptor = getattr(self, 'root_fd', None)
        if descriptor is not None:
            os.close(descriptor); self.root_fd = None

    def close(self):
        with self.lock:
            if getattr(self, 'confirmed_closed', False):
                return {'closed': True, 'helper_alive': False}
            if getattr(self, 'persistent', False):
                if self.detached:
                    return {'closed': False, 'detached': True, 'holder_stopped': False}
                if getattr(self, 'daemon_close_acknowledged', False):
                    return self._wait_daemon_closed()
                if self.daemon is None:
                    try:
                        old = json.loads(_read_file(self.root_fd, 'helper.json', MAX_MESSAGE))
                    except FileNotFoundError:
                        old = None
                    if old and old.get('status') != 'closed':
                        self._ensure_daemon()
                    else:
                        try:
                            marker = json.loads(_read_file(self.root_fd, 'launch.json', MAX_MESSAGE))
                        except FileNotFoundError:
                            marker = None
                        if marker and (not old or marker.get('nonce') != old.get('nonce')):
                            return {'closed': False, 'helper_alive': None, 'initialization_outcome_unknown': True,
                                    'persistent_daemon': True}
                        if old and old.get('starttime') is not None:
                            try:
                                if _process_start(old['pid']) == old['starttime']:
                                    return {'closed': False, 'helper_alive': True, 'close_acknowledged': True,
                                            'persistent_daemon': True}
                            except (FileNotFoundError, ProcessLookupError):
                                pass
                        self.confirmed_closed = True; self._release_channels()
                        return {'closed': True, 'helper_alive': False}
                try:
                    result = self._rpc('close')['result']
                    if result.get('closed'):
                        self.daemon_close_acknowledged = True
                        return self._wait_daemon_closed()
                    return result
                except Exception:
                    return {'closed': False, 'helper_alive': None,
                            'close_outcome_unknown': True, 'persistent_daemon': True}
            if self.proc is None:
                self.confirmed_closed = True; self._release_channels()
                return {'closed': True, 'helper_alive': False}
            if self.proc.poll() is not None:
                self.proc.wait()
                self._release_channels()
                return {'closed': False, 'helper_alive': False, 'offer_lifetime_lost': True}
            try:
                result = self._rpc('close')['result']
                if result.get('closed'):
                    self.proc.wait(timeout=self.timeout)
                    self.confirmed_closed = True
                    self._release_channels()
                return result
            except Exception:
                return {'closed': False, 'helper_alive': self.proc.poll() is None,
                        'close_outcome_unknown': True}


class _Helper:
    def __init__(self, config):
        # No GTK imports or object construction occur in the parent wrapper.
        import gi
        gi.require_version('Gtk', '3.0'); gi.require_version('GdkX11', '3.0')
        from gi.repository import Gtk, Gdk, GdkX11, GLib
        self.Gtk, self.Gdk, self.GLib = Gtk, Gdk, GLib
        self.config, self.timeout, self.budget = config, config['timeout'], config['budget']
        self.persistent = config.get('persistent_daemon', False)
        self.path = Path(config['state_path'])
        self.root = _private_root(self.path)
        self.root_identity = (os.fstat(self.root).st_dev, os.fstat(self.root).st_ino)
        self.debug_fd = None
        if os.environ.get('HEPTA_X11_SELECTION_DIAGNOSTICS') == '1':
            self.debug_fd = os.open('diagnostics-' + uuid.uuid4().hex + '.jsonl',
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=self.root)
        import fcntl
        self.owner_fd = os.open('owner.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                                0o600, dir_fd=self.root)
        owner = os.fstat(self.owner_fd)
        if not stat.S_ISREG(owner.st_mode) or owner.st_uid != os.getuid() or stat.S_IMODE(owner.st_mode) != 0o600 or owner.st_nlink != 1:
            raise ValueError('Unsafe private selection lock')
        fcntl.flock(self.owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old = None
        try:
            old = json.loads(_read_file(self.root, 'helper.json', MAX_MESSAGE))
            if old.get('status') != 'closed':
                if not self.persistent or not config.get('explicit_recovery') or old.get('binding') != config.get('binding'):
                    raise ValueError('Prior helper lifetime unconfirmed; explicit same-server recovery required')
                try:
                    if _process_start(old['pid']) == old['starttime']:
                        raise ValueError('Prior helper still alive; refusing replacement')
                except FileNotFoundError:
                    pass
                _publish(self.root, 'retired-helper-' + uuid.uuid4().hex + '.json', old)
        except FileNotFoundError:
            pass
        self.binding = {'server': _server_identity(config['display'], os.environ['XAUTHORITY']),
                        'state': {'device': self.root_identity[0], 'inode': self.root_identity[1]}}
        if self.persistent and (config.get('binding') != self.binding
                or config.get('source_sha256') != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()):
            raise ValueError('Persistent helper source/server/state binding changed')
        if self.persistent:
            marker = json.loads(_read_file(self.root, 'launch.json', MAX_MESSAGE))
            if any(marker.get(key) != config.get(key) for key in
                   ('nonce', 'unit', 'binding', 'source_sha256', 'budget', 'timeout')):
                raise ValueError('Persistent helper differs from the private submitted launch')
        ok, _ = Gtk.init_check([])
        if not ok:
            raise ValueError('Explicit X11 GTK display unavailable')
        self.display = Gdk.Display.open(config['display'])
        if not self.display or not isinstance(self.display, GdkX11.X11Display):
            raise ValueError('A genuine explicit X11 display is required')
        self.atom = Gdk.Atom.intern('CLIPBOARD', False)
        if not self.display.request_selection_notification(self.atom):
            raise ValueError('XFIXES selection ownership notifications are required')
        self.clipboard = Gtk.Clipboard.get_for_display(self.display, self.atom)
        self.clipboard.connect('owner-change', self._owner_changed)
        self.widget = Gtk.Invisible.new_for_screen(self.display.get_default_screen())
        self.widget.realize()
        self.window = self.widget.get_window()
        self.xid = self.window.get_xid()
        self.widget.connect('selection-get', self._selection_get)
        self.xlib = ctypes.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
        self.xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]; self.xlib.XOpenDisplay.restype = ctypes.c_void_p
        self.xlib.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]; self.xlib.XInternAtom.restype = ctypes.c_ulong
        self.xlib.XGetSelectionOwner.argtypes = [ctypes.c_void_p, ctypes.c_ulong]; self.xlib.XGetSelectionOwner.restype = ctypes.c_ulong
        self.monitor = self.xlib.XOpenDisplay(config['display'].encode())
        if not self.monitor:
            raise ValueError('Explicit owner-monitor connection failed')
        self.selection = self.xlib.XInternAtom(self.monitor, b'CLIPBOARD', 0)
        self.epoch = self.foreign = 0
        self.serving = self.active = None
        self.buffer = b''; self.connected = True
        self.loop = GLib.MainLoop()
        self.context = GLib.MainContext.default()
        if self.persistent:
            self.clients = {}; self.dispatching = False
            try:
                current = _file_identity(self.path / 'control.sock', 0o600, stat.S_ISSOCK)
                if not old or current != old.get('socket_identity'):
                    raise ValueError('Unknown stale private control socket')
                os.unlink('control.sock', dir_fd=self.root)
            except FileNotFoundError:
                pass
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.listener.bind('/proc/self/fd/' + str(self.root) + '/control.sock')
            os.chmod('control.sock', 0o600, dir_fd=self.root, follow_symlinks=False)
            self.listener.listen(8); self.listener.setblocking(False)
            GLib.io_add_watch(self.listener.fileno(), GLib.IO_IN, self._accept)
        self._anchor('running')
        if not self.persistent:
            os.set_blocking(sys.stdin.fileno(), False)
            GLib.io_add_watch(sys.stdin.fileno(), GLib.IO_IN | GLib.IO_HUP | GLib.IO_ERR, self._input)
        GLib.timeout_add(100, self._watchdog)

    def _guard(self):
        fd = os.open('/', os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in self.path.parts[1:]:
                new = os.open(name, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = new
            info = os.fstat(fd)
            current = os.stat('owner.lock', dir_fd=self.root, follow_symlinks=False)
            owned = os.fstat(self.owner_fd)
            if ((info.st_dev, info.st_ino) != self.root_identity or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or current.st_nlink != 1
                    or not stat.S_ISREG(current.st_mode) or current.st_uid != os.getuid()
                    or stat.S_IMODE(current.st_mode) != 0o600
                    or (current.st_dev, current.st_ino) != (owned.st_dev, owned.st_ino)):
                raise ValueError('Snapshot root or lock identity changed')
        finally:
            os.close(fd)

    def _anchor(self, status):
        self._guard()
        row = {'version': 1, 'pid': os.getpid(), 'display': self.config['display'], 'status': status}
        if self.persistent:
            probe = X11Selection.__new__(X11Selection)
            probe.env, probe.timeout = dict(os.environ), self.timeout
            row.update(version=PROTOCOL, nonce=self.config['nonce'], unit=self.config['unit'],
                starttime=_process_start(os.getpid()), unit_identity=probe._unit_identity(self.config['unit']),
                binding=self.binding, source_sha256=self.config['source_sha256'],
                socket_identity=_file_identity(self.path / 'control.sock', 0o600, stat.S_ISSOCK),
                budget=self.budget, timeout=self.timeout)
        _publish(self.root, 'helper.json', row)

    def _debug(self, event, **metadata):
        descriptor = getattr(self, 'debug_fd', None)
        if descriptor is not None:
            try:
                self._guard()
                os.write(descriptor, _json(dict(event=event, monotonic=time.monotonic(), **metadata)) + b'\n')
            except Exception:
                pass

    def _owner(self):
        return int(self.xlib.XGetSelectionOwner(self.monitor, self.selection))

    def _owner_changed(self, clipboard, event):
        self.epoch += 1
        # Inspect this event's owner, not only the latest server owner: a
        # foreign change followed by another change must never disappear.
        try:
            changed = event.owner.get_xid() if event.owner is not None else None
        except Exception:
            changed = None
        if changed != self.xid:
            self.foreign += 1
        if self._owner() != self.xid:
            self.serving = None
        self._debug('owner_change', event_owner=changed, current_owner=self._owner(),
                    epoch=self.epoch, foreign=self.foreign,
                    selection_time=getattr(event, 'selection_time', None), time=getattr(event, 'time', None))

    def _pump(self):
        while self.context.pending():
            self.context.iteration(False)

    def _wait(self, predicate):
        end = time.monotonic() + self.timeout
        while not predicate():
            self._pump()
            if time.monotonic() >= end:
                raise TimeoutError('Selection request timed out')
            time.sleep(.002)
        self._pump()

    def _read_target(self, target):
        result = []
        def received(clipboard, data, *_):
            if data.get_length() < 0:
                result.append(None)
            else:
                raw = b'' if data.get_length() == 0 else bytes(data.get_data())
                if len(raw) != data.get_length():
                    result.append(None)
                    return
                result.append({'type': data.get_data_type().name(), 'format': data.get_format(),
                               'raw': raw})
        self.clipboard.request_contents(self.Gdk.Atom.intern(target, False), received, None)
        self._wait(lambda: bool(result))
        if result[0] is None:
            raise ValueError('Source target refused')
        self._debug('snapshot_target', target=target, type=result[0]['type'], format=result[0]['format'],
                    bytes=len(result[0]['raw']), sha256=hashlib.sha256(result[0]['raw']).hexdigest())
        return result[0]

    def _same(self, owner, epoch):
        self._pump()
        if self.active and self.active['phase'] == 'snapshot' and (
                not self.connected or time.monotonic() >= self.active['deadline']
                or getattr(self, 'persistent', False) and self.clients.get(self.active.get('control_fd'))
                    is not self.active.get('control_state')):
            raise TimeoutError('Caller/snapshot lease expired before publication')
        if self._owner() != owner or self.epoch != epoch:
            raise ValueError('Clipboard ownership changed')

    def _snapshot(self, identity):
        self._guard(); self._pump()
        source, epoch = self._owner(), self.epoch
        os.mkdir(identity, 0o700, dir_fd=self.root)
        folder = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root)
        entries, total = {}, 0
        try:
            _publish(folder, 'snapshot.json', {'version': 1, 'complete': False})
            if source:
                targets = []
                self.clipboard.request_targets(lambda clipboard, atoms, *_: targets.append(atoms), None)
                self._wait(lambda: bool(targets))
                if targets[0] is None:
                    raise ValueError('Complete original targets unavailable')
                names = [atom.name() for atom in targets[0]]
                if len(names) != len(set(names)) or len(names) > 256 or any(not n or len(n.encode()) > 1024 for n in names):
                    raise ValueError('Original target metadata refused')
                if set(names) & UNSAFE_TARGETS:
                    raise ValueError('Original selection has action or X-resource targets')
                self._same(source, epoch)
                for target in names:
                    if target in CONTROL_TARGETS:
                        continue
                    self._same(source, epoch)
                    value = self._read_target(target)
                    raw = value.pop('raw')
                    if value['format'] not in (8, 16, 32) or value['type'] in UNSAFE_TARGETS:
                        raise ValueError('Original selection format/resource type refused')
                    if total + len(raw) > self.budget:
                        raise OverflowError('Snapshot budget exceeded')
                    name = 'format-' + str(len(entries)).zfill(6) + '.bin'
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 0o600, dir_fd=folder)
                    with os.fdopen(fd, 'wb') as out:
                        out.write(raw); out.flush(); os.fsync(out.fileno())
                    entries[target] = dict(value, file=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
                    total += len(raw)
                    self._same(source, epoch)
                if not entries:
                    raise ValueError('Owned selection has no restorable data targets')
            self._same(source, epoch)
            _publish(folder, 'snapshot.json', {'version': 2, 'complete': True, 'entries': entries,
                'source_empty': not bool(source), 'source_owner': source, 'source_epoch': epoch,
                'binding': self.binding})
            os.fsync(self.root)
        finally:
            os.close(folder)
        return {'kind': 'original', 'backup_id': identity, 'entries': entries,
                'source_owner': source, 'epoch': epoch, 'empty': not bool(source)}

    def _data(self, offer, target):
        if offer['kind'] == 'temporary':
            return {'type': target, 'format': 8}, offer['data']
        self._guard()
        folder = os.open(offer['backup_id'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.root)
        try:
            info = os.fstat(folder)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('Private snapshot folder changed')
            item = offer['entries'][target]
            raw = _read_file(folder, item['file'], self.budget)
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('Private snapshot bytes changed')
            return item, raw
        finally:
            os.close(folder)

    def _selection_get(self, widget, data, info, timestamp):
        offer = self.serving
        target = data.get_target().name()
        self._debug('selection_get', target=target, info=info, timestamp=timestamp,
            kind=offer['kind'] if offer else None, current_owner=self._owner(),
            phase=self.active['phase'] if self.active else None)
        if not offer or self._owner() != self.xid:
            self._debug('selection_get_skipped', target=target, reason='no_offer_or_not_owned')
            return
        try:
            item, raw = self._data(offer, target)
            data.set(self.Gdk.Atom.intern(item['type'], False), item['format'], raw)
            self._debug('selection_get_served', target=target, type=item['type'], format=item['format'],
                bytes=len(raw), set_length=data.get_length() if hasattr(data, 'get_length') else None,
                sha256=hashlib.sha256(raw).hexdigest())
            if self.active and offer['kind'] == 'temporary' and self.active['phase'] in ('armed', 'finishing'):
                self.active['receipt']['transfers'].append({'bytes_provided': len(raw),
                    'selection_data_provided': True, 'consumer_completion_confirmed': False})
        except Exception as error:
            self._debug('selection_get_refused', target=target, error_type=type(error).__name__)
            if self.active:
                self.active['transfer_failed'] = True

    def _publish_offer(self, offer):
        self._guard()
        self.serving = offer
        self.Gtk.selection_clear_targets(self.widget, self.atom)
        names = TEXT_TARGETS if offer['kind'] == 'temporary' else tuple(offer['entries'])
        self._debug('publication_start', kind=offer['kind'], targets=list(names), current_owner=self._owner())
        self.Gtk.selection_add_targets(self.widget, self.atom,
            [self.Gtk.TargetEntry.new(name, 0, i) for i, name in enumerate(names)])
        if not self.Gtk.selection_owner_set_for_display(self.display, self.widget, self.atom, 0):
            raise ValueError('Selection publication failed')
        self.display.sync(); self._pump()
        if self._owner() != self.xid:
            raise ValueError('Selection publication ownership unconfirmed')
        self._debug('publication_confirmed', kind=offer['kind'], owner=self.xid, epoch=self.epoch, foreign=self.foreign)

    def _save(self):
        self._guard()
        row = self.active['receipt']
        _publish(self.root, 'receipt-' + row['transaction_id'] + '.json', row)

    def _restore(self):
        state = self.active; row = state['receipt']; original = state['original']
        self._pump()
        if self.foreign != state['foreign'] or self._owner() != self.xid:
            return 'external_owner_changed_not_overwritten'
        for target in original['entries']:
            self._data(original, target)
        self._pump()
        if self.foreign != state['foreign'] or self._owner() != self.xid:
            return 'external_owner_changed_not_overwritten'
        if original['empty']:
            if not self.Gtk.selection_owner_set_for_display(self.display, None, self.atom, 0):
                raise ValueError('Empty selection restoration failed')
            self.display.sync(); self._pump(); self.serving = None
            return 'complete_original_empty_selection' if self._owner() == 0 else 'external_owner_changed_not_overwritten'
        self._publish_offer(original)
        if self.foreign != state['foreign']:
            return 'external_change_observed_during_restore'
        return 'complete_original_mime_offer_serving'

    def _finish(self, paste_error=None):
        state = self.active; row = state['receipt']
        was_armed = state['phase'] == 'armed'
        state['phase'] = 'finishing'  # Prevent watchdog recursion while pumping.
        failure = paste_error
        if was_armed and not failure:
            try:
                self._wait(lambda: bool(row['transfers']) or self.foreign != state['foreign'] or state.get('transfer_failed'))
                if not row['transfers'] or self.foreign != state['foreign'] or state.get('transfer_failed'):
                    raise ValueError('Paste data was not supplied')
            except Exception:
                failure = 'paste_transfer_unconfirmed'
        try:
            row['restoration'] = self._restore()
            row['original_bytes_offer_restored'] = row['restoration'] in (
                'complete_original_mime_offer_serving', 'complete_original_empty_selection')
        except Exception:
            row['restoration'] = 'restore_failed_private_backup_retained'
        if not row['original_bytes_offer_restored']:
            failure = failure or 'original_offer_not_restored'
        if failure:
            row['failure_reason'] = 'paste_callback_failed' if paste_error else failure
        row['phase'] = 'failed' if failure else 'completed'
        self._save(); self.active = None
        return {'status': row['phase'], 'receipt': row}

    def _dispatch(self, request):
        operation, identity = request['op'], request.get('transaction_id')
        if getattr(self, 'persistent', False) and self.active and operation in ('arm', 'finish'):
            if request.get('client_id') != self.active.get('client_id'):
                raise ValueError('Transaction belongs to another private client; no input replay')
        if operation == 'begin':
            if self.active is not None or not isinstance(identity, str) or len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
                raise ValueError('Overlapping or invalid transaction')
            try:
                existing = json.loads(_read_file(self.root, 'receipt-' + identity + '.json', MAX_MESSAGE))
                if existing != _receipt(identity):
                    return {'status': 'not_replayed', 'receipt': existing}
                try:
                    os.stat(identity, dir_fd=self.root, follow_symlinks=False)
                    return {'status': 'not_replayed', 'receipt': existing}
                except FileNotFoundError:
                    pass
            except FileNotFoundError:
                pass
            row = _receipt(identity)
            self.active = {'receipt': row, 'phase': 'snapshot', 'deadline': time.monotonic() + self.timeout * 3,
                           'client_id': request.get('client_id'), 'control_fd': request.get('_control_fd'),
                           'control_state': request.get('_control_state')}
            self._save()
            try:
                text = request['text']
                if not isinstance(text, str) or '\x00' in text or len(text.encode()) > MAX_MESSAGE // 2:
                    raise ValueError('Invalid temporary text')
                original = self._snapshot(identity)
                row.update(original_bytes_snapshot_complete=True, backup_retained=True,
                    original_data_targets=len(original['entries']), original_bytes=sum(x['bytes'] for x in original['entries'].values()))
                self.active.update(original=original, foreign=self.foreign)
                self._same(original['source_owner'], original['epoch'])
                row['clipboard_publication_attempted'] = True; self._save()
                self._publish_offer({'kind': 'temporary', 'data': text.encode()})
                self.active.update(phase='prepared', deadline=time.monotonic() + self.timeout * 2)
                row['phase'] = 'prepared'; self._save()
                return {'status': 'prepared', 'receipt': row}
            except Exception as error:
                if row['clipboard_publication_attempted']:
                    return self._finish('preparation_failed')
                row.update(phase='failed', failure_reason='snapshot_budget_exceeded' if isinstance(error, OverflowError) else 'snapshot_refused',
                           restoration='not_needed_no_clipboard_publication')
                self._save(); self.active = None
                return {'status': 'failed', 'receipt': row}
        if operation in ('arm', 'finish'):
            if not self.active or self.active['receipt']['transaction_id'] != identity:
                raise ValueError('Unknown transaction; no replay')
            if operation == 'arm':
                if self.active['phase'] != 'prepared' or self._owner() != self.xid or self.foreign != self.active['foreign']:
                    return self._finish('owner_changed_before_paste')
                self.active['phase'] = 'armed'; self.active['receipt']['phase'] = 'armed'
                self.active['receipt']['paste_attempted'] = True
                self.active['receipt']['paste_submission_uncertain'] = True
                self.active['deadline'] = time.monotonic() + self.timeout * 2
                self._save()
                return {'status': 'armed', 'receipt': self.active['receipt']}
            self.active['receipt']['paste_submission_uncertain'] = False
            self.active['receipt']['paste_callback_receipt'] = _paste_metadata(request.get('paste_receipt'))
            self.active['receipt']['paste_input_submitted'] = self.active['receipt']['paste_callback_receipt'].get('submitted')
            return self._finish(request.get('paste_error'))
        if operation == 'status':
            self._guard(); self._pump()
            current = self._owner()
            return {'result': {'persistent_daemon': getattr(self, 'persistent', False),
                'helper_alive': True, 'unit': self.config.get('unit'), 'owns_selection': current == self.xid,
                'serving_original': bool(self.serving and current == self.xid and self.serving['kind'] == 'original'),
                'owner': current, 'owner_epoch': self.epoch, 'foreign_owner_events': self.foreign,
                'active_transaction_id': self.active['receipt']['transaction_id'] if self.active else None,
                'server_identity_verified': self.binding['server'] == _server_identity(self.config['display'], os.environ['XAUTHORITY']),
                'original_owner_restored': False, 'atomic_compare_and_set_available': False,
                'automatic_retry': False}}
        if operation == 'restore_backup':
            if self.active or type(request.get('expected_owner')) is not int or request['expected_owner'] != 0:
                raise ValueError('Explicit restoration requires an idle helper and expected empty owner')
            self._guard(); self._pump()
            if self.binding['server'] != _server_identity(self.config['display'], os.environ['XAUTHORITY']):
                raise ValueError('Different X server; snapshot restoration refused')
            original = _snapshot_offer(self.root, identity, self.budget, self.binding)
            before, epoch = self._owner(), self.epoch
            if before != 0:
                return {'result': {'restored': False, 'reason': 'external_owner_not_overwritten',
                    'transaction_id': identity, 'input_replayed': False}}
            self._pump()
            if self._owner() != 0 or self.epoch != epoch:
                raise ValueError('Clipboard changed before explicit restoration')
            foreign = self.foreign
            if not original['empty']:
                self._publish_offer(original)
            restored = self._owner() == (0 if original['empty'] else self.xid) and self.foreign == foreign
            result = {'restored': restored, 'transaction_id': identity,
                'original_bytes_offer_restored': restored, 'original_owner_restored': False,
                'atomic_compare_and_set_available': False, 'input_replayed': False,
                'ownership_history_during_downtime_known': False,
                'reason': 'complete_original_offer_serving' if restored else 'ownership_changed_during_explicit_restore'}
            _publish(self.root, 'recovery-' + uuid.uuid4().hex + '.json', result)
            return {'result': result}
        if operation == 'close':
            if self.active:
                return {'result': {'closed': False, 'transaction_active': True, 'helper_alive': True}}
            self._pump()
            if self.serving and self._owner() == self.xid:
                return {'result': {'closed': False,
                    'retained_original_offer': self.serving['kind'] == 'original',
                    'retained_temporary_offer': self.serving['kind'] == 'temporary', 'helper_alive': True}}
            self._anchor('closed'); self.GLib.idle_add(self.loop.quit)
            return {'result': {'closed': True, 'helper_alive': False}}
        raise ValueError('Unknown private operation')

    def _accept(self, fd, condition):
        try:
            channel, _ = self.listener.accept()
            _, uid, _ = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != os.getuid() or len(self.clients) >= 16:
                channel.close(); return True
            channel.setblocking(False)
            key = channel.fileno()
            state = {'channel': channel, 'buffer': b'', 'deadline': time.monotonic() + self.timeout * 3 + 3}
            self.clients[key] = state
            state['watch'] = self.GLib.io_add_watch(key, self.GLib.IO_IN | self.GLib.IO_HUP | self.GLib.IO_ERR,
                                                  self._socket_input, state)
        except BlockingIOError:
            pass
        return True

    def _drop_client(self, fd, expected=None):
        state = self.clients.get(fd)
        if expected is not None and state is not expected:
            return
        if state:
            self.clients.pop(fd)
            if state.get('watch'):
                self.GLib.source_remove(state['watch'])
            state['channel'].close()

    def _socket_input(self, fd, condition, expected):
        state = self.clients.get(fd)
        if state is not expected:
            return False
        request = None
        try:
            chunk = state['channel'].recv(65536)
            if not chunk:
                self._drop_client(fd, state); return False
            state['buffer'] += chunk
            if len(state['buffer']) > MAX_MESSAGE:
                raise ValueError('Oversized private request')
            if b'\n' not in state['buffer']:
                return True
            line, extra = state['buffer'].split(b'\n', 1)
            request = json.loads(line)
            if (extra or request.get('nonce') != self.config['nonce'] or self.dispatching
                    or _identity(request.get('client_id')) is None):
                raise ValueError('Invalid or overlapping private control request')
            self.dispatching = True
            try:
                request['_control_fd'] = fd
                request['_control_state'] = state
                response = self._dispatch(request)
            finally:
                self.dispatching = False
        except BlockingIOError:
            return True
        except Exception:
            response = {'error': 'private_operation_refused'}
        try:
            # Small metadata only; bounded blocking send avoids silently dropping
            # a result on a partial nonblocking write. No operation is replayed.
            state['channel'].settimeout(self.timeout)
            state['channel'].sendall(_json(dict(response, id=request.get('id') if isinstance(request, dict) else None,
                                               nonce=self.config['nonce'])) + b'\n')
        except OSError:
            pass
        self._drop_client(fd, state)
        return False

    def _respond(self, identity, value):
        if self.connected:
            try:
                sys.stdout.buffer.write(_json(dict(value, id=identity)) + b'\n')
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                self.connected = False

    def _input(self, fd, condition):
        try:
            chunk = os.read(fd, 65536)
        except BlockingIOError:
            return True
        except OSError:
            chunk = b''
        if not chunk:
            self.connected = False
            # Keep a restored offer alive after caller EOF. Active transactions
            # are restored by the same lease watchdog, without submitting input.
            if not self.active and not (self.serving and self._owner() == self.xid):
                self._anchor('closed'); self.loop.quit()
            return False
        self.buffer += chunk
        if len(self.buffer) > MAX_MESSAGE:
            self.connected = False
            return False
        while b'\n' in self.buffer:
            line, self.buffer = self.buffer.split(b'\n', 1)
            request = None
            try:
                request = json.loads(line)
                response = self._dispatch(request)
            except Exception:
                response = {'error': 'private_operation_refused'}
            self._respond(request.get('id') if isinstance(request, dict) else None, response)
        return True

    def _watchdog(self):
        if getattr(self, 'persistent', False):
            for fd, state in list(self.clients.items()):
                if time.monotonic() >= state['deadline']:
                    self._drop_client(fd, state)
        if self.active and self.active['phase'] in ('prepared', 'armed') and time.monotonic() >= self.active['deadline']:
            self._finish('caller_lease_expired')
        if not getattr(self, 'persistent', False) and not self.connected and not self.active and not (self.serving and self._owner() == self.xid):
            self._anchor('closed'); self.loop.quit(); return False
        return True


def _main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--helper')
    group.add_argument('--daemon')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        helper = _Helper(json.loads(args.daemon or args.helper))
    except Exception:
        if not args.daemon:
            sys.stdout.buffer.write(_json({'id': 'ready', 'error': 'helper_initialization_refused'}) + b'\n')
            sys.stdout.buffer.flush()
        return 1
    if not args.daemon:
        helper._respond('ready', {'status': 'ready'})
    helper.loop.run()
    return 0


if __name__ == '__main__':
    raise SystemExit(_main())
