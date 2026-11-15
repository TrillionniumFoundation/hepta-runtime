"""Qualification transport only: all caller, policy and filesystem decisions are native."""
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import os
import select
import signal
import struct
import subprocess
import time

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
OBSERVED = []


def words(magic, *values):
    return magic + struct.pack('<' + 'Q' * len(values), *values)


def require(value, reason):
    if not value:
        raise AssertionError(reason)


class Session:
    def __init__(self, manifest, root, *, config=None, mode=0, legacy=None,
                 env=None, close_stderr=False, blocked_sigchld=False, trace=None, reference=None):
        self.manifest = Path(manifest).resolve(strict=True)
        self.metadata = json.loads(self.manifest.read_bytes())
        self.exe = self.manifest.parent / self.metadata['executable']
        require(SHA(self.exe.read_bytes()) == self.metadata['elf_sha256'], 'actual service ELF differs')
        require(len(self.metadata['members']) == 21, 'actual full-context regex member set differs')
        self.variant = 'native'
        if reference is not None:
            self.exe = Path(reference['path']).resolve(strict=True)
            require(SHA(self.exe.read_bytes()) == reference['sha256'], 'actual original binary differs')
            self.variant = 'original'
        self.input = bytearray(); self.output = bytearray(); self.pending = bytearray()
        self.events = []; self.closed = False
        self.stderr_closed = close_stderr
        self.environment = {'PATH': '', 'USER': 'operator'} | (env or {})
        for name in tuple(self.environment):
            if self.environment[name] is None:
                self.environment.pop(name)
        snapshot_read, snapshot_write = os.pipe2(os.O_CLOEXEC)
        # The initializer's private read end is distinct from ordinary stdin.
        # Descriptor 4 is reserved before Popen's close-fds pass, then replaced.
        try:
            os.fstat(4)
        except OSError:
            reserve = os.open('/dev/null', os.O_RDONLY | os.O_CLOEXEC)
            require(reserve == 4, 'private startup descriptor reservation differs')
        else:
            reserve = None
        def arrange():
            os.dup2(snapshot_read, 4, inheritable=True)
            if snapshot_read != 4:
                os.close(snapshot_read)
            if close_stderr:
                os.close(2)
            if blocked_sigchld:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
        argv = [os.fsencode(self.exe)]
        if config is not None:
            argv += [b'--runtime-config', os.fsencode(config)]
        argv += [b'--session-root', os.fsencode(root)]
        if trace is not None:
            argv = [b'/usr/bin/strace', b'-f', b'-qq', b'-o', os.fsencode(trace), b'-e',
                b'trace=clone,fork,vfork,execveat,flock,openat,mkdirat,close,pipe2,wait4,kill,prctl,exit,exit_group'] + argv
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=self.environment, pass_fds=tuple({4, snapshot_read}),
                preexec_fn=arrange, start_new_session=False)
        except BaseException:
            os.close(snapshot_write)
            raise
        finally:
            os.close(snapshot_read)
            if reserve is not None:
                os.close(reserve)
        raw = words(b'HMDINIT1', mode, int(legacy is not None), len(legacy or b'')) + (legacy or b'')
        try:
            pos = 0
            while pos < len(raw):
                pos += os.write(snapshot_write, raw[pos:])
        except BaseException:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            raise
        finally:
            os.close(snapshot_write)
        self.snapshot = raw
        self.started = time.monotonic()

    def send(self, command, identifier, payload=b''):
        raw = words(b'HMDCTL01', command, identifier, len(payload)) + payload
        raw = struct.pack('<Q', len(raw)) + raw
        self.process.stdin.write(raw); self.process.stdin.flush()
        self.input.extend(raw)

    def begin(self, identifier, path=b'child', metadata=None):
        if isinstance(path, str):
            path = path.encode()
        raw = words(b'HMDCRQ02', len(path), int(metadata is not None), len(metadata or b''), 0)
        self.send(1, identifier, raw + path + (metadata or b''))

    def event(self, timeout=30):
        end = time.monotonic() + timeout
        while True:
            if len(self.pending) >= 8:
                n = struct.unpack_from('<Q', self.pending)[0]
                require(40 <= n <= 134217768, 'service response length differs')
                if len(self.pending) >= n + 8:
                    raw = bytes(self.pending[8:n + 8]); del self.pending[:n + 8]
                    require(raw[:8] == b'HMDCTR01', 'service response magic differs')
                    kind, identifier, code, count = struct.unpack_from('<4Q', raw, 8)
                    require(len(raw) == 40 + count and kind in (1, 2, 3, 4), 'service event shape differs')
                    require(code <= 0xffffffff, 'service result is not an exact u32')
                    item = (kind, identifier, code, raw[40:])
                    self.events.append({'kind': kind, 'id': identifier, 'code': code, 'payload_hex': raw[40:].hex()})
                    return item
            remaining = end - time.monotonic()
            require(remaining > 0 and select.select([self.process.stdout], [], [], remaining)[0], 'service event deadline')
            raw = os.read(self.process.stdout.fileno(), 65536)
            if not raw:
                raise AssertionError(('service exited', self.process.poll(), self.process.stderr.read()))
            self.pending.extend(raw); self.output.extend(raw)

    def complete(self, identifier, path=b'child', metadata=None):
        self.begin(identifier, path, metadata)
        require(self.event() == (1, identifier, 0, b''), 'begin acknowledgment differs')
        kind, actual, code, raw = self.event()
        require((kind, actual) == (2, identifier), 'completion identity differs')
        require(code == len(raw) and raw[:8] == b'HMDCRS01', 'native caller result differs')
        tag, reserved, n = struct.unpack_from('<3Q', raw, 8)
        require(tag in (0, 1) and reserved == 0 and n == len(raw) - 32, 'native caller result fields differ')
        return tag, raw[32:]

    def close(self, *, expected_exit=0):
        if self.closed:
            return
        try:
            self.process.stdin.close(); self.process.stdin = None
            tail, stderr = self.process.communicate(timeout=30)
            self.pending.extend(tail); self.output.extend(tail)
            require(self.process.returncode == expected_exit, ('service exit differs', self.process.returncode, stderr))
            if self.variant == 'native' or self.stderr_closed:
                require(not stderr, ('unexpected service stderr', stderr))
            else:
                rows = [json.loads(line) for line in stderr.splitlines()]
                require(len(rows) == 2 and rows[0]['schema'] == 'hepta.directory.actual-sdk-bootstrap.v1'
                    and rows[1]['schema'] == 'hepta.directory.original-driver.v1', 'original SDK/driver observation differs')
            require(not self.pending, ('unconsumed service events', bytes(self.pending)))
            require(not Path('/proc', str(self.process.pid)).exists(), 'service process was not reaped')
            OBSERVED.append({'variant': self.variant, 'elf_sha256': SHA(self.exe.read_bytes()), 'pid': self.process.pid,
                'exit_code': self.process.returncode, 'reaped': True, 'events': self.events,
                'input_hex': self.input.hex(), 'output_hex': self.output.hex(),
                'snapshot_hex': self.snapshot.hex(), 'stderr_hex': stderr.hex(),
                'elapsed_seconds': time.monotonic() - self.started})
        except BaseException:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait()
            raise
        finally:
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        if kind is None:
            self.close()
        elif self.process.poll() is None:
            self.process.kill(); self.process.wait()


def exclusive(lock):
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    fcntl.flock(lock, fcntl.LOCK_UN)
    return True


def configuration(directory, *, roots=None, fence=False):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True)
    work = directory / 'workspace'; work.mkdir(mode=0o700)
    state = directory / 'state'
    config = directory / 'config.json'
    config.write_text(json.dumps({'state_dir': str(state),
        'controller_workspace_roots': [str(work)] if roots is None else roots,
        'hosts': {'h': {'ssh_target': 'target', 'remote_state_dir': '/remote'}}}))
    config.chmod(0o600)
    env = {}
    if fence:
        authority = directory / 'authority'; authority.mkdir(mode=0o700)
        lock = authority / '.owner.lock'; lock.write_bytes(b''); lock.chmod(0o600)
        record = authority / '.owner.json'
        record.write_text(json.dumps({'schema': 'hepta-effect-owner-fence-v1', 'owner': 'v4',
            'epoch': 1, 'phase': 'admitting', 'state_root': str(state)}))
        record.chmod(0o600)
        env = {'HEPTA_EFFECT_OWNER_FENCE_DIR': str(authority), 'HEPTA_EFFECT_OWNER_SELF': 'v4',
               'HEPTA_EFFECT_OWNER_FENCE_REQUIRED': '1'}
    return work, config, env
