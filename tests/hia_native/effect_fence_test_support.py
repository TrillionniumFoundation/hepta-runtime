"""Owned Linux fixtures for the unchanged Rust owner and the HIA prototype."""
from pathlib import Path
import hashlib
import json
import os
import select
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
COUNTS = {"processes": 0, "requests": 0, "responses": 0, "closed_processes": 0}
ROWS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def executable():
    original = os.environ.get("HIA_FENCE_REFERENCE_BINARY")
    if original:
        path = Path(original).resolve(strict=True)
        expected = os.environ["HIA_FENCE_REFERENCE_SHA256"]
        backend = "unchanged-original-rust"
    else:
        manifest = Path(os.environ["HIA_FENCE_MANIFEST"]).resolve(strict=True)
        metadata = json.loads(manifest.read_bytes())
        path = manifest.parent / metadata["executable"]
        expected = metadata["elf_sha256"]
        backend = "native-hia"
    if sha(path.read_bytes()) != expected:
        raise ValueError("effect-fence executable differs")
    return path, expected, backend


class Fixture:
    def __init__(self, role="v4", *, epoch=7):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-effect-owner-")
        self.directory = Path(self.temporary.name)
        self.authority = self.directory / "authority"
        self.state = self.directory / "state"
        self.prior = self.directory / "prior"
        for path in (self.authority, self.state, self.prior):
            path.mkdir(mode=0o700)
        self.role = role
        self.epoch = epoch
        self.write(self.authority / ".owner.lock", b"")
        self.record()
        self.sessions = []

    def write(self, path, raw, mode=0o600):
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def record(self, **changes):
        value = {"schema": "hepta-effect-owner-fence-v1", "owner": self.role,
                 "epoch": self.epoch, "phase": "admitting", "state_root": str(self.state)}
        if self.role == "v11":
            value["predecessor_state_root"] = str(self.prior)
        value.update(changes)
        self.write(self.authority / ".owner.json", json.dumps(value, separators=(",", ":")).encode())
        return value

    def jobs(self):
        path = self.prior / "jobs"
        path.mkdir(mode=0o700, exist_ok=True)
        return path

    def job(self, identity="one", host="local", key="old", *, name=None, **changes):
        value = {"id": identity, "host": host, "idempotency_key": key,
                 "request_digest": "0" * 64 if key is not None else None}
        value.update(changes)
        return self.write(self.jobs() / (name or identity + ".json"),
                          json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode())

    def session(self, case, *, config=None, state=None, close_stderr=False):
        env = {"PATH": "", "HEPTA_EFFECT_OWNER_FENCE_DIR": str(self.authority),
               "HEPTA_EFFECT_OWNER_SELF": self.role}
        if config is not None:
            for name, value in config.items():
                if value is None:
                    env.pop(name, None)
                else:
                    env[name] = value
        p = Session(case, self.state if state is None else state, env, close_stderr=close_stderr)
        self.sessions.append(p)
        return p

    def close(self):
        try:
            for session in self.sessions:
                if session.process.poll() is None:
                    session.close()
        finally:
            self.temporary.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Session:
    def __init__(self, case, state, env, *, close_stderr=False):
        path, self.identity, self.backend = executable()
        self.case = case
        self.process = subprocess.Popen([os.fsencode(path), b"--state-root", os.fsencode(state)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={os.fsencode(k): os.fsencode(v) for k, v in env.items()},
            preexec_fn=(lambda: os.close(2)) if close_stderr else None)
        self.pending = None
        COUNTS["processes"] += 1

    def send(self, op, host="", key=None):
        if self.pending is not None:
            raise AssertionError("qualification transport permits only one outstanding frame")
        host = host.encode() if isinstance(host, str) else host
        key = key.encode() if isinstance(key, str) else key
        body = b"" if key is None else key
        wire = b"HFFCMD01" + struct.pack("<4Q", op, int(key is not None), len(host), len(body)) + host + body
        self.process.stdin.write(struct.pack("<Q", len(wire)) + wire)
        self.process.stdin.flush()
        self.pending = wire
        COUNTS["requests"] += 1

    def receive(self, timeout=45):
        until = time.monotonic() + timeout
        def exact(count):
            result = bytearray()
            while len(result) < count:
                remaining = until - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise AssertionError((self.case, "effect owner response deadline"))
                chunk = os.read(self.process.stdout.fileno(), count - len(result))
                if not chunk:
                    raise AssertionError((self.case, "effect owner transport ended", self.process.poll()))
                result.extend(chunk)
            return bytes(result)
        size = struct.unpack("<Q", exact(8))[0]
        if size != 40:
            raise AssertionError((self.case, "effect owner response shape", size))
        wire = exact(40)
        if wire[:8] != b"HFFRES01":
            raise AssertionError((self.case, "effect owner response magic"))
        result = struct.unpack_from("<4Q", wire, 8)
        ROWS.append({"case": self.case, "ordinal": len(ROWS), "input_hex": self.pending.hex(),
                     "output_hex": wire.hex(), "code": result[0], "errno": result[1]})
        self.pending = None
        COUNTS["responses"] += 1
        return result

    def call(self, op, host="", key=None):
        self.send(op, host, key)
        return self.receive()

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            code = self.process.wait(timeout=5)
            stderr = self.process.stderr.read()
            if code != 0 or stderr:
                raise AssertionError((self.case, "effect owner exit", code, stderr.decode(errors="replace")))
            COUNTS["closed_processes"] += 1
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.process.stdout.close()
            self.process.stderr.close()
