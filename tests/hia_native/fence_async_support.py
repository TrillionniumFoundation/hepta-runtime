"""Owned framed transport for the asynchronous native effect-fence candidate."""
from pathlib import Path
import hashlib
import json
import os
import select
import struct
import subprocess
import time
import effect_fence_test_support as base

COUNTS, ROWS = base.COUNTS, base.ROWS


class Fixture(base.Fixture):
    def session(self, case, *, single=False, config=None, close_stderr=False, trace=False):
        env = {"PATH": "", "HEPTA_EFFECT_OWNER_FENCE_DIR": str(self.authority),
               "HEPTA_EFFECT_OWNER_SELF": self.role}
        for name, value in (config or {}).items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = value
        session = Session(case, self.state, env, single=single, close_stderr=close_stderr,
                          trace=self.directory / ("trace-" + case) if trace else None)
        self.sessions.append(session)
        return session


class Session(base.Session):
    def __init__(self, case, state, env, *, single=False, close_stderr=False, trace=None):
        manifest = Path(os.environ["HIA_FENCE_ASYNC_SINGLE_MANIFEST" if single else "HIA_FENCE_ASYNC_MANIFEST"])
        metadata = json.loads(manifest.read_bytes())
        self.executable = manifest.parent / metadata["executable"]
        if hashlib.sha256(self.executable.read_bytes()).hexdigest() != metadata["elf_sha256"]:
            raise AssertionError("native asynchronous fence artifact differs")
        if metadata["worker_limit"] != (1 if single else 512):
            raise AssertionError("native asynchronous fence worker profile differs")
        self.metadata, self.case, self.trace = metadata, case, trace
        self.pending = None
        args = [str(self.executable), "--state-root", os.fspath(state)]
        if trace is not None:
            args = ["/usr/bin/strace", "-f", "-qq", "-o", str(trace), "-e",
                    "trace=clone,clone3,flock,openat,read,close,futex,exit,exit_group"] + args
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, preexec_fn=(lambda: os.close(2)) if close_stderr else None)
        COUNTS["processes"] += 1

    def send(self, cmd, id=0, method=0, *, host="", key=None):
        if self.pending is not None:
            raise AssertionError("overlapping framed probe request")
        host = host.encode() if isinstance(host, str) else host
        key = key.encode() if isinstance(key, str) else key
        body = b"" if key is None else key
        wire = b"HFFASY01" + struct.pack("<7Q", cmd, id, method, int(key is not None),
                                         len(host), len(body), 0) + host + body
        self.process.stdin.write(struct.pack("<Q", len(wire)) + wire)
        self.process.stdin.flush()
        self.pending = wire
        COUNTS["requests"] += 1

    def receive(self, timeout=40):
        until = time.monotonic() + timeout
        def exact(n):
            out = bytearray()
            while len(out) < n:
                remaining = until - time.monotonic()
                if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                    raise AssertionError((self.case, "framed response timed out", self.process.poll()))
                raw = os.read(self.process.stdout.fileno(), n-len(out))
                if not raw:
                    raise AssertionError((self.case, "transport ended", self.process.poll(), self.process.stderr.read()))
                out.extend(raw)
            return bytes(out)
        size = struct.unpack("<Q", exact(8))[0]
        if size not in (64, 80):
            raise AssertionError((self.case, "response length", size))
        raw = exact(size)
        if raw[:8] != (b"HFFASR01" if size == 64 else b"HFFAST01"):
            raise AssertionError((self.case, "response magic", raw[:8]))
        ROWS.append({"case": self.case, "input_hex": self.pending.hex(), "output_hex": raw.hex()})
        self.pending = None
        COUNTS["responses"] += 1
        return struct.unpack("<" + "Q" * ((size-8)//8), raw[8:])

    def call(self, *args, **kw):
        self.send(*args, **kw)
        return self.receive()

    def create(self, *, permit=0, method=1, host="", key=None):
        result = self.call(1 if method == 1 else 4, permit, method, host=host, key=key)
        if result[0] != 0 or result[1] == 0:
            raise AssertionError((self.case, "future creation", result))
        return result[1]

    def await_future(self, id):
        value = self.call(6, id)
        if value[0] != 0 or value[1] != id:
            raise AssertionError((self.case, "future completion", value))
        return value

    def acquire(self):
        result = self.await_future(self.create())
        if result[3] != 0 or result[2] == 0:
            raise AssertionError((self.case, "expected permit", result))
        return result[2]

    def submit(self, id):
        if self.call(2, id) != (0, id, 0, 0, 0, 0, 0):
            raise AssertionError("future submission differs")

    def cancel(self, id):
        if self.call(3, id) != (0, id, 0, 0, 0, 0, 0):
            raise AssertionError("future cancellation differs")

    def release(self, id):
        if self.call(5, id) != (0, 0, id, 0, 0, 0, 0):
            raise AssertionError("permit release differs")

    def stats(self):
        return self.call(7)

    def wait_stats(self, predicate, timeout=5):
        until = time.monotonic() + timeout
        while True:
            values = self.stats()
            if predicate(values):
                return values
            if time.monotonic() >= until:
                raise AssertionError((self.case, "completion state deadline", values))
            time.sleep(0.005)
