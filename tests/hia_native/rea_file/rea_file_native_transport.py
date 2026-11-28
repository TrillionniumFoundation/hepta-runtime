"""Qualification transport for the closed HIA REA file actor and fd owner.

All admission, read policy, and metadata decisions execute in the HIA actor.
This observer supplies private memory, invokes its fixed syscall companion,
and retains complete action and state records. It is not a public runtime.
"""
from pathlib import Path
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
import struct

PENDING = 0xFFFFFFF0
U64 = (1 << 64) - 1


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def words(raw, offset=0, count=None):
    if count is None:
        count = (len(raw) - offset) // 8
    return struct.unpack_from("<" + "Q" * count, raw, offset)


def put(buffer, at, value):
    struct.pack_into("<Q", buffer, at, value & U64)


def path_request(path, roots):
    path = os.fsencode(path)
    roots = [os.fsencode(root) for root in roots]
    return b"HREAFPL1" + struct.pack("<3Q", 1, len(path), len(roots)) + path + b"".join(
        struct.pack("<Q", len(root)) + root for root in roots)


def metadata(info):
    return tuple(v & U64 for v in (
        info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
        info.st_gid, info.st_nlink, info.st_mtime_ns // 1_000_000_000,
        info.st_mtime_ns % 1_000_000_000, info.st_ctime_ns // 1_000_000_000,
        info.st_ctime_ns % 1_000_000_000))


def fd_snapshot():
    result = {}
    for name in os.listdir("/proc/self/fd"):
        try:
            fd = int(name)
            info = os.fstat(fd)
            result[fd] = (os.readlink("/proc/self/fd/" + name), info.st_dev, info.st_ino,
                          info.st_mode, fcntl.fcntl(fd, fcntl.F_GETFD))
        except FileNotFoundError:
            pass
        except OSError as exc:
            if exc.errno != 9:
                raise
    return result


class Engine:
    def __init__(self, path, expected_sha256):
        self.raw = Path(path).read_bytes()
        if sha(self.raw) != expected_sha256 or self.raw[:8] != b"HREAPK01":
            raise ValueError("exact HIA-emitted engine identity required")
        total, extent, create, step, take, destroy, reserved = words(self.raw, 8, 7)
        if total != len(self.raw) or extent + 64 != total or reserved or not (
                0 <= create < step < take < destroy < extent):
            raise ValueError("engine typed extent or exports differ")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, ctypes.c_long]
        self.libc.mmap.restype = ctypes.c_void_p
        self.libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.libc.munmap.restype = ctypes.c_int
        self.address = None
        self.size = extent
        descriptor = os.memfd_create("hia-rea-file-effects", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            remaining = memoryview(self.raw)[64:]
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short mechanical code write")
                remaining = remaining[written:]
            fcntl.fcntl(descriptor, 1033, 15)
            if fcntl.fcntl(descriptor, 1034) != 15:
                raise ValueError("engine seals differ")
            self.address = self.libc.mmap(None, extent, mmap.PROT_READ | mmap.PROT_EXEC,
                                          mmap.MAP_PRIVATE, descriptor, 0)
            if self.address in (None, ctypes.c_void_p(-1).value):
                raise OSError(ctypes.get_errno(), "mapping sealed mechanical code")
        finally:
            os.close(descriptor)
        self.create = ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p, ctypes.c_uint64)(
            self.address + create)
        for name, offset in (("step", step), ("take", take), ("destroy", destroy)):
            setattr(self, name, ctypes.CFUNCTYPE(ctypes.c_int64, ctypes.c_void_p)(self.address + offset))

    def close(self):
        if self.address is not None:
            if self.libc.munmap(self.address, self.size):
                raise OSError(ctypes.get_errno(), "unmapping mechanical engine")
            self.address = None


class Capture:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.folder.mkdir(mode=0o700, exist_ok=False)
        self.frames = (self.folder / "all-frames.bin").open("xb")
        self.rows = []

    def record(self, event, data, **fields):
        offset = self.frames.tell()
        pins = []
        for name, raw in data:
            self.frames.write(struct.pack("<Q", len(raw)))
            self.frames.write(raw)
            pins.append({"name": name, "bytes": len(raw), "sha256": sha(raw)})
        row = {"event": event, "offset": offset, "segments": pins, **fields}
        self.rows.append(row)
        self.frames.flush()
        (self.folder / "progress.json").write_text(json.dumps(row, sort_keys=True) + "\n")

    def close(self):
        self.frames.close()
        (self.folder / "all-observations.json").write_text(
            json.dumps(self.rows, sort_keys=True, indent=2) + "\n")


class FileActor:
    def __init__(self, module, engine, request, *, mode=0, maximum=0,
                 workspace_capacity=None, output_capacity=None, capture=None, label=""):
        self.module, self.engine = module, engine
        self.request, self.mode, self.maximum = request, mode, maximum
        self.label, self.capture = label, capture
        self.wcap = max(69632, len(request) + 4224) if workspace_capacity is None else workspace_capacity
        minimum = max(128, len(request) + 256)
        if mode and maximum < (1 << 32):
            minimum = max(minimum, maximum + 129)
        self.ocap = minimum if output_capacity is None else output_capacity
        self.input = ctypes.create_string_buffer(request, max(1, len(request)) + 16)
        self.output = ctypes.create_string_buffer(self.ocap + 16)
        self.workspace = ctypes.create_string_buffer(self.wcap + 16)
        ctypes.memset(ctypes.addressof(self.input) + len(request), 0xC3, 16)
        ctypes.memset(ctypes.addressof(self.output) + self.ocap, 0xA5, 16)
        ctypes.memset(ctypes.addressof(self.workspace) + self.wcap, 0x5A, 16)
        if self.wcap >= 160:
            put(self.workspace, 144, mode)
            put(self.workspace, 152, maximum)
        self.context = engine.create(self.workspace, self.wcap)
        if self.context < 0:
            raise ValueError(("engine context refused", self.context))
        self.calls = 0
        self.effects = 0
        self.code = None

    def check_guards(self):
        if bytes(self.input[:len(self.request)]) != self.request:
            raise ValueError("borrowed input changed")
        for buffer, length, fill in ((self.input, len(self.request), 0xC3),
                                     (self.output, self.ocap, 0xA5),
                                     (self.workspace, self.wcap, 0x5A)):
            if ctypes.string_at(ctypes.addressof(buffer) + length, 16) != bytes([fill]) * 16:
                raise ValueError("borrowed boundary guard changed")

    def observe(self, event, **fields):
        self.check_guards()
        if self.capture is not None:
            self.capture.record(event, [
                ("input", self.request), ("output", bytes(self.output[:self.ocap])),
                ("workspace", bytes(self.workspace[:self.wcap])),
                ("context", ctypes.string_at(self.context, 4096))],
                label=self.label, native_calls=self.calls, native_effects=self.effects, **fields)

    def invoke(self):
        self.code = self.module._entry(self.input, len(self.request), self.output, self.ocap,
                                       self.workspace, self.wcap)
        self.calls += 1
        self.observe("actor", code=self.code)
        return self.code

    def step(self):
        result = self.engine.step(self.context)
        self.effects += 1
        self.observe("effect", result=result)
        return result

    def run(self, hook=None):
        while True:
            code = self.invoke()
            if code != PENDING:
                if code >= 0xFFFF0000:
                    return code, b""
                if not 128 <= code <= self.ocap:
                    raise ValueError(("invalid terminal extent", code))
                raw = bytes(self.output[:code])
                if raw[:8] != b"HRFDRS01":
                    raise ValueError("terminal magic differs")
                if hook is not None:
                    hook(self, "terminal")
                return code, raw
            if hook is not None:
                hook(self, "before")
            if self.step() != 0:
                raise ValueError("actual fd step rejected the HIA action")
            if hook is not None:
                hook(self, "after")

    def take(self):
        result = self.engine.take(self.context)
        self.observe("take", result=result)
        return result

    def close(self):
        if self.context is not None:
            self.observe("before-destroy")
            result = self.engine.destroy(self.context)
            self.context = None
            self.check_guards()
            if result != 0:
                raise OSError(-result, "native owned descriptor cleanup")

