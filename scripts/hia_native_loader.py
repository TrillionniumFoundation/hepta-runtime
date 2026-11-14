"""Explicit pinned HIA images for the retained Python integration boundary.

The standalone executables do not import this module. This bridge owns only
code admission, immutable mapping and private byte transport, never fallback
implementation of HIA decisions. Trusted native code is not a sandbox.
"""
from __future__ import annotations
import ctypes
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import re
import stat
import threading

ABI = "hepta.runtime.borrowed-bytes.linux-x86_64.v1"
COMPILER_COMMIT = "d3e2c90173cf733e42b299d0c4274df4b593a12f"
MAX_IMAGE = 1 << 20
# Some CPython builds omit the Linux constants although the kernel API exists.
F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
F_GET_SEALS = getattr(fcntl, "F_GET_SEALS", 1034)
F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 1)
F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 2)
F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 4)
F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 8)


class NativeRejected(ValueError):
    """The HIA component rejected an input in its declared byte profile."""
    def __init__(self, message: str, code: int = 0xFFFFFFFF):
        super().__init__(message)
        self.code = code


class NativeCapacityError(ValueError):
    """The HIA component refused a declared buffer capacity."""
    code = 0xFFFFFFFE


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native manifest field")
        result[key] = value
    return result


def _read(path: Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("native input is not an ordinary bounded file")
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        if len(raw) > limit or identity(after) != identity(info):
            raise ValueError("native input changed while being read")
        return raw


class NativeModule:
    """Sealed RX code and independent source/output/workspace per invocation."""
    def __init__(self, manifest_path: str | Path, *, manifest_sha256: str):
        if (platform.system() != "Linux" or platform.machine() != "x86_64"
                or ctypes.sizeof(ctypes.c_void_p) != 8):
            raise ValueError("native HIA module requires Linux x86-64 LP64")
        if type(manifest_sha256) is not str or not re.fullmatch("[0-9a-f]{64}", manifest_sha256):
            raise ValueError("an exact native manifest SHA256 is required")
        path = Path(manifest_path).absolute()
        raw = _read(path, 64 << 10)
        if _sha(raw) != manifest_sha256:
            raise ValueError("native manifest identity mismatch")
        metadata = json.loads(raw, object_pairs_hook=_pairs)
        if (type(metadata) is not dict or metadata.get("schema") != "hepta.runtime.native-module.v1"
            or metadata.get("abi") != ABI or metadata.get("target") != "linux-x86_64"
            or metadata.get("compiler_commit") != COMPILER_COMMIT):
            raise ValueError("native module ABI/compiler differs")
        for name in ("image", "source"):
            value = metadata.get(name)
            if type(value) is not str or not re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
                raise ValueError("native member must be a plain basename")
        for name in ("source_sha256", "image_sha256", "compiler_sha256"):
            if type(metadata.get(name)) is not str or not re.fullmatch("[0-9a-f]{64}", metadata[name]):
                raise ValueError("native member hash is invalid")
        for name, maximum in (("input_capacity", 8 << 20), ("output_capacity", 8 << 20), ("workspace_capacity", 32 << 20)):
            if type(metadata.get(name)) is not int or not 0 < metadata[name] <= maximum:
                raise ValueError("native module declared buffer capacity is invalid")
        self.source_path = path.parent / metadata["source"]
        source = _read(self.source_path, MAX_IMAGE)
        image = _read(path.parent / metadata["image"], MAX_IMAGE)
        if not source or _sha(source) != metadata["source_sha256"]:
            raise ValueError("native source identity mismatch")
        if not image or _sha(image) != metadata["image_sha256"]:
            raise ValueError("native image identity mismatch")
        self.metadata = metadata
        self.manifest_sha256 = manifest_sha256
        self._lock = threading.RLock()
        self._address = None
        self._size = len(image)
        self._entry = None
        libc = ctypes.CDLL(None, use_errno=True)
        libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
        libc.mmap.restype = ctypes.c_void_p
        libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munmap.restype = ctypes.c_int
        self._libc = libc
        descriptor = os.memfd_create("hepta-runtime-native", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            at = 0
            while at < len(image):
                written = os.write(descriptor, image[at:])
                if written <= 0:
                    raise OSError("short write creating native image")
                at += written
            seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL
            fcntl.fcntl(descriptor, F_ADD_SEALS, seals)
            if fcntl.fcntl(descriptor, F_GET_SEALS) & seals != seals:
                raise OSError("native image kernel seals differ")
            address = libc.mmap(None, len(image), mmap.PROT_READ | mmap.PROT_EXEC, mmap.MAP_PRIVATE, descriptor, 0)
            if address is None or address == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_errno(), "mapping sealed native HIA image")
            self._address = address
            self._entry = ctypes.CFUNCTYPE(ctypes.c_uint64, *([ctypes.c_void_p, ctypes.c_uint64] * 3))(address)
        finally:
            os.close(descriptor)

    def invoke(self, wire: bytes, *, output_capacity: int | None = None,
               workspace_capacity: int | None = None) -> bytes:
        """Call HIA once; no host parser, semantic fallback or automatic retry."""
        with self.session(output_capacity=output_capacity, workspace_capacity=workspace_capacity) as session:
            return session.invoke(wire)

    def session(self, *, output_capacity: int | None = None,
                workspace_capacity: int | None = None):
        """Return private persistent HIA state, distinct from immutable code."""
        return NativeSession(self, output_capacity=output_capacity, workspace_capacity=workspace_capacity)

    def invoke_raw(self, wire: bytes, *, output_capacity: int, workspace_capacity: int,
                   output_fill: int = 0, workspace_fill: int = 0):
        """Qualification transport: exact return and entire owned mutable buffers."""
        for value in (output_fill, workspace_fill):
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("native fill must be an exact byte")
        with self.session(output_capacity=output_capacity, workspace_capacity=workspace_capacity) as session:
            ctypes.memset(session._output, output_fill, output_capacity)
            ctypes.memset(session._workspace, workspace_fill, workspace_capacity)
            return session.invoke_raw(wire)

    def _invoke_buffers(self, wire, output, workspace, output_capacity, workspace_capacity, *, raw=False):
        if type(wire) is not bytes or len(wire) > self.metadata["input_capacity"]:
            raise ValueError("native input exceeds its declared byte profile")
        with self._lock:
            if self._entry is None:
                raise RuntimeError("native HIA module has been closed")
            if _sha(_read(self.source_path, MAX_IMAGE)) != self.metadata["source_sha256"]:
                raise ValueError("native source changed after code admission")
            source = ctypes.create_string_buffer(wire, max(1, len(wire)))
            ctypes.memset(ctypes.addressof(output) + output_capacity, 0xA5, 16)
            ctypes.memset(ctypes.addressof(workspace) + workspace_capacity, 0x5A, 16)
            result = self._entry(source, len(wire), output, output_capacity, workspace, workspace_capacity)
            if (source.raw != (wire or b"\0") or output.raw[output_capacity:] != b"\xa5" * 16
                    or workspace.raw[workspace_capacity:] != b"\x5a" * 16):
                raise RuntimeError("native borrowed-buffer boundary changed")
            if raw:
                return result, output.raw[:output_capacity], workspace.raw[:workspace_capacity]
            if result == 0xFFFFFFFF:
                raise NativeRejected("HIA component refused the input")
            if result == 0xFFFFFFFE:
                raise NativeCapacityError("HIA component refused the output/workspace capacity")
            if 0xFFFF0000 <= result <= 0xFFFFFFFF:
                raise NativeRejected("HIA component returned a domain rejection", result)
            if not 0 <= result <= output_capacity:
                raise RuntimeError("native HIA result is outside the declared output")
            return output.raw[:result]

    def close(self):
        with self._lock:
            if self._address is not None:
                self._entry = None
                if self._libc.munmap(self._address, self._size):
                    raise OSError(ctypes.get_errno(), "unmapping native HIA image")
                self._address = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class NativeSession:
    """Per-client state retained across calls without sharing another session."""
    def __init__(self, module: NativeModule, *, output_capacity: int | None = None,
                 workspace_capacity: int | None = None):
        self.module = module
        self.output_capacity = module.metadata["output_capacity"] if output_capacity is None else output_capacity
        self.workspace_capacity = module.metadata["workspace_capacity"] if workspace_capacity is None else workspace_capacity
        for value, maximum in ((self.output_capacity, module.metadata["output_capacity"]),
                               (self.workspace_capacity, module.metadata["workspace_capacity"])):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError("invalid native invocation capacity")
        self._lock = threading.RLock()
        self._output = ctypes.create_string_buffer(self.output_capacity + 16)
        self._workspace = ctypes.create_string_buffer(self.workspace_capacity + 16)

    def invoke(self, wire: bytes) -> bytes:
        with self._lock:
            if self._output is None:
                raise RuntimeError("native HIA session has been closed")
            return self.module._invoke_buffers(wire, self._output, self._workspace,
                self.output_capacity, self.workspace_capacity)

    __call__ = invoke

    def invoke_raw(self, wire: bytes):
        with self._lock:
            if self._output is None:
                raise RuntimeError("native HIA session has been closed")
            return self.module._invoke_buffers(wire, self._output, self._workspace,
                self.output_capacity, self.workspace_capacity, raw=True)

    def close(self):
        with self._lock:
            self._output = self._workspace = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
