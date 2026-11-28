# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualification-only transport for native ASAR descriptor continuations."""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import struct
import sys
import time

WORKSPACE = 256 << 20
OUTPUT = (4 << 20) + 32
PENDING = 0xfffffff0
MASK = (1 << 64) - 1


def metadata_words(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_uid,
        st.st_gid, st.st_nlink, st.st_mtime_ns // 1_000_000_000,
        st.st_mtime_ns % 1_000_000_000, st.st_ctime_ns // 1_000_000_000,
        st.st_ctime_ns % 1_000_000_000]


def request(fd, operation="index", offset=0, limit=64, member="", length=16384,
            require_complete=False):
    raw = member.encode()
    op = {"index": 1, "read": 2}[operation]
    return b"HSARRQ01" + struct.pack("<16Q", op, offset,
        limit if op == 1 else length, int(require_complete), len(raw),
        *(v & MASK for v in metadata_words(os.fstat(fd)))) + raw


class AsarModule:
    def __init__(self, manifest, runtime):
        sys.path.insert(0, str(Path(runtime) / "scripts"))
        from hia_native_loader import NativeModule
        self.manifest = Path(manifest)
        self.module = NativeModule(self.manifest,
            manifest_sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.calls = 0

    def close(self):
        self.module.close()

    def invoke(self, wire, fd, event_stream=None, before_effect=None):
        output = ctypes.create_string_buffer(OUTPUT + 16)
        workspace = ctypes.create_string_buffer(WORKSPACE + 16)
        oa, wa = ctypes.addressof(output), ctypes.addressof(workspace)
        ctypes.memset(oa + OUTPUT, 0xa5, 16)
        ctypes.memset(wa + WORKSPACE, 0x5a, 16)
        sequence = effects = read_bytes = 0
        native_cpu = native_wall = 0.0
        with self.module._lock:
            for _ in range(1_000_000):
                source = ctypes.create_string_buffer(wire, len(wire))
                if event_stream:
                    event_stream.write(json.dumps({"event": "input", "bytes_hex": wire.hex()}) + "\n")
                wall_start, cpu_start = time.monotonic(), time.process_time()
                code = int(self.module._entry(source, len(wire), output, OUTPUT,
                    workspace, WORKSPACE))
                native_cpu += time.process_time() - cpu_start
                native_wall += time.monotonic() - wall_start
                self.calls += 1
                assert source.raw == wire
                assert ctypes.string_at(oa + OUTPUT, 16) == b"\xa5" * 16
                assert ctypes.string_at(wa + WORKSPACE, 16) == b"\x5a" * 16
                if code != PENDING:
                    assert 32 <= code <= OUTPUT, ("native return", code)
                    raw = ctypes.string_at(oa, code)
                    magic, status, error, n = struct.unpack("<8s3Q", raw[:32])
                    assert magic == b"HSARRS01" and status in (0, 1)
                    assert n + 32 == code and (status == 0) == (error == 0)
                    result = {"status": status, "error_code": error,
                        "payload": raw[32:].decode(), "native_calls": effects + 1,
                        "effects": effects, "actual_read_bytes": read_bytes,
                        "native_cpu_seconds": native_cpu, "native_wall_seconds": native_wall}
                    if event_stream:
                        event_stream.write(json.dumps({"event": "terminal", **result}, sort_keys=True) + "\n")
                        event_stream.flush()
                    return result
                effect = struct.unpack("<5Q", ctypes.string_at(wa + 65536, 40))
                magic, current, action, offset, count = effect
                assert magic == int.from_bytes(b"HSARFX01", "little")
                assert current == sequence + 1 and action in (1, 2)
                assert 0 < count <= 16 << 20
                if before_effect:
                    before_effect(effect, wa)
                data, errno = bytearray(), 0
                try:
                    if action == 1:
                        while len(data) < count:
                            part = os.pread(fd, min(65536, count - len(data)), offset + len(data))
                            if not part:
                                break
                            data.extend(part)
                        read_bytes += len(data)
                    else:
                        assert offset == 0 and count == 88
                        data.extend(struct.pack("<11Q", *(v & MASK for v in metadata_words(os.fstat(fd)))))
                except OSError as error:
                    errno = error.errno
                assert len(data) <= count
                wire = b"HSARIN01" + struct.pack("<3Q", current, len(data), errno) + bytes(data)
                if event_stream:
                    event_stream.write(json.dumps({"event": "effect", "request": list(effect),
                        "bytes_hex": bytes(data).hex(), "errno": errno}, sort_keys=True) + "\n")
                sequence, effects = current, effects + 1
            raise AssertionError("ASAR native continuation qualification guard exceeded")
