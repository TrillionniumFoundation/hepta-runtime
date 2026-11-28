# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Qualification-only byte transport for the HIA ZIP descriptor parser.

This module performs only image admission, borrowed-buffer calls, exact reads
from the caller's already-open descriptor, and descriptor metadata capture.
ZIP grammar, budgets, range selection, hashes, error text and JSON are HIA.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import os
import struct
import sys

WORKSPACE = 64 << 20
OUTPUT = (1 << 20) + 40
PENDING = 0xfffffff0
MASK = (1 << 64) - 1


def metadata_words(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_uid,
            st.st_gid, st.st_nlink, st.st_mtime_ns // 1_000_000_000,
            st.st_mtime_ns % 1_000_000_000, st.st_ctime_ns // 1_000_000_000,
            st.st_ctime_ns % 1_000_000_000]


def request(fd, filter_code=0, offset=0, limit=64):
    return b"HZIPRQ01" + struct.pack("<14Q", filter_code, offset, limit,
        *(value & MASK for value in metadata_words(os.fstat(fd))))


def field_request(operation, data, flags=0, method=0, payload_offset=0):
    return b"HZIPAT01" + struct.pack("<5Q", operation, flags, method,
        payload_offset, len(data)) + data


class ZipModule:
    def __init__(self, manifest, runtime):
        sys.path.insert(0, str(Path(runtime) / "scripts"))
        from hia_native_loader import NativeModule
        self.manifest = Path(manifest)
        self.module = NativeModule(self.manifest,
            manifest_sha256=hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.calls = 0

    def close(self):
        self.module.close()

    def invoke(self, wire, fd=None, event_stream=None, before_effect=None):
        source = ctypes.create_string_buffer(wire, len(wire))
        output = ctypes.create_string_buffer(OUTPUT + 16)
        workspace = ctypes.create_string_buffer(WORKSPACE + 16)
        oa = ctypes.addressof(output)
        wa = ctypes.addressof(workspace)
        ctypes.memset(oa + OUTPUT, 0xa5, 16)
        ctypes.memset(wa + WORKSPACE, 0x5a, 16)
        last_sequence, effects, read_bytes = 0, 0, 0
        with self.module._lock:
            for _ in range(1_000_000):
                code = int(self.module._entry(source, len(wire), output, OUTPUT,
                    workspace, WORKSPACE))
                self.calls += 1
                assert source.raw == wire
                assert ctypes.string_at(oa + OUTPUT, 16) == b"\xa5" * 16
                assert ctypes.string_at(wa + WORKSPACE, 16) == b"\x5a" * 16
                if code != PENDING:
                    assert 40 <= code <= OUTPUT, ("native return", code)
                    raw = ctypes.string_at(oa, code)
                    magic, status, error, length, io_bytes = struct.unpack("<8s4Q", raw[:40])
                    assert magic == b"HZIPRS01" and status in (0, 1)
                    assert code == length + 40
                    assert (status == 0) == (error == 0)
                    result = {"status": status, "error_code": error,
                              "payload": raw[40:].decode(), "io_bytes": io_bytes,
                              "actual_read_bytes": read_bytes,
                              "effects": effects, "native_calls": effects + 1}
                    if event_stream:
                        event_stream.write(json.dumps({"event": "terminal", **result},
                            sort_keys=True) + "\n")
                        event_stream.flush()
                    return result
                effect = struct.unpack("<10Q", ctypes.string_at(wa + 8192, 80))
                magic, sequence, action, offset, count, target, done, returned, error, reserved = effect
                assert magic == int.from_bytes(b"HZIPFX01", "little")
                assert sequence == last_sequence + 1 and action in (1, 2)
                assert done == returned == error == reserved == 0
                assert 0 < count <= 65536 and target <= WORKSPACE - count
                assert fd is not None
                if before_effect:
                    before_effect(effect, wa)
                data, error = b"", 0
                try:
                    if action == 1:
                        while len(data) < count:
                            part = os.pread(fd, count - len(data), offset + len(data))
                            if not part:
                                break
                            data += part
                        read_bytes += len(data)
                    else:
                        assert offset == 0 and count == 88 and target == 9000
                        data = struct.pack("<11Q", *(v & MASK for v in metadata_words(os.fstat(fd))))
                except OSError as failure:
                    error = failure.errno
                assert len(data) <= count
                if data:
                    ctypes.memmove(wa + target, data, len(data))
                completion = struct.pack("<4Q", sequence, len(data), error, 0)
                ctypes.memmove(wa + 8192 + 48, completion, len(completion))
                last_sequence, effects = sequence, effects + 1
                if event_stream:
                    event_stream.write(json.dumps({"event": "effect", "request": list(effect),
                        "bytes_hex": data.hex(), "errno": error}, sort_keys=True) + "\n")
            raise AssertionError("HIA continuation failed to terminate within the qualification guard")


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--path", type=Path, required=True)
    parser.add_argument("--events", type=Path)
    args = parser.parse_args()
    module = ZipModule(args.manifest, args.runtime)
    fd = os.open(args.path, os.O_RDONLY)
    events = args.events.open("x") if args.events else None
    try:
        result = module.invoke(request(fd), fd, events)
        print(json.dumps(result, sort_keys=True), flush=True)
    finally:
        if events:
            events.close()
        os.close(fd)
        module.close()


if __name__ == "__main__":
    main()
