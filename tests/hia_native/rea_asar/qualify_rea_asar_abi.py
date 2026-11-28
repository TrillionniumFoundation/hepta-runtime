# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Execute the ASAR borrowed-buffer and continuation contract on native HIA."""
from pathlib import Path
import argparse
import ctypes
import hashlib
import json
import mmap
import os
import struct
import sys
import time
import traceback

from qualify_rea_asar_differential import archive
from rea_asar_native_transport import AsarModule, metadata_words, request

WORKSPACE = 256 << 20
OUTPUT = (4 << 20) + 32
INVALID, CAPACITY, PENDING = 0xffffffff, 0xfffffffe, 0xfffffff0


def changed_word(wire, offset, value):
    data = bytearray(wire)
    struct.pack_into("<Q", data, offset, value)
    return bytes(data)


class Session:
    def __init__(self, owner, log):
        self.owner, self.log = owner, log
        self.memory = mmap.mmap(-1, WORKSPACE + 16)
        self.workspace = (ctypes.c_char * (WORKSPACE + 16)).from_buffer(self.memory)
        self.output = ctypes.create_string_buffer(OUTPUT + 16)
        self.wa, self.oa = ctypes.addressof(self.workspace), ctypes.addressof(self.output)
        ctypes.memset(self.wa + WORKSPACE, 0x5a, 16)
        self.calls = 0

    def close(self):
        del self.workspace
        self.memory.close()

    def call(self, label, wire, output_capacity=OUTPUT, workspace_capacity=WORKSPACE):
        assert 0 <= output_capacity <= OUTPUT and 0 <= workspace_capacity <= WORKSPACE
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        ctypes.memset(self.oa, 0xa5, OUTPUT + 16)
        self.log.write(json.dumps({"event": "intent", "case": label,
            "input_hex": wire.hex(), "output_capacity": output_capacity,
            "workspace_capacity": workspace_capacity}, sort_keys=True) + "\n")
        self.log.flush()
        with self.owner.module._lock:
            result = int(self.owner.module._entry(source, len(wire), self.output,
                output_capacity, self.workspace, workspace_capacity))
        self.calls += 1
        assert ctypes.string_at(source, len(wire)) == wire
        assert ctypes.string_at(self.wa + WORKSPACE, 16) == b"\x5a" * 16
        extent = result if result <= output_capacity else 0
        assert ctypes.string_at(self.oa + extent, OUTPUT + 16 - extent) == b"\xa5" * (OUTPUT + 16 - extent)
        body = ctypes.string_at(self.oa, extent)
        self.log.write(json.dumps({"event": "observation", "case": label,
            "result": result, "output_hex": body.hex(),
            "entire_input_unchanged": True, "entire_unreturned_output_unchanged": True,
            "workspace_tail_guard_unchanged": True}, sort_keys=True) + "\n")
        self.log.flush()
        return result, body

    def completion(self, fd):
        magic, sequence, action, offset, count = struct.unpack(
            "<5Q", ctypes.string_at(self.wa + 65536, 40))
        assert magic == int.from_bytes(b"HSARFX01", "little")
        assert action in (1, 2) and 0 < count <= 16 << 20
        if action == 1:
            data = os.pread(fd, count, offset)
        else:
            assert offset == 0 and count == 88
            data = struct.pack("<11Q", *(v & ((1 << 64) - 1) for v in metadata_words(os.fstat(fd))))
        return b"HSARIN01" + struct.pack("<3Q", sequence, len(data), 0) + data


def main():
    ap = argparse.ArgumentParser()
    for name in ("source", "manifest", "output"):
        ap.add_argument("--" + name, required=True, type=Path)
    args = ap.parse_args()
    out = args.output
    out.mkdir(mode=0o700, exist_ok=False)
    for name in ("qualify_rea_asar_abi.py", "qualify_rea_asar_differential.py", "rea_asar_native_transport.py"):
        (out / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    fixtures = out / "fixtures"
    fixtures.mkdir(mode=0o700)
    path = fixtures / "empty.asar"
    path.write_bytes(archive({"files": {}}))
    path.chmod(0o400)
    fd = os.open(path, os.O_RDONLY)
    owner = AsarModule(args.manifest, args.source)
    pins = {str(p): {"bytes": p.stat().st_size,
        "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
        for p in (args.manifest, args.source / "native/rea_asar_parser.hepta", path)}
    (out / "source-pins.json").write_text(json.dumps(pins, sort_keys=True, indent=2) + "\n")
    initial = request(fd)
    calls = controls = 0
    started = time.monotonic()
    try:
        with (out / "complete-native-observations.jsonl").open("x") as log:
            def one(label, wire, expected=INVALID, **kwargs):
                nonlocal calls, controls
                session = Session(owner, log)
                try:
                    code, _ = session.call(label, wire, **kwargs)
                    assert code == expected, (label, code, expected)
                    controls += 1
                finally:
                    calls += session.calls
                    session.close()

            for length in range(136):
                one(f"initial-truncation/{length}", initial[:length])
            for index in range(8):
                damaged = bytearray(initial)
                damaged[index] ^= 1
                one(f"initial-magic/{index}", bytes(damaged))
            for offset, values in ((8, (0, 3, (1 << 64) - 1)),
                                   (32, (2, (1 << 64) - 1)),
                                   (40, (1, (1 << 64) - 1))):
                for value in values:
                    one(f"initial-word/{offset}/{value}", changed_word(initial, offset, value))
            one("initial-trailing-data", initial + b"x")
            one("index-forbids-member", changed_word(initial, 40, 1) + b"x")
            one("index-forbids-complete", changed_word(initial, 32, 1))
            bad_utf8 = changed_word(changed_word(initial, 8, 2), 40, 1) + b"\xff"
            one("read-member-strict-utf8", bad_utf8)
            for capacity in (0, 1, 32775, WORKSPACE - 1):
                one(f"workspace-capacity/{capacity}", initial, CAPACITY, workspace_capacity=capacity)

            mutations = [
                ("completion-empty", lambda wire: b""),
                ("completion-header-short", lambda wire: wire[:31]),
                ("completion-magic", lambda wire: bytes([wire[0] ^ 1]) + wire[1:]),
                ("completion-old-sequence", lambda wire: changed_word(wire, 8, 0)),
                ("completion-future-sequence", lambda wire: changed_word(wire, 8, 2)),
                ("completion-overdeclared", lambda wire: changed_word(wire, 16, 17)),
                ("completion-unclaimed-tail", lambda wire: wire + b"x"),
            ]
            for label, mutate in mutations:
                session = Session(owner, log)
                try:
                    assert session.call(label + "/initial", initial)[0] == PENDING
                    wire = session.completion(fd)
                    assert session.call(label, mutate(wire))[0] == INVALID
                    controls += 1
                finally:
                    calls += session.calls
                    session.close()

            for label, errno, data_length in (("effect-error", 5, 16), ("effect-short", 0, 15)):
                session = Session(owner, log)
                try:
                    assert session.call(label + "/initial", initial)[0] == PENDING
                    wire = session.completion(fd)
                    wire = changed_word(changed_word(wire, 16, data_length), 24, errno)[:32 + data_length]
                    code, body = session.call(label, wire)
                    assert code == len(body) and body[:8] == b"HSARRS01"
                    assert struct.unpack_from("<3Q", body, 8) == (1, 3, len(body) - 32)
                    assert body[32:] == b"truncated ASAR Pickle prefix"
                    assert session.call(label + "/terminal-replay", wire)[0] == INVALID
                    controls += 1
                finally:
                    calls += session.calls
                    session.close()

            session = Session(owner, log)
            try:
                assert session.call("sequence-replay/initial", initial)[0] == PENDING
                wire = session.completion(fd)
                assert session.call("sequence-replay/first-completion", wire)[0] == PENDING
                assert session.call("sequence-replay/replayed-completion", wire)[0] == INVALID
                controls += 1
            finally:
                calls += session.calls
                session.close()

            complete = owner.invoke(initial, fd, log)
            expected_body = b"HSARRS01" + struct.pack("<3Q", 0, 0, len(complete["payload"].encode())) + complete["payload"].encode()
            calls += complete["native_calls"]
            (out / "complete-success.bin").write_bytes(expected_body)
            for capacity in (0, 1, 31, len(expected_body) - 1, len(expected_body)):
                session = Session(owner, log)
                try:
                    wire = initial
                    for ordinal in range(8):
                        code, body = session.call(f"output-capacity/{capacity}/{ordinal}", wire, output_capacity=capacity)
                        if code != PENDING:
                            break
                        wire = session.completion(fd)
                    assert code != PENDING
                    if capacity < len(expected_body):
                        assert code == CAPACITY
                    else:
                        assert code == len(expected_body) and body == expected_body
                    assert session.call(f"output-capacity/{capacity}/terminal-replay", wire)[0] == INVALID
                    controls += 1
                finally:
                    calls += session.calls
                    session.close()
        for name, pin in pins.items():
            raw = Path(name).read_bytes()
            assert len(raw) == pin["bytes"] and hashlib.sha256(raw).hexdigest() == pin["sha256"]
        report = {"status": "PASS", "independent_controls": controls,
            "actual_native_calls": calls, "seconds": time.monotonic() - started,
            "source_and_fixture_bytes_stable": True, "original_test_methods_replaced": False,
            "public_route_qualified": False,
            "scope": "Private disjoint-buffer request/completion/output contract; no hostile writable-workspace or input/output alias admission is claimed."}
        (out / "terminal.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps(report, sort_keys=True), flush=True)
    except BaseException as error:
        (out / "failure.json").write_text(json.dumps({"error": repr(error), "traceback": traceback.format_exc(),
            "completed_controls": controls, "actual_native_calls": calls}, sort_keys=True, indent=2) + "\n")
        raise
    finally:
        os.close(fd)
        owner.close()


if __name__ == "__main__":
    main()
