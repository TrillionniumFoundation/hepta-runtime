#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Meaningful native state, capacity and actual stdio transport controls."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from hia_native_loader import NativeModule
from connection_test_context import Context
CONTEXT = None
def validate(manifest):
    global CONTEXT
    if CONTEXT is None:
        CONTEXT = Context()
    assert manifest.resolve() == Path(CONTEXT.metadata["fixture"]["path"]).resolve()
    return CONTEXT.fixture()

sha = lambda raw: hashlib.sha256(raw).hexdigest()
U = lambda raw, at: struct.unpack_from("<Q", raw, at)[0]
M = "io.modelcontextprotocol/"


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def request(method, params=None, ident=1):
    value = {"jsonrpc": "2.0", "id": ident, "method": method}
    if params is not None:
        value["params"] = params
    return encode(value)


def initialize(ident=1, version="2025-11-25", name="first", caps=None):
    return request("initialize", {"protocolVersion": version, "capabilities": {} if caps is None else caps,
                                  "clientInfo": {"name": name, "version": "1"}}, ident)


def pair(raw, at):
    offset, size = struct.unpack_from("<QQ", raw, at)
    assert (offset == 0 and size == 0) or 256 <= offset <= offset + size <= len(raw)
    return None if offset == 0 else raw[offset:offset + size]


def frame(projection):
    return b"HRCNQ001" + struct.pack("<QQ", 1, len(projection)) + projection


def module(name):
    key = {"sdk-message-v6": "message", "sdk-connection-v1": "connection"}[name]
    return CONTEXT.module(key)


def state_bytes(session):
    header = ctypes.string_at(ctypes.addressof(session._workspace), 64)
    size = sum(U(header, at) for at in (24, 32, 40))
    return header + ctypes.string_at(ctypes.addressof(session._workspace) + 16384, size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    binary, metadata = validate(args.manifest)
    begun = time.monotonic()
    records = []
    result = {"status": "RUNNING", "elf_sha256": metadata["elf_sha256"],
              "test_sha256": sha(Path(__file__).read_bytes()), "state_calls": 0, "message_calls": 0,
              "actual_elf_processes": 0, "build_sha256": CONTEXT.digest, "sources": CONTEXT.metadata["sources"], "scope": "bounded native connection owner and real fixed transport"}

    def save():
        (args.output / "result.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        (args.output / "controls.json").write_text(json.dumps(records, sort_keys=True, indent=2) + "\n")

    save()
    try:
        with module("sdk-message-v6") as message, module("sdk-connection-v1") as connection:
            with message.session(output_capacity=2 << 20, workspace_capacity=4 << 20) as decoder:
                def parse(raw):
                    result["message_calls"] += 1
                    return decoder(b"HRCJQ001" + struct.pack("<QQ", 1, len(raw)) + raw)

                ping = parse(request("ping"))
                normal = parse(initialize())
                large_id = parse(initialize("\n" * 2048, name="rejected-id"))
                large_name = parse(initialize(name="x" * 60000))

                def call(session, value, raw=False):
                    result["state_calls"] += 1
                    return session.invoke_raw(value) if raw else session(value)

                # A failed initialize must not select legacy mode or install peer data.
                with connection.session(output_capacity=2048, workspace_capacity=65536) as state:
                    before = state_bytes(state)
                    ctypes.memset(ctypes.addressof(state._output), 0xa5, state.output_capacity)
                    code, output, _ = call(state, frame(large_id), True)
                    assert code == 0xfffffffe and output == bytes([0xa5]) * state.output_capacity
                    assert state_bytes(state) == before
                    preinit = call(state, frame(ping))
                    assert U(preinit, 8) == 1 and U(preinit, 24) == 0 and U(preinit, 48) == 0
                    response = call(state, frame(normal))
                    assert U(response, 8) == 1 and b'"protocolVersion":"2025-11-25"' in pair(response, 64)
                    prior = state_bytes(state)
                    ctypes.memset(ctypes.addressof(state._output), 0x69, state.output_capacity)
                    code, output, _ = call(state, frame(large_id), True)
                    assert code == 0xfffffffe and output == bytes([0x69]) * state.output_capacity
                    assert state_bytes(state) == prior
                    code, _, _ = call(state, frame(large_name), True)
                    assert code == 0xfffffffe and state_bytes(state) == prior
                    action = call(state, frame(parse(request("tools/list"))))
                    assert pair(action, 128) == b'{"name":"first","version":"1"}'
                    assert pair(action, 112) == b"2025-11-25" and U(action, 40) == 1
                    records.append({"control": "initialize-and-reinitialize-capacity-atomicity", "status": "PASS"})

                # State identity and every public header bound are checked before output or state mutation.
                malformed = [b"", b"HRCNQ001", b"HRCNQ001" + struct.pack("<QQ", 9, 0),
                             b"HRCNQ001" + struct.pack("<QQ", 2, 1) + b"x", frame(ping)[:-1]]
                original = frame(normal)
                for at, value in [(0, 0), (16, len(original)), (24, 0), (32, 6), (40, 20),
                                  (48, 4), (56, 2), (64, 3), (80, 1), (88, 1),
                                  (96, (1 << 64) - 1), (248, 1), (272, 1), (152, 0)]:
                    changed = bytearray(original)
                    struct.pack_into("<Q", changed, at, value)
                    malformed.append(bytes(changed))
                with connection.session(output_capacity=4096, workspace_capacity=65536) as state:
                    call(state, frame(normal))
                    for index, bad in enumerate(malformed):
                        before = bytes(state._workspace)[:state.workspace_capacity]
                        ctypes.memset(ctypes.addressof(state._output), 0xab, state.output_capacity)
                        code, output, after = call(state, bad, True)
                        assert code == 0xffffffff, (index, code)
                        assert output == b"\xab" * state.output_capacity and after == before
                    records.append({"control": "malformed-private-frames-atomic", "cases": len(malformed), "status": "PASS"})
                for at, value in [(0, 1), (8, 4), (16, 2), (24, 65536), (32, 65536), (40, 65536), (48, 1), (56, 1)]:
                    with connection.session(output_capacity=4096, workspace_capacity=65536) as state:
                        call(state, frame(normal))
                        struct.pack_into("<Q", state._workspace, at, value)
                        before = bytes(state._workspace)[:state.workspace_capacity]
                        ctypes.memset(ctypes.addressof(state._output), 0x6b, state.output_capacity)
                        code, output, after = call(state, frame(ping), True)
                        assert code == 0xffffffff and output == b"\x6b" * state.output_capacity and after == before
                records.append({"control": "corrupt-state-refusal", "cases": 8, "status": "PASS"})

                # Output at exact size succeeds; one byte less cannot commit the opener.
                with connection.session(output_capacity=4096, workspace_capacity=65536) as state:
                    expected = call(state, frame(normal))
                for capacity, accepted in [(len(expected), True), (len(expected) - 1, False)]:
                    with connection.session(output_capacity=capacity, workspace_capacity=65536) as state:
                        before = state_bytes(state)
                        code, output, _ = call(state, frame(normal), True)
                        assert (code == len(expected) and output == expected) if accepted else (code == 0xfffffffe and state_bytes(state) == before)
                records.append({"control": "exact-response-capacity", "bytes": len(expected), "status": "PASS"})

        # Actual Linux processes exercise streaming, compaction and final EOF input.
        first = initialize()
        ping_raw = request("ping", ident="tail")
        ordinary = first + b"\n" + ping_raw + b"\n"

        def execute(label, raw, *, expected=None, code=0, chunks=None, argv=()):
            begin = time.monotonic()
            if chunks is None:
                process = subprocess.run([str(binary), *argv], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         env={"PATH": "", "LC_ALL": "C"}, timeout=30)
                out, err, status = process.stdout, process.stderr, process.returncode
            else:
                process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env={"PATH": "", "LC_ALL": "C"})
                try:
                    for chunk in chunks:
                        process.stdin.write(chunk)
                        process.stdin.flush()
                    process.stdin.close()
                    process.stdin = None
                    out, err = process.communicate(timeout=30)
                    status = process.returncode
                except BaseException:
                    process.kill()
                    process.communicate()
                    raise
            result["actual_elf_processes"] += 1
            record = {"control": label, "command": [str(binary), *argv], "input_bytes": len(raw),
                      "input_sha256": sha(raw), "stdout_bytes": len(out), "stdout_sha256": sha(out),
                      "stderr_sha256": sha(err), "exit_code": status, "elapsed_seconds": time.monotonic() - begin,
                      "actual_fragments": 0 if chunks is None else len(chunks), "stdout_hex": out.hex(), "stderr_hex": err.hex()}
            records.append(record)
            assert status == code and not err and (expected is None or out == expected), record
            return out

        expected = execute("ordinary", ordinary)
        assert expected.count(b"\n") == 2
        execute("final-frame-no-newline", ordinary[:-1], expected=expected)
        execute("empty", b"", expected=b"")
        execute("blank-lines", b"\n\r\n\n\r", expected=b"")
        execute("BOM-CRLF", b"\xef\xbb\xbf" + first + b"\r\n" + ping_raw + b"\r\n", expected=expected)
        execute("invalid-syntax-between-frames", first + b"\n{\n" + ping_raw + b"\n", expected=expected)
        execute("one-byte-fragments", ordinary, expected=expected, chunks=[bytes([byte]) for byte in ordinary])
        execute("usage", b"", code=64, expected=b"", argv=("--mode=modern",))
        padded = b" " * ((8 << 20) - len(first)) + first
        execute("exact-8MiB-line-CRLF", padded + b"\r\n" + ping_raw + b"\n", expected=expected)
        execute("exact-8MiB-final-frame", padded, expected=expected.split(b"\n", 1)[0] + b"\n")
        execute("over-limit-no-partial-output", b" " + padded + b"\n", expected=b"", code=3)
        large_id = "\n\\😀" * 20000
        large = initialize(ident=large_id)
        large_output = execute("large-escaped-id", large + b"\n" + ping_raw + b"\n")
        assert json.loads(large_output.splitlines()[0])["id"] == large_id
        assert large_output.splitlines()[-1] == expected.splitlines()[-1]
        validate(args.manifest)
        CONTEXT.recheck()
        result.update(status="PASS", controls=len(records), elapsed_seconds=time.monotonic() - begun)
    except BaseException as error:
        result.update(status="FAIL", exception=type(error).__name__ + ": " + str(error))
        raise
    finally:
        result["controls_sha256"] = sha((json.dumps(records, sort_keys=True, indent=2) + "\n").encode())
        save()
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
