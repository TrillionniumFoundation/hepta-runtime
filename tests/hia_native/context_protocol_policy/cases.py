"""Fixed resolved-version and borrowed-buffer domains; no execution here."""
from __future__ import annotations

from dataclasses import dataclass
import struct

THRESHOLD = "2026-07-28"
KNOWN = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", THRESHOLD)
INVALID = 0xFFFFFFFF
NO_SEMANTIC = (1 << 64) - 1
GUARD = 16


def frame(version: str | None) -> bytes:
    value = b"" if version is None else version.encode("utf-8")
    return b"HCPOLQ01" + struct.pack("<3Q", 1, version is not None, len(value)) + value


def versions():
    yield "none", None
    yield "empty", ""
    for value in KNOWN:
        yield "known-" + value, value
    for size in range(len(THRESHOLD) + 1):
        yield f"threshold-prefix-{size}", THRESHOLD[:size]
    for position in range(len(THRESHOLD)):
        for byte in range(128):
            yield f"ascii-{position}-{byte:02x}", THRESHOLD[:position] + chr(byte) + THRESHOLD[position + 1:]
    for position in range(len(THRESHOLD) + 1):
        for number, value in enumerate(("\0", "\u007f", "\u0080", "é", "λ", "中", "😀", "\uffff", "\U0010ffff", "\n", "\r", "\t")):
            yield f"unicode-insertion-{position}-{number}", THRESHOLD[:position] + value + THRESHOLD[position:]
    for number, value in enumerate((
        "2026-07-27", "2026-07-29", "2026-7-1", "2026-07-028", "2026-007-28", "2026-00-99",
        "2026-99-00", "2026-13-99", "20260-01-01", "2025-99-99", "203-01-01", "02026-07-28",
        "2026/07/28", "2026.07.28", "2026:07:28", "2026-07-28Z", "2026-07-28\0",
        "2026-07-28\n", "2026-07-28 ", "2026-07-28λ", "2026-07-280", "2026-07-28-",
        "2026-07-28T00:00:00Z", "2026-07-28+00:00", "v2026-07-28", " 2026-07-28", "\0" + THRESHOLD,
        "９９９９-０１-０１", "２０２６-０７-２８", "0000-00-00", "9999-99-99", "-1", "+2026-07-28",
    )):
        yield f"lexical-{number}", value
    for size in (1, 2, 7, 8, 9, 10, 31, 32, 33, 255, 256, 257, 4095, 4096):
        yield f"threshold-suffix-{size}", THRESHOLD + "x" * size
    # Every complete UTF-8 payload exceeds 8 MiB, remains inside serde-json.v1,
    # and is retained in both native before/after input and the actual SDK echo.
    yield "wide-equal-prefix", THRESHOLD + "x" * ((8 << 20) + 1 - len(THRESHOLD))
    yield "wide-less-prefix", "2026-07-27" + "z" * ((8 << 20) + 17 - 10)
    yield "wide-unicode", THRESHOLD + ("λ\0😀" * (((8 << 20) // 7) + 3))


def semantic_count():
    return sum(1 for _ in versions())


@dataclass(frozen=True)
class Call:
    name: str
    wire: bytes
    output_capacity: int
    workspace_capacity: int
    session: int
    semantic: int = NO_SEMANTIC


def calls():
    session = 0
    for index, (name, version) in enumerate(versions()):
        yield Call(name, frame(version), 33, 257, session, index)
        session += 1
    valid = frame(THRESHOLD)
    for length in range(32):
        yield Call(f"short-header-{length}", valid[:length], 33, 257, session)
        session += 1
    for offset in range(32):
        for bit in range(8):
            changed = bytearray(valid)
            changed[offset] ^= 1 << bit
            yield Call(f"header-bit-{offset}-{bit}", bytes(changed), 33, 257, session)
            session += 1
    for field in (8, 16, 24):
        for value in (0, 2, 255, 256, (1 << 63), (1 << 64) - 32, (1 << 64) - 1):
            changed = bytearray(valid)
            struct.pack_into("<Q", changed, field, value)
            yield Call(f"word-{field}-{value}", bytes(changed), 33, 257, session)
            session += 1
    malformed = [
        ("none-payload", b"HCPOLQ01" + struct.pack("<3Q", 1, 0, 1) + b"x"),
        ("extra-byte", valid + b"x"),
        ("missing-byte", valid[:-1]),
        ("wrong-magic", b"HCPOLS01" + valid[8:]),
        ("empty-input", b""),
    ]
    for name, wire in malformed:
        yield Call(name, wire, 33, 257, session)
        session += 1
    for output in range(34):
        for version in (None, "", THRESHOLD):
            yield Call(f"output-{output}-{version!r}", frame(version), output, 257, session)
            session += 1
    for workspace in (0, 1, 31, 32, 33, 4096):
        for index, wire in enumerate((valid, frame(None), frame(""), valid[:-1])):
            yield Call(f"workspace-{workspace}-{index}", wire, 33, workspace, session)
            session += 1
    # Two independently owned persistent sessions alternate successful and refused
    # calls. Their exact dirty output/workspace preimages must follow their own
    # preceding complete postimages, never another session's state.
    for index, wire in enumerate((valid, frame(None), valid[:-1], frame(""), frame("2026-07-27"),
                                  frame(THRESHOLD + "\0"), b"", frame("😀"), frame(None), valid)):
        for which in (0, 1):
            value = wire if which == 0 else (frame(None) if index % 2 else valid)
            yield Call(f"persistent-{which}-{index}", value, 33, 257, session + which)
    session += 2
    wide = b"x" * ((8 << 20) + 3)
    yield Call("wide-none-payload-refusal", b"HCPOLQ01" + struct.pack("<3Q", 1, 0, len(wide)) + wide,
               33, 257, session)


def expected(wire: bytes, output_capacity: int):
    if len(wire) < 32 or output_capacity < 32 or wire[:8] != b"HCPOLQ01":
        return INVALID, None
    operation, present, length = struct.unpack_from("<3Q", wire, 8)
    if operation != 1 or present > 1 or length != len(wire) - 32 or (present == 0 and length):
        return INVALID, None
    allowed = int(present == 1 and wire[32:] >= THRESHOLD.encode())
    return 32, b"HCPOLS01" + struct.pack("<3Q", present, allowed, 1 - allowed)


def initial_output(session: int, capacity: int) -> bytes:
    return bytes([(0xC1 + session * 17) & 255]) * capacity + b"\xa5" * GUARD


def initial_workspace(session: int, capacity: int) -> bytes:
    return bytes([(0x71 + session * 29) & 255]) * capacity + b"\x5a" * GUARD


TRACE_HEADER = struct.Struct("<8s12Q")


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated complete capture")
    return data


def read_trace(stream):
    raw = stream.read(TRACE_HEADER.size)
    if not raw:
        return None
    if len(raw) != TRACE_HEADER.size:
        raise ValueError("truncated trace header")
    row = TRACE_HEADER.unpack(raw)
    if row[0] != b"HCPTRC01" or row[-4:] != (16, 16, 16, 0):
        raise ValueError("trace header contract differs")
    _, index, semantic, session, local_call, result, n, out, work, *_ = row
    if n > (16 << 20) or out > 4096 or work > 4096:
        raise ValueError("trace sizes outside the fixed qualification domain")
    arrays = [read_exact(stream, size) for size in (max(1, n) + 16, max(1, n) + 16,
                                                    out + 16, out + 16, work + 16, work + 16)]
    return row, arrays
