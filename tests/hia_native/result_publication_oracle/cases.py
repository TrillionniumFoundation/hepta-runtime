"""Independent semantic inputs; no expected native result is computed here.

The complete logical strings are the original Rust input domain. Native tests
may split any bytes, including a UTF-8 scalar, across their own append calls.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct

INPUT_MAGIC = b"HRPOI001"
OUTPUT_MAGIC = b"HRPOO001"
U64 = struct.Struct("<Q")
RECORD = struct.Struct("<6Q")


def rpc_prefix(case_id: int) -> bytes:
    return (f'{{"jsonrpc":"2.0","id":{case_id},"result":'
            '{"content":[{"type":"text","text":').encode()


def iter_cases():
    """Yield deterministic full inputs. Metadata is outside the binary record."""
    next_id = 0

    def row(name, mode, base, hints=(), *, is_error=False, prefix=None):
        nonlocal next_id
        value = {"case_id": next_id, "name": name, "mode": mode,
                 "is_error": bool(is_error), "base": base, "hints": list(hints),
                 "prefix": (rpc_prefix(next_id) if prefix is None else prefix) if mode == 3 else b""}
        next_id += 1
        return value

    examples = [
        ("empty-base-empty-list", b"", []),
        ("one-empty-hint", b"", [b""]),
        ("whitespace-base", b" \t\r\n", []),
        ("post-drain-duplicates", "base\0尾\n".encode(),
         [b"", b"same", b"same", "é".encode(), "e\u0301".encode(), "尾\n\r\0".encode()]),
        ("all-control-escapes", bytes(range(32)) + b'"\\/\x7f', [b'"\\\t\n\r\x08\x0c']),
        ("warning-prefix-as-data", "⚠️ already\n\n".encode(), ["⚠️ nested\n".encode(), b""]),
        ("unicode-width-boundaries", "\u007f\u0080\u07ff\u0800\u2028\u2029\ufeff\uffff\U00010000\U0010ffff".encode(),
         ["中é𝄞🙂".encode()]),
        ("line-ending-preservation", b"\r\r\nA\r\nB\n", [b"CRLF\r\n", b"line\n\n", b"trailing  "]),
    ]
    for mode in range(4):
        for is_error in (False, True):
            for name, base, hints in examples:
                yield row(f"m{mode}-e{int(is_error)}-{name}", mode, base, hints, is_error=is_error)

    for size in (1, 2, 3, 7, 8, 15, 31, 63, 64, 255, 256, 4095, 4096, 65535, 65536):
        base = (b'a"\\\0\n' * ((size + 4) // 5))[:size]
        yield row(f"source-boundary-{size}", 1, base, ["🙂".encode(), b""])
    yield row("4097-distinct-hints", 2, b"base", [f"hint-{i}".encode() for i in range(4097)])
    yield row("many-empty-and-duplicate-hints", 3, b"", [b"", b"repeat", b""] * 137, is_error=True)
    yield row("trusted-unicode-id-prefix", 3, "result尾".encode(), [b""],
              prefix=b'{"jsonrpc":"2.0","id":' + json.dumps("id尾\n\0", ensure_ascii=False).encode()
              + b',"result":{"content":[{"type":"text","text":')

    limit = 8 << 20
    yield row("raw-base-over-eight-mib", 0, b"R" * (limit + 17))
    yield row("quoted-base-over-eight-mib", 1, b'"' * (limit + 17))
    yield row("mcp-base-over-eight-mib", 2, b"M" * (limit + 17), [b"", b"same", b"same"])
    yield row("rpc-composed-over-eight-mib", 3, b"P" * (limit - 3), ["尾🙂".encode(), b""])
    yield row("json-escaping-crosses-eight-mib", 1, b"\0" * ((2 << 20) + 1))
    scalars = "".join(chr(cp) for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF).encode()
    yield row("all-scalars-base-plus-hint", 2, scalars, [scalars, b""], is_error=True)
    yield row("hint-list-over-eight-mib", 0, b"", [b"H" * 131073] * 64)
    yield row("rpc-base-over-sixteen-mib", 3, b"S" * ((16 << 20) + 3), [b"last"])


def _read_exact(stream, count):
    value = stream.read(count)
    if len(value) != count:
        raise ValueError(f"truncated corpus: wanted {count}, got {len(value)}")
    return value


def write_cases(stream, cases):
    """Write a complete seekable binary corpus and return byte-free metadata."""
    start = stream.tell()
    stream.write(INPUT_MAGIC + U64.pack(0))
    metadata = []
    seen = set()
    for case in cases:
        cid, mode = case["case_id"], case["mode"]
        error = int(case["is_error"])
        prefix, base, hints = case["prefix"], case["base"], case["hints"]
        if cid in seen or mode not in range(4) or error not in (0, 1):
            raise ValueError("invalid case identity")
        if mode != 3 and prefix:
            raise ValueError("prefix outside mode 3")
        seen.add(cid)
        base.decode("utf-8")
        for hint in hints:
            hint.decode("utf-8")
        offset = stream.tell()
        stream.write(RECORD.pack(cid, mode, error, len(prefix), len(base), len(hints)))
        stream.write(prefix)
        stream.write(base)
        for hint in hints:
            stream.write(U64.pack(len(hint)))
            stream.write(hint)
        metadata.append({"case_id": cid, "name": case.get("name", f"case-{cid}"),
                         "mode": mode, "is_error": bool(error), "offset": offset,
                         "record_bytes": stream.tell() - offset, "prefix_bytes": len(prefix),
                         "base_bytes": len(base), "hint_count": len(hints),
                         "hint_bytes": sum(map(len, hints))})
    end = stream.tell()
    stream.seek(start + 8)
    stream.write(U64.pack(len(metadata)))
    stream.seek(end)
    return metadata


def encode_cases(cases) -> bytes:
    stream = io.BytesIO()
    write_cases(stream, cases)
    return stream.getvalue()


def read_cases(data):
    """Read bytes or a binary stream; no output/composition semantics."""
    stream = io.BytesIO(data) if isinstance(data, (bytes, bytearray)) else data
    if _read_exact(stream, 8) != INPUT_MAGIC:
        raise ValueError("input corpus magic differs")
    count = U64.unpack(_read_exact(stream, 8))[0]
    seen = set()
    for _ in range(count):
        cid, mode, error, prefix_len, base_len, hint_count = RECORD.unpack(_read_exact(stream, 48))
        if cid in seen or mode not in range(4) or error not in (0, 1):
            raise ValueError("invalid case identity")
        seen.add(cid)
        prefix = _read_exact(stream, prefix_len)
        base = _read_exact(stream, base_len)
        hints = [_read_exact(stream, U64.unpack(_read_exact(stream, 8))[0]) for _ in range(hint_count)]
        yield {"case_id": cid, "mode": mode, "is_error": bool(error),
               "prefix": prefix, "base": base, "hints": hints}
    if stream.read(1):
        raise ValueError("trailing input corpus bytes")


def read_outputs(stream):
    if _read_exact(stream, 8) != OUTPUT_MAGIC:
        raise ValueError("output corpus magic differs")
    count = U64.unpack(_read_exact(stream, 8))[0]
    for _ in range(count):
        cid, size = struct.unpack("<QQ", _read_exact(stream, 16))
        yield cid, _read_exact(stream, size)
    if stream.read(1):
        raise ValueError("trailing output corpus bytes")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.output.open("xb+") as stream:
        metadata = write_cases(stream, iter_cases())
    digest = hashlib.sha256()
    with args.output.open("rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    report = {"schema": "hepta.runtime.result-publication.original-input.v1",
              "cases": metadata, "count": len(metadata), "bytes": args.output.stat().st_size,
              "sha256": digest.hexdigest(), "expected_output_computed": False}
    args.output.with_suffix(".json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "cases"}, sort_keys=True))


if __name__ == "__main__":
    main()
