#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent byte fixtures for a finite public ELF format qualification.

This manifest adds compressed section names and integer/range boundaries to the
older operation profile. It is neither a fuzzer nor a claim about every ELF or
Zstandard bit stream. The producer and offline consumer regenerate these bytes.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import zlib

import rea_operation_qualification as q


PROFILE = "rea-agents-6.8.0/inspect_elf_notes/linux-format-corpus/v2"
NAMES = b"\0.note.good\0"


def put(raw, offset, width, value, order):
    raw[offset:offset + width] = value.to_bytes(width, order)


def compression_header(payload, declared, codec, bits, order):
    prefix = "<" if order == "little" else ">"
    return struct.pack(prefix + ("IIQQ" if bits == 64 else "III"),
                       *((codec, 0, declared, 1) if bits == 64 else (codec, declared, 1))) + payload


def stored_zlib(raw):
    """One stored DEFLATE block, independent of compressor heuristics/version."""
    q.require(len(raw) <= 65535, "fixture exceeds one stored block")
    return (b"\x78\x01\x01" + struct.pack("<HH", len(raw), 65535 - len(raw))
            + raw + struct.pack(">I", zlib.adler32(raw)))


def stored_zstd(raw):
    """One complete single-segment raw frame; size is an unsigned one-byte FCS."""
    q.require(len(raw) <= 255, "fixture exceeds one-byte frame size")
    return bytes.fromhex("28b52ffd20") + bytes([len(raw)]) + ((len(raw) << 3) | 1).to_bytes(3, "little") + raw


def named_elf(names, bits=64, order="little", flags=0, note_flags=0):
    prefix = "<" if order == "little" else ">"
    ehsize, shsize = (64, 64) if bits == 64 else (52, 40)
    name_at = ehsize + 3 * shsize
    note_at = q.align(name_at + len(names), 4)
    notes = q.note(order=order)
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if order == "little" else 2, 1, 0]) + bytes(8)
    values = (2, 62 if bits == 64 else 3, 1, 0, 0, ehsize, 0, ehsize, 0, 0, shsize, 3, 1)
    raw = ident + struct.pack(prefix + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"), *values)
    section_format = prefix + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    raw += bytes(shsize)
    raw += struct.pack(section_format, 0, 3, flags, 0, name_at, len(names), 0, 0, 1, 0)
    raw += struct.pack(section_format, 1, 7, note_flags, 0, note_at, len(notes), 0, 0, 4, 0)
    return raw + names + bytes(note_at - name_at - len(names)) + notes


def corpus(workspace, write=False):
    """Return the exact ordered set; no producer-supplied PASS chooses cases."""
    workspace, fixtures, cases = Path(workspace), {}, []

    def add(name, raw, kind, category, bits, order):
        path = workspace / (name + ".elf")
        if write:
            with path.open("xb") as stream:
                stream.write(raw)
        item = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        fixtures[name] = item
        cases.append({"id": name, "kind": kind, "category": category,
                      "bits": bits, "byte_order": order, "arguments": {"path": str(path)}, "fixture": item})

    for bits in (32, 64):
        for order in ("little", "big"):
            stem = "elf%d_%s_" % (bits, order)
            ehsize, shsize, width = (64, 64, 8) if bits == 64 else (52, 40, 4)
            base = named_elf(NAMES, bits, order)
            add(stem + "names_plain", base, "success", "names-plain", bits, order)
            for codec, encoded in ((1, stored_zlib(NAMES)), (2, stored_zstd(NAMES))):
                comp = compression_header(encoded, len(NAMES), codec, bits, order)
                add(stem + "names_codec_%d" % codec, named_elf(comp, bits, order, 0x800),
                    "success", "names-compressed", bits, order)
                short = compression_header(encoded, 1, codec, bits, order)
                add(stem + "names_codec_%d_output_limit" % codec, named_elf(short, bits, order, 0x800),
                    "error", "names-output-limit", bits, order)
                huge = compression_header(encoded, (1 << bits) - 1, codec, bits, order)
                add(stem + "names_codec_%d_declared_overflow" % codec, named_elf(huge, bits, order, 0x800),
                    "error", "names-declared-overflow", bits, order)
            bad_zlib = bytearray(stored_zlib(NAMES))
            bad_zlib[-1] ^= 1
            for label, payload in (("checksum", bytes(bad_zlib)), ("truncated", stored_zlib(NAMES)[:-1])):
                comp = compression_header(payload, len(NAMES), 1, bits, order)
                add(stem + "zlib_" + label, named_elf(comp, bits, order, 0x800),
                    "error", "compressed-invalid", bits, order)
            for label, payload, declared, kind in (
                ("checksum", bytes.fromhex("28b52ffd240529000068656c6c6fa36d9f89"), 5, "error"),
                ("partial_checksum", bytes.fromhex("28b52ffd240529000068656c6c6f"), 5, "success"),
                ("skippable", bytes.fromhex("502a4d180000000028b52ffd200529000068656c6c6f"), 0, "success"),
                ("window", bytes.fromhex("28b52ffd0090010000"), 0, "error"),
            ):
                comp = compression_header(payload, declared, 2, bits, order)
                add(stem + "zstd_" + label, named_elf(comp, bits, order, 0x800),
                    kind, "compressed-producer-boundary", bits, order)
            unknown = compression_header(b"", (1 << bits) - 1, 99, bits, order)
            add(stem + "unknown_codec", named_elf(unknown, bits, order, 0x800),
                "success", "unsupported-names", bits, order)
            add(stem + "short_compression_header", named_elf(bytes(3), bits, order, 0x800),
                "error", "compressed-invalid", bits, order)
            add(stem + "compressed_note", named_elf(NAMES, bits, order, note_flags=0x800),
                "error", "unsupported-notes", bits, order)
            mutations = (
                ("section_offset_max", 40 if bits == 64 else 32, width, (1 << bits) - 1),
                ("section_entry_small", 58 if bits == 64 else 46, 2, shsize - 1),
                ("extended_program_count", 56 if bits == 64 else 44, 2, 65535),
                ("extended_names_index", 62 if bits == 64 else 50, 2, 65535),
                ("note_offset_outside", ehsize + 2 * shsize + (24 if bits == 64 else 16), width, len(base) + 1),
                ("note_size_max", ehsize + 2 * shsize + (32 if bits == 64 else 20), width, (1 << bits) - 1),
            )
            for label, offset, field_width, value in mutations:
                changed = bytearray(base)
                put(changed, offset, field_width, value, order)
                add(stem + label, bytes(changed), "error", "integer-range", bits, order)
            if bits == 64:
                for label, value in (("safe_integer_edge", (1 << 53) - 1), ("unsafe_integer", 1 << 53)):
                    changed = bytearray(base)
                    put(changed, 40, 8, value, order)
                    add(stem + label, bytes(changed), "error", "integer-range", bits, order)

    # Fixed old decoder regressions are promoted to the actual public MCP path.
    # These unchanged bytes are not a substitute for the full 5,244-case corpus.
    for name, payload in (
        ("zstd-bit-8-37", "28b52ffd20284d000010414101001bce0eb0"),
        ("zstd-bit-9-145", "28b52ffd60204d4d000010414101001bce0eb2"),
        ("zstd-bit-9-105", "28b52ffd60204d4d000010414103001bce0eb0"),
        ("zstd-bit-9-141", "28b52ffd60204d4d000010414101001bce2eb0"),
        ("zstd-bit-9-144", "28b52ffd60204d4d000010414101001bce0eb1"),
        ("zstd-bit-9-148", "28b52ffd60204d4d000010414101001bce0ea0"),
        ("zstd-bit-9-150", "28b52ffd60204d4d000010414101001bce0ef0"),
    ):
        raw = compression_header(bytes.fromhex(payload), 20000, 2, 64, "little")
        add(name, named_elf(raw, flags=0x800), "error", "zstd-destination-precedence", 64, "little")
    return {"profile": PROFILE, "fixtures": fixtures, "cases": cases}
