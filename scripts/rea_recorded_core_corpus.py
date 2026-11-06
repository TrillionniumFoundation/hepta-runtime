#!/usr/bin/env python3
"""Deterministic byte fixtures for the frozen REA recorded-core oracle.

This builder encodes file bytes, never expected parser answers. The unchanged
reference implementation supplies every expected value and typed error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import random
import struct

SCHEMA = "hepta.rea.recorded-core-corpus.v1"
U64 = (1 << 64) - 1
CORE = b"CORE\0"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patched(data: bytes, offset: int, value: int, size: int) -> bytes:
    result = bytearray(data)
    result[offset:offset + size] = value.to_bytes(size, "little")
    return bytes(result)


def elf(machine=62, segments=(), *, phentsize=56, osabi=0, phoff=64,
        shoff=0, shentsize=64, shnum=0, shstrndx=0, phnum=None,
        tail=b"", ehsize=64) -> bytes:
    """Build ELF64 LE headers and literal segments with independent overrides."""
    segments = list(segments)
    ident = b"\x7fELF\x02\x01\x01" + bytes([osabi, 0]) + bytes(7)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 4, machine, 1, 0,
        phoff, shoff, 0, ehsize, phentsize,
        len(segments) if phnum is None else phnum, shentsize, shnum, shstrndx)
    # Physical header entries remain complete even for invalid declared widths.
    stride = max(phentsize, 56)
    physical_phoff = phoff if phoff <= 8192 else 64
    result = bytearray(header)
    result.extend(bytes(max(0, physical_phoff + len(segments) * stride - len(result))))
    data_offset = len(result)
    payloads = []
    for index, segment in enumerate(segments):
        body = segment.get("body", b"")
        offset = segment.get("offset", data_offset)
        file_size = segment.get("file_size", len(body))
        encoded = struct.pack("<IIQQQQQQ", segment.get("type", 4),
            segment.get("flags", 0), offset, segment.get("vaddr", 0),
            segment.get("paddr", 0), file_size,
            segment.get("memory_size", file_size), segment.get("align", 4))
        start = physical_phoff + index * stride
        result[start:start + 56] = encoded
        if phentsize > 56:
            extension = segment.get("extension", bytes([0xA5]) * (phentsize - 56))
            result[start + 56:start + phentsize] = extension
        payloads.append(body)
        data_offset += len(body)
    for payload in payloads:
        result.extend(payload)
    result.extend(tail)
    return bytes(result)


def note(type_id=0xAABBCCDD, owner=CORE, descriptor=b"", *,
         owner_pad=0, descriptor_pad=0, namesz=None, descsz=None) -> bytes:
    return (struct.pack("<III", len(owner) if namesz is None else namesz,
            len(descriptor) if descsz is None else descsz, type_id)
        + owner + bytes([owner_pad]) * (-len(owner) % 4)
        + descriptor + bytes([descriptor_pad]) * (-len(descriptor) % 4))


def prstatus(machine=62, *, signal=11, pid=1234, pattern=0) -> bytes:
    count, size = (27, 336) if machine == 62 else (34, 392)
    result = bytearray(size)
    struct.pack_into("<H", result, 12, signal & 0xFFFF)
    struct.pack_into("<I", result, 32, pid & 0xFFFFFFFF)
    for index in range(count):
        value = (index * 0x0102030405060708 + pattern) & U64
        struct.pack_into("<Q", result, 112 + index * 8, value)
    return bytes(result)


def siginfo(*, number=11, errno=0, code=1, address=0x123456789ABCDEF0,
            trapno=7, pad=0) -> bytes:
    result = bytearray([pad] * 32)
    struct.pack_into("<III", result, 0,
                     number & 0xFFFFFFFF, errno & 0xFFFFFFFF, code & 0xFFFFFFFF)
    struct.pack_into("<QI", result, 16, address, trapno)
    return bytes(result)


def extended_count(count=1, *, machine=62, sh_type=0, sh_flags=0,
                   sh_name=0, sh_link=0, sh_entsize=0,
                   str_type=3, str_offset=None, str_size=6,
                   shstrndx=1, shentsize=64, section_count=2,
                   declared_shoff=None, truncate=0) -> bytes:
    body = note(2, CORE, b"opaque")
    base = elf(machine, [{"body": body}], phnum=0xFFFF)
    shoff = (len(base) + 7) & ~7
    string_offset = shoff + 128
    first = struct.pack("<IIQQQQIIQQ", sh_name, sh_type, sh_flags, 0,
                        0, 0, sh_link, count, 0, sh_entsize)
    second = struct.pack("<IIQQQQIIQQ", 1, str_type, 0, 0,
                         string_offset if str_offset is None else str_offset,
                         str_size, 0, 0, 1, 0)
    result = (base + bytes(shoff - len(base)) + first + second + b"\0name\0")
    result = patched(result, 40, shoff if declared_shoff is None else declared_shoff, 8)
    result = patched(result, 58, shentsize, 2)
    result = patched(result, 60, section_count, 2)
    result = patched(result, 62, shstrndx, 2)
    return result[:-truncate] if truncate else result


def cases():
    rows = []
    seen = set()

    def add(name, category, data, description):
        if name in seen:
            raise AssertionError("duplicate case " + name)
        seen.add(name)
        rows.append((name, category, data, description))

    base = elf()
    for machine in (62, 183):
        for osabi in (0, 3):
            add(f"minimal-m{machine}-osabi{osabi}", "header", elf(machine, osabi=osabi),
                "Empty admitted ELF64 LE ET_CORE with explicit machine and OSABI.")
    for length in range(64):
        add(f"header-truncated-{length:02}", "header-truncation", base[:length],
            "Literal prefix truncation before the complete 64-byte ELF header.")
    for offset, width, values, label in (
        (0, 4, [0, 0x464C457E, 0x464C457F], "magic"),
        (4, 1, [0, 1, 3, 255], "class"),
        (5, 1, [0, 2, 3, 255], "data"),
        (6, 1, [0, 2, 255], "ident-version"),
        (7, 1, [1, 2, 6, 9, 12, 64, 255], "osabi"),
        (8, 1, [1, 2, 255], "abi-version"),
        (16, 2, [0, 1, 2, 3, 0xFFFF], "elf-type"),
        (18, 2, [0, 3, 40, 243, 0xFFFF], "machine"),
        (20, 4, [0, 2, 0xFFFFFFFF], "header-version"),
        (52, 2, [0, 1, 63, 64, 65, 0xFFFF], "ehsize"),
        (24, 8, [1, 1 << 63, U64], "entry"),
        (48, 4, [1, 0xFFFFFFFF], "flags"),
    ):
        for value in values:
            add(f"header-{label}-{value:x}", "header-field", patched(base, offset, value, width),
                "One independent header field changes; oracle decides admitted or typed failure.")
    add("header-ident-padding", "header-field", base[:9] + b"\xffABCDEFG"[:7] + base[16:],
        "Nonzero ELF identification padding.")
    for offset in (0, 1, 63, 64, 65, U64):
        add(f"zero-count-phoff-{offset:x}", "program-header", patched(base, 32, offset, 8),
            "No program headers but declared table origin is still range checked.")
    for width in (0, 1, 55, 56, 57, 64, 128, 0xFFFF):
        add(f"zero-count-phentsize-{width}", "program-header", patched(base, 54, width, 2),
            "No program headers with independent declared entry width.")
        if width < 1024:
            add(f"one-count-phentsize-{width}", "program-header",
                elf(segments=[{"type": 0}], phentsize=width),
                "One program header, including nonstandard extended sizes.")
    one = elf(segments=[{"type": 0}])
    for count in (0, 1, 2, 65534):
        add(f"declared-phcount-{count}", "program-header", patched(one, 56, count, 2),
            "Declared program count differs from physically encoded table.")
    for position in (0, 1, 63, 65, 119, 120, 121, 1 << 63, U64):
        add(f"one-phoff-{position:x}", "program-header", patched(one, 32, position, 8),
            "Table origin covers overlap, truncation, past EOF and large unsigned offsets.")
    for machine in (62, 183):
        for type_id in tuple(range(10)) + (0x60000000, 0x6FFFFFFF, 0x6474E550,
                0x6474E551, 0x6474E552, 0x6474E553, 0x70000000, 0x70000001,
                0x70000003, 0x7FFFFFFF, 0xFFFFFFFF):
            add(f"segment-type-m{machine}-{type_id:08x}", "segment-type",
                elf(machine, [{"type": type_id, "offset": U64, "flags": 0xFFFFFFFF,
                    "vaddr": U64, "paddr": 1 << 63, "align": U64}]),
                "Zero-file-size segment tests exact type labels and unsigned metadata.")
    for type_id in (0, 1, 2, 4, 0xFFFFFFFF):
        for offset, size, memsize in ((U64, U64, 0), (120, 1, 0),
                (120, 1, 1), (119, 2, 2), (121, 0, 0), (122, 0, 0),
                (U64, 1, 1), (1 << 63, 1 << 63, U64)):
            add(f"range-t{type_id:x}-o{offset:x}-s{size:x}-m{memsize:x}", "segment-range",
                elf(segments=[{"type": type_id, "offset": offset, "file_size": size,
                    "memory_size": memsize, "body": b"\0"}]),
                "Segment backing, null segment exemption and PT_LOAD size precedence.")
    for count in (0, 1, 2, 0xFFFFFFFF):
        for machine in (62, 183):
            add(f"pn-xnum-m{machine}-count{count}", "extended-count",
                extended_count(count, machine=machine),
                "PN_XNUM follows unchanged ELFFile section zero and string-table path.")
    for label, kwargs in (
        ("no-sections", {"section_count": 0}),
        ("one-section", {"section_count": 1}),
        ("shstr-zero", {"shstrndx": 0}),
        ("shstr-extended-link0", {"shstrndx": 0xFFFF, "sh_link": 0}),
        ("shstr-extended-link1", {"shstrndx": 0xFFFF, "sh_link": 1}),
        ("shstr-extended-link2", {"shstrndx": 0xFFFF, "sh_link": 2}),
        ("shstr-large", {"shstrndx": 0xFFFE}),
        ("shoff-zero", {"declared_shoff": 0}),
        ("shoff-max", {"declared_shoff": U64}),
        ("shoff-large", {"declared_shoff": 1 << 63}),
        ("str-offset-max", {"str_offset": U64}),
        ("str-offset-zero", {"str_offset": 0}),
        ("str-size-zero", {"str_size": 0}),
        ("str-type-null", {"str_type": 0}),
        ("str-type-unknown", {"str_type": 0xFFFFFFFF}),
        ("name-offset-large", {"sh_name": 0xFFFFFFFF}),
        ("compressed", {"sh_flags": 0x800}),
    ):
        add("pn-xnum-" + label, "extended-count", extended_count(**kwargs),
            "Independent malformed or unusual section/string-table metadata.")
    for width in (0, 1, 63, 64, 65, 128, 0xFFFF):
        add(f"pn-xnum-shentsize-{width}", "extended-count", extended_count(shentsize=width),
            "Section zero entry-width validation and string-table positioning.")
    for kind in (1, 2, 3, 4, 6, 7, 8, 9, 11, 17, 18, 0x6FFFFFF5,
                 0x6FFFFFF6, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF, 0xFFFFFFFF):
        add(f"pn-xnum-section-type-{kind:08x}", "extended-section-type",
            extended_count(sh_type=kind), "Section zero factory may select specialized constructors.")
    for cut in (1, 6, 7, 32, 64, 70, 100, 128):
        add(f"pn-xnum-truncate-{cut}", "extended-count", extended_count(truncate=cut),
            "Section or string-table truncation retains the original upstream diagnostic.")
    owners = (b"", b"\0", CORE, b"CORE", b"CORE\0\0", b"CORE\0x",
              b"core\0", b"GNU\0", b"LINUX\0", b"\xff\xfe\0", b"a\0z", b"\xff")
    note_types = (0, 1, 2, 3, 4, 5, 6, 0x53494749, 0x46494C45, 0xFFFFFFFF)
    for owner_index, owner in enumerate(owners):
        for kind in note_types:
            add(f"owner-{owner_index:02}-type-{kind:08x}", "note-owner-and-type",
                elf(segments=[{"body": note(kind, owner, b"\x00\xff\x80xyz")}]),
                "Only byte-exact CORE NUL admits Linux interpretation and ET_CORE enum labels.")
    for machine in (62, 183):
        descriptor = prstatus(machine)
        for length in (0, 1, 11, 12, 13, 31, 32, 111, 112, len(descriptor) - 1,
                       len(descriptor), len(descriptor) + 1, len(descriptor) + 32):
            payload = (descriptor + b"\xEE" * 32)[:length]
            add(f"prstatus-m{machine}-bytes{length}", "prstatus-layout",
                elf(machine, [{"body": note(1, CORE, payload)}]),
                "Actual pinned pwntools PRSTATUS size, truncation and opaque extension.")
        for index, (signal, pid, pattern) in enumerate(((0, 0, 0),
                (0x7FFF, 0x7FFFFFFF, 1), (0x8000, 0x80000000, 1 << 63),
                (0xFFFF, 0xFFFFFFFF, U64), (11, 0x80000001, 0xFEDCBA9876543210))):
            add(f"prstatus-m{machine}-signed-{index}", "prstatus-signed",
                elf(machine, [{"body": note(1, CORE, prstatus(machine,
                    signal=signal, pid=pid, pattern=pattern))}]),
                "Signed16 current signal, signed32 historical pid and full unsigned64 registers.")
        signal = siginfo()
        for length in (0, 1, 11, 12, 15, 16, 23, 24, 27, 28, 31, 32, 33, 127, 128, 129):
            add(f"siginfo-m{machine}-bytes{length}", "siginfo-layout",
                elf(machine, [{"body": note(0x53494749, CORE,
                    (signal + bytes(128))[:length])}]),
                "Pinned ctypes object is 32 bytes; Linux's larger conventional union is not assumed.")
        for index, (number, code, errno, address) in enumerate((
                (11, 1, 0, 0), (11, 2, 0, U64), (11, 0, 0, U64),
                (11, 3, 0, 42), (11, 0xFFFFFFFF, 0xFFFFFFFF, 42),
                (7, 1, 0, 42), (0, 0, 0, 0),
                (0x80000000, 0x80000000, 0x80000000, U64),
                (0xFFFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, U64))):
            add(f"siginfo-m{machine}-union-{index}", "siginfo-union",
                elf(machine, [{"body": note(0x53494749, CORE,
                    siginfo(number=number, code=code, errno=errno, address=address, pad=0xA5))}]),
                "Signed signal/code/errno and narrowly admitted fault-address union meaning.")
    for length in range(1, 16):
        for value in (0, 0xFF):
            add(f"note-tail-{length}-{value:x}", "note-padding",
                elf(segments=[{"body": note(2, CORE, b"x") + bytes([value]) * length}]),
                "Tail shorter than note header is padding only if all zero.")
    for namesz in range(0, 9):
        owner = (b"A" * (namesz - 1) + b"\0") if namesz else b""
        for descsz in range(0, 9):
            add(f"note-alignment-n{namesz}-d{descsz}", "note-alignment",
                elf(segments=[{"body": note(2, owner, bytes(range(descsz)),
                    owner_pad=0xCC, descriptor_pad=0xDD)}]),
                "Nonzero alignment padding and all modulo-four owner/descriptor lengths.")
    for namesz, descsz in ((0xFFFFFFFF, 0), (0, 0xFFFFFFFF),
                           (0xFFFFFFFF, 0xFFFFFFFF), (1, 0), (6, 0), (5, 1), (5, 5)):
        add(f"note-declared-n{namesz:x}-d{descsz:x}", "note-range",
            elf(segments=[{"body": note(2, CORE, b"", namesz=namesz, descsz=descsz)}]),
            "Declared note lengths exercise padded range arithmetic before owner validation.")
    for index, owner in enumerate((b"\xc0\xaf\0", b"\xe0\x80\xaf\0", b"\xed\xa0\x80\0",
            b"\xf0\x80\x80\xaf\0", b"\xf4\x90\x80\x80\0", b"\xf5\x80\x80\x80\0",
            b"\xe2\x82\0", b"\xf0\x9f\x92\0", b"\x80\xbf\0", b"\xe2(\xa1\0",
            b"\xc2\xa9\0", b"\xf0\x9f\x92\xa9\0")):
        add(f"owner-utf8-{index:02}", "owner-utf8",
            elf(segments=[{"body": note(2, owner, b"opaque")}]),
            "Exact Python UTF-8 replacement semantics for overlong, surrogate, out-of-range and truncated sequences.")
    duplicate_body = note(2, CORE, b"first") + note(6, CORE, b"second")
    duplicate = elf(segments=[{"body": duplicate_body},
        {"offset": 176, "file_size": len(duplicate_body), "body": b""}])
    add("duplicate-note-ranges", "overlapping-notes", duplicate,
        "Two PT_NOTE rows cover identical bytes and must retain both observations and distinct indexes.")
    first_note_size = len(note(2, CORE, b"first"))
    overlap = elf(segments=[{"body": duplicate_body},
        {"offset": 176 + first_note_size, "file_size": len(duplicate_body) - first_note_size, "body": b""}])
    add("overlapping-note-ranges", "overlapping-notes", overlap,
        "A second PT_NOTE overlaps one complete note within the first segment.")
    add("duplicate-empty-note-segments", "overlapping-notes", elf(segments=[{"body": b""}, {"body": b""}]),
        "Empty note segments retain segment records without inventing observations.")
    mixed = elf(62, [{"type": 1, "body": b"recorded\0bytes", "memory_size": 128},
        {"body": note(1, CORE, prstatus(pid=0xFFFFFFFF))
            + note(0x53494749, CORE, siginfo()) + note(6, b"GNU\0", b"raw")},
        {"body": note(1, CORE, prstatus(signal=0x8000, pid=2, pattern=U64))
            + note(0x53494749, CORE, siginfo(number=7)) + b"\0\0"},
        {"type": 0, "offset": U64, "file_size": U64, "memory_size": 0}])
    add("mixed-segments-and-threads", "mixed", mixed,
        "Global note indexes, segment indexes, signed threads and unassociated signals remain literal.")
    valid_note = elf(183, [{"body": note(1, CORE, prstatus(183))
        + note(0x53494749, CORE, siginfo())}], phentsize=64)
    for cut in (1, 2, 3, 4, 5, 7, 11, 12, 15, 16, 31, 32, 63, 64, 127, 128):
        add(f"compound-truncate-{cut}", "compound-truncation", valid_note[:-cut],
            "Backing-range check precedes nested descriptor parsing on truncated admitted-shaped file.")
    rng = random.Random(0x524541434F5245)
    for index in range(128):
        source = (base, one, mixed, valid_note, extended_count())[index % 5]
        data = bytearray(source)
        for _ in range(1 + index % 3):
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
        add(f"seeded-mutation-{index:03}", "seeded-mutation", bytes(data),
            "Deterministic independent byte mutations; no expected result synthesized by generator.")
    # Additive second tranche: ELFFile's DynamicSegment constructor traverses
    # section factories even when the helper only reports program headers.
    dynamic_variants = [
        ("canonical", {}), ("no-sections", {"section_count": 0}),
        ("one-section", {"section_count": 1}),
        ("shoff-zero", {"declared_shoff": 0}),
        ("shoff-max", {"declared_shoff": U64}),
        ("bad-shstrndx", {"shstrndx": 0xFFFE}),
        ("str-offset-max", {"str_offset": U64}),
        ("str-offset-zero", {"str_offset": 0}),
        ("short-shentsize", {"shentsize": 63}),
        ("large-shentsize", {"shentsize": 128}),
        ("compressed", {"sh_flags": 0x800}),
        ("str-truncated", {"truncate": 7}),
        ("section-truncated", {"truncate": 100}),
    ]
    for kind in (1, 2, 3, 4, 6, 7, 8, 9, 11, 17, 18, 0x6FFFFFF5,
                 0x6FFFFFF6, 0x6FFFFFFD, 0x6FFFFFFE, 0x6FFFFFFF, 0xFFFFFFFF):
        dynamic_variants.append((f"section-type-{kind:08x}", {"sh_type": kind}))
    for kind, entsize in ((2, 24), (4, 24), (6, 16), (9, 16), (11, 24)):
        dynamic_variants.append((f"linked-type-{kind}-size{entsize}",
                                 {"sh_type": kind, "sh_entsize": entsize, "sh_link": 1}))
    for name, kwargs in dynamic_variants:
        data = patched(patched(extended_count(**kwargs), 56, 1, 2), 64, 2, 4)
        add("dynamic-sections-" + name, "dynamic-section-constructor", data,
            "Ordinary phnum with PT_DYNAMIC triggers unchanged section-factory traversal before metadata reporting.")
    for memory_field, value in (("shnum", 0), ("shnum", 3), ("shnum", 0xFFFF)):
        data = patched(patched(extended_count(), 56, 1, 2), 64, 2, 4)
        data = patched(data, 60, value, 2)
        if value == 0:
            shoff = int.from_bytes(data[40:48], "little")
            data = patched(data, shoff + 32, 2, 8)
        add(f"dynamic-sections-count-{value}", "dynamic-section-constructor", data,
            "Ordinary and extended section counts used by DynamicSegment construction.")
    return rows


def write_corpus(output: Path):
    output.mkdir(parents=True, exist_ok=False)
    (output / "fixtures").mkdir()
    manifest = []
    for index, (name, category, content, description) in enumerate(cases()):
        path = "fixtures/" + name + ".core"
        (output / path).write_bytes(content)
        manifest.append({"index": index, "id": name, "category": category,
            "path": path, "bytes": len(content), "sha256": sha256(content),
            "description": description, "parser_domain": "captured-below-native-hard-cap"})
    encoded = (json.dumps({"schema": SCHEMA, "generator_sha256": sha256(Path(__file__).read_bytes()),
        "fixture_count": len(manifest), "cases": manifest}, indent=2, sort_keys=True) + "\n").encode()
    (output / "manifest.json").write_bytes(encoded)
    print(json.dumps({"corpus": str(output.resolve()), "fixture_count": len(manifest),
                      "manifest_sha256": sha256(encoded)}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    write_corpus(parser.parse_args().output)
