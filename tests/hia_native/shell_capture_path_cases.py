"""Inputs and byte envelopes for the pure capture-path owner.

No Python path normalization, parent calculation, capture-path formatting or
expected semantic output is implemented here. Rust and HIA execute those rules.
Raw Unix path bytes include invalid UTF-8 and NUL. NUL in a typed TMPDIR
observation is a pure projection case, not an actual OS environment claim.
"""
from __future__ import annotations
from collections import Counter
from itertools import product
import struct

MASK64 = (1 << 64) - 1

def payload(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if type(value) is not dict or set(value) != {"pattern", "bytes"}:
        raise ValueError("invalid capture-path byte recipe")
    pattern = bytes.fromhex(value["pattern"])
    size = value["bytes"]
    if not pattern or type(size) is not int or size < 0:
        raise ValueError("invalid capture-path repeat extent")
    count, rest = divmod(size, len(pattern))
    return pattern * count + pattern[:rest]

def repeat(pattern, size):
    return {"pattern": pattern.hex(), "bytes": size}

def frame(*, op, first=b"", second=b"", tmpdir_present=0, pid=0, seq=0):
    first, second = payload(first), payload(second)
    words = (op, tmpdir_present, pid, seq, len(first), len(second), 0)
    if any(type(word) is not int or not 0 <= word <= MASK64 for word in words):
        raise ValueError("capture-path request word is not u64")
    return b"HSHCPQ01" + struct.pack("<7Q", *words) + first + second

def decode_body(body):
    if len(body) < 80 or body[:8] != b"HSHCPR01":
        raise ValueError("capture-path response header differs")
    op, extent, flag, next_seq, path_size, id_size, stdout_size, stderr_size, reserved = struct.unpack_from("<9Q", body, 8)
    if op not in (1, 2, 3) or extent != len(body) or reserved != 0:
        raise ValueError("capture-path response tags or full extent differ")
    if 80 + path_size + id_size + stdout_size + stderr_size != extent:
        raise ValueError("capture-path response component extents differ")
    if op == 1 and (flag not in (0, 1) or any((next_seq, path_size, id_size, stdout_size, stderr_size))):
        raise ValueError("capture-path equality envelope differs")
    if op == 2 and (flag not in (0, 1) or any((next_seq, id_size, stdout_size, stderr_size)) or (flag == 0 and path_size != 0)):
        raise ValueError("capture-path parent envelope differs")
    if op == 3 and flag != 0:
        raise ValueError("capture-path formatting envelope differs")
    cursor = 80
    fields = {}
    for name, size in (("path", path_size), ("id", id_size), ("stdout", stdout_size), ("stderr", stderr_size)):
        fields[name] = body[cursor:cursor + size]
        cursor += size
    return {"op": op, "extent": extent, "flag": flag, "next_seq": next_seq, **fields}

def response_at(raw, offset):
    if not 0 <= offset <= len(raw) - 16:
        raise ValueError("missing capture-path response packet")
    returned, size = struct.unpack_from("<2Q", raw, offset)
    if returned != 80 or size < 80 or offset + 16 + size > len(raw):
        raise ValueError("invalid capture-path fixed return or full extent")
    body = raw[offset + 16:offset + 16 + size]
    decode_body(body)
    return offset + 16 + size, body

def specifications():
    result = []
    def add(name, group, **fields):
        result.append({"name": name, "group": group, "fields": fields})
    # Cartesian input generation does not calculate expected equality.
    short = {b"", b"/", b"//", b"///", b".", b"..", b"./", b"../"}
    for length in range(1, 3):
        for components in product((b"", b"a", b"b", b".", b".."), repeat=length):
            path = b"/".join(components)
            short.update((path, b"/" + path, b"./" + path, path + b"/"))
    short = sorted(short)
    for i, first in enumerate(short):
        for j, second in enumerate(short):
            add(f"eq-cartesian-{i}-{j}", "component-equality-cartesian", op=1, first=first, second=second)
    paths = set(short)
    for length in range(1, 5):
        for components in product((b"", b"a", b"b", b".", b".."), repeat=length):
            path = b"/".join(components)
            paths.update((path, b"//" + path, b"./" + path, path + b"//./"))
    for index, path in enumerate(sorted(paths)):
        add(f"parent-components-{index}", "parent-components", op=2, first=path)
        for variant, other in enumerate((path, path + b"/", path + b"/.", b"./" + path, b"/" + path)):
            add(f"eq-components-{index}-{variant}", "component-equality-variants", op=1, first=path, second=other)
    for byte in range(256):
        raw = bytes([byte])
        samples = (raw, b"a/" + raw, raw + b"/a", b"./" + raw, b"//" + raw + b"//.", b"a/" + raw + b"/../b")
        for index, path in enumerate(samples):
            add(f"parent-byte-{byte:02x}-{index}", "parent-raw-byte", op=2, first=path)
            add(f"eq-byte-self-{byte:02x}-{index}", "equality-raw-byte", op=1, first=path, second=path)
            add(f"eq-byte-dot-{byte:02x}-{index}", "equality-raw-byte", op=1, first=path, second=path + b"/.")
            add(f"eq-byte-other-{byte:02x}-{index}", "equality-raw-byte", op=1, first=path, second=path + b"x")
    malformed = (b"\xc0\x80", b"\xc2", b"\xe2\x82", b"\xed\xa0\x80", b"\xf0\x90\x80", b"\xf4\x90\x80\x80", b"\xff\xfe", "目录/文件".encode(), b"a\x00b", b"C:\\root\\file")
    for index, raw in enumerate(malformed):
        for variant, path in enumerate((raw, b"/" + raw, b"./" + raw + b"//./..")):
            add(f"parent-raw-sequence-{index}-{variant}", "parent-raw-sequence", op=2, first=path)
            add(f"eq-raw-sequence-{index}-{variant}", "equality-raw-sequence", op=1, first=path, second=path + b"/.")
    pids = sorted({0, 1, 9, 10, 99, 100, 999, 1000, (1 << 31) - 1, 1 << 31, (1 << 32) - 2, (1 << 32) - 1})
    seqs = {0, 1, 2, MASK64 - 1, MASK64}
    for exponent in range(1, 20):
        for delta in (-1, 0, 1):
            value = 10 ** exponent + delta
            if value <= MASK64:
                seqs.add(value)
    for exponent in (31, 32, 53, 63):
        seqs.update(((1 << exponent) - 1, 1 << exponent, (1 << exponent) + 1))
    seqs = sorted(seqs)
    tempdirs = (None, b"", b"/", b"//", b"/tmp", b"/tmp/", b"tmp", b".", b"..", b"./tmp", b"tmp//./", b"../tmp", b"/a/../b", b"/a//./b//", "临时/目录".encode(), b"/tmp/\xff", b"a\x00b")
    for ti, tempdir in enumerate(tempdirs):
        for pid in pids:
            for seq in seqs:
                add(f"capture-decimal-{ti}-{pid}-{seq}", "capture-decimal-and-tmpdir", op=3,
                    first=b"" if tempdir is None else tempdir, tmpdir_present=int(tempdir is not None), pid=pid, seq=seq)
    for byte in range(256):
        for variant, tempdir in enumerate((bytes([byte]), b"a/" + bytes([byte]) + b"//")):
            for seq in (0, MASK64):
                add(f"capture-byte-{byte:02x}-{variant}-{seq}", "capture-raw-byte", op=3,
                    first=tempdir, tmpdir_present=1, pid=(1 << 32) - 1, seq=seq)
    # Finite resource-sized samples do not impose a native/API byte quota.
    for size in (4095, 4096, 4097, 65535, 65536, 65537, 1048577):
        path = repeat(b"a/./b//../", size)
        add(f"parent-large-{size}", "large-byte-extents", op=2, first=path)
        add(f"eq-large-{size}", "large-byte-extents", op=1, first=path, second=path)
        add(f"capture-large-{size}", "large-byte-extents", op=3, first=path, tmpdir_present=1, pid=(1 << 32) - 1, seq=MASK64)
    names = [item["name"] for item in result]
    if len(names) != len(set(names)):
        raise ValueError("duplicate capture-path semantic case name")
    return result

def counts(cases=None):
    cases = specifications() if cases is None else cases
    return {"semantic_cases": len(cases),
            "groups": dict(sorted(Counter(item["group"] for item in cases).items())),
            "operations": dict(sorted(Counter(item["fields"]["op"] for item in cases).items()))}
