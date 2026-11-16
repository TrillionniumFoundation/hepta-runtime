"""Independent actual-filesystem inputs for ordinary local view qualification.

This module generates inputs only. Expected text, endpoint decisions, cache
contents and original I/O outcomes are produced by the frozen Rust functions.
"""
from __future__ import annotations

import json
import struct

INPUT_MAGIC = b"HVCOI001"
OUTPUT_MAGIC = b"HVCOO001"
LIMIT = 5 << 20


def blob_record(metadata, blobs):
    raw = json.dumps(metadata, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":"), allow_nan=False).encode()
    return struct.pack("<QQ", len(raw), len(blobs)) + raw + b"".join(
        struct.pack("<Q", len(value)) + value for value in blobs)


def encode_cases(cases):
    cases = list(cases)
    return INPUT_MAGIC + struct.pack("<Q", len(cases)) + b"".join(
        blob_record(case["metadata"], case["blobs"]) for case in cases)


def _read_exact(stream, count):
    raw = stream.read(count)
    if len(raw) != count:
        raise AssertionError("truncated original view record")
    return raw


def read_records(stream, magic):
    if _read_exact(stream, 8) != magic:
        raise AssertionError("original view protocol magic differs")
    count, = struct.unpack("<Q", _read_exact(stream, 8))
    for _ in range(count):
        size, n = struct.unpack("<QQ", _read_exact(stream, 16))
        meta = json.loads(_read_exact(stream, size))
        blobs = []
        for _ in range(n):
            size, = struct.unpack("<Q", _read_exact(stream, 8))
            blobs.append(_read_exact(stream, size))
        yield {"metadata": meta, "blobs": blobs}
    if stream.read(1):
        raise AssertionError("trailing original view record")


class Builder:
    def __init__(self, case_id, name, *, path=b"file", params=None, session=None,
                 reset=True, context=True, raw=False, cancel=False):
        self.blobs = []
        self.meta = dict(case_id=case_id, name=name,
                         session=case_id if session is None else session,
                         path_hex=path.hex(), params=params or {},
                         reset_cache=reset, context=context, raw_path=raw,
                         cancel_after_render=cancel, setup=[], hooks=[],
                         cache_probes=[path.hex()])

    def data(self, raw):
        if isinstance(raw, str):
            raw = raw.encode()
        self.blobs.append(raw)
        return len(self.blobs) - 1

    def write(self, data, path=None):
        return dict(kind="write", path_hex=path or self.meta["path_hex"],
                    blob=self.data(data))

    def setup(self, data):
        self.meta["setup"].append(self.write(data))
        return self

    def after(self, event, occurrence, data=None, *, actions=None):
        self.meta["hooks"].append(dict(event=event, occurrence=occurrence,
                                       when="after", actions=actions or [self.write(data)]))
        return self

    def before(self, event, occurrence, actions):
        self.meta["hooks"].append(dict(event=event, occurrence=occurrence,
                                       when="before", actions=actions))
        return self

    def finish(self):
        return {"metadata": self.meta, "blobs": self.blobs}


def iter_cases():
    serial = 0

    def case(name, **kw):
        nonlocal serial
        row = Builder(serial, name, **kw)
        serial += 1
        return row

    for name, data in [
        ("empty", b""), ("one-line-no-lf", b"alpha"),
        ("one-line-lf", b"alpha\n"), ("single-empty-line", b"\n"),
        ("crlf-and-lone-cr", b"alpha\r\n\r\nbeta\rgamma\r\n"),
        ("unicode-nul-controls", "中🙂\0\"\\\t\r\nsecond\n"),
        ("all-lf-boundary", b"\n\n\n"),
    ]:
        yield case(name).setup(data).finish()
    endpoints = [
        ("range-first", {"start": 1, "end": 1}),
        ("range-last-negative", {"start": -1}),
        ("range-reversed-clamped", {"start": 900, "end": -900}),
        ("range-i64-min-max", {"start": -(1 << 63), "end": (1 << 63) - 1}),
        ("range-stale-composite-id", {"start": "2:FF", "end": "3:00"}),
        ("range-numeric-whitespace", {"start": " 2 ", "end": " -1 "}),
        ("range-zero", {"start": 0}),
        ("range-float", {"start": 1.5}),
        ("range-bool", {"start": True}),
        ("range-malformed-id", {"start": "2:gg"}),
        ("range-null", {"start": None, "end": None}),
    ]
    for name, params in endpoints:
        yield case(name, params=params).setup(b"one\r\ntwo\nthree\r\nfour").finish()
    yield case("empty-range-zero-is-whole", params={"start": 0}).setup(b"").finish()
    yield case("range-first-invalid-then-valid", params={"start": 2}).setup(b"\xffbad").after(
        "read", 1, b"good\r\nnext\n").finish()
    yield case("range-first-empty-then-valid", params={"start": 3}).setup(b"").after(
        "read", 1, b"first\nsecond\n").finish()
    yield case("range-shrinks-start-error", params={"start": 4, "end": 4}).setup(
        b"a\nb\nc\nd\n").after("read", 1, b"a\n").finish()
    yield case("range-shrinks-end-clamps", params={"start": 1, "end": 4}).setup(
        b"a\nb\nc\nd\n").after("read", 1, b"a\nb\n").finish()
    yield case("range-same-size-replacement", params={"start": 2, "end": 2}).setup(
        b"a\nb\nc\n").after("read", 1, b"x\ny\nz\n").finish()
    yield case("whole-invalid-utf8").setup(b"valid\n\xf0\x28\x8c\xbc").finish()
    yield case("range-second-invalid", params={"start": 9, "end": -9}).setup(
        b"a\nb\n").after("read", 1, b"\xff").finish()
    yield case("utf8-cross-64k-read").setup(b"a" * 65535 + "🙂\r\n中".encode()).finish()
    yield case("utf8-truncated-at-eof").setup(b"a" * 65535 + b"\xf0\x9f\x99").finish()
    yield case("five-mib-exact").setup(b"q" * LIMIT).finish()
    yield case("five-mib-plus-one").setup(b"q" * (LIMIT + 1)).finish()
    yield case("range-precheck-before-read", params={"start": 1, "end": 1}).setup(
        b"q" * (LIMIT + 1)).finish()
    yield case("range-second-stat-observes-growth", params={"start": 1, "end": 1}).setup(
        b"a\nb\n").after("read", 1, b"a\n" + b"q" * LIMIT).finish()
    yield case("range-growth-after-second-stat-over-16mib", params={"start": 1, "end": 1}).setup(
        b"first\nsecond\n").after("metadata", 2, b"first\n" + b"q" * ((17 << 20) + 3) + b"\nlast\n").finish()
    yield case("whole-growth-after-stat-over-16mib").setup(b"short\n").after(
        "metadata", 1, b"q" * ((17 << 20) + 3)).finish()
    row = case("first-read-growth-then-shrink", params={"start": 1, "end": 1}).setup(b"a\nb\n")
    row.after("metadata", 1, b"a\n" + b"q" * ((17 << 20) + 3) + b"\nz\n")
    row.after("read", 1, b"x\ny\n")
    yield row.finish()

    row = case("normal-symlink")
    row.meta["setup"] = [row.write(b"link target\n", b"target".hex()),
                          dict(kind="symlink", path_hex=b"file".hex(), target_hex=b"target".hex())]
    row.meta["cache_probes"].append(b"target".hex())
    yield row.finish()
    row = case("normal-hardlink")
    row.meta["setup"] = [row.write(b"hard target\n", b"target".hex()),
                          dict(kind="hardlink", path_hex=b"file".hex(), target_hex=b"target".hex())]
    row.meta["cache_probes"].append(b"target".hex())
    yield row.finish()
    yield case("raw-unix-path", path=b"raw-\xff-file", raw=True).setup(b"raw\r\nbytes\n").finish()
    yield case("embedded-nul-path", path=b"a\0b", raw=True).finish()
    yield case("missing-public-path").finish()
    row = case("dangling-symlink")
    row.meta["setup"] = [dict(kind="symlink", path_hex=b"file".hex(), target_hex=b"absent".hex())]
    yield row.finish()
    row = case("vanish-after-file-check").setup(b"present\n")
    row.after("is_file", 1, actions=[dict(kind="remove", path_hex=b"file".hex())])
    yield row.finish()
    row = case("vanish-after-stat").setup(b"present\n")
    row.after("metadata", 1, actions=[dict(kind="remove", path_hex=b"file".hex())])
    yield row.finish()
    row = case("directory-after-file-check").setup(b"present\n")
    row.after("is_file", 1, actions=[dict(kind="remove", path_hex=b"file".hex()),
                                     dict(kind="mkdir", path_hex=b"file".hex())])
    yield row.finish()
    row = case("range-first-stat-error-recovered", params={"start": 1, "end": 1}).setup(b"old\n")
    row.before("metadata", 1, [dict(kind="remove", path_hex=b"file".hex())])
    row.after("metadata", 1, b"new\nnext\n")
    yield row.finish()

    # Same cache handle, actual relative path and content across separate calls.
    for name, data, params, reset, context, cancel in [
        ("cache-first", b"first\r\nsecond\n", {}, True, True, False),
        ("cache-unchanged-normalized", b"first\nsecond\n", {}, False, True, False),
        ("cache-full", b"first\nsecond\n", {"full": True}, False, True, False),
        ("cache-delta", b"first\nchanged\n", {}, False, True, False),
        ("range-leaves-cache", b"first\nchanged again\n", {"start": 2}, False, True, False),
        ("whole-after-range", b"first\nchanged again\n", {}, False, True, False),
        ("outside-scope-keeps-cache", b"outside\n", {}, False, False, False),
        ("cache-applied-before-cancel", b"cancelled result\n", {}, False, True, True),
        ("cache-survives-cancel", b"cancelled result\n", {}, False, True, False),
        ("cache-applied-before-8mib-error", b"\n" * (1 << 20), {}, False, True, False),
        ("cache-survives-8mib-error", b"\n" * (1 << 20), {}, False, True, False),
        ("cache-evicted-before-8mib-error", b"\n" * ((1 << 20) + 1), {"full": True}, False, True, False),
        ("cache-absent-after-error", b"again\n", {}, False, True, False),
    ]:
        yield case(name, session=1000, reset=reset, params=params, context=context,
                   cancel=cancel).setup(data).finish()


def materialize_inputs(path):
    raw = encode_cases(iter_cases())
    path.write_bytes(raw)
    return len(raw)
