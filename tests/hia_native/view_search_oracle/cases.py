"""Independent inputs for literal local-file search; no expected search output.

The binary framing and scheduling fields match the existing actual-I/O view
oracle. One explicitly marked whole-file preparation call establishes a real
nonempty session cache; all other admitted calls exercise literal search.
"""
from __future__ import annotations

import json
import struct

INPUT_MAGIC = b"HVCOI001"
OUTPUT_MAGIC = b"HVCOO001"
FILE_LIMIT = 5 << 20
RESULT_LIMIT = 8 << 20
FIRST_CASE_ID = 10000
SESSION = 20000


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def blob_record(metadata, blobs):
    raw = canonical(metadata)
    return struct.pack("<QQ", len(raw), len(blobs)) + raw + b"".join(
        struct.pack("<Q", len(blob)) + blob for blob in blobs)


def write_cases(stream):
    count = sum(1 for _ in iter_cases())
    stream.write(INPUT_MAGIC + struct.pack("<Q", count))
    for row in iter_cases():
        stream.write(blob_record(row["metadata"], row["blobs"]))
    return count


def encode_cases(rows=None):
    rows = list(iter_cases() if rows is None else rows)
    return INPUT_MAGIC + struct.pack("<Q", len(rows)) + b"".join(
        blob_record(row["metadata"], row["blobs"]) for row in rows)


def _read_exact(stream, size):
    raw = stream.read(size)
    if len(raw) != size:
        raise AssertionError("truncated search original record")
    return raw


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AssertionError("duplicate original JSON key")
        result[key] = value
    return result


def read_records(stream, magic):
    if _read_exact(stream, 8) != magic:
        raise AssertionError("original search protocol magic differs")
    count, = struct.unpack("<Q", _read_exact(stream, 8))
    for _ in range(count):
        size, n = struct.unpack("<QQ", _read_exact(stream, 16))
        metadata = json.loads(_read_exact(stream, size), object_pairs_hook=_object,
                              parse_constant=lambda value: (_ for _ in ()).throw(
                                  AssertionError("nonfinite original JSON")))
        blobs = []
        for _ in range(n):
            size, = struct.unpack("<Q", _read_exact(stream, 8))
            blobs.append(_read_exact(stream, size))
        yield {"metadata": metadata, "blobs": blobs}
    if stream.read(1):
        raise AssertionError("trailing original search bytes")


class Builder:
    def __init__(self, case_id, name, *, pattern="hit", lines=0, path=b"file",
                 params=None, session=None, reset=True, context=True,
                 cancel=False, domain="literal-search"):
        self.blobs = []
        parameters = {} if domain == "whole-prime" else {
            "content": pattern, "context": lines, "regex": False}
        parameters.update(params or {})
        self.meta = dict(case_id=case_id, name=name, domain=domain,
                         session=case_id if session is None else session,
                         path_hex=path.hex(), params=parameters,
                         reset_cache=reset, context=context, raw_path=False,
                         cancel_after_render=cancel, setup=[], hooks=[],
                         cache_probes=[path.hex()])

    def data(self, raw):
        raw = raw.encode() if isinstance(raw, str) else raw
        assert type(raw) is bytes
        self.blobs.append(raw)
        return len(self.blobs) - 1

    def write(self, raw, path=None):
        return dict(kind="write", path_hex=(path or bytes.fromhex(
            self.meta["path_hex"])).hex(), blob=self.data(raw))

    def setup(self, raw, path=None):
        self.meta["setup"].append(self.write(raw, path))
        return self

    def after(self, event, occurrence, raw=None, *, actions=None):
        self.meta["hooks"].append(dict(event=event, occurrence=occurrence,
            when="after", actions=[self.write(raw)] if actions is None else actions))
        return self

    def finish(self):
        assert self.meta["domain"] in ("literal-search", "whole-prime")
        if self.meta["domain"] == "literal-search":
            assert self.meta["params"]["content"].strip()
            value = self.meta["params"]["context"]
            assert type(value) is int and 0 <= value < 1 << 64
            assert self.meta["params"]["regex"] is False
        return {"metadata": self.meta, "blobs": self.blobs}


def iter_cases():
    serial = FIRST_CASE_ID

    def case(name, **kwargs):
        nonlocal serial
        row = Builder(serial, name, **kwargs)
        serial += 1
        return row

    basics = [
        ("empty", b"", "hit"),
        ("empty-file-message-bytes", b"", "\"\\\0\n中"),
        ("single-empty-line", b"\n", "hit"),
        ("one-line-no-lf", b"hit", "hit"),
        ("one-line-lf", b"hit\n", "hit"),
        ("case-sensitive-miss", b"HIT\nHit\n", "hit"),
        ("repeated-occurrences-one-line", b"hit hit hit\nmiss\nhit\n", "hit"),
        ("regex-punctuation-is-literal", b"[x].* (bad\nanything\n", "[x].*"),
        ("invalid-regex-is-literal", b"(\nmiss\n", "("),
        ("pattern-not-trimmed", b"hit\n hit \n  hit  \n", " hit "),
        ("pattern-crosses-lines", b"a\nb\na\nb\n", "a\nb"),
        ("crlf-and-lone-cr", b"x\r\ny\r\nx\ry\r\ny\r", "y\r"),
        ("no-trailing-lf-match", b"zero\nhit\nlast", "hit"),
        ("nul-pattern-and-file", b"a\0hit\nb\0tail\n", "\0"),
        ("unicode-scalar-pattern", "α\n中🙂\r\n🙂中\n", "中🙂"),
        ("unicode-normalization-not-applied", "e\u0301\né\n", "é"),
        ("non-ascii-whitespace-preserved", "\u0085hit\u00a0\nhit\n", "\u0085hit\u00a0"),
        ("no-match-message-control-bytes", b"nothing\n", "\"\\\0\t中"),
    ]
    for name, raw, pattern in basics:
        yield case(name, pattern=pattern).setup(raw).finish()

    context_raw = b"hit\none\ntwo\nhit\nfour\nfive\nsix\nhit\nlast"
    for amount in (0, 1, 2, 3, (1 << 63) - 1, 1 << 63, (1 << 64) - 1):
        yield case("context-" + str(amount), lines=amount).setup(context_raw).finish()
    yield case("all-lines-match-no-duplicates", lines=1).setup(b"hit\nhit\nhit\n").finish()
    yield case("only-last-line-context-clamped", lines=9).setup(b"a\nb\nhit").finish()

    invalid = [
        ("lossy-single-invalid", b"a\xffhit\n"),
        ("lossy-repeated-invalid", b"\xff\xff\n\xff\n"),
        ("lossy-truncated-sequence", b"valid\n\xf0\x9f\x99"),
        ("lossy-overlong", b"\xc0\xaf\n"),
        ("lossy-surrogate", b"\xed\xa0\x80\n"),
        ("lossy-out-of-range", b"\xf4\x90\x80\x80\n"),
        ("lossy-stray-continuations", b"\x80\x81\x82\n"),
        ("lossy-invalid-second-byte", b"\xf0\x28\x8c\xbc\n"),
        ("lossy-all-byte-values", bytes(range(256))),
        ("lossy-valid-and-replaced-scalar", "�\n".encode() + b"\xff\n"),
        ("lossy-cross-64k", b"a" * 65535 + b"\xf0\x9f\x99\nhit\n"),
    ]
    for name, raw in invalid:
        yield case(name, pattern="�", lines=1).setup(raw).finish()
    yield case("valid-utf8-cross-64k", pattern="🙂").setup(
        b"a" * 65535 + "🙂\r\n中\n".encode()).finish()

    for name, path in [
        ("unicode-control-file-name", "中\"\nfile".encode()),
        ("existing-pipe-file-name", b"one|two"),
    ]:
        yield case(name, path=path).setup(b"hit\n").finish()
    for kind in ("symlink", "hardlink"):
        row = case(kind + "-regular-file", path=b"alias").setup(b"miss\nhit\n", b"target")
        row.meta["setup"].append(dict(kind=kind, path_hex=b"alias".hex(),
                                      target_hex=b"target".hex()))
        yield row.finish()
    row = case("dangling-symlink", path=b"alias")
    row.meta["setup"].append(dict(kind="symlink", path_hex=b"alias".hex(),
                                  target_hex=b"missing".hex()))
    yield row.finish()
    yield case("missing-file").finish()
    yield case("not-directory-in-path", path=b"file/child").setup(b"hit\n", b"file").finish()
    yield case("nul-path", path=b"file\0tail").finish()

    remove = dict(kind="remove", path_hex=b"file".hex())
    mkdir = dict(kind="mkdir", path_hex=b"file".hex())
    for event, occurrence in (("exists", 1), ("is_dir", 1), ("exists", 2), ("is_file", 1), ("metadata", 1)):
        yield case("remove-after-" + event + "-" + str(occurrence)).setup(
            b"hit\n").after(event, occurrence, actions=[remove]).finish()
    yield case("directory-after-metadata-read-error").setup(b"hit\n").after(
        "metadata", 1, actions=[remove, mkdir]).finish()
    yield case("same-size-replacement-after-metadata").setup(b"old\nhit\n").after(
        "metadata", 1, b"hit\nnew\n").finish()
    yield case("replacement-after-read-preserves-snapshot").setup(b"hit old\n").after(
        "read", 1, b"different new\n").finish()
    yield case("truncate-after-metadata").setup(b"hit\n").after("metadata", 1, b"").finish()

    for offset, label in ((-1, "minus-one"), (0, "exact"), (1, "plus-one")):
        yield case("metadata-five-mib-" + label).setup(b"a" * (FILE_LIMIT + offset)).finish()
    yield case("grow-after-metadata-over-17mib").setup(b"hit old\n").after(
        "metadata", 1, b"a" * ((17 << 20) + 3) + b"\nhit new\n").finish()
    # The original line identifier has five ASCII bytes for line 1. These
    # inputs straddle the result gate; only Rust computes the actual result.
    for delta, label in ((-1, "minus-one"), (0, "exact"), (1, "plus-one")):
        n, tail = divmod(RESULT_LIMIT + delta - 9, 3)
        raw = b"hit:" + b"\xff" * n + b"q" * tail
        yield case("result-eight-mib-" + label).setup(raw).finish()

    yield case("search-ignores-malformed-endpoints", params={
        "start": {"invalid": [True, None, "2:GG"]}, "end": [1e15, False],
        "full": True}).setup(b"miss\nhit\n").finish()

    yield case("cache-prime-real-whole-view", session=SESSION,
               domain="whole-prime").setup(b"old cached\n").finish()
    yield case("cache-search-full-keeps-previous", session=SESSION, reset=False,
               params={"full": True}).setup(b"hit changed\n").finish()
    yield case("cache-search-unbound-keeps-previous", session=SESSION, reset=False,
               context=False).setup(b"hit unbound\n").finish()
    yield case("cache-search-cancel-keeps-previous", session=SESSION, reset=False,
               cancel=True).setup(b"hit cancelled\n").finish()
    yield case("cache-search-empty-keeps-previous", session=SESSION, reset=False).setup(b"").finish()
    yield case("cache-search-lossy-keeps-previous", session=SESSION, reset=False,
               pattern="�").setup(b"\xffhit\n").finish()
    yield case("cache-search-error-keeps-previous", session=SESSION, reset=False).setup(
        b"a" * (FILE_LIMIT + 1)).finish()
    yield case("cache-search-next-after-error", session=SESSION, reset=False).setup(b"hit final\n").finish()


def describe():
    rows = list(iter_cases())
    return dict(cases=len(rows),
                literal_search_cases=sum(row["metadata"]["domain"] == "literal-search" for row in rows),
                whole_preparation_cases=sum(row["metadata"]["domain"] == "whole-prime" for row in rows),
                first_case_id=rows[0]["metadata"]["case_id"],
                last_case_id=rows[-1]["metadata"]["case_id"],
                cases_with_hooks=sum(bool(row["metadata"]["hooks"]) for row in rows),
                cancel_cases=sum(row["metadata"]["cancel_after_render"] for row in rows),
                binary_input_bytes=16 + sum(len(blob_record(row["metadata"], row["blobs"])) for row in rows))
