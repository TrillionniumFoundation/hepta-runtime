"""Independent inputs for regex local-file search; no expected search output.

The binary framing and scheduling fields match the existing actual-I/O view
oracle. One explicitly marked whole-file preparation call establishes a real
nonempty session cache; all other admitted calls exercise regex search.
"""
from __future__ import annotations

import json
import struct

INPUT_MAGIC = b"HVCOI001"
OUTPUT_MAGIC = b"HVCOO001"
FILE_LIMIT = 5 << 20
RESULT_LIMIT = 8 << 20
FIRST_CASE_ID = 30000
SESSION = 40000


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
                 cancel=False, domain="regex-search"):
        self.blobs = []
        parameters = {} if domain == "whole-prime" else {
            "content": pattern, "context": lines, "regex": True}
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
        assert self.meta["domain"] in ("regex-search", "whole-prime")
        if self.meta["domain"] == "regex-search":
            assert self.meta["params"]["content"].strip()
            value = self.meta["params"]["context"]
            assert type(value) is int and 0 <= value < 1 << 64
            assert self.meta["params"]["regex"] is True
        return {"metadata": self.meta, "blobs": self.blobs}


def baseline_cases():
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
                regex_search_cases=sum(row["metadata"]["domain"] == "regex-search" for row in rows),
                whole_preparation_cases=sum(row["metadata"]["domain"] == "whole-prime" for row in rows),
                first_case_id=rows[0]["metadata"]["case_id"],
                last_case_id=rows[-1]["metadata"]["case_id"],
                cases_with_hooks=sum(bool(row["metadata"]["hooks"]) for row in rows),
                cancel_cases=sum(row["metadata"]["cancel_after_render"] for row in rows),
                binary_input_bytes=16 + sum(len(blob_record(row["metadata"], row["blobs"])) for row in rows))


# Inputs only: no native or Rust output is consulted to choose expectations.
REGEX_ADDITIONAL = [('empty-invalid-pattern-skips-compile', b'', '(', 0), ('empty-unterminated-class-skips-compile', b'', '[', 0), ('empty-nfa-limit-skips-compile', b'', '\\w{500}', 0), ('single-lf-invalid-pattern-compiles', b'\n', '(', 0), ('unanchored-substring', b'prefix hit suffix\nHIT\n', 'hit', 0), ('anchors-are-per-line', b'prefix hit suffix\nhit\n', '^hit$', 0), ('unicode-case-fold', 'a K K k\nÄä\n', '(?i)k', 0), ('unicode-case-fold-diaeresis', 'x äÄ y\n', '(?i)\\u00e4', 0), ('unicode-case-fold-sigma', 'Σ σ ς\nx\n', '(?i)\\u03a3', 0), ('unicode-greek-property', 'abc\nαβ\n中\n', '\\p{Greek}+', 0), ('unicode-word-boundary', ' 中 \nword\nabcword\n', '\\bword\\b', 0), ('unicode-word-boundary-nonascii', ' 中 \na中\n', '\\b\\u4e2d\\b', 0), ('ascii-word-boundary', b'word\nxwordx\n', '(?-u:\\b)word(?-u:\\b)', 0), ('set-intersection', b'qq\nqa\n123\n', '[a-z&&[^q]]+', 0), ('set-difference', b'aeiou\nxyz\n', '[a-z--[aeiou]]+', 0), ('set-symmetric-difference', b'a\nb\nc\nd\n', '[a-c~~b-d]', 0), ('multiline-flag-line-isolation', b'a\nb\nc\n', '(?m)^b$', 0), ('dotall-does-not-join-lines', b'a\nb\naXb\n', '(?s)a.b', 0), ('crlf-trim-before-regex', b'hit\r\nhit\r', 'hit$', 0), ('explicit-cr-only-lone-cr', b'hit\r\nhit\r', '\\r$', 0), ('trailing-newline-no-phantom-line', b'x\n', '^$', 0), ('empty-lines-match', b'\nx\n\n', '^$', 1), ('verbose-empty-expression', b'x\n\nz\n', '(?x) # ignored', 0), ('alternation-empty-branch', b'x\n\nz\n', 'no|', 0), ('greedy-lazy-look-not-needed', b'aab\naaa\n', 'a+?b', 0), ('captures-nested', b'abcd\nabd\n', '(a)(?:b)(?<named>c)?d', 0), ('flags-nested', b'Aa\nAA\naa\n', '(?i:a)(?-i:a)', 0), ('special-word-start', b'word\nsword\n', '\\b{start}word', 0), ('special-word-end', b'word\nwordx\n', 'word\\b{end}', 0), ('unicode-lossy-replacement-regex', b'a\xffb\nclean\n', '\\x{fffd}', 0), ('repetition-non-match', b'aaa\nbbbb\n', 'a{2,2}$', 0), ('range-endpoints-ignored', b'x\nhit\n', 'h.t', 0), ('nul-expression', b'a\x00b\nabc\n', '\\x00', 0), ('escaped-pattern-newline-does-not-cross-lines', b'a\nb\n', 'a\\nb', 0), ('literal-lf-does-not-cross-lines', b'a\nb\n', 'a\nb', 0), ('no-match-message-keeps-regex-pattern', b'other\n', '"\\\\\x00中', 0)]
DIAGNOSTIC_INPUTS = [(0, 'a'), (1, '^a$'), (2, '(?i)Ä'), (3, '(?m)^b$'), (4, 'a|bc'), (5, '\\p{Greek}+'), (6, '\\bword\\b'), (7, '[a-z&&[^q]]+'), (8, '(?x)#end'), (10, '('), (11, ')'), (12, '(()'), (13, '(?'), (14, '(?)'), (15, '(?P'), (16, '(?P<'), (17, '(?<'), (18, '(?<>a)'), (19, '(?P<>a)'), (20, '(?<1x>a)'), (21, '(?<x!>a)'), (22, '(?<x>a)(?<x>b)'), (23, '(?i-i:a)'), (24, '(?ii:a)'), (25, '(?i--m:a)'), (26, '(?-:a)'), (27, '(?i'), (28, '(?-)'), (29, '(?q:a)'), (30, '(?🙂:a)'), (31, '(?=a)'), (32, '(?!a)'), (33, '(?<=a)'), (34, '(?<!a)'), (35, '*'), (36, '+'), (37, '?'), (38, '{3}'), (39, '(?i)*'), (40, 'a{'), (41, 'a{}'), (42, 'a{,}'), (43, 'a{2,1}'), (44, 'a{1'), (45, 'a{1,'), (46, 'a{1,2'), (47, 'a{a}'), (48, 'a{4294967296}'), (49, 'a{1,4294967296}'), (50, '\\'), (51, '\\1'), (52, '\\8'), (53, '\\k'), (54, '\\é'), (55, '\\x'), (56, '\\xF'), (57, '\\xG'), (58, '\\x{'), (59, '\\x{}'), (60, '\\x{G}'), (61, '\\x{FFFFFFFFF}'), (62, '\\x{D800}'), (63, '\\x{110000}'), (64, '\\uD800'), (65, '\\U00110000'), (66, '['), (67, '[]'), (68, '[^'), (69, '[-'), (70, '[a'), (71, '[['), (72, '[a-'), (73, '[a-]'), (74, '[a-z'), (75, '[z-a]'), (76, '[\\d-a]'), (77, '[a-\\d]'), (78, '[\\b]'), (79, '[\\A]'), (80, '[\\q]'), (81, '\\p'), (82, '\\p{'), (83, '\\p{Greek'), (84, '\\p\\'), (85, '\\p{}'), (86, '\\p{NoSuch}'), (87, '\\p{Script=NoSuch}'), (88, '\\p{NoSuch=Greek}'), (89, '(?-u:\\pL)'), (90, '(?-u:\\xFF)'), (91, '(?-u:.)'), (92, '(?-u:[é])'), (93, '(?-u:\\D)'), (94, '(?-u:[^\\x00-\\x7F])'), (95, '\\b{'), (96, '\\b{x}'), (97, '\\b{startX}'), (98, '\\b{start!'), (99, '\\b{abcdefghijklmnopq}'), (100, '\\b{start}'), (101, '\\b{end-half}'), (102, 'a\n('), (103, '(?x)\n[a-\n\\d]'), (104, '(?x)\r\n\\q'), (105, '(?x)\n(?<a>.)\n(?<a>.)'), (106, '(?x)\n[\\d-\n a]'), (107, '(?x)\n\\x{\n G}'), (108, '\t\\q'), (109, '🙂\\q'), (110, 'é['), (111, '\r('), (112, '\r\n('), (113, 'a\n'), (114, 'a\n\n\\'), (115, 'a\n(?i-i:a)'), (116, '\\w{500}'), (117, 'a{327674}'), (118, '(((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((a)))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))))'), (119, '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[a]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]'), (120, '\\x0'), (121, '\\x00'), (122, '\\x{0}'), (123, '\\x{0000000000000000000000000000000000000}'), (124, '\\x{FFFFFF}'), (125, '\\x{123456789}'), (126, '\\x{ 0 }'), (127, '\\x{1\n2}'), (128, '\\u0'), (129, '\\u00'), (130, '\\u{0}'), (131, '\\u{0000000000000000000000000000000000000}'), (132, '\\u{FFFFFF}'), (133, '\\u{123456789}'), (134, '\\u{ 0 }'), (135, '\\u{1\n2}'), (136, '\\U0'), (137, '\\U00'), (138, '\\U{0}'), (139, '\\U{0000000000000000000000000000000000000}'), (140, '\\U{FFFFFF}'), (141, '\\U{123456789}'), (142, '\\U{ 0 }'), (143, '\\U{1\n2}'), (144, '['), (145, '\\q'), (146, '(?<dup>a)(?<dup>b)'), (147, '[z-a]'), (148, '\\p{Xxx=Zzz}'), (149, 'é['), (150, 'é\\q'), (151, 'é(?<dup>a)(?<dup>b)'), (152, 'é[z-a]'), (153, 'é\\p{Xxx=Zzz}'), (154, '(?x) \n['), (155, '(?x) \n\\q'), (156, '(?x) \n(?<dup>a)(?<dup>b)'), (157, '(?x) \n[z-a]'), (158, '(?x) \n\\p{Xxx=Zzz}'), (159, '(?x)\r\n['), (160, '(?x)\r\n\\q'), (161, '(?x)\r\n(?<dup>a)(?<dup>b)'), (162, '(?x)\r\n[z-a]'), (163, '(?x)\r\n\\p{Xxx=Zzz}')]

def iter_cases():
    rows = baseline_cases()
    for row in rows:
        yield row
    serial = FIRST_CASE_ID + 72
    for name, raw, pattern, amount in REGEX_ADDITIONAL:
        row = Builder(serial, name, pattern=pattern, lines=amount)
        if name == "range-endpoints-ignored":
            row.meta["params"].update({"start": {"bad": True}, "end": [False], "full": True})
        yield row.setup(raw).finish()
        serial += 1
    for identity, pattern in DIAGNOSTIC_INPUTS:
        yield Builder(serial, "diagnostic-" + str(identity), pattern=pattern).setup("prefix a \u03b1\u4e2d suffix\nother\n").finish()
        serial += 1
