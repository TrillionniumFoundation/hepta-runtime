"""Deterministic semantic inputs for HIA/original shell outcome comparison.

This module constructs inputs and validates binary envelopes. It does not
calculate shell output, errno text, terminal cleanup or Rust exit semantics.
Large inputs use compact byte recipes so corpus enumeration does not allocate
every multi-megabyte log at once. The reader reconstructs their complete bytes.
"""
from __future__ import annotations

import struct
from collections import Counter

LIMIT = 8 * 1024 * 1024
MASK64 = (1 << 64) - 1


def payload(value=b""):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if type(value) is not dict:
        raise ValueError("unknown byte recipe")
    if set(value) == {"parts"}:
        return b"".join(payload(part) for part in value["parts"])
    if set(value) != {"pattern", "bytes"}:
        raise ValueError("invalid byte recipe members")
    pattern = bytes.fromhex(value["pattern"])
    size = value["bytes"]
    if not pattern or type(size) is not int or size < 0:
        raise ValueError("invalid repeat recipe")
    count, rest = divmod(size, len(pattern))
    return pattern * count + pattern[:rest]


def repeat(pattern: bytes, size: int):
    return {"pattern": pattern.hex(), "bytes": size}


def concat(*parts):
    return {"parts": list(parts)}


def signed(value):
    if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
        raise ValueError("signed i32 input required")
    return value & MASK64


def frame(*, op=1, wait_kind=0, wait_value=0, stdout_kind=0,
          stdout_errno=0, stderr_kind=0, stderr_errno=0, pid=0,
          wait_error=b"", stdout=b"", stderr=b"", command=b"", id=b""):
    values = [payload(item) for item in (wait_error, stdout, stderr, command, id)]
    words = [op, wait_kind, signed(wait_value), stdout_kind, signed(stdout_errno),
             stderr_kind, signed(stderr_errno), pid, *(len(item) for item in values)]
    return b"HSHOUT01" + struct.pack("<13Q", *words) + b"".join(values)


def decode_body(body):
    if len(body) < 40 or body[:8] != b"HSHOUR01":
        raise ValueError("outcome response header differs")
    kind, text_size, uri_present, uri_size = struct.unpack_from("<4Q", body, 8)
    if kind not in (0, 1, 2) or uri_present not in (0, 1):
        raise ValueError("invalid outcome response tag")
    if 40 + text_size + uri_size != len(body):
        raise ValueError("outcome response extent differs")
    if (kind != 0 and uri_present != 0) or (uri_present == 0 and uri_size != 0):
        raise ValueError("outcome response URI tag differs")
    text = body[40:40 + text_size]
    uri = body[40 + text_size:]
    text.decode("utf-8", errors="strict")
    uri.decode("utf-8", errors="strict")
    return {"kind": kind, "text": text, "uri": uri if uri_present else None}


def response_at(raw, offset):
    if not 0 <= offset <= len(raw) - 16:
        raise ValueError("missing outcome response packet")
    returned, size = struct.unpack_from("<2Q", raw, offset)
    if returned != 40 or size < 40 or offset + 16 + size > len(raw):
        raise ValueError("invalid outcome semantic packet")
    body = raw[offset + 16:offset + 16 + size]
    decode_body(body)
    return offset + 16 + size, body


def _numbers(seed, count):
    """Fixed xorshift32 input enumeration; no platform RNG state."""
    value = seed
    for _ in range(count):
        value ^= (value << 13) & 0xffffffff
        value ^= value >> 17
        value ^= (value << 5) & 0xffffffff
        value &= 0xffffffff
        yield value if value < (1 << 31) else value - (1 << 32)


def specifications():
    result = []

    def add(name, group, **fields):
        result.append({"name": name, "group": group, "fields": fields})

    # Every Linux x86 errno slot, all holes, zero and a wide contiguous unknown
    # interval. The signed edges and deterministic distant values test decimal
    # formatting independently of the finite known-message table.
    errors = set(range(-512, 1025))
    errors.update((-(1 << 31), -(1 << 31) + 1, (1 << 31) - 2, (1 << 31) - 1))
    for shift in range(1, 31):
        for delta in (-1, 0, 1):
            errors.add((1 << shift) + delta)
            errors.add(-((1 << shift) + delta))
    errors.update(_numbers(0x48494131, 2048))
    for value in sorted(errors):
        add(f"errno-{value}", "errno-display", op=3, wait_kind=2, wait_value=value)

    # ExitStatusExt::from_raw accepts the entire signed i32 carrier. These
    # projections do not assert that every bit pattern is a real wait result.
    for status in range(65536):
        add(f"raw-status-low16-{status:04x}", "wait-status-low16", wait_value=status,
            stdout=b"out", stderr=b"warn")
    high_status = set(_numbers(0x48534831, 2048))
    for upper in (1, 2, 0x7fff, 0x8000, 0xffff):
        for low in (0, 1, 7, 9, 15, 0x7f, 0x80, 0xff, 0x100, 0x700, 0xff00, 0xffff):
            value = (upper << 16) | low
            high_status.add(value if value < (1 << 31) else value - (1 << 32))
    for status in sorted(high_status):
        add(f"raw-status-high-{status}", "wait-status-high", wait_value=status,
            stdout=b"out", stderr=b"warn")

    error_values = [(1, 0, b""), (1, 0, "custom\n错误\x00\x1b[31m"),
                    (2, 0, b""), (2, 2, b""), (2, 21, b""),
                    (2, -1, b""), (3, 0, b""), (4, 0, b"")]
    waits = [(0, status, b"") for status in (0, 7 << 8, 9, 0x7f)] + error_values
    reads = [(0, 0, b" \x1b[32mraw\x1b[0m\nraw\nraw\n")] + error_values
    for wi, (wk, wv, wp) in enumerate(waits):
        for oi, (ok, ov, op) in enumerate(reads):
            for ei, (ek, ev, ep) in enumerate(reads):
                add(f"error-priority-{wi}-{oi}-{ei}", "error-priority", wait_kind=wk,
                    wait_value=wv, wait_error=wp, stdout_kind=ok, stdout_errno=ov,
                    stdout=op, stderr_kind=ek, stderr_errno=ev, stderr=ep)

    streams = [b"", b"a", b"a\n", b"\n\r\x00\x07\t  ", b"same\nsame\n",
               b"same\nsame\nsame\n", b"a\rxyz\rQ\n", b"abc\b\bX\n",
               "  世\b界\t \n", b"\x1b[31mRED\x1b[0m\n",
               b"\x1b]0;title\x07text\n", b"\x1b]8;;url\x1b\\link\x1b]8;;\x1b\\",
               b"\xff\bQ", b"\xe2\x82\bQ", b"\x1b\xffX", b"\xff\rQ",
               b" \xc2\xa0\xe3\x80\x80", b"\nA\n\nB\n", b"\x1b[bad-partial"]
    for i, out in enumerate(streams):
        for j, err in enumerate(streams):
            add(f"stream-merge-{i}-{j}", "clean-and-merge", stdout=out, stderr=err)
    for first in range(256):
        add(f"single-byte-out-{first:02x}", "lossy-utf8", stdout=bytes([first]))
        add(f"single-byte-err-{first:02x}", "lossy-utf8", stderr=bytes([first]))
        for second in (0, 0x1b, 0x7f, 0x80, 0x9f, 0xa0, 0xbf, 0xc0, 0xc2,
                       0xdf, 0xe0, 0xed, 0xef, 0xf0, 0xf4, 0xff):
            add(f"utf8-pair-{first:02x}-{second:02x}", "lossy-utf8",
                stdout=bytes([first, second]) + b"\bQ", stderr=b"!" + bytes([second, first]))
    utf8 = [b"\xc0\x80", b"\xc1\xbf", b"\xc2\x80", b"\xdf\xbf", b"\xe0\x9f\xbf",
            b"\xe0\xa0\x80", b"\xed\x9f\xbf", b"\xed\xa0\x80", b"\xef\xbf\xbf",
            b"\xf0\x8f\xbf\xbf", b"\xf0\x90\x80\x80", b"\xf4\x8f\xbf\xbf",
            b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xf8\x88\x80\x80\x80"]
    for i, sequence in enumerate(utf8):
        for cut in range(len(sequence) + 1):
            for suffix in (b"", b"\bX", b"\x1b[31mX", b"\rX\n"):
                add(f"utf8-cut-{i}-{cut}-{suffix.hex()}", "lossy-utf8",
                    stdout=sequence[:cut] + suffix, stderr=sequence[cut:])

    for delta in (-1, 0, 1):
        for status in (0, 7 << 8, 9):
            add(f"limit-single-{delta}-{status}", "size-boundary", wait_value=status,
                stdout=repeat(b"A", LIMIT + delta))
        add(f"limit-both-{delta}", "size-boundary", stdout=repeat(b"A", LIMIT - 11 + delta),
            stderr=b"B")
        add(f"limit-unicode-err-{delta}", "size-boundary",
            stdout=repeat(b"A", LIMIT - 13 + delta), stderr="世")
    add("raw-over-limit-trailing-space", "raw-over-limit-cleaned-small",
        stdout=concat(b"ok", repeat(b" ", LIMIT + 1)))
    add("raw-over-limit-cr-overwrite", "raw-over-limit-cleaned-small",
        stdout=concat(repeat(b"A", LIMIT + 1), b"\rOK"))
    add("raw-over-limit-ansi", "raw-over-limit-cleaned-small",
        stdout=concat(repeat(b"\x1b[31m", 5 * ((LIMIT // 5) + 1)), b"OK"))
    add("raw-over-limit-duplicates", "raw-over-limit-cleaned-small",
        stdout=repeat(b"x\n", 2 * ((LIMIT // 2) + 1)))
    add("raw-over-limit-backspace", "raw-over-limit-cleaned-small",
        stdout=concat(repeat(b"A", LIMIT // 2 + 1), repeat(b"\b", LIMIT // 2 + 1), b"OK"))
    for extra in (0, 1):
        add(f"lossy-expansion-near-limit-{extra}", "size-boundary",
            stdout=repeat(b"\xff", LIMIT // 3 + extra))
    for count in (LIMIT + (1 << 18), LIMIT + 3 * (1 << 18)):
        add(f"megabyte-rounding-{count}", "size-boundary", stdout=repeat(b"A", count))
    for stream in ("wait", "stdout", "stderr"):
        fields = {"wait_value": 7 << 8, "stdout": repeat(b"A", LIMIT + 1),
                  "stderr": repeat(b"B", LIMIT + 1)}
        if stream == "wait":
            fields.update(wait_kind=1, wait_value=0, wait_error="wait-error\x1b[31m")
        else:
            fields.update({stream + "_kind": 1, stream: "read-error\x1b[31m"})
        add("error-before-size-" + stream, "error-before-size", **fields)
    add("long-display-is-not-output-limited", "error-before-size", wait_kind=1,
        wait_error=repeat(b"E", LIMIT + 1))

    commands = ["", "echo ok", "git stash", "git stash push -m 'x'", "git stash save",
                "git stash pop", "git stash apply", "git stash list", "git stash show",
                "false && git stash; echo later", "git stash && run && git stash pop",
                "env X=1 git stash push", "git -C repo stash push", "git -c x=y stash",
                "printf '%s' 'git stash'", "echo $(git stash)", "echo `git stash`",
                "git\tstash\n", "GIT stash", "git stash\x00push", "世; git stash"]
    ids = ["", "job-1", "a/b ?#%", "世\x00界", "../x", "background://shell/x"]
    for ci, command in enumerate(commands):
        for ii, job_id in enumerate(ids):
            for pid in (0, 1, 2147483647, 4294967295):
                add(f"promotion-{ci}-{ii}-{pid}", "promotion", op=2,
                    command=command, id=job_id, pid=pid)

    names = [case["name"] for case in result]
    if len(names) != len(set(names)):
        raise ValueError("duplicate outcome semantic case name")
    return result


def counts(cases=None):
    cases = specifications() if cases is None else cases
    return {"semantic_cases": len(cases),
            "groups": dict(sorted(Counter(case["group"] for case in cases).items())),
            "operations": dict(sorted(Counter(case["fields"].get("op", 1) for case in cases).items()))}
