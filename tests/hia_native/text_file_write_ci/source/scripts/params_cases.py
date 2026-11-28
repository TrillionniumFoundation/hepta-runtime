#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Input-only current TextFileWriteParams domain; no expected outputs."""
from __future__ import annotations
import copy
import json


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def cases():
    rows = []
    def raw(name, text):
        rows.append(dict(case_id=len(rows), name=name, raw_json=text))
    def add(name, value):
        raw(name, dumps(value))
    base = dict(path="note.txt", mode="create", content="hello\n", expected_sha256="absent")
    for mode in ("create", "replace", "append"):
        value = {**base, "mode": mode, "expected_sha256": "absent" if mode == "create" else "0" * 64}
        add("mode-" + mode, value)
        for text, label in (("", "empty"), ("\r\n", "crlf"), ("λ🙂中", "unicode"),
                            ("\\\"\t\b\f\n\r", "escaped"), ("a\u0000b", "nul"),
                            ("a" * 65535, "limit-minus-one"), ("a" * 65536, "limit"),
                            ("a" * 65537, "limit-plus-one")):
            add(mode + "-content-" + label, {**value, "content": text})
        for path in ("", "relative/note.txt", "/workspace/note.txt", "./note.txt", "a/../b",
                     "ssh://example/note.txt", "λ/🙂.txt", "a\u0000b"):
            add(mode + "-path-" + str(len(rows)), {**value, "path": path})
        for expected in ("", "absent", "0" * 63, "0" * 64, "0" * 65, "A" * 64,
                         "f" * 64, "λ" * 32, "x\u0000y"):
            add(mode + "-expected-" + str(len(rows)), {**value, "expected_sha256": expected})
    values = [None, False, True, 0, -1, 17, 17.0, 1.5, "", [], [1], {}, {"a": 1},
              {"create": None}, {"replace": None}, {"append": None}, {"create": {}},
              {"create": False}, {"create": None, "replace": None}]
    for field in ("path", "mode", "content", "expected_sha256"):
        absent = dict(base); del absent[field]; add("missing-" + field, absent)
        for n, value in enumerate(values):
            add("field-" + field + "-type-" + str(n), {**base, field: value})
    for mask in range(16):
        add("presence-" + str(mask), {key: value for i, (key, value) in enumerate(base.items()) if mask & (1 << i)})
    for mode in ("CREATE", "", "unknown", "Create", "creat", "create\u0000", "λ", "🙂", "a`b"):
        add("unknown-mode-" + str(len(rows)), {**base, "mode": mode})
        add("unknown-mode-map-" + str(len(rows)), {**base, "mode": {mode: None}})
    for field in ("extra", "Path", "_meta", "aaa", "zzz", "λ", "a`b", "a\n\u0000b"):
        add("unknown-field-" + str(len(rows)), {**base, field: None})
        add("unknown-before-missing-" + str(len(rows)), {field: 1})
    for value in [None, False, True, 17, 17.0, "text", [], [base]]:
        add("root-kind-" + str(len(rows)), value)
    for raw_number in ("-0", "-0.0", "1e0", "1e30", "18446744073709551615",
                       "-9223372036854775808", "18446744073709551616", "1.2345678901234567"):
        for field in ("path", "content", "expected_sha256", "mode"):
            fields = [dumps(key) + ":" + (raw_number if key == field else dumps(value)) for key, value in base.items()]
            raw("number-" + field + "-" + raw_number, "{" + ",".join(fields) + "}")
    raw("escaped-keys-values", '{"p\\u0061th":"n\\u006fte","m\\u006fde":"cre\\u0061te","c\\u006fntent":"\\ud83d\\ude42","expected_sha256":"absent"}')
    raw("duplicate-path-last", '{"path":false,"path":"note","mode":"create","content":"x","expected_sha256":"absent"}')
    raw("duplicate-mode-last", '{"path":"note","mode":"unknown","mode":"append","content":"x","expected_sha256":"absent"}')
    raw("whitespace", ' { "path" : "note", "mode" : { "replace" : null }, "content" : "x", "expected_sha256" : "absent" } ')
    for text in ("", "{", "{} trailing", '{"path":}', '{"path":"unterminated}', '{"path":"\\uD800"}', "[1,]"):
        raw("ordinary-json-refusal-" + str(len(rows)), text)
    assert len({row["name"] for row in rows}) == len(rows)
    return rows


def encoded():
    return b"".join((dumps(row) + "\n").encode() for row in cases())


if __name__ == "__main__":
    import sys
    sys.stdout.buffer.write(encoded())
