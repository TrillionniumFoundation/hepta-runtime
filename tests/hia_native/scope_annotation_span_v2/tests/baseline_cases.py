"""Deterministic full-function corpus; no retained result is a Python oracle."""
import hashlib
import json
import random
import struct

RAW = "$serde_json::private::RawValue"
KEYS = ("authenticated_chatgpt_caller_isolation", "credential_metadata_resume",
        "cross_session_resume", "metadata_resume_after_restart", "ownership_scope",
        "session_resume_after_restart", "session_scope",
        "unfinished_search_after_controller_restart")


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def budget_base(authenticated, search, text):
    """Construct only a simple corpus fixture to locate exact wire-length edges.

    Every resulting row is compared with the unchanged real Rust method. This
    fixture calculation supplies input lengths, never an admitted output.
    """
    kind = "authenticated_private_operator_credential" if authenticated else "native_mcp_session_only"
    value = {"payload": text, "ownership_scope": kind,
             "authenticated_chatgpt_caller_isolation": False,
             "credential_metadata_resume": authenticated}
    if search:
        value.update(metadata_resume_after_restart=authenticated,
                     session_resume_after_restart=False,
                     unfinished_search_after_controller_restart="interrupted_without_relaunch")
    else:
        value.update(session_scope=kind, cross_session_resume=authenticated)
    annotation = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return len(encode({"resultType": "complete", "content": [{"type": "text", "text": annotation}], "isError": False}))


def cases():
    rows = []

    def add(label, raw, auth=False, search=False, **extra):
        assert isinstance(raw, bytes) and len(raw) <= 8 << 20
        raw.decode("utf-8")
        rows.append(dict(label=label, raw=raw, authenticated=bool(auth), search=bool(search), **extra))

    basic = [
        ("empty", b"{}"), ("whitespace", b" \r\n\t { }\t\r\n "),
        ("null", b"null"), ("true", b"true"), ("false", b"false"),
        ("integer-root", b"42"), ("float-root", b"-0.0"), ("string-root", b'"metadata"'),
        ("array-root", b"[{},null]"),
        ("all-fields", encode({k: [None, "old", {"nested": True}] for k in KEYS})),
        ("unrelated", encode({"z": [1, 2, {"n": None}], "a": "keep"})),
        ("duplicate-injected", b'{"ownership_scope":null,"ownership_scope":{"a":1},"session_scope":[] }'),
        ("escaped-injected", br'{"\u006fwnership_scope":5,"credential_metadata_resum\u0065":6}'),
        ("unicode-values", encode({"payload": "\x00\b\t\n\f\r\"\\/é𐀀\u2028\u2029", "nested": {"雪": "🧪"}})),
        ("all-control-values", encode({"payload": "".join(chr(i) for i in range(32))})),
        ("numeric-bits", b'{"n":[-0,-0.0,0.0,0,18446744073709551615,18446744073709551616,-9223372036854775809,5e-324,2.2250738585072014e-308,1.7976931348623157e308,1e-999,1e20]}'),
        ("invalid-empty", b""), ("invalid-space", b" \n\t"), ("invalid-object", b"{"),
        ("invalid-unclosed", b'{"a":['), ("invalid-trailing", b"{} x"),
        ("invalid-key", b"{1:2}"), ("invalid-colon", b'{"a" 1}'),
        ("invalid-comma", b'{"a":1,}'), ("invalid-duplicate-separator", b'{"a":1,,"b":2}'),
        ("invalid-number", b'{"a":01}'), ("invalid-exponent", b'{"a":1e999}'),
        ("invalid-escape", br'{"a":"\x"}'), ("invalid-surrogate", br'{"a":"\ud800"}'),
        ("invalid-lone-low", br'{"a":"\udc00"}'), ("invalid-control", b'{"a":"\x00"}'),
        ("invalid-line", b'{\n "a": [1,\n]}'),
    ]
    for value in (None, False, 4, "per_session", [], [1, 2], {}, {"per_owner": 8},
                  {"per_session": None}, {"per_owner": 9, "per_session": False},
                  {"per_owner": {"old": 1}, "per_session": [1, {"v": -0.0}]},
                  {"a": 1, "per_owne": 2, "per_owner0": 3, "per_session0": 4, "z": 5, "per_session": "limit"}):
        basic.append(("retention-" + str(len(basic)), encode({"retention": value})))
    basic.extend([
        ("retention-duplicate", b'{"retention":{"per_session":1,"per_session":2,"per_owner":9}}'),
        ("retention-escaped", br'{"retention":{"per_\u0073ession":null,"per_owner":9,"\u0000":1,"\u96ea":2}}'),
        ("retention-root-duplicate", b'{"retention":{"per_session":2},"retention":null}'),
        ("retention-rawvalue-first", encode({"retention": {RAW: '{"per_session":-0.0,"per_owner":9}'}})),
        ("retention-rawvalue-nonfirst", b'{"retention":{"z":0,"$serde_json::private::RawValue":"7","per_session":null}}'),
        ("rawvalue-first-object", encode({RAW: '{"retention":{"per_session":3},"x":-0.0}'})),
        ("rawvalue-first-nonobject", encode({RAW: '7'})),
        ("rawvalue-first-error", encode({RAW: '{'})),
        ("rawvalue-first-trailing-field", b'{"$serde_json::private::RawValue":"{}","z":1}'),
        ("rawvalue-nonfirst", b'{"a":0,"$serde_json::private::RawValue":"7"}'),
        ("rawvalue-nonfirst-null", b'{"a":0,"$serde_json::private::RawValue":null}'),
        ("rawvalue-escaped-first", br'{"\u0024serde_json::private::RawValue":"{}"}'),
        ("rawvalue-nested-nonfirst", b'{"x":{"a":0,"$serde_json::private::RawValue":"7"}}'),
    ])
    keys = ["", "\x00", "\n", "\"", "\\", "a", "authenticated_chatgpt_caller_isolation0",
            "credential_metadata_resum", "cross_session_resume0", "metadata_resume_after_restart0",
            "ownership_scope0", "retention0", "session_resume_after_restart0", "session_scope0",
            "unfinished_search_after_controller_restart0", "z", "é", "雪", "𐀀", "\uffff", "\U0010ffff"]
    basic.append(("all-key-order", encode({key: {"per_session": key} for key in reversed(keys)})))
    for depth in (1, 16, 64, 124, 125, 126, 127, 128):
        basic.append(("depth-" + str(depth), b'{"payload":' + b"["*depth + b"0" + b"]"*depth + b"}"))
    for label, raw in basic:
        for auth, search in ((False, False), (True, False), (False, True), (True, True)):
            add(label + "-" + str(int(auth)) + str(int(search)), raw, auth, search)
    rng = random.Random(0x53434f5045)
    values = [None, False, True, 0, 1, -1, 0.5, -0.0, "", "\x00é\"", [], {}, [1, None]]
    for index in range(128):
        selected = rng.sample(keys + list(KEYS), rng.randrange(1, 12))
        value = {key: rng.choice(values) for key in selected}
        if index % 3:
            value["retention"] = {key: rng.choice(values) for key in rng.sample(["per_session", "per_owner", "a", "z", "雪"], rng.randrange(6))}
        add("seeded-" + str(index), encode(value), bool(index & 1), bool(index & 2))
    for auth in (False, True):
        for search in (False, True):
            for label, seed in (("ascii", ""), ("quoted", '"\\'*128), ("control", '\x00\n\t'*128), ("unicode", "雪🧪"*128)):
                size = budget_base(auth, search, seed)
                for wanted in (65535, 65536, 65537):
                    text = seed + "x"*(wanted-size)
                    assert budget_base(auth, search, text) == wanted
                    add(f"wire-{wanted}-{label}-{int(auth)}{int(search)}", encode({"payload": text}), auth, search,
                        expected_wire_bytes=wanted, expected_kind=int(wanted > 65536))
    add("eight-mib-whitespace", b"{}" + b" "*((8 << 20)-2), True, True)
    add("eight-mib-string-root", b'"' + b"x"*((8 << 20)-2) + b'"')
    add("eight-mib-object", b'{"payload":"' + b"x"*((8 << 20)-14) + b'"}', True, False,
        expected_kind=1, expected_category=3)
    add("wide-number-array", b'{"payload":[' + b','.join([b'1e15', b'9e9', b'-0', b'5e-324']*8192) + b"]}", False, True,
        expected_kind=1, expected_category=3)
    assert len({r["label"] for r in rows}) == len(rows)
    for index, row in enumerate(rows):
        row["index"] = index
        row["raw_sha256"] = hashlib.sha256(row["raw"]).hexdigest()
    return rows


def input_frame(row):
    raw = row["raw"]
    return b"HSCANQ01" + struct.pack("<5Q", 1, int(row["authenticated"]), int(row["search"]), len(raw), 0) + raw


def packet(raw):
    return struct.pack("<Q", len(raw)) + raw


def observed_frame(response, annotation, wire):
    return b"HSCASR01" + struct.pack("<3Q", len(response), len(annotation), len(wire)) + response + annotation + wire


if __name__ == "__main__":
    rows = cases()
    print(json.dumps(dict(cases=len(rows), input_bytes=sum(len(input_frame(r))+8 for r in rows),
                          input_sha256=hashlib.sha256(b"".join(packet(input_frame(r)) for r in rows)).hexdigest()), sort_keys=True))
