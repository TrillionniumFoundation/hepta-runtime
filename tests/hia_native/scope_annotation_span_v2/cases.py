"""Frozen full baseline and source-contract inputs; outputs come from real Rust."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tests"))
import baseline_cases as baseline

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PACK = lambda *values: struct.pack("<" + "Q" * len(values), *values)
encode = baseline.encode


def cases():
    originals = baseline.cases()
    assert len(originals) == 444
    rows = []

    def add(label, raw, auth=False, search=True, operation=2, group="effect", **expected):
        assert isinstance(raw, bytes)
        raw.decode("utf-8")
        rows.append(dict(label=label, raw=raw, authenticated=bool(auth), search=bool(search),
                         operation=operation, group=group, **expected))

    # The entire qualified old semantic corpus is retained, including all
    # 48 complete-wire budget edges, three 8MiB inputs and the numeric array.
    for row in originals:
        expected = {key: value for key, value in row.items() if key.startswith("expected_")}
        add("baseline-" + row["label"], row["raw"], row["authenticated"], row["search"],
            operation=1, group="baseline", **expected)
    # Replay every original search-mode row through the actual effect method.
    # This includes parse/non-object failures and exact budget transitions.
    for row in originals:
        if row["search"]:
            expected = {key: value for key, value in row.items() if key == "expected_wire_bytes"}
            add("effect-baseline-" + row["label"], row["raw"], row["authenticated"],
                group="effect-baseline", expected_kind=0, **expected)

    identity = "0123456789abcdef" * 4
    padding = "x" * 66000
    fixtures = []

    def object_case(label, search, **fields):
        fixtures.append((label, encode(dict(payload=padding, search=search, **fields))))

    object_case("id-valid", {"search_id": identity})
    for label, value in (("short", identity[:-1]), ("long", identity + "0"),
                         ("uppercase", identity.upper()), ("invalid-ascii", "g" + identity[1:]),
                         ("multibyte", "é" * 32), ("empty", ""), ("null", None),
                         ("true", True), ("number", 123), ("array", [identity]),
                         ("object", {"id": identity})):
        object_case("id-" + label, {"search_id": value})
    object_case("id-missing", {"host": "node"})
    for label, search in (("null", None), ("array", []), ("string", "search"), ("number", 0), ("bool", False)):
        object_case("search-" + label, search)
    fixtures.append(("search-missing", encode({"payload": padding})))

    for key, maximum in (("host", 64), ("state", 64), ("reason", 512)):
        for count in (0, maximum - 1, maximum, maximum + 1):
            object_case(f"{key}-ascii-{count}", {"search_id": identity, key: "x" * count})
        for unit, label in (("é", "two-byte"), ("🧪", "four-byte"), ("\0", "escaped-nul")):
            width = len(unit.encode())
            for count in (maximum // width, maximum // width + 1):
                object_case(f"{key}-{label}-{count}", {"search_id": identity, key: unit * count})
        for label, value in (("null", None), ("number", 7), ("bool", True), ("array", []), ("object", {})):
            object_case(f"{key}-type-{label}", {"search_id": identity, key: value})

    for key in ("stop_requested", "already_terminal"):
        for label, value in (("false", False), ("true", True), ("null", None), ("zero", 0),
                             ("one", 1), ("string", "true"), ("array", []), ("object", {})):
            object_case(key + "-" + label, {"search_id": identity}, **{key: value})
    object_case("all-retained-fields", {"search_id": identity, "host": "é" * 32,
                "state": "🧪" * 16, "reason": "\0" * 512}, stop_requested=False, already_terminal=True,
                ownership_scope="old", automatic_retry=True, authenticated_chatgpt_caller_isolation=True,
                recovery="old", scope_annotation_status="old")
    quoted_id = "".join("\\u" + f"{ord(c):04x}" for c in identity)
    fixtures.append(("escaped-id-and-key", b'{"payload":"' + padding.encode()
                     + b'","sear\\u0063h":{"search_\\u0069d":"' + quoted_id.encode() + b'"}}'))
    fixtures.append(("duplicate-id-last-valid", b'{"payload":"' + padding.encode()
                     + b'","search":{"search_id":null,"search_id":"' + identity.encode() + b'"}}'))
    fixtures.append(("duplicate-id-last-invalid", b'{"payload":"' + padding.encode()
                     + b'","search":{"search_id":"' + identity.encode() + b'","search_id":null}}'))
    raw_object = encode({"search": {"search_id": identity, "host": "raw"}, "payload": padding}).decode()
    fixtures.append(("rawvalue-first-object", encode({baseline.RAW: raw_object})))
    fixtures.append(("rawvalue-nonfirst-retained", encode({"a": 0, baseline.RAW: raw_object,
                                                          "search": {"search_id": identity}, "payload": padding})))
    for label, raw in fixtures:
        for auth in (False, True):
            add("effect-" + label + "-" + str(int(auth)), raw, auth,
                group="effect-identity", expected_kind=0, expected_category=3, expected_warning=1)

    size = 9 << 20
    add("wide-whitespace-annotate", b"{}" + b" " * (size - 2), True, operation=1, group="span-wide",
        expected_kind=0, expected_category=0, expected_warning=0)
    add("wide-object-effect-identity", encode({"search": {"search_id": identity, "host": "wide"},
                                               "payload": "x" * size}), True, group="span-wide",
        expected_kind=0, expected_category=3, expected_warning=1, expected_fallback=1)
    add("wide-string-effect-original", b'"' + b"x" * size + b'"', False, group="span-wide",
        expected_kind=0, expected_category=2, expected_warning=1, expected_fallback=2)
    add("wide-error-effect-original", b'{"payload":"' + b"x" * size + b'"} trailing', True,
        group="span-wide", expected_kind=0, expected_category=1, expected_warning=1, expected_fallback=2)

    assert len({row["label"] for row in rows}) == len(rows)
    for index, row in enumerate(rows):
        row.update(index=index, bytes=len(row["raw"]), raw_sha256=SHA(row["raw"]))
    return rows


def frame(row):
    raw = row["raw"]
    return b"HSCANS02" + PACK(row["operation"], int(row["authenticated"]), int(row["search"]), len(raw), 0) + raw


def packet(raw):
    return PACK(len(raw)) + raw


def domain():
    rows = cases()
    digest, size, groups = hashlib.sha256(), 0, {}
    frozen = []
    for row in rows:
        raw = packet(frame(row))
        digest.update(raw)
        size += len(raw)
        groups[row["group"]] = groups.get(row["group"], 0) + 1
        frozen.append({key: value for key, value in row.items() if key != "raw"})
    return dict(schema="hepta.scope-annotation-span.domain.v2", cases=frozen, groups=groups,
                input_bytes=size, input_sha256=digest.hexdigest(), baseline_cases=444,
                output_oracle="unchanged actual target methods with real rmcp 3.9.0 and tracing",
                original_qualified=False)


if __name__ == "__main__":
    value = domain()
    (ROOT / "DOMAIN.json").write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: value[key] for key in ("groups", "input_bytes", "input_sha256", "baseline_cases")}, sort_keys=True))
