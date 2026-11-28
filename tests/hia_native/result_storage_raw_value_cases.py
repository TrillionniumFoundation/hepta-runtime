# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Additional typed DTO/retention inputs; the complete earlier corpus is separate."""
import copy
import json

from result_safe_dto_cases import body, health
from result_storage_fixture import member, configurations

MARKER = "$serde_json::private::RawValue"
DOMAINS = ("safe_dto", "retention")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def raw_value(text):
    return "{" + json.dumps(MARKER) + ":" + json.dumps(text, ensure_ascii=False) + "}"


def configured_hosts():
    value = configurations("safe_dto")["mixed"]
    assert value == configurations("retention")["mixed"]
    return value


def samples():
    raw, _, _, _ = member("safe_dto", "mixed/original-summaries.stdout.jsonl")
    other, _, _, _ = member("retention", "mixed/original-summaries.stdout.jsonl")
    assert raw == other
    summary, = [json.loads(row) for row in raw.splitlines()]
    values = {name: json.loads(summary[name]["text"]) for name in ("host_list", "effective_config")}
    values["host_health"] = health("a", configured_hosts()["a"]["platform"])
    for tool, value in values.items():
        text = encoded(value)
        variants = [
            ("plain", text, True),
            ("first-key-root", raw_value(text), True),
            ("nested-document", raw_value(raw_value(text)), True),
            ("inner-whitespace", raw_value(" \r\n" + text + "\t"), True),
            ("escaped-marker", raw_value(text).replace("$serde", r"\u0024serde", 1), True),
            ("raw-first-extra", raw_value(text)[:-1] + ',"extra":null}', False),
            ("raw-first-duplicate", raw_value(text)[:-1] + "," + json.dumps(MARKER) + ":null}", False),
        ]
        for index, inner in enumerate(("", "{", "{} trailing", "1e9999", "-1e9999",
                "null", "true", "[]", "0", '"text"', "[" * 128 + "0" + "]" * 128)):
            variants.append(("bad-or-wrong-inner-" + str(index), raw_value(inner), False))
        for index, wrong in enumerate((None, False, 0, [], {})):
            variants.append(("raw-non-string-" + str(index), encoded({MARKER: wrong}), False))
        for field, item in value.items():
            changed = copy.deepcopy(value)
            changed[field] = {MARKER: encoded(item)}
            variants.append(("field-" + field, encoded(changed), True))
        # Parsing must validate the first numeric occurrence before duplicate
        # pruning; the final field value otherwise reproduces the valid object.
        field = next(iter(value))
        duplicates = "{" + json.dumps(field) + ":1e9999," + text[1:]
        variants.append(("overflow-before-duplicate", raw_value(duplicates), False))
        wrong = copy.deepcopy(value); wrong[MARKER] = "{"
        # Explicitly place a normal key first. Its RawValue-named sibling is an
        # ordinary Value string, but the resulting extra field is not a safe DTO.
        key = next(iter(value))
        ordinary_first = "{" + json.dumps(key) + ":" + encoded(value[key])
        ordinary_first += "".join("," + json.dumps(k) + ":" + encoded(v) for k, v in wrong.items() if k != key) + "}"
        variants.append(("non-first-marker", ordinary_first, False))
        if tool == "host_health":
            for number, accepted in (("1.0", True), ("1e0", True), ("-0", True),
                    ("0e999999", True), ("60000", True), ("60001", False),
                    ("-1", False), ("1e9999", False)):
                changed = copy.deepcopy(value)
                changed["ssh_roundtrip_ms"] = {MARKER: number}
                variants.append(("wrapped-number-" + number, encoded(changed), accepted))
        for label, inner, accepted in variants:
            yield {"label": "raw-value/" + tool + "/" + label, "tool": tool,
                "body": body(inner), "expected_acceptance": accepted}


def cases(domain):
    assert domain in DOMAINS
    result = []
    for sample in samples():
        row = {key: copy.deepcopy(sample[key]) for key in ("label", "tool", "body")}
        if domain == "safe_dto":
            row["op"] = "dto"
        else:
            row.update(op="transition", operation=2, accepted=str(1 << 64),
                request_id="a1" * 32, owner="b2" * 32, policy_binding="c3" * 32)
        result.append(row)
    assert len({row["label"] for row in result}) == len(result)
    return result


def inputs(domain):
    return b"".join(encoded(row).encode() + b"\n" for row in cases(domain))


def admit_reference(domain, data):
    rows = cases(domain)
    observations = [json.loads(line) for line in data.splitlines()]
    assert len(observations) == len(rows)
    accepted = refused = 0
    for row, expectation, actual in zip(rows, samples(), observations, strict=True):
        assert actual["label"] == row["label"]
        decision = actual["accepted"] if domain == "safe_dto" else actual["state"] == "stored"
        assert decision == expectation["expected_acceptance"], (domain, row["label"], actual)
        if domain == "retention":
            assert actual["state"] == ("stored" if decision else "not_retained_dto")
        accepted += int(decision)
        refused += int(not decision)
    assert accepted > 0 and refused > 0
    return observations, {"cases": len(rows), "accepted": accepted, "refused": refused}
