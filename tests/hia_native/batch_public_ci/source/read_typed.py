"""Read every typed native byte and optionally compare a fresh target replay."""
from pathlib import Path
from collections import Counter
import gzip
import json
import struct

from receipt_support import ROOT, SHA, PIN, require, regular, read_json, exact
from qualify_typed import load_inputs, raw_input, typed_frame, projected, HEADERS, MAGICS, NEEDS, SOURCE_FILES


def word(raw, at):
    return struct.unpack_from("<Q", raw, at)[0]


def response(owner, code, out):
    header = HEADERS[owner]
    require(code == header and len(out) >= header and out[:8] == MAGICS[owner], "typed response header")
    status, needed = word(out, 8), word(out, NEEDS[owner])
    require(status in (0, 1, 2, 3, 4), "typed response status")
    if status in (2, 3, 4):
        expected = bytearray(header)
        expected[:8] = MAGICS[owner]
        struct.pack_into("<Q", expected, 8, status)
        struct.pack_into("<Q", expected, NEEDS[owner], needed)
        require(out[:header] == bytes(expected), "growth header contains partial fields")
        size = header
    elif owner == 1:
        require(status == 0 and needed == 0, "canonical Value status")
        size = 32 + word(out, 16)
    elif owner == 2:
        require(needed == 0 and word(out, 56) == 0, "retained typed reserved fields")
        if status == 0:
            require(word(out, 40) == 0, "retained typed success diagnostic")
            size = 64 + word(out, 16) + word(out, 24)
        else:
            require(out[16:40] == bytes(24), "retained typed error projection")
            size = 64 + word(out, 40)
    else:
        require(needed == 0 and out[88:128] == bytes(40), "carrier reserved fields")
        if status == 0:
            require(word(out, 16) == 1 and word(out, 32) == 1 and out[48:80] == bytes(32),
                    "carrier success fields")
            size = 128 + word(out, 24) + word(out, 40)
        else:
            require(out[16:72] == bytes(56), "carrier error fields")
            size = 128 + word(out, 72)
    require(size <= len(out) and out[size:] == b"\xa5" * (len(out) - size), "complete typed output tail")
    return status, needed, out[:size]


def read(capture, *, original_stdout=None):
    capture = Path(capture)
    report = read_json(capture / "result.json")
    require(report["schema"] == "hepta.runtime.rebuilt-batch-typed-comparison.v1" and report["status"] == "PASS"
            and report["failure"] is None, "typed capture completion")
    require((report["semantic_cases"], report["control_cases"], report["actual_native_calls"], report["complete_record_bytes"])
            == (417, 115, 3143, 720021713), "complete typed domain or physical extent changed")
    require(report["calls_by_owner"] == {"1": 1250, "2": 946, "3": 947}, "typed call attribution")
    for key in ("fresh_current_original_compared", "effects_executed", "public_batch_qualified", "whole_runtime_replaced"):
        require(report[key] is False, "typed producer scope changed")
    require(set(report["source_inputs"]["files"]) == set(SOURCE_FILES), "complete executed typed source closure")
    for name, expected in report["source_inputs"]["files"].items():
        require(PIN(regular(ROOT / name)) == expected, "typed executed source changed: " + name)
    for name, expected in report["artifacts"].items():
        require(PIN(regular(capture / name)) == expected, "typed capture bytes changed: " + name)
    indices = [json.loads(line) for line in regular(capture / "calls.jsonl").splitlines()]
    semantic = [json.loads(line) for line in regular(capture / "semantic.jsonl").splitlines()]
    controls = [json.loads(line) for line in regular(capture / "controls.jsonl").splitlines()]
    cases = [row for row in load_inputs() if row["domain"] == "typed-object"]
    require([(x["case_id"], x["name"], x["domain"]) for x in semantic]
            == [(x["case_id"], x["name"], x["domain"]) for x in cases], "typed source case identity/order")
    require(Counter(row["kind"] for row in controls) == Counter({"invalid-frame": 46, "short-output": 9,
        "output-boundary": 24, "workspace-growth": 24, "dirty-prior-state": 12}), "typed control domain")
    requested = {}
    for row in semantic:
        for owner, key in ((1, "value_calls"), (2, "retained_calls"), (3, "carrier_calls")):
            calls = row[key]
            require(isinstance(calls, list) and calls, "missing actual semantic sequence")
            for number in calls:
                require(number not in requested, "semantic call counted twice")
                requested[number] = (owner, row["case_id"], number == calls[-1])
    by_control = {row["call"]: row for row in controls}
    require(len(by_control) == 115, "duplicate controls")
    previous, finals, observations, control_values = {}, {}, {}, {}
    offset = 0
    with gzip.open(capture / "calls.bin.gz", "rb") as stream:
        for idx in indices:
            header = exact(stream, 64)
            number, owner, cid, code, ilen, ocap, wcap, zero = struct.unpack("<8Q", header)
            require(owner in HEADERS and zero == 0 and number == len(previous) + 1, "typed call ordinal/owner")
            require((number, owner, cid, code, ilen, ocap, wcap) == tuple(idx[k] for k in
                ("call", "owner", "case_id", "return_code", "input_bytes", "output_capacity", "workspace_capacity")),
                "typed call index/header binding")
            extent = 64 + ilen + 2 * ocap + 2 * wcap
            require(extent <= 720021713 - offset and idx["bytes"] == extent and idx["offset"] == offset,
                    "typed call outside complete stream")
            parts = [header, exact(stream, ilen), exact(stream, wcap), exact(stream, ocap),
                     exact(stream, ocap), exact(stream, wcap)]
            wire, before, obefore, out, after = parts[1:]
            digest = __import__("hashlib").sha256()
            for part in parts:
                digest.update(part)
            require(digest.hexdigest() == idx["record_sha256"], "complete physical typed call")
            for key, raw in zip(("input", "before", "output_before", "output", "after"), parts[1:]):
                require(SHA(raw) == idx[key + "_sha256"], "complete typed " + key)
            require(obefore == b"\xa5" * ocap, "typed initial output fill")
            offset += extent
            status = needed = result = None
            if code in (0xffffffff, 0xfffffffe):
                require(number in by_control and out == obefore, "unattributed refusal or output mutation")
                if code == 0xfffffffe:
                    require(after == before, "short output mutated private state")
            else:
                status, needed, result = response(owner, code, out)
                if status == 2:
                    require(needed > wcap, "nonprogressing workspace growth")
                elif status == 3:
                    require(needed > ocap, "nonprogressing output growth")
            if number in requested:
                o, case, terminal = requested[number]
                require((owner, cid, idx["label"]) == (o, case, "semantic"), "semantic attribution")
                require(status in ((0,) if owner == 1 else (0, 1)) if terminal else status in (2, 3),
                        "semantic completion/growth state")
                if terminal:
                    observations.setdefault(cid, {})[owner] = (wire, result)
            if status in (0, 1):
                finals[(owner, SHA(wire))] = result
            if number in by_control:
                control = by_control[number]
                require(owner in (2, 3) and idx["label"] == control["kind"], "private control attribution")
                control_values[number] = (owner, wire, code, status, needed, result, wcap, ocap)
            previous[number] = (owner, cid, SHA(wire), status, needed, wcap, ocap, SHA(after))
        require(stream.read(1) == b"", "unindexed typed stream suffix")
    require(len(previous) == 3143 and offset == 720021713, "typed physical stream incomplete")
    for row in semantic:
        for owner, key in ((1, "value_calls"), (2, "retained_calls"), (3, "carrier_calls")):
            for a, b in zip(row[key], row[key][1:]):
                left, right = previous[a], previous[b]
                require(b == a + 1 and left[:3] == right[:3], "growth changed semantic request")
                require((right[5] == left[4] and right[6] == left[6]) if left[3] == 2
                        else (left[3] == 3 and right[6] == left[4] and right[5] == left[5]), "growth grant differs")
    for row in controls:
        owner, wire, code, status, needed, result, wcap, ocap = control_values[row["call"]]
        kind = row["kind"]
        if kind == "invalid-frame":
            require(code == row["expected_code"] == 0xffffffff, "malformed frame admitted")
        elif kind == "short-output":
            require(code == row["expected_code"] == 0xfffffffe and ocap < HEADERS[owner], "short output admitted")
        else:
            full = finals.get((owner, SHA(wire)))
            require(full is not None and SHA(full) == row["expected_response_sha256"], "control complete baseline")
            if status in (0, 1):
                require(result == full, "capacity/prior state changed typed result")
            if kind == "output-boundary":
                require(status in (0, 1, 3) and row["required_capacity"] == len(full), "output boundary domain")
                if status == 3:
                    require(needed == len(full), "output growth is not exact")
            elif kind == "workspace-growth":
                require(status == 2 and wcap in (0, 1, 32767, 32768), "workspace control domain")
                resumed = row["resume_calls"]
                require(resumed and all(previous[x][0] == owner and previous[x][2] == SHA(wire) for x in resumed)
                        and previous[resumed[-1]][3] in (0, 1), "workspace retry missing or changed")
            else:
                require(kind == "dirty-prior-state" and status in (0, 1) and len(full) == row["expected_response_bytes"],
                        "dirty-state control domain")
    for row, case in zip(semantic, cases):
        seen = observations[row["case_id"]]
        raw = raw_input(case)
        require(seen[1][0] == b"HJSVS002" + struct.pack("<2Q", 1, len(raw)) + raw, "Value consumed other input")
        canonical = seen[1][1][32:]
        require(seen[2][0] == seen[3][0] == typed_frame(canonical), "typed owners bypassed actual Value result")
        require(seen[3][1] == projected(seen[2][1]), "carrier changed complete retained typed semantics")
        require((len(raw), SHA(raw), len(canonical), SHA(canonical), len(seen[2][1]), SHA(seen[2][1]),
                 len(seen[3][1]), SHA(seen[3][1]), word(seen[2][1], 8)) == tuple(row[k] for k in
            ("input_bytes", "input_sha256", "canonical_bytes", "canonical_sha256", "retained_bytes",
             "retained_sha256", "carrier_bytes", "carrier_sha256", "status")), "typed semantic full-byte row")
    result = {"status": "PASS", "typed_cases": 417, "controls": 115, "actual_native_calls": 3143,
        "complete_record_bytes": offset, "current_original_compared": original_stdout is not None,
        "public_batch_qualified": False, "whole_runtime_replaced": False, "reader_process_launches": 0}
    if original_stdout is not None:
        from corpus.batch_params_cases import sdk_cases
        expected = load_inputs() + list(sdk_cases())
        rows = [json.loads(x) for x in original_stdout.splitlines()]
        require(len(rows) == len(expected) == 447 and original_stdout.endswith(b"\n"), "complete original typed rows")
        native = dict(observations)
        by_name, sdk = {}, []
        private = 0
        for row, case in zip(rows, expected):
            require(tuple(row[k] for k in ("case_id", "name", "domain"))
                    == tuple(case[k] for k in ("case_id", "name", "domain")), "original typed source identity")
            value = row["result"]
            if row["domain"] == "actual-sdk":
                sdk.append(row)
                continue
            if row["domain"] == "private-raw-value":
                private += 1
                continue
            seen = native.pop(row["case_id"])
            require(seen[1][1][32:] == value["canonical"].encode(), "actual Rust Value differs")
            if value["ok"] is True:
                path, normalized = value["path"].encode(), value["normalized_json"].encode()
                want = b"HBPRR002" + struct.pack("<7Q", 0, len(path), len(normalized), value["operation_count"], 0, 0, 0) + path + normalized
            else:
                require(value["ok"] is False, "original typed result boolean")
                error = value["error"].encode()
                want = b"HBPRR002" + struct.pack("<7Q", 1, 0, 0, 0, len(error), 0, 0) + error
            require(seen[2][1] == want and seen[3][1] == projected(want), "current original full typed result: " + row["name"])
            by_name[row["name"]] = value
        require(not native and private == 8 and len(sdk) == 22, "missing actual current typed domain")
        for row in sdk:
            wanted, actual = by_name[row["name"].rsplit("-", 1)[0]], row["result"]
            require(actual["outer_entries"] == 1 and actual["actual_parameters_extractor"] is True
                    and actual["actual_method_adapter"] is True and actual["original_batch_handler_executed"] is False
                    and actual["effects_executed"] is False, "actual current SDK fixture boundary")
            seen, reply = actual["handler_observations"], actual["responses"][-1]
            if wanted["ok"]:
                require(len(seen) == 1 and seen[0]["normalized"] == wanted["normalized"]
                        and reply["result"]["isError"] is False
                        and json.loads(reply["result"]["content"][0]["text"]) == seen[0], "actual SDK typed success")
            else:
                require(not seen and reply["error"]["code"] == -32602
                        and reply["error"]["message"] == "failed to deserialize parameters: " + wanted["error"],
                        "actual SDK typed diagnostic/order")
        result.update(actual_current_sdk_cases=22, private_top_level_reference_cases_not_claimed=8)
    return result
