# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Fresh original-Rust versus native-HIA typed result metadata comparison."""
from contextlib import ExitStack
from pathlib import Path
import argparse
import copy
import ctypes
import gzip
import hashlib
import itertools
import json
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_value_fixture import retained

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
INVALID, CAPACITY, CALL = 0xffffffff, 0xfffffffe, 0xfffffff0
ACTION, SNAPSHOT = 256, 4096
REQUEST, REPLY, WORK = (16 << 20) + 8192, (32 << 20) + 16384, 192 << 20
ID = "io.hepta.runtime/request-v8"
ACK = "io.hepta.runtime/retention-v8"
TOOLS = ("host_list", "host_health", "effective_config", "request_status", "request_result",
         "request_start", "request_cancel", "request_history", "_unknown_tool", "host_list\0", "HOST_LIST", "", "查询")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def request(case, raw):
    tool, identity, state = [case[k].encode() for k in ("tool", "request_id", "state")]
    return b"HRPRQ001" + struct.pack("<11Q", case["op"], case["tag"], len(tool), len(identity),
        len(state), len(raw), case["audit_durable"], case["cancelled"], case["visible"], case["readonly"], 0) + tool + identity + state + raw


def case(label, body, tag=1, op=1, tool="host_list", **fields):
    return dict(label=label, tag=tag, op=op, tool=tool, body=copy.deepcopy(body), request_id="a1" * 32,
        state="stored", audit_durable=True, cancelled=False, visible=True, readonly=True, **fields)


class Bridge:
    def __init__(self, owner, value, typed, exceptions):
        self.owner, self.value, self.typed, self.exceptions = owner, value, typed, exceptions
        self.entries = self.calls = self.value_calls = self.typed_calls = 0

    def read(self, offset, size):
        return ctypes.string_at(ctypes.addressof(self.owner._workspace) + offset, size)

    def write(self, offset, value):
        ctypes.memmove(ctypes.addressof(self.owner._workspace) + offset, value, len(value))

    def word(self, offset, value=None):
        cell = ctypes.c_uint64.from_address(ctypes.addressof(self.owner._workspace) + offset)
        if value is None:
            return cell.value
        cell.value = value

    def invoke(self, session, wire):
        try:
            raw = session.invoke(wire)
            return len(raw), raw
        except self.exceptions as error:
            return error.code, b""

    def enter(self, wire):
        self.entries += 1
        return self.invoke(self.owner, wire)

    def complete(self):
        fields = struct.unpack("<8s11Q", self.read(ACTION, 96))
        magic, seq, child, reserved, start, size, output, capacity, ack, code, zero, zero2 = fields
        assert magic == b"HRPRA001" and seq > 0 and child in (1, 2)
        assert reserved == ack == code == zero == zero2 == 0
        assert start == REQUEST and output == REPLY and capacity == 64 << 20
        assert 24 < size <= (16 << 20) + 24
        wire = self.read(start, size)
        assert wire[:8] == (b"HSJVAL01" if child == 1 else b"HRTYP001")
        assert struct.unpack_from("<2Q", wire, 8) == (1, size - 24)
        self.calls += 1
        if child == 1:
            self.value_calls += 1
        else:
            self.typed_calls += 1
        result, reply = self.invoke(self.value if child == 1 else self.typed, wire)
        self.write(REPLY, reply)
        self.word(ACTION + 64, seq)
        self.word(ACTION + 72, result)
        return dict(sequence=seq, child=child, input_bytes=len(wire), input_sha256=SHA(wire), output_bytes=len(reply),
                    output_sha256=SHA(reply), child_code=result)

    def run(self, wire):
        code, raw = self.enter(wire)
        children = []
        while code == CALL:
            assert len(children) < 2
            children.append(self.complete())
            code, raw = self.enter(wire)
        return code, raw, children


def decode(raw):
    assert len(raw) >= 64 and raw[:8] == b"HRPRS001"
    tag, size, eligible, expose, completion, retain, refused = struct.unpack_from("<7Q", raw, 8)
    assert 1 <= tag <= 3 and size == len(raw) - 64 and eligible <= 1 and expose <= 1 and retain <= 1 and refused <= 1
    assert completion in (1, 2, 3)
    return dict(tag=tag, eligible=bool(eligible), expose=bool(expose), completion=completion,
                retention_candidate=bool(retain), budget_refused=bool(refused), output_body=raw[64:].decode())


def body_cases():
    texts = ["", "plain", 'quote" slash\\ line\n tab\t nul\0 é汉😀', "\u2028\u2029"]
    for text in texts:
        for error in (None, False, True):
            body = {"content": [{"type": "text", "text": text}]}
            if error is not None:
                body["isError"] = error
            yield "text", 1, body
    yield "empty", 1, {"content": []}
    for structured in (None, False, 0, -0.0, "str", [], {"a": [1, "x"], "b": None}):
        yield "structured", 1, {"content": [], "structuredContent": structured}
    yield "image", 1, {"content": [{"type": "image", "data": "YWJj", "mimeType": "image/png"}]}
    yield "audio", 1, {"content": [{"type": "audio", "data": "YWJj", "mimeType": "audio/wav"}]}
    yield "resource", 1, {"content": [{"type": "resource", "resource": {"uri": "https://example.test/x", "text": "保留"}}]}
    values = [None, False, 0, -0.0, "", "prior\n汉", [], {"request_id": "prior", "nested": [None, True, {"x": "y"}]}]
    extras = {"\0": 0, '"': 1, "\\": 2, "io.hepta.runtime/request-v7": 7,
              "io.hepta.runtime/request-v9": 9, "io.hepta.runtime/retention-v9": 10, "z": 11, "汉": 12}
    for index, value in enumerate(values):
        for meta in ({ID: value}, {ACK: value}, {**extras, ID: value, ACK: value}, {}):
            yield f"complete-meta-{index}", 1, {"content": [{"type": "text", "text": "body"}], "_meta": meta}
            yield f"error-meta-{index}", 2, {"code": -32603, "message": "error\n汉", "data": meta}
        yield f"error-scalar-{index}", 2, {"code": -32602, "message": "error", "data": value}
    yield "error-absent", 2, {"code": -32603, "message": "error"}
    yield "task", 3, {"resultType": "task", "taskId": "task-1", "status": "working", "createdAt": "2026-11-05T00:00:00Z", "lastUpdatedAt": "2026-11-05T00:00:00Z", "ttlMs": None}


def cases():
    bodies = list(body_cases())
    for index, (label, tag, body) in enumerate(bodies):
        for op in (1, 2, 3, 4):
            yield case(f"typed-{index}-{label}-{op}", body, tag, op, TOOLS[index % len(TOOLS)])
    for tool, (cancelled, visible, readonly), error in itertools.product(TOOLS, itertools.product((False, True), repeat=3), (None, False, True)):
        body = {"content": [{"type": "text", "text": "outcome"}]}
        if error is not None:
            body["isError"] = error
        row = case("complete-decisions", body, op=4, tool=tool)
        row.update(cancelled=cancelled, visible=visible, readonly=readonly)
        yield row
    for tool, tag, flags in itertools.product(TOOLS, (2, 3), itertools.product((False, True), repeat=3)):
        body = {"code": -32603, "message": "failure"} if tag == 2 else bodies[-1][2]
        row = case("other-decisions", body, tag=tag, op=4, tool=tool)
        row.update(zip(("cancelled", "visible", "readonly"), flags, strict=True))
        yield row
    for value in ("", "bad-id", "A" * 64, "a" * 63, "f" * 65, "汉😀", "".join(chr(i) for i in range(32)), '"\\', "x" * 8192):
        for op, tag in itertools.product((1, 3), (1, 2)):
            row = case("string-escaping", {"content": []} if tag == 1 else {"code": -1, "message": "x"}, tag, op)
            row.update(request_id=value, state=value, audit_durable=bool(len(value) % 2))
            yield row
    rng = random.Random(0x52534c54)
    keys = ["io.hepta.runtime/request-v8", "io.hepta.runtime/retention-v8", "a", "z", "\0", "\\", "汉", "io.hepta.runtime/request-v8x"]
    for ordinal in range(256):
        meta = {key: rng.choice([None, bool(ordinal % 2), ordinal, "x\n汉", [ordinal, None], {"kept": ordinal}]) for key in keys if rng.randrange(2)}
        tag = rng.choice((1, 2))
        body = {"content": [{"type": "text", "text": str(ordinal)}], "_meta": meta} if tag == 1 else {"code": -32603, "message": str(ordinal), "data": meta}
        yield case(f"random-metadata-{ordinal}", body, tag, rng.choice((1, 2, 3, 4)), rng.choice(TOOLS))


def oracle_rows(rows, output, name):
    wire = b"".join(encoded(row) + b"\n" for row in rows)
    stdout, receipt = retained("request", "probes" if name == "original-budget-probes" else "cases",
        wire, output / name)
    results = [json.loads(line) for line in stdout.splitlines()]
    assert len(results) == len(rows)
    return results, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "value-manifest", "typed-manifest", "runtime", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(args.runtime.resolve(strict=True) / "scripts"))
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    started = time.monotonic()
    report = dict(schema="hepta.request-result.actual-comparison.v1", status="FAIL", cases=[], controls=[],
        retained_reference_inputs=[], whole_runtime_replaced=False, production_activated=False, old_stack_removal_qualified=False,
        audit_storage_qualified=False, result_storage_qualified=False, typed_canonical_private_profile=True)
    save = lambda: (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    save()
    try:
        probes = []
        for meta in ({}, {ID: None, ACK: {"before": [1, 2, 3]}}):
            row = case("exact-budget-overhead", {"content": [{"type": "text", "text": ""}], "_meta": meta}, op=3)
            row.update(state="durability_unknown_not_dispatched", audit_durable=False)
            probes.append(row)
        blocks = [dict(type="text", text="annotated"),
            dict(type="image", data="AA==", mimeType="image/png"),
            dict(type="audio", data="AA==", mimeType="audio/wav"),
            dict(type="resource", resource=dict(uri="urn:text", text="text")),
            dict(type="resource", resource=dict(uri="urn:blob", blob="AA==")),
            dict(type="resource_link", uri="urn:link", name="link")]
        for priority, block in itertools.product((0.1, 0.33333334, 1e-20, 1.4e-45, 1e20, -0.0, -0.1), blocks):
            block = copy.deepcopy(block)
            block["annotations"] = dict(priority=priority, audience=["user", "assistant"])
            row = case("typed-f32-budget-overhead", dict(content=[dict(type="text", text=""), block],
                _meta={"arbitrary_value_numbers": [0.1, -0.0, 1e-20]}), op=3)
            row.update(state="durability_unknown_not_dispatched", audit_durable=False)
            probes.append(row)
        probe_results, receipt = oracle_rows(probes, args.output, "original-budget-probes")
        report["retained_reference_inputs"].append(receipt)
        rows = list(cases())
        for index, (probe, expected) in enumerate(zip(probes, probe_results, strict=True)):
            overhead = expected["output_typed_bytes"]
            for tool in ("effective_config", "request_status", "request_result", "request_start", "request_cancel"):
                cap = 262144 if tool == "effective_config" else 65536
                for delta in ((-3, -2, -1, 0, 1, 2, 3) if index < 2 else (-1, 0, 1)):
                    body = copy.deepcopy(probe["body"])
                    body["content"][0]["text"] = "x" * (cap - overhead + delta)
                    rows.append(case(f"exact-budget-{index}-{tool}-{delta}", body, op=2, tool=tool))
        for tool in TOOLS:
            rows.append(case("unlimited-actual-metadata", {"content": [{"type": "text", "text": "x" * 300000}]}, op=2, tool=tool))
            rows.append(case("error-budget-exempt", {"code": -32603, "message": "x" * 300000}, tag=2, op=2, tool=tool))
        observations, receipt = oracle_rows(rows, args.output, "original-cases")
        report["retained_reference_inputs"].append(receipt)
        with ExitStack() as stack:
            owner = stack.enter_context(NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())))
            value = stack.enter_context(NativeModule(args.value_manifest, manifest_sha256=SHA(args.value_manifest.read_bytes())))
            typed = stack.enter_context(NativeModule(args.typed_manifest, manifest_sha256=SHA(args.typed_manifest.read_bytes())))
            report["modules"] = dict(owner=owner.metadata, value=value.metadata, typed=typed.metadata)
            session = stack.enter_context(owner.session(output_capacity=64 << 20, workspace_capacity=WORK))
            child = stack.enter_context(value.session(output_capacity=64 << 20, workspace_capacity=256 << 20))
            serializer = stack.enter_context(typed.session(output_capacity=64 << 20, workspace_capacity=96 << 20))
            bridge = Bridge(session, child, serializer, (NativeRejected, NativeCapacityError))
            with gzip.open(args.output / "native-results.bin.gz", "wb", compresslevel=6) as retained:
                for ordinal, (row, observed) in enumerate(zip(rows, observations, strict=True)):
                    wire = request(row, observed["input_body"].encode())
                    code, raw, child_receipt = bridge.run(wire)
                    assert code == len(raw) and code < 0xffff0000, (ordinal, row["label"], code)
                    actual = decode(raw)
                    expected = {k: v for k, v in observed.items() if k not in ("input_body", "output_typed_bytes")}
                    assert actual == expected, (ordinal, row["label"], actual, expected)
                    retained.write(struct.pack("<Q", len(raw)) + raw)
                    report["cases"].append(dict(ordinal=ordinal, label=row["label"], input_sha256=SHA(wire), input_bytes=len(wire),
                        output_sha256=SHA(raw), output_bytes=len(raw), original_body_sha256=SHA(observed["output_body"].encode()),
                        original_typed_body_bytes=observed["output_typed_bytes"], child=child_receipt))
            baseline = case("control", {"content": []})
            canonical = encoded({"content": []})
            wire = request(baseline, canonical)
            controls = [("short", b"", INVALID), ("magic", b"????????" + wire[8:], INVALID),
                ("reserved", wire[:88] + struct.pack("<Q", 1) + wire[96:], INVALID),
                ("trailing", wire + b"x", INVALID), ("invalid-json", request(baseline, b"{"), INVALID),
                ("noncanonical", request(baseline, b'{ "content": [] }'), INVALID),
                ("duplicate-key", request(baseline, b'{"content":[],"content":[]}'), INVALID),
                ("nonobject-complete", request(baseline, b"[]"), INVALID),
                ("depth", request(baseline, b"[" * 128 + b"0" + b"]" * 128), INVALID)]
            for label, raw_input, expected in controls:
                ctypes.memset(ctypes.addressof(session._workspace), 0, 512)
                before = bytes(session._output)
                code, raw, child_receipt = bridge.run(raw_input)
                assert code == expected and raw == b"" and bytes(session._output) == before, (label, code)
                report["controls"].append(dict(label=label, actual_code=code, output_unchanged=True, child=child_receipt))
            # An over-profile wire is refused by the loader before native entry.
            before = bytes(session._output)
            try:
                session.invoke(wire + b" " * (16 << 20))
            except ValueError as error:
                assert str(error) == "native input exceeds its declared byte profile"
            else:
                raise AssertionError("input profile was not enforced")
            assert bytes(session._output) == before
            report["controls"].append(dict(label="loader-input-profile", native_executed=False, output_unchanged=True))
            for label, capacity, workspace in (("native-short-workspace", 64, WORK - 8), ("native-short-output", 63, WORK)):
                with owner.session(output_capacity=capacity, workspace_capacity=workspace) as short:
                    before = bytes(short._output)[:capacity]
                    code, raw = bridge.invoke(short, wire)
                    assert code == CAPACITY and raw == b"" and bytes(short._output)[:capacity] == before, (label, code)
                    bridge.entries += 1
                    report["controls"].append(dict(label=label, actual_code=code, native_executed=True, output_unchanged=True))
            for start in (96, 96 + len(baseline["tool"])):
                ctypes.memset(ctypes.addressof(session._workspace), 0, 512)
                changed = bytearray(wire)
                changed[start] = 255
                before = bytes(session._output)
                code, raw = bridge.enter(bytes(changed))
                assert code == INVALID and raw == b"" and bytes(session._output) == before
                report["controls"].append(dict(label="invalid-utf8-prefix", offset=start, actual_code=code, output_unchanged=True))
            for offset in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88):
                ctypes.memset(ctypes.addressof(session._workspace), 0, 512)
                assert bridge.enter(wire)[0] == CALL
                bridge.complete()
                bridge.word(ACTION + offset, bridge.word(ACTION + offset) ^ 1)
                before = bytes(session._output)
                code, raw = bridge.enter(wire)
                assert code == INVALID and raw == b"" and bytes(session._output) == before, ("receipt", offset, code)
                report["controls"].append(dict(label="changed-receipt", offset=offset, actual_code=code, output_unchanged=True))
            ctypes.memset(ctypes.addressof(session._workspace), 0, 512)
            assert bridge.enter(wire)[0] == CALL
            bridge.complete()
            changed = bytearray(wire)
            changed[96] ^= 1
            code, raw = bridge.enter(bytes(changed))
            assert code == INVALID and raw == b""
            report["controls"].append(dict(label="changed-resume-custody", actual_code=code))
            budget_wire = request(case("budget-control", {"content": []}, op=2, tool="request_status"), canonical)

            def pending(phase):
                ctypes.memset(ctypes.addressof(session._workspace), 0, 512)
                assert bridge.enter(budget_wire)[0] == CALL
                if phase == 2:
                    assert bridge.complete()["child"] == 1
                    assert bridge.enter(budget_wire)[0] == CALL
                assert bridge.complete()["child"] == phase

            for offset in (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 88):
                pending(2)
                bridge.word(ACTION + offset, bridge.word(ACTION + offset) ^ 1)
                before = bytes(session._output)
                code, raw = bridge.enter(budget_wire)
                assert code == INVALID and raw == b"" and bytes(session._output) == before
                report["controls"].append(dict(label="changed-typed-receipt", offset=offset, actual_code=code, output_unchanged=True))
            for phase, offset in itertools.product((1, 2), (0, 8, 16, 24)):
                pending(phase)
                old = bridge.read(REQUEST + offset, 1)
                bridge.write(REQUEST + offset, bytes([old[0] ^ 1]))
                before = bytes(session._output)
                code, raw = bridge.enter(budget_wire)
                assert code == INVALID and raw == b"" and bytes(session._output) == before
                report["controls"].append(dict(label="changed-child-request", child=phase, offset=offset,
                    actual_code=code, output_unchanged=True))
            pending(2)
            changed = bytearray(budget_wire)
            changed[96] ^= 1
            before = bytes(session._output)
            code, raw = bridge.enter(bytes(changed))
            assert code == INVALID and raw == b"" and bytes(session._output) == before
            report["controls"].append(dict(label="changed-typed-input-custody", actual_code=code, output_unchanged=True))
            for failure in (INVALID, CAPACITY):
                pending(2)
                bridge.word(ACTION + 72, failure)
                before = bytes(session._output)
                code, raw = bridge.enter(budget_wire)
                assert code == failure and raw == b"" and bytes(session._output) == before and bridge.word(8) == 0
                report["controls"].append(dict(label="typed-child-status-propagation", child_status=failure,
                    actual_code=code, output_unchanged=True, original_budget_error_not_synthesized=True))
            pending(2)
            bridge.write(REPLY, b"x")
            bridge.word(ACTION + 72, 1)
            before = bytes(session._output)
            code, raw = bridge.enter(budget_wire)
            assert code == INVALID and raw == b"" and bytes(session._output) == before
            report["controls"].append(dict(label="malformed-typed-reply", actual_code=code, output_unchanged=True))
            report.update(native_entries=bridge.entries, actual_value_child_calls=bridge.value_calls,
                actual_typed_child_calls=bridge.typed_calls, actual_child_calls=bridge.calls)
        assert len(rows) == 1926 and len(probes) == 44 and len(report["controls"]) == 49
        report.update(status="PASS", compared_cases=len(rows), original_probe_cases=len(probes),
            actual_original_cases=0, retained_original_cases=len(rows) + len(probes), output_bytes_equal=True, controls_passed=len(report["controls"]),
            elapsed_seconds=time.monotonic() - started)
    finally:
        save()
    print(json.dumps({**{key: report[key] for key in ("schema", "status", "compared_cases", "original_probe_cases", "actual_original_cases", "native_entries", "actual_value_child_calls", "actual_typed_child_calls", "actual_child_calls", "controls_passed", "output_bytes_equal", "elapsed_seconds")}, "report_sha256": SHA((args.output / "result.json").read_bytes())}))


if __name__ == "__main__":
    main()
