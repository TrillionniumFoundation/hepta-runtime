# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual typed SDK serialization against the native Complete/ErrorData owner."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import random
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_value_cases import cases as sdk_cases
from result_value_fixture import retained

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ENCODE = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def cases():
    values = [row for row in sdk_cases() if row["variant"] not in ("task", "input_required")]
    assert len(values) == 119
    bits = {sign | exponent << 23 | mantissa for sign in (0, 1 << 31) for exponent in range(256)
            for mantissa in (0, 1, 0x3fffff, 0x400000, 0x7ffffe, 0x7fffff)}
    rng = random.Random(0x5459504544)
    bits.update(rng.getrandbits(32) for _ in range(2048))
    blocks = [dict(type="text", text="text"), dict(type="image", data="AA==", mimeType="image/png"),
        dict(type="audio", data="AA==", mimeType="audio/wav"),
        dict(type="resource", resource=dict(uri="urn:text", text="text")),
        dict(type="resource", resource=dict(uri="urn:blob", blob="AA==")),
        dict(type="resource_link", uri="urn:resource", name="resource")]
    for index, value in enumerate(sorted(bits)):
        values.append(dict(variant="priority_bits", bits=value, label="priority-" + hex(value),
            body=dict(content=[blocks[index % len(blocks)]], _meta={"generic": [0.1, -0.0, None]})))
    for depth in (1, 32, 127, 256):
        for variant in ("deep_meta", "deep_structured"):
            values.append(dict(variant=variant, depth=depth, label=variant + "-" + str(depth), body={}))
    return values


def oracle_rows(args, rows, name):
    wire = b"".join(ENCODE(row) + b"\n" for row in rows)
    stdout, receipt = retained("typed", "probes" if name == "probes" else "cases", wire, args.output / name)
    result = [json.loads(line) for line in stdout.splitlines()]
    assert len(result) == len(rows)
    return result, receipt


def wire(tag, body):
    return b"HRTYP001" + struct.pack("<2Q", tag, len(body)) + body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "runtime", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(args.runtime / "scripts"))
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    report = dict(schema="hepta.typed-json.actual-comparison.v1", status="FAIL", cases=[], controls=[],
        retained_reference_inputs=[], trusted_typed_canonical_projection_required=True,
        noncomplete_serialization_qualified=False, production_activated=False, whole_runtime_replaced=False)
    save = lambda: (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    save()
    start = time.monotonic()
    try:
        probes = [dict(variant="text", label="text-overhead", body=dict(text="", error=False)),
                  dict(variant="error", label="error-overhead", body=dict(code=-32603, message=""))]
        observed, receipt = oracle_rows(args, probes, "probes")
        report["retained_reference_inputs"].append(receipt)
        rows = cases()
        for before, after in zip(probes, observed, strict=True):
            size = (8 << 20) - len(after["body"].encode())
            row = json.loads(json.dumps(before))
            row["body"]["text" if row["variant"] == "text" else "message"] = "x" * size
            row["label"] = "complete-eight-mib-" + row["variant"]
            rows.append(row)
        observations, receipt = oracle_rows(args, rows, "original")
        report["retained_reference_inputs"].append(receipt)
        with NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())) as module:
            report["module"] = module.metadata
            with module.session(output_capacity=16 << 20, workspace_capacity=96 << 20) as session:
                with gzip.open(args.output / "native-results.bin.gz", "wb", compresslevel=6) as retained:
                    for index, (row, observed) in enumerate(zip(rows, observations, strict=True)):
                        body = observed["body"].encode()
                        framed = wire(observed["tag"], body)
                        actual = session.invoke(framed)
                        expected = observed["typed_bytes"].encode()
                        assert actual == expected, (index, row["label"], actual[:300], expected[:300])
                        retained.write(struct.pack("<Q", len(actual)) + actual)
                        report["cases"].append(dict(index=index, label=row["label"], input_bytes=len(framed),
                            input_sha256=SHA(framed), output_bytes=len(actual), output_sha256=SHA(actual)))
                malformed = [("short", b"", 0xffffffff), ("magic", b"?" * 24, 0xffffffff),
                    ("unsupported-tag", wire(3, b"{}"), 0xffffffff),
                    ("missing-content", wire(1, b"{}"), 0xffffffff),
                    ("unknown-field", wire(1, b'{"content":[],"unknown":0}'), 0xffffffff),
                    ("content-kind", wire(1, b'{"content":true}'), 0xffffffff),
                    ("content-tag", wire(1, b'{"content":[{"type":"tool_use"}]}'), 0xffffffff),
                    ("bad-utf8", wire(1, b'{"content":[],"_meta":{"x":"\xff"}}'), 0xffffffff),
                    ("unwidened-priority", wire(1, ENCODE(dict(content=[dict(type="text", text="", annotations=dict(priority=0.1))]))), 0xffffffff),
                    ("priority-string", wire(1, ENCODE(dict(content=[dict(type="text", text="", annotations=dict(priority="x"))]))), 0xffffffff),
                    ("nullable-map", wire(1, b'{"_meta":null,"content":[]}'), 0xffffffff),
                    ("body-capacity", wire(1, b"x" * ((8 << 20) + 1)), 0xfffffffe)]
                for label, framed, expected in malformed:
                    before = bytes(session._output)[:session.output_capacity]
                    try:
                        session.invoke(framed)
                    except (NativeRejected, NativeCapacityError) as error:
                        assert error.code == expected, (label, error.code)
                    else:
                        raise AssertionError(label)
                    assert bytes(session._output)[:session.output_capacity] == before
                    report["controls"].append(dict(label=label, code=expected, output_unchanged=True))
            for label, output, work in (("short-output", 2, 96 << 20), ("short-workspace", 64, (96 << 20) - 8)):
                with module.session(output_capacity=output, workspace_capacity=work) as session:
                    ctypes.memset(ctypes.addressof(session._output), 0x6b, output)
                    before = bytes(session._output)[:output]
                    try:
                        session.invoke(wire(1, b'{"content":[]}'))
                    except NativeCapacityError as error:
                        assert error.code == 0xfffffffe
                    else:
                        raise AssertionError(label)
                    assert bytes(session._output)[:output] == before
                    report["controls"].append(dict(label=label, code=0xfffffffe, output_unchanged=True))
        assert len(rows) == 5249 and len(report["controls"]) == 14
        assert all(row["input_bytes"] == (8 << 20) + 24 for row in report["cases"][-2:])
        report.update(status="PASS", compared_cases=len(rows), original_probe_cases=2,
            actual_original_cases=0, retained_original_cases=len(rows) + 2, controls_passed=len(report["controls"]), complete_bytes_equal=True,
            elapsed_seconds=time.monotonic() - start)
    finally:
        save()
    print(json.dumps({**{k: report[k] for k in ("schema", "status", "compared_cases", "actual_original_cases",
        "controls_passed", "complete_bytes_equal", "elapsed_seconds")}, "report_sha256": SHA((args.output / "result.json").read_bytes())}))


if __name__ == "__main__":
    main()
