# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Compare actual HIA binary32 serialization with the locked Rust serializer."""
from pathlib import Path
import argparse
import ctypes
import gzip
import hashlib
import json
import random
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from result_value_fixture import retained

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def cases():
    mantissas = {0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33,
        0x3ffffe, 0x3fffff, 0x400000, 0x400001, 0x7ffffb, 0x7ffffc, 0x7ffffd, 0x7ffffe, 0x7fffff}
    values = {sign | exponent << 23 | mantissa
              for sign in (0, 1 << 31) for exponent in range(256) for mantissa in mantissas}
    for value in range(65536):
        for magnitude in (value, 0x800000 - value):
            values.add(magnitude)
            values.add((1 << 31) | magnitude)
    for exponent in range(-45, 39):
        bits = struct.unpack("<I", struct.pack("<f", 10.0 ** exponent))[0]
        for distance in range(-16, 17):
            if 0 <= bits + distance <= 0x7f800000:
                values.add(bits + distance)
                values.add((bits + distance) | 0x80000000)
    rng = random.Random(0x32464d494a)
    values.update(rng.getrandbits(32) for _ in range(262144))
    result = sorted(values)
    assert len(result) < 1048576
    assert {value >> 23 & 255 for value in result} == set(range(256))
    return result


def process(wire, output):
    return retained("binary32", "main", wire, output / "original")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "bulk-manifest", "runtime", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sys.path.insert(0, str(args.runtime / "scripts"))
    from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError
    values = cases()
    assert len(values) == 541693
    wire = struct.pack("<" + str(len(values)) + "I", *values)
    report = dict(schema="hepta.binary32.actual-comparison.v1", status="FAIL", cases=len(values),
        input_sha256=SHA(wire), input_bytes=len(wire), controls=[], whole_runtime_replaced=False,
        production_activated=False, exhaustive_all_32_bit_patterns=False, actual_original_cases=0)
    save = lambda: (args.output / "result.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    save()
    begin = time.monotonic()
    try:
        expected, receipt = process(wire, args.output)
        report["retained_reference_input"] = receipt
        lines = expected.splitlines()
        assert len(lines) == len(values)
        with NativeModule(args.bulk_manifest, manifest_sha256=SHA(args.bulk_manifest.read_bytes())) as bulk:
            start = time.monotonic()
            actual = bulk.invoke(wire, output_capacity=len(wire) * 5, workspace_capacity=8192)
            report["native_bulk_seconds"] = time.monotonic() - start
            report["bulk_module"] = bulk.metadata
        with gzip.open(args.output / "native.stdout.jsonl.gz", "wb", compresslevel=6) as retained_output:
            retained_output.write(actual)
        if actual != expected:
            actual_lines = actual.splitlines()
            differences = [dict(index=i, bits=hex(bits), native=a.decode(), original=b.decode())
                for i, (bits, a, b) in enumerate(zip(values, actual_lines, lines, strict=True)) if a != b]
            report["difference_count"] = len(differences)
            report["first_differences"] = differences[:100]
            raise AssertionError("actual binary32 serialized bytes differ")
        ordinal = {bits: i for i, bits in enumerate(values)}
        samples = [0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x00800000, 0x3f800000,
            0x7f7fffff, 0xff7fffff, 0x7f800000, 0xff800000, 0x7fffffff, 0xffffffff]
        samples += values[::max(1, len(values) // 1024)]
        with NativeModule(args.manifest, manifest_sha256=SHA(args.manifest.read_bytes())) as owner:
            report["owner_module"] = owner.metadata
            with owner.session(output_capacity=32, workspace_capacity=8192) as session:
                for bits in samples:
                    assert session.invoke(b"HJF32001" + struct.pack("<Q", bits)) == lines[ordinal[bits]]
                for label, raw in (("short", b""), ("magic", b"????????" + b"\0" * 8),
                    ("upper-word", b"HJF32001" + struct.pack("<Q", 1 << 32)),
                    ("trailing", b"HJF32001" + b"\0" * 9)):
                    before = bytes(session._output)[:32]
                    try:
                        session.invoke(raw)
                    except NativeRejected as error:
                        assert error.code == 0xffffffff
                    else:
                        raise AssertionError(label)
                    assert bytes(session._output)[:32] == before
                    report["controls"].append(dict(name=label, code=0xffffffff, output_unchanged=True))
            for label, output_capacity, workspace_capacity in (("short-output", 2, 8192), ("short-workspace", 32, 8191)):
                with owner.session(output_capacity=output_capacity, workspace_capacity=workspace_capacity) as session:
                    ctypes.memset(ctypes.addressof(session._output), 0x6b, output_capacity)
                    before = bytes(session._output)[:output_capacity]
                    try:
                        session.invoke(b"HJF32001" + struct.pack("<Q", 0))
                    except NativeCapacityError as error:
                        assert error.code == 0xfffffffe
                    else:
                        raise AssertionError(label)
                    assert bytes(session._output)[:output_capacity] == before
                    report["controls"].append(dict(name=label, code=0xfffffffe, output_unchanged=True))
        report.update(status="PASS", complete_bytes_equal=True, output_bytes=len(actual), output_sha256=SHA(actual),
            production_entries=len(samples) + 6, bulk_entries=1, controls_passed=len(report["controls"]),
            elapsed_seconds=time.monotonic() - begin)
    finally:
        save()
    print(json.dumps({**{k: report[k] for k in ("schema", "status", "cases", "complete_bytes_equal", "output_bytes",
        "output_sha256", "production_entries", "bulk_entries", "controls_passed", "elapsed_seconds")}, "report_sha256": SHA((args.output / "result.json").read_bytes())}))


if __name__ == "__main__":
    main()
