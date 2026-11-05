#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Verify recorded source, reference agreement and exact numeric budget evidence."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct


def read(path):
    return json.loads(path.read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def flatten(rows):
    return [value for row in rows for value in row]


def exact_square(before, after):
    assert len(before) == len(after)
    return sum((Fraction(b) - Fraction(a)) ** 2 for a, b in zip(before, after))


def check_budget(report, before, after, radius):
    square = exact_square(before, after)
    units = square * (1 << 298)
    assert units.denominator == 1
    assert report["squared_update_units_hex"] == format(units.numerator, "x")
    assert report["squared_update_unit_exponent"] == -298
    assert report["radius_f64_bits"] == format(struct.unpack("<Q", struct.pack("<d", radius))[0], "016x")
    assert report["within_budget"] is (square <= Fraction(radius) ** 2)


def main():
    here = Path(__file__).resolve().parent
    repo = here.parents[2]
    qualification = here / "qualification"
    manifest = read(qualification / "evidence_manifest.json")
    for row in manifest["files"]:
        data = (qualification / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"]
    for row in read(qualification / "source_manifest.json"):
        data = (repo / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and digest(data) == row["sha256"], row["path"]
    local = read(qualification / "local_attempt_1.json")
    rpc = read(qualification / "rpc_attempt_1.json")
    assert local["passed"] and local["completed"] and local["source_unchanged_after_format"]
    assert len(local["commands"]) == 6 and all(c["exit_code"] == 0 and not c["timed_out"] for c in local["commands"])
    assert rpc["passed"] and rpc["completed"] and rpc["failure"] is None
    assert local["binary"]["sha256"] == rpc["binary_sha256"] and rpc["executed_binary_unchanged"]
    assert digest((here / "PROTOCOL.json").read_bytes()) == local["protocol_sha256"]
    assert digest((here / "run_native_qualification.py").read_bytes()) == rpc["driver_sha256"]
    assert digest((here / "mcp_fixture_client.py").read_bytes()) == rpc["helper_sha256"]
    for field, filename in [("references", "reference_cases.json"), ("norms", "norm_cases.json"), ("derived_public", "derived_public_fixture.json")]:
        assert digest((here / "fixtures" / filename).read_bytes()) == rpc["fixture_sha256"][field]

    cases = read(here / "fixtures/reference_cases.json")["cases"]
    for case in cases:
        report = read(qualification / "planners" / (case["name"] + ".json"))["report"]
        params = case["params"]
        expected = flatten(case["reference"]["weights_f64"])
        found = flatten(report["weights_f64"])
        assert len(found) == len(expected)
        assert max(abs(a - b) for a, b in zip(found, expected)) <= 1e-8 * (1 + max(map(abs, expected)))
        before, after = flatten(params["base_weights"]), flatten(report["weights_f32"])
        check_budget(report["f32_update_budget"], before, after, params["max_update_l2_norm"])
        assert report["f32_update_budget"]["within_budget"]
        patched = bytearray(struct.pack("<" + "f" * len(before), *before))
        for edit in report["f32_element_edits"]:
            offset = 4 * edit["index"]
            assert patched[offset:offset + 4] == bytes.fromhex(edit["expected_hex"])
            patched[offset:offset + 4] = bytes.fromhex(edit["replacement_hex"])
        assert bytes(patched) == struct.pack("<" + "f" * len(after), *after)
        assert not report["f32_optimality_certified"]
        assert not report["trust_region"]["f64_global_optimality_certified"]

    reports = {row["case"]: row["report"] for row in read(qualification / "norm_receipts.json")}
    checks = {(row["family"], row["radius_index"]): row for row in rpc["norm_checks"]}
    total = feasible = 0
    for family in read(here / "fixtures/norm_cases.json")["families"]:
        before = [x[0] for x in struct.iter_unpack("<f", bytes.fromhex(family["before_f32_hex"]))]
        after = [x[0] for x in struct.iter_unpack("<f", bytes.fromhex(family["after_f32_hex"]))]
        for index, radius in enumerate(family["radii"]):
            total += 1
            within = exact_square(before, after) <= Fraction(radius["radius"]) ** 2
            assert within is radius["within_budget"]
            row = checks[(family["name"], index)]
            assert row["expected_within_budget"] is within and row["source_bytes_unchanged"]
            if within:
                feasible += 1
                report = reports[f"norm:{family['name']}:{index}"]
                check_budget(report["f32_update_budget"], before, after, radius["radius"])
                assert report["f32_update_budget_source_bytes_authenticated"]
                assert report["outcome"] == "rejected_and_restored" and report["gain"] == 0
                assert row["restored_all_bytes"]
            else:
                assert row["outcome"] == "rejected_before_publication_by_exact_budget"
    assert len(cases) == 7 and total == 60 and feasible == len(reports) == 32
    assert len(rpc["negative_controls"]) == 4 and all(row["rejected"] for row in rpc["negative_controls"])
    print(json.dumps({"source_files": 10, "plan_cases": len(cases), "exact_norm_checks": total,
                      "feasible_norm_receipts": feasible, "passed": True,
                      "scope": "Evidence consistency; fresh MCP replay remains a separate command."}))


if __name__ == "__main__":
    main()
