#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Compare publisher sanitizers locally; never execute binaries or remote work."""

import ast
import hashlib
import importlib
import io
import json
from pathlib import Path
import sys
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "a25-evidence-tools"))
import build_x230_a26_series_evidence as original
import build_x230_a26_series_evidence_r02 as candidate
import build_x230_a26_series_evidence_tests as fixtures


def corpus():
    identities = [{"pid": 81000 + number, "nonce": "private-nonce-%04d" % number,
                   "hostname": "private-node-%04d" % number, "username": "private-user-%02d" % number}
                  for number in range(32)]
    rows = [{"okay": number % 9 != 0, "tool": "process_status", "host": "mac",
             "request_id": "synthetic-request-%04d" % (number % 64),
             "elapsed_ms": 1.5, "purpose": "complete repeated metadata snapshot",
             "message": "pid 81001 private-nonce-0001 private-node-0001 /home/private-user-01/file",
             "native_error": "capacity unavailable" if number % 9 == 0 else None,
             "argv": ["never disclose this"], "stdin_base64": "eA==", "start_monotonic": number / 3}
            for number in range(800)]
    special = ["81001", "x81001", "81001x", "81001_", "081001", "(81001)",
               "private-nonce-0001/private-node-0001", "a" * 64,
               '  "argv": ["never disclose this"],\n', "report-final-81001-123456.json",
               "203.0.113.44", "2001:db8::1", "person@example.test", "abc-" * 150,
               "é" * 520, " /home/private-user-01/file " * 30]
    return {"synthetic_only": True, "identities": identities, "rows": rows, "special_strings": special}


def run():
    expected_original = "8b87f117e212dbca6558cb22e18b47d8d2fb95725dcf72d6f617c93f01e20642"
    original_raw = Path(original.__file__).read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == expected_original
    for module in (original, candidate):
        ast.parse(Path(module.__file__).read_bytes())
    # The original suite runs unchanged, with its module reference redirected
    # in this test process only. Its source and the original publisher stay intact.
    fixtures.evidence = candidate
    output = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromModule(fixtures)
    suite_result = unittest.TextTestRunner(stream=output, verbosity=1).run(suite)
    assert suite_result.wasSuccessful(), output.getvalue()
    raw = corpus()
    start = time.perf_counter()
    old = original.CompleteSanitizer(raw)
    old_init = time.perf_counter() - start
    start = time.perf_counter()
    old_value = old(raw)
    old_seconds = time.perf_counter() - start
    start = time.perf_counter()
    new = candidate.CompleteSanitizer(raw)
    new_init = time.perf_counter() - start
    start = time.perf_counter()
    new_value = new(raw)
    new_seconds = time.perf_counter() - start
    assert old_value == new_value
    old_canonical = original.canonical(old_value)
    assert old_canonical == candidate.canonical(new_value)
    assert old(raw) == old_value and new(raw) == new_value
    assert new.users == old.users and new.pids == old.pids and new.private_values == old.private_values
    # A repeated call still checks every dictionary key for a collision.
    collision = {"pid": 81000, "81000": 1, "<pid>": 2}
    for cls in (original.CompleteSanitizer, candidate.CompleteSanitizer):
        cleaner = cls(collision)
        for _ in range(2):
            try:
                cleaner(collision)
            except ValueError:
                pass
            else:
                raise AssertionError("sanitized key collision was not refused")
    empty = candidate.CompleteSanitizer({})
    for number in range(9000):
        empty.string("unique-public-string-%05d" % number)
    cache = empty._short_strings.cache_info()
    assert cache.maxsize == cache.currsize == 8192
    misses = cache.misses
    empty.string("a" * 64)
    empty.string("x" * 513)
    assert empty._short_strings.cache_info().misses == misses
    # Existing local diagnostic material is read only and never printed. Both
    # sanitizers must produce the same complete event/log values, including errors.
    prior = HERE.parent / "a25-d4-review/initial.receipt.json"
    historical_checked = False
    if prior.exists():
        actual = json.loads(prior.read_bytes())
        assert original.CompleteSanitizer(actual)(actual) == candidate.CompleteSanitizer(actual)(actual)
        historical_checked = True
    result = {"schema": "hepta-x230-a26-publisher-r02-local-checks/v1",
        "scope": "Only local synthetic/equivalence checks; no actual A26 inputs, binaries, RPCs, SSH or remote work executed.",
        "original_publisher_unchanged": True, "original_sha256": expected_original,
        "candidate_sha256": hashlib.sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
        "candidate_bytes": Path(candidate.__file__).stat().st_size,
        "local_check_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "original_regression_suite_against_r02": {"tests": suite_result.testsRun, "passed": True},
        "synthetic_complete_canonical_output_identical": True,
        "synthetic_output_sha256": hashlib.sha256(old_canonical).hexdigest(),
        "synthetic_output_bytes": len(old_canonical),
        "synthetic_rows": len(raw["rows"]), "synthetic_failed_rows": sum(row["okay"] is False for row in raw["rows"]),
        "discovered_identity_sets_equal": True, "repeated_input_results_identical": True,
        "dictionary_collision_checks_preserved": True,
        "cache_max_entries": cache.maxsize, "cache_observed_entries_after_9000_distinct_strings": cache.currsize,
        "cache_only_non_sha_strings_at_most_512_characters": True,
        "historical_D4_receipt_equivalence_checked": historical_checked,
        "local_synthetic_timing_seconds": {"original_init": old_init, "r02_init": new_init,
            "original_sanitize": old_seconds, "r02_sanitize": new_seconds},
        "timing_scope": "Publisher-only synthetic local timing; not x230, runtime or workload performance evidence.",
        "super_string_purity_review": "Reads fixed users; regex/ipaddress/hash string transforms only. No evidence counters, identity discovery, authorization checks or I/O are skipped by caching.",
        "all_evidence_predicates_and_record_traversals_unchanged": True}
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    run()
