#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Synthetic lossless-package tests; no remote calls or workload execution."""

import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import pack_x230_a26_publication as pack

RECORDED = ("standard_compare", "capacity_compare", "fairness_candidate", "calibration", "soak",
            "completed_recovery", "single_running", "six_running")
NOT_RUN = ("standard_candidate", "capacity_candidate", "fairness_compare")


def compressed(raw):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0, compresslevel=9) as target:
        target.write(raw)
    return stream.getvalue()


def fixture(root):
    source = root / pack.SOURCE_DIRECTORY
    source.mkdir()
    failures = [{"okay": False, "index": index, "native_error": "synthetic retained failure " + "x" * 1200}
                for index in range(64)]
    summary = {"schema": pack.SCHEMA, "candidate_validation_passed": True, "artifact_integrity_passed": True,
        "comparison_valid": False, "performance_adoption": False,
        "original_input_receipts": {str(index): {"bytes": index, "sha256": "a" * 64} for index in range(91)},
        "stages": {}, "public_artifacts": {}, "all_failure_rows": failures,
        "resources": {"errors": ["PermissionError: synthetic one", "PermissionError: synthetic two"], "samples": 42},
        "not_covered": ["power loss", "global optimum"], "method": {"unfiltered": True}}
    series_raw = pack.canonical({"series": {"completed": True, "comparison_valid": False}, "plan": {"synthetic": True}})
    (source / pack.SERIES_NAME).write_bytes(series_raw)
    summary["public_artifacts"][pack.SERIES_NAME] = {"bytes": len(series_raw), "sha256": pack.sha(series_raw)}
    for name in RECORDED:
        row = {"recorded": True, "state": "completed", "raw_passed": name != "capacity_compare",
            "all_failure_rows": failures if name == "capacity_compare" else [],
            "resources": {"errors": ["PermissionError: synthetic retained"]},
            "artifact_receipts": {str(index): {"actual": {"bytes": index, "sha256": "b" * 64}} for index in range(3)}}
        summary["stages"][name] = row
        for suffix in (".complete.sanitized.json.gz", ".report.complete.sanitized.json.gz"):
            raw = pack.canonical({"stage": name, "rows": failures, "synthetic": True})
            zipped = compressed(raw)
            filename = name + suffix
            (source / filename).write_bytes(zipped)
            summary["public_artifacts"][filename] = {"bytes": len(zipped), "sha256": pack.sha(zipped),
                "uncompressed_bytes": len(raw), "uncompressed_sha256": pack.sha(raw)}
    for name in NOT_RUN:
        summary["stages"][name] = {"recorded": False, "state": "not-run", "reason": "predeclared condition"}
    (source / pack.SUMMARY_NAME).write_bytes(pack.canonical(summary))
    return source, summary


class PackageTests(unittest.TestCase):
    def test_exact_reconstruction_all_failures_and_git_blob_receipts(self):
        with tempfile.TemporaryDirectory(prefix="a26-pack-synthetic-") as temporary:
            root = Path(temporary)
            source, original = fixture(root)
            original_bytes = {path.name: path.read_bytes() for path in source.iterdir()}
            manifest, printed = pack.package(root)
            target = root / pack.OUTPUT_DIRECTORY
            self.assertEqual(len(list(target.iterdir())), 20)
            self.assertTrue(manifest["package_complete"])
            self.assertEqual(len(manifest["files"]), 18)
            for record in manifest["files"]:
                data = (target / record["published_name"]).read_bytes()
                raw = original_bytes[record["original_name"]]
                if record["operation"] == "gzip-original-json":
                    self.assertEqual(gzip.decompress(data), raw)
                    self.assertEqual(data[4:8], b"\0" * 4)
                    self.assertEqual(data, compressed(raw))
                else:
                    self.assertEqual(data, raw)
                    declared = original["public_artifacts"][record["original_name"]]
                    self.assertEqual(pack.sha(gzip.decompress(data)), declared["uncompressed_sha256"])
            for record in printed:
                data = (target / record["name"]).read_bytes()
                self.assertEqual(record["bytes"], len(data))
                self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(record["git_blob_sha1"], hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest())
            review = json.loads((target / pack.REVIEW_NAME).read_bytes())
            index = review.pop(pack.REVIEW_KEY)
            expected = copy.deepcopy(original)
            expected.pop("original_input_receipts")
            for stage in expected["stages"].values():
                stage.pop("artifact_receipts", None)
            self.assertEqual(review, expected)
            self.assertEqual(index["removed_receipt_index_entries"], 91 + 8 * 3)
            self.assertEqual(index["complete_summary"]["original_sha256"], pack.sha(original_bytes[pack.SUMMARY_NAME]))
            self.assertEqual(len(review["all_failure_rows"]), 64)
            self.assertEqual(len(review["stages"]["capacity_compare"]["all_failure_rows"]), 64)
            self.assertEqual(len(review["resources"]["errors"]), 2)
            self.assertTrue(manifest["readable_index"]["review_exceeds_64kib"])
            self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, original_bytes)
            package_before = {path.name: path.read_bytes() for path in target.iterdir()}
            with self.assertRaises(ValueError):
                pack.package(root)
            self.assertEqual({path.name: path.read_bytes() for path in target.iterdir()}, package_before)

    def test_changed_original_hash_refuses_before_creating_package(self):
        with tempfile.TemporaryDirectory(prefix="a26-pack-mismatch-") as temporary:
            root = Path(temporary)
            source, original = fixture(root)
            filename = next(name for name in original["public_artifacts"] if name.endswith(".gz"))
            (source / filename).write_bytes((source / filename).read_bytes() + b"changed")
            before = {path.name: path.read_bytes() for path in source.iterdir()}
            with self.assertRaises(ValueError):
                pack.package(root)
            self.assertFalse((root / pack.OUTPUT_DIRECTORY).exists())
            self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)

    def test_wrong_decompressed_receipt_preserves_partial_without_manifest(self):
        with tempfile.TemporaryDirectory(prefix="a26-pack-uncompressed-") as temporary:
            root = Path(temporary)
            source, original = fixture(root)
            filename = next(name for name in original["public_artifacts"] if name.endswith(".gz"))
            original["public_artifacts"][filename]["uncompressed_sha256"] = "0" * 64
            (source / pack.SUMMARY_NAME).write_bytes(pack.canonical(original))
            before = {path.name: path.read_bytes() for path in source.iterdir()}
            with self.assertRaises(ValueError):
                pack.package(root)
            target = root / pack.OUTPUT_DIRECTORY
            self.assertTrue(target.is_dir())
            self.assertTrue(list(target.iterdir()))
            self.assertFalse((target / pack.MANIFEST_NAME).exists())
            with self.assertRaises(ValueError):
                pack.package(root)
            self.assertEqual({path.name: path.read_bytes() for path in source.iterdir()}, before)


if __name__ == "__main__":
    unittest.main()
