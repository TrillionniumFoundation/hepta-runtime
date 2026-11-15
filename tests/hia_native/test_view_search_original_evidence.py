"""Small rejection controls over admitted actual search reference artifacts.

This suite executes no Rust or HIA. It first admits the complete actual Rust and
native byte comparison, then mutates small evidence records in memory or in its
own temporary directory. Control-shaped native records are never reported as
native executions.
"""
from __future__ import annotations

import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


reader = module(ROOT / "scripts/hia_native_view_search_reference.py", "_search_reference_reader_controls")
oracle = ROOT / "tests/hia_native/view_search_oracle"
cases = module(oracle / "cases.py", "_search_reference_control_cases")
replay = module(oracle / "replay_compare.py", "_search_reference_control_replay")
CONTROLS = []
BASELINE = None
CAPTURE = None


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_change(value, path, replacement):
    value = copy.deepcopy(value)
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return value


def flipped(raw):
    assert raw
    return bytes((raw[0] ^ 1,)) + raw[1:]


class SearchOriginalEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global BASELINE, CAPTURE
        original = Path(os.environ["HIA_VIEW_SEARCH_ORIGINAL_OUTPUT"])
        native = Path(os.environ["HIA_VIEW_SEARCH_NATIVE_CORPUS"])
        CAPTURE = Path(os.environ["HIA_VIEW_SEARCH_ORIGINAL_EVIDENCE_CAPTURE_DIR"])
        CAPTURE.mkdir(parents=True, exist_ok=False)
        BASELINE = reader.reference_evidence(ROOT, original, native_corpus=native)
        assert BASELINE["status"] == "COMPLETE_BYTE_PARITY_REQUIRES_NATIVE_ADMISSION"
        (CAPTURE / "baseline.json").write_bytes(reader.canonical(BASELINE))
        cls.original = original
        cls.requests = {row["metadata"]["case_id"]: row for row in cases.iter_cases()
                        if row["metadata"]["case_id"] in (10003, 10053, 10065, 10067)}
        cls.records = {}
        with (original / "original.stdout").open("rb") as stream:
            for row in cases.read_records(stream, cases.OUTPUT_MAGIC):
                cid = row["metadata"]["case_id"]
                if cid in cls.requests:
                    cls.records[cid] = row
        assert set(cls.records) == set(cls.requests)
        for cid in cls.records:
            reader._record(cls.requests[cid]["metadata"], cls.records[cid])
        cls.processes = reader.decode((original / "process-receipts.json").read_bytes())

    def deny(self, name, operation):
        try:
            operation()
        except AssertionError as error:
            CONTROLS.append(dict(group=self._testMethodName, name=name, rejected=True,
                                 error_type=type(error).__name__, message=str(error)))
            return
        self.fail("evidence corruption accepted: " + name)

    def record(self, cid, value):
        return reader._record(self.requests[cid]["metadata"], value)

    def test_01_typed_json(self):
        self.assertEqual(reader.decode(b'{"a":1}'), {"a": 1})
        for name, raw in (("duplicate-key", b'{"a":1,"a":2}'),
                          ("nan-token", b'{"a":NaN}'),
                          ("infinity-token", b'{"a":Infinity}'),
                          ("overflow-float", b'{"a":1e999}')):
            self.deny(name, lambda raw=raw: reader.decode(raw))
        self.deny("boolean-is-not-uint", lambda: reader.uint(True, "case id"))
        self.deny("nested-boolean-is-not-count", lambda: reader.exact(
            {"counts": [False]}, {"counts": [0]}, "typed nested count"))

    def test_02_actual_process_receipts(self):
        actual = self.processes[2]
        verify = lambda row: reader._process(row, "original", actual["command"], actual["cwd"], actual["stdin"])
        verify(actual)
        for field in ("timed_out", "timeout_seconds"):
            row = copy.deepcopy(actual)
            del row[field]
            self.deny("missing-" + field, lambda row=row: verify(row))
        changes = [
            ("spawn-error", ("spawn_error",), "failed to spawn"),
            ("boolean-exit", ("exit_code",), False),
            ("float-deadline", ("timeout_seconds",), 180.0),
            ("zero-elapsed", ("elapsed_seconds",), 0),
            ("different-command", ("command",), actual["command"] + ["extra"]),
            ("malformed-stream-pin", ("stdout", "sha256"), "g" * 64),
        ]
        for name, path, replacement in changes:
            row = copy_change(actual, path, replacement)
            self.deny(name, lambda row=row: verify(row))

    def test_03_artifact_paths(self):
        with tempfile.TemporaryDirectory(prefix="search-reference-paths-") as temporary:
            root = Path(temporary)
            (root / "regular").write_bytes(b"actual")
            (root / "directory").mkdir()
            (root / "directory/file").write_bytes(b"actual")
            (root / "link").symlink_to("regular")
            (root / "linked-directory").symlink_to("directory", target_is_directory=True)
            os.mkfifo(root / "fifo")
            self.assertEqual(reader.inside(root, "regular").read_bytes(), b"actual")
            for name, path in (("parent-traversal", "../regular"),
                               ("absolute-path", str(root / "regular")),
                               ("inward-file-symlink", "link"),
                               ("inward-parent-symlink", "linked-directory/file"),
                               ("directory-artifact", "directory"),
                               ("fifo-artifact", "fifo")):
                self.deny(name, lambda path=path: reader.inside(root, path))

    def test_04_actual_io_and_complete_records(self):
        cid = 10003
        actual = self.records[cid]
        read_at = next(i for i, row in enumerate(actual["metadata"]["events"])
                       if row["kind"] == "io" and row["event"] == "read")
        read_result = actual["metadata"]["events"][read_at]["result"]
        changes = [
            ("boolean-case-id", ("metadata", "case_id"), True),
            ("io-occurrence-gap", ("metadata", "events", read_at, "occurrence"), 2),
            ("raw-snapshot-length", ("metadata", "events", read_at, "result", "bytes"), read_result["bytes"] + 1),
            ("boolean-read-count", ("metadata", "io_counts", "read"), True),
        ]
        for name, path, replacement in changes:
            row = copy_change(actual, path, replacement)
            self.deny(name, lambda row=row: self.record(cid, row))
        row = copy.deepcopy(actual)
        index = row["metadata"]["outcome"]["blob"]
        row["blobs"][index] = flipped(row["blobs"][index])
        self.deny("complete-visible-body-byte", lambda: self.record(cid, row))
        extra = copy.deepcopy(actual)
        extra["blobs"].append(b"unreferenced")
        self.deny("unreferenced-output-blob", lambda: self.record(cid, extra))
        missing = copy.deepcopy(actual)
        del missing["metadata"]["events"][read_at]
        self.deny("missing-actual-read-event", lambda: self.record(cid, missing))
        mutation = copy.deepcopy(self.records[10053])
        index = next(i for i, event in enumerate(mutation["metadata"]["events"])
                     if event["kind"] == "mutation")
        mutation["metadata"]["events"][index]["occurrence"] = 2
        self.deny("mutation-at-wrong-io", lambda: self.record(10053, mutation))

    def test_05_cancel_and_cache(self):
        actual = self.records[10067]
        changes = [
            ("boolean-publication-count", ("metadata", "outcome", "publication_bytes"), False),
            ("missing-cancel-base", ("metadata", "before_cancel"), None),
            ("unexpected-cancel-hint", ("metadata", "before_cancel", "hints"), ["invented"]),
        ]
        for name, path, replacement in changes:
            row = copy_change(actual, path, replacement)
            self.deny(name, lambda row=row: self.record(10067, row))
        changed = copy.deepcopy(actual)
        index = changed["metadata"]["before_cancel"]["blob"]
        changed["blobs"][index] = flipped(changed["blobs"][index])
        self.deny("cancel-base-byte-differs", lambda: self.record(10067, changed))
        cached = copy.deepcopy(self.records[10065])
        index = cached["metadata"]["cache_after"][0]["blob"]
        cached["blobs"][index] = flipped(cached["blobs"][index])
        self.deny("search-mutated-existing-cache", lambda: self.record(10065, cached))
        status = copy_change(self.records[10003], ("metadata", "outcome", "ok"), False)
        self.deny("error-status-below-result-limit", lambda: self.record(10003, status))

    def test_06_complete_byte_comparison(self):
        cid = 10003
        reference, request = self.records[cid], self.requests[cid]
        meta, blobs = reference["metadata"], reference["blobs"]
        with tempfile.TemporaryDirectory(prefix="search-reference-byte-controls-") as temporary:
            root = Path(temporary)
            contents = {}

            def capture(name, raw):
                contents[name] = raw
                (root / name).write_bytes(gzip.compress(raw, mtime=0))
                return name

            native = dict(case_id=cid, cancelled=False, ok=True, after_render_status=0,
                input_path=capture("input.gz", cases.encode_cases([request])),
                body_path=capture("body.gz", blobs[meta["outcome"]["blob"]]),
                after_render_path=capture("base.gz", blobs[meta["rendered"]["blob"]]),
                cache_before=[dict(path_hex=request["metadata"]["path_hex"], present=False, content_path=None)],
                cache_after=[dict(path_hex=request["metadata"]["path_hex"], present=False, content_path=None)], io=[])
            for event in meta["events"]:
                assert event["kind"] == "io"
                item = dict(event=event["event"], occurrence=event["occurrence"],
                            operation=5 if event["event"] == "read" else 1)
                item.update({key: value for key, value in event["result"].items()
                             if key not in ("bytes", "snapshot_blob")})
                if "snapshot_blob" in event["result"]:
                    item["snapshot_path"] = capture("snapshot.gz", blobs[event["result"]["snapshot_blob"]])
                native["io"].append(item)
            replay.compare_case(root, native, reference, request)
            for name in ("input.gz", "body.gz", "base.gz", "snapshot.gz"):
                (root / name).write_bytes(gzip.compress(flipped(contents[name]), mtime=0))
                self.deny("full-byte-" + name, lambda: replay.compare_case(root, native, reference, request))
                (root / name).write_bytes(gzip.compress(contents[name], mtime=0))
            reordered = copy.deepcopy(native)
            reordered["io"][0], reordered["io"][1] = reordered["io"][1], reordered["io"][0]
            self.deny("native-io-order", lambda: replay.compare_case(root, reordered, reference, request))
            typed = copy_change(native, ("ok",), 1)
            self.deny("native-success-not-boolean", lambda: replay.compare_case(root, typed, reference, request))
            reader._native_operation("literal-search", dict(event="read", operation=5))
            reader._native_operation("whole-prime", dict(event="read", operation=2))
            self.deny("search-used-text-read", lambda: reader._native_operation(
                "literal-search", dict(event="read", operation=2)))
            self.deny("whole-prime-used-raw-read", lambda: reader._native_operation(
                "whole-prime", dict(event="read", operation=5)))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SearchOriginalEvidence)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = dict(schema="hepta.runtime.view-search-original-controls.v1",
        status="PASS" if result.wasSuccessful() else "FAIL", groups=result.testsRun,
        controls=len(CONTROLS), rejected=sum(row["rejected"] for row in CONTROLS),
        expected_groups=6, expected_controls=42, actual_hia_calls=0, actual_rust_processes=0,
        control_records_are_execution_claims=False, controls_detail=CONTROLS,
        reader_sha256=digest(ROOT / "scripts/hia_native_view_search_reference.py"),
        test_sha256=digest(Path(__file__)), baseline_sha256=None if BASELINE is None else
        hashlib.sha256(reader.canonical(BASELINE)).hexdigest(),
        whole_view_migrated=False, whole_runtime_replaced=False)
    if result.wasSuccessful():
        assert summary["groups"] == 6 and summary["controls"] == summary["rejected"] == 42
    if CAPTURE is not None:
        (CAPTURE / "result.json").write_bytes(reader.canonical(summary))
    print(json.dumps(summary, sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
