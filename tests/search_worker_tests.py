#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Adversarial real native worker checks using private disposable file trees."""
import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKER = ROOT / "src/mcp/runtime/search_worker.py"
if not WORKER.exists():
    WORKER = pathlib.Path(__file__).with_name("search_worker.py")
spec = importlib.util.spec_from_file_location("search_worker", WORKER)
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class SearchWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-search-worker-")
        self.base = pathlib.Path(self.temp.name).resolve()
        self.root = self.base / "root"
        self.root.mkdir()
        self.state = self.base / "state"
        self.identity = "1" * 64
        self.owner = "2" * 64

    def tearDown(self):
        self.temp.cleanup()

    def request(self, action, **extra):
        value = {"action": action, "search_id": self.identity, "owner": self.owner,
                 "state_dir": str(self.state)}
        value.update(extra)
        return value

    def rpc(self, action, expect=True, **extra):
        output = subprocess.run([sys.executable, str(WORKER)], input=json.dumps(self.request(action, **extra)),
                                text=True, capture_output=True, timeout=8)
        if expect:
            self.assertEqual(output.returncode, 0, output.stderr)
            return json.loads(output.stdout)
        self.assertNotEqual(output.returncode, 0)
        self.assertEqual(json.loads(output.stderr), {"error": "native search request refused"})
        self.assertNotIn(str(self.root), output.stderr)
        return output

    def start(self, **extra):
        value = {"root": str(self.root), "allowed_roots": [str(self.root)], "query": "needle",
                 "kind": "content", "include_hidden": False,
                 "limits": {"results": 1000, "entries": 10000, "bytes": 64 * 1024 * 1024, "seconds": 10}}
        value.update(extra)
        return self.rpc("start", **value)

    def terminal(self):
        for _ in range(200):
            value = self.rpc("results", cursor=0, limit=32)
            if value["state"] in worker.TERMINAL:
                return value
            time.sleep(0.01)
        self.fail("search did not terminate")

    def direct_search(self):
        directory = pathlib.Path(tempfile.mkdtemp(dir=self.base, prefix="direct-"))
        fd = worker.open_dir(str(directory))
        try:
            request = self.request("start", root=str(self.root), allowed_roots=[str(self.root)], query="needle",
                                   kind="content", limits={"results": 100, "entries": 100, "bytes": 64*1024*1024, "seconds": 10})
            worker.search(fd, request, {"owner": self.owner, "state": "running", "deadline": time.time()+10})
            return worker.snapshot(fd, worker.read_json(fd, "record.json"), 0, 32)
        finally:
            os.close(fd)

    def test_native_content_path_utf8_binary_and_no_symlink_or_hardlink_escape(self):
        (self.root / "alpha.txt").write_text("needle 中文\nother\nneedle two\n")
        (self.root / ".hidden").write_text("needle hidden")
        (self.root / "binary").write_bytes(b"needle\0binary")
        outside = self.base / "outside"
        outside.write_text("needle secret")
        (self.root / "link").symlink_to(outside)
        os.link(outside, self.root / "hardlink")
        os.mkfifo(self.root / "fifo")
        self.start()
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual([row["line"] for row in value["results"]], [1, 3])
        self.assertEqual(value["statistics"]["skipped_symlinks"], 1)
        self.assertEqual(value["statistics"]["skipped_hardlinks"], 1)
        self.assertEqual(value["statistics"]["skipped_binary_or_non_utf8"], 1)
        self.assertEqual(value["statistics"]["skipped_special"], 1)
        self.assertFalse(value["statistics"]["coverage_complete"])
        self.assertEqual(value["statistics"]["coverage_reasons"], ["unsupported_binary_or_non_utf8"])
        (self.root / "alpha.txt").write_text("different")
        self.assertEqual(self.rpc("results", cursor=0, limit=32), value)
        self.identity = "3" * 64
        self.start(kind="files", query="alpha")
        self.assertEqual(self.terminal()["results"], [{"path": "alpha.txt"}])

    def test_cursors_independent_terminal_snapshot_repeat_and_resource_limit(self):
        (self.root / "match.txt").write_text("needle\n" * 40)
        self.start(limits={"results": 40, "entries": 100, "bytes": 10000, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["state"], "limited")
        self.assertEqual(value["reason"], "result_limit")
        one = self.rpc("results", cursor=0, limit=7)
        two = self.rpc("results", cursor=7, limit=7)
        self.assertEqual(one["next_cursor"], 7)
        self.assertEqual(two["results"][0]["line"], 8)
        self.assertEqual(self.rpc("results", cursor=0, limit=7), one)
        self.rpc("results", expect=False, cursor=41, limit=7)

    def test_owner_denial_and_stop_cannot_cancel_someone_elses_job(self):
        (self.root / "input").write_text("needle")
        self.start()
        original = self.owner
        self.owner = "9" * 64
        self.rpc("results", expect=False)
        self.rpc("stop", expect=False)
        self.assertFalse((self.state / "search" / self.identity / "cancel").exists())
        self.owner = original
        self.assertEqual(self.terminal()["state"], "completed")

    def test_cooperative_cancellation_retains_stable_partial_snapshot(self):
        # Cancellation is deterministically exercised before scanning, without introducing a fake sleep option.
        request = self.request("start", root=str(self.root), allowed_roots=[str(self.root)], query="needle",
                               kind="content", include_hidden=False,
                               limits={"results": 1000, "entries": 10000, "bytes": 64*1024*1024, "seconds": 10})
        directory = self.base / "direct"
        directory.mkdir(mode=0o700)
        fd = worker.open_dir(str(directory))
        try:
            (directory / "cancel").write_text("")
            record = {"owner": self.owner, "state": "running", "deadline": time.time()+10}
            worker.search(fd, request, record)
            value = worker.read_json(fd, "record.json")
            self.assertEqual(value["state"], "cancelled")
            self.assertTrue(value["snapshot_ready"])
            self.assertEqual(worker.snapshot(fd, value, 0, 32)["results"], [])
        finally:
            os.close(fd)

    def test_root_authorization_symlink_state_and_interrupted_deadline(self):
        self.rpc("start", expect=False, root=str(self.base), allowed_roots=[str(self.root)], query="x",
                 kind="files", limits={"results": 10, "entries": 100, "bytes": 1000, "seconds": 1})
        link = self.base / "root-link"
        link.symlink_to(self.root)
        self.start(root=str(link), allowed_roots=[str(self.base)])
        self.assertEqual(self.terminal()["state"], "failed")
        directory = self.state / "search" / self.identity
        fd = worker.open_dir(str(directory))
        try:
            record = {"owner": self.owner, "state": "running", "deadline": time.time()-30}
            worker.write_json(fd, "record.json", record)
            interrupted = worker.reconcile(fd, record)
            self.assertEqual(interrupted["state"], "interrupted")
            self.assertFalse(interrupted["snapshot_ready"])
        finally:
            os.close(fd)

    def test_size_caps_and_entry_byte_limits(self):
        for i in range(4):
            (self.root / f"{i}.txt").write_text("needle" * 100)
        self.start(limits={"results": 100, "entries": 1, "bytes": 10000, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["reason"], "entry_limit")
        self.assertFalse(value["statistics"]["coverage_complete"])
        self.assertFalse(value["statistics"]["traversal_complete"])
        self.assertIn("entry_limit", value["statistics"]["coverage_reasons"])
        self.assertEqual(value["statistics"]["entries"], 1)
        self.identity = "3" * 64
        self.start(limits={"results": 100, "entries": 10, "bytes": 4, "seconds": 10})
        value = self.terminal()
        self.assertEqual(value["reason"], "read_bytes_limit")
        self.assertEqual(value["statistics"]["bytes"], 4)
        self.assertLess(len(json.dumps(value).encode()), 96*1024)

    def test_mac_case_and_unicode_normalization_protected_aliases_fail_closed(self):
        with mock.patch.object(worker.sys,"platform","darwin"):
            self.assertTrue(worker.protected_path("/private/tmp/Root/Secret/file", ["/private/tmp/root/secret"]))
            self.assertTrue(worker.protected_path("/private/tmp/root/Cafe\u0301/file", ["/private/tmp/root/CAFÉ"]))
            self.assertFalse(worker.protected_path("/private/tmp/root/secret-suffix/file", ["/private/tmp/root/secret"]))
        if sys.platform=="darwin":
            (self.root / "Secret").mkdir()
            (self.root / "Secret" / "private").write_text("needle forbidden")
            self.start(protected_roots=[str(self.root / "secret")])
            value=self.terminal()
            self.assertEqual(value["results"],[])
            self.assertEqual(value["statistics"]["skipped_protected"],1)

    def test_explicit_regex_literal_case_context_filters_and_exclusions(self):
        (self.root / "match.TXT").write_text("before\nNEEDLE one\nafter\nlast\n")
        (self.root / "ignored.py").write_text("needle")
        (self.root / "vendor").mkdir()
        (self.root / "vendor" / "match.TXT").write_text("needle secret")
        self.start(query=r"need.e", literal_search=False, ignore_case=True, context_lines=1,
                   file_pattern="*.txt|*.md", exclude_patterns=["vendor"], glob_program={
                       "version": 1, "file_rules": [
                           {"regex": r"(?i)^(?:/?|.*/)[^/]*\.txt$", "include": True, "only_dir": False},
                           {"regex": r"(?i)^(?:/?|.*/)[^/]*\.md$", "include": True, "only_dir": False}],
                       "exclude_rules": [{"regex": r"(?i)^(?:/?|.*/)vendor$", "include": False, "only_dir": False}],
                       "query_rules": None})
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual(len(value["results"]), 1)
        match = value["results"][0]
        self.assertEqual((match["path"], match["line"], match["preview"]), ("match.TXT", 2, "NEEDLE one"))
        self.assertEqual(match["context_before"], [{"line": 1, "text": "before", "truncated": False}])
        self.assertEqual(match["context_after"], [{"line": 3, "text": "after", "truncated": False}])
        self.assertEqual(value["statistics"]["files"], 1)
        self.assertTrue(value["statistics"]["coverage_complete"])
        self.identity = "3" * 64
        self.start(query=r"need.e", ignore_case=True)
        self.assertEqual(self.terminal()["results"], [])

    def test_file_glob_mode_and_explicit_exact_name_early_termination(self):
        (self.root / "One.TXT").write_text("body")
        (self.root / "two.py").write_text("body")
        self.start(kind="files", query="*.txt", query_mode="glob", ignore_case=True, glob_program={
            "version": 1, "file_rules": [], "exclude_rules": [], "query_rules": [
                {"regex": r"(?i)^(?:/?|.*/)[^/]*\.txt$", "include": True, "only_dir": False}]})
        self.assertEqual(self.terminal()["results"], [{"path": "One.TXT"}])
        self.identity = "3" * 64
        self.start(kind="files", query="one.txt", ignore_case=True, early_termination=True)
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual(value["reason"], "exact_filename_match")
        self.assertFalse(value["statistics"]["coverage_complete"])
        self.assertFalse(value["statistics"]["traversal_complete"])

    def test_bad_regex_conflicts_and_unbounded_options_are_refused_before_job_creation(self):
        for extra in ({"query": "[", "query_mode": "regex"},
                      {"query_mode": "regex", "literal_search": True},
                      {"query_mode": "glob"}, {"context_lines": 11},
                      {"context_lines": True}, {"ignore_case": 1},
                      {"file_pattern": "*.txt||*.py"}, {"file_pattern": 3},
                      {"exclude_patterns": ["x"] * 33}, {"exclude_patterns": ["\n"]}):
            with self.subTest(extra=extra):
                request = dict(root=str(self.root), allowed_roots=[str(self.root)], query="needle", kind="content",
                               limits={"results": 100, "entries": 100, "bytes": 10000, "seconds": 10})
                request.update(extra)
                self.rpc("start", expect=False, **request)
                self.assertFalse((self.state / "search" / self.identity).exists())

    def test_compiled_globs_refuse_unknown_versions_bad_byte_regex_and_rule_flags(self):
        base = {"version": 1, "file_rules": [], "exclude_rules": [], "query_rules": None}
        values = [dict(base, version=2), dict(base, version=True), dict(base, file_rules=None)]
        for expression in (r"(?u)^.*$", "non-ascii-中", "["):
            values.append(dict(base, file_rules=[{"regex": expression, "include": True, "only_dir": False}]))
        values.append(dict(base, file_rules=[{"regex": ".*", "include": 1, "only_dir": False}]))
        for program in values:
            with self.subTest(program=program):
                self.rpc("start", expect=False, root=str(self.root), allowed_roots=[str(self.root)],
                         query="needle", kind="content", glob_program=program,
                         limits={"results": 100, "entries": 100, "bytes": 10000, "seconds": 10})
                self.assertFalse((self.state / "search" / self.identity).exists())

    def test_progressive_reader_sees_only_fsynced_committed_prefix_and_immutable_terminal_pages(self):
        (self.root / "input").write_text("needle one\nneedle two\n")
        directory = self.base / "direct"
        directory.mkdir(mode=0o700)
        fd = worker.open_dir(str(directory))
        original = worker.write_json
        observed = []
        def publish(target_fd, name, record):
            original(target_fd, name, record)
            if record.get("state") == "running" and record.get("committed_results"):
                published = worker.read_json(target_fd, name)
                observed.append(worker.snapshot(target_fd, published, 0, 32))
        try:
            request = self.request("start", root=str(self.root), allowed_roots=[str(self.root)], query="needle",
                                   kind="content", limits={"results": 100, "entries": 100, "bytes": 10000, "seconds": 10})
            with mock.patch.object(worker, "write_json", side_effect=publish):
                worker.search(fd, request, {"owner": self.owner, "state": "running", "deadline": time.time()+10})
            self.assertEqual([len(value["results"]) for value in observed], [1, 2])
            self.assertTrue(all(value["progressive"] and not value["snapshot_ready"] for value in observed))
            self.assertEqual(observed[0]["next_cursor"], 1)
            # An uncommitted trailing fragment is never returned, even when it
            # is already visible through the descriptor after a writer crash.
            with (directory / "results.ndjson").open("ab") as output:
                output.write(b'{"path":"uncommitted')
            prefix = dict(state="running", snapshot_ready=False, statistics={"results": 1},
                          committed_results=1, committed_result_bytes=observed[0]["committed_result_bytes"])
            self.assertEqual(worker.snapshot(fd, prefix, 0, 32)["results"], observed[0]["results"])
            terminal = worker.read_json(fd, "record.json")
            one = worker.snapshot(fd, terminal, 0, 1)
            self.assertFalse(one["progressive"])
            self.assertEqual(worker.snapshot(fd, terminal, 0, 1), one)
            self.assertEqual(worker.snapshot(fd, terminal, 1, 1)["results"][0]["line"], 2)
        finally:
            os.close(fd)

    def test_bounded_docx_xlsx_embedded_text_and_invalid_or_unavailable_documents(self):
        def package(name, parts):
            with zipfile.ZipFile(self.root / name, "w", zipfile.ZIP_DEFLATED) as archive:
                for part, content in parts.items():
                    archive.writestr(part, content)
        package("report.docx", {
            "word/document.xml": '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>needle body</w:t></w:r></w:p></w:body></w:document>',
            "word/header1.xml": '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>needle header</w:t></w:r></w:p></w:hdr>',
            # External relationships are never opened or resolved.
            "word/_rels/document.xml.rels": '<Relationships><Relationship Target="https://invalid.example/needle" TargetMode="External"/></Relationships>'})
        package("book.xlsx", {
            "xl/sharedStrings.xml": '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>needle shared</t></si></sst>',
            "xl/worksheets/sheet1.xml": '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>needle inline</t></is></c><c r="C1"><f>needle()</f><v>2</v></c></row></sheetData></worksheet>'})
        package("entity.docx", {"word/document.xml": '<!DOCTYPE x [<!ENTITY e "needle">]><x>&e;</x>'.encode("utf-16")})
        package("bomb.docx", {"word/document.xml": "x" * (worker.DOCUMENT_EXPANSION + 1)})
        (self.root / "broken.docx").write_bytes(b"invalid")
        (self.root / "unavailable.pdf").write_bytes(b"%PDF-1.3\ninvalid")
        self.start()
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual(len(value["results"]), 5)
        matches = {(row["path"], row["preview"]) for row in value["results"]}
        self.assertIn(("report.docx", "needle body"), matches)
        self.assertIn(("report.docx", "needle header"), matches)
        self.assertIn(("book.xlsx", "needle shared"), matches)
        self.assertIn(("book.xlsx", "=needle()"), matches)
        self.assertEqual(value["statistics"]["extracted_documents"], 2)
        self.assertGreaterEqual(value["statistics"]["skipped_document_invalid"], 2)
        self.assertEqual(value["statistics"]["skipped_document_limited"], 1)
        self.assertEqual(value["statistics"]["skipped_document_invalid"] + value["statistics"]["skipped_document_unavailable"] + value["statistics"]["skipped_document_limited"], 4)
        self.assertFalse(value["statistics"]["coverage_complete"])
        self.assertTrue(value["statistics"]["traversal_complete"])
        self.assertIn("document_budget_limit", value["statistics"]["coverage_reasons"])
        self.assertIn("document_decode_failed", value["statistics"]["coverage_reasons"])
        self.assertTrue(all("document" in row for row in value["results"]))

    def test_coverage_reports_size_missing_parser_and_unreadable_without_claiming_full_scan(self):
        (self.root / "large.txt").write_bytes(b"x" * (worker.CAPS["file_bytes"] + 1))
        (self.root / "valid.txt").write_text("needle")
        value = self.direct_search()
        self.assertEqual(value["state"], "completed")
        self.assertEqual(len(value["results"]), 1)
        self.assertFalse(value["statistics"]["coverage_complete"])
        self.assertEqual(value["statistics"]["coverage_reasons"], ["file_size_limit"])
        self.assertTrue(value["statistics"]["traversal_complete"])
        (self.root / "large.txt").unlink()
        (self.root / "missing.pdf").write_bytes(b"%PDF-1.0")
        with mock.patch.object(worker, "document_text", side_effect=ImportError("parser missing")):
            value = self.direct_search()
        self.assertEqual(value["statistics"]["coverage_reasons"], ["document_parser_unavailable"])
        self.assertFalse(value["statistics"]["coverage_complete"])
        (self.root / "missing.pdf").unlink()
        source_open = worker.os.open
        def denied(name, *args, **kwargs):
            if name == "valid.txt":
                raise PermissionError("fixture refusal")
            return source_open(name, *args, **kwargs)
        with mock.patch.object(worker.os, "open", side_effect=denied):
            value = self.direct_search()
        self.assertEqual(value["statistics"]["coverage_reasons"], ["unreadable_or_changed"])
        self.assertFalse(value["statistics"]["coverage_complete"])

    def test_pdf_extraction_with_installed_parser_is_bounded_and_page_located(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            self.skipTest("optional pypdf parser unavailable in this interpreter")
        from pypdf.generic import DecodedStreamObject, DictionaryObject, EncodedStreamObject, NameObject, NumberObject
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=200)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 10 100 Td (needle PDF) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        buffer = io.BytesIO()
        writer.write(buffer)
        texts = list(worker.document_text(buffer.getvalue(), ".pdf", lambda: None))
        self.assertEqual(texts[0][0], {"format": "pdf", "page": 1})
        self.assertIn("needle PDF", texts[0][1])
        (self.root / "report.pdf").write_bytes(buffer.getvalue())
        self.start()
        value = self.terminal()
        self.assertEqual(value["state"], "completed")
        self.assertEqual(value["results"][0]["document"], {"format": "pdf", "page": 1})
        self.assertIn("needle PDF", value["results"][0]["preview"])
        writer.encrypt("private password")
        encrypted = io.BytesIO()
        writer.write(encrypted)
        with self.assertRaises(ValueError):
            list(worker.document_text(encrypted.getvalue(), ".pdf", lambda: None))
        # Reject expansion before allocating the full decompressed stream,
        # and refuse codecs capable of invoking external image helpers.
        from pypdf.errors import LimitReachedError
        def with_content(content):
            document = PdfWriter()
            target = document.add_blank_page(width=300, height=200)
            target[NameObject("/Contents")] = document._add_object(content)
            data = io.BytesIO()
            document.write(data)
            return data.getvalue()
        oversized = DecodedStreamObject()
        oversized.set_data(b" " * (worker.DOCUMENT_EXPANSION + 1))
        with self.assertRaises(LimitReachedError):
            list(worker.document_text(with_content(oversized.flate_encode()), ".pdf", lambda: None))
        external_codec = EncodedStreamObject()
        external_codec._data = b"invalid helper payload"
        external_codec[NameObject("/Filter")] = NameObject("/JBIG2Decode")
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("external helper must not run")):
            with self.assertRaises(ValueError):
                list(worker.document_text(with_content(external_codec), ".pdf", lambda: None))
        predictor = DecodedStreamObject()
        predictor.set_data(b"small")
        predictor = predictor.flate_encode()
        predictor[NameObject("/DecodeParms")] = DictionaryObject({
            NameObject("/Predictor"): NumberObject(12), NameObject("/Columns"): NumberObject(2**30)})
        with self.assertRaises(ValueError):
            list(worker.document_text(with_content(predictor), ".pdf", lambda: None))


if __name__ == "__main__":
    unittest.main()
