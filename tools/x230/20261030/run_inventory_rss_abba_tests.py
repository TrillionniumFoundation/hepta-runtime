#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Parser, fixed-inclusion, provenance and original-child reap regressions.

Only Python fixture children run here. No runtime ELF, Rust, SSH, user receipts,
or complete 128 MiB benchmark fixture is executed or created by these tests.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).absolute().parent
SPEC = importlib.util.spec_from_file_location("inventory_rss_harness", HERE / "run_inventory_rss_abba.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def list_reply(text):
    return {"jsonrpc": "2.0", "id": 2,
            "result": {"content": [{"type": "text", "text": text}], "isError": False}}


def complete_rows():
    rows = []
    counters = {"A": 0, "B": 0}
    fixture = {"records": H.COUNT, "bytes": H.COUNT * H.PRIVATE_ARGUMENT_BYTES + 1024,
               "manifest_sha256": "0" * 64}
    for specification in H.PLAN:
        arm = specification["arm"]
        value = (100 + 20 * counters[arm]) * (1 if arm == "A" else 0.5)
        counters[arm] += 1
        rows.append({**specification, "okay": True, "errors": [], "inputs_unchanged": True,
                     "list_elapsed_ms": value / 10, "fixture_before": copy.deepcopy(fixture),
                     "fixture_after": copy.deepcopy(fixture),
                     "response": {"rows": H.COUNT, "sdk_wire_bytes": 400000,
                                  "budget_check_sdk_wire_bytes": 400000},
                     "shutdown": {"started": True, "reaped": True, "actual_wait4_pid": 1000 + len(rows),
                                  "exit_code": 0, "raw_wait_status": 0, "shutdown_signals": [],
                                  "capture_errors": [], "received_response_ids": [1, 2],
                                  "child_cpu_ms": value / 2, "maxrss_kib": value * 1024}})
    return rows


class InventoryParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = H.expected_text()

    def test_fixture_has_exact_private_payload_unique_id_and_public_timestamp_order(self):
        ids = set()
        for index in range(H.COUNT):
            row = H.public_row(index)
            self.assertEqual(set(row), {"id", "host", "created_unix_ms", "execution_mode", "launch_state"})
            self.assertEqual(row["created_unix_ms"], 1700000000000 + index)
            ids.add(row["id"])
        self.assertEqual(len(ids), 2048)
        for index in (0, 17, H.COUNT - 1):
            record = H.synthetic_record(index)
            self.assertEqual(sum(len(value.encode()) for value in record["args"]), 65536)
            self.assertTrue(record["args"][0].startswith("SYNTHETIC_PRIVATE_ARGUMENT_"))
            self.assertLess(len(H.encoded(record)), 4 * 1024 * 1024)
        self.assertNotIn("SYNTHETIC_PRIVATE_ARGUMENT_", self.expected)

    def test_exact_complete_sdk_response_is_accepted_and_budget_counts_outer_envelope(self):
        receipt = H.validate_list_reply(list_reply(self.expected), self.expected)
        self.assertEqual(receipt["rows"], 2048)
        self.assertEqual(receipt["sdk_wire_bytes"], len(H.encoded(list_reply(self.expected)["result"])))
        self.assertGreater(receipt["sdk_wire_bytes"], receipt["inner_text_bytes"])
        self.assertLess(receipt["sdk_wire_bytes"], 1024 * 1024)

    def test_partial_reordered_extra_private_or_mistyped_rows_are_refused(self):
        original = json.loads(self.expected)
        variants = []
        value = copy.deepcopy(original)
        value["jobs"].pop()
        variants.append(value)
        value = copy.deepcopy(original)
        value["jobs"][0], value["jobs"][1] = value["jobs"][1], value["jobs"][0]
        variants.append(value)
        value = copy.deepcopy(original)
        value["jobs"][0]["args"] = ["private"]
        variants.append(value)
        value = copy.deepcopy(original)
        value["jobs"][0]["created_unix_ms"] = str(value["jobs"][0]["created_unix_ms"])
        variants.append(value)
        value = copy.deepcopy(original)
        value["status_authoritative"] = True
        variants.append(value)
        for value in variants:
            with self.subTest(kind=list(value)):
                with self.assertRaises(RuntimeError):
                    H.validate_list_reply(list_reply(H.encoded(value).decode()), self.expected)

    def test_tool_error_rpc_error_wrong_id_or_extra_sdk_payload_is_refused(self):
        good = list_reply(self.expected)
        variants = []
        value = copy.deepcopy(good)
        value["result"]["isError"] = True
        variants.append(value)
        value = copy.deepcopy(good)
        value["id"] = True
        variants.append(value)
        value = copy.deepcopy(good)
        value["error"] = {"code": -1, "message": "failed"}
        variants.append(value)
        value = copy.deepcopy(good)
        value["result"]["structuredContent"] = {"private": "extra"}
        variants.append(value)
        for value in variants:
            with self.assertRaises(RuntimeError):
                H.validate_list_reply(value, self.expected)

    def test_duplicate_json_members_and_nonfinite_values_are_refused(self):
        for raw in (b'{"id":1,"id":2}', b'{"result":{"total":1,"total":2048}}',
                    b'{"x":NaN}', b'{"x":1e9999}'):
            with self.assertRaises(RuntimeError):
                H.decoded(raw)


class AggregateTests(unittest.TestCase):
    def test_stop_after_the_last_attempt_cannot_publish_a_successful_summary(self):
        rows = complete_rows()
        report = {"complete": True, "attempts": rows, "summary": H.summarize(rows)}
        try:
            H.STOP_SIGNAL = signal.SIGTERM
            H.refuse_stopped_report(report)
        finally:
            H.STOP_SIGNAL = None
        self.assertFalse(report["complete"])
        self.assertNotIn("summary", report)
        self.assertEqual(report["stopped_by_signal"], "SIGTERM")
        self.assertEqual(report["attempts"], rows)

    def test_both_blocks_and_all_original_process_peaks_are_included(self):
        result = H.summarize(complete_rows())
        for metric in ("list_elapsed_ms", "child_cpu_ms", "maxrss_kib"):
            self.assertEqual(result["pooled"]["A"][metric]["count"], 4)
            self.assertEqual(result["pooled"]["B"][metric]["count"], 4)
            self.assertEqual(result["pooled"]["B_vs_A_percent"][metric]["median"], -50)
            for block in result["per_block"]:
                self.assertEqual(block["A"][metric]["count"], 2)
                self.assertEqual(block["B_vs_A_percent"][metric]["mean"], -50)
        self.assertEqual(result["pooled"]["A"]["maxrss_kib"]["minimum"], 100 * 1024)
        self.assertEqual(result["pooled"]["A"]["maxrss_kib"]["maximum"], 160 * 1024)

    def test_missing_reordered_duplicate_failed_and_nonfinite_attempts_are_not_selected_away(self):
        cases = []
        cases.append(complete_rows()[:-1])
        rows = complete_rows()
        rows[0], rows[1] = rows[1], rows[0]
        cases.append(rows)
        rows = complete_rows()
        rows[7] = copy.deepcopy(rows[3])
        cases.append(rows)
        rows = complete_rows()
        rows[2]["okay"] = False
        cases.append(rows)
        rows = complete_rows()
        rows[2]["list_elapsed_ms"] = float("nan")
        cases.append(rows)
        rows = complete_rows()
        rows[2]["shutdown"]["maxrss_kib"] = True
        cases.append(rows)
        for rows in cases:
            with self.assertRaises(RuntimeError):
                H.summarize(rows)

    def test_dirty_shutdown_changed_inputs_partial_or_oversized_output_prevents_summary(self):
        cases = []
        rows = complete_rows()
        rows[1]["shutdown"]["shutdown_signals"] = ["SIGTERM"]
        cases.append(rows)
        rows = complete_rows()
        rows[1]["inputs_unchanged"] = False
        cases.append(rows)
        rows = complete_rows()
        rows[1]["fixture_after"]["records"] -= 1
        cases.append(rows)
        rows = complete_rows()
        rows[1]["response"]["rows"] -= 1
        cases.append(rows)
        rows = complete_rows()
        rows[1]["response"]["sdk_wire_bytes"] = H.WIRE_BUDGET
        cases.append(rows)
        for rows in cases:
            with self.assertRaises(RuntimeError):
                H.summarize(rows)


class ProvenanceTests(unittest.TestCase):
    def test_qualification_uses_tested_map_and_detects_later_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            (source / "src").mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock", "rustfmt.toml", "src/lib.rs"):
                (source / name).write_text("synthetic input\n")
            sources = H.current_sources(source)
            source_map = root / "source-map.json"
            source_map.write_bytes(H.encoded(sources))
            binary = root / "synthetic-header-never-executed"
            binary.write_bytes(b"\x7fELFsynthetic header only; never execute")
            binary.chmod(0o700)
            evidence = root / "isolated-tests"
            evidence.mkdir()
            (evidence / "source-manifest.input").write_bytes(source_map.read_bytes())
            summary = {"schema": "hepta-isolated-libtest/v1", "success": True, "filter": "",
                       "retries": 0, "passed": 1, "failed": 0, "ignored": 0, "selected": 1,
                       "source_manifest_sha256": H.sha(source_map), "source_manifest_path": str(source_map)}
            summary_path = evidence / "summary.json"
            summary_path.write_bytes(H.encoded(summary))
            audit_path = root / "isolated-tests.audit.json"
            audit = {"schema": "hepta-isolated-libtest-audit/v1", "success": True,
                     "expected_filter": "", "errors": [], "auditor_sha256": "0" * 64,
                     "passed": 1, "failed": 0, "ignored": 0, "selected": 1, "executed": 1,
                     "evidence": str(evidence), "input_sha256": {
                         "summary.json": H.sha(summary_path), "source-manifest.input": H.sha(source_map)}}
            audit_path.write_bytes(H.encoded(audit))
            report = {"schema": "hepta-x230-composed-qualification/v1", "qualified": True,
                      "automatic_test_retries": 0,
                      "stages": [{"name": name, "returncode": 0} for name in H.STAGES],
                      "source": str(source), "source_input": {"pre-format": "different"},
                      "source_tested": sources, "source_after": sources,
                      "harness_before": {"audit_isolated_tests.py": "0" * 64},
                      "harness_after": {"audit_isolated_tests.py": "0" * 64},
                      "binaries": {"hepta-runtime": {"path": str(binary), "sha256": H.sha(binary)}}}
            report["stages"][6]["command"] = ["python3", "audit.py", "--evidence", str(evidence),
                                               "--output", str(audit_path)]
            report_path = root / "report.json"
            report_path.write_bytes(H.encoded(report))
            with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbound reopen forbidden")):
                binding = H.qualification_binding(report_path, H.sha(report_path), source_map, H.sha(source_map),
                                                   audit_path, H.sha(audit_path))
            H.verify_binding(binding)
            for field, value in (("success", False), ("expected_filter", "targeted"),
                                 ("executed", 2), ("failed", 1)):
                damaged = {**audit, field: value}
                audit_path.write_bytes(H.encoded(damaged))
                with self.assertRaisesRegex(RuntimeError, "audit"):
                    H.qualification_binding(report_path, H.sha(report_path), source_map, H.sha(source_map),
                                             audit_path, H.sha(audit_path))
            audit_path.write_bytes(H.encoded(audit))
            (source / "src/lib.rs").write_text("changed after qualification\n")
            with self.assertRaises(RuntimeError):
                H.verify_binding(binding)
            report["stages"][6]["returncode"] = 1
            report_path.write_bytes(H.encoded(report))
            with self.assertRaises(RuntimeError):
                H.qualification_binding(report_path, H.sha(report_path), source_map, H.sha(source_map),
                                         audit_path, H.sha(audit_path))

    def test_guarded_read_refuses_same_bytes_path_replacement_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, replacement = root / "original", root / "replacement"
            original.write_bytes(b"identical bytes")
            replacement.write_bytes(b"identical bytes")
            expected = H.sha(original)
            real_open = os.open

            def replaced_after_open(path, flags):
                fd = real_open(path, flags)
                if Path(path) == original:
                    os.replace(replacement, original)
                return fd

            with mock.patch.object(H.os, "open", side_effect=replaced_after_open):
                with self.assertRaisesRegex(RuntimeError, "identity"):
                    H.checked_file(original, expected, capture=True)
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaises(RuntimeError):
                H.checked_file(link, expected, capture=True)


@unittest.skipUnless(sys.platform == "linux", "Linux wait4 fixture")
class OriginalChildTests(unittest.TestCase):
    def child_script(self, root, body):
        path = root / "python-fixture-child"
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)
        return path

    def test_real_python_child_has_one_wait4_reap_without_popen_wait_or_poll(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.child_script(root, '''import json, os, sys
for line in sys.stdin:
    value = json.loads(line)
    if "id" in value:
        os.write(1, (json.dumps({"jsonrpc":"2.0", "id":value["id"], "result":{}})+"\\n").encode())
''')
            controller = H.Controller(root)
            with mock.patch.object(subprocess.Popen, "wait", side_effect=AssertionError("Popen.wait forbidden")), \
                 mock.patch.object(subprocess.Popen, "poll", side_effect=AssertionError("Popen.poll forbidden")), \
                 mock.patch.object(subprocess.Popen, "communicate", side_effect=AssertionError("communicate forbidden")):
                try:
                    controller.start(script, root / "unused-config", root / "ssh", root / "denial")
                    controller.send("initialize", {}, 1)
                    controller.reply(1, 5)
                    controller.send("notifications/initialized", {})
                    controller.send("tools/call", {}, 2)
                    controller.reply(2, 5)
                finally:
                    receipt = controller.close(grace=2, escalation=1)
            self.assertEqual(receipt["exit_code"], 0)
            self.assertEqual(receipt["shutdown_signals"], [])
            self.assertEqual(receipt["capture_errors"], [])
            self.assertEqual(receipt["received_response_ids"], [1, 2])
            self.assertGreater(receipt["maxrss_kib"], 0)
            self.assertIs(controller.close(), receipt)
            with self.assertRaises(ChildProcessError):
                os.wait4(receipt["actual_wait4_pid"], os.WNOHANG)

    def test_stuck_python_child_is_signalled_only_through_original_owner_then_reaped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.child_script(root, '''import json, os, signal, sys
signal.signal(signal.SIGTERM, signal.SIG_IGN)
value = json.loads(sys.stdin.readline())
os.write(1, (json.dumps({"jsonrpc":"2.0", "id":value["id"], "result":{}})+"\\n").encode())
while True:
    signal.pause()
''')
            controller = H.Controller(root)
            try:
                controller.start(script, root / "unused-config", root / "ssh", root / "denial")
                controller.send("initialize", {}, 1)
                controller.reply(1, 5)
            finally:
                receipt = controller.close(grace=0.02, escalation=0.02)
            self.assertEqual(receipt["exit_code"], -signal.SIGKILL)
            self.assertEqual(receipt["shutdown_signals"], ["SIGTERM", "SIGKILL"])
            with self.assertRaises(ChildProcessError):
                os.wait4(receipt["actual_wait4_pid"], os.WNOHANG)

    def test_stop_signal_sets_flag_then_safe_point_closes_and_reaps_python_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.child_script(root, '''import json, os, sys
for line in sys.stdin:
    value = json.loads(line)
    if "id" in value:
        os.write(1, (json.dumps({"jsonrpc":"2.0", "id":value["id"], "result":{}})+"\\n").encode())
''')
            previous = signal.signal(signal.SIGTERM, H.stop_requested)
            controller = H.Controller(root)
            try:
                controller.start(script, root / "unused-config", root / "ssh", root / "denial")
                controller.send("initialize", {}, 1)
                controller.reply(1, 5)
                os.kill(os.getpid(), signal.SIGTERM)
                self.assertEqual(H.STOP_SIGNAL, signal.SIGTERM)
                with self.assertRaisesRegex(RuntimeError, "SIGTERM"):
                    H.check_stop()
            finally:
                receipt = controller.close(grace=2, escalation=1)
                H.STOP_SIGNAL = None
                signal.signal(signal.SIGTERM, previous)
            self.assertTrue(receipt["reaped"])
            self.assertEqual(receipt["exit_code"], 0)
            with self.assertRaises(ChildProcessError):
                os.wait4(receipt["actual_wait4_pid"], os.WNOHANG)

    def test_partial_start_registration_failure_still_closes_all_pipes_and_reaps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = self.child_script(root, "import sys\nfor line in sys.stdin:\n    pass\n")
            controller = H.Controller(root)
            try:
                with mock.patch.object(controller.selector, "register", side_effect=RuntimeError("registration fixture")):
                    with self.assertRaisesRegex(RuntimeError, "registration fixture"):
                        controller.start(script, root / "unused-config", root / "ssh", root / "denial")
            finally:
                receipt = controller.close(grace=2, escalation=1)
            self.assertTrue(receipt["reaped"])
            self.assertEqual(receipt["exit_code"], 0)
            self.assertTrue(all(getattr(controller.child, name).closed for name in ("stdin", "stdout", "stderr")))
            with self.assertRaises(ChildProcessError):
                os.wait4(receipt["actual_wait4_pid"], os.WNOHANG)

    def test_protocol_duplicate_ids_and_unbounded_lines_are_retained_as_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            controller = H.Controller(root)
            controller.outstanding = 1
            message = H.encoded({"jsonrpc": "2.0", "id": 1, "result": {}}) + b"\n"
            controller.consume("stdout", message + message)
            self.assertTrue(controller.errors)
            self.assertEqual(controller.received_ids, [1])
            controller.close()
            self.assertEqual((root / "stdout.raw").read_bytes(), message + message)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            controller = H.Controller(root)
            controller.consume("stdout", b"x" * (H.MAX_LINE + 1))
            controller.consume("stderr", b"x" * (H.MAX_CAPTURE + 32))
            self.assertEqual(len(controller.errors), 2)
            controller.close()
            self.assertEqual((root / "stderr.raw").stat().st_size, H.MAX_CAPTURE)


if __name__ == "__main__":
    unittest.main()
