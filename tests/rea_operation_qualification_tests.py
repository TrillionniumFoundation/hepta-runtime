#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Refusal and wire-integrity checks; fake MCPs never qualify an operation."""

from copy import deepcopy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_operation_qualification as q


class OperationQualificationTests(unittest.TestCase):
    def test_actual_operation_entrypoint_reaches_argument_parser(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            q.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--reference-tarball", output.getvalue())

    def test_build_summary_and_pin_are_required_together_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "not-created"
            argv = ["--operation", "inspect_elf_notes", "--repo", "/unused/repo",
                    "--binary", "/unused/native", "--binary-sha256", "0" * 64,
                    "--reference-package", "/unused/package", "--reference-tarball", "/unused/package.tgz",
                    "--node", "/unused/node", "--output-dir", str(output)]
            for extra in (["--build-summary", "/unused/summary.json"],
                          ["--build-summary-sha256", "0" * 64]):
                with self.subTest(extra=extra), mock.patch.object(q, "reference_package") as package, \
                        mock.patch.object(q.subprocess, "run") as process, \
                        self.assertRaisesRegex(q.QualificationError, "must be supplied together"):
                    q.main(argv + extra)
                package.assert_not_called()
                process.assert_not_called()
                self.assertFalse(output.exists())

    def test_duplicate_members_and_nonfinite_numbers_fail_closed(self):
        for raw in (b'{"x":1,"x":2}', b'NaN', b'1e400', b'Infinity', b'-Infinity'):
            with self.subTest(raw=raw), self.assertRaises(q.QualificationError):
                q.parse_json(raw)

    def test_json_equality_distinguishes_every_kind_and_nested_boolean_numbers(self):
        values = [None, False, 0, "0", [], {}]
        for left_index, left in enumerate(values):
            for right_index, right in enumerate(values):
                with self.subTest(left=left, right=right):
                    self.assertEqual(q.json_equal(left, right), left_index == right_index)
        for left, right in ((False, 0), (False, 0.0), (True, 1), (True, 1.0)):
            with self.subTest(left=left, right=right):
                self.assertFalse(q.json_equal({"nested": [{"value": left}]}, {"nested": [{"value": right}]}))
                self.assertFalse(q.json_equal([right], [left]))
        self.assertFalse(q.json_equal({}, {"omitted": None}))
        self.assertFalse(q.json_equal([1, 2], [2, 1]))
        self.assertTrue(q.json_equal({"a": [1, False], "b": None}, {"b": None, "a": [1, False]}))

    def test_numeric_equality_preserves_reviewed_spellings_without_rounding_integers(self):
        for left, right in ((1, 1.0), (1, q.parse_json(b'1e0')), (0, -0.0),
                            (10 ** 400, 10 ** 400), (9007199254740992, 9007199254740992.0)):
            with self.subTest(left=left, right=right):
                self.assertTrue(q.json_equal({"value": left}, {"value": right}))
        self.assertFalse(q.json_equal(9007199254740993, float(9007199254740993)))
        self.assertFalse(q.json_equal(10 ** 400, 10 ** 400 + 1))

    def test_nonfinite_and_non_json_values_cannot_compare_equal(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                self.assertFalse(q.finite_number(value))
                self.assertFalse(q.json_equal(value, value))
                self.assertFalse(q.json_equal({"nested": [value]}, {"nested": [value]}))
        for value in ((1,), {1: "numeric key"}, {True: "boolean key"}, {1}, b"text"):
            with self.subTest(value=value):
                self.assertFalse(q.json_equal(value, value))
        self.assertFalse(q.finite_number(True))
        self.assertFalse(q.finite_number(False))

    def test_raw_request_cannot_replace_numeric_argument_with_boolean(self):
        client = q.Mcp.__new__(q.Mcp)
        client.process, client._log = mock.Mock(), mock.Mock()
        params = {"name": "inspect_elf_notes", "arguments": {"max_entries": 1}}
        raw = b'{"name":"inspect_elf_notes","arguments":{"max_entries":true}}'
        with self.assertRaisesRegex(q.QualificationError, "parsed facts"):
            client.send("tools/call", params, 1, raw)
        client.process.stdin.write.assert_not_called()
        client._log.assert_not_called()
        client.send("tools/call", params, 1, raw.replace(b'true', b'1e0'))
        self.assertIn(b'"max_entries":1e0', client.process.stdin.write.call_args.args[0])

    def test_text_json_key_order_is_not_a_behavior_difference(self):
        left = {"id": 1, "result": {"content": [{"type": "text", "text": '{"b":2,"a":1}'}],
                                   "structuredContent": {"a": 1, "b": 2}, "_meta": q.TARGET_META}}
        right = deepcopy(left)
        right["result"]["content"][0]["text"] = '{ "a" : 1, "b" : 2 }'
        self.assertEqual(q.tool_value(left), q.tool_value(right))

    def test_result_envelope_is_not_removed_from_comparison(self):
        left = {"result": {"content": [{"type": "text", "text": '{"x":1}'}], "structuredContent": {"x": 1}}}
        right = deepcopy(left)
        right["result"]["_meta"] = q.TARGET_META
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))
        right = deepcopy(left)
        right["result"]["isError"] = True
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))

    def test_structured_text_disagreement_is_rejected(self):
        with self.assertRaisesRegex(q.QualificationError, "disagreement"):
            q.tool_value({"result": {"content": [{"type": "text", "text": '{"x":1}'}],
                                     "structuredContent": {"x": 2}}})

    def test_structured_content_cannot_change_boolean_number_types(self):
        for text, structured in ((False, 0), (True, 1), (1, True), (0.0, False)):
            with self.subTest(text=text, structured=structured), \
                    self.assertRaisesRegex(q.QualificationError, "disagreement"):
                q.tool_value({"result": {"content": [{"type": "text", "text": json.dumps({"nested": [text]})}],
                                         "structuredContent": {"nested": [structured]}}})

    def test_complete_result_rejects_numeric_retryable_and_error_flags(self):
        def response(retryable=False, is_error=True):
            return {"result": {"isError": is_error, "content": [{"type": "text", "text": json.dumps(
                {"error": {"code": "invalid_request", "retryable": retryable}})}]}}
        for changed in (response(retryable=0), response(is_error=1)):
            with self.subTest(changed=changed), \
                    self.assertRaisesRegex(q.QualificationError, "full public MCP result differs"):
                q.compare_case({"kind": "error"}, response(), changed)

    def test_evidence_provenance_requires_a_boolean_untrusted_flag(self):
        response = {"result": {"content": [{"type": "text", "text": "{}"}], "structuredContent": {},
                               "_meta": {"provenance": {"untrusted_content": 1, "source": "analysis_target"}}}}
        with self.assertRaisesRegex(q.QualificationError, "target provenance"):
            q.evidence_value(response)

    def test_summary_counts_cannot_be_booleans(self):
        payload = {"kind": "evidence-bundle-summary", "filters": {}, "total_retained_records": 0,
                   "matching_records": 0, "unknown_revisions": 0, "records": []}
        query = {"arguments": {"detail": "summary"}}
        for field in ("total_retained_records", "matching_records", "unknown_revisions"):
            with self.subTest(field=field), self.assertRaisesRegex(q.QualificationError, "summary/filter projection"):
                structured = {"result": {**payload, field: False}}
                response = {"result": {"content": [{"type": "text", "text": json.dumps(structured)}],
                                       "structuredContent": structured, "_meta": q.TARGET_META}}
                q.check_retention_response(query, response, [])

    def test_non_json_text_is_compared_exactly(self):
        left = {"result": {"content": [{"type": "text", "text": 'not JSON'}]}}
        right = {"result": {"content": [{"type": "text", "text": 'different text'}]}}
        self.assertEqual(q.tool_value(left)["content"][0]["text"], "not JSON")
        self.assertNotEqual(q.tool_value(left), q.tool_value(right))

    def test_missing_route_and_full_schema_drift_are_rejected(self):
        rows = [{"name": name, "inputSchema": {"type": "object", "additionalProperties": False},
                 "outputSchema": {"type": "object"}, "annotations": {"readOnlyHint": False}}
                for name in ("inspect_elf_notes", "get_evidence_bundle")]
        native = [{**row, "name": "rea_" + row["name"]} for row in rows]
        self.assertEqual(len(q.compare_registration(rows, native)), 6)
        native[0] = {**native[0], "inputSchema": {"type": "object", "additionalProperties": True}}
        with self.assertRaisesRegex(q.QualificationError, "inputSchema"):
            q.compare_registration(rows, native)
        with self.assertRaisesRegex(q.QualificationError, "missing public MCP"):
            q.compare_registration(rows, native[1:])

    def test_schema_keywords_and_annotations_cannot_change_boolean_number_types(self):
        rows = [{"name": name, "inputSchema": {"type": "object", "additionalProperties": False},
                 "outputSchema": {"type": "object"}, "annotations": {"readOnlyHint": True}}
                for name in ("inspect_elf_notes", "get_evidence_bundle")]
        for field, keyword, replacement in (("inputSchema", "additionalProperties", 0),
                                            ("annotations", "readOnlyHint", 1)):
            native = [{**deepcopy(row), "name": "rea_" + row["name"]} for row in rows]
            native[0][field][keyword] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(q.QualificationError, field):
                q.compare_registration(rows, native)

    def test_elf_fixture_bytes_have_independent_endianness_and_alias_facts(self):
        for bits in (32, 64):
            for order, prefix in (("little", "<"), ("big", ">")):
                raw = q.elf(q.note(order=order), bits=bits, order=order, section=True)
                self.assertEqual(raw[:4], b"\x7fELF")
                self.assertEqual(raw[4], 1 if bits == 32 else 2)
                self.assertEqual(raw[5], 1 if order == "little" else 2)
                if bits == 64:
                    phoff, shoff = struct.unpack_from(prefix + "QQ", raw, 32)
                    offset, size = struct.unpack_from(prefix + "Q16xQ", raw, phoff + 8)
                    section_offset, section_size = struct.unpack_from(prefix + "QQ", raw, shoff + 64 + 24)
                else:
                    phoff, shoff = struct.unpack_from(prefix + "II", raw, 28)
                    offset, size = struct.unpack_from(prefix + "I8xI", raw, phoff + 4)
                    section_offset, section_size = struct.unpack_from(prefix + "II", raw, shoff + 40 + 16)
                self.assertEqual((offset, size), (section_offset, section_size))
                self.assertEqual(struct.unpack_from(prefix + "III", raw, offset), (4, 20, 3))
                self.assertEqual(raw[offset + 12:offset + 16], b"GNU\0")
                self.assertEqual(raw[offset + 16:offset + 36], bytes(range(20)))

    def test_fixture_manifest_contains_contract_boundary_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            fixtures, cases = q.fixture_cases(Path(directory))
            ids = [case["id"] for case in cases]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertTrue({"explicit_defaults", "integer_spelling_1_0", "integer_spelling_1e0",
                             "unknown_key", "max_entries_invalid_0", "aliased_program_section",
                             "entry_budget", "file_budget", "nonzero_tail"} <= set(ids))
            for fixture in fixtures.values():
                self.assertEqual(q.file_hash(fixture["path"]), fixture["sha256"])

    def test_integer_only_evidence_verifier_refuses_float_or_hidden_semantic_change(self):
        value = {key: None for key in ("analysis_profile", "raw_result", "environment", "relationship_coverage")}
        value.update(subject={"digest": {"sha256": "0" * 64}, "format": "elf", "architecture": None,
                              "name": "display", "local_path": "/display"},
                     provider=q.PROVIDER, predicate_type="rea.analysis", operation="inspect_elf_notes",
                     parameters={"max_entries": 32}, normalized_result={"count": 1}, confidence="observed",
                     authority="shipped-artifact", limitations=[], locations=[], evidence_links=[])
        original = q.semantic_evidence_id(value)
        value["subject"]["local_path"] = "/changed-display"
        self.assertEqual(q.semantic_evidence_id(value), original)
        value["normalized_result"]["count"] = 2
        self.assertNotEqual(q.semantic_evidence_id(value), original)
        value["normalized_result"]["count"] = 1.0
        with self.assertRaises(q.QualificationError):
            q.semantic_evidence_id(value)

    def test_package_authentication_checks_all_installed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "package"
            (package / "dist").mkdir(parents=True)
            files = {"package.json": b'{"name":"rea-agents","version":"6.8.0"}',
                     "dist/mcp-catalog-full.json": b'[]', "implementation.js": b'original\n'}
            archive = root / "package.tgz"
            with tarfile.open(archive, "w:gz") as bundle:
                for name, raw in files.items():
                    (package / name).write_bytes(raw)
                    info = tarfile.TarInfo("package/" + name)
                    info.size = len(raw)
                    bundle.addfile(info, io.BytesIO(raw))
            with mock.patch.object(q, "PACKAGE_SHA256", q.file_hash(archive)), mock.patch.object(
                    q, "CATALOG_SHA256", hashlib.sha256(b'[]').hexdigest()):
                self.assertEqual(q.reference_package(package, archive)["file_count"], 3)
                (package / "implementation.js").write_bytes(b'modified\n')
                with self.assertRaisesRegex(q.QualificationError, "differs from the frozen"):
                    q.reference_package(package, archive)

    def test_package_extra_file_and_symlink_are_not_authenticated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "package.tgz"
            package = root / "package"
            package.mkdir()
            with tarfile.open(archive, "w:gz") as bundle:
                raw = b'{}'
                info = tarfile.TarInfo("package/package.json")
                info.size = len(raw)
                bundle.addfile(info, io.BytesIO(raw))
                (package / "package.json").write_bytes(raw)
            with mock.patch.object(q, "PACKAGE_SHA256", q.file_hash(archive)):
                (package / "extra.js").write_bytes(b'not from npm')
                with self.assertRaisesRegex(q.QualificationError, "differs from the frozen"):
                    q.reference_package(package, archive)
                (package / "extra.js").unlink()
                (package / "extra.js").symlink_to(package / "package.json")
                with self.assertRaisesRegex(q.QualificationError, "symlink"):
                    q.reference_package(package, archive)


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "owned pipe-child cleanup requires Linux pidfds")
class McpInitializationCleanupTests(unittest.TestCase):
    """Real private pipe children verify cleanup, never operation qualification."""

    def exercise_failure(self, stage, *, stubborn=False, receipt_failure=False,
                         group_unknown=False, error_type=RuntimeError):
        before_fds = set(os.listdir("/proc/self/fd"))
        failure = error_type("injected " + stage)
        real_popen, real_start = subprocess.Popen, q.threading.Thread.start
        real_identity, real_open = q.process_identity, Path.open
        real_kill, real_killpg = os.kill, os.killpg
        children, identities, pidfds = [], [], []
        real_pidfd_open = os.pidfd_open
        client = q.Mcp.__new__(q.Mcp)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "owner"
            def launch(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                children.append(process)
                identities.append(real_identity(process.pid))
                self.assertEqual(identities[-1]["parent_pid"], os.getpid())
                self.assertEqual(identities[-1]["process_group"], process.pid)
                if stubborn:
                    deadline = time.monotonic() + 3
                    while b"READY\n" not in (output / "stderr.log").read_bytes():
                        if time.monotonic() >= deadline or process.poll() is not None:
                            self.fail("private child did not install its signal handler")
                        time.sleep(0.005)
                return process
            def open_pidfd(pid):
                if stage == "pidfd-open":
                    raise failure
                fd = real_pidfd_open(pid)
                pidfds.append(fd)
                return fd
            def start_reader(reader):
                if stage == "reader-start-before":
                    raise failure
                real_start(reader)
                if stage == "reader-start-after":
                    raise failure
            def open_file(path, *args, **kwargs):
                if receipt_failure and path.name == "initialization-failure.json":
                    raise OSError("injected diagnostic disk failure")
                return real_open(path, *args, **kwargs)
            child = ("import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                     "print('READY',file=sys.stderr,flush=True); time.sleep(30)" if stubborn
                     else "import sys; sys.stdin.buffer.read()")
            try:
                with ExitStack() as patches:
                    patches.enter_context(mock.patch.object(q.subprocess, "Popen", side_effect=launch))
                    patches.enter_context(mock.patch.object(q.os, "pidfd_open", side_effect=open_pidfd))
                    patches.enter_context(mock.patch.object(q.threading.Thread, "start", new=start_reader))
                    patches.enter_context(mock.patch.object(Path, "open", new=open_file))
                    sent = patches.enter_context(mock.patch.object(q.os, "kill", wraps=real_kill))
                    groups = patches.enter_context(mock.patch.object(q.os, "killpg", wraps=real_killpg))
                    if stage == "owner-identity":
                        patches.enter_context(mock.patch.object(q, "process_identity", side_effect=failure))
                    if stage == "launch-write":
                        writer = patches.enter_context(mock.patch.object(q, "write_json", side_effect=failure))
                    if stubborn:
                        patches.enter_context(mock.patch.object(q, "EOF_SECONDS", 0.05))
                    if group_unknown:
                        patches.enter_context(mock.patch.object(q, "process_group_exists", return_value=True))
                    with self.assertRaises(error_type) as raised:
                        q.Mcp.__init__(client, [sys.executable, "-I", "-S", "-u", "-c", child],
                                       root, {}, output)
                    self.assertIs(raised.exception, failure)
                    if stage == "launch-write":
                        self.assertEqual(writer.call_count, 1)
                observation = client.close_observation
                self.assertIs(client.close(), observation)
                self.assertFalse(observation["construction_succeeded"])
                self.assertFalse(observation["qualification_claimed"])
                self.assertNotIn("returncode", observation)  # cannot pass a normal-close consumer
                self.assertEqual(observation["original_failure"]["message"], str(failure))
                self.assertTrue(failure.__notes__)
                self.assertEqual(len(children), 1)
                self.assertIs(client.process, children[0])
                self.assertEqual(observation["popen_child"]["pid"], children[0].pid)
                self.assertIsNotNone(children[0].returncode)
                self.assertFalse(Path("/proc", str(children[0].pid)).exists())
                with self.assertRaises(ChildProcessError):
                    os.waitpid(children[0].pid, os.WNOHANG)
                self.assertTrue(observation["reader_stopped"])
                self.assertTrue(client.reader is None or not client.reader.is_alive())
                self.assertTrue(all(observation[name + "_closed"] for name in ("stdin", "stdout", "stderr", "wire")))
                self.assertFalse(hasattr(client, "pidfd"))  # compatible with guarded_client's hasattr/os.close
                for fd in pidfds:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                if stage in {"pidfd-open", "owner-identity"}:
                    self.assertIsNone(observation["owner"])
                else:
                    self.assertEqual(observation["owner"], identities[0])
                if stage == "pidfd-open":
                    self.assertIsNone(observation["owner_pidfd_exited"])
                else:
                    self.assertTrue(observation["owner_pidfd_exited"])
                self.assertEqual(observation["cleanup_complete"], not (receipt_failure or group_unknown))
                self.assertEqual(observation["forced_cleanup"],
                                 ["SIGTERM-direct-child", "SIGKILL-direct-child"] if stubborn else [])
                self.assertEqual([call.args for call in sent.call_args_list],
                                 [(children[0].pid, signal.SIGTERM), (children[0].pid, signal.SIGKILL)]
                                 if stubborn else [])
                self.assertTrue(all(call.args == (children[0].pid, 0) for call in groups.call_args_list))
                if stubborn:
                    self.assertEqual(children[0].returncode, -signal.SIGKILL)
                if receipt_failure:
                    self.assertFalse((output / "initialization-failure.json").exists())
                    self.assertTrue(any(row["stage"] == "failure-receipt-write" for row in observation["cleanup_errors"]))
                else:
                    self.assertEqual(json.loads((output / "initialization-failure.json").read_bytes()), observation)
                result = deepcopy(observation)
            finally:
                # A regression must fail its assertions without leaking a test
                # child into another test or leaving a blocked reader behind.
                for process in children:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=3)
                    for stream in (process.stdin, process.stdout):
                        if stream is not None and not stream.closed:
                            stream.close()
                reader = getattr(client, "reader", None)
                if reader is not None and reader.ident is not None:
                    reader.join(timeout=3)
                for name in ("stderr", "wire"):
                    stream = getattr(client, name, None)
                    if stream is not None and not stream.closed:
                        stream.close()
                if isinstance(getattr(client, "pidfd", None), int):
                    try:
                        os.close(client.pidfd)
                    except OSError:
                        pass
        self.assertEqual(set(os.listdir("/proc/self/fd")), before_fds)
        return result

    def test_pidfd_open_failure_reaps_original_child_without_fabricating_identity(self):
        self.exercise_failure("pidfd-open")

    def test_owner_identity_failure_closes_already_open_pidfd(self):
        self.exercise_failure("owner-identity")

    def test_reader_start_failure_before_start_does_not_join_unstarted_thread(self):
        self.exercise_failure("reader-start-before")

    def test_reader_start_failure_after_real_start_drains_reader(self):
        self.exercise_failure("reader-start-after")

    def test_launch_write_failure_uses_independent_failure_receipt(self):
        self.exercise_failure("launch-write")

    def test_baseexception_during_construction_also_closes_owned_resources(self):
        self.exercise_failure("pidfd-open", error_type=KeyboardInterrupt)

    def test_uncooperative_owned_child_is_killed_and_never_reported_as_normal_close(self):
        self.exercise_failure("pidfd-open", stubborn=True)

    def test_incomplete_group_observation_stays_explicitly_failed(self):
        result = self.exercise_failure("launch-write", group_unknown=True)
        self.assertFalse(result["process_group_gone"])
        self.assertTrue(result["cleanup_errors"])

    def test_unwritable_failure_receipt_emits_bounded_real_stderr_fallback(self):
        read_fd, write_fd = os.pipe()
        saved_stderr = os.dup(2)
        try:
            os.dup2(write_fd, 2)
            result = self.exercise_failure("launch-write", receipt_failure=True)
        finally:
            os.dup2(saved_stderr, 2)
            os.close(saved_stderr)
            os.close(write_fd)
        try:
            raw = os.read(read_fd, 8193)
        finally:
            os.close(read_fd)
        self.assertGreater(len(raw), 0)
        self.assertLessEqual(len(raw), 8192)
        fallback = json.loads(raw)
        self.assertTrue(fallback["diagnostic_file_write_failed"])
        self.assertFalse(fallback["construction_succeeded"])
        self.assertFalse(fallback["qualification_claimed"])
        self.assertFalse(fallback["cleanup_complete"])
        self.assertEqual(fallback["popen_child_pid"], result["popen_child"]["pid"])
        self.assertTrue(fallback["reader_stopped"])
        self.assertTrue(all(fallback["streams_closed"].values()))

    def test_successful_constructor_keeps_normal_close_format(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            client = q.Mcp([sys.executable, "-I", "-S", "-c", "import sys; sys.stdin.buffer.read()"],
                           root, {}, root / "success")
            result = client.close()
            self.assertEqual(set(result), {"returncode", "elapsed_seconds", "forced_cleanup", "reader_stopped",
                                          "owner", "owner_pidfd_exited", "process_group_gone"})
            self.assertEqual(result["returncode"], 0)
            self.assertEqual(result["forced_cleanup"], [])
            self.assertTrue(result["reader_stopped"] and result["owner_pidfd_exited"] and result["process_group_gone"])
            self.assertFalse((root / "success" / "initialization-failure.json").exists())


if __name__ == "__main__":
    unittest.main()
