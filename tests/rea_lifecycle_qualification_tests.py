#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Fail-closed lifecycle receipt tests; synthetic rows are never provider evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_lifecycle_evidence as evidence
import rea_lifecycle_qualification as lifecycle
import rea_operation_qualification as q


OWNER = {"pid": 1234, "parent_pid": 1200, "process_group": 1234, "start_time_ticks": 91}
BINARY = "/selected/hepta-runtime"
FIXTURES = {"active": {"path": "/owned/active.elf", "dev": 8, "ino": 42}}


def raw_stat(identity=OWNER, state="S", comm="test (owned) process"):
    fields = [state, str(identity["parent_pid"]), str(identity["process_group"])]
    fields += ["0"] * 16
    fields += [str(identity["start_time_ticks"])]
    return f'{identity["pid"]} ({comm}) ' + " ".join(fields) + "\n"


def process(identity=OWNER, state="S", worker=False):
    argv = [BINARY, "rea-elf-notes-worker"] if worker else [BINARY, "mcp"]
    return {"pid": identity["pid"], "stat": raw_stat(identity, state), "stat_after": raw_stat(identity, state),
            "cmdline_hex": b"\0".join(x.encode() for x in argv).hex() + "00", "exe": BINARY,
            "listed_threads": [identity["pid"]], "thread_children": {str(identity["pid"]): ""},
            "listed_fds": [], "fds": []}


def observation(active=False):
    owner = process()
    if active:
        owner["listed_fds"] = [5]
        owner["fds"] = [{"fd": 5, "dev": 8, "ino": 42, "mode": stat.S_IFREG | 0o600,
                         "link": "/owned/active.elf", "fdinfo": "pos:\t65536\nflags:\t0100000\n"}]
    return {"schema": "hepta.rea.proc-observation.v1", "start_ns": 100, "end_ns": 200,
            "processes": [owner], "errors": [], "tracked": []}


def wire(records):
    return b"".join(json.dumps({"direction": direction, "monotonic_ns": when,
                                 "wire_utf8": json.dumps(value) + "\n"}).encode() + b"\n"
                    for direction, when, value in records)


def request(identifier=4):
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
            "params": {"name": "inspect_elf_notes", "arguments": {"path": "/owned/active.elf"}}}


def cancel(identifier=4):
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": identifier}}


def cancelled_response(identifier=4, code="cancelled"):
    value = {"error": {"code": code, "category": "cancelled", "details": {"operation": "inspect_elf_notes"}}}
    return {"jsonrpc": "2.0", "id": identifier, "result": {"_meta": q.TARGET_META, "isError": True,
            "content": [{"type": "text", "text": json.dumps(value)}]}}


class ObservationTests(unittest.TestCase):
    def validate(self, value):
        return evidence.validate_observation(value, OWNER, FIXTURES, BINARY)

    def test_proc_identity_handles_spaces_and_parentheses(self):
        self.assertEqual(lifecycle.proc_identity(raw_stat()), OWNER)
        self.assertEqual(evidence.parse_stat(raw_stat())[0], OWNER)

    def test_open_target_is_positive_and_not_drained(self):
        value = self.validate(observation(active=True))
        self.assertEqual(value["matches"], {"active"})
        self.assertFalse(value["clear"])

    def test_complete_live_owner_without_target_is_clear(self):
        self.assertTrue(self.validate(observation())["clear"])

    def test_unreadable_proc_is_unknown_even_with_pass_flag(self):
        row = observation()
        row.update({"passed": True, "qualified": True, "errors": ["fd access denied"]})
        value = self.validate(row)
        self.assertFalse(value["complete"])
        self.assertFalse(value["clear"])

    def test_missing_owner_does_not_become_empty_tree(self):
        row = observation()
        row.update({"processes": [], "errors": ["owner unavailable"]})
        with self.assertRaises(evidence.OpenObservation):
            self.validate(row)

    def test_different_start_time_is_not_same_owner(self):
        row = observation()
        changed = {**OWNER, "start_time_ticks": 92}
        row["processes"] = [process(changed)]
        with self.assertRaises(evidence.OpenObservation):
            self.validate(row)

    def test_descriptor_omission_cannot_prove_absence(self):
        row = observation()
        row["processes"][0]["listed_fds"] = [5]
        with self.assertRaises(ValueError):
            self.validate(row)
        row["errors"] = ["descriptor vanished during scan"]
        self.assertFalse(self.validate(row)["clear"])

    def test_missing_thread_children_cannot_prove_absence(self):
        row = observation()
        row["processes"][0]["thread_children"] = {}
        with self.assertRaises(ValueError):
            self.validate(row)
        row["errors"] = ["thread disappeared"]
        self.assertFalse(self.validate(row)["clear"])

    def test_child_inventory_must_include_reported_child(self):
        row = observation()
        row["processes"][0]["thread_children"]["1234"] = "1235 "
        with self.assertRaises(ValueError):
            self.validate(row)

    def test_descriptor_without_independent_identity_is_rejected(self):
        row = observation(True)
        del row["processes"][0]["fds"][0]["ino"]
        with self.assertRaises(ValueError):
            self.validate(row)

    def test_active_descriptor_requires_file_position(self):
        row = observation(True)
        row["processes"][0]["fds"][0]["fdinfo"] = "flags:\t0100000\n"
        with self.assertRaises(ValueError):
            self.validate(row)

    def test_duplicate_descriptor_rejected(self):
        row = observation(True)
        row["processes"][0]["fds"] *= 2
        with self.assertRaises(ValueError):
            self.validate(row)

    def test_stopped_owned_worker_is_detected_but_not_drained(self):
        row = observation()
        identity = {"pid": 1235, "parent_pid": 1234, "process_group": 1234, "start_time_ticks": 92}
        row["processes"][0]["thread_children"]["1234"] = "1235 "
        row["processes"].append(process(identity, "T", worker=True))
        row["tracked"] = [{"identity": identity, "pidfd_exited": False, "stat": raw_stat(identity, "T")}]
        value = self.validate(row)
        self.assertEqual(value["workers"], [identity])
        self.assertFalse(value["clear"])

    def test_exited_pidfd_is_not_a_reaped_process(self):
        row = observation()
        identity = {"pid": 1235, "parent_pid": 1234, "process_group": 1234, "start_time_ticks": 92}
        row["tracked"] = [{"identity": identity, "pidfd_exited": True, "stat": raw_stat(identity, "Z")}]
        self.assertFalse(self.validate(row)["clear"])
        row["tracked"][0]["stat"] = None
        self.assertTrue(self.validate(row)["clear"])

    def test_pid_reuse_invalidates_pidfd_absence_claim(self):
        row = observation()
        identity = {"pid": 1235, "parent_pid": 1234, "process_group": 1234, "start_time_ticks": 92}
        row["tracked"] = [{"identity": identity, "pidfd_exited": True,
                           "stat": raw_stat({**identity, "start_time_ticks": 93})}]
        with self.assertRaises(ValueError):
            self.validate(row)

    def test_unowned_process_group_is_rejected(self):
        row = observation()
        row["processes"] = [process({**OWNER, "process_group": 9999})]
        with self.assertRaises(ValueError):
            self.validate(row)


class WireTests(unittest.TestCase):
    def test_cancel_notification_requires_no_acknowledgement(self):
        value = evidence.original_wire(wire([("sent", 10, request()), ("sent", 20, cancel())]))
        self.assertEqual(evidence.cancellation_outcome(value, 4, 20), "no-terminal-response")
        self.assertEqual(len(value["notifications"]), 1)

    def test_typed_cancellation_is_an_optional_valid_terminal(self):
        value = evidence.original_wire(wire([("sent", 10, request()), ("sent", 20, cancel()),
                                             ("received", 30, cancelled_response())]))
        self.assertEqual(evidence.cancellation_outcome(value, 4, 20), "typed-cancelled")

    def test_completion_before_cancel_is_open(self):
        value = evidence.original_wire(wire([("sent", 10, request()),
                                             ("received", 15, cancelled_response()), ("sent", 20, cancel())]))
        with self.assertRaises(evidence.OpenObservation):
            evidence.cancellation_outcome(value, 4, 20)

    def test_unexpected_error_after_cancel_is_not_accepted(self):
        value = evidence.original_wire(wire([("sent", 10, request()), ("sent", 20, cancel()),
                                             ("received", 30, cancelled_response(code="resource_constraint"))]))
        with self.assertRaises(evidence.FailedObservation):
            evidence.cancellation_outcome(value, 4, 20)

    def test_duplicate_response_is_rejected(self):
        raw = wire([("sent", 10, request()), ("received", 20, cancelled_response()),
                    ("received", 30, cancelled_response())])
        with self.assertRaises(ValueError):
            evidence.original_wire(raw)

    def test_response_before_request_is_rejected(self):
        with self.assertRaises(ValueError):
            evidence.original_wire(wire([("sent", 20, request()), ("received", 10, cancelled_response())]))

    def test_wire_does_not_accept_request_id_boolean(self):
        with self.assertRaises(ValueError):
            evidence.original_wire(wire([("sent", 10, request(True))]))


class FailClosedTests(unittest.TestCase):
    def test_original_fixture_digest_is_independent_of_receipt(self):
        raw = q.elf(q.note())
        self.assertEqual(evidence.expected_fixture(len(raw)), hashlib.sha256(raw).hexdigest())

    def test_pass_summary_does_not_hide_forced_cleanup(self):
        replay = evidence.Replay.__new__(evidence.Replay)
        replay.owner = OWNER
        replay.close = {"owner": OWNER, "returncode": 0, "forced_cleanup": ["SIGKILL"],
                        "reader_stopped": True, "owner_pidfd_exited": True, "process_group_gone": True,
                        "elapsed_seconds": 0.1, "status": "PASS", "qualified": True}
        replay.events = [{"event": "eof", "owner": OWNER}, {"event": "closed", "observation": replay.close}]
        with self.assertRaises(evidence.FailedObservation):
            replay.closed()

    def test_unsupported_trace_stays_open(self):
        replay = evidence.Replay.__new__(evidence.Replay)
        replay.closed = lambda: None
        replay.events = [{"event": "unobserved", "status": "PASS", "qualified": True}]
        with self.assertRaises(evidence.OpenObservation):
            replay.replay()

    def test_known_execution_error_stays_failed(self):
        replay = evidence.Replay.__new__(evidence.Replay)
        replay.closed = lambda: None
        replay.events = [{"event": "error", "reason": "owner leaked", "status": "PASS"}]
        with self.assertRaises(evidence.FailedObservation):
            replay.replay()

    def test_stop_refuses_unowned_child_before_any_signal(self):
        probe = lifecycle.ProcessProbe(SimpleNamespace(owner=OWNER), {})
        with mock.patch.object(signal_module(), "pidfd_send_signal") as send:
            with self.assertRaises(ValueError):
                probe.stop_worker({"pid": 1235, "parent_pid": 9999, "process_group": 1234, "start_time_ticks": 92})
            send.assert_not_called()

    def test_stop_refuses_reused_pid_before_any_signal(self):
        probe = lifecycle.ProcessProbe(SimpleNamespace(owner=OWNER), {})
        identity = {"pid": 1235, "parent_pid": 1234, "process_group": 1234, "start_time_ticks": 92}
        with mock.patch.object(os, "pidfd_open", return_value=98), mock.patch.object(os, "close") as close, \
                mock.patch.object(lifecycle, "proc_stat", return_value=raw_stat({**identity, "start_time_ticks": 93})), \
                mock.patch.object(signal_module(), "pidfd_send_signal") as send:
            with self.assertRaises(lifecycle.Unobserved):
                probe.stop_worker(identity)
            send.assert_not_called()
            close.assert_called_once_with(98)


def signal_module():
    return lifecycle.signal


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"), "Linux procfs/pidfd observation")
class ActualOwnedProcessTests(unittest.TestCase):
    def test_real_descriptor_open_and_drain_with_same_live_owner(self):
        with tempfile.TemporaryDirectory(prefix="rea-lifecycle-test-") as directory:
            target = Path(directory) / "owned.elf"
            target.write_bytes(q.elf(q.note()))
            metadata = target.stat()
            fixture = {"path": str(target), "dev": metadata.st_dev, "ino": metadata.st_ino}
            code = ("import sys\n"
                    "f = open(sys.argv[1], 'rb'); f.read(16)\n"
                    "print('OPEN', flush=True)\n"
                    "sys.stdin.readline(); f.close()\n"
                    "print('CLOSED', flush=True)\n"
                    "sys.stdin.readline()\n")
            child = subprocess.Popen([sys.executable, "-c", code, str(target)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(child.stdout.readline(), b"OPEN\n")
                client = SimpleNamespace(owner=q.process_identity(child.pid), process=child)
                probe = lifecycle.ProcessProbe(client, {"active": fixture})
                opened, _ = lifecycle.wait_observation(probe, lambda row: lifecycle.matches_target(row, fixture), 3)
                parsed = evidence.validate_observation(opened, client.owner, {"active": fixture}, BINARY)
                self.assertIn("active", parsed["matches"])
                self.assertFalse(parsed["clear"])
                child.stdin.write(b"close\n")
                child.stdin.flush()
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(child.stdout.readline(), b"CLOSED\n")
                cleared, _ = lifecycle.wait_observation(probe, lambda row: lifecycle.drained(row, client.owner, [fixture]), 3)
                self.assertTrue(evidence.validate_observation(cleared, client.owner, {"active": fixture}, BINARY)["clear"])
                self.assertIsNone(child.poll())
                probe.close()
            finally:
                child.stdin.close()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()


class ArchiveRelocationTests(unittest.TestCase):
    """Complete synthetic OPEN receipts check relocation, never execution success."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rea-lifecycle-archive-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.repo, self.original = self.base / "source", self.base / "original-output"
        self.root = self.original
        self.root.mkdir()
        checkout = Path(__file__).resolve().parents[1]
        for name in evidence.PRODUCER_FILES:
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(checkout / name, target)
        from rea_full_qualification import Selection
        source = Selection(self.repo, None, None).snapshot()
        binary = {"path": BINARY, "bytes": 10, "sha256": "1" * 64}
        node = {"path": "/selected/node", "bytes": 20, "sha256": "2" * 64}
        reference = {"name": "rea-agents", "version": "6.8.0", "file_count": 2398,
            "tarball_sha256": q.PACKAGE_SHA256, "files_sha256": q.PACKAGE_FILES_SHA256,
            "catalog_sha256": q.CATALOG_SHA256, "git_source_commit": q.REFERENCE_COMMIT,
            "package_root": "/selected/rea-agents"}
        bindings = [q.artifact_reference(self.repo / name, self.repo) for name in evidence.PRODUCER_FILES]
        self.fixtures = {name: {"path": str(self.original / "workspace" / (name + ".elf")),
            "sha256": evidence.expected_fixture(size), "bytes": size, "dev": 8, "ino": 42 + index,
            "mode": stat.S_IFREG | 0o600} for index, (name, size) in enumerate((
                ("prime", len(q.elf(q.note()))), ("active", evidence.ACTIVE_BYTES), ("worker", evidence.WORKER_BYTES)))}
        self.config = {"controller_workspace_roots": [str(self.original / "workspace")],
            "state_dir": str(self.original / "state"), "hosts": {"never-connect": {
                "ssh_target": "never-connect-invalid", "remote_state_dir": str(self.original / "unused-remote"),
                "allow_execute": False, "allow_pty": False, "allow_write": False, "allow_job_network": False}}}
        self.report = {"schema": evidence.SCHEMA, "profile": evidence.PROFILE, "operation": "inspect_elf_notes",
            "errors": [], "producer_before": bindings, "producer_after": copy.deepcopy(bindings),
            "source_before": self.put("source-before.json", source), "source_after": self.put("source-after.json", source),
            "source_monitor": self.put("source-monitor.json", {"event_count": 0, "errors": [],
                "retained_events": [], "events_truncated": False}),
            "reference_before": reference, "reference_after": copy.deepcopy(reference),
            "native_before": binary, "native_after": copy.deepcopy(binary),
            "node_before": node, "node_after": copy.deepcopy(node), "node_version": "v22.23.4",
            "binary_source_commit_declared": "3" * 40,
            "binary_source_receipt": self.put("binary-source-receipt.json", {"binary": binary, "commit": "3" * 40}),
            "config": self.put("runtime.json", self.config), "fixtures": self.put("fixtures.json", self.fixtures),
            "fixtures_after": self.put("fixtures-after.json", self.fixtures), "sessions": [],
            "unsupported": [{"producer": "reference", "scenario": "worker-deadline",
                "reason": "frozen ElfNotesProvider parses in process; no independent parser pidfd deadline injection boundary"}]}
        for index, (label, scenario) in enumerate(evidence.SESSION_ORDER):
            prefix = label + "-" + scenario
            owner = {"pid": 1234 + index, "parent_pid": 1200, "process_group": 1234 + index, "start_time_ticks": 91 + index}
            close = {"owner": owner, "returncode": 0, "forced_cleanup": [], "reader_stopped": True,
                     "owner_pidfd_exited": True, "process_group_gone": True, "elapsed_seconds": 0.1}
            argv = ([node["path"], "/selected/rea-agents/scripts/rea.mjs", "mcp"] if label == "reference"
                    else [BINARY, "mcp", "--runtime-config", str(self.original / "runtime.json")])
            launch = {"pid": owner["pid"], "owner": owner, "argv": argv, "cwd": str(self.original / "workspace"),
                      "environment": lifecycle.REFERENCE_ENVIRONMENT if label == "reference" else {}}
            tool = "inspect_elf_notes" if label == "reference" else "rea_inspect_elf_notes"
            arguments = {"path": self.fixtures["active"]["path"], "max_file_bytes": evidence.ACTIVE_BYTES}
            request_value = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                             "params": {"name": tool, "arguments": arguments}}
            trace = {"schema": "hepta.rea.lifecycle-trace.v1", "producer": label, "scenario": scenario,
                "events": [{"event": "request", "when_ns": 2, "request_id": 4, "tool": tool,
                            "arguments": arguments, "role": "active"},
                           {"event": "unobserved", "when_ns": 3},
                           {"event": "eof", "when_ns": 4, "owner": owner},
                           {"event": "closed", "when_ns": 5, "observation": close}]}
            self.report["sessions"].append({"producer": label, "scenario": scenario,
                "trace": self.put(prefix + "/trace.json", trace),
                "wire": self.put(prefix + "/wire.jsonl", wire([("sent", 1, request_value)])),
                "launch": self.put(prefix + "/launch.json", launch), "close": self.put(prefix + "/close.json", close),
                "stderr": self.put(prefix + "/stderr.log", b"")})
        self.pin = self.put("qualification.json", self.report)["sha256"]

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else q.json_bytes(value))
        return q.artifact_reference(path, self.root)

    def read(self, reference):
        return json.loads((self.root / reference["path"]).read_bytes())

    def validate(self, repin=False):
        if repin:
            self.pin = self.put("qualification.json", self.report)["sha256"]
        return evidence.validate_lifecycle_receipt(self.repo, self.root / "qualification.json", self.pin)

    def relocate(self):
        destination = self.base / "relocated-archive"
        shutil.copytree(self.root, destination)
        shutil.rmtree(self.root)
        self.root = destination

    def test_unchanged_complete_receipt_replays_after_original_path_is_gone(self):
        before = self.validate()
        originals = {path.relative_to(self.root): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.relocate()
        self.assertFalse(self.original.exists())
        old_open, old_resolve, old_stat = Path.open, Path.resolve, Path.stat

        def guard(function):
            def checked(path, *args, **kwargs):
                self.assertFalse(path.is_relative_to(self.original), "recorded execution path was used for filesystem access")
                return function(path, *args, **kwargs)
            return checked

        with mock.patch.object(Path, "open", guard(old_open)), mock.patch.object(Path, "resolve", guard(old_resolve)), \
                mock.patch.object(Path, "stat", guard(old_stat)):
            after = self.validate()
        self.assertEqual(before, after)
        self.assertEqual(after["status"], "OPEN")
        self.assertFalse(after["qualified"])
        self.assertEqual({key: (self.root / key).read_bytes() for key in originals}, originals)

    def test_recorded_paths_are_lexical_canonical_linux_metadata(self):
        self.assertEqual(str(evidence.recorded_output_root(self.fixtures)), str(self.original))
        paths = ("relative/workspace/prime.elf", "/owned/../workspace/prime.elf", "/owned//workspace/prime.elf",
                 "/owned/./workspace/prime.elf", "//owned/workspace/prime.elf", "/owned/workspace/other.elf",
                 "/owned/other/prime.elf", "/workspace/prime.elf", "/owned/\0/workspace/prime.elf", None)
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                evidence.recorded_output_root({"prime": {"path": path}})

    def test_rehashing_config_cannot_rebase_original_execution_to_archive(self):
        self.relocate()
        changed = copy.deepcopy(self.config)
        changed["controller_workspace_roots"] = [str(self.root / "workspace")]
        self.report["config"] = self.put("runtime.json", changed)
        with self.assertRaises(ValueError):
            self.validate(repin=True)

    def test_rehashing_fixtures_cannot_change_the_recorded_workspace(self):
        self.relocate()
        changed = copy.deepcopy(self.fixtures)
        for value in changed.values():
            value["path"] = str(self.root / "workspace" / Path(value["path"]).name)
        self.report["fixtures"] = self.put("fixtures.json", changed)
        self.report["fixtures_after"] = self.put("fixtures-after.json", changed)
        with self.assertRaises(ValueError):
            self.validate(repin=True)

    def test_original_launch_argv_and_cwd_remain_required_after_relocation(self):
        self.relocate()
        session = self.report["sessions"][1]
        reference = copy.deepcopy(session["launch"])
        original = self.read(reference)
        for field in ("argv", "cwd"):
            changed = copy.deepcopy(original)
            if field == "argv":
                changed[field][-1] = str(self.root / "runtime.json")
            else:
                changed[field] = str(self.root / "workspace")
            session["launch"] = self.put(reference["path"], changed)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(repin=True)

    def test_archive_references_cannot_follow_recorded_or_outside_paths(self):
        self.relocate()
        original = copy.deepcopy(self.report["config"])
        for path in (str(self.original / "runtime.json"), "../runtime.json"):
            self.report["config"] = {**original, "path": path}
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.validate(repin=True)
        self.report["config"] = original
        outside = self.base / "outside.json"
        shutil.copyfile(self.root / original["path"], outside)
        (self.root / original["path"]).unlink()
        (self.root / original["path"]).symlink_to(outside)
        with self.assertRaises(ValueError):
            self.validate(repin=True)

    def test_trace_rehash_does_not_override_the_original_wire_request(self):
        self.relocate()
        session = self.report["sessions"][0]
        changed = self.read(session["trace"])
        changed["events"][0]["arguments"]["path"] = str(self.root / "workspace/active.elf")
        session["trace"] = self.put(session["trace"]["path"], changed)
        with self.assertRaises(ValueError):
            self.validate(repin=True)

    def test_source_and_binary_identity_checks_remain_required(self):
        self.relocate()
        source_path = self.repo / evidence.PRODUCER_FILES[0]
        original = source_path.read_bytes()
        source_path.write_bytes(original + b"\n")
        with self.assertRaises(ValueError):
            self.validate()
        source_path.write_bytes(original)
        self.report["native_before"]["sha256"] = self.report["native_after"]["sha256"] = "4" * 64
        with self.assertRaises(ValueError):
            self.validate(repin=True)

    def test_normal_owner_close_is_not_weakened_by_relocation_or_pass_labels(self):
        self.relocate()
        session = self.report["sessions"][1]
        changed = self.read(session["close"])
        changed["forced_cleanup"] = ["SIGKILL"]
        session["close"] = self.put(session["close"]["path"], changed)
        trace = self.read(session["trace"])
        trace["events"][-1]["observation"] = changed
        session["trace"] = self.put(session["trace"]["path"], trace)
        self.report.update({"qualified": True, "status": "PASS"})
        result = self.validate(repin=True)
        self.assertEqual(result["status"], "FAILED")
        self.assertFalse(result["qualified"])


if __name__ == "__main__":
    unittest.main()
