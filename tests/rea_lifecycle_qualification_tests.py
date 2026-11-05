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


if __name__ == "__main__":
    unittest.main()
