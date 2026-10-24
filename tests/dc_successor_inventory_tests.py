# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
#!/usr/bin/env python3
"""Offline stdlib fixtures only: no real endpoint, credential, state, or service.

Run: python3 tests/dc_successor_inventory_tests.py --results-dir results/run-001
All fixture data lives in TemporaryDirectory. Raw unittest results and source/
test before-after SHA256 bindings are written to a new named results directory.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "deploy" / "dc_successor_inventory.py"
SPEC = importlib.util.spec_from_file_location("dc_successor_inventory", SOURCE)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
SECRET = "FIXTURE_PRIVATE_ARGV_ENV_OUTPUT_NEVER_PUBLIC_019283"


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inventory-offline-")
        self.root = Path(self.temp.name)
        self.jobs = self.root / "jobs"
        self.jobs.mkdir(mode=0o700)
        self.members = {}
        self.token = self.root / "fixture-token"
        self.token.write_text("SYNTHETIC_FIXTURE_TOKEN")
        self.token.chmod(0o600)
        self.credential_identity = M.credential_inode(self.token)

    def tearDown(self):
        self.temp.cleanup()

    def put(self, identity, host="main", **extra):
        path = self.jobs / (identity + ".json")
        path.write_text(json.dumps(dict(id=identity, host=host, argv=[SECRET], env={"S": SECRET}, **extra)))
        path.chmod(0o600)
        self.members[identity] = host
        return path

    def populate(self, count):
        for n in range(count):
            self.put("job-%05d" % n, M.HOSTS[n % len(M.HOSTS)])

    def observe(self, factory=None, **kwargs):
        if factory is None:
            self.factory = Factory(self.members)
            factory = self.factory
        return M.observe_inventory(str(self.jobs), factory, credential_identity=self.credential_identity, budget_seconds=20, **kwargs)

    def registry_error(self, code=None):
        with self.assertRaises(M.RegistryError) as captured:
            M.read_registry(str(self.jobs), credential_identity=self.credential_identity)
        if code is not None:
            self.assertEqual(captured.exception.code, code)
        self.assertNotIn(SECRET, str(captured.exception))
        return captured.exception


class Factory:
    def __init__(self, members, *, listing=None, status=None, after_status=None, fail_host=None):
        self.members = dict(members)
        self.listing, self.status = listing, status
        self.after_status, self.fail_host = after_status, fail_host
        self.calls, self.closed, self.created = [], [], []
        self.lock = threading.Lock()
        self.active, self.max_active, self.active_hosts, self.max_per_host = 0, 0, {}, 0

    def __call__(self, host, deadline, credential_identity):
        with self.lock:
            self.created.append(host)
        factory = self
        class Client:
            def __init__(self):
                self.host = host
                self.expected_credential_identity = credential_identity
            def call(self, name, args, *, timeout_seconds):
                with factory.lock:
                    factory.calls.append((host, name, dict(args), timeout_seconds, deadline.remaining()))
                    factory.active += 1
                    factory.active_hosts[host] = factory.active_hosts.get(host, 0) + 1
                    factory.max_active = max(factory.max_active, factory.active)
                    factory.max_per_host = max(factory.max_per_host, factory.active_hosts[host])
                try:
                    if factory.fail_host == host:
                        raise RuntimeError(SECRET)
                    if name == "process_list":
                        rows = [{"id": identity, "host": authority, "argv": [SECRET], "output": SECRET}
                                for identity, authority in sorted(factory.members.items()) if authority == host]
                        return factory.listing(host, rows) if factory.listing else {"jobs": rows}
                    if name != "process_status":
                        raise AssertionError("unexpected tool")
                    identity = args["job_id"]
                    row = {"id": identity, "host": host, "state": "completed", "status_authoritative": True,
                           "launch_nonce_present": True, "supervisor_binding_verified": True,
                           "backend": "detached", "pid": 31, "argv": [SECRET], "env": {"S": SECRET}, "output": SECRET}
                    if factory.status:
                        row = factory.status(host, identity, row)
                    if factory.after_status:
                        factory.after_status(host, identity)
                    return row
                finally:
                    with factory.lock:
                        factory.active -= 1
                        factory.active_hosts[host] -= 1
            def close(self):
                with factory.lock:
                    factory.closed.append(host)
        return Client()


class RegistryTests(Fixture):
    def test_safe_fingerprint_and_payload_discard(self):
        path = self.put("job-a")
        snap = M.read_registry(str(self.jobs), credential_identity=self.credential_identity)
        self.assertTrue(snap.complete)
        self.assertEqual(snap.jobs, {"job-a": "main"})
        self.assertEqual(len(snap.fingerprint), 64)
        self.assertNotIn(SECRET, repr(snap))
        public = [["job-a", "main", list(snap.pins["job-a"])]]
        expected = hashlib.sha256(json.dumps(public, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(snap.fingerprint, expected)
        self.assertNotEqual(snap.fingerprint, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_16385_overflow_before_any_payload_read(self):
        for n in range(M.MAX_RECORDS + 1):
            (self.jobs / ("job-%05d.json" % n)).touch(mode=0o600)
        with mock.patch.object(M.os, "read", side_effect=AssertionError("must not read")) as reader:
            self.registry_error("RegistryOverflow")
        reader.assert_not_called()

    def test_missing_directory_is_incomplete(self):
        snap = M.read_registry(str(self.root / "missing"), credential_identity=self.credential_identity)
        self.assertFalse(snap.complete)
        self.assertTrue(snap.missing)

    def test_missing_pin_rejected_except_explicit_lowlevel_fixture(self):
        self.put("job-a")
        with self.assertRaises(M.RegistryError): M.read_registry(str(self.jobs))
        self.assertTrue(M.read_registry(str(self.jobs), fixture=True).complete)
        factory = Factory(self.members)
        for pin in (None, (0, 0), (True, 1), [1, 2]):
            with self.assertRaises(M.InventoryError):
                M.observe_inventory(str(self.jobs), factory, credential_identity=pin)
        self.assertEqual(factory.created, [])
        self.assertEqual(factory.calls, [])

    def test_unknown_entry_keeps_only_safe_partial(self):
        self.put("aaa")
        (self.jobs / "zzz-unrecognized").write_text(SECRET)
        exc = self.registry_error("RegistryInvalid")
        self.assertEqual(exc.partial.jobs, {"aaa": "main"})
        self.assertFalse(exc.partial.complete)
        self.assertNotIn(SECRET, repr(exc.partial))

    def test_badtypes_and_logical_binding(self):
        cases = [[], {"id": 1, "host": "main"}, {"id": "wrong", "host": "main"},
                 {"id": "job-a", "host": "other"}, {"id": "job-a", "host": []}]
        path = self.jobs / "job-a.json"
        for row in cases:
            with self.subTest(row_type=type(row).__name__):
                path.write_text(json.dumps(row)); path.chmod(0o600)
                self.registry_error()

    def test_duplicate_json_keys_rejected(self):
        path = self.jobs / "job-a.json"
        path.write_text('{"id":"job-a","id":"job-a","host":"main"}')
        path.chmod(0o600)
        self.registry_error("ProtocolInvalid")

    def test_nonfinite_float_and_constants_rejected(self):
        path = self.jobs / "job-a.json"
        for number in ("1e999", "-1e999", "NaN", "Infinity"):
            path.write_text('{"id":"job-a","host":"main","private":' + number + '}')
            path.chmod(0o600)
            with self.subTest(number=number): self.registry_error("ProtocolInvalid")

    def test_foreign_uid_metadata_rejected_without_chown(self):
        path = self.put("job-a")
        for info, validate in ((path.stat(), M._private_file), (self.jobs.stat(), M._private_directory)):
            values = {field: getattr(info, field) for field in M.STAT_FIELDS}
            values["st_uid"] = os.getuid() + 1
            with self.assertRaises(M.InventoryError): validate(types.SimpleNamespace(**values))

    def test_symlink_and_fifo_and_hardlink(self):
        target = self.root / "fixture-private"
        target.write_text(SECRET); target.chmod(0o600)
        path = self.jobs / "job-a.json"
        path.symlink_to(target); self.registry_error(); path.unlink()
        os.mkfifo(path, 0o600); self.registry_error(); path.unlink()
        os.link(target, path); self.registry_error(); path.unlink()

    def test_directory_and_ancestor_symlink(self):
        link = self.root / "linked"
        link.symlink_to(self.jobs, target_is_directory=True)
        with self.assertRaises(M.RegistryError):
            M.read_registry(str(link), credential_identity=self.credential_identity)
        nested = self.jobs / "inner"
        nested.mkdir(mode=0o700)
        with self.assertRaises(M.RegistryError):
            M.read_registry(str(link / "inner"), credential_identity=self.credential_identity)

    def test_private_parent_and_file_modes(self):
        path = self.put("job-a")
        path.chmod(0o644); self.registry_error("RegistryInvalid"); path.chmod(0o600)
        self.jobs.chmod(0o755); self.registry_error("RegistryInvalid"); self.jobs.chmod(0o700)
        self.root.chmod(0o755); self.registry_error("RegistryInvalid"); self.root.chmod(0o700)

    def test_credential_alias_before_read_without_digest(self):
        path = self.put("job-a")
        pin = M.credential_inode(path)
        with mock.patch.object(M.os, "read", side_effect=AssertionError("alias must not be read")) as reader:
            with self.assertRaises(M.RegistryError) as captured:
                M.read_registry(str(self.jobs), credential_identity=pin)
        self.assertEqual(captured.exception.code, "CredentialAlias")
        reader.assert_not_called()

    def test_changed_fd_and_path_replacement(self):
        path = self.put("job-a")
        original_read = os.read
        changed = False
        def mutate(descriptor, count):
            nonlocal changed
            if not changed:
                changed = True
                with path.open("a") as writer:
                    writer.write(" ")
            return original_read(descriptor, count)
        with mock.patch.object(M.os, "read", side_effect=mutate):
            self.registry_error("RegistryChanged")
        self.put("job-a")
        changed = False
        def replace(descriptor, count):
            nonlocal changed
            if not changed:
                changed = True
                path.unlink()
                self.put("job-a")
            return original_read(descriptor, count)
        with mock.patch.object(M.os, "read", side_effect=replace):
            self.registry_error("RegistryInvalid")

    def test_metadata_mode_mutates_during_fd_read(self):
        path = self.put("job-a")
        original_read = os.read
        def change_mode(descriptor, count):
            path.chmod(0o644)
            return original_read(descriptor, count)
        with mock.patch.object(M.os, "read", side_effect=change_mode):
            self.registry_error("RegistryInvalid")

    def test_membership_changes_during_registry_read(self):
        self.put("job-a")
        original_read = os.read
        changed = False
        def mutate(descriptor, count):
            nonlocal changed
            if not changed:
                changed = True
                self.put("job-b")
            return original_read(descriptor, count)
        with mock.patch.object(M.os, "read", side_effect=mutate):
            self.registry_error("RegistryChanged")

    def test_655kb_private_payload_stays_ram_only(self):
        self.put("job-a", large_private=SECRET * 14000)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            snap = M.read_registry(str(self.jobs), credential_identity=self.credential_identity)
        self.assertTrue(snap.complete)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(SECRET, repr(snap))


class ReconciliationTests(Fixture):
    def assert_complete(self, count):
        self.populate(count)
        result = self.observe()
        self.assertTrue(result["membership_complete"])
        self.assertTrue(result["status_observation_complete"])
        self.assertTrue(result["status_authoritative_complete"])
        self.assertTrue(result["bindings_complete"])
        self.assertTrue(result["jobs_complete"])
        self.assertEqual({row["id"] for row in result["jobs"]}, set(self.members))
        status_calls = [args["job_id"] for _, tool, args, _, _ in self.factory.calls if tool == "process_status"]
        self.assertEqual(len(status_calls), count)
        self.assertEqual(set(status_calls), set(self.members))
        self.assertLessEqual(self.factory.max_active, 6)
        self.assertEqual(self.factory.max_per_host, 1)
        self.assertEqual(set(self.factory.closed), set(M.HOSTS))
        self.assertTrue(all(timeout > 0 and timeout <= remaining + 0.01 for _, _, _, timeout, remaining in self.factory.calls))
        self.assertEqual(result["decision"], "HOLD")
        self.assertFalse(result["ptys_complete"])
        self.assertFalse(result["streams_complete"])
        self.assertFalse(any(result["dispatch"].values()))
        self.assertNotIn(SECRET, json.dumps(result))

    def test_4097_full_id_coverage(self):
        self.assert_complete(4097)

    def test_5650_full_id_coverage(self):
        self.assert_complete(5650)

    def test_4097_sanitizer_public_fields_and_fixed_domains(self):
        self.populate(4097)
        result = self.observe()
        result["private"] = SECRET
        for row in result["jobs"]:
            row.update(argv=[SECRET], env={"S": SECRET}, output=SECRET)
        result.update(ptys=[{"private": SECRET}], streams=[{"private": SECRET}],
                      ptys_complete=True, streams_complete=True,
                      dispatch={"native_complete": True, "facade_complete": True, "admission_frozen": True})
        safe = M.sanitized_inventory(result)
        self.assertEqual(len(safe["jobs"]), 4097)
        self.assertTrue(safe["jobs_complete"])
        self.assertNotIn(SECRET, json.dumps(safe))
        self.assertEqual(safe["ptys"], [])
        self.assertFalse(safe["ptys_complete"])
        self.assertFalse(safe["streams_complete"])
        self.assertFalse(any(safe["dispatch"].values()))
        self.assertEqual(safe["decision"], "HOLD")

    def test_sanitizer_16385_overflow_and_duplicate_fail_closed(self):
        row = {"id": "job-a", "host": "main", "state": "succeeded"}
        with self.assertRaises(M.InventoryError) as captured:
            M.sanitized_inventory({"jobs": [row] * (M.MAX_RECORDS + 1)})
        self.assertEqual(captured.exception.code, "InventoryOverflow")
        with self.assertRaises(M.InventoryError) as captured:
            M.sanitized_inventory({"jobs": [row, row]})
        self.assertEqual(captured.exception.code, "DuplicateIdentity")

    def test_sanitizer_strict_flags_and_bad_error_types(self):
        self.put("job-a")
        result = self.observe()
        result.update(membership_complete=1, status_observation_complete="true", jobs_complete=True)
        result["errors"] = [{"scope": SECRET, "error_type": SECRET}]
        safe = M.sanitized_inventory(result)
        self.assertFalse(safe["membership_complete"])
        self.assertFalse(safe["status_observation_complete"])
        self.assertFalse(safe["jobs_complete"])
        self.assertEqual(safe["errors"], [{"scope": "global", "error_type": "ReadFailure"}])
        self.assertNotIn(SECRET, json.dumps(safe))
        result["errors"] = [{"scope": [SECRET], "error_type": {"private": SECRET}}]
        self.assertNotIn(SECRET, json.dumps(M.sanitized_inventory(result)))

    def test_missing_state_is_unknown_without_terminal_default(self):
        self.put("job-a")
        def status(host, identity, row):
            del row["state"]
            del row["status_authoritative"]
            del row["launch_nonce_present"]
            del row["supervisor_binding_verified"]
            return row
        result = self.observe(Factory(self.members, status=status))
        self.assertTrue(result["membership_complete"])
        self.assertFalse(result["status_observation_complete"])
        self.assertFalse(result["status_authoritative_complete"])
        self.assertFalse(result["bindings_complete"])
        self.assertFalse(result["jobs_complete"])
        self.assertEqual(result["jobs"][0]["state"], "unknown")
        self.assertIsNone(result["jobs"][0]["launch_nonce_present"])
        self.assertFalse(result["jobs"][0]["status_authoritative"])
        self.assertIn("JOB_STATUS_INCOMPLETE", result["holds"])

    def test_authoritative_and_bindings_strict_true(self):
        self.put("job-a")
        for value in (False, 1, "true", None):
            def status(host, identity, row):
                row.update(status_authoritative=value, launch_nonce_present=value, supervisor_binding_verified=value)
                return row
            with self.subTest(value_type=type(value).__name__):
                result = self.observe(Factory(self.members, status=status))
                self.assertTrue(result["membership_complete"])
                self.assertTrue(result["status_observation_complete"])
                self.assertFalse(result["status_authoritative_complete"])
                self.assertFalse(result["bindings_complete"])
                self.assertFalse(result["jobs_complete"])
                self.assertEqual(result["jobs"][0]["state"], "completed")

    def test_legacy_launch_record_never_skips_status_rpc(self):
        self.put("job-a")
        def listing(host, rows):
            for row in rows:
                row.update(state="completed", status_authoritative=True)
            return {"jobs": rows}
        result = self.observe(Factory(self.members, listing=listing, status=lambda h, i, row: {"id": i, "host": h}))
        self.assertEqual(result["jobs"][0]["state"], "unknown")
        self.assertFalse(result["jobs_complete"])

    def test_audited_native_hostless_job_id_succeeded_response(self):
        self.put("job-a")
        def status(host, identity, row):
            row["job_id"] = row.pop("id")
            del row["host"]
            row["state"] = "succeeded"
            # Actual legacy responses may lack these; matching request identity
            # supplies host binding only, never invents authority/nonce flags.
            del row["status_authoritative"]
            del row["launch_nonce_present"]
            del row["supervisor_binding_verified"]
            return row
        result = self.observe(Factory(self.members, status=status))
        self.assertTrue(result["membership_complete"])
        self.assertTrue(result["status_observation_complete"])
        self.assertEqual(result["jobs"][0]["state"], "succeeded")
        self.assertEqual(result["jobs"][0]["host"], "main")
        self.assertFalse(result["status_authoritative_complete"])
        self.assertFalse(result["bindings_complete"])
        self.assertFalse(result["jobs_complete"])

    def test_unregistered_id_blocks_status_calls_for_host(self):
        self.put("job-a")
        def listing(host, rows):
            if host == "main": rows.append({"id": "unregistered", "host": host})
            return {"jobs": rows}
        factory = Factory(self.members, listing=listing)
        result = self.observe(factory)
        self.assertFalse(result["membership_complete"])
        self.assertFalse(any(tool == "process_status" for _, tool, _, _, _ in factory.calls))
        self.assertEqual({row["id"] for row in result["jobs"]}, {"job-a", "unregistered"})
        self.assertTrue(all(row["state"] == "unknown" for row in result["jobs"]))

    def test_six_host_aggregate_overflow_blocks_all_unregistered_status_calls(self):
        self.put("job-a")
        def listing(host, rows):
            return {"jobs": [{"id": host + "-unknown-%05d" % n, "host": host} for n in range(M.MAX_RECORDS)]}
        factory = Factory(self.members, listing=listing)
        result = self.observe(factory)
        self.assertFalse(result["membership_complete"])
        self.assertFalse(result["jobs_complete"])
        self.assertLessEqual(len(result["jobs"]), M.MAX_RECORDS)
        self.assertFalse(any(tool == "process_status" for _, tool, _, _, _ in factory.calls))
        self.assertTrue(any(row["error_type"] == "InventoryOverflow" for row in result["errors"]))

    def test_duplicate_and_mismatched_host_listings(self):
        self.put("job-a")
        for variant in ("duplicate", "wrong-host", "alias-id", "bad-type", "missing-host"):
            def listing(host, rows):
                if rows:
                    if variant == "duplicate": rows = rows + rows
                    elif variant == "wrong-host": rows[0]["host"] = "rog"
                    elif variant == "alias-id": rows[0]["job_id"] = "different"
                    elif variant == "bad-type": rows[0]["id"] = []
                    else: del rows[0]["host"]
                return {"jobs": rows}
            with self.subTest(variant=variant):
                result = self.observe(Factory(self.members, listing=listing))
                self.assertFalse(result["membership_complete"])
                self.assertFalse(result["jobs_complete"])
                self.assertEqual(result["jobs"][0]["state"], "unknown")

    def test_cross_host_duplicate(self):
        self.put("job-a")
        def listing(host, rows):
            if host == "rog": rows.append({"id": "job-a", "host": "rog"})
            return {"jobs": rows}
        result = self.observe(Factory(self.members, listing=listing))
        self.assertFalse(result["membership_complete"])
        self.assertTrue(any(row["error_type"] == "DuplicateIdentity" for row in result["errors"]))

    def test_status_wrong_id_or_host_or_badstate(self):
        self.put("job-a")
        for field, value in (("id", "different"), ("host", "rog"), ("state", []), ("state", "pretend_terminal")):
            def status(host, identity, row):
                row[field] = value
                return row
            with self.subTest(field=field):
                result = self.observe(Factory(self.members, status=status))
                self.assertEqual(result["jobs"][0]["state"], "unknown")
                self.assertFalse(result["status_observation_complete"])

    def test_unreviewed_killed_stopped_states_are_unknown(self):
        self.put("job-a")
        for state in ("killed", "stopped"):
            def status(host, identity, row):
                row["state"] = state
                return row
            result = self.observe(Factory(self.members, status=status))
            self.assertEqual(result["jobs"][0]["state"], "unknown")
            self.assertFalse(result["status_observation_complete"])
            self.assertFalse(result["jobs_complete"])

    def test_explicit_pagination_incomplete_not_overridden_by_registry(self):
        self.put("job-a")
        for extra in ({"has_more": True}, {"has_more": 0}, {"inventory_complete": False}, {"nextCursor": "cursor"}):
            def listing(host, rows):
                return dict(jobs=rows, **extra)
            result = self.observe(Factory(self.members, listing=listing))
            self.assertFalse(result["membership_complete"])

    def test_registry_mutates_between_before_after_and_status_truth_separate(self):
        path = self.put("job-a")
        factory = Factory(self.members, after_status=lambda h, i: path.touch())
        result = self.observe(factory)
        self.assertFalse(result["membership_complete"])
        self.assertTrue(result["status_observation_complete"])
        self.assertFalse(result["jobs_complete"])
        self.assertTrue(any(row["error_type"] == "RegistryChanged" for row in result["errors"]))

    def test_unknown_entry_prevents_all_calls_and_retains_partial(self):
        self.put("aaa")
        (self.jobs / "zzz").write_text(SECRET)
        factory = Factory(self.members)
        result = self.observe(factory)
        self.assertEqual(factory.created, [])
        self.assertEqual(result["jobs"][0]["id"], "aaa")
        self.assertEqual(result["jobs"][0]["state"], "unknown")
        self.assertFalse(result["membership_complete"])

    def test_factory_cannot_return_differently_bound_credential(self):
        self.put("job-a")
        original = Factory(self.members)
        def factory(host, deadline, pin):
            client = original(host, deadline, pin)
            client.expected_credential_identity = (pin[0], pin[1] + 1)
            return client
        result = self.observe(factory)
        self.assertFalse(result["membership_complete"])
        self.assertFalse(result["jobs_complete"])
        self.assertEqual(original.calls, [])

    def test_exception_text_and_payload_never_public_or_stdout(self):
        self.populate(6)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = self.observe(Factory(self.members, fail_host="main"))
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertTrue(any(row["error_type"] == "ReadFailure" for row in result["errors"]))

    def test_deadline_zero_submits_no_client_or_rpc(self):
        self.put("job-a")
        factory = Factory(self.members)
        result = M.observe_inventory(str(self.jobs), factory, credential_identity=self.credential_identity, budget_seconds=0)
        self.assertEqual(factory.created, [])
        self.assertEqual(factory.calls, [])
        self.assertFalse(result["jobs_complete"])

    def test_partial_deadline_no_new_call_unobserved_ids_unknown(self):
        self.populate(60)
        now = [0.0]
        lock = threading.Lock()
        def clock():
            with lock: return now[0]
        def advance(host, identity):
            with lock: now[0] += 0.4
        factory = Factory(self.members, after_status=advance)
        result = M.observe_inventory(str(self.jobs), factory, credential_identity=self.credential_identity, budget_seconds=1, clock=clock)
        statuses = [call for call in factory.calls if call[1] == "process_status"]
        self.assertGreater(len(statuses), 0)
        self.assertLess(len(statuses), len(self.members))
        self.assertTrue(all(call[4] > 0 for call in factory.calls))
        self.assertEqual({row["id"] for row in result["jobs"]}, set(self.members))
        unknowns = [row for row in result["jobs"] if not row["status_observed"]]
        self.assertTrue(unknowns)
        self.assertTrue(all(row["state"] == "unknown" and row["status_authoritative"] is False for row in unknowns))
        self.assertFalse(result["status_observation_complete"])
        self.assertFalse(result["jobs_complete"])

    def test_inflight_not_falsely_claimed_killed_or_complete(self):
        self.put("job-a")
        release = threading.Event()
        class SlowFactory(Factory):
            def __call__(self, host, deadline, credential_identity):
                client = super().__call__(host, deadline, credential_identity)
                original = client.call
                def delayed(name, args, *, timeout_seconds):
                    if host == "main": release.wait(0.3)
                    return original(name, args, timeout_seconds=timeout_seconds)
                client.call = delayed
                return client
        try:
            result = M.observe_inventory(str(self.jobs), SlowFactory(self.members), credential_identity=self.credential_identity, budget_seconds=0.04)
            self.assertFalse(result["jobs_complete"])
            self.assertTrue(any(row["error_type"] == "InFlightAtDeadline" for row in result["errors"]))
        finally:
            release.set()
            time.sleep(0.02)


class FakeSocket:
    def __init__(self): self.timeouts = []
    def settimeout(self, value): self.timeouts.append(value)


class Response:
    def __init__(self, payload=b"", status=200, headers=None):
        self.payload, self.status, self.offset = payload, status, 0
        self.headers = {"Content-Type": "application/json", "Mcp-Session-Id": "fixture-session"}
        if headers: self.headers.update(headers)
    def getheader(self, name): return self.headers.get(name)
    def read1(self, limit):
        value = self.payload[self.offset:self.offset + limit]
        self.offset += len(value)
        return value
    def close(self): pass


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inventory-http-offline-")
        self.addCleanup(self.temp.cleanup)
        self.token = Path(self.temp.name) / "fixture-token"
        self.token.write_text("SYNTHETIC_FIXTURE_TOKEN")
        self.token.chmod(0o600)
        self.credential_identity = M.credential_inode(self.token)
        self.calls, self.connections = [], []
        self.response_hook = None
        self.send_hook = None
        case = self
        class Connection:
            def __init__(self, host, port, *, timeout):
                case.assertEqual((host, port), ("127.0.0.1", 8790))
                self.sock, self.timeout, self.closed = FakeSocket(), timeout, False
                self.sent_timeouts = []
                case.connections.append(self)
            def connect(self): pass
            def send(self, data):
                self.sent_timeouts.append(self.sock.timeouts[-1])
                if case.send_hook: case.send_hook(data)
            def request(self, method, path, *, body, headers):
                case.assertEqual((method, path), ("POST", "/mcp"))
                self.req = json.loads(body)
                self.headers = headers
                case.calls.append((self.req, dict(headers)))
                self.send(b"FIXTURE_HEADERS")
                self.send(body)
            def getresponse(self):
                request = self.req
                if request["method"] == "notifications/initialized":
                    response = Response(b"", status=202)
                else:
                    result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fixture", "version": "1"}}
                    if request["method"] == "tools/call":
                        result = {"content": [{"type": "text", "text": json.dumps({"jobs": [], "private": SECRET})}], "isError": False}
                    response = Response(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode())
                return case.response_hook(request, response) if case.response_hook else response
            def close(self): self.closed = True
        self.patch = mock.patch.object(M.http.client, "HTTPConnection", Connection)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def client(self, host="main", deadline=None, rpc_timeout=1):
        return M.LoopbackReadClient(self.token, token_reader=lambda _: "FIXTURE_TOKEN",
                                    host=host, deadline=deadline or M.Deadline(10), rpc_timeout=rpc_timeout,
                                    expected_credential_identity=self.credential_identity)

    def test_fixed_endpoint_header_matching_sequence_and_no_mutation(self):
        with mock.patch.dict(os.environ, {"http_proxy": "http://invalid-proxy", "HTTP_PROXY": "http://invalid-proxy"}):
            client = self.client()
            result = client.call("process_list", {"host": "main"})
            self.assertEqual(result["jobs"], [])
            count = len(self.calls)
            for tool in ("process_start", "process_cancel", "host_signal", "shell_start", "service_start", "stream_handoff_write"):
                with self.assertRaises(M.InventoryError):
                    client.call(tool, {"host": "main"})
            client.close()
            self.assertEqual(len(self.calls), count)
        self.assertEqual([row[0].get("id") for row in self.calls], [1, None, 3])
        self.assertEqual(self.calls[0][1]["MCP-Protocol-Version"], "2025-06-18")
        self.assertEqual(self.calls[0][1]["X-Hepta-Runtime-Token"], "FIXTURE_TOKEN")
        self.assertEqual(self.calls[2][1]["Mcp-Session-Id"], "fixture-session")
        self.assertTrue(all(conn.closed for conn in self.connections))
        self.assertLessEqual(max(self.connections[2].sock.timeouts), 1)

    def test_independent_sessions_and_sequence_per_host(self):
        a, b = self.client("main"), self.client("rog")
        self.assertIsNot(a, b)
        a.call("process_list", {"host": "main"}); b.call("process_list", {"host": "rog"})
        self.assertEqual([request.get("id") for request, _ in self.calls], [1, None, 1, None, 3, 3])
        a.close(); b.close()

    def test_redirect_id_boolean_duplicate_json_session_changes_rejected(self):
        for variant in ("redirect", "id", "bool-id", "duplicates", "session"):
            with self.subTest(variant=variant):
                client = self.client()
                def hook(request, response):
                    if request["method"] != "tools/call": return response
                    if variant == "redirect": response.status = 302
                    elif variant == "session": response.headers["Mcp-Session-Id"] = "changed"
                    elif variant == "duplicates": response.payload = b'{"jsonrpc":"2.0","id":3,"id":3,"result":{}}'
                    else:
                        response.payload = json.dumps({"jsonrpc": "2.0", "id": True if variant == "bool-id" else 999, "result": {}}).encode()
                    return response
                self.response_hook = hook
                with self.assertRaises(M.InventoryError) as captured:
                    client.call("process_list", {"host": "main"})
                self.assertNotIn(SECRET, str(captured.exception))
                client.close()
                self.response_hook = None

    def test_32mib_overflow_fixed_cap_content_length_and_actual_bytes(self):
        self.assertEqual(M.HTTP_MAX_BYTES, 32 * 1024 * 1024)
        for announced in (True, False):
            with self.subTest(announced=announced):
                client = self.client(rpc_timeout=10)
                def hook(request, response):
                    if request["method"] == "tools/call":
                        response.payload = b"x" * (M.HTTP_MAX_BYTES + 1)
                        if announced: response.headers["Content-Length"] = str(len(response.payload))
                    return response
                self.response_hook = hook
                with self.assertRaises(M.InventoryError) as captured:
                    client.call("process_list", {"host": "main"})
                self.assertEqual(captured.exception.code, "HTTPOverflow")
                client.close(); self.response_hook = None

    def test_http_large_json_655kb_and_sse_matching(self):
        client = self.client(rpc_timeout=10)
        def hook(request, response):
            if request["method"] == "tools/call":
                value = {"jobs": [], "private": SECRET * 14000}
                rpc = {"jsonrpc": "2.0", "id": request["id"], "result": {"content": [{"type": "text", "text": json.dumps(value)}]}}
                response.payload = ("data: " + json.dumps(rpc) + "\n\n").encode()
                response.headers["Content-Type"] = "text/event-stream"
            return response
        self.response_hook = hook
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(client.call("process_list", {"host": "main"})["jobs"], [])
        self.assertEqual(output.getvalue(), "")
        client.close()

    def test_type_sensitive_structured_content_and_nonfinite_faults(self):
        for text_value, structured_value in ((True, 1), (1, 1.0), ([True], [1]), ({"a": True}, {"a": 1})):
            with self.subTest(text_type=type(text_value).__name__):
                client = self.client()
                def hook(request, response):
                    if request["method"] == "tools/call":
                        rpc = {"jsonrpc": "2.0", "id": request["id"], "result": {
                            "content": [{"type": "text", "text": json.dumps({"value": text_value})}],
                            "structuredContent": {"value": structured_value}}}
                        response.payload = json.dumps(rpc).encode()
                    return response
                self.response_hook = hook
                with self.assertRaises(M.InventoryError): client.call("process_list", {"host": "main"})
                client.close(); self.response_hook = None
        client = self.client()
        def nonfinite(request, response):
            if request["method"] == "tools/call":
                response.payload = ('{"jsonrpc":"2.0","id":' + str(request["id"]) + ',"result":{"private":1e999}}').encode()
            return response
        self.response_hook = nonfinite
        with self.assertRaises(M.InventoryError): client.call("process_list", {"host": "main"})
        client.close()

    def test_wrong_host_notify_or_rpc_refused_without_requests(self):
        client = self.client()
        count = len(self.calls)
        for invoke in (lambda: client.call("process_list", {"host": "rog"}),
                       lambda: client.rpc("DELETE", {}),
                       lambda: client.rpc("tools/list", {}, notify=True)):
            with self.assertRaises(M.InventoryError): invoke()
        self.assertEqual(len(self.calls), count)
        client.close()

    def test_token_reader_exception_never_retains_private_message(self):
        def failing_reader(_): raise RuntimeError(SECRET)
        with self.assertRaises(M.InventoryError) as captured:
            M.LoopbackReadClient(self.token, token_reader=failing_reader, host="main", deadline=M.Deadline(10), expected_credential_identity=self.credential_identity)
        self.assertEqual(captured.exception.code, "ReadFailure")
        self.assertNotIn(SECRET, str(captured.exception))
        self.assertEqual(self.calls, [])

    def replace_token(self):
        replacement = self.token.with_name("fixture-replacement")
        replacement.write_text("ROTATED_SYNTHETIC_TOKEN")
        replacement.chmod(0o600)
        os.replace(replacement, self.token)

    def test_required_credential_pin_none_wrong_pin_no_reader_or_http(self):
        reader = mock.Mock(return_value="FIXTURE_TOKEN")
        for pin in (None, (0, 0), (self.credential_identity[0], self.credential_identity[1] + 1)):
            with self.assertRaises(M.InventoryError):
                M.LoopbackReadClient(self.token, token_reader=reader, host="main", deadline=M.Deadline(10),
                                    expected_credential_identity=pin)
        reader.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_token_reader_time_inode_replacement_no_http(self):
        def reader(_):
            self.replace_token()
            return "FIXTURE_TOKEN"
        with self.assertRaises(M.InventoryError) as captured:
            M.LoopbackReadClient(self.token, token_reader=reader, host="main", deadline=M.Deadline(10),
                                expected_credential_identity=self.credential_identity)
        self.assertEqual(captured.exception.code, "CredentialChanged")
        self.assertEqual(self.calls, [])

    def test_rotation_or_same_inode_update_before_rpc_no_new_http(self):
        client = self.client()
        count = len(self.calls)
        self.replace_token()
        with self.assertRaises(M.InventoryError) as captured:
            client.call("process_list", {"host": "main"})
        self.assertEqual(captured.exception.code, "CredentialChanged")
        self.assertEqual(len(self.calls), count)
        client.close()
        self.credential_identity = M.credential_inode(self.token)
        client = self.client()
        count = len(self.calls)
        self.token.write_text("SAME_INODE_SYNTHETIC_ROTATION")
        with self.assertRaises(M.InventoryError) as captured:
            client.call("process_list", {"host": "main"})
        self.assertEqual(captured.exception.code, "CredentialChanged")
        self.assertEqual(len(self.calls), count)
        client.close()

    def test_socket_timeout_remaining_budget_and_per_rpc_budget(self):
        now = [0.0]
        deadline = M.Deadline(0.6, clock=lambda: now[0])
        client = self.client(deadline=deadline, rpc_timeout=0.5)
        def hook(request, response):
            if request["method"] == "tools/call":
                original = response.read1
                def advance(limit):
                    now[0] += 0.3
                    chunk = original(limit)
                    return chunk if chunk else b" "
                response.read1 = advance
            return response
        self.response_hook = hook
        with self.assertRaises(M.InventoryError) as captured:
            client.call("process_list", {"host": "main"})
        self.assertEqual(captured.exception.code, "DeadlineExpired")
        self.assertTrue(all(timeout <= 0.6 for conn in self.connections for timeout in conn.sock.timeouts))
        self.assertLessEqual(max(self.connections[-1].sock.timeouts), 0.5)
        count = len(self.calls)
        with self.assertRaises(M.InventoryError): client.call("process_list", {"host": "main"})
        self.assertEqual(count, len(self.calls))
        client.close()

    def test_trickling_statusline_headers_chunk_size_trailers_deadline(self):
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        payload = header + b"000001\r\nx\r\n0\r\nX-Fixture: safe\r\n\r\n"
        offsets = {"statusline": 0, "headers": len(b"HTTP/1.1 200 OK\r\n"),
                   "chunk_size": len(header), "trailers": len(header) + len(b"000001\r\nx\r\n0\r\n")}
        for phase, offset in offsets.items():
            with self.subTest(phase=phase):
                now = [0.0]
                deadline = M.Deadline(0.35, clock=lambda: now[0])
                class TricklingRaw(io.BytesIO):
                    def readinto(self, buffer):
                        if self.tell() >= offset: now[0] += 0.1
                        chunk = self.read(1)
                        buffer[:len(chunk)] = chunk
                        return len(chunk)
                class Socket(FakeSocket):
                    def makefile(self, mode, buffering=-1):
                        return TricklingRaw(payload) if buffering == 0 else io.BytesIO(payload)
                sock = Socket()
                response = M._DeadlineHTTPResponse(sock, remaining=lambda: deadline.timeout(0.35))
                try:
                    with self.assertRaises(M.InventoryError) as captured:
                        response.begin()
                        if phase == "trailers": self.assertEqual(response.read1(16), b"x")
                        response.read1(16)
                    self.assertEqual(captured.exception.code, "DeadlineExpired")
                    self.assertLessEqual(now[0], 0.4 + 1e-9)
                    self.assertTrue(all(value > 0 and value <= 0.35 for value in sock.timeouts))
                finally:
                    response.close()

    def test_multiple_send_calls_each_get_remaining_total_timeout(self):
        now = [0.0]
        deadline = M.Deadline(0.5, clock=lambda: now[0])
        client = self.client(deadline=deadline, rpc_timeout=0.5)
        def delayed_send(data): now[0] += 0.3
        self.send_hook = delayed_send
        with self.assertRaises(M.InventoryError) as captured:
            client.call("process_list", {"host": "main"})
        self.assertEqual(captured.exception.code, "DeadlineExpired")
        self.assertEqual(len(self.connections[-1].sent_timeouts), 2)
        self.assertAlmostEqual(self.connections[-1].sent_timeouts[0], 0.5)
        self.assertAlmostEqual(self.connections[-1].sent_timeouts[1], 0.2)
        count = len(self.calls)
        with self.assertRaises(M.InventoryError): client.call("process_list", {"host": "main"})
        self.assertEqual(len(self.calls), count)
        client.close()

    def test_bounded_response_standard_header_and_body_parse_memory_only(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        class Socket(FakeSocket):
            def makefile(self, mode, buffering=-1): return io.BytesIO(payload)
        sock = Socket()
        response = M._DeadlineHTTPResponse(sock, remaining=lambda: 1)
        try:
            response.begin()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read1(32), b"{}")
        finally:
            response.close()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", required=True, help="new output directory; previous runs retained")
    args = parser.parse_args()
    destination = Path(args.results_dir).resolve()
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    bound_files = [SOURCE, Path(__file__).resolve()]
    before = {str(path.relative_to(ROOT)): digest(path) for path in bound_files}
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    started = time.monotonic()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    elapsed = time.monotonic() - started
    raw = stream.getvalue()
    # Fixtures contain no real secrets. Still reject accidental fixture payload output.
    if SECRET in raw:
        raise RuntimeError("fixture-private-payload appeared in runner output")
    (destination / "raw_unittest.txt").write_text(raw)
    after = {str(path.relative_to(ROOT)): digest(path) for path in bound_files}
    summary = {"scope": "offline_jobs_registry_status_and_mock_http_only", "production_observation": False,
        "endpoint_contacted": False, "real_credentials_read": False, "service_control": False,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "seconds": round(elapsed, 4), "passed": result.wasSuccessful(), "inputs_before": before,
        "inputs_after": after, "inputs_unchanged": before == after,
        "raw_results_sha256": digest(destination / "raw_unittest.txt"),
        "untested": ["actual_server_http_behavior", "production_inventory", "PTY_pagination",
                     "stream_registry_completeness", "dispatch_admission_freeze", "same_UID_adversarial_writers"]}
    (destination / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0 if result.wasSuccessful() and before == after else 1


if __name__ == "__main__":
    raise SystemExit(main())
