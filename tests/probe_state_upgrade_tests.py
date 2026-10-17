#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Adversarial offline upgrade-probe tests; no production endpoints or effects."""
import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import probe_state_upgrade as P

JOB = "1a13acafe00-b2f-134a"
PTY = "dpty-abcdef0123"
STREAM = "stream-" + "a" * 64


def job_record(identity=JOB, host="main"):
    return {"id": identity, "host": host, "execution_mode": "operator", "system_jobctl": False,
            "ssh_target": "local-alias", "unit": "hepta-job-" + identity,
            "remote_job_dir": "/private/jobs/" + identity, "executable": "/usr/bin/true", "args": [],
            "cwd": None, "env_keys": [], "created_unix_ms": 1,
            "idempotency_key": "DO-NOT-EMIT-PRIVATE-KEY", "request_fingerprint": 1,
            "request_digest": "b" * 64, "launch_state": "launched", "launch_error": None}


def terminal_record():
    return {"session_id": PTY, "host": "main", "ssh_target": "local-alias", "remote_state_dir": "/private",
            "job_dir": "/private/terminals/" + PTY, "request": {"session_id": PTY}}


def write(path, value, mode=0o600):
    path.write_text(json.dumps(value))
    path.chmod(mode)


def archive(data=b"abc", *, maximum=None):
    data = data if maximum is None else data[:maximum]
    return {"offset": 0, "next_offset": len(data), "size": 3, "bytes_hex": data.hex(),
            "text": data.decode(), "eof": len(data) == 3}


class FakeClient:
    def __init__(self, *, job_ids=(JOB,), terminals=(PTY,), streams=(STREAM,), newer=False,
                 active=False, corrupt=False):
        self.job_ids, self.terminals, self.streams = list(job_ids), list(terminals), list(streams)
        self.newer, self.active, self.corrupt = newer, active, corrupt
        self.calls = []

    def call(self, name, arguments):
        if name not in P.READ_TOOLS:
            raise AssertionError("effect attempted")
        self.calls.append((name, arguments))
        if name == "host_list":
            return {"hosts": [{"name": "main"}]}
        if name == "process_list":
            if arguments != {"host": "main"}:
                raise AssertionError("unsharded job inventory")
            rows = [{"id": item, "host": "main"} for item in self.job_ids]
            return {"jobs": rows, "total": len(rows), "inventory_complete": True} if self.newer else {"jobs": rows}
        if name == "pty_list":
            after = arguments.get("after_session_id", "")
            identities = [item for item in sorted(self.terminals) if item > after]
            page = identities[:arguments["limit"]]
            more = len(identities) > len(page)
            return {"sessions": [{"session_id": item, "host": "main", "persistent_across_runtime_restart": True}
                                  for item in page], "has_more": more,
                    "next_after_session_id": page[-1] if more else None}
        if name == "stream_handoff_list":
            return {"sessions": [{"session_id": item} for item in self.streams]}
        if name == "process_status":
            result = {"job_id": arguments["job_id"], "state": "owner_unknown" if self.active else "succeeded", "exit_code": 0}
            if self.newer:
                result["audit_recorded"] = True
            return result
        if name == "process_read":
            result = {"job_id": arguments["job_id"], "stdout": archive(b"abd" if self.corrupt else b"abc"), "stderr": archive()}
            if self.newer:
                result["audit_recorded"] = True
            return result
        if name == "pty_read":
            page = archive(maximum=arguments["limit"])
            page["available_end"] = page.pop("size")
            page["status"] = {"state": "exited", "output_complete": True}
            return page
        if name == "stream_handoff_status":
            return {"state": "exited", "output_complete": True, "session_id": arguments["session_id"]}
        if name == "stream_handoff_read":
            return {"data_base64": "YWJj", "offset": 0, "next_offset": 3, "available_end": 3,
                    "chunk_sha256": hashlib.sha256(b"abc").hexdigest(), "output_complete": True}
        raise AssertionError(name)


class UpgradeProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-state-probe-")
        self.base = pathlib.Path(self.temp.name)
        self.state = self.base / "state"
        self.state.mkdir(mode=0o700)
        for kind in ("jobs", "terminals", "stream_handoffs"):
            (self.state / kind).mkdir(mode=0o700)
        write(self.state / "jobs" / (JOB + ".json"), job_record())
        write(self.state / "terminals" / (PTY + ".json"), terminal_record())
        folder = self.state / "stream_handoffs" / STREAM
        folder.mkdir(mode=0o700)
        write(folder / "request.json", {"session_id": STREAM, "application_identities": []})
        write(folder / "final.json", {"session_id": STREAM, "state": "exited", "output_complete": True})
        (folder / "stdout.log").write_bytes(b"abc")
        (folder / "stdout.log").chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        candidate = self.base / "candidate"
        shutil.copytree(self.state, candidate)
        return candidate

    def test_old_idempotency_unique_and_secret_free_but_no_cutover(self):
        report=P.audit_legacy_idempotency(self.state)
        self.assertTrue(report["complete"],report)
        self.assertEqual(report["total_valid_jobs"],1)
        self.assertEqual(report["keyed_jobs"],1)
        self.assertEqual(report["unique_host_keys"],1)
        self.assertFalse(report["cutover_eligible"])
        self.assertNotIn("DO-NOT-EMIT-PRIVATE-KEY",repr(report))
        self.assertFalse(report["cross_generation_replay_filter_installed"])

    def test_old_idempotency_duplicate_host_key_blocks_readiness(self):
        other="1a13acafe00-b2f-135b"
        write(self.state/"jobs"/(other+".json"),job_record(identity=other))
        report=P.audit_legacy_idempotency(self.state)
        self.assertFalse(report["complete"])
        self.assertIn("same_host_idempotency_collision",report["issues"])
        self.assertEqual(report["unique_host_keys"],1)

    def test_old_idempotency_same_key_on_separate_host_is_valid(self):
        other="1a13acafe00-b2f-135b"
        write(self.state/"jobs"/(other+".json"),job_record(identity=other,host="mac"))
        report=P.audit_legacy_idempotency(self.state)
        self.assertTrue(report["complete"],report)
        self.assertEqual(report["unique_host_keys"],2)

    def test_old_idempotency_missing_digest_must_hold(self):
        original=job_record();original["request_digest"]=None
        write(self.state/"jobs"/(JOB+".json"),original)
        report=P.audit_legacy_idempotency(self.state)
        self.assertFalse(report["complete"])
        self.assertIn("legacy_key_without_full_digest",report["issues"])

    def test_old_idempotency_temporary_metadata_refused(self):
        write(self.state/"jobs"/(JOB+".json.tmp.123"),job_record())
        report=P.audit_legacy_idempotency(self.state)
        self.assertFalse(report["complete"])
        self.assertIn("temporary_or_unknown_registry_entry",report["issues"])

    def test_old_idempotency_missing_key_is_counted_not_proven(self):
        original=job_record();original["idempotency_key"]=None
        write(self.state/"jobs"/(JOB+".json"),original)
        report=P.audit_legacy_idempotency(self.state)
        self.assertTrue(report["complete"])
        self.assertEqual(report["jobs_without_key"],1)
        self.assertFalse(report["cutover_eligible"])

    def test_old_idempotency_cli_never_claims_cutover_and_remains_private(self):
        path=self.base/"idempotency-report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            status=P.main(["--state",str(self.state),
                "--legacy-idempotency","--out",str(path)])
        result=json.loads(path.read_text())
        self.assertEqual(status,2)
        self.assertEqual(result["decision"],"HOLD")
        self.assertTrue(result["legacy_idempotency"]["complete"])
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        self.assertNotIn("DO-NOT-EMIT-PRIVATE-KEY",path.read_text())

    def test_byte_preserving_snapshot_and_secret_free_inventory(self):
        before = {str(p.relative_to(self.state)): p.read_bytes() for p in self.state.rglob("*") if p.is_file()}
        source, candidate = P.inventory(self.state), P.inventory(self.snapshot())
        self.assertTrue(source["complete"], source["issues"])
        self.assertEqual(source["sha256"], candidate["sha256"])
        self.assertEqual([source["registries"][kind]["count"] for kind in source["scope"]], [1, 1, 1])
        self.assertNotIn("DO-NOT-EMIT", json.dumps(source))
        self.assertEqual(before, {str(p.relative_to(self.state)): p.read_bytes() for p in self.state.rglob("*") if p.is_file()})

    def test_changed_snapshot_metadata_is_detected(self):
        candidate = self.snapshot()
        value = job_record()
        value["idempotency_key"] = "different-private-key"
        write(candidate / "jobs" / (JOB + ".json"), value)
        self.assertNotEqual(P.inventory(self.state)["sha256"], P.inventory(candidate)["sha256"])

    def test_temporary_metadata_is_classified_and_holds(self):
        write(self.state / "jobs" / (JOB + ".json.tmp.123"), job_record())
        result = P.inventory(self.state)
        self.assertFalse(result["complete"])
        self.assertEqual(result["registries"]["jobs"]["temporary_count"], 1)
        self.assertIn("temporary_metadata_requires_reconciliation", [item["reason"] for item in result["issues"]])

    def test_unknown_entry_name_is_hashed_without_echoing_it(self):
        write(self.state / "jobs" / "PRIVATE-UNKNOWN-NAME", {})
        result = P.inventory(self.state)
        self.assertFalse(result["complete"])
        self.assertNotIn("PRIVATE-UNKNOWN-NAME", json.dumps(result))

    def test_duplicate_json_keys_refuse(self):
        path = self.state / "jobs" / (JOB + ".json")
        path.write_text('{"id":"' + JOB + '","host":"main","host":"rog"}')
        result = P.inventory(self.state)
        self.assertFalse(result["complete"])
        self.assertEqual(result["issues"][0]["reason"], "duplicate_json_key")

    def test_symlink_hardlink_and_fifo_never_become_records(self):
        for shape in ("symlink", "hardlink", "fifo"):
            with self.subTest(shape=shape):
                path = self.state / "jobs" / (JOB + ".json")
                raw = path.read_bytes()
                path.unlink()
                target = self.base / "target"
                target.write_bytes(raw)
                target.chmod(0o600)
                if shape == "symlink":
                    path.symlink_to(target)
                elif shape == "hardlink":
                    os.link(target, path)
                else:
                    os.mkfifo(path, 0o600)
                self.assertFalse(P.inventory(self.state)["complete"])
                path.unlink()
                target.unlink()
                path.write_bytes(raw)
                path.chmod(0o600)

    def test_private_root_and_metadata_modes_are_required(self):
        self.state.chmod(0o750)
        self.assertFalse(P.inventory(self.state)["complete"])
        self.state.chmod(0o700)
        (self.state / "jobs" / (JOB + ".json")).chmod(0o640)
        self.assertFalse(P.inventory(self.state)["complete"])

    def test_wrong_identity_and_metadata_type_hold(self):
        for change in ({"id": "1-2-3"}, {"request_fingerprint": True}, {"request_digest": "invalid"}):
            with self.subTest(change=change):
                write(self.state / "jobs" / (JOB + ".json"), {**job_record(), **change})
                self.assertFalse(P.inventory(self.state)["complete"])

    def test_stream_special_or_temporary_artifact_holds(self):
        folder = self.state / "stream_handoffs" / STREAM
        write(folder / "state.json.new-123", {})
        self.assertFalse(P.inventory(self.state)["complete"])
        (folder / "state.json.new-123").unlink()
        os.mkfifo(folder / "stderr.log", 0o600)
        self.assertFalse(P.inventory(self.state)["complete"])

    def test_native_pagination_and_host_sharding_are_complete(self):
        ids = [f"dpty-{index:064x}" for index in range(130)]
        client = FakeClient(terminals=ids)
        result = P.native_membership(client)
        self.assertEqual(len(result["terminals"]), 130)
        self.assertEqual(sum(name == "pty_list" for name, _ in client.calls), 2)
        self.assertEqual(result["jobs"], [("main", JOB)])

    def test_nonprogressing_native_cursor_refuses(self):
        client = FakeClient()
        original = client.call
        def call(name, arguments):
            result = original(name, arguments)
            if name == "pty_list":
                result.update(has_more=True, next_after_session_id="not-the-last-id")
            return result
        client.call = call
        with self.assertRaisesRegex(P.ProbeError, "nonprogressing"):
            P.native_membership(client)

    def test_same_members_and_terminal_bytes_pass_with_audit_addition(self):
        source = P.inventory(self.state)
        old, new = FakeClient(), FakeClient(newer=True)
        result = P.compare_native(old, new, source, source)
        self.assertTrue(result["complete"], result["issues"])
        self.assertEqual(len(result["observations"]), 3)
        self.assertEqual(len(result["archive_samples"]), 3)
        self.assertTrue(all(name in P.READ_TOOLS for name, _ in old.calls + new.calls))

    def test_missing_member_unknown_status_and_archive_difference_hold(self):
        source = P.inventory(self.state)
        for newer in (FakeClient(job_ids=[]), FakeClient(active=True), FakeClient(corrupt=True)):
            with self.subTest(newer=newer):
                result = P.compare_native(FakeClient(), newer, source, source)
                self.assertFalse(result["complete"])

    def test_partial_observation_coverage_holds(self):
        source = P.inventory(self.state)
        source["registries"]["jobs"]["records"].append({"id": "1-2-3", "host": "main"})
        result = P.compare_native(FakeClient(job_ids=(JOB, "1-2-3")), FakeClient(job_ids=(JOB, "1-2-3")),
                                  source, source, sample_count=1)
        self.assertFalse(result["complete"])
        self.assertIn("terminal_observation_coverage_incomplete", [row["reason"] for row in result["issues"]])
        result = P.compare_native(FakeClient(job_ids=(JOB, "1-2-3")), FakeClient(job_ids=(JOB, "1-2-3")),
                                  source, source, sample_count=1, all_observations=True)
        self.assertTrue(result["complete"], result["issues"])

    def test_invalid_archive_cursor_or_digest_refuses(self):
        for value in ({**archive(), "next_offset": 2}, {**archive(), "offset": 4},
                      {**archive(), "chunk_sha256": "0" * 64}, {**archive(), "truncated_before_offset": True}):
            with self.subTest(value=value):
                with self.assertRaises(P.ProbeError):
                    P.validate_archive_page(value)

    def test_read_client_rejects_effect_without_network(self):
        client = object.__new__(P.ReadClient)
        client.proxy = mock.Mock()
        with self.assertRaisesRegex(P.ProbeError, "outside_read_whitelist"):
            client.call("process_start", {})
        client.proxy.exchange.assert_not_called()

    def test_inventory_only_stays_hold_and_evidence_is_private_nonoverwriting(self):
        path = self.base / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(P.main(["--state", str(self.state), "--out", str(path)]), 2)
        self.assertEqual(json.loads(path.read_text())["decision"], "HOLD")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
            P.main(["--state", str(self.state), "--out", str(path)])

    def test_candidate_cannot_be_the_original_state(self):
        path = self.base / "shared-root-report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = P.main(["--state", str(self.state), "--candidate-state", str(self.state), "--out", str(path)])
        report = json.loads(path.read_text())
        self.assertEqual(code, 2)
        self.assertTrue(report["snapshot_registry_bytes_equal"])
        self.assertFalse(report["independent_snapshot"])
        self.assertEqual(report["decision"], "HOLD")

    def test_metadata_changed_while_reading_is_rejected(self):
        original = P.os.read
        changed = False
        def read(fd, count):
            nonlocal changed
            data = original(fd, count)
            if not changed:
                changed = True
                path = self.state / "jobs" / (JOB + ".json")
                with path.open("ab") as stream:
                    stream.write(b" ")
            return data
        with mock.patch.object(P.os, "read", side_effect=read):
            result = P.inventory(self.state)
        self.assertFalse(result["complete"])
        self.assertIn("file_changed_during_read", [row["reason"] for row in result["issues"]])


    def test_shadow_delta_additive_records_qualify_without_cutover(self):
        baseline = P.inventory(self.state)
        candidate_root = self.snapshot()
        added = "1a13acafe00-b2f-134b"
        write(candidate_root / "jobs" / (added + ".json"),
              job_record(identity=added,host="pocket4"))
        current = P.inventory(candidate_root)
        result = P.incremental_shadow_delta(baseline, current)
        self.assertTrue(result["qualified"], result)
        self.assertFalse(result["cutover_eligible"])
        self.assertEqual(result["registries"]["jobs"]["added"],1)
        self.assertEqual(result["registries"]["jobs"]["added_by_host"],{"pocket4":1})
        self.assertEqual(result["registries"]["jobs"]["missing"],0)
        self.assertEqual(result["registries"]["jobs"]["rewritten"],0)
        self.assertEqual(result["registries"]["terminals"]["unchanged"],1)
        self.assertEqual(result["registries"]["stream_handoffs"]["unchanged"],1)
        self.assertNotIn("DO-NOT-EMIT-PRIVATE-KEY",repr(result))
        self.assertNotIn(added,repr(result))

    def test_shadow_delta_removed_or_rewritten_existing_job_refuses(self):
        baseline = P.inventory(self.state)
        for operation in ("remove","rewrite"):
            with self.subTest(operation=operation):
                root=self.snapshot() if operation=="remove" else self.base / "changed"
                if operation=="rewrite":
                    shutil.copytree(self.state,root)
                path=root / "jobs" / (JOB + ".json")
                if operation=="remove":path.unlink()
                else:
                    record=job_record();record["idempotency_key"]="PRIVATE_DIFFERENT_KEY"
                    write(path,record)
                result=P.incremental_shadow_delta(baseline,P.inventory(root))
                self.assertFalse(result["qualified"])
                self.assertFalse(result["cutover_eligible"])
                self.assertIn("missing_existing_record" if operation=="remove" else "rewritten_existing_record",result["issues"])
                self.assertNotIn("PRIVATE_DIFFERENT_KEY",repr(result))

    def test_shadow_delta_retains_terminal_and_stream_custody(self):
        for folder,name in (("terminals",PTY + ".json"),("stream_handoffs",STREAM)):
            with self.subTest(folder=folder):
                baseline=P.inventory(self.state)
                root=self.snapshot() if folder=="terminals" else self.base/"candidate-stream"
                if folder=="stream_handoffs":shutil.copytree(self.state,root)
                p=root/folder/name
                if p.is_dir():shutil.rmtree(p)
                else:p.unlink()
                result=P.incremental_shadow_delta(baseline,P.inventory(root))
                self.assertFalse(result["qualified"])
                self.assertEqual(result["registries"][folder]["missing"],1)

    def test_shadow_delta_changed_stream_bytes_refuse(self):
        baseline=P.inventory(self.state)
        root=self.snapshot()
        (root/"stream_handoffs"/STREAM/"stdout.log").write_bytes(b"DIFFERENT_PRIVATE_OUTPUT")
        result=P.incremental_shadow_delta(baseline,P.inventory(root))
        self.assertFalse(result["qualified"])
        self.assertEqual(result["registries"]["stream_handoffs"]["rewritten"],1)
        self.assertNotIn("DIFFERENT_PRIVATE_OUTPUT",repr(result))

    def test_shadow_delta_incomplete_or_same_root_refuses(self):
        clean=P.inventory(self.state)
        alias=P.incremental_shadow_delta(clean,clean)
        self.assertFalse(alias["qualified"])
        self.assertIn("independent_snapshot_required",alias["issues"])
        root=self.snapshot()
        write(root/"jobs"/(JOB+".json.tmp.123"),job_record())
        invalid=P.incremental_shadow_delta(clean,P.inventory(root))
        self.assertFalse(invalid["qualified"])
        self.assertIn("incomplete_or_untrusted_snapshot",invalid["issues"])

    def test_shadow_delta_cli_remains_hold_and_secret_free(self):
        candidate=self.snapshot()
        new_job="1a13acafe00-b2f-134b"
        write(candidate/"jobs"/(new_job+".json"),job_record(identity=new_job))
        report=self.base/"incremental.json"
        with contextlib.redirect_stdout(io.StringIO()):
            rc=P.main(["--state",str(self.state),"--candidate-state",str(candidate),
                       "--shadow-delta","--out",str(report)])
        result=json.loads(report.read_text())
        self.assertEqual(rc,2)
        self.assertEqual(result["decision"],"HOLD")
        self.assertTrue(result["shadow_delta"]["qualified"])
        self.assertFalse(result["shadow_delta"]["cutover_eligible"])
        self.assertNotIn("DO-NOT-EMIT-PRIVATE-KEY",report.read_text())
        self.assertEqual(report.stat().st_mode & 0o777,0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
