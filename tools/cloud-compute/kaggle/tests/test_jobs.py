import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kaggle_jobs import KaggleAdapter, safe_name, bound_response_ref
from kaggle_transport import AdapterError, RemoteError, scrub, remember_secret


class FakeTransport:
    def __init__(self):
        self.calls = []; self.saved = None; self.username = "tester"
        self.state = "RUNNING"; self.sid = None; self.lose_ack = False
        self.payloads = {}; self.log = ""; self.source_override = None
        self.version = 1; self.private = True; self.tamper_download = False; self.kernel_id = 9
        self.missing_status = 404; self.list_pages = {None: {"kernels": []}}; self.list_error = None
        self.submit_error = None
        self.ack_prefix = ""
        self.provider_sizes = {}; self.http_lengths = {}; self.downloads = []

    def account(self):
        return {"authenticated": True, "username": self.username, "user_id": 42}

    def call(self, action, values, *, mutation=False):
        self.calls.append((action, dict(values), mutation))
        if action == "list":
            if self.list_error: raise self.list_error
            return self.list_pages[values.get("page_token")]
        if action == "get":
            if self.saved is None: raise RemoteError("HTTP_ERROR", "missing or unreadable", status=self.missing_status)
            response = {"metadata": {"ref": self.saved["slug"], "id": self.kernel_id,
                                     "currentVersionNumber": self.version, "isPrivate": self.private},
                        "blob": {"source": self.source_override if self.source_override is not None else self.saved["text"]}}
            if self.sid: response["kernelSessionId"] = self.sid
            return response
        if action == "submit":
            self.saved = dict(values)
            if self.submit_error: raise self.submit_error
            if self.lose_ack: raise RemoteError("TRANSPORT_ERROR", "response lost", ambiguous=True)
            response = {"ref": self.ack_prefix + values["slug"], "versionNumber": self.version, "kernelId": 9}
            if self.sid: response["kernelSessionId"] = self.sid
            return response
        if action == "status": return {"status": self.state}
        if action == "cancel": return {}
        if action == "files": return {"files": [{"name": k, "size": self.provider_sizes.get(k, len(v))} for k, v in self.payloads.items()]}
        if action == "output": return {"files": [{"fileName": k, "url": "https://storage.googleapis.com/example/" + k} for k in self.payloads], "log": self.log}
        raise AssertionError(action)

    def download(self, url, path, *, expected_size, max_bytes, require_content_length=False):
        name = url.split("/example/", 1)[1]
        self.downloads.append(name)
        data = self.payloads[name]
        if len(data) > max_bytes: raise AdapterError("ARTIFACT_BUDGET", "too large")
        if expected_size is not None and len(data) != expected_size: raise AdapterError("ARTIFACT_LENGTH", "wrong expected size")
        path.write_bytes(data + (b"tamper" if self.tamper_download else b""))
        declared = self.http_lengths.get(name, len(data))
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "http_content_length": declared,
                "http_content_length_verified": declared is not None}

    def count(self, action): return sum(x[0] == action for x in self.calls)


class JobsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "main.py"; self.source.write_text("print(2 + 3)\n")
        self.transport = FakeTransport()
        self.adapter = KaggleAdapter(self.transport, self.base / "state")

    def submit(self, request="test-1"):
        return self.adapter.submit(request_id=request, source=self.source, timeout=120)

    def prepare_outputs(self, request="test-1"):
        self.submit(request); self.transport.state = "COMPLETE"
        result = b'{"answer":5}\n'
        manifest = {"schema": "hepta-artifact-manifest-v1", "request_id": request,
                    "files": [{"path": "result.json", "bytes": len(result), "sha256": hashlib.sha256(result).hexdigest()}]}
        self.transport.payloads = {"result.json": result, "hepta-manifest.json": json.dumps(manifest).encode()}

    def test_repeated_submit_never_replays_remote_effect(self):
        a = self.submit(); b = self.submit()
        self.assertEqual(a["notebook_ref"], b["notebook_ref"])
        self.assertTrue(b["reused"])
        self.assertEqual(self.transport.count("submit"), 1)
        self.assertIsNone(a["kernel_session_id"])
        self.assertEqual(a["notebook_version"], 1)

    def test_exact_code_prefixed_ack_is_bound_without_changing_raw_receipt(self):
        self.transport.ack_prefix = "/code/"
        result = self.submit()
        self.assertEqual(result["submission_state"], "ACCEPTED")
        self.assertEqual(result["notebook_ref"], self.transport.saved["slug"])
        original = self.adapter.ledger.submission_responses("test-1")[0][1]
        self.assertEqual(original["ref"], "/code/" + result["notebook_ref"])

    def test_prefixed_durable_ack_recovers_v1_after_latest_v2_without_replay(self):
        self.transport.ack_prefix = "/code/"
        result = self.submit()
        record = self.adapter.ledger.load("test-1")
        record.update(submission_state="UNKNOWN", notebook_version=None, kernel_id=None,
                      remote_submission_state="MAY_HAVE_BEEN_SENT", remote_effect_unknown=True,
                      last_error={"code": "SUBMIT_IDENTITY_INCOMPLETE"})
        self.adapter.ledger.save(record)
        before = len(self.transport.calls)
        self.transport.version = 2
        recovered = self.adapter.resume("test-1")
        self.assertEqual(recovered["notebook_version"], 1)
        self.assertEqual(recovered["notebook_ref"], result["notebook_ref"])
        self.assertTrue(recovered["reconciled"])
        self.assertNotIn("last_error", recovered)
        self.assertEqual(self.transport.count("submit"), 1)
        for action, values, _ in self.transport.calls[before:]:
            self.assertIn(action, {"get", "status"})
            self.assertEqual(values.get("version_label"), "v1")

    def test_prefixed_ack_rejects_query_fragment_encoding_extra_path_or_other_owner(self):
        expected = "tester/exact-notebook"
        for ref in ("/code/" + expected + "?x=1", "/code/" + expected + "#fragment",
                    "/code/tester%2Fexact-notebook", "/code/" + expected + "/v1",
                    "/code/other/exact-notebook", "https://www.kaggle.com/code/" + expected,
                    " /code/" + expected, "/code//" + expected, "/code/tester/../exact-notebook"):
            with self.subTest(ref=ref): self.assertIsNone(bound_response_ref(ref, expected))

    def test_new_reference_403_does_not_need_object_get_permission(self):
        self.transport.missing_status = 403
        result = self.submit()
        self.assertEqual(result["submission_state"], "ACCEPTED")
        self.assertEqual(self.transport.count("get"), 0)
        self.assertEqual(self.transport.count("list"), 1)
        listing = [x[1] for x in self.transport.calls if x[0] == "list"][0]
        self.assertEqual(listing, {"group": "PROFILE", "user": "tester", "language": "all", "kernel_type": "all", "output_type": "all", "page_size": 100})

    def test_profile_pagination_collision_on_later_page_prevents_write(self):
        ref = "tester/hepta-test-1-" + "a" * 24
        self.transport.list_pages = {None: {"kernels": [{"ref": "tester/old-one"}], "nextPageToken": "p2"},
                                     "p2": {"kernels": [{"ref": ref}]}}
        with patch("kaggle_jobs.secrets.token_hex", return_value="a" * 32):
            with self.assertRaises(AdapterError) as ctx: self.submit()
        self.assertEqual(ctx.exception.code, "NOTEBOOK_COLLISION")
        self.assertEqual(self.transport.count("submit"), 0)
        self.assertEqual(self.adapter.ledger.load("test-1")["submission_state"], "REJECTED")

    def test_profile_pagination_must_finish_and_cannot_loop(self):
        self.transport.list_pages = {None: {"kernels": [], "nextPageToken": "same"},
                                     "same": {"kernels": [], "nextPageToken": "same"}}
        with self.assertRaises(AdapterError) as ctx: self.submit()
        self.assertEqual(ctx.exception.code, "NOTEBOOK_LIST_PAGINATION")
        self.assertEqual(self.transport.count("submit"), 0)
        self.assertEqual(self.transport.count("list"), 2)

    def test_incomplete_profile_enumeration_is_rejected_and_never_replayed(self):
        self.transport.list_error = RemoteError("HTTP_ERROR", "permission denied", status=403)
        with self.assertRaises(RemoteError): self.submit()
        self.transport.list_error = None
        again = self.submit()
        self.assertEqual(again["submission_state"], "REJECTED")
        self.assertEqual(self.transport.count("list"), 1)
        self.assertEqual(self.transport.count("submit"), 0)
        self.assertEqual(again["remote_submission_state"], "NOT_SENT")
        self.assertFalse(again["remote_effect_unknown"])

    def test_sent_http_403_is_unknown_even_if_transport_legacy_flag_was_false(self):
        self.transport.submit_error = RemoteError("HTTP_ERROR", "denied", status=403, ambiguous=False)
        with self.assertRaises(RemoteError): self.submit()
        record = self.adapter.ledger.load("test-1")
        self.assertEqual(record["submission_state"], "UNKNOWN")
        self.assertEqual(record["remote_submission_state"], "MAY_HAVE_BEEN_SENT")
        self.assertTrue(record["remote_effect_unknown"])
        self.assertEqual(self.transport.saved["slug"], record["notebook_ref"])
        self.assertIsNone(record["notebook_version"])
        self.transport.submit_error = None
        repeated = self.submit()
        self.assertEqual(repeated["submission_state"], "UNKNOWN")
        self.assertEqual(self.transport.count("submit"), 1)

    def test_old_post_dispatch_rejected_record_cannot_prove_rollback(self):
        self.transport.submit_error = RemoteError("HTTP_ERROR", "denied", status=403, ambiguous=False)
        with self.assertRaises(RemoteError): self.submit()
        record = self.adapter.ledger.load("test-1")
        record.update(submission_state="REJECTED")
        record.pop("remote_submission_state"); record.pop("remote_effect_unknown")
        record["last_error"]["details"]["remote_effect_unknown"] = False
        self.adapter.ledger.save(record)
        result = self.submit()
        self.assertEqual(result["submission_state"], "REJECTED")
        self.assertEqual(result["effective_submission_state"], "UNKNOWN")
        self.assertTrue(result["remote_effect_unknown"])
        self.assertTrue(result["historical_rejection_does_not_prove_rollback"])
        self.assertTrue(result["last_error"]["details"]["remote_effect_unknown"])
        # Preserve historical evidence rather than silently rewriting old entries.
        self.assertFalse(self.adapter.ledger.load("test-1")["last_error"]["details"]["remote_effect_unknown"])
        self.assertEqual(self.transport.count("submit"), 1)

    def test_profile_pagination_complete_before_save_and_nonce_persisted(self):
        self.transport.list_pages = {None: {"kernels": [{"ref": "tester/old-one"}], "nextPageToken": "p2"},
                                     "p2": {"kernels": [{"ref": "tester/old-two"}]}}
        result = self.submit()
        record = self.adapter.ledger.load("test-1")
        self.assertRegex(record["request_nonce"], r"^[0-9a-f]{32}$")
        self.assertTrue(result["notebook_ref"].endswith(record["request_nonce"][:24]))
        self.assertEqual([x[0] for x in self.transport.calls], ["list", "list", "submit"])
        self.assertEqual(self.submit()["notebook_ref"], result["notebook_ref"])

    def test_changed_source_refuses_same_identity(self):
        self.submit(); self.source.write_text("print(6)\n")
        with self.assertRaises(AdapterError) as ctx: self.submit()
        self.assertEqual(ctx.exception.code, "IDEMPOTENCY_CONFLICT")
        self.assertEqual(self.transport.count("submit"), 1)

    def test_lost_ack_stays_unknown_without_original_version_evidence(self):
        self.transport.lose_ack = True
        with self.assertRaises(RemoteError): self.submit()
        self.assertEqual(self.adapter.ledger.load("test-1")["submission_state"], "UNKNOWN")
        retry = self.submit()
        self.assertEqual(retry["submission_state"], "UNKNOWN")
        self.assertEqual(self.transport.count("submit"), 1)
        recovered = self.adapter.resume("test-1")
        self.assertFalse(recovered["identity_verified"])
        self.assertEqual(recovered["submission_state"], "UNKNOWN")
        self.assertIsNone(recovered["notebook_version"])
        self.assertFalse(recovered["reconciled"])
        self.assertFalse(recovered["remote_submission_replayed"])
        self.assertEqual(self.transport.count("submit"), 1)
        reads = [x for x in self.transport.calls if x[0] == "get"]
        self.assertNotIn("version_label", reads[-1][1])

    def test_same_source_later_version_cannot_be_claimed_as_original(self):
        self.transport.lose_ack = True
        with self.assertRaises(RemoteError): self.submit()
        self.transport.version = 2
        recovered = self.adapter.resume("test-1")
        self.assertEqual(recovered["submission_state"], "UNKNOWN")
        self.assertIsNone(recovered["notebook_version"])
        self.assertEqual(recovered["candidate"]["latest_version_observed"], 2)
        self.assertFalse(recovered["candidate"]["original_execution_proven"])
        self.assertEqual(self.transport.count("submit"), 1)

    def test_durable_submit_response_recovers_exact_version_even_after_latest_changes(self):
        self.submit()
        record = self.adapter.ledger.load("test-1")
        record.update(submission_state="SUBMITTING", notebook_version=None, kernel_id=None)
        self.adapter.ledger.save(record)
        self.transport.version = 2
        recovered = self.adapter.resume("test-1")
        self.assertEqual(recovered["notebook_version"], 1)
        self.assertEqual(recovered["kernel_id"], 9)
        self.assertTrue(recovered["reconciled"])
        self.assertEqual(self.transport.count("submit"), 1)
        for action, values, _ in self.transport.calls[-3:]:
            self.assertEqual(values.get("version_label"), "v1")

    def test_deleted_and_recreated_notebook_ref_is_not_same_identity(self):
        self.prepare_outputs()
        self.transport.kernel_id = 99
        for action in (lambda: self.adapter.status("test-1"), lambda: self.adapter.artifacts("test-1"), lambda: self.adapter.logs("test-1")):
            with self.assertRaises(AdapterError) as ctx: action()
            self.assertEqual(ctx.exception.code, "NOTEBOOK_IDENTITY_MISMATCH")

    def test_unknown_not_found_remains_unknown(self):
        self.transport.lose_ack = True
        with self.assertRaises(RemoteError): self.submit()
        self.transport.saved = None
        result = self.adapter.resume("test-1")
        self.assertEqual(result["submission_state"], "UNKNOWN")
        self.assertFalse(result["reconciled"])
        self.assertEqual(self.transport.count("submit"), 1)

    def test_mismatched_source_cannot_adopt_remote_run(self):
        self.transport.lose_ack = True
        with self.assertRaises(RemoteError): self.submit()
        self.transport.source_override = "print('other run')"
        with self.assertRaises(AdapterError) as ctx: self.adapter.resume("test-1")
        self.assertEqual(ctx.exception.code, "SOURCE_IDENTITY_MISMATCH")
        self.assertEqual(self.adapter.ledger.load("test-1")["submission_state"], "UNKNOWN")

    def test_status_pins_original_version_after_remote_latest_changes(self):
        self.submit(); self.transport.version = 5
        self.adapter.status("test-1")
        self.assertEqual(self.transport.calls[-1][1]["version_label"], "v1")

    def test_changed_account_cannot_observe_or_cancel_job(self):
        self.submit(); self.transport.username = "other"
        old = len(self.transport.calls)
        with self.assertRaises(AdapterError) as ctx: self.adapter.status("test-1")
        self.assertEqual(ctx.exception.code, "ACCOUNT_MISMATCH")
        self.assertEqual(len(self.transport.calls), old)

    def test_version_is_never_used_as_session_id(self):
        self.submit()
        with self.assertRaises(AdapterError) as ctx: self.adapter.cancel("test-1", wait_seconds=0)
        self.assertEqual(ctx.exception.code, "SESSION_IDENTITY_UNPROVEN")
        self.assertEqual(self.transport.count("cancel"), 0)

    def test_cancel_ack_does_not_claim_stopped(self):
        self.transport.sid = 123456
        self.submit()
        result = self.adapter.cancel("test-1", wait_seconds=0)
        self.assertFalse(result["remote_stop_confirmed"])
        cancel = [x for x in self.transport.calls if x[0] == "cancel"][0]
        self.assertEqual(cancel[1], {"kernel_session_id": 123456})
        self.adapter.cancel("test-1", wait_seconds=0)
        self.assertEqual(self.transport.count("cancel"), 1)
        self.transport.state = "CANCEL_ACKNOWLEDGED"
        stopped = self.adapter.cancel("test-1", wait_seconds=0)
        self.assertTrue(stopped["remote_stop_confirmed"])

    def test_verified_manifest_and_existing_download_reuse(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertTrue(result["remote_manifest_verified"])
        self.assertFalse(result["reused"])
        old = self.transport.count("output")
        again = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertTrue(again["reused"])
        self.assertEqual(old, self.transport.count("output"))
        folder = Path(result["directory"])
        (folder / "result.json").write_text("changed")
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "LOCAL_ARTIFACT_CHANGED")

    def test_reused_artifacts_enforce_tighter_budget_before_hashing(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        before = self.adapter.ledger.load("test-1")
        calls, downloads = len(self.transport.calls), len(self.transport.downloads)
        for manifest_name in (None, "hepta-manifest.json"):
            with self.subTest(manifest=manifest_name), patch("kaggle_jobs.hash_file") as hashed:
                with self.assertRaises(AdapterError) as ctx:
                    self.adapter.artifacts("test-1", manifest_name=manifest_name,
                                           max_bytes=result["total_bytes"] - 1)
                self.assertEqual(ctx.exception.code, "ARTIFACT_BUDGET")
                hashed.assert_not_called()
            self.assertEqual(self.adapter.ledger.load("test-1"), before)
        self.assertEqual((len(self.transport.calls), len(self.transport.downloads)), (calls, downloads))
        exact = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json",
                                       max_bytes=result["total_bytes"])
        self.assertTrue(exact["reused"])

    def test_recovered_artifacts_enforce_tighter_budget_before_hashing(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        record = self.adapter.ledger.load("test-1")
        record.pop("artifacts"); self.adapter.ledger.save(record)
        before = self.adapter.ledger.load("test-1")
        calls, downloads = len(self.transport.calls), len(self.transport.downloads)
        with patch("kaggle_jobs.hash_file") as hashed:
            with self.assertRaises(AdapterError) as ctx:
                self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json", max_bytes=1)
            self.assertEqual(ctx.exception.code, "ARTIFACT_BUDGET")
            hashed.assert_not_called()
        self.assertEqual(self.adapter.ledger.load("test-1"), before)
        self.assertEqual((len(self.transport.calls), len(self.transport.downloads)), (calls, downloads))
        exact = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json",
                                       max_bytes=result["total_bytes"])
        self.assertTrue(exact["recovered_local_publish"])

    def test_retained_payload_growth_is_bounded_before_reading(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1")
        target = Path(result["directory"]) / "result.json"
        target.write_bytes(b"x" * (result["total_bytes"] + 1))
        from kaggle_jobs import hash_file
        with patch("kaggle_jobs.os.fdopen") as stream_open:
            with self.assertRaises(AdapterError) as ctx:
                hash_file(target, max_bytes=result["total_bytes"])
            self.assertEqual(ctx.exception.code, "ARTIFACT_BUDGET")
            stream_open.assert_not_called()
        with self.assertRaises(AdapterError) as ctx:
            self.adapter.artifacts("test-1", max_bytes=result["total_bytes"])
        self.assertEqual(ctx.exception.code, "ARTIFACT_BUDGET")

    def test_artifact_budget_requires_integer_bytes(self):
        for value in (True, False, 1.0, "100", None):
            with self.subTest(value=value), self.assertRaises(AdapterError) as ctx:
                self.adapter.artifacts("test-1", max_bytes=value)
            self.assertEqual(ctx.exception.code, "INVALID_ARTIFACT_BUDGET")
        self.assertEqual(self.transport.calls, [])

    def test_remote_hash_mismatch_never_publishes(self):
        self.prepare_outputs()
        self.transport.payloads["result.json"] = b'{"answer":6}\n'
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertEqual(ctx.exception.code, "REMOTE_MANIFEST_HASH")
        self.assertNotIn("artifacts", self.adapter.ledger.load("test-1"))
        self.assertFalse((self.adapter.ledger.directory("test-1") / "artifacts/v1").exists())

    def test_manifest_verification_preserves_provider_size_conflicts(self):
        self.prepare_outputs()
        self.transport.provider_sizes = {"hepta-manifest.json": 920, "result.json": 887}
        # The execution bytes fit even though provider metadata does not.
        actual_total = sum(len(x) for x in self.transport.payloads.values())
        result = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json", max_bytes=actual_total)
        self.assertTrue(result["remote_manifest_verified"])
        self.assertEqual(result["verification_policy"], "manifest-and-http-v1")
        self.assertFalse(result["provider_sizes_all_match"])
        self.assertEqual(len(result["warnings"]), 2)
        self.assertEqual(self.transport.downloads[0], "hepta-manifest.json")
        entries = {x["path"]: x for x in result["files"]}
        self.assertEqual(entries["result.json"]["provider_list_size"], 887)
        self.assertEqual(entries["hepta-manifest.json"]["provider_list_size"], 920)
        for name, item in entries.items():
            self.assertEqual(item["bytes"], len(self.transport.payloads[name]))
            self.assertEqual(item["http_content_length"], item["bytes"])
            self.assertTrue(item["http_content_length_verified"])
            self.assertFalse(item["provider_size_matches"])
        again = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertTrue(again["reused"])
        self.assertEqual(again["warnings"], result["warnings"])
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "ARTIFACT_LENGTH")

    def test_wrong_provider_size_without_manifest_still_fails(self):
        self.prepare_outputs(); self.transport.provider_sizes["result.json"] = 887
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "ARTIFACT_LENGTH")
        self.assertNotIn("artifacts", self.adapter.ledger.load("test-1"))

    def test_manifest_requires_http_length_for_manifest_and_every_payload(self):
        for name in ("hepta-manifest.json", "result.json"):
            with self.subTest(name=name):
                # Each failed attempt remains unpublished and can re-download.
                if not self.transport.saved: self.prepare_outputs()
                self.transport.http_lengths = {name: None}
                with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
                self.assertEqual(ctx.exception.code, "HTTP_CONTENT_LENGTH_REQUIRED")
                self.assertNotIn("artifacts", self.adapter.ledger.load("test-1"))

    def test_manifest_does_not_override_http_length_mismatch(self):
        self.prepare_outputs(); self.transport.http_lengths["result.json"] = 887
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertEqual(ctx.exception.code, "ARTIFACT_LENGTH")

    def test_incomplete_manifest_rejected_before_any_payload_download(self):
        self.prepare_outputs(); self.transport.payloads["extra.txt"] = b"not covered"
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertEqual(ctx.exception.code, "REMOTE_MANIFEST_COVERAGE")
        self.assertEqual(self.transport.downloads, ["hepta-manifest.json"])

    def test_publish_crash_recovery_uses_local_receipt_without_download(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        record = self.adapter.ledger.load("test-1")
        record.pop("artifacts"); self.adapter.ledger.save(record)
        before = len(self.transport.calls)
        recovered = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertTrue(recovered["recovered_local_publish"])
        self.assertEqual(recovered["files_manifest_sha256"], result["files_manifest_sha256"])
        self.assertEqual(before, len(self.transport.calls))

    def test_reuse_performs_newly_requested_remote_manifest_check(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1")
        self.assertFalse(result["remote_manifest_verified"])
        again = self.adapter.artifacts("test-1", manifest_name="hepta-manifest.json")
        self.assertTrue(again["remote_manifest_verified"])
        self.assertTrue(self.adapter.ledger.load("test-1")["artifacts"]["remote_manifest_verified"])

    def test_recovered_publication_rejects_receipt_from_other_request(self):
        self.prepare_outputs()
        result = self.adapter.artifacts("test-1")
        record = self.adapter.ledger.load("test-1")
        record.pop("artifacts"); self.adapter.ledger.save(record)
        path = Path(result["directory"]) / ".hepta-download-receipt.json"
        receipt = json.loads(path.read_bytes()); receipt["request_id"] = "other"
        path.write_text(json.dumps(receipt))
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "ARTIFACT_RECEIPT_IDENTITY")

    def test_untrusted_download_receipt_is_independently_hashed(self):
        self.prepare_outputs(); self.transport.tamper_download = True
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "DOWNLOAD_HASH_MISMATCH")

    def test_traversal_rejected_before_downloading(self):
        self.prepare_outputs(); self.transport.payloads = {"../escaped.txt": b"bad"}
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "UNSAFE_ARTIFACT_PATH")
        self.assertFalse((self.base / "escaped.txt").exists())
        for name in ("/abs", "a/../b", "a//b", "./a", "a\\b", "C:/a", ".", ""):
            with self.subTest(name=name), self.assertRaises(AdapterError): safe_name(name)

    def test_private_notebook_identity_must_be_confirmed(self):
        self.prepare_outputs(); self.transport.private = False
        with self.assertRaises(AdapterError) as ctx: self.adapter.artifacts("test-1")
        self.assertEqual(ctx.exception.code, "PRIVACY_MISMATCH")

    def test_log_cursors_detect_replacement(self):
        self.submit(); self.transport.log = "hello\n"
        a = self.adapter.logs("test-1", limit=3)
        self.assertEqual(a["text"], "hel")
        self.transport.log = "hello\nworld\n"
        b = self.adapter.logs("test-1", cursor=a["next_cursor"])
        self.assertEqual(b["text"], "lo\nworld\n")
        self.transport.log = "a different log\n"
        with self.assertRaises(AdapterError) as ctx: self.adapter.logs("test-1", cursor=b["next_cursor"])
        self.assertEqual(ctx.exception.code, "LOG_REPLACED")

    def test_lock_excludes_another_process(self):
        self.submit()
        code = "from pathlib import Path\nfrom kaggle_jobs import Ledger\nfrom kaggle_transport import AdapterError\ntry:\n with Ledger(Path(" + repr(str(self.base / "state")) + ")).locked('test-1'): print('UNSAFE')\nexcept AdapterError as e: print(e.code)\n"
        with self.adapter.ledger.locked("test-1"):
            p = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
        self.assertEqual(p.stdout.strip(), "REQUEST_BUSY")

    def test_event_orphan_is_preserved_after_crash(self):
        self.submit(); rec = self.adapter.ledger.load("test-1")
        d = self.adapter.ledger.directory("test-1") / "events"
        orphan = d / f"{rec['event_count']+1:06d}.json"
        orphan.write_text('{"old":"uncommitted"}')
        self.adapter.ledger.event(rec, "after_restart")
        self.assertEqual(orphan.read_text(), '{"old":"uncommitted"}')

    def test_credentials_redacted_but_auth_state_remains(self):
        secret = "test-secret-value-123"
        remember_secret(secret)
        result = scrub({"authorization": {"authenticated": False}, "token": secret, "log": secret + " https://example.test/a?token=another"})
        self.assertEqual(result["authorization"], {"authenticated": False})
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn("another", json.dumps(result))

    def test_ledger_events_never_persist_storage_url_capability(self):
        self.submit(); record = self.adapter.ledger.load("test-1")
        self.adapter.ledger.event(record, "test_output_response", {"url": "https://www.kaggleusercontent.com/kf/123/SECRET_PATH_CAPABILITY/result.json"})
        path = self.adapter.ledger.directory("test-1") / "events" / f"{record['event_count']:06d}.json"
        content = path.read_text()
        self.assertNotIn("SECRET_PATH_CAPABILITY", content)
        self.assertNotIn("/kf/123", content)
        self.assertIn("REDACTED_STORAGE_URL", content)


if __name__ == "__main__": unittest.main()
