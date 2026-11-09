import base64
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
from pathlib import Path
import tempfile
import threading
import time
import unittest
from hepta_compute import Router, RouterError, digest, locked, safe_receipt


class FakeLauncher:
    def __init__(self, root):
        self.root = Path(root)
        self.calls = []
        self.effects = Counter()
        self.guard = threading.Lock()
        self.active = self.max_active = 0
        self.barrier = None
        self.blocked = set()
        self.timeout_submit = self.unknown_status = self.bad_artifact = False
        self.fail_bind = self.unknown_release = False
        self.reconcile_phase = "runtime_ready"
        self.reconcile_receipt = None
        self.lookup_result = None
        self.timeout_cancel = False
        self.unknown_close = False
        self.remaining = 108000
        self.bytes = b'{"cuda":true,"value":128}\n'

    def call(self, provider, account, args, timeout=90):
        with self.guard:
            self.calls.append((provider, account, list(args)))
        if args[:2] in (["manage", "inventory"], ["batch", "quota"]):
            with self.guard:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            if self.barrier:
                self.barrier.wait(timeout=5)
            time.sleep(0.01)
            with self.guard:
                self.active -= 1
        if args[:2] == ["batch", "quota"]:
            return {"account": {"authenticated": True, "username": account}, "raw_quota": {
                "gpuQuota": {"totalTimeAllowed": str(self.remaining) + "s", "timeUsed": "0s", "timeReserved": "0s"}}}
        if args[:2] == ["batch", "account"]:
            return {"authenticated": True, "username": account}
        if args[:2] == ["manage", "account"]:
            return {"status": "authorized", "account_email": account + "@unit.test"}
        if args[:2] == ["batch", "readiness"]:
            if (provider, account) in self.blocked:
                return {"ready": False, "error": {"code": "NOTEBOOK_LIST_SCOPE"}}
            return {"ready": True}
        if args[:2] == ["manage", "inventory"]:
            return {"account": {"status": "authorized", "account_email": account + "@unit.test"}, "eligibility": {"status": "available", "runtime_specs": [
                {"variant": "GPU", "accelerator": "T4", "shape": "STANDARD", "eligible": True}]},
                "assignments": {"status": "available", "runtimes": []}}
        if args[:2] == ["manage", "readiness"]:
            return {"can_create": (provider, account) not in self.blocked, "job_profile_supported": True,
                    "allocation_blockers": [{"phase": "allocation_unknown", "key": "old"}] if (provider, account) in self.blocked else []}
        if args[:2] == ["batch", "submit"]:
            self.effects["submit"] += 1
            if self.timeout_submit:
                raise RouterError("PROVIDER_OBSERVATION_TIMEOUT")
            return {"submission_state": "ACCEPTED", "remote_submission_state": "ACCEPTED", "remote_effect_unknown": False}
        if args[:2] in (["batch", "status"], ["batch", "resume"]):
            if self.unknown_status:
                return {"submission_state": "UNKNOWN", "remote_effect_unknown": True, "remote_state": "UNKNOWN", "identity_verified": False}
            return {"submission_state": "ACCEPTED", "remote_submission_state": "ACCEPTED", "remote_effect_unknown": False,
                    "remote_state": "COMPLETE", "identity_verified": True, "notebook_version": 1}
        if args[:2] == ["batch", "logs"]:
            raw = "CUDA verified\n"
            return {"cursor": "0:0", "next_cursor": "0:14", "eof": True, "snapshot_bytes": 14,
                    "snapshot_sha256": digest(raw.encode()), "text": raw, "redacted": False}
        if args[:2] == ["batch", "artifacts"]:
            base = self.root / "kaggle-artifacts"
            base.mkdir(exist_ok=True)
            (base / "result.json").write_bytes(self.bytes)
            return {"directory": str(base), "files": [{"path": "result.json", "bytes": len(self.bytes),
                     "sha256": "0" * 64 if self.bad_artifact else digest(self.bytes)}]}
        if args[:2] == ["manage", "create"]:
            self.effects["allocate"] += 1
            return {"phase": "runtime_ready", "owned_runtime": True}
        if args[:2] == ["manage", "release"]:
            self.effects["release"] += 1
            return {"phase": "release_unknown" if self.unknown_release else "released"}
        if args[:2] == ["manage", "reconcile"]:
            return self.reconcile_receipt or {"phase": self.reconcile_phase, "profile_hash": "a" * 64}
        if args[:2] == ["manage", "close-unstarted"]:
            self.effects["close_unstarted"] += 1
            return {"phase": "release_unknown" if self.unknown_close else "released", "never_dispatched": True,
                    "cleanup_reason": "unstarted_compute", "owned_runtime": True}
        if args[0] == "--provision-key":
            if args[2:4] == ["manage", "bind"]:
                self.effects["bind"] += 1
                if self.fail_bind:
                    raise RouterError("PROVIDER_OBSERVATION_TIMEOUT")
                return {"phase": "bound", "profile_hash": "a" * 64}
            verb = args[3]
            if verb == "submit":
                self.effects["submit_local"] += 1
                return {"job_id": "colab-job-1", "state": "queued"}
            if verb == "run":
                self.effects["run"] += 1
                if self.lookup_result and self.lookup_result.get("found"):
                    self.lookup_result["job"].update(state="succeeded", submit_attempts=1, local_only_cancel=False)
                return {"job_id": "colab-job-1", "state": "succeeded", "cloud_execution_stopped": True}
            if verb == "status":
                if self.lookup_result and self.lookup_result.get("found"):
                    stopped = self.lookup_result["job"].get("state") == "succeeded" and self.lookup_result["job"].get("submit_attempts") == 1
                    return dict(self.lookup_result["job"], cloud_execution_stopped=stopped,
                                artifacts={"result.json": {"size": len(self.bytes), "sha256": digest(self.bytes)}} if stopped else {})
                return {"job_id": "colab-job-1", "state": "succeeded", "cloud_execution_stopped": True,
                        "artifacts": {"result.json": {"size": len(self.bytes), "sha256": digest(self.bytes)}}}
            if verb == "inspect-key":
                if self.lookup_result is None:
                    return {"found": False, "absence_verified": True, "ledger_present": True,
                            "profile_hash": "a" * 64, "idempotency_key": args[-1]}
                return json.loads(json.dumps(self.lookup_result))
            if verb == "cancel":
                self.effects["cancel_unstarted"] += 1
                self.lookup_result["job"].update(state="cancelled", local_only_cancel=True)
                if self.timeout_cancel:
                    raise RouterError("PROVIDER_OBSERVATION_TIMEOUT")
                return json.loads(json.dumps(self.lookup_result["job"]))
            if verb == "read":
                raw = b"CUDA result verified\n"
                return {"text": raw.decode(), "data_base64": base64.b64encode(raw).decode(), "sha256": digest(raw),
                        "verified": True, "eof": True, "next_offset": len(raw)}
            if verb == "fetch":
                dest = Path(args[args.index("--destination") + 1])
                dest.write_bytes(self.bytes)
                return {"job_id": "colab-job-1", "path": str(dest), "verified": True, "size": len(self.bytes), "sha256": digest(self.bytes)}
        raise AssertionError((provider, account, args))


def lock_worker(path, shared, overlap):
    with locked(Path(path), timeout=5):
        with shared.get_lock():
            if shared.value:
                overlap.value = 1
            shared.value += 1
        time.sleep(0.08)
        with shared.get_lock():
            shared.value -= 1


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for provider in ("colab", "kaggle"):
            path = self.root / ".config" / ("hepta-" + provider)
            path.mkdir(parents=True)
            (path / "accounts.json").write_text(json.dumps({"accounts": {x: {} for x in ("account-a", "account-c", "account-b")},
                                                          "default_account": "account-a"}))
        self.fake = FakeLauncher(self.root)
        self.router = Router(home=self.root, launcher=self.fake)
        self.source = self.root / "task.py"
        self.source.write_text("print('hello')\n")

    def tearDown(self):
        self.temp.cleanup()

    def plan(self, key="test-one", **kwargs):
        return self.router.plan(key, self.source, artifacts=["result.json"], **kwargs)

    def unstarted_record(self, found=False):
        record = self.plan(provider="colab", account="account-c")
        record["state"] = "RECONCILIATION_REQUIRED"
        record["lease_until"] = 0
        record["effects"] = {"allocate": {"status": "confirmed"}, "bind": {"status": "confirmed"},
                             "submit_local": {"status": "unknown"}}
        record["receipts"] = {"allocate": {"phase": "runtime_ready"}, "bind": {"phase": "bound", "profile_hash": "a" * 64}}
        record["last_error"] = "LOCAL_SUBMISSION_RESPONSE_LOST"
        self.router.store.save(record)
        self.fake.reconcile_phase = "bound"
        self.fake.lookup_result = {"found": found, "ledger_present": True, "absence_verified": not found,
                                  "profile_hash": "a" * 64, "idempotency_key": record["provider_request_id"]}
        if found:
            code_hash = digest(self.source.read_text().encode())
            self.fake.lookup_result.update(job={"job_id": "colab-job-1", "code_sha256": code_hash,
                "state": "queued", "submit_attempts": 0, "local_only_cancel": False},
                request={"code_sha256": code_hash, "wall_seconds": record["intent"]["timeout"],
                         "artifacts": record["intent"]["artifacts"], "runner_sha256": "b" * 64, "runner_matches_current": True})
        return record

    def test_six_accounts_evaluated_concurrently(self):
        self.fake.barrier = threading.Barrier(6)
        result = self.router.evaluate()
        self.assertEqual(len(result["candidates"]), 6)
        self.assertEqual(self.fake.max_active, 6)
        self.assertTrue(all(x["ready"] for x in result["candidates"]))
        for provider in ("kaggle", "colab"):
            for account in ("account-a", "account-c", "account-b"):
                calls = [x[2] for x in self.fake.calls if x[:2] == (provider, account)]
                self.assertEqual(len(calls), 2)

    def test_quota_never_overrides_ownership_or_old_allocation_guard(self):
        self.fake.blocked = {("kaggle", x) for x in ("account-a", "account-c", "account-b")}
        self.fake.blocked.add(("colab", "account-a"))
        record = self.plan()
        self.assertEqual(record["provider"], "colab")
        self.assertNotEqual(record["account"], "account-a")
        self.assertEqual(self.fake.effects, {})

    def test_account_quota_not_aggregated(self):
        self.fake.remaining = 100
        result = self.router.evaluate(provider="kaggle", wall_seconds=120)
        self.assertTrue(all(not row["ready"] for row in result["candidates"]))
        self.assertTrue(all("INSUFFICIENT_ACCOUNT_QUOTA" in row["blockers"] for row in result["candidates"]))

    def test_plan_same_request_is_idempotent_and_binding_immutable(self):
        first = self.plan()
        before = len(self.fake.calls)
        second = self.plan()
        self.assertEqual(first["provider"], second["provider"])
        self.assertEqual(first["account"], second["account"])
        self.assertEqual(len(self.fake.calls), before)
        self.source.write_text("print('different')\n")
        with self.assertRaisesRegex(RouterError, "REQUEST_INTENT_CONFLICT"):
            self.plan()
        self.assertEqual(self.router.store.get("test-one")["digest"], first["digest"])

    def test_concurrent_plans_reserve_distinct_accounts(self):
        with ThreadPoolExecutor(2) as pool:
            records = [f.result() for f in [pool.submit(self.plan, "parallel-" + str(i)) for i in range(2)]]
        self.assertNotEqual((records[0]["provider"], records[0]["account"]), (records[1]["provider"], records[1]["account"]))

    def test_unknown_submission_never_repeats_or_changes_account(self):
        first = self.plan(provider="kaggle")
        self.fake.timeout_submit = self.fake.unknown_status = True
        result = self.router.execute(first["request_id"])
        self.assertEqual(result["state"], "RECONCILIATION_REQUIRED")
        for _ in range(3):
            result = self.router.execute(first["request_id"])
        self.assertEqual(self.fake.effects["submit"], 1)
        self.assertEqual((result["provider"], result["account"]), (first["provider"], first["account"]))
        self.assertTrue(any(x["request_id"] == first["request_id"] for x in self.router.store.reservations()))

    def test_source_snapshot_tampering_blocks_execution(self):
        record = self.plan()
        self.source.write_text("print('edited after planning')")
        self.assertNotEqual(digest(self.source.read_bytes()), record["intent"]["source_sha256"])
        Path(record["source"]).write_text("tampered")
        with self.assertRaisesRegex(RouterError, "SOURCE_SNAPSHOT_CHANGED"):
            self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects, {})

    def test_complete_kaggle_task_artifacts_checked_and_reservation_released(self):
        record = self.plan(provider="kaggle")
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "REMOTE_TERMINAL")
        record = self.router.collect(record["request_id"])
        self.assertEqual(record["state"], "COLLECTED")
        self.assertEqual(Path(record["outputs"]["files"][0]["path"]).read_bytes(), self.fake.bytes)
        self.assertEqual(self.router.store.reservations(), [])
        self.router.execute(record["request_id"])
        self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects["submit"], 1)

    def test_corrupt_artifact_not_claimed_collected(self):
        record = self.plan(provider="kaggle")
        self.router.execute(record["request_id"])
        self.fake.bad_artifact = True
        with self.assertRaisesRegex(RouterError, "ARTIFACT_INTEGRITY_MISMATCH"):
            self.router.collect(record["request_id"])
        self.assertNotEqual(self.router.store.get(record["request_id"])["state"], "COLLECTED")

    def test_colab_own_profile_job_result_and_release_exactly_once(self):
        record = self.plan(provider="colab", account="account-c")
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "REMOTE_TERMINAL")
        record = self.router.collect(record["request_id"])
        self.assertEqual(record["state"], "COLLECTED")
        self.router.execute(record["request_id"])
        self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects, {"allocate": 1, "bind": 1, "submit_local": 1, "run": 1, "release": 1})
        effect_calls = [args for p, a, args in self.fake.calls if p == "colab" and args[0] == "--provision-key"]
        self.assertTrue(all(x[1] == record["provision_key"] for x in effect_calls))

    def test_only_unexecuted_plans_expire(self):
        record = self.plan()
        record["lease_until"] = time.time() - 1
        self.router.store.save(record)
        self.router.store.reservations()
        self.assertEqual(self.router.store.get(record["request_id"])["state"], "EXPIRED")
        self.assertEqual(self.router.execute(record["request_id"])["state"], "EXPIRED")
        self.assertEqual(self.fake.effects, {})

    def test_cross_process_account_lock_serializes(self):
        path = self.router.store.locks / "shared-account.lock"
        context = multiprocessing.get_context("fork")
        shared = context.Value("i", 0)
        overlap = context.Value("i", 0)
        workers = [context.Process(target=lock_worker, args=(str(path), shared, overlap)) for _ in range(4)]
        for process in workers:
            process.start()
        for process in workers:
            process.join(timeout=5)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(overlap.value, 0)

    def test_receipts_do_not_cache_credentials_or_account_email(self):
        value = safe_receipt({"job_id": "stable", "account_email": "private@example.test", "token": "secret",
                              "runtime_proxy_info": {"token": "secret"}, "url": "https://private.test"})
        self.assertEqual(value, {"job_id": "stable"})


    def test_known_allocation_resumes_next_unstarted_stage_without_reallocating(self):
        record = self.plan(provider="colab")
        self.router.effect(record, "allocate", ["manage", "create", "--key", record["provision_key"]])
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "REMOTE_TERMINAL")
        self.assertEqual(self.fake.effects["allocate"], 1)
        self.assertEqual(self.fake.effects["run"], 1)

    def test_uncertain_bind_only_resumes_after_original_binding_confirmed(self):
        record = self.plan(provider="colab")
        self.fake.fail_bind = True
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "RECONCILIATION_REQUIRED")
        self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects["bind"], 1)
        self.assertEqual(self.fake.effects["run"], 0)
        self.fake.reconcile_phase = "bound"
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "REMOTE_TERMINAL")
        self.assertEqual(self.fake.effects["bind"], 1)
        self.assertEqual(self.fake.effects["run"], 1)

    def test_uncertain_release_reconciles_original_key_without_second_release(self):
        record = self.plan(provider="colab")
        self.router.execute(record["request_id"])
        self.fake.unknown_release = True
        record = self.router.collect(record["request_id"])
        self.assertEqual(record["state"], "RELEASE_PENDING")
        self.assertEqual(self.fake.effects["release"], 1)
        self.fake.reconcile_phase = "released"
        original = self.fake.call
        def disconnected(provider, account, args, timeout=90):
            if args[0] == "--provision-key" and args[2] == "run":
                raise RouterError("RUNTIME_ALREADY_GONE")
            return original(provider, account, args, timeout)
        self.fake.call = disconnected
        record = self.router.collect(record["request_id"])
        self.assertEqual(record["state"], "COLLECTED")
        self.assertEqual(self.fake.effects["release"], 1)


    def test_kaggle_logs_collect_all_utf8_pages_and_verify_snapshot(self):
        record = self.plan(provider="kaggle")
        raw = ("A" * 65535 + "中Z").encode()
        original = self.fake.call
        def paginated(provider, account, args, timeout=90):
            if args[:2] != ["batch", "logs"]:
                return original(provider, account, args, timeout)
            offset = int(args[-1].split(":")[-1]) if "--cursor" in args else 0
            end = 65535 if offset == 0 else len(raw)
            return {"cursor": "0:" + str(offset), "next_cursor": "0:" + str(end), "eof": end == len(raw),
                    "snapshot_bytes": len(raw), "snapshot_sha256": digest(raw), "text": raw[offset:end].decode(), "redacted": False}
        self.fake.call = paginated
        folder = self.router.store.job_dir(record["request_id"]) / "log-test"
        folder.mkdir(mode=0o700)
        result = self.router.kaggle_logs(record, folder, 100000)
        self.assertEqual(Path(result["path"]).read_bytes(), raw)
        self.assertTrue(result["complete"])

    def test_colab_logs_preserve_bytes_across_utf8_chunk_boundaries(self):
        record = self.plan(provider="colab")
        self.router.execute(record["request_id"])
        raw = "中".encode()
        original = self.fake.call
        def split_log(provider, account, args, timeout=90):
            if args[0] != "--provision-key" or args[3] != "read":
                return original(provider, account, args, timeout)
            offset = int(args[args.index("--offset") + 1])
            chunk = raw[offset:offset+1]
            return {"data_base64": base64.b64encode(chunk).decode(), "sha256": digest(chunk), "text": "invalid replacement",
                    "verified": True, "next_offset": offset + len(chunk), "eof": offset + len(chunk) == len(raw)}
        self.fake.call = split_log
        record = self.router.collect(record["request_id"])
        self.assertEqual(Path(record["outputs"]["logs"]["stdout"]["path"]).read_bytes(), raw)

    def test_explicit_allocation_refusal_never_triggers_account_rotation(self):
        record = self.plan(provider="colab", account="account-c")
        original = self.fake.call
        def refused(provider, account, args, timeout=90):
            if args[:2] in (["manage", "create"], ["manage", "reconcile"]):
                if args[1] == "create":
                    self.fake.effects["allocate"] += 1
                return {"phase": "allocation_refused", "owned_runtime": False, "refusal_http_status": 412,
                        "refusal_source": "official_sdk_http_412", "error_code": "ALLOCATION_REFUSED_PRECONDITION"}
            return original(provider, account, args, timeout)
        self.fake.call = refused
        record = self.router.execute(record["request_id"])
        self.assertEqual(record["state"], "REJECTED")
        self.assertEqual(record["account"], "account-c")
        self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects["allocate"], 1)
        self.assertEqual(self.router.store.reservations(), [])

    def test_collected_is_not_gpu_execution_proof(self):
        record = self.plan(provider="kaggle")
        self.router.execute(record["request_id"])
        record = self.router.collect(record["request_id"])
        self.assertEqual(record["state"], "COLLECTED")
        self.assertTrue(record["outcome"]["compute_succeeded"])
        self.assertEqual(record["outcome"]["accelerator_execution_verification"], "requires_task_specific_artifact")


    def test_alias_reconfigured_to_different_authenticated_account_blocks_first_effect(self):
        record = self.plan(provider="kaggle")
        original = self.fake.call
        def changed(provider, account, args, timeout=90):
            if args[:2] == ["batch", "account"]:
                return {"authenticated": True, "username": "different-account"}
            return original(provider, account, args, timeout)
        self.fake.call = changed
        with self.assertRaisesRegex(RouterError, "ACCOUNT_IDENTITY_CHANGED"):
            self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects, {})
        self.assertEqual(self.router.store.get(record["request_id"])["account_identity_sha256"], record["account_identity_sha256"])


    def test_self_consistent_fetch_cannot_override_prior_terminal_manifest(self):
        record = self.plan(provider="colab")
        self.router.execute(record["request_id"])
        original = self.fake.call
        replacement = self.fake.bytes + b"unexpected larger contents"
        def stale_fetch(provider, account, args, timeout=90):
            if args[0] == "--provision-key" and args[3] == "fetch":
                target = Path(args[args.index("--destination") + 1])
                target.write_bytes(replacement)
                return {"verified": True, "path": str(target), "size": len(replacement), "sha256": digest(replacement)}
            return original(provider, account, args, timeout)
        self.fake.call = stale_fetch
        with self.assertRaisesRegex(RouterError, "ARTIFACT_INTEGRITY_MISMATCH"):
            self.router.collect(record["request_id"], max_bytes=len(self.fake.bytes) + 1)
        self.assertEqual(self.fake.effects["release"], 0)
        self.assertNotEqual(self.router.store.get(record["request_id"])["state"], "COLLECTED")

    def test_retained_artifact_tamper_blocks_release_reconciliation_completion(self):
        record = self.plan(provider="colab")
        self.router.execute(record["request_id"])
        self.fake.unknown_release = True
        record = self.router.collect(record["request_id"])
        Path(record["outputs"]["files"][0]["path"]).write_bytes(b"tampered")
        self.fake.reconcile_phase = "released"
        with self.assertRaisesRegex(RouterError, "RETAINED_OUTPUT_INTEGRITY_MISMATCH"):
            self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects["release"], 1)


    def test_colab_static_contract_rejected_before_allocation(self):
        for opts in ({"wall_seconds": 900}, {"artifacts": ["stdout"]},
                     {"artifacts": ["item" + str(i) for i in range(33)]}):
            with self.subTest(opts=opts):
                with self.assertRaises(RouterError):
                    self.router.plan("invalid-" + str(len(self.fake.calls)), self.source, provider="colab", **opts)
                self.assertEqual(self.fake.effects, {})
        self.source.write_text("#" * 262145)
        with self.assertRaisesRegex(RouterError, "COLAB_SOURCE_LIMIT_EXCEEDED"):
            self.router.plan("too-large", self.source, provider="colab")
        self.assertEqual(self.fake.effects, {})

    def test_bad_utf8_and_artifact_names_rejected_without_provider_calls(self):
        self.source.write_bytes(b"\xff")
        with self.assertRaisesRegex(RouterError, "SOURCE_MUST_BE_UTF8"):
            self.router.plan("bad-utf8", self.source)
        self.source.write_text("pass")
        for name in ("bad\x00name", "x" * 513):
            with self.assertRaisesRegex(RouterError, "INVALID_ARTIFACT_NAME"):
                self.router.plan("bad-name", self.source, artifacts=[name])
        self.assertEqual(self.fake.calls, [])

    def test_kaggle_unknown_uses_durable_response_resume_without_submit_replay(self):
        record = self.plan(provider="kaggle")
        self.fake.timeout_submit = True
        original = self.fake.call
        resumed = []
        def recover(provider, account, args, timeout=90):
            if args[:2] == ["batch", "resume"]:
                resumed.append(args[-1])
                return {"submission_state": "ACCEPTED", "remote_effect_unknown": False, "remote_state": "COMPLETE",
                        "identity_verified": True, "notebook_version": 7, "kernel_id": 123,
                        "remote_submission_replayed": False, "reconciled": True}
            return original(provider, account, args, timeout)
        self.fake.call = recover
        result = self.router.execute(record["request_id"])
        self.assertEqual(result["state"], "REMOTE_TERMINAL")
        self.assertEqual(resumed, [record["provider_request_id"]])
        self.assertEqual(self.fake.effects["submit"], 1)
        self.assertFalse(result["receipts"]["observation"]["remote_submission_replayed"])

    def test_task_artifacts_cannot_overwrite_router_receipt_or_logs(self):
        record = self.plan(provider="kaggle")
        self.router.execute(record["request_id"])
        original = self.fake.call
        def names(provider, account, args, timeout=90):
            out = original(provider, account, args, timeout)
            if args[:2] == ["batch", "artifacts"]:
                for name in ("router-receipt.json", "stdout.log", "provider-log-pages.json"):
                    data = ("user artifact: " + name).encode()
                    (Path(out["directory"]) / name).write_bytes(data)
                    out["files"].append({"path": name, "bytes": len(data), "sha256": digest(data)})
            return out
        self.fake.call = names
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "COLLECTED")
        for entry in result["outputs"]["files"]:
            self.assertIn("/outputs/artifacts/", entry["path"])
            self.assertEqual(digest(Path(entry["path"]).read_bytes()), entry["sha256"])
        log = result["outputs"]["logs"]["stdout"]
        self.assertIn("/outputs/logs/", log["path"])
        self.assertEqual(digest(Path(log["path"]).read_bytes()), log["sha256"])


    def test_unstarted_failed_task_cleans_owned_resource_without_fake_result(self):
        record = self.unstarted_record()
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "CLEANED_NOT_EXECUTED")
        self.assertFalse(result["outcome"]["compute_succeeded"])
        self.assertEqual(result["outputs"]["files"], [])
        self.assertEqual(self.fake.effects["close_unstarted"], 1)
        self.assertEqual(self.router.store.reservations(), [])
        self.router.execute(record["request_id"])
        self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects["close_unstarted"], 1)
        next_record = self.plan("new-independent-task", provider="colab", account="account-c")
        self.assertEqual(next_record["state"], "PLANNED")

    def test_queued_original_job_is_locally_cancelled_before_cleanup(self):
        record = self.unstarted_record(found=True)
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "CLEANED_NOT_EXECUTED")
        self.assertEqual(self.fake.effects["cancel_unstarted"], 1)
        self.assertEqual(self.fake.effects["close_unstarted"], 1)
        self.assertEqual(self.fake.effects["run"], 0)

    def test_old_key_with_different_intent_is_not_adopted_or_cancelled(self):
        record = self.unstarted_record(found=True)
        self.fake.lookup_result["request"]["wall_seconds"] += 1
        with self.assertRaisesRegex(RouterError, "LOCAL_SUBMIT_INTENT_MISMATCH"):
            self.router.collect(record["request_id"])
        saved = self.router.store.get(record["request_id"])
        self.assertNotIn("adapter_job_id", saved)
        self.assertEqual(self.fake.effects["cancel_unstarted"], 0)
        self.assertEqual(self.fake.effects["close_unstarted"], 0)

    def test_missing_local_ledger_does_not_prove_never_dispatched(self):
        record = self.unstarted_record()
        self.fake.lookup_result.update(ledger_present=False, absence_verified=False)
        with self.assertRaisesRegex(RouterError, "LOCAL_LEDGER_ABSENCE_UNVERIFIED"):
            self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects["close_unstarted"], 0)

    def test_any_run_intent_forbids_unstarted_cleanup(self):
        record = self.unstarted_record()
        record["effects"]["run"] = {"status": "started"}
        self.router.store.save(record)
        with self.assertRaisesRegex(RouterError, "REMOTE_COMPLETION_UNCONFIRMED"):
            self.router.collect(record["request_id"])
        self.assertEqual(self.fake.effects["close_unstarted"], 0)
        self.assertEqual(len(self.router.store.reservations()), 1)

    def test_unknown_local_cancel_is_observed_not_reissued(self):
        record = self.unstarted_record(found=True)
        self.fake.timeout_cancel = True
        with self.assertRaisesRegex(RouterError, "PROVIDER_OBSERVATION_TIMEOUT"):
            self.router.collect(record["request_id"])
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "CLEANED_NOT_EXECUTED")
        self.assertEqual(self.fake.effects["cancel_unstarted"], 1)
        self.assertEqual(self.fake.effects["close_unstarted"], 1)

    def test_unknown_cleanup_requires_original_release_and_never_dispatch_proof(self):
        record = self.unstarted_record()
        self.fake.unknown_close = True
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "CLEANUP_PENDING")
        self.fake.reconcile_receipt = {"phase": "released"}
        result = self.router.inspect(record["request_id"])
        self.assertEqual(result["state"], "CLEANUP_PENDING")
        self.assertEqual(len(self.router.store.reservations()), 1)
        self.fake.reconcile_receipt = {"phase": "released", "never_dispatched": True, "cleanup_reason": "unstarted_compute"}
        result = self.router.inspect(record["request_id"])
        self.assertEqual(result["state"], "CLEANED_NOT_EXECUTED")
        self.assertEqual(self.fake.effects["close_unstarted"], 1)

    def test_original_local_submit_response_can_recover_queued_job_for_one_run(self):
        record = self.unstarted_record(found=True)
        result = self.router.execute(record["request_id"])
        self.assertEqual(result["state"], "REMOTE_TERMINAL")
        self.assertEqual(self.fake.effects["submit_local"], 0)
        self.assertEqual(self.fake.effects["run"], 1)
        self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects["run"], 1)


    def test_recovered_local_cancelled_job_never_creates_run_effect_and_can_close(self):
        record = self.unstarted_record(found=True)
        self.fake.lookup_result["job"].update(state="cancelled", submit_attempts=0, local_only_cancel=True)
        result = self.router.execute(record["request_id"])
        self.assertEqual(result["state"], "LOCAL_CANCELLED")
        self.assertNotIn("run", result["effects"])
        self.assertEqual(self.fake.effects["run"], 0)
        result = self.router.collect(record["request_id"])
        self.assertEqual(result["state"], "CLEANED_NOT_EXECUTED")
        self.assertEqual(self.fake.effects["cancel_unstarted"], 0)
        self.assertEqual(self.fake.effects["close_unstarted"], 1)


    def test_claim_prevents_expiry_race_during_auth_with_stale_evaluation(self):
        record = self.plan(provider="kaggle", account="account-a")
        snapshot = json.loads(json.dumps(record["evaluation"]))
        record["lease_until"] = time.time() + 0.15
        self.router.store.save(record)
        entered, release = threading.Event(), threading.Event()
        original = self.fake.call
        def delayed_auth(provider, account, args, timeout=90):
            if args[:2] == ["batch", "account"]:
                entered.set()
                if not release.wait(timeout=3):
                    raise AssertionError("test authentication gate timed out")
            return original(provider, account, args, timeout)
        self.fake.call = delayed_auth
        with ThreadPoolExecutor(1) as pool:
            old_execution = pool.submit(self.router.execute, record["request_id"])
            try:
                self.assertTrue(entered.wait(timeout=2))
                time.sleep(0.2)
                self.router.evaluate = lambda **kwargs: json.loads(json.dumps(snapshot))
                with self.assertRaisesRegex(RouterError, "CANDIDATES_RESERVED_DURING_PLANNING"):
                    self.plan("competing-task", provider="kaggle", account="account-a")
                self.assertEqual(self.router.store.get(record["request_id"])["state"], "PREPARING")
            finally:
                release.set()
            result = old_execution.result(timeout=3)
        self.assertEqual(result["state"], "REMOTE_TERMINAL")
        self.assertEqual(self.fake.effects["submit"], 1)
        self.assertEqual(len(self.router.store.reservations()), 1)

    def test_expired_terminal_job_cannot_be_revived_by_stale_actor(self):
        record = self.plan()
        expired = dict(record, lease_until=time.time() - 1)
        self.router.store.save(expired)
        self.router.store.reservations()
        record["state"] = "EFFECT_PENDING"
        record["effects"]["submit"] = {"status": "started"}
        with self.assertRaisesRegex(RouterError, "TERMINAL_JOB_CANNOT_BE_REVIVED"):
            self.router.store.save(record)
        self.assertEqual(self.router.store.get(record["request_id"])["state"], "EXPIRED")
        self.assertEqual(self.fake.effects, {})

    def test_crash_after_claim_can_inspect_and_resume_first_effect(self):
        record = self.plan(provider="kaggle")
        prepared = self.router.store.claim_execution(record)
        self.assertEqual(prepared["state"], "PREPARING")
        before = len(self.fake.calls)
        self.assertEqual(self.router.inspect(record["request_id"])["state"], "PREPARING")
        with self.assertRaisesRegex(RouterError, "REQUEST_NOT_EXECUTED"):
            self.router.collect(record["request_id"])
        self.assertEqual(len(self.fake.calls), before)
        result = self.router.execute(record["request_id"])
        self.assertEqual(result["state"], "REMOTE_TERMINAL")
        self.assertEqual(self.fake.effects["submit"], 1)
        self.assertFalse(any(args[:2] == ["batch", "resume"] for _, _, args in self.fake.calls))

    def test_pre_effect_auth_failure_releases_claim_to_original_plan_lease(self):
        record = self.plan(provider="kaggle")
        original = self.fake.call
        def auth_failed(provider, account, args, timeout=90):
            if args[:2] == ["batch", "account"]:
                raise RouterError("AUTH_REQUIRED")
            return original(provider, account, args, timeout)
        self.fake.call = auth_failed
        with self.assertRaisesRegex(RouterError, "AUTH_REQUIRED"):
            self.router.execute(record["request_id"])
        saved = self.router.store.get(record["request_id"])
        self.assertEqual(saved["state"], "PLANNED")
        self.assertEqual(saved["lease_until"], record["lease_until"])
        self.assertEqual(saved["last_error"], "AUTH_REQUIRED")
        self.assertEqual(saved["effects"], {})
        self.fake.call = original
        self.router.execute(record["request_id"])
        self.assertEqual(self.fake.effects["submit"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
