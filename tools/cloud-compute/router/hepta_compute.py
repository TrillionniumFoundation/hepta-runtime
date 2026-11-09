#!/usr/bin/env python3
"""Bounded, durable Colab/Kaggle routing through account-isolated adapters.

This controller never copies credentials, aggregates account quotas, repeats an
uncertain cloud effect, or changes a request's provider/account after planning.
All provider APIs are invoked through the installed account launchers.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

VERSION = "0.1.0"
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
PROVIDERS = ("kaggle", "colab")
TERMINAL = {"COLLECTED", "CLEANED_NOT_EXECUTED", "REJECTED", "EXPIRED"}
COLAB_TERMINAL = {"succeeded", "failed", "cancelled", "timed_out"}
KAGGLE_TERMINAL = {"COMPLETE", "ERROR", "CANCEL_ACKNOWLEDGED"}
MAX_SOURCE = 2 * 1024 * 1024


class RouterError(Exception):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def private_dir(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        raise RouterError("STATE_SYMLINK_REJECTED")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise RouterError("STATE_DIRECTORY_NOT_PRIVATE")
    return path


def atomic_write(path, data):
    path = Path(path)
    parent = private_dir(path.parent)
    temp = parent / (".write-" + uuid.uuid4().hex)
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temp.unlink(missing_ok=True)


@contextmanager
def locked(path, timeout=15):
    path = Path(path)
    private_dir(path.parent)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise RouterError("LOCK_FILE_UNSAFE")
        until = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise RouterError("ACCOUNT_OR_REQUEST_BUSY")
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def duration(value):
    if isinstance(value, bool):
        raise RouterError("QUOTA_SCHEMA_INVALID")
    if isinstance(value, str) and re.fullmatch(r"\d+(?:\.\d+)?s", value):
        result = float(value[:-1])
    elif isinstance(value, (int, float)):
        result = float(value)
    else:
        raise RouterError("QUOTA_SCHEMA_INVALID")
    if not math.isfinite(result) or result < 0:
        raise RouterError("QUOTA_SCHEMA_INVALID")
    return result


def artifact_name(value):
    p = Path(value)
    if (not value or p.is_absolute() or any(x in (".", "..") for x in p.parts)
            or "\\" in value or "\x00" in value or len(value.encode()) > 512 or value != p.as_posix()):
        raise RouterError("INVALID_ARTIFACT_NAME")
    return value


def account_identity(provider, account):
    if provider == "colab":
        verified = account.get("status") == "authorized"
        identifier = account.get("account_email")
    else:
        verified = account.get("authenticated") is True
        identifier = account.get("username")
    if not verified or not isinstance(identifier, str) or not identifier.strip():
        raise RouterError("AUTHENTICATED_IDENTITY_UNVERIFIED")
    return digest((provider + ":" + identifier.strip().casefold()).encode())


def validate_provider_intent(provider, intent, payload):
    try:
        payload.decode("utf-8")
    except UnicodeError:
        raise RouterError("SOURCE_MUST_BE_UTF8") from None
    if provider == "colab":
        if len(payload) > 262144:
            raise RouterError("COLAB_SOURCE_LIMIT_EXCEEDED")
        if not 1 <= intent["timeout"] <= 600:
            raise RouterError("COLAB_PROFILE_WALL_LIMIT_EXCEEDED")
        if len(intent["artifacts"]) > 32 or set(intent["artifacts"]) & {"stdout", "stderr"}:
            raise RouterError("COLAB_ARTIFACT_CONTRACT_INVALID")


def safe_receipt(data):
    """Persist identity/status evidence, never full account credentials/URLs."""
    allowed = {"schema", "request_id", "input_digest", "submission_state", "remote_submission_state",
               "remote_effect_unknown", "remote_state", "notebook_ref", "notebook_version", "kernel_id",
               "kernel_session_id", "identity_verified", "last_error", "event_count", "job_id", "state",
               "payload_sha256", "code_sha256", "endpoint", "session_id", "submit_attempts", "error_code",
               "cloud_execution_stopped", "phase", "key", "owned_runtime", "owned_kernel", "profile_hash",
               "runtime_submit_attempts", "release_submit_attempts", "kernel_submit_attempts", "updated_at", "actual_spec",
               "refusal_http_status", "refusal_source", "remote_submission_replayed", "reconciled",
               "local_only_cancel", "cleanup_reason", "never_dispatched", "cleanup_evidence"}
    out = {k: v for k, v in data.items() if k in allowed}
    if isinstance(out.get("last_error"), dict):
        out["last_error"] = {k: v for k, v in out["last_error"].items() if k in ("code", "type")}
    return out


class Launcher:
    def __init__(self, home):
        self.home = Path(home)

    def call(self, provider, account, args, timeout=90):
        argv = [str(self.home / ".local/bin" / ("hepta-" + provider + "-account")), account, *args]
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise RouterError("PROVIDER_OBSERVATION_TIMEOUT") from None
        except OSError:
            raise RouterError("PROVIDER_LAUNCH_FAILED") from None
        if len(result.stdout) > 4 * 1024 * 1024:
            raise RouterError("PROVIDER_RESPONSE_TOO_LARGE")
        try:
            data = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise RouterError("PROVIDER_RESPONSE_INVALID", {"returncode": result.returncode}) from None
        if not isinstance(data, dict):
            raise RouterError("PROVIDER_RESPONSE_INVALID")
        if provider == "kaggle":
            if data.get("ok") is not True:
                error = data.get("error") or {}
                details = {}
                cursor = (error.get("details") or {}).get("next_cursor")
                if error.get("code") == "LOG_REPLACED" and isinstance(cursor, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}:\d+", cursor):
                    details["next_cursor"] = cursor
                raise RouterError(error.get("code", "PROVIDER_FAILED"), details)
            data = data.get("result")
        elif data.get("status") in ("blocked", "authorization_required") and not data.get("allocation_blockers"):
            raise RouterError(data.get("error_code", "PROVIDER_BLOCKED"))
        elif provider == "colab" and data.get("error"):
            code = data.get("code")
            safe_code = code.upper() if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", code) else "ADAPTER_OPERATION_FAILED"
            raise RouterError("COLAB_" + safe_code)
        if not isinstance(data, dict):
            raise RouterError("PROVIDER_RESPONSE_INVALID")
        # Some provider terminal failures deliberately exit nonzero. Evidence in
        # their structured receipt, rather than process exit alone, is decisive.
        return data


class Store:
    def __init__(self, root):
        self.root = private_dir(root)
        self.locks = private_dir(self.root / "locks")
        self.jobs = private_dir(self.root / "jobs")
        self.database = self.root / "router.sqlite3"
        if self.database.is_symlink():
            raise RouterError("STATE_SYMLINK_REJECTED")
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS jobs (request_id TEXT PRIMARY KEY, digest TEXT NOT NULL, "
                       "provider TEXT NOT NULL, account TEXT NOT NULL, state TEXT NOT NULL, "
                       "lease_until REAL NOT NULL, data TEXT NOT NULL)")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.database, timeout=15)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.row_factory = sqlite3.Row
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def get(self, request_id):
        with self.connection() as db:
            row = db.execute("SELECT data FROM jobs WHERE request_id=?", (request_id,)).fetchone()
        if row is None:
            raise RouterError("REQUEST_NOT_FOUND")
        return json.loads(row[0])

    def save(self, record, event=None):
        record["updated_at"] = now()
        if event:
            record.setdefault("events", []).append({"at": now(), **event})
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT provider,account,digest,state,lease_until FROM jobs WHERE request_id=?", (record["request_id"],)).fetchone()
            if old is None or (old["provider"], old["account"], old["digest"]) != (record["provider"], record["account"], record["digest"]):
                raise RouterError("IMMUTABLE_BINDING_CONFLICT")
            if old["state"] in TERMINAL and record["state"] != old["state"]:
                raise RouterError("TERMINAL_JOB_CANNOT_BE_REVIVED")
            if old["state"] == "PLANNED" and record.get("effects") and old["lease_until"] <= time.time():
                raise RouterError("PLAN_LEASE_EXPIRED_BEFORE_EFFECT")
            db.execute("UPDATE jobs SET state=?,lease_until=?,data=? WHERE request_id=?",
                       (record["state"], record["lease_until"], canonical(record).decode(), record["request_id"]))

    def claim_execution(self, record):
        """Atomically retain the reservation before any auth/network latency."""
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE request_id=?", (record["request_id"],)).fetchone()
            if row is None or (row["provider"], row["account"], row["digest"]) != (record["provider"], record["account"], record["digest"]):
                raise RouterError("IMMUTABLE_BINDING_CONFLICT")
            current = json.loads(row["data"])
            if row["state"] != "PLANNED":
                return current
            if current.get("effects"):
                raise RouterError("PLANNED_JOB_HAS_EFFECTS")
            expired = row["lease_until"] <= time.time()
            current["state"] = "EXPIRED" if expired else "PREPARING"
            current["updated_at"] = now()
            current.setdefault("events", []).append({"at": now(), "event": "unexecuted_plan_expired" if expired else "execution_reservation_claimed"})
            db.execute("UPDATE jobs SET state=?,data=? WHERE request_id=?", (current["state"], canonical(current).decode(), current["request_id"]))
        return current

    def expire(self, db):
        rows = db.execute("SELECT data FROM jobs WHERE state='PLANNED' AND lease_until<?", (time.time(),)).fetchall()
        for row in rows:
            record = json.loads(row[0])
            if record.get("effects"):
                continue
            record["state"] = "EXPIRED"
            record["updated_at"] = now()
            db.execute("UPDATE jobs SET state='EXPIRED',data=? WHERE request_id=?", (canonical(record).decode(), record["request_id"]))

    def reservations(self):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire(db)
            rows = db.execute("SELECT provider,account,request_id,state FROM jobs WHERE state NOT IN ('COLLECTED','CLEANED_NOT_EXECUTED','REJECTED','EXPIRED')").fetchall()
        return [dict(row) for row in rows]

    def job_dir(self, request_id):
        return private_dir(self.jobs / digest(request_id.encode()))

    def request_lock(self, request_id):
        return locked(self.locks / ("request-" + digest(request_id.encode()) + ".lock"), timeout=1)

    def account_lock(self, provider, account):
        return locked(self.locks / ("account-" + digest((provider + ":" + account).encode()) + ".lock"), timeout=120)


class Router:
    def __init__(self, home=None, state=None, launcher=None):
        self.home = Path(home or Path.home()).absolute()
        self.store = Store(state or self.home / ".local/state/hepta-compute")
        self.launcher = launcher or Launcher(self.home)

    def accounts(self, provider=None, account=None):
        result = []
        for name in PROVIDERS:
            if provider and name != provider:
                continue
            path = self.home / ".config" / ("hepta-" + name) / "accounts.json"
            try:
                data = json.loads(path.read_text())
            except (OSError, ValueError):
                raise RouterError("ACCOUNT_CONFIGURATION_UNAVAILABLE", {"provider": name}) from None
            entries = data.get("accounts")
            if not isinstance(entries, dict):
                raise RouterError("ACCOUNT_CONFIGURATION_INVALID", {"provider": name})
            default = data.get("default_account")
            ordered = sorted(entries, key=lambda key: (key != default, key))
            for alias in ordered:
                if account and account != alias:
                    continue
                if not SAFE_ID.fullmatch(alias):
                    raise RouterError("INVALID_ACCOUNT_ALIAS")
                result.append((name, alias))
        if not result:
            raise RouterError("ACCOUNT_NOT_CONFIGURED")
        return result

    def probe(self, provider, account, accelerator, wall_seconds, request_id):
        result = {"provider": provider, "account": account, "observed_at": now(), "authenticated": False,
                  "ready": False, "blockers": [], "resource": {"accelerator": accelerator}}
        try:
            with self.store.account_lock(provider, account):
                if provider == "colab":
                    inv = self.launcher.call(provider, account, ["manage", "inventory"])
                    result["authenticated"] = inv.get("account", {}).get("status") == "authorized"
                    result["account_identity_sha256"] = account_identity(provider, inv.get("account", {}))
                    eligibility = inv.get("eligibility", {})
                    assignments = inv.get("assignments", {})
                    kind = "DEFAULT" if accelerator == "cpu" else "GPU"
                    model = "NONE" if accelerator == "cpu" else accelerator
                    eligible = eligibility.get("status") == "available" and any(
                        x.get("variant") == kind and x.get("accelerator") == model and x.get("shape") == "STANDARD"
                        and x.get("eligible") is True for x in eligibility.get("runtime_specs", []))
                    result["resource"].update(eligible=eligible, eligibility_evidence="public_runtime_specs_eligible_true" if eligible else None)
                    if not eligible:
                        result["blockers"].append("RESOURCE_NOT_ELIGIBLE")
                    result["active_runtime_count"] = len(assignments.get("runtimes", [])) if assignments.get("status") == "available" else None
                    if assignments.get("status") != "available":
                        result["blockers"].append("ASSIGNMENTS_UNKNOWN")
                    elif result["active_runtime_count"]:
                        result["blockers"].append("EXISTING_RUNTIME_REQUIRES_EXPLICIT_BINDING")
                    readiness = self.launcher.call(provider, account, ["manage", "readiness"])
                    result["profile_binding_ready"] = readiness.get("job_profile_supported") is True
                    result["allocation_blockers"] = [
                        {k: item.get(k) for k in ("key", "phase", "error_code") if item.get(k) is not None}
                        for item in readiness.get("allocation_blockers", [])]
                    if readiness.get("can_create") is not True:
                        result["blockers"].append("ALLOCATION_LEDGER_BLOCKED")
                    if not result["profile_binding_ready"]:
                        result["blockers"].append("JOB_PROFILE_BINDING_UNAVAILABLE")
                else:
                    quota = self.launcher.call(provider, account, ["batch", "quota"])
                    result["authenticated"] = quota.get("account", {}).get("authenticated") is True
                    result["account_identity_sha256"] = account_identity(provider, quota.get("account", {}))
                    raw = quota.get("raw_quota", {})
                    gpu = raw.get("gpuQuota", raw.get("gpu_quota"))
                    if not isinstance(gpu, dict):
                        raise RouterError("QUOTA_SCHEMA_INVALID")
                    remaining = max(0.0, duration(gpu.get("totalTimeAllowed", 0)) - duration(gpu.get("timeUsed", "0s")) - duration(gpu.get("timeReserved", "0s")))
                    result["resource"].update(remaining_seconds=remaining, eligible=accelerator == "cpu" or remaining >= wall_seconds)
                    if accelerator != "cpu" and remaining < wall_seconds:
                        result["blockers"].append("INSUFFICIENT_ACCOUNT_QUOTA")
                    readiness = self.launcher.call(provider, account, ["batch", "readiness", "--request-id", request_id])
                    result["notebook_scope_ready"] = readiness.get("ready") is True
                    if not result["notebook_scope_ready"]:
                        result["blockers"].append((readiness.get("error") or {}).get("code", "NOTEBOOK_PREFLIGHT_FAILED"))
                if not result["authenticated"]:
                    result["blockers"].append("AUTHORIZATION_UNVERIFIED")
                result["ready"] = not result["blockers"]
        except RouterError as exc:
            result["blockers"].append(exc.code)
        result["completed_at"] = now()
        return result

    def evaluate(self, *, provider=None, account=None, accelerator="T4", wall_seconds=120, request_id=None):
        if not 1 <= wall_seconds <= 43200:
            raise RouterError("INVALID_TIMEOUT")
        pairs = self.accounts(provider, account)
        key = request_id or ("assessment-" + uuid.uuid4().hex)
        started = time.monotonic()
        observations = []
        with ThreadPoolExecutor(max_workers=min(6, len(pairs))) as pool:
            futures = [pool.submit(self.probe, p, a, accelerator, wall_seconds, key) for p, a in pairs]
            for future in as_completed(futures):
                observations.append(future.result())
        reservations = {(x["provider"], x["account"]): x for x in self.store.reservations()}
        for observation in observations:
            held = reservations.get((observation["provider"], observation["account"]))
            if held:
                observation["reservation"] = held
                observation["blockers"].append("ACCOUNT_RESERVED")
                observation["ready"] = False
        order = {pair: i for i, pair in enumerate(pairs)}
        observations.sort(key=lambda x: order[(x["provider"], x["account"])])
        return {"schema": "hepta-compute-evaluation-v1", "observed_at": now(),
                "elapsed_seconds": round(time.monotonic() - started, 3), "candidates": observations,
                "quota_is_allocation_guarantee": False, "automatic_account_rotation": False}

    def plan(self, request_id, source, *, provider=None, account=None, accelerator="T4", wall_seconds=120, artifacts=()):
        if not SAFE_ID.fullmatch(request_id):
            raise RouterError("INVALID_REQUEST_ID")
        source = Path(source)
        if not source.is_absolute() or source.is_symlink():
            raise RouterError("SOURCE_MUST_BE_ABSOLUTE_REGULAR_FILE")
        with source.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise RouterError("SOURCE_MUST_BE_ABSOLUTE_REGULAR_FILE")
            payload = stream.read(MAX_SOURCE + 1)
        if not payload or len(payload) > MAX_SOURCE:
            raise RouterError("INVALID_SOURCE_SIZE")
        if not 1 <= wall_seconds <= 43200:
            raise RouterError("INVALID_TIMEOUT")
        names = sorted(set(artifact_name(value) for value in artifacts))
        intent = {"source_sha256": digest(payload), "timeout": wall_seconds, "accelerator": accelerator,
                  "requested_provider": provider, "requested_account": account, "artifacts": names,
                  "kaggle_internet": False, "kaggle_private": True}
        validate_provider_intent(provider or "kaggle", intent, payload)
        fingerprint = digest(canonical(intent))
        with self.store.request_lock(request_id):
            try:
                existing = self.store.get(request_id)
            except RouterError as exc:
                if exc.code != "REQUEST_NOT_FOUND":
                    raise
            else:
                if existing["digest"] != fingerprint:
                    raise RouterError("REQUEST_INTENT_CONFLICT")
                return existing
            provider_key = "hc-" + digest(request_id.encode())[:40]
            evaluation = self.evaluate(provider=provider, account=account, accelerator=accelerator,
                                       wall_seconds=wall_seconds, request_id=provider_key)
            for candidate in evaluation["candidates"]:
                try:
                    validate_provider_intent(candidate["provider"], intent, payload)
                except RouterError as exc:
                    candidate["blockers"].append(exc.code)
                    candidate["ready"] = False
            candidates = [x for x in evaluation["candidates"] if x["ready"]]
            if not candidates:
                raise RouterError("NO_READY_ACCOUNT", {"evaluation": evaluation})
            directory = self.store.job_dir(request_id)
            frozen = directory / "source.py"
            atomic_write(frozen, payload)
            with self.store.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                self.store.expire(db)
                occupied = {(row[0], row[1]) for row in db.execute("SELECT provider,account FROM jobs WHERE state NOT IN ('COLLECTED','CLEANED_NOT_EXECUTED','REJECTED','EXPIRED')")}
                selected = next((x for x in candidates if (x["provider"], x["account"]) not in occupied), None)
                if selected is None:
                    raise RouterError("CANDIDATES_RESERVED_DURING_PLANNING")
                record = {"schema": "hepta-compute-job-v1", "router_version": VERSION, "request_id": request_id,
                          "provider_request_id": provider_key, "provision_key": provider_key, "digest": fingerprint,
                          "provider": selected["provider"], "account": selected["account"], "intent": intent,
                          "account_identity_sha256": selected["account_identity_sha256"],
                          "execution_configuration": {"network": "disabled" if selected["provider"] == "kaggle" else "provider_default",
                              "visibility": "private_notebook" if selected["provider"] == "kaggle" else "authenticated_account_runtime"},
                          "source": str(frozen), "state": "PLANNED", "created_at": now(), "updated_at": now(),
                          "lease_until": time.time() + 900, "evaluation": evaluation, "effects": {}, "receipts": {},
                          "events": [{"at": now(), "event": "planned_and_reserved"}]}
                db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)", (request_id, fingerprint, record["provider"],
                           record["account"], record["state"], record["lease_until"], canonical(record).decode()))
            return record

    def call(self, record, args, timeout=90):
        return self.launcher.call(record["provider"], record["account"], args, timeout=timeout)

    def colab_args(self, record, verb, *args):
        return ["--provision-key", record["provision_key"], "run", verb, *args]

    def effect(self, record, stage, args, timeout=90):
        old = record["effects"].get(stage)
        if old:
            if old["status"] == "confirmed":
                return record["receipts"][stage]
            raise RouterError("REMOTE_EFFECT_REQUIRES_RECONCILIATION", {"stage": stage})
        record["effects"][stage] = {"status": "started", "at": now()}
        record["state"] = "EFFECT_PENDING"
        record["lease_until"] = 0
        self.store.save(record, {"event": "effect_intent_persisted", "stage": stage})
        try:
            output = self.call(record, args, timeout=timeout)
        except RouterError as exc:
            record["effects"][stage].update(status="unknown", error_code=exc.code)
            record["state"] = "RECONCILIATION_REQUIRED"
            self.store.save(record, {"event": "effect_response_unconfirmed", "stage": stage, "error_code": exc.code})
            raise
        receipt = safe_receipt(output)
        confirmed = True
        if stage == "allocate":
            confirmed = output.get("phase") in ("runtime_ready", "kernel_ready", "bound")
        elif stage == "bind":
            confirmed = output.get("phase") == "bound"
        elif stage == "release":
            confirmed = output.get("phase") == "released"
        elif stage == "run":
            confirmed = output.get("state") in COLAB_TERMINAL | {"running", "submitted"}
        elif stage == "submit":
            confirmed = output.get("remote_effect_unknown") is False
        elif stage == "close_unstarted":
            confirmed = (output.get("phase") == "released" and output.get("never_dispatched") is True
                         and output.get("cleanup_reason") == "unstarted_compute")
        elif stage == "cancel_unstarted":
            confirmed = output.get("local_only_cancel") is True and output.get("submit_attempts") == 0
        record["effects"][stage]["status"] = "confirmed" if confirmed else "unknown"
        record["receipts"][stage] = receipt
        self.store.save(record, {"event": "effect_response_received", "stage": stage})
        return output

    def observe_locked(self, record):
        try:
            if record["provider"] == "kaggle":
                recovering = record["effects"].get("submit", {}).get("status") in ("started", "unknown")
                args = ["batch", "resume" if recovering else "status", "--request-id", record["provider_request_id"]]
                receipt = self.call(record, args)
                if not recovering and (receipt.get("submission_state") in ("UNKNOWN", "SUBMITTING") or receipt.get("remote_effect_unknown") is True):
                    receipt = self.call(record, ["batch", "resume", "--request-id", record["provider_request_id"]])
                record["receipts"]["observation"] = safe_receipt(receipt)
                if (receipt.get("identity_verified") is True and receipt.get("remote_effect_unknown") is False
                        and "submit" in record["effects"]):
                    record["effects"]["submit"]["status"] = "confirmed"
                if receipt.get("remote_submission_state") == "NOT_SENT" and receipt.get("remote_effect_unknown") is False:
                    record["state"] = "REJECTED"
                elif receipt.get("remote_state") in KAGGLE_TERMINAL and receipt.get("identity_verified") is True:
                    record["state"] = "REMOTE_TERMINAL"
                    record["outcome"] = {"provider_terminal_state": receipt["remote_state"],
                        "compute_succeeded": receipt["remote_state"] == "COMPLETE",
                        "accelerator_requested": record["intent"]["accelerator"],
                        "accelerator_execution_verification": "requires_task_specific_artifact"}
                elif receipt.get("submission_state") == "ACCEPTED" and receipt.get("remote_effect_unknown") is False:
                    record["state"] = "RUNNING"
                else:
                    record["state"] = "RECONCILIATION_REQUIRED"
            else:
                job_id = record.get("adapter_job_id")
                if job_id:
                    receipt = self.call(record, self.colab_args(record, "status", "--job-id", job_id))
                    record["receipts"]["observation"] = safe_receipt(receipt)
                    manifest = receipt.get("artifacts") or {}
                    record["artifact_manifest"] = {name: {k: item.get(k) for k in ("size", "sha256")}
                        for name, item in manifest.items() if isinstance(item, dict)
                        and name in set(record["intent"]["artifacts"]) | {"stdout", "stderr"}}
                    if receipt.get("state") in COLAB_TERMINAL and receipt.get("cloud_execution_stopped") is True:
                        record["state"] = "REMOTE_TERMINAL"
                        record["outcome"] = {"provider_terminal_state": receipt["state"],
                            "compute_succeeded": receipt["state"] == "succeeded",
                            "accelerator_requested": record["intent"]["accelerator"],
                            "accelerator_execution_verification": "requires_task_specific_artifact"}
                    elif receipt.get("state") in ("running", "submitted"):
                        record["state"] = "RUNNING"
                    else:
                        record["state"] = "RECONCILIATION_REQUIRED"
                elif "allocate" in record["effects"]:
                    receipt = self.call(record, ["manage", "reconcile", "--key", record["provision_key"]])
                    record["receipts"]["provision_observation"] = safe_receipt(receipt)
                    if receipt.get("phase") in ("runtime_ready", "kernel_ready", "bound"):
                        record["effects"]["allocate"]["status"] = "confirmed"
                        record["receipts"]["allocate"] = safe_receipt(receipt)
                    if receipt.get("phase") == "bound" and "bind" in record["effects"]:
                        record["effects"]["bind"]["status"] = "confirmed"
                        record["receipts"]["bind"] = safe_receipt(receipt)
                        if "submit_local" in record["effects"] and not record.get("adapter_job_id"):
                            lookup = self.inspect_submit_key(record)
                            if lookup.get("found") is True:
                                job = lookup["job"]
                                record["effects"]["submit_local"]["status"] = "confirmed"
                                record["receipts"]["submit_local"] = safe_receipt(job)
                                if job.get("submit_attempts", 0) != 0:
                                    record["effects"]["run"] = {"status": "confirmed", "at": now(), "recovered_from_original_ledger": True}
                                    record["receipts"]["run"] = safe_receipt(job)
                    # Runtime existence alone does not prove that a compute job
                    # ran, nor authorize retrying the next uncertain effect.
                    record["state"] = "RECONCILIATION_REQUIRED"
                    if (receipt.get("phase") == "allocation_refused" and receipt.get("owned_runtime") is False
                            and receipt.get("refusal_http_status") == 412
                            and receipt.get("refusal_source") == "official_sdk_http_412"):
                        record["effects"]["allocate"]["status"] = "rejected"
                        record["receipts"]["allocate"] = safe_receipt(receipt)
                        record["state"] = "REJECTED"
                        record["outcome"] = {"provider_terminal_state": "allocation_refused", "compute_succeeded": False,
                                             "error_code": "ALLOCATION_REFUSED_PRECONDITION"}
            record.pop("observation_error", None)
        except RouterError as exc:
            record["observation_error"] = exc.code
            record["state"] = "RECONCILIATION_REQUIRED"
        self.store.save(record, {"event": "observed_original_binding"})
        return record

    def inspect_submit_key(self, record):
        lookup = self.call(record, self.colab_args(record, "inspect-key", "--key", record["provider_request_id"]))
        if lookup.get("idempotency_key") != record["provider_request_id"]:
            raise RouterError("LOCAL_SUBMIT_KEY_IDENTITY_MISMATCH")
        expected_profile = record["receipts"].get("bind", {}).get("profile_hash")
        if expected_profile and lookup.get("profile_hash") != expected_profile:
            raise RouterError("LOCAL_SUBMIT_PROFILE_IDENTITY_MISMATCH")
        evidence = {key: lookup.get(key) for key in ("found", "idempotency_key", "profile_hash", "ledger_present", "absence_verified")}
        if lookup.get("found") is True:
            job, intent = lookup.get("job", {}), lookup.get("request", {})
            payload = Path(record["source"]).read_bytes()
            code_hash = digest(payload.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode())
            if (intent.get("code_sha256") != code_hash or job.get("code_sha256") != code_hash
                    or intent.get("wall_seconds") != record["intent"]["timeout"]
                    or intent.get("artifacts") != sorted(record["intent"]["artifacts"])
                    or intent.get("runner_matches_current") is not True):
                raise RouterError("LOCAL_SUBMIT_INTENT_MISMATCH")
            job_id = job.get("job_id")
            if not isinstance(job_id, str) or not SAFE_ID.fullmatch(job_id):
                raise RouterError("ADAPTER_JOB_ID_UNVERIFIED")
            if record.get("adapter_job_id") not in (None, job_id):
                raise RouterError("ADAPTER_JOB_IDENTITY_MISMATCH")
            record["adapter_job_id"] = job_id
            evidence["job"] = safe_receipt(job)
            evidence["request"] = {key: intent.get(key) for key in ("code_sha256", "wall_seconds", "artifacts", "runner_sha256", "runner_matches_current")}
        elif lookup.get("found") is not False:
            raise RouterError("LOCAL_SUBMIT_LOOKUP_INVALID")
        record["submit_lookup"] = evidence
        self.store.save(record, {"event": "original_local_submit_key_observed"})
        return lookup

    def cleanup_unstarted(self, record, observe_only=False):
        if record["provider"] != "colab" or "allocate" not in record["effects"] or "run" in record["effects"]:
            raise RouterError("UNSTARTED_CLEANUP_NOT_AUTHORIZED")
        if "close_unstarted" in record["effects"]:
            closed = record["receipts"].get("close_unstarted", {})
            if (closed.get("phase") != "released" or closed.get("never_dispatched") is not True
                    or closed.get("cleanup_reason") != "unstarted_compute"):
                closed = self.call(record, ["manage", "reconcile", "--key", record["provision_key"]])
        else:
            if observe_only:
                return record
            if "submit_local" in record["effects"]:
                lookup = self.inspect_submit_key(record)
                if lookup.get("found") is False:
                    if lookup.get("absence_verified") is not True:
                        raise RouterError("LOCAL_LEDGER_ABSENCE_UNVERIFIED")
                else:
                    job = lookup["job"]
                    if job.get("submit_attempts") != 0 or job.get("state") not in ("queued", "cancelled"):
                        raise RouterError("LOCAL_JOB_MAY_HAVE_DISPATCHED")
                    if job["state"] == "queued":
                        if "cancel_unstarted" in record["effects"]:
                            raise RouterError("LOCAL_CANCEL_REQUIRES_RECONCILIATION")
                        job = self.effect(record, "cancel_unstarted", self.colab_args(record, "cancel", "--job-id", record["adapter_job_id"]))
                    if job.get("local_only_cancel") is not True or job.get("submit_attempts") != 0 or job.get("state") != "cancelled":
                        raise RouterError("LOCAL_CANCELLATION_UNVERIFIED")
                    if "cancel_unstarted" in record["effects"]:
                        record["effects"]["cancel_unstarted"]["status"] = "confirmed"
                        record["receipts"]["cancel_unstarted"] = safe_receipt(job)
                        self.store.save(record, {"event": "local_unstarted_cancellation_confirmed"})
            closed = self.effect(record, "close_unstarted", ["manage", "close-unstarted", "--key", record["provision_key"]], timeout=150)
        record["receipts"]["close_unstarted"] = safe_receipt(closed)
        if (closed.get("phase") != "released" or closed.get("never_dispatched") is not True
                or closed.get("cleanup_reason") != "unstarted_compute"):
            record["state"] = "CLEANUP_PENDING"
            self.store.save(record, {"event": "unstarted_cleanup_unconfirmed"})
            return record
        record["effects"]["close_unstarted"]["status"] = "confirmed"
        record["state"] = "CLEANED_NOT_EXECUTED"
        record["lease_until"] = 0
        record["outcome"] = {"provider_terminal_state": "never_dispatched", "compute_succeeded": False,
                              "resource_released": True, "error_code": record.get("last_error", "COMPUTE_NOT_DISPATCHED")}
        directory = private_dir(self.store.job_dir(record["request_id"]) / "outputs")
        record["outputs"] = {"directory": str(directory), "files": [], "logs": {}, "not_created_reason": "computation_was_not_dispatched"}
        self.store.save(record, {"event": "owned_resource_cleaned_without_execution"})
        atomic_write(directory / "router-receipt.json", canonical(record) + b"\n")
        return record

    def execute(self, request_id):
        with self.store.request_lock(request_id):
            record = self.store.get(request_id)
            if record["state"] in TERMINAL:
                return record
            with self.store.account_lock(record["provider"], record["account"]):
                if "close_unstarted" in record["effects"]:
                    return self.cleanup_unstarted(record, observe_only=True)
                if "cancel_unstarted" in record["effects"]:
                    return self.observe_locked(record)
                if record["state"] not in ("PLANNED", "PREPARING"):
                    record = self.observe_locked(record)
                    local_job = record["receipts"].get("observation", record["receipts"].get("submit_local", {}))
                    if (record["provider"] == "colab" and local_job.get("state") == "cancelled"
                            and local_job.get("submit_attempts") == 0 and local_job.get("local_only_cancel") is True
                            and "run" not in record["effects"]):
                        record["state"] = "LOCAL_CANCELLED"
                        self.store.save(record, {"event": "cancelled_local_job_not_dispatched"})
                        return record
                    # Advance only a stage which has never started, following
                    # confirmed earlier stages. Never replay an unknown effect.
                    if (record["provider"] != "colab" or "run" in record["effects"]
                            or record["state"] == "REMOTE_TERMINAL"
                            or any(x["status"] != "confirmed" for x in record["effects"].values())):
                        return record
                if record["state"] == "PLANNED":
                    record = self.store.claim_execution(record)
                    if record["state"] != "PREPARING":
                        return record
                try:
                    data = Path(record["source"]).read_bytes()
                    if digest(data) != record["intent"]["source_sha256"]:
                        raise RouterError("SOURCE_SNAPSHOT_CHANGED")
                    validate_provider_intent(record["provider"], record["intent"], data)
                    account = self.call(record, ["manage" if record["provider"] == "colab" else "batch", "account"])
                    if account_identity(record["provider"], account) != record["account_identity_sha256"]:
                        raise RouterError("ACCOUNT_IDENTITY_CHANGED")
                except (RouterError, OSError) as exc:
                    code = exc.code if isinstance(exc, RouterError) else "SOURCE_SNAPSHOT_UNAVAILABLE"
                    if not record["effects"] and record["state"] == "PREPARING":
                        record["state"] = "PLANNED" if record["lease_until"] > time.time() else "EXPIRED"
                        record["last_error"] = code
                        self.store.save(record, {"event": "pre_effect_preparation_failed", "error_code": code})
                    raise RouterError(code) from None
                intent = record["intent"]
                try:
                    if record["provider"] == "kaggle":
                        model = "cpu" if intent["accelerator"] == "cpu" else "NvidiaTeslaT4"
                        self.effect(record, "submit", ["batch", "submit", "--request-id", record["provider_request_id"],
                                    "--source", record["source"], "--timeout", str(intent["timeout"]), "--accelerator", model], timeout=180)
                    else:
                        model = "NONE" if intent["accelerator"] == "cpu" else intent["accelerator"]
                        allocation = self.effect(record, "allocate", ["manage", "create", "--key", record["provision_key"],
                            "--kind", "cpu" if model == "NONE" else "gpu", "--accelerator", model, "--shape", "standard"], timeout=150)
                        if allocation.get("phase") not in ("runtime_ready", "kernel_ready", "bound"):
                            raise RouterError("ALLOCATION_NOT_CONFIRMED")
                        bound = self.effect(record, "bind", ["--provision-key", record["provision_key"], "manage", "bind",
                                            "--key", record["provision_key"]], timeout=150)
                        if bound.get("phase") != "bound":
                            raise RouterError("PROFILE_BINDING_NOT_CONFIRMED")
                        args = self.colab_args(record, "submit", "--key", record["provider_request_id"], "--code-file",
                                               record["source"], "--wall-seconds", str(intent["timeout"]))
                        for name in intent["artifacts"]:
                            args.extend(["--artifact", name])
                        submitted = self.effect(record, "submit_local", args)
                        job_id = submitted.get("job_id")
                        if not isinstance(job_id, str) or not SAFE_ID.fullmatch(job_id):
                            raise RouterError("ADAPTER_JOB_ID_UNVERIFIED")
                        record["adapter_job_id"] = job_id
                        self.store.save(record, {"event": "adapter_job_bound"})
                        self.effect(record, "run", self.colab_args(record, "run", "--job-id", job_id), timeout=intent["timeout"] + 120)
                except RouterError as exc:
                    record["last_error"] = exc.code
                    record["state"] = "RECONCILIATION_REQUIRED"
                    self.store.save(record, {"event": "execution_needs_observation", "error_code": exc.code})
                return self.observe_locked(record)

    def inspect(self, request_id):
        with self.store.request_lock(request_id):
            record = self.store.get(request_id)
            if record["state"] in TERMINAL or record["state"] in ("PLANNED", "PREPARING") and not record["effects"]:
                return record
            with self.store.account_lock(record["provider"], record["account"]):
                if "close_unstarted" in record["effects"]:
                    return self.cleanup_unstarted(record, observe_only=True)
                return self.observe_locked(record)

    def kaggle_logs(self, record, directory, max_bytes):
        cursor, pages, chunks, replaced = None, [], [], 0
        while len(pages) < 1024:
            args = ["batch", "logs", "--request-id", record["provider_request_id"], "--limit", "65536"]
            if cursor:
                args.extend(["--cursor", cursor])
            try:
                page = self.call(record, args)
            except RouterError as exc:
                if exc.code == "LOG_REPLACED" and exc.details.get("next_cursor") and replaced < 2:
                    cursor, pages, chunks = exc.details["next_cursor"], [], []
                    replaced += 1
                    continue
                raise
            size = page.get("snapshot_bytes")
            text = page.get("text")
            following = page.get("next_cursor")
            if not isinstance(size, int) or size < 0 or size > max_bytes or not isinstance(text, str):
                raise RouterError("LOG_SIZE_OR_SCHEMA_INVALID")
            if not isinstance(following, str) or not re.fullmatch(r"\d+:\d+", following):
                raise RouterError("LOG_CURSOR_INVALID")
            if cursor and page.get("cursor") != cursor:
                raise RouterError("LOG_CURSOR_IDENTITY_CHANGED")
            pages.append(page)
            chunks.append(text.encode())
            if sum(map(len, chunks)) > max_bytes:
                raise RouterError("LOG_COLLECTION_LIMIT")
            if page.get("eof") is True:
                payload = b"".join(chunks)
                redacted = any(item.get("redacted") is True for item in pages)
                if not redacted and (len(payload) != size or digest(payload) != page.get("snapshot_sha256")):
                    raise RouterError("LOG_INTEGRITY_MISMATCH")
                atomic_write(directory / "stdout.log", payload)
                atomic_write(directory / "provider-log-pages.json", canonical(pages) + b"\n")
                return {"path": str(directory / "stdout.log"), "bytes": len(payload), "sha256": digest(payload),
                        "redacted": redacted, "provider_snapshot_sha256": page.get("snapshot_sha256"), "complete": True}
            if following == cursor:
                raise RouterError("LOG_CURSOR_STALLED")
            cursor = following
        raise RouterError("LOG_COLLECTION_LIMIT")

    def verify_retained_outputs(self, record, max_bytes):
        outputs = record.get("outputs") or {}
        directory = self.store.job_dir(record["request_id"]) / "outputs"
        if outputs.get("directory") != str(directory):
            raise RouterError("RETAINED_OUTPUT_DIRECTORY_UNVERIFIED")
        total = 0
        entries = list(outputs.get("files", [])) + list(outputs.get("logs", {}).values())
        if not entries:
            raise RouterError("RETAINED_OUTPUTS_MISSING")
        for entry in entries:
            path = Path(entry.get("path", ""))
            if not path.is_absolute() or path.is_symlink() or not path.resolve().is_relative_to(directory.resolve()):
                raise RouterError("RETAINED_OUTPUT_PATH_UNSAFE")
            if path.stat().st_size != entry.get("bytes"):
                raise RouterError("RETAINED_OUTPUT_INTEGRITY_MISMATCH")
            if entry.get("bytes", -1) < 0 or entry["bytes"] > max_bytes:
                raise RouterError("ARTIFACT_COLLECTION_LIMIT")
            payload = path.read_bytes()
            if len(payload) != entry["bytes"] or digest(payload) != entry.get("sha256"):
                raise RouterError("RETAINED_OUTPUT_INTEGRITY_MISMATCH")
            if "name" in entry:
                total += len(payload)
        if total > max_bytes:
            raise RouterError("ARTIFACT_COLLECTION_LIMIT")
        receipt = record.get("receipts", {}).get("observation", {})
        if receipt.get("state") not in COLAB_TERMINAL or receipt.get("cloud_execution_stopped") is not True:
            raise RouterError("RETAINED_TERMINAL_EVIDENCE_UNVERIFIED")
        return directory

    def finish_collection(self, record, directory):
        record["state"] = "COLLECTED"
        record["lease_until"] = 0
        self.store.save(record, {"event": "complete_and_resources_reconciled"})
        atomic_write(directory / "router-receipt.json", canonical(record) + b"\n")
        return record

    def collect(self, request_id, max_bytes=64 * 1024 * 1024):
        if not 1 <= max_bytes <= 1024 * 1024 * 1024:
            raise RouterError("INVALID_COLLECTION_BYTE_LIMIT")
        with self.store.request_lock(request_id):
            record = self.store.get(request_id)
            if record["state"] in TERMINAL:
                return record
            if record["state"] in ("PLANNED", "PREPARING") and not record["effects"]:
                raise RouterError("REQUEST_NOT_EXECUTED", {"job": record})
            with self.store.account_lock(record["provider"], record["account"]):
                if "close_unstarted" in record["effects"]:
                    return self.cleanup_unstarted(record, observe_only=True)
                if record["provider"] == "colab" and "release" in record["effects"] and record.get("outputs"):
                    directory = self.verify_retained_outputs(record, max_bytes)
                    released = record["receipts"].get("release", {})
                    if released.get("phase") != "released":
                        released = self.call(record, ["manage", "reconcile", "--key", record["provision_key"]])
                    record["receipts"]["release"] = safe_receipt(released)
                    if released.get("phase") != "released":
                        record["state"] = "RELEASE_PENDING"
                        self.store.save(record, {"event": "resource_release_unconfirmed"})
                        return record
                    record["effects"]["release"]["status"] = "confirmed"
                    return self.finish_collection(record, directory)
                record = self.observe_locked(record)
                if record["state"] != "REMOTE_TERMINAL":
                    if record["state"] == "REJECTED":
                        return record
                    if record["provider"] == "colab" and "allocate" in record["effects"] and "run" not in record["effects"]:
                        return self.cleanup_unstarted(record)
                    raise RouterError("REMOTE_COMPLETION_UNCONFIRMED", {"job": record})
                directory = private_dir(self.store.job_dir(request_id) / "outputs")
                artifact_directory = private_dir(directory / "artifacts")
                log_directory = private_dir(directory / "logs")
                files, logs, missing = [], {}, []
                if record["provider"] == "kaggle":
                    logs["stdout"] = self.kaggle_logs(record, log_directory, max_bytes)
                    if record["outcome"]["compute_succeeded"]:
                        artifacts = self.call(record, ["batch", "artifacts", "--request-id", record["provider_request_id"],
                                                      "--max-bytes", str(max_bytes)], timeout=180)
                    else:
                        # The adapter intentionally allows artifact retrieval
                        # only for COMPLETE versions; retain failed-task logs.
                        artifacts = {"directory": str(directory), "files": []}
                    base = Path(artifacts.get("directory", ""))
                    if not base.is_absolute():
                        raise RouterError("ARTIFACT_DIRECTORY_UNVERIFIED")
                    total = 0
                    for entry in artifacts.get("files", []):
                        name = artifact_name(entry["path"])
                        path = base / name
                        if path.resolve().is_relative_to(base.resolve()) is False or path.is_symlink():
                            raise RouterError("ARTIFACT_PATH_UNSAFE")
                        payload = path.read_bytes()
                        total += len(payload)
                        if total > max_bytes:
                            raise RouterError("ARTIFACT_COLLECTION_LIMIT")
                        if len(payload) != entry["bytes"] or digest(payload) != entry["sha256"]:
                            raise RouterError("ARTIFACT_INTEGRITY_MISMATCH")
                        target = artifact_directory / name
                        atomic_write(target, payload)
                        files.append({"name": name, "path": str(target), "bytes": len(payload), "sha256": digest(payload)})
                    missing = sorted(set(record["intent"]["artifacts"]) - {x["name"] for x in files})
                    if missing and record["outcome"]["compute_succeeded"]:
                        raise RouterError("EXPECTED_ARTIFACT_MISSING", {"names": missing})
                else:
                    job_id = record["adapter_job_id"]
                    for stream in ("stdout", "stderr"):
                        chunks = []
                        offset = 0
                        for _ in range(1024):
                            chunk = self.call(record, self.colab_args(record, "read", "--job-id", job_id, "--stream", stream,
                                                                     "--offset", str(offset), "--limit", "16384"))
                            if chunk.get("verified") is not True:
                                raise RouterError("LOG_INTEGRITY_UNVERIFIED")
                            try:
                                raw = base64.b64decode(chunk.get("data_base64", ""), validate=True)
                            except (ValueError, TypeError):
                                raise RouterError("LOG_BYTES_INVALID") from None
                            if digest(raw) != chunk.get("sha256"):
                                raise RouterError("LOG_INTEGRITY_MISMATCH")
                            chunks.append(raw)
                            following = chunk.get("next_offset")
                            if following != offset + len(raw) or sum(map(len, chunks)) > max_bytes:
                                raise RouterError("LOG_CURSOR_OR_SIZE_INVALID")
                            if chunk.get("eof") is True:
                                break
                            if not isinstance(following, int) or following <= offset:
                                raise RouterError("LOG_CURSOR_STALLED")
                            offset = following
                        else:
                            raise RouterError("LOG_COLLECTION_LIMIT")
                        payload = b"".join(chunks)
                        atomic_write(log_directory / (stream + ".log"), payload)
                        logs[stream] = {"path": str(log_directory / (stream + ".log")), "bytes": len(payload),
                                        "sha256": digest(payload), "complete": True}
                    total = 0
                    for name in record["intent"]["artifacts"]:
                        entry = record.get("artifact_manifest", {}).get(name)
                        if entry is None and not record["outcome"]["compute_succeeded"]:
                            missing.append(name)
                            continue
                        if not isinstance(entry, dict) or not isinstance(entry.get("size"), int):
                            raise RouterError("ARTIFACT_MANIFEST_UNVERIFIED")
                        total += entry["size"]
                        if total > max_bytes or entry["size"] < 0:
                            raise RouterError("ARTIFACT_COLLECTION_LIMIT")
                        target = artifact_directory / name
                        private_dir(target.parent)
                        item = self.call(record, self.colab_args(record, "fetch", "--job-id", job_id, "--artifact", name,
                                                                "--destination", str(target)), timeout=150)
                        if item.get("verified") is not True or item.get("path") != str(target):
                            raise RouterError("ARTIFACT_INTEGRITY_UNVERIFIED")
                        payload = target.read_bytes()
                        if (len(payload) != item.get("size") or digest(payload) != item.get("sha256")
                                or len(payload) != entry["size"] or digest(payload) != entry.get("sha256")):
                            raise RouterError("ARTIFACT_INTEGRITY_MISMATCH")
                        actual_total = sum(x["bytes"] for x in files) + len(payload)
                        if actual_total > max_bytes:
                            raise RouterError("ARTIFACT_COLLECTION_LIMIT")
                        files.append({"name": name, "path": str(target), "bytes": len(payload), "sha256": digest(payload)})
                record["outputs"] = {"directory": str(directory), "files": files, "logs": logs,
                                     "missing_expected_artifacts": missing}
                self.store.save(record, {"event": "artifacts_verified_and_retained"})
                if record["provider"] == "colab":
                    if record["effects"].get("release", {}).get("status") in ("started", "unknown"):
                        released = self.call(record, ["manage", "reconcile", "--key", record["provision_key"]])
                    else:
                        released = self.effect(record, "release", ["manage", "release", "--key", record["provision_key"]], timeout=150)
                    record["receipts"]["release"] = safe_receipt(released)
                    if released.get("phase") != "released":
                        record["state"] = "RELEASE_PENDING"
                        self.store.save(record, {"event": "resource_release_unconfirmed"})
                        return record
                    record["effects"]["release"]["status"] = "confirmed"
                return self.finish_collection(record, directory)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state-dir", type=Path, help="Private controller state (default ~/.local/state/hepta-compute)")
    p.add_argument("--version", action="version", version=VERSION)
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("evaluate", "plan"):
        command = commands.add_parser(name)
        command.add_argument("--provider", choices=PROVIDERS)
        command.add_argument("--account")
        command.add_argument("--accelerator", choices=("T4", "cpu"), default="T4")
        command.add_argument("--timeout", type=int, default=120, help="Required bounded compute duration, in seconds")
        command.add_argument("--json", action="store_true", help="JSON is always emitted; retained for explicit machine use")
        if name == "plan":
            command.add_argument("--request-id", required=True)
            command.add_argument("--source", type=Path, required=True)
            command.add_argument("--artifact", action="append", default=[])
    for name in ("execute", "inspect", "collect"):
        command = commands.add_parser(name)
        command.add_argument("--request-id", required=True)
        if name == "collect":
            command.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        router = Router(state=args.state_dir)
        if args.command == "evaluate":
            out = router.evaluate(provider=args.provider, account=args.account, accelerator=args.accelerator, wall_seconds=args.timeout)
        elif args.command == "plan":
            out = router.plan(args.request_id, args.source, provider=args.provider, account=args.account,
                              accelerator=args.accelerator, wall_seconds=args.timeout, artifacts=args.artifact)
        elif args.command == "execute":
            out = router.execute(args.request_id)
        elif args.command == "inspect":
            out = router.inspect(args.request_id)
        else:
            out = router.collect(args.request_id, max_bytes=args.max_bytes)
        print(json.dumps({"ok": True, "result": out}, ensure_ascii=False))
        return 0
    except RouterError as exc:
        print(json.dumps({"ok": False, "error": {"code": exc.code, "details": exc.details}}, ensure_ascii=False))
        return 2
    except (OSError, ValueError, sqlite3.Error):
        print(json.dumps({"ok": False, "error": {"code": "LOCAL_STATE_OR_CONFIGURATION_FAILURE"}}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
