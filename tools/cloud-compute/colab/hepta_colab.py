#!/usr/bin/env python3
"""Fail-closed Colab script adapter for Hepta process tools.

Stdlib ledger/CLI with a lazy, optional official google-colab-cli SDK provider.
No CLI callback, browser-cookie access, implicit OAuth, or runtime allocation.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import sqlite3
import stat
import sys
import tempfile
import time
from typing import Callable, Protocol
import uuid

TERMINAL = frozenset({"succeeded", "failed", "cancelled", "timed_out"})
ACTIVE = frozenset({"queued", "dispatched", "running", "cancel_requested", "unknown"})
HEX = re.compile(r"^[0-9a-f]{64}$")
RUNNER = Path(__file__).with_name("remote_runner.py")
OFFICIAL_SOURCE_COMMIT = "d2d97794941723ab806c0f3642416691a951ec7d"


class AdapterError(Exception):
    pass


class Conflict(AdapterError):
    pass


class IntegrityError(AdapterError):
    pass


class AuthRequired(AdapterError):
    pass


class SessionBusy(Conflict):
    pass


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def artifact_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name.encode()) > 512:
        raise IntegrityError("invalid_artifact_name")
    parts = name.split("/")
    if (name.startswith("/") or "\\" in name or "\x00" in name
            or any(p in ("", ".", "..") for p in parts)):
        raise IntegrityError("invalid_artifact_name")
    return name


@dataclass(frozen=True)
class Profile:
    name: str
    session_name: str
    state_file: str
    endpoint: str
    kernel_id: str
    session_id: str
    remote_root: str = "/content/hepta_jobs"
    max_wall_seconds: int = 600
    max_artifact_bytes: int = 33554432
    max_output_bytes: int = 8388608
    auth_provider: str = "oauth2"
    expected_account_email: str | None = None

    def __post_init__(self):
        if any(not isinstance(getattr(self, k), str) or not getattr(self, k)
               for k in ("name", "session_name", "state_file", "endpoint",
                         "kernel_id", "session_id")):
            raise IntegrityError("incomplete_fixed_profile")
        if not os.path.isabs(self.state_file):
            raise IntegrityError("state_file_must_be_absolute")
        if (not self.remote_root.startswith("/content/")
                or any(p in ("", ".", "..") for p in self.remote_root[1:].split("/"))):
            raise IntegrityError("invalid_remote_root")
        if not 1 <= self.max_wall_seconds <= 3600:
            raise IntegrityError("wall_limit_out_of_range")
        if not 1 <= self.max_output_bytes <= self.max_artifact_bytes <= 134217728:
            raise IntegrityError("byte_limits_out_of_range")
        if self.auth_provider not in ("oauth2", "adc"):
            raise IntegrityError("unsupported_auth_provider")

    @property
    def fingerprint(self):
        return sha256(canonical(asdict(self)))

    @classmethod
    def load(cls, path):
        return cls(**json.loads(Path(path).read_text()))


class Provider(Protocol):
    def execute(self, job: dict, code_wrapper: str,
                output_hook: Callable[[dict], None]) -> list[dict]: ...
    def read_bytes(self, remote_path: str) -> bytes: ...
    def write_bytes(self, remote_path: str, data: bytes) -> None: ...
    def close(self) -> None: ...


class Ledger:
    def __init__(self, state_dir: Path | str):
        self.root = Path(state_dir).absolute()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.root.is_symlink():
            raise IntegrityError("state_directory_is_symlink")
        os.chmod(self.root, 0o700)
        self.path = self.root / "jobs.sqlite3"
        if self.path.is_symlink():
            raise IntegrityError("ledger_is_symlink")
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                  job_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                  profile_hash TEXT NOT NULL, profile_json TEXT NOT NULL,
                  payload_sha256 TEXT NOT NULL, code_sha256 TEXT NOT NULL,
                  runner_sha256 TEXT NOT NULL, code TEXT NOT NULL,
                  artifacts_json TEXT NOT NULL, wall_seconds INTEGER NOT NULL,
                  endpoint TEXT NOT NULL, kernel_id TEXT NOT NULL, session_id TEXT NOT NULL,
                  remote_dir TEXT NOT NULL, state TEXT NOT NULL,
                  submit_attempts INTEGER NOT NULL DEFAULT 0 CHECK(submit_attempts <= 1),
                  worker_pid INTEGER, worker_start_ticks TEXT,
                  created_at REAL NOT NULL, updated_at REAL NOT NULL,
                  dispatched_at REAL, cancel_requested_at REAL,
                  receipt_json TEXT, manifest_json TEXT, error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS jobs_session ON jobs(endpoint,kernel_id,state);
                CREATE TABLE IF NOT EXISTS events (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL,
                  event TEXT NOT NULL, at REAL NOT NULL, details_json TEXT NOT NULL
                );
            """)
        os.chmod(self.path, 0o600)

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=30000")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def event(db, job_id, event, details=None):
        db.execute("INSERT INTO events(job_id,event,at,details_json) VALUES(?,?,?,?)",
                   (job_id, event, time.time(), canonical(details or {}).decode()))

    @staticmethod
    def decoded(row):
        if row is None:
            raise AdapterError("job_not_found")
        job = dict(row)
        job["artifacts"] = json.loads(job.pop("artifacts_json"))
        job["profile"] = json.loads(job.pop("profile_json"))
        job["receipt"] = json.loads(job.pop("receipt_json")) if job["receipt_json"] else None
        job["manifest"] = json.loads(job.pop("manifest_json")) if job["manifest_json"] else None
        return job

    def get(self, job_id):
        with self.connection() as db:
            return self.decoded(db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone())

    def submit(self, profile, idempotency_key, code, artifacts=(), wall_seconds=300):
        if not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key.encode()) <= 128:
            raise IntegrityError("invalid_idempotency_key")
        if not isinstance(code, str) or not code or len(code.encode()) > 262144:
            raise IntegrityError("code_size_invalid")
        if not isinstance(wall_seconds, int) or isinstance(wall_seconds, bool) or not 1 <= wall_seconds <= profile.max_wall_seconds:
            raise IntegrityError("wall_limit_invalid")
        names = sorted(artifact_name(name) for name in artifacts)
        if len(names) != len(set(names)) or len(names) > 32 or set(names) & {"stdout", "stderr"}:
            raise IntegrityError("artifact_contract_invalid")
        runner_sha = sha256(RUNNER.read_bytes())
        request_hash = sha256(canonical({"profile_hash": profile.fingerprint,
            "code": code, "artifacts": names, "wall_seconds": wall_seconds,
            "runner_sha256": runner_sha, "adapter_schema": 1}))
        now = time.time()
        job_id = str(uuid.uuid4())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if previous:
                if previous["payload_sha256"] != request_hash:
                    db.rollback()
                    raise Conflict("idempotency_payload_mismatch")
                db.commit()
                return self.decoded(previous)
            marks = ",".join("?" for _ in ACTIVE)
            busy = db.execute(f"SELECT job_id FROM jobs WHERE endpoint=? AND kernel_id=? AND state IN ({marks})",
                              (profile.endpoint, profile.kernel_id, *ACTIVE)).fetchone()
            if busy:
                db.rollback()
                raise SessionBusy("fixed_session_has_unresolved_job")
            db.execute("""INSERT INTO jobs(job_id,idempotency_key,profile_hash,profile_json,
                payload_sha256,code_sha256,runner_sha256,code,artifacts_json,wall_seconds,
                endpoint,kernel_id,session_id,remote_dir,state,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (job_id, idempotency_key, profile.fingerprint, canonical(asdict(profile)).decode(),
                 request_hash, sha256(code.encode()), runner_sha, code, canonical(names).decode(),
                 wall_seconds, profile.endpoint, profile.kernel_id, profile.session_id,
                 f"{profile.remote_root}/{job_id}", "queued", now, now))
            self.event(db, job_id, "queued")
            db.commit()
        return self.get(job_id)

    def claim(self, job_id):
        ticks = None
        try:
            ticks = Path(f"/proc/{os.getpid()}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except OSError:
            pass
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            result = db.execute("""UPDATE jobs SET state='dispatched',submit_attempts=1,
                worker_pid=?,worker_start_ticks=?,dispatched_at=?,updated_at=?
                WHERE job_id=? AND state='queued' AND submit_attempts=0""",
                (os.getpid(), ticks, time.time(), time.time(), job_id))
            won = result.rowcount == 1
            if won:
                self.event(db, job_id, "dispatch_claimed")
            db.commit()
            return won

    def problem(self, job_id, error_code):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,submit_attempts FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if row and row["state"] not in TERMINAL:
                next_state = "unknown" if row["submit_attempts"] else row["state"]
                db.execute("UPDATE jobs SET state=?,error_code=?,updated_at=? WHERE job_id=?",
                           (next_state, error_code, time.time(), job_id))
                self.event(db, job_id, "observation_problem", {"error_code": error_code})
            db.commit()

    def reconcile(self, job_id, receipt, manifest=None):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,receipt_json,cancel_requested_at FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row:
                db.rollback()
                raise AdapterError("job_not_found")
            # Never replace retained terminal evidence with a stale running read.
            if row["state"] in TERMINAL:
                if receipt["state"] in TERMINAL and row["receipt_json"]:
                    old = json.loads(row["receipt_json"])
                    if old != receipt:
                        db.rollback()
                        raise IntegrityError("terminal_receipt_changed")
                db.commit()
                return
            state = receipt["state"]
            if state == "starting":
                state = "dispatched"
            if state in ("running", "dispatched") and row["cancel_requested_at"]:
                state = "cancel_requested"
            db.execute("""UPDATE jobs SET state=?,receipt_json=?,
                manifest_json=COALESCE(?,manifest_json),error_code=NULL,updated_at=? WHERE job_id=?""",
                (state, canonical(receipt).decode(), canonical(manifest).decode() if manifest else None,
                 time.time(), job_id))
            self.event(db, job_id, "cloud_observed", {"state": state})
            db.commit()

    def request_cancel(self, job_id):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if not row:
                raise AdapterError("job_not_found")
            if row["state"] in TERMINAL:
                db.commit()
                return "terminal"
            if row["state"] == "queued":
                db.execute("UPDATE jobs SET state='cancelled',cancel_requested_at=?,updated_at=? WHERE job_id=?",
                           (time.time(), time.time(), job_id))
                self.event(db, job_id, "cancelled_before_dispatch")
                db.commit()
                return "local"
            db.execute("""UPDATE jobs SET state='cancel_requested',
                cancel_requested_at=COALESCE(cancel_requested_at,?),updated_at=? WHERE job_id=?""",
                       (time.time(), time.time(), job_id))
            self.event(db, job_id, "cancel_requested")
            db.commit()
            return "remote"


def identity(job):
    return {k: job[k] for k in ("job_id", "payload_sha256", "endpoint", "kernel_id", "session_id")}


def check_identity(job, document):
    if not isinstance(document, dict) or any(document.get(k) != v for k, v in identity(job).items()):
        raise IntegrityError("cloud_identity_mismatch")


def public_job(job):
    receipt = job.get("receipt")
    return {k: job[k] for k in ("job_id", "state", "payload_sha256", "code_sha256",
            "endpoint", "kernel_id", "session_id", "remote_dir", "submit_attempts",
            "worker_pid", "worker_start_ticks", "created_at", "updated_at",
            "dispatched_at", "cancel_requested_at", "error_code")} | {
                "cloud_receipt": receipt,
                "cloud_execution_stopped": bool(receipt and receipt.get("cloud_execution_stopped")),
                "artifacts": job["manifest"].get("entries", {}) if job.get("manifest") else {},
                "local_only_cancel": job["state"] == "cancelled" and job["submit_attempts"] == 0,
            }



@contextmanager
def read_only_ledger(state_dir):
    """Open the original private SQLite ledger without creating missing state."""
    from authorize_colab import _open_status_parent
    root = Path(state_dir)
    if not root.is_absolute():
        raise IntegrityError("state_directory_must_be_absolute")
    path = root / "jobs.sqlite3"
    if not root.exists():
        parent, _ = _open_status_parent(str(root))
        os.close(parent)
        yield None
        return
    parent, name = _open_status_parent(str(path))
    source = None
    db = None
    try:
        try:
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            yield None
            return
        info = os.fstat(source)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise IntegrityError("ledger_not_private")
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                aux = os.stat(name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if (not stat.S_ISREG(aux.st_mode) or aux.st_uid != os.geteuid()
                    or aux.st_nlink != 1 or aux.st_mode & 0o077):
                raise IntegrityError("ledger_auxiliary_not_private")
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        # Missing or malformed tables are an error, never evidence of no job.
        db.execute("""SELECT job_id,idempotency_key,profile_hash,submit_attempts,state,
            endpoint,dispatched_at,worker_pid,worker_start_ticks,receipt_json,manifest_json
            FROM jobs LIMIT 0""")
        db.execute("SELECT job_id,event FROM events LIMIT 0")
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise IntegrityError("ledger_identity_changed")
        yield db
    finally:
        if db is not None:
            db.close()
        if source is not None:
            os.close(source)
        os.close(parent)


def inspect_submission_key(profile, state_dir, key):
    """Read one submit key under its original profile; never dispatch or mutate."""
    if not isinstance(key, str) or not 1 <= len(key.encode()) <= 128:
        raise IntegrityError("invalid_idempotency_key")
    result = {"idempotency_key": key, "profile_hash": profile.fingerprint,
              "endpoint": profile.endpoint, "kernel_id": profile.kernel_id,
              "session_id": profile.session_id}
    with read_only_ledger(state_dir) as db:
        if db is None:
            return result | {"found": False, "ledger_present": False,
                             "absence_verified": False, "job": None}
        row = db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (key,)).fetchone()
        if row is None:
            return result | {"found": False, "ledger_present": True,
                             "absence_verified": True, "job": None}
        if row["profile_hash"] != profile.fingerprint:
            raise Conflict("profile_identity_changed")
        job = Ledger.decoded(row)
        current_runner_sha256 = sha256(RUNNER.read_bytes())
        if job["runner_sha256"] != current_runner_sha256:
            raise Conflict("runner_changed_after_submission")
        return result | {"found": True, "ledger_present": True,
                         "absence_verified": False, "job": public_job(job),
                         "request": {"code_sha256": job["code_sha256"],
                                     "runner_sha256": job["runner_sha256"],
                                     "runner_matches_current": True,
                                     "wall_seconds": job["wall_seconds"],
                                     "artifacts": job["artifacts"]}}


class Engine:
    def __init__(self, profile, ledger, provider_factory=None):
        self.profile = profile
        self.ledger = ledger
        self.provider_factory = provider_factory or OfficialSDKProvider

    def _job(self, job_id):
        job = self.ledger.get(job_id)
        if job["profile_hash"] != self.profile.fingerprint:
            raise Conflict("profile_identity_changed")
        return job

    def submit(self, key, code, artifacts=(), wall_seconds=300):
        return public_job(self.ledger.submit(self.profile, key, code, artifacts, wall_seconds))

    def run(self, job_id):
        job = self._job(job_id)
        if job["state"] != "queued":
            return self.status(job_id)
        source = RUNNER.read_text()
        if sha256(source.encode()) != job["runner_sha256"]:
            raise Conflict("runner_changed_after_submission")
        provider = self.provider_factory(self.profile)
        try:
            if not self.ledger.claim(job_id):
                return public_job(self._job(job_id))
            job = self._job(job_id)
            payload = identity(job) | {"code": job["code"], "code_sha256": job["code_sha256"],
                "remote_dir": job["remote_dir"], "wall_seconds": job["wall_seconds"],
                "artifacts": job["artifacts"], "max_artifact_bytes": self.profile.max_artifact_bytes,
                "max_output_bytes": self.profile.max_output_bytes}
            wrapper = "_HEPTA_PAYLOAD = " + repr(payload) + "\n" + source
            event_path = self.ledger.root / f"{job_id}.iopub.jsonl"
            def record(output):
                fd = os.open(event_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "ab") as stream:
                    stream.write(canonical(output) + b"\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                # A cancellation may have arrived while the remote claim
                # directory did not yet exist. Initial cloud output is emitted
                # after that directory/status exist, so deliver the same intent.
                current = self._job(job_id)
                if current["cancel_requested_at"] and current["state"] not in TERMINAL:
                    try:
                        self._deliver_cancel(current, provider)
                    except Exception:
                        pass  # Remains requested/unknown; never claim stopped.
            try:
                provider.execute(job, wrapper, record)
            except BaseException as exc:
                self.ledger.problem(job_id, type(exc).__name__)
            return self._refresh(job_id, provider)
        finally:
            provider.close()

    def _refresh(self, job_id, provider):
        job = self._job(job_id)
        if job["submit_attempts"] == 0:
            return public_job(job)
        observed = False
        refresh_error = None
        try:
            raw = provider.read_bytes(job["remote_dir"] + "/status.json")
            if len(raw) > 65536:
                raise IntegrityError("receipt_too_large")
            receipt = json.loads(raw)
            check_identity(job, receipt)
            if receipt.get("state") not in TERMINAL | {"starting", "running", "unknown"}:
                raise IntegrityError("invalid_cloud_state")
            if receipt["state"] in TERMINAL:
                if receipt.get("cloud_execution_stopped") is not True or receipt.get("cloud_process_group_alive") is not False:
                    raise IntegrityError("terminal_state_without_cloud_stop_proof")
                if receipt["state"] == "succeeded" and (type(receipt.get("exit_code")) is not int or receipt["exit_code"] != 0):
                    raise IntegrityError("success_without_zero_exit_code")
            if receipt["state"] in {"starting", "running"} and job["cancel_requested_at"]:
                self._deliver_cancel(job, provider)
            manifest = None
            if receipt["state"] in TERMINAL:
                manifest_raw = provider.read_bytes(job["remote_dir"] + "/artifacts.json")
                if len(manifest_raw) > 65536 or len(manifest_raw) != receipt.get("artifact_manifest_size") or sha256(manifest_raw) != receipt.get("artifact_manifest_sha256"):
                    raise IntegrityError("manifest_hash_mismatch")
                manifest = json.loads(manifest_raw)
                check_identity(job, manifest)
                entries = manifest.get("entries")
                if not isinstance(entries, dict) or not {"stdout", "stderr"} <= set(entries):
                    raise IntegrityError("invalid_manifest")
                if receipt["state"] == "succeeded" and (not set(job["artifacts"]) <= set(entries) or manifest.get("errors")):
                    raise IntegrityError("successful_manifest_incomplete")
                for name, entry in entries.items():
                    self._validate_entry(job, name, entry)
            self.ledger.reconcile(job_id, receipt, manifest)
            observed = True
            # Retain exact outputs and requested artifacts as soon as terminal
            # evidence is seen. Network failures here do not undo completion.
            finished = self._job(job_id)
            if finished["state"] in TERMINAL and finished.get("manifest"):
                for name in finished["manifest"]["entries"]:
                    try:
                        self._verified_bytes(finished, name, provider)
                    except Exception as exc:
                        with self.ledger.connection() as db:
                            self.ledger.event(db, job_id, "artifact_cache_failed",
                                              {"artifact": name, "error_code": type(exc).__name__})
        except (Exception, KeyboardInterrupt) as exc:
            refresh_error = type(exc).__name__
            self.ledger.problem(job_id, refresh_error)
        result = public_job(self._job(job_id))
        result["cloud_observation"] = "fresh" if observed else "retained" if result["cloud_receipt"] else "unavailable"
        result["refresh_error"] = refresh_error
        return result

    def status(self, job_id, refresh=True):
        job = self._job(job_id)
        if not refresh or not job["submit_attempts"]:
            return public_job(job)
        try:
            provider = self.provider_factory(self.profile)
        except Exception as exc:
            self.ledger.problem(job_id, type(exc).__name__)
            result = public_job(self._job(job_id))
            result["cloud_observation"] = "retained" if result["cloud_receipt"] else "unavailable"
            result["refresh_error"] = type(exc).__name__
            return result
        try:
            return self._refresh(job_id, provider)
        finally:
            provider.close()

    def cancel(self, job_id):
        self._job(job_id)
        # Persist intent before any credential/network operation. The atomic
        # result also covers a concurrent run() claiming a formerly queued job.
        if self.ledger.request_cancel(job_id) != "remote":
            return public_job(self._job(job_id))
        try:
            provider = self.provider_factory(self.profile)
        except Exception as exc:
            self.ledger.problem(job_id, type(exc).__name__)
            result = public_job(self._job(job_id))
            result["cloud_observation"] = "unavailable"
            result["refresh_error"] = type(exc).__name__
            return result
        try:
            self._refresh(job_id, provider)
            job = self._job(job_id)
            if job["state"] in TERMINAL:
                return public_job(job)
            try:
                self._deliver_cancel(job, provider)
            except Exception as exc:
                self.ledger.problem(job_id, type(exc).__name__)
            return self._refresh(job_id, provider)
        finally:
            provider.close()

    def _deliver_cancel(self, job, provider):
        path = job["remote_dir"] + "/cancel.request.json"
        requested = canonical(identity(job) | {"cancel": True})
        try:
            existing = provider.read_bytes(path)
            if existing != requested:
                raise IntegrityError("cancel_marker_identity_mismatch")
            return
        except FileNotFoundError:
            # Repeating this exact immutable control-file PUT after a missing
            # observation is idempotent. It never dispatches a new computation.
            provider.write_bytes(path, requested)

    def _validate_entry(self, job, name, entry):
        if not isinstance(entry, dict) or name not in {"stdout", "stderr", *job["artifacts"]}:
            raise IntegrityError("artifact_not_requested")
        artifact_name(name)
        suffix = {"stdout": "/stdout.bin", "stderr": "/stderr.bin"}.get(name, "/work/" + name)
        if entry.get("remote_path") != job["remote_dir"] + suffix:
            raise IntegrityError("artifact_path_mismatch")
        if not isinstance(entry.get("size"), int) or isinstance(entry.get("size"), bool) or not 0 <= entry["size"] <= self.profile.max_artifact_bytes:
            raise IntegrityError("artifact_size_invalid")
        if not isinstance(entry.get("sha256"), str) or not HEX.fullmatch(entry["sha256"]):
            raise IntegrityError("artifact_hash_invalid")

    def _cache_path(self, job, entry):
        folder = self.ledger.root / "artifacts" / job["job_id"]
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        if folder.is_symlink() or folder.parent.is_symlink():
            raise IntegrityError("artifact_cache_is_symlink")
        return folder / entry["sha256"]

    def _verified_bytes(self, job, name, provider):
        manifest = job.get("manifest")
        if not manifest or name not in manifest["entries"]:
            raise IntegrityError("artifact_not_in_verified_manifest")
        entry = manifest["entries"][name]
        self._validate_entry(job, name, entry)
        cache = self._cache_path(job, entry)
        try:
            fd = os.open(cache, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(entry["size"] + 1)
            if len(data) != entry["size"] or sha256(data) != entry["sha256"]:
                raise IntegrityError("local_artifact_cache_corrupt")
            return data, entry
        except FileNotFoundError:
            if provider is None:
                raise
        data = provider.read_bytes(entry["remote_path"])
        if len(data) != entry["size"] or sha256(data) != entry["sha256"]:
            raise IntegrityError("artifact_content_mismatch")
        publish_no_clobber(cache, data)
        return data, entry

    def fetch(self, job_id, artifact, local_path):
        artifact_name(artifact)
        job = self._job(job_id)
        if job["state"] in TERMINAL and job.get("manifest"):
            try:
                data, entry = self._verified_bytes(job, artifact, None)
                saved = publish_no_clobber(Path(local_path), data)
                return {"job_id": job_id, "artifact": artifact, "path": str(saved),
                        "sha256": entry["sha256"], "size": entry["size"], "verified": True,
                        "source": "retained_verified_artifact"}
            except FileNotFoundError:
                pass
        provider = self.provider_factory(self.profile)
        try:
            self._refresh(job_id, provider)
            job = self._job(job_id)
            if job["state"] not in TERMINAL:
                raise Conflict("artifact_requires_terminal_receipt")
            data, entry = self._verified_bytes(job, artifact, provider)
            saved = publish_no_clobber(Path(local_path), data)
            return {"job_id": job_id, "artifact": artifact, "path": str(saved),
                    "sha256": entry["sha256"], "size": entry["size"], "verified": True}
        finally:
            provider.close()

    def read(self, job_id, stream="stdout", offset=0, limit=16384):
        if stream not in ("stdout", "stderr") or offset < 0 or not 1 <= limit <= 65536:
            raise IntegrityError("invalid_read_range")
        job = self._job(job_id)
        cached = None
        if job["state"] in TERMINAL and job.get("manifest"):
            try:
                cached, _ = self._verified_bytes(job, stream, None)
            except FileNotFoundError:
                pass
        provider = None if cached is not None else self.provider_factory(self.profile)
        try:
            if provider is not None:
                self._refresh(job_id, provider)
            job = self._job(job_id)
            verified = job["state"] in TERMINAL
            if cached is not None:
                data = cached
            elif verified:
                data, _ = self._verified_bytes(job, stream, provider)
            else:
                data = provider.read_bytes(job["remote_dir"] + f"/{stream}.bin")
            chunk = data[offset:offset + limit]
            return {"job_id": job_id, "stream": stream, "offset": offset,
                "next_offset": offset + len(chunk), "observed_size": len(data),
                "eof": verified and offset + len(chunk) >= len(data),
                "verified": verified, "data_base64": base64.b64encode(chunk).decode(),
                "sha256": sha256(chunk), "text": chunk.decode("utf-8", errors="replace")}
        finally:
            if provider is not None:
                provider.close()


def publish_no_clobber(path: Path, data: bytes) -> Path:
    if not path.is_absolute():
        raise IntegrityError("destination_must_be_absolute")
    if any(p in (".", "..") for p in str(path).split("/")):
        raise IntegrityError("invalid_destination")
    parts = path.parts
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        name = parts[-1]
        temp_name = f".hepta-{uuid.uuid4().hex}.tmp"
        out_fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(out_fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temp_name, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            except FileExistsError:
                existing_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                with os.fdopen(existing_fd, "rb") as existing:
                    if not stat.S_ISREG(os.fstat(existing.fileno()).st_mode):
                        raise IntegrityError("destination_not_regular")
                    if existing.read(len(data) + 1) != data:
                        raise Conflict("destination_exists_with_different_content")
            os.fsync(fd)
        finally:
            os.unlink(temp_name, dir_fd=fd)
    finally:
        os.close(fd)
    return path


def cached_credentials(auth_provider="oauth2"):
    # The dedicated adapter process must never show SDK warnings, OAuth URLs,
    # credentials, or transport exception details at this boundary.
    import contextlib
    import io
    logging.disable(logging.CRITICAL)
    captured_out, captured_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_err):
        from colab_cli import auth
        from google.auth.transport.requests import Request
        class BoundedRefreshRequest(Request):
            def __call__(self, *args, **kwargs):
                kwargs["timeout"] = 30
                return super().__call__(*args, **kwargs)
        if auth_provider == "adc":
            import google.auth
            creds, _ = google.auth.default(scopes=auth.PUBLIC_SCOPES)
        else:
            from google.oauth2.credentials import Credentials
            from authorize_colab import preflight_keyring, AuthFailure
            try:
                preflight_keyring(auth)
            except AuthFailure as exc:
                raise AuthRequired(exc.code) from None
            token_json = auth._get_token_from_keyring()
            if not token_json:
                raise AuthRequired("AUTH_USER_INTERACTION_REQUIRED")
            creds = Credentials.from_authorized_user_info(json.loads(token_json), auth.PUBLIC_SCOPES)
        if not creds.valid:
            if not getattr(creds, "refresh_token", None) and auth_provider == "oauth2":
                raise AuthRequired("AUTH_REFRESH_TOKEN_REQUIRED")
            creds.refresh(BoundedRefreshRequest())
            if auth_provider == "oauth2":
                try:
                    preflight_keyring(auth)
                except AuthFailure as exc:
                    raise AuthRequired(exc.code) from None
                auth._save_token_to_keyring(creds.to_json())
        if not creds.valid:
            raise AuthRequired("AUTH_VALID_CACHED_CREDENTIALS_REQUIRED")
        return creds


def validate_runtime_url(url, endpoint=None):
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        # Only the actual assigned runtime's 8080 proxy may use the new
        # *.prod.r.colab.dev origin; a bare suffix check is insufficient.
        current_colab_proxy = bool(
            endpoint and host and host.startswith("8080-" + endpoint + "-")
            and host.endswith(".prod.r.colab.dev")
            and parsed.path in ("", "/")
        )
        valid = (parsed.scheme == "https" and host and
                 (host == "colab.research.google.com"
                  or host.endswith(".googleusercontent.com")
                  or current_colab_proxy)
                 and parsed.port in (None, 443) and parsed.username is None
                 and parsed.password is None and not parsed.query and not parsed.fragment)
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise IntegrityError("runtime_proxy_origin_unverified")
    return url


def cached_account(creds):
    # The same Google tokeninfo endpoint used by upstream `colab whoami`.
    # Never follow a redirect carrying the credential to another origin, and
    # never expose transport exception text containing the authenticated URL.
    import requests
    try:
        with requests.get("https://oauth2.googleapis.com/tokeninfo",
                          params={"access_token": creds.token}, timeout=10,
                          allow_redirects=False, stream=True) as response:
            if response.status_code != 200:
                raise IntegrityError("account_identity_non_success_response")
            chunks, size = [], 0
            for chunk in response.iter_content(8192):
                size += len(chunk)
                if size > 65536:
                    raise IntegrityError("account_identity_response_too_large")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
    except IntegrityError:
        raise
    except Exception:
        raise IntegrityError("account_identity_request_failed") from None
    if not isinstance(data, dict):
        raise IntegrityError("account_identity_unavailable")
    email = data.get("email")
    if not isinstance(email, str) or not email:
        raise IntegrityError("account_identity_unavailable")
    return {"email": email, "scopes": str(data.get("scope", "")).split()}


def bind_profile(profile_path, session_name, state_file, name="rog-colab",
                 auth_provider="oauth2", expected_email=None):
    logging.disable(logging.CRITICAL)
    if not expected_email:
        raise IntegrityError("verified_account_email_required")
    from colab_cli.state import StateStore
    session = StateStore(state_file).get(session_name)
    if session is None or not session.kernel_id or not session.session_id:
        raise IntegrityError("existing_session_requires_kernel_and_client_session_ids")
    validate_runtime_url(session.url, session.endpoint)
    if expected_email:
        account = cached_account(cached_credentials(auth_provider))
        if account["email"].casefold() != expected_email.casefold():
            raise IntegrityError("account_identity_mismatch")
    profile = Profile(name=name, session_name=session_name, state_file=state_file,
                      endpoint=session.endpoint, kernel_id=session.kernel_id,
                      session_id=session.session_id, auth_provider=auth_provider,
                      expected_account_email=expected_email)
    publish_no_clobber(Path(profile_path), canonical(asdict(profile)) + b"\n")
    return {"profile_path": profile_path, "profile_hash": profile.fingerprint,
            "endpoint": profile.endpoint, "kernel_id": profile.kernel_id,
            "session_id": profile.session_id, "session_name": profile.session_name,
            "accelerator": str(session.accelerator), "variant": str(session.variant),
            "machine_shape": str(session.machine_shape)}


class OfficialSDKProvider:
    def __init__(self, profile):
        logging.disable(logging.CRITICAL)
        self.profile = profile
        self.runtime = None
        verified_creds = None
        if not profile.expected_account_email:
            raise IntegrityError("verified_account_email_required")
        if profile.expected_account_email:
            verified_creds = cached_credentials(profile.auth_provider)
            account = cached_account(verified_creds)
            if account["email"].casefold() != profile.expected_account_email.casefold():
                raise IntegrityError("account_identity_mismatch")
        from colab_cli.state import StateStore
        from datetime import datetime, timedelta, timezone
        self.store = StateStore(profile.state_file)
        session = self.store.get(profile.session_name)
        if session is None:
            raise IntegrityError("fixed_session_not_found")
        validate_runtime_url(session.url, session.endpoint)
        for key in ("endpoint", "kernel_id", "session_id"):
            if getattr(session, key) != getattr(profile, key):
                raise IntegrityError("fixed_session_identity_mismatch")
        if not session.token_expires_at or session.token_expires_at - datetime.now(timezone.utc) < timedelta(minutes=5):
            from colab_cli.client import Client, Prod
            from google.auth.transport.requests import AuthorizedSession
            auth_session = AuthorizedSession(verified_creds or cached_credentials(profile.auth_provider))
            try:
                # The official Client defaults timeout from this environment var.
                os.environ.setdefault("COLAB_CLI_REQUEST_TIMEOUT", "30")
                assignments = Client(Prod(), auth_session).list_assignments()
            finally:
                auth_session.close()
            found = next((a for a in assignments if a.endpoint == profile.endpoint), None)
            if found is None:
                raise IntegrityError("fixed_cloud_runtime_no_longer_exists")
            info = found.runtime_proxy_info
            validate_runtime_url(info.url, profile.endpoint)
            session.token, session.url = info.token, info.url
            session.token_expires_at = info.expires_at()
            self.store.add(session)
        self.session = session
        self.contents = self._bounded_contents(session)

    def _bounded_contents(self, session):
        # Exact ContentsClient contract from the pinned upstream source, with
        # bounded network deadlines and streamed response-size enforcement.
        from colab_cli.contents import ContentsClient
        import requests
        from urllib.parse import quote
        max_wire = 2 * self.profile.max_artifact_bytes + 1048576
        class BoundedContents(ContentsClient):
            def _request(self, method, path, params=None, json_data=None):
                quoted = quote(path.strip("/"), safe="/")
                url = f"{self.base_url}/api/contents/{quoted}"
                query = {"authuser": "0", "colab-runtime-proxy-token": self.token}
                query.update(params or {})
                with requests.request(method, url, params=query, json=json_data,
                                      timeout=(10, 30), stream=True, allow_redirects=False) as response:
                    if response.status_code == 404:
                        raise FileNotFoundError("remote_file_missing")
                    if not 200 <= response.status_code < 300:
                        raise IntegrityError("contents_non_success_response")
                    chunks, size = [], 0
                    for chunk in response.iter_content(65536):
                        size += len(chunk)
                        if size > max_wire:
                            raise IntegrityError("remote_response_too_large")
                        chunks.append(chunk)
                    return json.loads(b"".join(chunks)) if method != "DELETE" else None
        return BoundedContents(session)

    def execute(self, job, code_wrapper, output_hook):
        from colab_cli.runtime import ColabRuntime
        self.runtime = ColabRuntime(self.session.url, self.session.token,
            session_name=self.profile.session_name, kernel_id=self.profile.kernel_id,
            session_id=self.profile.session_id)
        # With both IDs supplied, official SDK connects to the existing kernel.
        if self.runtime.kernel_client.id != self.profile.kernel_id:
            raise IntegrityError("kernel_identity_changed")
        return self.runtime.execute_code(code_wrapper, allow_stdin=False,
            output_hook=output_hook, timeout=job["wall_seconds"] + 90)

    def read_bytes(self, remote_path):
        with tempfile.TemporaryDirectory(prefix="hepta-colab-read-") as tmp:
            target = Path(tmp) / "content.bin"
            self.contents.download(remote_path, str(target))
            if target.stat().st_size > self.profile.max_artifact_bytes:
                raise IntegrityError("remote_file_too_large")
            return target.read_bytes()

    def write_bytes(self, remote_path, data):
        if len(data) > 65536:
            raise IntegrityError("control_message_too_large")
        with tempfile.TemporaryDirectory(prefix="hepta-colab-write-") as tmp:
            source = Path(tmp) / "request.json"
            source.write_bytes(data)
            self.contents.upload(str(source), remote_path)

    def close(self):
        if self.runtime:
            self.runtime.stop(shutdown_kernel=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--state-dir", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("--session-name", required=True)
    bind.add_argument("--session-state-file", required=True)
    bind.add_argument("--name", default="rog-colab")
    bind.add_argument("--auth-provider", choices=["oauth2", "adc"], default="oauth2")
    bind.add_argument("--expected-email", required=True)
    submit = commands.add_parser("submit")
    submit.add_argument("--key", required=True)
    submit.add_argument("--code-file", required=True)
    submit.add_argument("--artifact", action="append", default=[])
    submit.add_argument("--wall-seconds", type=int, default=300)
    inspect_key = commands.add_parser("inspect-key")
    inspect_key.add_argument("--key", required=True)
    for name in ("run", "status", "cancel", "read", "fetch"):
        p = commands.add_parser(name)
        p.add_argument("--job-id", required=True)
        if name == "status":
            p.add_argument("--local", action="store_true")
        if name == "read":
            p.add_argument("--stream", choices=["stdout", "stderr"], default="stdout")
            p.add_argument("--offset", type=int, default=0)
            p.add_argument("--limit", type=int, default=16384)
        if name == "fetch":
            p.add_argument("--artifact", required=True)
            p.add_argument("--destination", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "bind":
            result = bind_profile(args.profile, args.session_name, args.session_state_file,
                                  args.name, args.auth_provider, args.expected_email)
            print(canonical(result).decode())
            return 0
        profile = Profile.load(args.profile)
        if args.command == "inspect-key":
            result = inspect_submission_key(profile, args.state_dir, args.key)
            print(canonical(result).decode())
            return 0
        engine = Engine(profile, Ledger(args.state_dir))
        if args.command == "submit":
            result = engine.submit(args.key, Path(args.code_file).read_text(),
                                   args.artifact, args.wall_seconds)
        elif args.command == "run":
            result = engine.run(args.job_id)
        elif args.command == "status":
            result = engine.status(args.job_id, refresh=not args.local)
        elif args.command == "cancel":
            result = engine.cancel(args.job_id)
        elif args.command == "read":
            result = engine.read(args.job_id, args.stream, args.offset, args.limit)
        else:
            result = engine.fetch(args.job_id, args.artifact, args.destination)
        print(canonical(result).decode())
        return 0
    except BaseException as exc:
        # Exception objects in requests and upstream SDKs may contain bearer
        # URLs. Never format them, their repr, or tracebacks at this boundary.
        safe_message = str(exc) if isinstance(exc, AdapterError) else None
        print(canonical({"error": type(exc).__name__, "code": safe_message}).decode())
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
