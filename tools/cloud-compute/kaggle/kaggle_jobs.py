"""Durable, account-bound Kaggle jobs. All remote writes are single-attempt."""
from __future__ import annotations

import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import tempfile
import time
from typing import Any

from kaggle_transport import AdapterError, RemoteError, atomic_json, scrub, private_read

SCHEMA = "hepta-kaggle-job-v1"
TERMINAL = {"COMPLETE", "ERROR", "CANCEL_ACKNOWLEDGED"}
MAX_SOURCE = 2 * 1024 * 1024


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def checked_request_id(value: str):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value):
        raise AdapterError("INVALID_REQUEST_ID", "Request ID must be 1..80 simple ASCII characters.")
    return value


def positive_int(value):
    if isinstance(value, bool): return None
    if isinstance(value, str) and value.isdigit(): value = int(value)
    return value if isinstance(value, int) and value > 0 else None


def attr(obj: dict, camel: str, snake: str | None = None, default=None):
    return obj.get(camel, obj.get(snake, default) if snake else default)


def bound_response_ref(value, expected):
    """Accept only an exact canonical ref or Kaggle's exact /code/ prefix.

    No URL parsing, percent-decoding, query stripping or path normalization is
    appropriate for an identity assertion. The original raw receipt is retained.
    """
    if not isinstance(expected, str) or not re.fullmatch(r"[A-Za-z0-9_-]+/[a-z0-9-]+", expected):
        raise AdapterError("REMOTE_IDENTITY_MISSING", "Expected notebook reference is not safely bound.")
    return expected if value == expected or value == "/code/" + expected else None


def status_name(response: dict):
    value = response.get("status")
    if value is None:
        # The protobuf's explicitly documented zero/default state is QUEUED.
        return "QUEUED" if response == {} else "UNKNOWN"
    if isinstance(value, int):
        return {0: "QUEUED", 1: "RUNNING", 2: "COMPLETE", 3: "ERROR", 4: "CANCEL_REQUESTED", 5: "CANCEL_ACKNOWLEDGED", 6: "NEW_SCRIPT"}.get(value, "UNKNOWN")
    value = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", str(value)).upper()
    return value if value in TERMINAL | {"QUEUED", "RUNNING", "CANCEL_REQUESTED", "NEW_SCRIPT"} else "UNKNOWN"


def safe_name(value: str):
    if not isinstance(value, str) or not value or len(value) > 1024 or "\\" in value or "\x00" in value:
        raise AdapterError("UNSAFE_ARTIFACT_PATH", "Provider output filename is not a safe relative path.")
    parts = value.split("/")
    if any(x in ("", ".", "..") for x in parts) or PurePosixPath(value).is_absolute() or any(":" in x for x in parts):
        raise AdapterError("UNSAFE_ARTIFACT_PATH", "Provider output filename attempts path traversal or aliasing.")
    return value


def hash_file(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    size, h = 0, hashlib.sha256()
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AdapterError("UNSAFE_ARTIFACT_PATH", "Artifact is not a regular file.")
        with os.fdopen(fd, "rb", closefd=False) as f:
            while chunk := f.read(1024 * 1024): size += len(chunk); h.update(chunk)
    finally: os.close(fd)
    return {"bytes": size, "sha256": h.hexdigest()}


def read_source(path: Path, kernel_type: str):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > MAX_SOURCE:
            raise AdapterError("SOURCE_LIMIT", "Source must be a regular file of at most 2 MiB.")
        with os.fdopen(fd, "rb", closefd=False) as f: data = f.read(MAX_SOURCE + 1)
    finally: os.close(fd)
    if len(data) > MAX_SOURCE:
        raise AdapterError("SOURCE_LIMIT", "Source exceeds the size limit.")
    try: code = data.decode("utf-8")
    except UnicodeError: raise AdapterError("SOURCE_ENCODING", "Notebook source must be UTF-8.") from None
    if kernel_type == "notebook":
        try:
            nb = json.loads(code)
            if not isinstance(nb.get("cells"), list): raise ValueError()
            for cell in nb["cells"]:
                if cell.get("cell_type") == "code": cell["outputs"] = []
                if isinstance(cell.get("source"), list): cell["source"] = "".join(cell["source"])
            code = canonical(nb).decode()
        except (ValueError, AttributeError, TypeError):
            raise AdapterError("INVALID_NOTEBOOK", "Source is not a supported notebook document.") from None
    return code


def verified_owned_notebook_inventory(transport, account, *, target=None):
    """Enumerate the authenticated owner's full profile; never probe an unreadable new ref."""
    username = account.get("username")
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", username):
        raise AdapterError("ACCOUNT_UNVERIFIED", "Authenticated username is not available.")
    if target is not None and (not isinstance(target, str) or not re.fullmatch(re.escape(username) + r"/[a-z0-9-]+", target)):
        raise AdapterError("NOTEBOOK_IDENTITY_MISMATCH", "Collision target must belong to the authenticated account.")
    token, seen_tokens, seen_refs = None, set(), set()
    pages_hash = hashlib.sha256()
    for page_number in range(1, 1001):
        values = {"group": "PROFILE", "user": username, "language": "all", "kernel_type": "all",
                  "output_type": "all", "page_size": 100}
        if token is not None: values["page_token"] = token
        response = transport.call("list", values)
        if not isinstance(response, dict) or response.get("error"):
            raise AdapterError("NOTEBOOK_LIST_INCOMPLETE", "Owned notebook listing did not return a successful page.")
        kernels = response.get("kernels", [])
        if not isinstance(kernels, list):
            raise AdapterError("NOTEBOOK_LIST_INCOMPLETE", "Owned notebook listing has an invalid collection.")
        pages_hash.update(canonical(response))
        for item_number, item in enumerate(kernels, start=1):
            ref = item.get("ref") if isinstance(item, dict) else None
            if not isinstance(ref, str) or not re.fullmatch(re.escape(username) + r"/[a-z0-9-]+", ref):
                raise AdapterError("NOTEBOOK_LIST_SCOPE", "Notebook listing did not confirm ownership of every returned reference.",
                                   details={"page_number": page_number, "item_number": item_number,
                                            "reference_present": isinstance(ref, str) and bool(ref),
                                            "redacted_private_placeholder": isinstance(item, dict) and item.get("title") == "[Private Notebook]",
                                            "observed_page_sha256": digest(response),
                                            "all_pages_completed": False, "cloud_write_sent": False})
            if ref == target:
                raise AdapterError("NOTEBOOK_COLLISION", "The target reference already exists in this account; no version was pushed.")
            if ref in seen_refs:
                raise AdapterError("NOTEBOOK_LIST_UNSTABLE", "Owned notebook pagination repeated a reference; full enumeration is unproven.")
            seen_refs.add(ref)
        next_token = attr(response, "nextPageToken", "next_page_token")
        if next_token is None or next_token == "":
            return {"method": "ListKernels.PROFILE", "all_pages_completed": True, "pages": page_number,
                    "notebooks_seen": len(seen_refs), "pages_sha256": pages_hash.hexdigest(),
                    "atomic_remote_create": False, "collision_found": False, "target_checked": target is not None}
        if not isinstance(next_token, str) or len(next_token) > 16384 or next_token in seen_tokens:
            raise AdapterError("NOTEBOOK_LIST_PAGINATION", "Owned notebook pagination is invalid or repeats a token.")
        seen_tokens.add(next_token); token = next_token
    raise AdapterError("NOTEBOOK_LIST_LIMIT", "Owned notebook listing did not finish within its bounded page count.")


def submission_readiness(transport, *, request_id=None):
    """Observe account/profile prerequisites without creating a request or cloud object.

    request_id is only caller correlation. A positive observation is neither a
    reservation nor a submission receipt; submit repeats its full preflight.
    """
    if request_id is not None: checked_request_id(request_id)
    result = {"schema": "hepta-kaggle-readiness-v1", "provider": "kaggle",
              "observed_at": now(), "ready": False, "request_id": request_id,
              "request_id_is_correlation_only": True, "authorization_verified": False,
              "readiness_scope": "authentication_and_owned_notebook_inventory",
              "quota_checked": False, "cloud_mutation_performed": False,
              "allocation_guaranteed": False, "submission_must_recheck": True}
    try:
        account = transport.account()
        result["account"] = account
        result["authorization_verified"] = account.get("authenticated") is True
        if not result["authorization_verified"]:
            raise AdapterError("ACCOUNT_UNVERIFIED", "Provider authentication is not confirmed.")
        result["owned_notebook_inventory"] = verified_owned_notebook_inventory(transport, account)
        result["ready"] = True
    except AdapterError as exc:
        result["error"] = exc.as_dict()
    return scrub(result)


class Ledger:
    def __init__(self, root: Path):
        self.root = root.expanduser().absolute()
        if self.root.is_symlink(): raise AdapterError("UNSAFE_STATE_ROOT", "State root cannot be a symlink.")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        s = self.root.stat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise AdapterError("UNSAFE_STATE_ROOT", "State root must be a private directory owned by the current user.")
        self.requests = self.root / "requests"
        if self.requests.is_symlink(): raise AdapterError("UNSAFE_STATE_ROOT", "Requests directory cannot be a symlink.")
        self.requests.mkdir(mode=0o700, exist_ok=True)
        s = self.requests.stat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise AdapterError("UNSAFE_STATE_ROOT", "Requests directory must be private and owned by the current user.")

    def directory(self, request_id):
        path = self.requests / checked_request_id(request_id)
        if path.is_symlink(): raise AdapterError("UNSAFE_STATE_PATH", "Request directory cannot be a symlink.")
        path.mkdir(mode=0o700, exist_ok=True)
        s = path.stat()
        if s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise AdapterError("UNSAFE_STATE_PATH", "Request directory is not private.")
        return path

    @contextlib.contextmanager
    def locked(self, request_id):
        path = self.directory(request_id) / ".lock"
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise AdapterError("REQUEST_BUSY", "Another process is working on this exact request.") from None
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)

    def load(self, request_id, required=True):
        path = self.directory(request_id) / "request.json"
        if not path.exists():
            if required: raise AdapterError("REQUEST_NOT_FOUND", "No durable request exists for this ID.")
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            s = os.fstat(fd)
            if not stat.S_ISREG(s.st_mode) or s.st_size > 16 * 1024 * 1024:
                raise AdapterError("LEDGER_INVALID", "Request record type/size validation failed.")
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as f: data = json.load(f)
        finally: os.close(fd)
        if data.get("schema") != SCHEMA or data.get("request_id") != request_id:
            raise AdapterError("LEDGER_INVALID", "Request record schema or identity does not match.")
        return data

    def save(self, record):
        record["updated_at"] = now()
        atomic_json(self.directory(record["request_id"]) / "request.json", scrub(record))

    def event(self, record, kind, payload=None):
        events = record.setdefault("events", [])
        # Separate raw receipts remain immutable, so bound the state index.
        count = record.get("event_count", 0) + 1
        d = self.directory(record["request_id"]) / "events"
        if d.is_symlink(): raise AdapterError("UNSAFE_STATE_PATH", "Event directory cannot be a symlink.")
        d.mkdir(mode=0o700, exist_ok=True)
        while (d / f"{count:06d}.json").exists(): count += 1
        record["event_count"] = count
        event = {"sequence": count, "at": now(), "kind": kind, "payload": scrub(payload or {})}
        fd = os.open(d / f"{count:06d}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(event, f, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
        events.append({"sequence": count, "at": event["at"], "kind": kind, "sha256": digest(event)})
        record["events"] = events[-128:]
        self.save(record)

    def source(self, request_id):
        return self.directory(request_id) / "source.txt"

    def write_source(self, request_id, code):
        path = self.source(request_id)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(code); f.flush(); os.fsync(f.fileno())

    def submission_responses(self, request_id):
        """Include create-only receipts orphaned by a crash before ledger save."""
        folder = self.directory(request_id) / "events"
        if folder.is_symlink(): raise AdapterError("UNSAFE_STATE_PATH", "Event directory cannot be a symlink.")
        paths = sorted(folder.glob("*.json"))
        if len(paths) > 10000: raise AdapterError("EVENT_SCAN_LIMIT", "Submission recovery exceeds the bounded event scan.")
        result = []
        for path in paths:
            if not re.fullmatch(r"[0-9]{6,}\.json", path.name): continue
            event = json.loads(private_read(path, 16 * 1024 * 1024))
            if event.get("kind") == "remote_submit_response":
                payload = event.get("payload")
                if not isinstance(payload, dict): raise AdapterError("LEDGER_INVALID", "Submission response receipt is malformed.")
                result.append((event.get("sequence"), payload))
        return result


class KaggleAdapter:
    def __init__(self, transport, state_dir: Path):
        self.transport = transport
        self.ledger = Ledger(state_dir)

    @staticmethod
    def receipt(record, **extra):
        keys = ("schema", "request_id", "input_digest", "account", "intent", "submission_state", "remote_submission_state", "remote_effect_unknown", "remote_state", "notebook_ref", "notebook_version", "kernel_id", "kernel_session_id", "session_binding", "created_at", "updated_at", "event_count", "cancel_state", "artifacts", "last_error", "identity_verified", "invalid_inputs")
        out = {key: record[key] for key in keys if key in record}
        if "remote_submission_state" not in record:
            kinds = {event.get("kind") for event in record.get("events", [])}
            if record.get("submission_state") in {"ACCEPTED", "ACCEPTED_WITH_INVALID_INPUTS"}:
                out.update(remote_submission_state="ACKNOWLEDGED", remote_effect_unknown=False)
            elif kinds & {"remote_submit_intent", "remote_submit_incomplete", "remote_submit_response"}:
                out.update(remote_submission_state="MAY_HAVE_BEEN_SENT", remote_effect_unknown=True,
                           effective_submission_state="UNKNOWN",
                           historical_rejection_does_not_prove_rollback=True,
                           historical_note="Older REJECTED states after dispatch describe an HTTP/API rejection, not proof that no remote object or version was created.")
                if isinstance(out.get("last_error"), dict) and isinstance(out["last_error"].get("details"), dict):
                    old = out["last_error"]
                    out["last_error"] = {**old, "details": {**old["details"], "remote_effect_unknown": True,
                                                           "legacy_remote_effect_assertion": old["details"].get("remote_effect_unknown")}}
            elif "preflight_failed" in kinds:
                out.update(remote_submission_state="NOT_SENT", remote_effect_unknown=False)
            else:
                out.update(remote_submission_state="UNPROVEN_LEGACY_RECORD", remote_effect_unknown=True)
        out.update(extra)
        return scrub(out)

    def _account_for(self, record):
        active = self.transport.account()
        if active.get("username") != record["account"].get("username"):
            raise AdapterError("ACCOUNT_MISMATCH", "The active Kaggle account does not own this recorded request.")
        old_id, new_id = record["account"].get("user_id"), active.get("user_id")
        if old_id is not None and new_id is not None and old_id != new_id:
            raise AdapterError("ACCOUNT_MISMATCH", "The active Kaggle account identity changed.")
        return active

    @staticmethod
    def ref_params(record, *, pinned=True):
        ref = record.get("notebook_ref")
        if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9_-]+/[a-z0-9-]+", ref):
            raise AdapterError("REMOTE_IDENTITY_MISSING", "Notebook reference is not safely bound.")
        user, slug = ref.split("/")
        out = {"user_name": user, "kernel_slug": slug}
        if pinned:
            version = positive_int(record.get("notebook_version"))
            if version is None:
                raise AdapterError("REMOTE_VERSION_MISSING", "Exact notebook version is not known; latest is not a substitute.")
            out["version_label"] = "v" + str(version)
        return out

    def _bind_explicit_session(self, record, response, source):
        sid = positive_int(attr(response, "kernelSessionId", "kernel_session_id"))
        if sid is None:
            obj = response.get("kernelSession")
            if isinstance(obj, dict): sid = positive_int(obj.get("id"))
        if sid is None: return
        if record.get("kernel_session_id") not in (None, sid):
            raise AdapterError("SESSION_IDENTITY_CONFLICT", "Kaggle response disagrees with the original session identity.")
        record["kernel_session_id"] = sid
        record["session_binding"] = {"source": source, "response_sha256": digest(response), "notebook_ref": record["notebook_ref"], "notebook_version": record.get("notebook_version")}

    def _confirm_no_owned_notebook_collision(self, record):
        return verified_owned_notebook_inventory(self.transport, record["account"], target=record["notebook_ref"])

    def submit(self, *, request_id, source, timeout=300, accelerator="cpu", internet=False,
               kernel_type="script", dataset_sources=(), kernel_sources=(), model_sources=(), competition_sources=()):
        checked_request_id(request_id)
        if kernel_type not in {"script", "notebook"}: raise AdapterError("INVALID_KERNEL_TYPE", "Only Python scripts and notebooks are supported.")
        if isinstance(timeout, bool) or not 1 <= timeout <= 43200:
            raise AdapterError("INVALID_TIMEOUT", "Remote runtime limit must be between 1 and 43200 seconds.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", accelerator):
            raise AdapterError("INVALID_ACCELERATOR", "Accelerator identifier has an invalid format.")
        code = read_source(Path(source), kernel_type)
        intent = {"source_sha256": hashlib.sha256(code.encode()).hexdigest(), "timeout_seconds": timeout,
                  "accelerator": accelerator, "internet": bool(internet), "kernel_type": kernel_type,
                  "language": "python", "is_private": True, "dataset_sources": list(dataset_sources),
                  "kernel_sources": list(kernel_sources), "model_sources": list(model_sources),
                  "competition_sources": list(competition_sources)}
        for key in ("dataset_sources", "kernel_sources", "model_sources", "competition_sources"):
            if len(intent[key]) > 50 or any(not isinstance(v, str) or len(v) > 512 or "\n" in v for v in intent[key]):
                raise AdapterError("INVALID_INPUT_REFERENCE", "Data source references exceed their bounds.")
        fingerprint = digest(intent)
        with self.ledger.locked(request_id):
            existing = self.ledger.load(request_id, required=False)
            if existing:
                if existing["input_digest"] != fingerprint:
                    raise AdapterError("IDEMPOTENCY_CONFLICT", "Request ID is already bound to different code, inputs or settings.")
                self._account_for(existing)
                if existing["submission_state"] == "SUBMITTING":
                    existing["submission_state"] = "UNKNOWN"
                    self.ledger.event(existing, "interrupted_submission_observed")
                # Deliberately never resubmit, including UNKNOWN and REJECTED.
                return self.receipt(existing, reused=True, remote_submission_replayed=False)
            account = self.transport.account()
            username = account.get("username", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", username):
                raise AdapterError("ACCOUNT_UNVERIFIED", "Authenticated username is not available.")
            stem = re.sub(r"[^a-z0-9]+", "-", request_id.lower()).strip("-")[:18]
            nonce = secrets.token_hex(16)
            slug = "hepta-" + stem + "-" + nonce[:24]
            ref = username + "/" + slug
            record = {"schema": SCHEMA, "provider": "kaggle", "request_id": request_id,
                      "input_digest": fingerprint, "account": account, "intent": intent, "request_nonce": nonce,
                      "notebook_ref": ref, "notebook_version": None, "kernel_id": None,
                      "kernel_session_id": None, "submission_state": "PREPARED", "remote_state": "UNKNOWN",
                      "remote_submission_state": "NOT_SENT", "remote_effect_unknown": False,
                      "created_at": now(), "identity_verified": False}
            self.ledger.write_source(request_id, code)
            self.ledger.event(record, "intent_persisted")
            try:
                collision_check = self._confirm_no_owned_notebook_collision(record)
                self.ledger.event(record, "owned_notebook_enumeration_complete", collision_check)
            except BaseException as exc:
                record["submission_state"] = "REJECTED"
                record["last_error"] = exc.as_dict() if isinstance(exc, AdapterError) else {"code": "PREFLIGHT_INCOMPLETE", "type": type(exc).__name__}
                self.ledger.event(record, "preflight_failed", record["last_error"])
                raise
            values = {"slug": ref, "new_title": slug, "text": code, "language": "python", "kernel_type": kernel_type,
                      "is_private": True, "enable_gpu": accelerator.lower() != "cpu" and not accelerator.lower().startswith("tpu"),
                      "enable_tpu": accelerator.lower().startswith("tpu"), "enable_internet": bool(internet),
                      "session_timeout_seconds": timeout, "kernel_execution_type": "SAVE_AND_RUN_ALL",
                      "dataset_data_sources": list(dataset_sources), "kernel_data_sources": list(kernel_sources),
                      "model_data_sources": list(model_sources), "competition_data_sources": list(competition_sources)}
            if accelerator.lower() != "cpu": values["machine_shape"] = accelerator
            record["submission_state"] = "SUBMITTING"
            # Persist uncertainty before dispatch. This does not claim that bytes
            # necessarily reached Kaggle; it prevents false rollback assumptions.
            record["remote_submission_state"] = "MAY_HAVE_BEEN_SENT"
            record["remote_effect_unknown"] = True
            self.ledger.event(record, "remote_submit_intent", {"rpc": "SaveKernel", "payload_sha256": digest(values)})
            try:
                response = self.transport.call("submit", values, mutation=True)
            except BaseException as exc:
                record["submission_state"] = "UNKNOWN"
                if isinstance(exc, AdapterError):
                    exc.details["remote_effect_unknown"] = True
                    if isinstance(exc, RemoteError): exc.ambiguous = True
                record["last_error"] = exc.as_dict() if isinstance(exc, AdapterError) else {"code": "INTERRUPTED_OR_UNCERTAIN", "type": type(exc).__name__}
                self.ledger.event(record, "remote_submit_incomplete", record["last_error"])
                raise
            self.ledger.event(record, "remote_submit_response", response)
            if response.get("error"):
                record["submission_state"] = "UNKNOWN"
                record["last_error"] = {"code": "PROVIDER_REJECTED", "message": scrub(str(response["error"]))[:1000]}
                self.ledger.event(record, "remote_submit_rejected")
                return self.receipt(record, reused=False)
            version = positive_int(attr(response, "versionNumber", "version_number"))
            actual_ref = bound_response_ref(response.get("ref"), ref)
            kernel_id = positive_int(attr(response, "kernelId", "kernel_id"))
            if actual_ref != ref or version is None or kernel_id is None:
                record["submission_state"] = "UNKNOWN"
                record["last_error"] = {"code": "SUBMIT_IDENTITY_INCOMPLETE", "message": "SaveKernel did not confirm the intended reference, notebook ID and exact version."}
                self.ledger.event(record, "remote_submit_identity_unknown")
                return self.receipt(record, reused=False)
            record["notebook_version"] = version
            record["kernel_id"] = kernel_id
            self._bind_explicit_session(record, response, "SaveKernel.response")
            invalid = {k: v for k, v in response.items() if k.startswith("invalid") and v}
            record["submission_state"] = "ACCEPTED_WITH_INVALID_INPUTS" if invalid else "ACCEPTED"
            record["remote_submission_state"] = "ACKNOWLEDGED"
            record["remote_effect_unknown"] = False
            if invalid: record["invalid_inputs"] = scrub(invalid)
            self.ledger.event(record, "remote_identity_bound", {"invalid_inputs": invalid})
            return self.receipt(record, reused=False)

    def _check_source_identity(self, record, response):
        metadata, blob = response.get("metadata", {}), response.get("blob", {})
        if metadata.get("ref") != record["notebook_ref"]:
            raise AdapterError("NOTEBOOK_IDENTITY_MISMATCH", "Kaggle notebook reference does not match the recorded request.")
        if record.get("kernel_id") is not None and positive_int(metadata.get("id")) != record["kernel_id"]:
            raise AdapterError("NOTEBOOK_IDENTITY_MISMATCH", "Kaggle notebook ID changed; a reused reference is not the original notebook.")
        if attr(metadata, "isPrivate", "is_private") is not True:
            raise AdapterError("PRIVACY_MISMATCH", "Kaggle did not confirm that this notebook is private.")
        source = blob.get("source")
        if not isinstance(source, str) or hashlib.sha256(source.encode()).hexdigest() != record["intent"]["source_sha256"]:
            raise AdapterError("SOURCE_IDENTITY_MISMATCH", "Kaggle source does not exactly match the frozen request.")
        record["identity_verified"] = True

    def _status(self, record):
        self._account_for(record)
        if record["submission_state"] not in {"ACCEPTED", "ACCEPTED_WITH_INVALID_INPUTS"}:
            return self.receipt(record, observed_remote=False)
        self._check_source_identity(record, self.transport.call("get", self.ref_params(record)))
        response = self.transport.call("status", self.ref_params(record))
        self._bind_explicit_session(record, response, "GetKernelSessionStatus.response")
        record["remote_state"] = status_name(response)
        if record["remote_state"] == "CANCEL_ACKNOWLEDGED": record["cancel_state"] = "CONFIRMED"
        record["last_status_response"] = scrub(response)
        self.ledger.event(record, "remote_status_observed", response)
        return self.receipt(record, observed_remote=True)

    def status(self, request_id):
        with self.ledger.locked(request_id):
            return self._status(self.ledger.load(request_id))

    def resume(self, request_id):
        with self.ledger.locked(request_id):
            record = self.ledger.load(request_id)
            self._account_for(record)
            if record["submission_state"] in {"UNKNOWN", "SUBMITTING"}:
                record["submission_state"] = "UNKNOWN"
                receipts = self.ledger.submission_responses(request_id)
                proven = []
                for sequence, payload in receipts:
                    version = positive_int(attr(payload, "versionNumber", "version_number"))
                    kernel_id = positive_int(attr(payload, "kernelId", "kernel_id"))
                    if not payload.get("error") and bound_response_ref(payload.get("ref"), record["notebook_ref"]) == record["notebook_ref"] and version and kernel_id:
                        proven.append((sequence, payload, version, kernel_id))
                identities = {(item[2], item[3]) for item in proven}
                if len(identities) > 1:
                    raise AdapterError("SUBMISSION_RECEIPT_CONFLICT", "Durable SaveKernel receipts disagree about the original execution identity.")
                if proven:
                    sequence, acknowledged, version, kernel_id = proven[0]
                    candidate = dict(record, notebook_version=version, kernel_id=kernel_id)
                    pinned = self.transport.call("get", self.ref_params(candidate))
                    self._check_source_identity(candidate, pinned)
                    record.update(notebook_version=version, kernel_id=kernel_id, identity_verified=True)
                    self._bind_explicit_session(record, acknowledged, "SaveKernel.durable_response")
                    self._bind_explicit_session(record, pinned, "GetKernel.pinned.response")
                    invalid = {k: v for k, v in acknowledged.items() if k.startswith("invalid") and v}
                    record["submission_state"] = "ACCEPTED_WITH_INVALID_INPUTS" if invalid else "ACCEPTED"
                    record["remote_submission_state"] = "ACKNOWLEDGED"
                    record["remote_effect_unknown"] = False
                    record.pop("last_error", None)
                    if invalid: record["invalid_inputs"] = scrub(invalid)
                    self.ledger.event(record, "original_submission_reconciled", {"submit_receipt_sequence": sequence, "submit_response_sha256": digest(acknowledged), "pinned_response_sha256": digest(pinned)})
                    result = self._status(record)
                    result.update(remote_submission_replayed=False, reconciled=True)
                    return result
                try: response = self.transport.call("get", self.ref_params(record, pinned=False))
                except RemoteError as exc:
                    if exc.status != 404: raise
                    record["submission_state"] = "UNKNOWN"
                    self.ledger.event(record, "reconcile_not_found", {"meaning": "No visible notebook; this does not authorize resubmission."})
                    return self.receipt(record, remote_submission_replayed=False, reconciled=False)
                # Same source may have been saved again as another version. This is
                # only an observed candidate, never evidence of our original run.
                self._check_source_identity(dict(record), response)
                metadata = response.get("metadata", {})
                version = positive_int(attr(metadata, "currentVersionNumber", "current_version_number"))
                candidate = {"notebook_ref": record["notebook_ref"], "latest_version_observed": version,
                             "source_matches": True, "original_execution_proven": False}
                record["identity_verified"] = False
                self.ledger.event(record, "unbound_submission_candidate_observed", {**candidate, "response_sha256": digest(response)})
                return self.receipt(record, remote_submission_replayed=False, reconciled=False, candidate=candidate,
                                    recovery_blocker="Original version is absent from durable SaveKernel response evidence; latest cannot identify it.")
            result = self._status(record)
            result.update({"remote_submission_replayed": False, "reconciled": record["submission_state"] in {"ACCEPTED", "ACCEPTED_WITH_INVALID_INPUTS"}})
            return result

    def wait(self, request_id, seconds=30, poll_interval=3):
        if not 0 <= seconds <= 60 or not 1 <= poll_interval <= 30:
            raise AdapterError("INVALID_WAIT", "Wait is bounded to 60 seconds; poll interval is 1..30 seconds.")
        deadline = time.monotonic() + seconds
        while True:
            result = self.status(request_id)
            if result.get("remote_state") in TERMINAL or not result.get("observed_remote") or time.monotonic() >= deadline:
                return result
            time.sleep(min(poll_interval, max(0, deadline - time.monotonic())))

    def logs(self, request_id, cursor=None, limit=16384):
        if not 1 <= limit <= 65536: raise AdapterError("INVALID_LOG_LIMIT", "Log reads are bounded to 64 KiB.")
        with self.ledger.locked(request_id):
            record = self.ledger.load(request_id); self._account_for(record)
            self._check_source_identity(record, self.transport.call("get", self.ref_params(record)))
            params = self.ref_params(record); params["page_size"] = 1
            response = self.transport.call("output", params)
            raw = response.get("log") or ""
            if not isinstance(raw, str):
                raise AdapterError("INVALID_LOG_RESPONSE", "Provider log is not text.")
            data = raw.encode()
            old = record.get("log_snapshot", {})
            generation = old.get("generation", 0)
            if old:
                prev_path = self.ledger.directory(request_id) / f"log-{generation}.txt"
                prev = prev_path.read_bytes()
                if not data.startswith(prev): generation += 1
            path = self.ledger.directory(request_id) / f"log-{generation}.txt"
            fd, tmp = tempfile.mkstemp(prefix=".log-", dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data); f.flush(); os.fsync(f.fileno())
                if path.is_symlink(): raise AdapterError("UNSAFE_STATE_PATH", "Log path cannot be a symlink.")
                os.replace(tmp, path)
            finally:
                with contextlib.suppress(FileNotFoundError): os.unlink(tmp)
            record["log_snapshot"] = {"generation": generation, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            self.ledger.save(record)
            offset = 0
            if cursor:
                if not re.fullmatch(r"\d+:\d+", cursor): raise AdapterError("INVALID_CURSOR", "Log cursor is malformed.")
                gen, offset = map(int, cursor.split(":"))
                if gen != generation: raise AdapterError("LOG_REPLACED", "Provider log changed; resume from the new generation.", details={"next_cursor": f"{generation}:0"})
            if offset > len(data): raise AdapterError("INVALID_CURSOR", "Log cursor is beyond the current snapshot.")
            end = min(len(data), offset + limit)
            while True:
                try: text = data[offset:end].decode(); break
                except UnicodeDecodeError as exc:
                    if exc.start == 0 and end - offset >= 4: raise AdapterError("INVALID_CURSOR", "Log cursor is not at a UTF-8 boundary.") from None
                    end -= 1
                    if end <= offset: raise AdapterError("LOG_LIMIT_TOO_SMALL", "Log limit cannot hold the next UTF-8 character.") from None
            clean = scrub(text)
            return {"request_id": request_id, "notebook_ref": record["notebook_ref"], "notebook_version": record["notebook_version"],
                    "cursor": f"{generation}:{offset}", "next_cursor": f"{generation}:{end}", "eof": end == len(data),
                    "snapshot_bytes": len(data), "snapshot_sha256": record["log_snapshot"]["sha256"], "text": clean, "redacted": clean != text}

    def _pages(self, record, action, page_size=100):
        token, seen = None, set()
        for _ in range(100):
            params = self.ref_params(record); params["page_size"] = page_size
            if token: params["page_token"] = token
            response = self.transport.call(action, params)
            yield response
            token = attr(response, "nextPageToken", "next_page_token")
            if not token: return
            if not isinstance(token, str) or token in seen:
                raise AdapterError("PAGINATION_LOOP", "Provider output pagination is not progressing.")
            seen.add(token)
        raise AdapterError("PAGE_LIMIT", "Provider output exceeds the bounded page count.")

    @staticmethod
    def _manifest_entries(folder, request_id, manifest_name):
        manifest_path = folder / safe_name(manifest_name)
        if manifest_path.stat().st_size > MAX_SOURCE:
            raise AdapterError("REMOTE_MANIFEST_TOO_LARGE", "Remote hash manifest exceeds its bound.")
        try: manifest = json.loads(manifest_path.read_bytes())
        except (ValueError, UnicodeError): raise AdapterError("INVALID_REMOTE_MANIFEST", "Remote hash manifest is not valid JSON.") from None
        if not isinstance(manifest, dict): raise AdapterError("INVALID_REMOTE_MANIFEST", "Remote hash manifest must be an object.")
        if manifest.get("schema") != "hepta-artifact-manifest-v1" or manifest.get("request_id") != request_id:
            raise AdapterError("REMOTE_MANIFEST_IDENTITY", "Remote manifest belongs to a different request.")
        if not isinstance(manifest.get("files"), list): raise AdapterError("INVALID_REMOTE_MANIFEST", "Remote manifest must contain a file list.")
        declared = {}
        for entry in manifest["files"]:
            if not isinstance(entry, dict): raise AdapterError("INVALID_REMOTE_MANIFEST", "Remote manifest file entry is not an object.")
            name = safe_name(entry.get("path"))
            if name in declared: raise AdapterError("DUPLICATE_MANIFEST_PATH", "Remote manifest repeats a path.")
            if type(entry.get("bytes")) is not int or entry["bytes"] < 0 or not isinstance(entry.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                raise AdapterError("INVALID_REMOTE_MANIFEST", "Manifest file size or SHA-256 has an invalid representation.")
            declared[name] = {"bytes": entry.get("bytes"), "sha256": entry.get("sha256")}
        return declared

    @staticmethod
    def _verify_manifest(folder, files, request_id, manifest_name):
        if manifest_name not in {x["path"] for x in files}:
            raise AdapterError("REMOTE_MANIFEST_MISSING", "Execution did not produce the required hash manifest.")
        declared = KaggleAdapter._manifest_entries(folder, request_id, manifest_name)
        actual_map = {x["path"]: {"bytes": x["bytes"], "sha256": x["sha256"]} for x in files if x["path"] != manifest_name}
        if declared != actual_map:
            raise AdapterError("REMOTE_MANIFEST_HASH", "Downloaded output does not match the complete remote hash manifest.")

    @staticmethod
    def _require_http_length(info, actual):
        if type(info.get("http_content_length")) is not int or info.get("http_content_length_verified") is not True:
            raise AdapterError("HTTP_CONTENT_LENGTH_REQUIRED", "A verified HTTP Content-Length receipt is required for every manifest-mode file.")
        if info["http_content_length"] != actual["bytes"]:
            raise AdapterError("ARTIFACT_LENGTH", "Actual bytes do not match the verified HTTP length receipt.")

    def _reuse_artifacts(self, record, folder, receipt, manifest_name, *, recovered=False):
        if folder.is_symlink() or folder.parent.is_symlink() or not folder.is_dir():
            raise AdapterError("UNSAFE_STATE_PATH", "Artifact directory must be a regular local directory.")
        identity = {"schema": "hepta-kaggle-download-v1", "request_id": record["request_id"],
                    "input_digest": record["input_digest"], "notebook_ref": record["notebook_ref"],
                    "notebook_version": record["notebook_version"], "directory": str(folder)}
        if any(receipt.get(k) != v for k, v in identity.items()) or record.get("remote_state") != "COMPLETE":
            raise AdapterError("ARTIFACT_RECEIPT_IDENTITY", "Published artifacts are not bound to this completed request.")
        files = receipt.get("files")
        if not isinstance(files, list) or receipt.get("files_manifest_sha256") != digest(files):
            raise AdapterError("ARTIFACT_RECEIPT_INVALID", "Published artifact receipt is incomplete or damaged.")
        if not manifest_name and any(item.get("provider_size_matches") is False for item in files):
            raise AdapterError("ARTIFACT_LENGTH", "Provider-size conflict requires an explicitly requested execution manifest; strict provider-size mode cannot accept it.")
        seen, total = set(), 0
        for item in files:
            name = safe_name(item["path"])
            if name in seen: raise AdapterError("ARTIFACT_RECEIPT_INVALID", "Published artifact receipt repeats a path.")
            seen.add(name)
            target = folder / name
            if any(parent.is_symlink() for parent in target.parents if parent != folder.parent):
                raise AdapterError("UNSAFE_STATE_PATH", "Artifact path contains a symlink.")
            checked = hash_file(target)
            if checked != {"bytes": item["bytes"], "sha256": item["sha256"]}:
                raise AdapterError("LOCAL_ARTIFACT_CHANGED", "A previously verified artifact has changed.")
            total += checked["bytes"]
        if total != receipt.get("total_bytes"):
            raise AdapterError("ARTIFACT_RECEIPT_INVALID", "Published artifact byte total does not match.")
        if manifest_name:
            self._verify_manifest(folder, files, record["request_id"], manifest_name)
            for item in files: self._require_http_length(item, item)
            receipt.update(remote_manifest_verified=True, remote_manifest_name=manifest_name, verification_policy="manifest-and-http-v1")
        if recovered or record.get("artifacts") != receipt:
            atomic_json(folder / ".hepta-download-receipt.json", receipt)
            record["artifacts"] = receipt
            self.ledger.event(record, "artifacts_recovered" if recovered else "artifact_manifest_verified", receipt)
        return {**receipt, "reused": True, "recovered_local_publish": recovered}

    def artifacts(self, request_id, *, max_bytes=1024 ** 3, manifest_name=None):
        if not 1 <= max_bytes <= 64 * 1024 ** 3: raise AdapterError("INVALID_ARTIFACT_BUDGET", "Download budget must be 1 byte..64 GiB.")
        if manifest_name: safe_name(manifest_name)
        with self.ledger.locked(request_id):
            record = self.ledger.load(request_id); self._account_for(record)
            self.ref_params(record)
            if record["submission_state"] == "ACCEPTED_WITH_INVALID_INPUTS":
                raise AdapterError("INVALID_REMOTE_INPUTS", "Kaggle reported invalid input sources; outputs cannot pass request acceptance.")
            existing = record.get("artifacts")
            folder = self.ledger.directory(request_id) / "artifacts" / ("v" + str(record["notebook_version"]))
            if existing:
                return self._reuse_artifacts(record, folder, dict(existing), manifest_name)
            if folder.exists() or folder.is_symlink():
                if folder.is_symlink() or folder.parent.is_symlink():
                    raise AdapterError("UNSAFE_STATE_PATH", "Artifact directory cannot contain a symlink.")
                try: receipt = json.loads(private_read(folder / ".hepta-download-receipt.json", 16 * 1024 * 1024))
                except (FileNotFoundError, json.JSONDecodeError):
                    raise AdapterError("ARTIFACT_DESTINATION_EXISTS", "Unrecorded artifact directory has no valid publication receipt.") from None
                return self._reuse_artifacts(record, folder, receipt, manifest_name, recovered=True)
            self._status(record)
            if record["remote_state"] != "COMPLETE":
                raise AdapterError("REMOTE_NOT_COMPLETE", "Only a completed execution can publish verified artifacts.", details={"remote_state": record["remote_state"]})
            identity = self.transport.call("get", self.ref_params(record))
            self._check_source_identity(record, identity)
            self.ledger.event(record, "artifact_source_verified", {"response_sha256": digest(identity)})
            sizes, items = {}, {}
            for page in self._pages(record, "files"):
                for item in page.get("files") or []:
                    name = safe_name(item.get("name"))
                    if name == ".hepta-download-receipt.json":
                        raise AdapterError("RESERVED_OUTPUT_NAME", "Provider output conflicts with the adapter's reserved receipt filename.")
                    if name in sizes: raise AdapterError("DUPLICATE_OUTPUT", "Provider lists the same output more than once.")
                    raw_size = item.get("size", 0)
                    size = int(raw_size) if isinstance(raw_size, (str, int)) and str(raw_size).isdigit() else None
                    if size is None: raise AdapterError("INVALID_OUTPUT_SIZE", "Provider returned an invalid file size.")
                    sizes[name] = size
            if not manifest_name and sum(sizes.values()) > max_bytes: raise AdapterError("ARTIFACT_BUDGET", "Provider output exceeds the download budget.")
            for page in self._pages(record, "output"):
                for item in page.get("files") or []:
                    name = safe_name(attr(item, "fileName", "file_name"))
                    if name in items: raise AdapterError("DUPLICATE_OUTPUT", "Provider lists the same output URL more than once.")
                    url = item.get("url")
                    if not isinstance(url, str): raise AdapterError("INVALID_OUTPUT_URL", "Provider omitted an output URL.")
                    items[name] = url
            if set(sizes) != set(items): raise AdapterError("OUTPUT_LIST_MISMATCH", "Provider size and URL listings do not name the same fixed-version outputs.")
            if manifest_name and manifest_name not in items: raise AdapterError("REMOTE_MANIFEST_MISSING", "Execution did not produce the required hash manifest.")
            reqdir = self.ledger.directory(request_id)
            stage = Path(tempfile.mkdtemp(prefix=".download-", dir=reqdir))
            files, total, warnings, declared = [], 0, [], None
            try:
                ordered = ([manifest_name] + sorted(set(items) - {manifest_name})) if manifest_name else sorted(items)
                for name in ordered:
                    target = stage / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    expected_size = None if name == manifest_name else declared[name]["bytes"] if manifest_name else sizes[name]
                    budget = min(max_bytes - total, MAX_SOURCE) if name == manifest_name else max_bytes - total
                    info = self.transport.download(items[name], target, expected_size=expected_size, max_bytes=budget,
                                                   require_content_length=bool(manifest_name))
                    # Independently hash the descriptor after download; a transport receipt alone is not verification.
                    actual = hash_file(target)
                    if {"bytes": info.get("bytes"), "sha256": info.get("sha256")} != actual:
                        raise AdapterError("DOWNLOAD_HASH_MISMATCH", "Downloaded bytes do not match the transport receipt.")
                    if manifest_name: self._require_http_length(info, actual)
                    if expected_size is not None and actual["bytes"] != expected_size:
                        raise AdapterError("ARTIFACT_LENGTH", "Actual bytes do not match the required file size.")
                    if manifest_name and name != manifest_name and actual != declared[name]:
                        raise AdapterError("REMOTE_MANIFEST_HASH", "Payload bytes or SHA-256 do not match the execution-generated manifest.")
                    provider_matches = sizes[name] == actual["bytes"]
                    item_receipt = {"path": name, **actual, "provider_list_size": sizes[name], "provider_size_matches": provider_matches,
                                    "http_content_length": info.get("http_content_length"),
                                    "http_content_length_verified": info.get("http_content_length_verified", False)}
                    files.append(item_receipt); total += actual["bytes"]
                    if not provider_matches:
                        if not manifest_name: raise AdapterError("ARTIFACT_LENGTH", "Actual bytes do not match the provider file-list size.")
                        warnings.append({"code": "PROVIDER_SIZE_CONFLICT", "path": name, "provider_list_size": sizes[name],
                                         "http_content_length": info["http_content_length"], "actual_bytes": actual["bytes"],
                                         "verification_authority": "http_length_and_local_hash" if name == manifest_name else "execution_manifest_size_and_sha256"})
                    if name == manifest_name:
                        declared = self._manifest_entries(stage, request_id, manifest_name)
                        if set(declared) != set(items) - {manifest_name}:
                            raise AdapterError("REMOTE_MANIFEST_COVERAGE", "Manifest must cover every fixed-version output except itself exactly once.")
                        if total + sum(x["bytes"] for x in declared.values()) > max_bytes:
                            raise AdapterError("ARTIFACT_BUDGET", "Execution manifest output sizes exceed the download budget.")
                verified = False
                if manifest_name:
                    self._verify_manifest(stage, files, request_id, manifest_name)
                    verified = True
                publish_parent = reqdir / "artifacts"
                if publish_parent.is_symlink(): raise AdapterError("UNSAFE_STATE_PATH", "Artifact directory cannot be a symlink.")
                publish_parent.mkdir(mode=0o700, exist_ok=True)
                destination = publish_parent / ("v" + str(record["notebook_version"]))
                if destination.exists() or destination.is_symlink(): raise AdapterError("ARTIFACT_DESTINATION_EXISTS", "Unrecorded artifact destination already exists; refusing replacement.")
                receipt = {"schema": "hepta-kaggle-download-v1", "request_id": request_id, "input_digest": record["input_digest"],
                           "notebook_ref": record["notebook_ref"], "notebook_version": record["notebook_version"],
                           "directory": str(destination), "files": files, "total_bytes": total,
                           "remote_manifest_verified": verified, "remote_manifest_name": manifest_name, "files_manifest_sha256": digest(files),
                           "verification_policy": "manifest-and-http-v1" if manifest_name else "provider-size-strict-v1",
                           "provider_sizes_all_match": not warnings, "warnings": warnings}
                atomic_json(stage / ".hepta-download-receipt.json", receipt)
                os.rename(stage, destination)
                dfd = os.open(publish_parent, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(dfd)
                finally: os.close(dfd)
                record["artifacts"] = receipt
                self.ledger.event(record, "artifacts_verified", receipt)
                return {**receipt, "reused": False, "request_id": request_id}
            except BaseException as exc:
                self.ledger.event(record, "artifact_download_failed", {"files_completed": len(files), "bytes_completed": total,
                                                                     "error": exc.as_dict() if isinstance(exc, AdapterError) else {"type": type(exc).__name__}})
                raise
            finally:
                if stage.exists(): shutil.rmtree(stage)

    def cancel(self, request_id, *, wait_seconds=30):
        if not 0 <= wait_seconds <= 60: raise AdapterError("INVALID_WAIT", "Cancellation observation is bounded to 60 seconds.")
        with self.ledger.locked(request_id):
            record = self.ledger.load(request_id); self._account_for(record)
            self._status(record)
            if record["remote_state"] in TERMINAL:
                return self.receipt(record, remote_stop_confirmed=record["remote_state"] == "CANCEL_ACKNOWLEDGED", cancel_rpc_sent=False)
            sid = positive_int(record.get("kernel_session_id"))
            binding = record.get("session_binding")
            if sid is None or not binding or binding.get("notebook_ref") != record["notebook_ref"] or binding.get("notebook_version") != record["notebook_version"]:
                raise AdapterError("SESSION_IDENTITY_UNPROVEN", "Cloud cancellation requires a proven Kaggle kernel session ID; notebook ID and version are not substitutes.")
            already_sent = record.get("cancel_state") in {"REQUESTING", "REQUESTED", "UNKNOWN"}
            if not already_sent:
                record["cancel_state"] = "REQUESTING"
                self.ledger.event(record, "cancel_intent", {"kernel_session_id": sid})
                try: response = self.transport.call("cancel", {"kernel_session_id": sid}, mutation=True)
                except BaseException as exc:
                    record["cancel_state"] = "UNKNOWN"
                    self.ledger.event(record, "cancel_response_unknown", exc.as_dict() if isinstance(exc, AdapterError) else {"type": type(exc).__name__})
                    raise
                error = attr(response, "errorMessage", "error_message")
                record["cancel_state"] = "REJECTED" if error else "REQUESTED"
                self.ledger.event(record, "cancel_response", response)
                if error: return self.receipt(record, remote_stop_confirmed=False, cancel_rpc_sent=True)
        result = self.wait(request_id, seconds=wait_seconds)
        result.update({"remote_stop_confirmed": result.get("remote_state") == "CANCEL_ACKNOWLEDGED", "cancel_rpc_sent": not already_sent})
        return result

