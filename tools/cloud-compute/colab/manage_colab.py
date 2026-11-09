#!/usr/bin/env python3
"""Safe, noninteractive bootstrap for a fixed Hepta Colab runtime and kernel.

The public REST API is used only for account eligibility reads. Runtime
allocation uses the pinned official SDK, once per durable request key. A
dedicated Jupyter session path gives a read-only way to reconcile an uncertain
kernel creation; no existing user kernel is adopted, restarted, or deleted.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import asdict
from datetime import datetime, timezone
import fcntl
import hashlib
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from urllib.parse import quote, urlsplit

from hepta_colab import Profile, Ledger, ACTIVE, canonical, cached_credentials, cached_account, read_only_ledger
from authorize_colab import AuthFailure, authorize, _open_status_parent

REST_BASE = "https://colaboratory.googleapis.com/v1beta/"
VALID_ACCELERATORS = frozenset({"NONE", "T4", "L4", "A100", "H100", "G4"})
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$")
SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
TIERS = frozenset({"SUBSCRIPTION_TIER_FREE", "SUBSCRIPTION_TIER_PRO",
                  "SUBSCRIPTION_TIER_PRO_PLUS", "SUBSCRIPTION_TIER_UNSPECIFIED"})


class BootstrapError(Exception):
    def __init__(self, code):
        self.code = code


class AllocationRefused(BootstrapError):
    """The official SDK confirmed HTTP 412 with no assignment returned."""


def now():
    return datetime.now(timezone.utc).isoformat()


def identifier(value, code="INVALID_REMOTE_IDENTIFIER"):
    if not isinstance(value, str) or not SAFE_ID.fullmatch(value):
        raise BootstrapError(code)
    return value


def enum_name(value):
    return getattr(value, "name", str(value))


def private_write(path, value, *, no_clobber=False):
    """Atomic, fsynced 0600 write through a validated pinned parent fd."""
    data = canonical(value) + b"\n"
    if len(data) > 1048576:
        raise BootstrapError("STATE_TOO_LARGE")
    fd, name = _open_status_parent(str(path))
    temp_name = ".bootstrap-" + uuid.uuid4().hex
    try:
        outfd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        with os.fdopen(outfd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if no_clobber:
            try:
                os.link(temp_name, name, src_dir_fd=fd, dst_dir_fd=fd,
                        follow_symlinks=False)
            except FileExistsError:
                previous = private_read(path)
                if canonical(previous) != canonical(value):
                    raise BootstrapError("STATE_DESTINATION_CONFLICT") from None
        else:
            os.replace(temp_name, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temp_name, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def private_read(path):
    fd, name = _open_status_parent(str(path))
    try:
        source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=fd)
        with os.fdopen(source, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise BootstrapError("STATE_FILE_NOT_PRIVATE")
            data = stream.read(1048577)
        if len(data) > 1048576:
            raise BootstrapError("STATE_TOO_LARGE")
        return json.loads(data)
    finally:
        os.close(fd)


class Journal:
    def __init__(self, root):
        self.root = Path(root)
        if not self.root.is_absolute():
            raise BootstrapError("STATE_DIRECTORY_MUST_BE_ABSOLUTE")
        # Validate ancestors before mkdir; never follow a symlink through an
        # attacker-writable parent. Parent must already exist.
        probe = self.root / (".validate-" + uuid.uuid4().hex) if self.root.exists() else self.root
        fd, _ = _open_status_parent(str(probe))
        os.close(fd)
        self.root.mkdir(mode=0o700, exist_ok=True)
        if self.root.is_symlink():
            raise BootstrapError("STATE_DIRECTORY_UNSAFE")
        info = self.root.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise BootstrapError("STATE_DIRECTORY_NOT_PRIVATE")
        self.provision = self.root / "provisioning"
        self.credentials = self.root / "credentials"
        for path in (self.provision, self.credentials):
            path.mkdir(mode=0o700, exist_ok=True)
            if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077:
                raise BootstrapError("STATE_DIRECTORY_NOT_PRIVATE")
        self.state_file = self.credentials / "sessions.json"

    @contextmanager
    def locked(self):
        lock_path = self.root / "bootstrap.lock"
        parent, name = _open_status_parent(str(lock_path))
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                         os.O_CLOEXEC, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
                raise BootstrapError("STATE_LOCK_UNSAFE")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def path(self, key):
        if not isinstance(key, str) or not SAFE_KEY.fullmatch(key):
            raise BootstrapError("INVALID_REQUEST_KEY")
        return self.provision / (hashlib.sha256(key.encode()).hexdigest() + ".json")

    def load(self, key):
        try:
            value = private_read(self.path(key))
        except FileNotFoundError:
            return None
        if not isinstance(value, dict) or value.get("key") != key or value.get("schema") != 1:
            raise BootstrapError("PROVISIONING_JOURNAL_INVALID")
        return value

    def save(self, value):
        value["updated_at"] = now()
        private_write(self.path(value["key"]), value)

    def records(self):
        paths = list(self.provision.glob("*.json"))
        if len(paths) > 1024:
            raise BootstrapError("TOO_MANY_PROVISIONING_RECORDS")
        records = []
        for path in paths:
            value = private_read(path)
            if not isinstance(value, dict) or value.get("schema") != 1 or self.path(value.get("key")) != path:
                raise BootstrapError("PROVISIONING_JOURNAL_INVALID")
            records.append(value)
        return records

    def save_session(self, record, assignment):
        from colab_cli.state import SessionState
        info = assignment.runtime_proxy_info
        session = SessionState(name=record["session_name"], token=info.token,
            url=info.url, endpoint=record["endpoint"],
            token_expires_at=info.expires_at(),
            variant=record["actual_spec"]["variant"],
            accelerator=record["actual_spec"]["accelerator"],
            machine_shape=record["actual_spec"]["shape"],
            kernel_id=record["kernel_id"], session_id=record["client_session_id"])
        try:
            sessions = private_read(self.state_file)
        except FileNotFoundError:
            sessions = {}
        if not isinstance(sessions, dict):
            raise BootstrapError("SESSION_STORE_INVALID")
        previous = sessions.get(session.name)
        if previous and any(previous.get(k) != getattr(session, k)
                            for k in ("endpoint", "kernel_id", "session_id")):
            raise BootstrapError("SESSION_STORE_IDENTITY_CONFLICT")
        sessions[session.name] = session.model_dump(mode="json")
        private_write(self.state_file, sessions)


class Backend:
    def __init__(self, expected_email=None, quota_project=None):
        if quota_project is not None and not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", quota_project):
            raise BootstrapError("INVALID_QUOTA_PROJECT")
        self.quota_project = quota_project
        logging.disable(logging.CRITICAL)
        self.account = authorize(argparse.Namespace(expected_account=expected_email,
            non_interactive=True, open_browser=False, status_file=None), io.StringIO(), io.StringIO())
        from colab_cli.client import Client, Prod
        from google.auth.transport.requests import AuthorizedSession
        # Explicitly disable AuthorizedSession's auth retry: a mutation must
        # never be replayed automatically after an uncertain response.
        creds = cached_credentials("oauth2")
        actual_account = cached_account(creds)
        if actual_account["email"].casefold() != self.account["account_email"].casefold():
            raise BootstrapError("AUTH_ACCOUNT_CHANGED_DURING_BOOTSTRAP")
        self.session = AuthorizedSession(creds, max_refresh_attempts=0)
        os.environ["COLAB_CLI_ASSIGN_RETRIES"] = "0"
        os.environ["COLAB_CLI_REQUEST_TIMEOUT"] = "45"
        self.client = Client(Prod(), self.session)

    def close(self):
        self.session.close()

    def read_rest(self, resource):
        try:
            headers = {}
            if self.quota_project:
                headers["x-goog-user-project"] = self.quota_project
            with self.session.get(REST_BASE + resource, timeout=(10, 25), headers=headers,
                                  allow_redirects=False, stream=True) as response:
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > 1048576:
                        raise BootstrapError("PUBLIC_API_RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
                raw = json.loads(b"".join(chunks))
                if response.status_code != 200:
                    code = "PUBLIC_API_HTTP_" + str(response.status_code)
                    # Only fixed Google error reasons are exposed, never raw
                    # messages, URLs, headers or arbitrary error metadata.
                    for detail in raw.get("error", {}).get("details", []):
                        if isinstance(detail, dict) and detail.get("reason") in {
                            "SERVICE_DISABLED", "USER_PROJECT_DENIED",
                            "ACCESS_TOKEN_SCOPE_INSUFFICIENT", "BILLING_DISABLED",
                        }:
                            code = "PUBLIC_API_" + detail["reason"]
                            break
                    return {"status": "unavailable", "error_code": code}
            if resource == "subscription":
                tier = raw.get("tier")
                if tier not in TIERS:
                    raise BootstrapError("PUBLIC_API_SCHEMA_INVALID")
                return {"status": "available", "tier": tier}
            specs = []
            if not isinstance(raw.get("runtimeSpecs"), list):
                raise BootstrapError("PUBLIC_API_SCHEMA_INVALID")
            for item in raw["runtimeSpecs"]:
                key = item.get("key", {})
                variant = {"VARIANT_CPU": "DEFAULT", "VARIANT_GPU": "GPU",
                           "VARIANT_TPU": "TPU"}.get(key.get("variant"))
                shape = {"SHAPE_STANDARD": "STANDARD", "SHAPE_HIGHMEM": "HIGH_RAM"}.get(key.get("shape"))
                accelerator = key.get("accelerator")
                # Google protobuf JSON omits a scalar boolean when false.
                # Absence is ineligible, never an implicit eligibility grant.
                eligible = item.get("eligible", False)
                if variant is None or shape is None or not isinstance(eligible, bool):
                    raise BootstrapError("PUBLIC_API_SCHEMA_INVALID")
                if not isinstance(accelerator, str) or not re.fullmatch(r"[A-Z0-9_-]{1,32}", accelerator):
                    raise BootstrapError("PUBLIC_API_SCHEMA_INVALID")
                specs.append({"variant": variant, "accelerator": accelerator,
                              "shape": shape, "eligible": eligible})
            return {"status": "available", "runtime_specs": specs}
        except BootstrapError as exc:
            return {"status": "unavailable", "error_code": exc.code}
        except Exception:
            return {"status": "unavailable", "error_code": "PUBLIC_API_READ_FAILED"}

    def assignments(self):
        return self.client.list_assignments()

    def inventory(self):
        try:
            usage = self.client.get_consumption_user_info()
            balance, rate = float(usage.paid_compute_units_balance), float(usage.consumption_rate_hourly)
            count = int(usage.assignments_count)
            if not math.isfinite(balance) or not math.isfinite(rate) or count < 0:
                raise BootstrapError("CONSUMPTION_SCHEMA_INVALID")
            consumption = {"status": "available", "paid_compute_units_balance": balance,
                           "consumption_rate_hourly": rate, "assignments_count": count}
        except Exception:
            consumption = {"status": "unavailable", "error_code": "CONSUMPTION_READ_FAILED"}
        try:
            assignments = {"status": "available", "runtimes": [assignment_projection(a) for a in self.assignments()]}
        except Exception:
            assignments = {"status": "unavailable", "error_code": "ASSIGNMENTS_READ_FAILED"}
        return {"status": "observed", "account": self.account, "observed_at": now(),
                "subscription": self.read_rest("subscription"),
                "eligibility": self.read_rest("runtimespecs"),
                "consumption": consumption, "assignments": assignments}

    def assign(self, notebook_hash, spec):
        from colab_cli.client import Accelerator, Shape, Variant, TooManyAssignmentsError
        # Overwrite even if a caller changed its environment after construction.
        os.environ["COLAB_CLI_ASSIGN_RETRIES"] = "0"
        try:
            return self.client.assign(uuid.UUID(notebook_hash), Variant[spec["variant"]],
                                      Accelerator[spec["accelerator"]], Shape[spec["shape"]])
        except TooManyAssignmentsError:
            # The pinned SDK raises this only for the allocation POST's HTTP 412.
            # That is an explicit refusal, unlike a timeout or gateway failure.
            raise AllocationRefused("ALLOCATION_REFUSED_PRECONDITION") from None

    def reconcile_assignment(self, notebook_hash, spec):
        from colab_cli.client import Accelerator, Shape, Variant, Assignment
        value = self.client._get_assignment(uuid.UUID(notebook_hash), Variant[spec["variant"]],
                                            Accelerator[spec["accelerator"]], Shape[spec["shape"]])
        return value if isinstance(value, Assignment) else None

    def jupyter(self, assignment, method, route, body=None):
        import requests
        info = assignment.runtime_proxy_info
        parsed = urlsplit(info.url)
        host = parsed.hostname or ""
        # October 2026 Colab proxies moved to *.prod.r.colab.dev.
        # Bind that origin to the exact assignment ID before sending its token.
        assigned_prefix = "8080-" + identifier(assignment.endpoint) + "-"
        current_colab_proxy = (host.startswith(assigned_prefix)
                               and host.endswith(".prod.r.colab.dev"))
        if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.port not in (None, 443)
                or not (host.endswith(".googleusercontent.com")
                        or host == "colab.research.google.com"
                        or host.endswith(".colab.google")
                        or current_colab_proxy)):
            raise BootstrapError("RUNTIME_CONNECTION_ORIGIN_UNVERIFIED")
        url = info.url.rstrip("/") + route
        # Runtime credentials go only to the API-returned HTTPS origin. No
        # Google account bearer token is sent to the Jupyter proxy.
        headers = {"X-Colab-Runtime-Proxy-Token": info.token,
                   "X-Colab-Client-Agent": "colab-cli", "Accept": "application/json"}
        with requests.request(method, url, headers=headers, params={"authuser": "0"},
                              json=body, timeout=(10, 45), allow_redirects=False,
                              stream=True) as response:
            if response.status_code not in (200, 201, 204):
                raise BootstrapError("JUPYTER_HTTP_" + str(response.status_code))
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > 1048576:
                    raise BootstrapError("JUPYTER_RESPONSE_TOO_LARGE")
                chunks.append(chunk)
            return json.loads(b"".join(chunks)) if chunks else None

    def unassign(self, endpoint):
        self.client.unassign(endpoint)


def assignment_projection(assignment):
    variant, accelerator, shape = (enum_name(getattr(assignment, name))
                                   for name in ("variant", "accelerator", "machine_shape"))
    if variant not in ("DEFAULT", "GPU", "TPU") or shape not in ("STANDARD", "HIGH_RAM"):
        raise BootstrapError("ASSIGNMENT_SCHEMA_INVALID")
    if not re.fullmatch(r"[A-Z0-9_-]{1,32}", accelerator):
        raise BootstrapError("ASSIGNMENT_SCHEMA_INVALID")
    return {"endpoint": identifier(assignment.endpoint), "variant": variant,
            "accelerator": accelerator, "shape": shape}


def select_resource(inventory, kind, accelerator="auto", shape="standard"):
    wanted = {"variant": "DEFAULT" if kind == "cpu" else "GPU",
              "shape": "STANDARD" if shape == "standard" else "HIGH_RAM"}
    if accelerator != "auto":
        wanted["accelerator"] = accelerator
    elif kind == "cpu":
        wanted["accelerator"] = "NONE"
    if kind == "cpu" and wanted.get("accelerator") != "NONE":
        raise BootstrapError("CPU_ACCELERATOR_MUST_BE_NONE")
    rank = {"NONE": 0, "T4": 1, "L4": 2, "G4": 3, "A100": 4, "H100": 5}
    def matches(s):
        return s.get("accelerator") in VALID_ACCELERATORS and all(s.get(k) == v for k, v in wanted.items())
    existing = sorted((s for s in inventory["assignments"].get("runtimes", []) if matches(s)),
                      key=lambda s: (rank[s["accelerator"]], s["endpoint"]))
    if inventory["assignments"].get("status") != "available":
        raise BootstrapError("EXISTING_RUNTIME_INVENTORY_REQUIRED")
    if existing:
        return {"source": "existing_assignment", "endpoint": existing[0]["endpoint"],
                "spec": {k: existing[0][k] for k in ("variant", "accelerator", "shape")},
                "eligibility_evidence": "currently_assigned_to_verified_account"}
    if inventory["eligibility"].get("status") != "available":
        raise BootstrapError("ELIGIBILITY_API_UNAVAILABLE")
    eligible = sorted((s for s in inventory["eligibility"]["runtime_specs"]
                       if s.get("eligible") is True and matches(s)),
                      key=lambda s: rank[s["accelerator"]])
    if not eligible:
        raise BootstrapError("NO_ELIGIBLE_MATCHING_SPEC")
    return {"source": "eligible_new_runtime", "spec": {k: eligible[0][k]
            for k in ("variant", "accelerator", "shape")},
            "eligibility_evidence": "public_runtime_specs_eligible_true"}


def public_record(record):
    keys = ("key", "phase", "account_email", "notebook_hash", "endpoint", "requested_spec",
            "actual_spec", "owned_runtime", "owned_kernel", "kernel_id", "client_session_id",
            "server_session_id", "session_name", "profile_path", "profile_hash", "error_code",
            "created_at", "updated_at", "runtime_submit_attempts", "kernel_submit_attempts",
            "release_submit_attempts", "jobs_state_dir", "refusal_http_status", "refusal_source",
            "cleanup_reason", "never_dispatched", "cleanup_evidence",
            "jobs_ledger_initialized_before_kernel")
    return {key: record[key] for key in keys if key in record}


class Manager:
    def __init__(self, journal, backend):
        self.journal, self.backend = journal, backend

    def _record(self, key):
        record = self.journal.load(key)
        if record is None:
            raise BootstrapError("PROVISIONING_REQUEST_NOT_FOUND")
        if record["account_email"].casefold() != self.backend.account["account_email"].casefold():
            raise BootstrapError("AUTH_ACCOUNT_MISMATCH")
        return record


    def readiness(self):
        """Report validated allocation blockers without issuing a cloud mutation."""
        with self.journal.locked():
            records = self.journal.records()
            blockers = []
            for record in records:
                # All records must belong to this authenticated account,
                # including terminal history; never silently skip corruption.
                self._record(record["key"])
                if record.get("phase") in ("admitted", "allocation_unknown", "release_unknown"):
                    blockers.append({k: record[k] for k in ("key", "phase", "error_code")
                                     if k in record})
            return {"status": "blocked" if blockers else "ready", "authorized": True,
                    "can_create": not blockers, "job_profile_supported": True,
                    "record_count": len(records), "allocation_blockers": blockers}

    def _assignment(self, record):
        found = [a for a in self.backend.assignments() if a.endpoint == record.get("endpoint")]
        if len(found) != 1:
            raise BootstrapError("FIXED_RUNTIME_NOT_FOUND")
        actual = assignment_projection(found[0])
        actual.pop("endpoint")
        if actual != record["requested_spec"]:
            record["actual_spec"] = actual
            record["phase"] = "allocation_mismatch"
            record["error_code"] = "ALLOCATED_SPEC_MISMATCH"
            self.journal.save(record)
            raise BootstrapError("ALLOCATED_SPEC_MISMATCH")
        record["actual_spec"] = actual
        return found[0]

    def create(self, key, kind, accelerator="auto", shape="standard"):
        with self.journal.locked():
            existing = self.journal.load(key)
            intent = {"kind": kind, "accelerator": accelerator, "shape": shape}
            if existing:
                record = self._record(key)
                if record["intent"] != intent:
                    raise BootstrapError("REQUEST_KEY_INTENT_CONFLICT")
                # Repeating create is never another allocation or kernel POST.
                return self._reconcile(record)
            for previous in self.journal.records():
                if previous.get("phase") in ("admitted", "allocation_unknown", "release_unknown"):
                    raise BootstrapError("UNRESOLVED_ALLOCATION_BLOCKS_NEW_REQUEST")
            selection = select_resource(self.backend.inventory(), kind, accelerator, shape)
            record = {"schema": 1, "key": key, "intent": intent,
                "account_email": self.backend.account["account_email"],
                "notebook_hash": str(uuid.uuid4()), "client_session_id": str(uuid.uuid4()),
                "kernel_path": "hepta_" + uuid.uuid4().hex + ".ipynb",
                "session_name": "hepta-" + uuid.uuid4().hex,
                "requested_spec": selection["spec"], "selection": selection,
                "owned_runtime": False, "owned_kernel": False,
                "runtime_submit_attempts": 0, "kernel_submit_attempts": 0,
                "created_at": now(), "phase": "admitted"}
            self.journal.save(record)
            if selection["source"] == "existing_assignment":
                record["endpoint"] = selection["endpoint"]
                self._assignment(record)
                record["phase"] = "runtime_ready"
                self.journal.save(record)
                return public_record(record)
            record["runtime_submit_attempts"] = 1
            record["phase"] = "allocation_unknown"
            self.journal.save(record)  # fsync before the only allocation call
            try:
                allocated = self.backend.assign(record["notebook_hash"], record["requested_spec"])
                record["endpoint"] = identifier(allocated.endpoint)
                record["owned_runtime"] = True
                self.journal.save(record)  # retain ownership before inventory verification
                self._assignment(record)
                record["phase"] = "runtime_ready"
                record.pop("error_code", None)
            except AllocationRefused as exc:
                if record.get("endpoint") or record.get("owned_runtime"):
                    # Never downgrade already observed ownership to a refusal.
                    record["error_code"] = "ALLOCATION_UNCONFIRMED"
                else:
                    record.update(phase="allocation_refused", error_code=exc.code,
                                  refusal_http_status=412, refusal_source="official_sdk_http_412")
            except Exception:
                record["error_code"] = "ALLOCATION_UNCONFIRMED"
            self.journal.save(record)
            return public_record(record)

    def reconcile(self, key):
        with self.journal.locked():
            return self._reconcile(self._record(key))

    def _reconcile(self, record):
        if record["phase"] == "allocation_refused":
            # Same-key retries preserve the explicit refusal and never reassign.
            # Historical allocation_unknown records have no such evidence and
            # intentionally continue through the original read-only reconcile.
            return public_record(record)
        if record["phase"] in ("release_unknown", "released"):
            present = any(a.endpoint == record.get("endpoint") for a in self.backend.assignments())
            if not present:
                record["phase"] = "released"
                record.pop("error_code", None)
                self.journal.save(record)
            return public_record(record)
        if not record.get("endpoint") and record["runtime_submit_attempts"]:
            assigned = self.backend.reconcile_assignment(record["notebook_hash"], record["requested_spec"])
            if assigned is None:
                record["phase"] = "allocation_unknown"
                record["error_code"] = "ALLOCATION_NOT_OBSERVED_NO_RESUBMIT"
                self.journal.save(record)
                return public_record(record)
            record["endpoint"] = identifier(assigned.endpoint)
            record["owned_runtime"] = True
            self.journal.save(record)
        if not record.get("endpoint"):
            record["error_code"] = "ADMITTED_REQUEST_REQUIRES_MANUAL_REVIEW"
            self.journal.save(record)
            return public_record(record)
        assignment = self._assignment(record)
        if record["kernel_submit_attempts"] and not record.get("kernel_id"):
            self._observe_kernel(record, assignment)
        elif record.get("kernel_id"):
            self._observe_kernel(record, assignment)
        else:
            record["phase"] = "runtime_ready"
            record.pop("error_code", None)
        self.journal.save(record)
        return public_record(record)

    def _observe_kernel(self, record, assignment):
        sessions = self.backend.jupyter(assignment, "GET", "/api/sessions")
        if not isinstance(sessions, list):
            raise BootstrapError("JUPYTER_SESSIONS_SCHEMA_INVALID")
        matching = [s for s in sessions if isinstance(s, dict) and s.get("path") == record["kernel_path"]]
        if len(matching) > 1:
            raise BootstrapError("DEDICATED_SESSION_AMBIGUOUS")
        if not matching:
            record["phase"] = "kernel_unknown"
            record["error_code"] = "KERNEL_NOT_OBSERVED_NO_RESUBMIT"
            return False
        value = matching[0]
        kernel_id = identifier(value.get("kernel", {}).get("id"))
        server_session_id = identifier(value.get("id"))
        if kernel_id in record.get("baseline_kernel_ids", []):
            raise BootstrapError("EXISTING_USER_KERNEL_WOULD_BE_ADOPTED")
        if record.get("kernel_id") and (record["kernel_id"] != kernel_id
                or record["server_session_id"] != server_session_id):
            raise BootstrapError("DEDICATED_KERNEL_IDENTITY_CHANGED")
        if not record["kernel_submit_attempts"]:
            raise BootstrapError("KERNEL_OWNERSHIP_NOT_ADMITTED")
        record.update(kernel_id=kernel_id, server_session_id=server_session_id,
                      owned_kernel=True, phase="bound" if record.get("profile_hash") else "kernel_ready")
        record.pop("error_code", None)
        return True

    def bind(self, key, profile_path, name="rog-colab", jobs_state_dir=None):
        with self.journal.locked():
            record = self._record(key)
            if record["phase"] in ("release_unknown", "released"):
                raise BootstrapError("RUNTIME_RELEASED_OR_UNCERTAIN")
            # Reconcile only; unresolved runtime creates must never allocate here.
            self._reconcile(record)
            if record["phase"] not in ("runtime_ready", "kernel_ready", "bound"):
                return public_record(record)
            path = Path(profile_path)
            fd, _ = _open_status_parent(str(path))
            os.close(fd)
            jobs_root = Path(jobs_state_dir) if jobs_state_dir else self.journal.root / "jobs"
            if not jobs_root.is_absolute():
                raise BootstrapError("JOBS_STATE_DIRECTORY_MUST_BE_ABSOLUTE")
            probe = jobs_root / (".validate-" + uuid.uuid4().hex) if jobs_root.exists() else jobs_root
            fd, _ = _open_status_parent(str(probe))
            os.close(fd)
            if record.get("jobs_state_dir") and record["jobs_state_dir"] != str(jobs_root):
                raise BootstrapError("JOBS_STATE_DIRECTORY_CONFLICT")
            if record.get("profile_path") and record["profile_path"] != str(path):
                raise BootstrapError("PROFILE_PATH_CONFLICT")
            # Establish the fixed jobs ledger before a kernel can exist or a
            # usable profile is exposed. A missing ledger after a kernel was
            # attempted is evidence loss, never permission to create an empty one.
            with read_only_ledger(jobs_root) as existing_jobs:
                missing_ledger = existing_jobs is None
            if missing_ledger:
                if (record.get("kernel_submit_attempts") != 0
                        or any(record.get(k) for k in ("owned_kernel", "kernel_id",
                                                       "profile_path", "profile_hash"))):
                    raise BootstrapError("BIND_JOBS_LEDGER_EVIDENCE_MISSING")
                Ledger(jobs_root)
            if record.get("kernel_submit_attempts") == 0:
                record["jobs_ledger_initialized_before_kernel"] = True
            record["jobs_state_dir"] = str(jobs_root)
            self.journal.save(record)
            assignment = self._assignment(record)
            if not record["kernel_submit_attempts"]:
                for previous in self.journal.records():
                    if (previous["key"] != key and previous.get("endpoint") == record["endpoint"]
                            and previous.get("phase") == "kernel_unknown"):
                        raise BootstrapError("UNRESOLVED_KERNEL_BLOCKS_NEW_REQUEST")
                kernels = self.backend.jupyter(assignment, "GET", "/api/kernels")
                sessions = self.backend.jupyter(assignment, "GET", "/api/sessions")
                if not isinstance(kernels, list) or not isinstance(sessions, list):
                    raise BootstrapError("JUPYTER_INVENTORY_SCHEMA_INVALID")
                record["baseline_kernel_ids"] = [identifier(k.get("id")) for k in kernels]
                if any(s.get("path") == record["kernel_path"] for s in sessions):
                    raise BootstrapError("DEDICATED_SESSION_PATH_ALREADY_EXISTS")
                record["kernel_submit_attempts"] = 1
                record["phase"] = "kernel_unknown"
                self.journal.save(record)  # before the one new-kernel mutation
                try:
                    self.backend.jupyter(assignment, "POST", "/api/sessions", {
                        "path": record["kernel_path"], "name": record["session_name"],
                        "type": "notebook", "kernel": {"name": "python3"}})
                except Exception:
                    record["error_code"] = "KERNEL_CREATION_UNCONFIRMED"
                    self.journal.save(record)
                    return public_record(record)
            if not self._observe_kernel(record, assignment):
                self.journal.save(record)
                return public_record(record)
            self.journal.save(record)
            self.journal.save_session(record, assignment)
            profile = Profile(name=name, session_name=record["session_name"],
                state_file=str(self.journal.state_file), endpoint=record["endpoint"],
                kernel_id=record["kernel_id"], session_id=record["client_session_id"],
                expected_account_email=record["account_email"])
            private_write(path, asdict(profile), no_clobber=True)
            record.update(phase="bound", profile_path=str(path), profile_hash=profile.fingerprint)
            self.journal.save(record)
            return public_record(record)

    def release(self, key, jobs_state_dir):
        return self._release(key, jobs_state_dir)

    def close_unstarted(self, key):
        # Account wrappers always use this sibling jobs directory. An arbitrary
        # empty ledger must never substitute for the account's original scope.
        jobs_state_dir = self.journal.root.parent / "jobs"
        return self._release(key, jobs_state_dir, unstarted=True)

    def _release(self, key, jobs_state_dir, unstarted=False):
        with self.journal.locked():
            record = self._record(key)
            if not record["owned_runtime"] or record["runtime_submit_attempts"] != 1:
                raise BootstrapError("RELEASE_REQUIRES_TASK_OWNED_RUNTIME")
            jobs_path = str(Path(jobs_state_dir))
            never_bound = (record.get("phase") == "runtime_ready"
                           and record.get("kernel_submit_attempts") == 0
                           and not record.get("owned_kernel")
                           and not record.get("kernel_id")
                           and not record.get("profile_path")
                           and not record.get("profile_hash"))
            if record.get("jobs_state_dir"):
                if record["jobs_state_dir"] != jobs_path:
                    raise BootstrapError("RELEASE_REQUIRES_FIXED_JOBS_STATE_DIRECTORY")
            elif not (unstarted and never_bound):
                raise BootstrapError("RELEASE_REQUIRES_FIXED_JOBS_STATE_DIRECTORY")
            if record.get("release_submit_attempts"):
                if unstarted and (record.get("cleanup_reason") != "unstarted_compute"
                                  or record.get("never_dispatched") is not True):
                    raise BootstrapError("CLOSE_UNSTARTED_EVIDENCE_REQUIRED")
                return self._reconcile(record)
            if unstarted:
                if record.get("phase") not in ("runtime_ready", "kernel_ready", "bound"):
                    raise BootstrapError("CLOSE_UNSTARTED_REQUIRES_CONFIRMED_RUNTIME_AND_KERNEL")
                with read_only_ledger(jobs_state_dir) as original:
                    if original is None and not never_bound:
                        raise BootstrapError("CLOSE_UNSTARTED_LEDGER_EVIDENCE_MISSING")
            assignment = self._assignment(record)
            ledger = Ledger(jobs_state_dir)
            with ledger.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                marks = ",".join("?" for _ in ACTIVE)
                busy = db.execute(f"SELECT job_id FROM jobs WHERE endpoint=? AND state IN ({marks})",
                                  (record["endpoint"], *ACTIVE)).fetchone()
                if busy:
                    raise BootstrapError("RELEASE_BLOCKED_BY_ACTIVE_OR_UNKNOWN_JOB")
                cleanup_evidence = None
                if unstarted:
                    jobs = db.execute("""SELECT state,submit_attempts,dispatched_at,
                        worker_pid,worker_start_ticks,receipt_json,manifest_json
                        FROM jobs WHERE endpoint=?""", (record["endpoint"],)).fetchall()
                    # Only no job or a purely local pre-dispatch cancellation
                    # can support this cleanup path. Completed cloud jobs use
                    # the existing normal release after receipt/artifact checks.
                    if any(j["state"] != "cancelled" or j["submit_attempts"] != 0
                           or any(j[k] is not None for k in ("dispatched_at", "worker_pid",
                               "worker_start_ticks", "receipt_json", "manifest_json"))
                           for j in jobs):
                        raise BootstrapError("CLOSE_UNSTARTED_JOB_MAY_HAVE_DISPATCHED")
                    dispatch_event = db.execute("""SELECT 1 FROM events e JOIN jobs j
                        ON j.job_id=e.job_id WHERE j.endpoint=? AND
                        e.event IN ('dispatch_claimed','cloud_observed') LIMIT 1""",
                        (record["endpoint"],)).fetchone()
                    if dispatch_event:
                        raise BootstrapError("CLOSE_UNSTARTED_JOB_MAY_HAVE_DISPATCHED")
                    cleanup_evidence = {"jobs_state_dir": jobs_path,
                        "scope": "all_account_ledger_jobs_on_original_endpoint",
                        "matching_jobs": len(jobs), "locally_cancelled_jobs": len(jobs),
                        "submit_attempts": 0, "active_jobs": 0,
                        "dispatch_events": 0, "never_bound": never_bound,
                        "observed_at": now()}
                kernels = self.backend.jupyter(assignment, "GET", "/api/kernels")
                if not isinstance(kernels, list):
                    raise BootstrapError("JUPYTER_INVENTORY_SCHEMA_INVALID")
                # A baseline proves which kernels we must not adopt; it does
                # not prove ownership. Even an idle baseline kernel therefore
                # blocks deleting the whole runtime.
                allowed = {record.get("kernel_id")} if record.get("owned_kernel") else set()
                for kernel in kernels:
                    if kernel.get("id") not in allowed or kernel.get("execution_state") != "idle":
                        raise BootstrapError("RELEASE_BLOCKED_BY_FOREIGN_OR_BUSY_KERNEL")
                if unstarted:
                    # The SQLite write transaction remains held through the
                    # remote mutation, so no job can claim dispatch in between.
                    record.update(jobs_state_dir=jobs_path,
                                  cleanup_reason="unstarted_compute", never_dispatched=True,
                                  cleanup_evidence=cleanup_evidence)
                record["release_submit_attempts"] = 1
                record["phase"] = "release_unknown"
                self.journal.save(record)
                try:
                    self.backend.unassign(record["endpoint"])
                except Exception:
                    record["error_code"] = "RELEASE_UNCONFIRMED"
                    self.journal.save(record)
                    return public_record(record)
                return self._reconcile(record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--expected-email")
    parser.add_argument("--quota-project", help="Explicit Google Cloud project for public API quota")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("account")
    commands.add_parser("inventory")
    commands.add_parser("readiness")
    for verb in ("select", "create"):
        command = commands.add_parser(verb)
        if verb == "create":
            command.add_argument("--key", required=True)
        command.add_argument("--kind", choices=["cpu", "gpu"], default="cpu")
        command.add_argument("--accelerator", choices=["auto", *sorted(VALID_ACCELERATORS)], default="auto")
        command.add_argument("--shape", choices=["standard", "highmem"], default="standard")
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--key", required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("--key", required=True)
    bind.add_argument("--profile", required=True)
    bind.add_argument("--name", default="rog-colab")
    bind.add_argument("--jobs-state-dir")
    release = commands.add_parser("release")
    release.add_argument("--key", required=True)
    release.add_argument("--jobs-state-dir", required=True)
    close_unstarted = commands.add_parser("close-unstarted")
    close_unstarted.add_argument("--key", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    backend = None
    result, rc = None, 0
    # Even SDK print/debug/error paths cannot write URLs or tokens to the tool.
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        try:
            backend = (Backend(args.expected_email, quota_project=args.quota_project)
                       if args.quota_project else Backend(args.expected_email))
            if args.command == "account":
                result = backend.account
            elif args.command == "inventory":
                result = backend.inventory()
            elif args.command == "select":
                result = select_resource(backend.inventory(), args.kind, args.accelerator, args.shape)
            else:
                manager = Manager(Journal(args.state_dir), backend)
                if args.command == "readiness":
                    result = manager.readiness()
                elif args.command == "create":
                    result = manager.create(args.key, args.kind, args.accelerator, args.shape)
                elif args.command == "reconcile":
                    result = manager.reconcile(args.key)
                elif args.command == "bind":
                    result = manager.bind(args.key, args.profile, args.name, args.jobs_state_dir)
                elif args.command == "close-unstarted":
                    result = manager.close_unstarted(args.key)
                else:
                    result = manager.release(args.key, args.jobs_state_dir)
        except AuthFailure as exc:
            result, rc = {"status": "authorization_required", "error_code": exc.code}, 3
        except BootstrapError as exc:
            result, rc = {"status": "blocked", "error_code": exc.code}, 2
        except BaseException:
            result, rc = {"status": "blocked", "error_code": "BOOTSTRAP_OPERATION_FAILED"}, 2
        finally:
            if backend is not None:
                try:
                    backend.close()
                except Exception:
                    pass
    print(canonical(result).decode())
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
