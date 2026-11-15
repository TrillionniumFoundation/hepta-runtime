"""Draft read-only large job inventory observer (stdlib; never a cutover action).

Only a caller-validated jobs directory and audited token reader may be supplied.
No registry bytes, launch argv/env, output, token digest, or exception text enters
public results. A complete observation is not an admission freeze or permission
to signal/adopt/replay. PTY, stream and dispatch proofs remain separate and false.
"""
from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import http.client
import json
import math
import os
import pathlib
import queue
import re
import stat
import threading
import time

HOSTS = ("main", "pocket4", "rog", "mac", "x230", "ai395")
ENDPOINT = "http://127.0.0.1:8790/mcp"
MAX_RECORDS = 16384
HTTP_MAX_BYTES = 32 * 1024 * 1024
REGISTRY_MAX_BYTES = 1024 * 1024
MAX_BUDGET_SECONDS = 300.0
MAX_RPC_SECONDS = 30.0
ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
READ_TOOLS = frozenset({"host_list", "process_list", "process_status", "pty_list",
                       "pty_read", "stream_handoff_list", "stream_handoff_status"})
TERMINAL = frozenset({"succeeded", "completed", "exited", "failed", "cancelled", "timed_out", "killed", "stopped"})
STATES = TERMINAL | {"running", "unknown", "owner_unknown", "lost", "launch_unknown",
                    "finalizing", "completed_unknown", "activating", "active", "inactive", "idle"}
STAT_FIELDS = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
               "st_uid", "st_nlink", "st_mode")
DIRECTORY_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_mtime_ns", "st_ctime_ns")
PARENT_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode")
ERROR_CODES = frozenset({"RegistryUnavailable", "RegistryInvalid", "RegistryOverflow",
    "RegistryChanged", "CredentialAlias", "DeadlineExpired", "ReadFailure",
    "ProtocolInvalid", "HTTPOverflow", "SessionChanged", "IdentityMismatch",
    "InventoryOverflow", "DuplicateIdentity", "InFlightAtDeadline", "MembershipMismatch"})


class InventoryError(Exception):
    """Fixed public code only; never retain sensitive input or exception text."""
    def __init__(self, code):
        self.code = code if code in ERROR_CODES else "ReadFailure"
        super().__init__(self.code)


class RegistryError(InventoryError):
    def __init__(self, code, partial=None):
        super().__init__(code)
        self.partial = partial


class Deadline:
    def __init__(self, seconds, clock=time.monotonic):
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds):
            raise InventoryError("DeadlineExpired")
        if seconds > MAX_BUDGET_SECONDS:
            raise InventoryError("DeadlineExpired")
        self.clock = clock
        self.end = clock() + max(0.0, seconds)

    def remaining(self):
        return max(0.0, self.end - self.clock())

    def timeout(self, requested=MAX_RPC_SECONDS):
        if isinstance(requested, bool) or not isinstance(requested, (int, float)) or not math.isfinite(requested) or requested <= 0:
            raise InventoryError("DeadlineExpired")
        remaining = self.remaining()
        if remaining <= 0:
            raise InventoryError("DeadlineExpired")
        return min(remaining, requested, MAX_RPC_SECONDS)


def _identity(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise InventoryError("IdentityMismatch")
    return value


def _hosts(hosts):
    if not isinstance(hosts, (list, tuple)) or len(hosts) != len(HOSTS) or set(hosts) != set(HOSTS):
        raise InventoryError("IdentityMismatch")
    return tuple(hosts)


def _pin(info, fields=STAT_FIELDS):
    return tuple(getattr(info, field) for field in fields)


def _json(raw):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError("ProtocolInvalid")
            result[key] = value
        return result
    def constant(_value):
        raise InventoryError("ProtocolInvalid")
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise InventoryError("ProtocolInvalid")
        return result
    try:
        return json.loads(raw, object_pairs_hook=object_pairs, parse_constant=constant, parse_float=finite_float)
    except Exception:
        raise InventoryError("ProtocolInvalid") from None


def _open_parent(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or not path.name or ".." in path.parts or any(ord(c) < 32 for c in str(path)):
        raise InventoryError("RegistryInvalid")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def _private_directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise InventoryError("RegistryInvalid")


def _private_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)):
        raise InventoryError("RegistryInvalid")


def credential_inode(path):
    """Metadata only. Intended for the audited caller; never hash/read credentials."""
    parent = descriptor = None
    try:
        parent, name = _open_parent(path)
        before_parent = os.fstat(parent)
        _private_directory(before_parent)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=parent)
        before = os.fstat(descriptor)
        _private_file(before)
        if before.st_uid != os.getuid():
            raise InventoryError("RegistryInvalid")
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        after = os.fstat(descriptor)
        if (_pin(before) != _pin(after) or _pin(after) != _pin(linked)
                or _pin(before_parent, PARENT_FIELDS) != _pin(os.fstat(parent), PARENT_FIELDS)):
            raise InventoryError("RegistryChanged")
        return before.st_dev, before.st_ino
    except InventoryError:
        raise
    except Exception:
        raise InventoryError("RegistryUnavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


@dataclasses.dataclass(frozen=True)
class RegistrySnapshot:
    jobs: dict
    pins: dict
    directory_pin: tuple = ()
    parent_pin: tuple = ()
    fingerprint: str = ""
    complete: bool = False
    missing: bool = False


def _snapshot(jobs, pins, directory_pin=(), parent_pin=(), complete=False, missing=False):
    # Only public-safe membership and stat identity are hashed; no private bytes.
    public = [[identity, jobs[identity], list(pins[identity])] for identity in sorted(jobs)]
    fingerprint = hashlib.sha256(json.dumps(public, separators=(",", ":")).encode()).hexdigest() if complete else ""
    return RegistrySnapshot(dict(jobs), dict(pins), directory_pin, parent_pin, fingerprint, complete, missing)


def read_registry(directory, *, hosts=HOSTS, credential_identity=None, deadline=None):
    """Strict bounded <id>.json membership; partial errors contain safe IDs only."""
    hosts = _hosts(hosts)
    if credential_identity is not None and (not isinstance(credential_identity, tuple)
            or len(credential_identity) != 2 or any(type(v) is not int or v < 0 for v in credential_identity)):
        raise RegistryError("RegistryInvalid")
    jobs, pins = {}, {}
    parent = descriptor = child = None
    def partial():
        return _snapshot(jobs, pins)
    def check_deadline():
        if deadline is not None:
            deadline.timeout()
    try:
        check_deadline()
        parent, name = _open_parent(directory)
        parent_before = os.fstat(parent)
        _private_directory(parent_before)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=parent)
        except FileNotFoundError:
            return _snapshot(jobs, pins, missing=True)
        before_directory = os.fstat(descriptor)
        _private_directory(before_directory)
        names = sorted(os.listdir(descriptor))
        # Refuse the total count before any record bytes are read.
        if len(names) > MAX_RECORDS:
            raise RegistryError("RegistryOverflow", partial())
        for name in names:
            check_deadline()
            if not name.endswith(".json") or not ID.fullmatch(name[:-5]):
                raise RegistryError("RegistryInvalid", partial())
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                            dir_fd=descriptor)
            try:
                before = os.fstat(child)
                # An alias is rejected before read, even when bytes would be JSON.
                if credential_identity == (before.st_dev, before.st_ino):
                    raise RegistryError("CredentialAlias", partial())
                _private_file(before)
                if before.st_size > REGISTRY_MAX_BYTES:
                    raise RegistryError("RegistryOverflow", partial())
                raw = bytearray()
                while len(raw) <= REGISTRY_MAX_BYTES:
                    check_deadline()
                    chunk = os.read(child, min(65536, REGISTRY_MAX_BYTES + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                after = os.fstat(child)
                _private_file(after)
                linked = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _pin(before) != _pin(after) or _pin(after) != _pin(linked):
                    raise RegistryError("RegistryChanged", partial())
                if len(raw) != before.st_size or len(raw) > REGISTRY_MAX_BYTES:
                    raise RegistryError("RegistryChanged", partial())
                row = _json(raw)
                if not isinstance(row, dict):
                    raise RegistryError("RegistryInvalid", partial())
                identity, host = _identity(row.get("id")), _identity(row.get("host"))
                if name != identity + ".json" or host not in hosts or identity in jobs:
                    raise RegistryError("IdentityMismatch", partial())
                jobs[identity], pins[identity] = host, _pin(after)
                del raw, row
            finally:
                os.close(child)
                child = None
        after_directory = os.fstat(descriptor)
        linked_directory = os.stat(pathlib.Path(directory).name, dir_fd=parent, follow_symlinks=False)
        _private_directory(after_directory)
        _private_directory(os.fstat(parent))
        if (sorted(os.listdir(descriptor)) != names
                or _pin(before_directory, DIRECTORY_FIELDS) != _pin(after_directory, DIRECTORY_FIELDS)
                or _pin(after_directory, DIRECTORY_FIELDS) != _pin(linked_directory, DIRECTORY_FIELDS)
                or _pin(parent_before, PARENT_FIELDS) != _pin(os.fstat(parent), PARENT_FIELDS)):
            raise RegistryError("RegistryChanged", partial())
        return _snapshot(jobs, pins, _pin(after_directory, DIRECTORY_FIELDS),
                         _pin(parent_before, PARENT_FIELDS), complete=True)
    except RegistryError:
        raise
    except InventoryError as error:
        raise RegistryError(error.code, partial()) from None
    except Exception:
        raise RegistryError("RegistryUnavailable", partial()) from None
    finally:
        if child is not None:
            os.close(child)
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


class LoopbackReadClient:
    """One host's independent MCP session/sequence; fixed direct loopback only.

    The caller supplies an audited credential reader. HTTPConnection does not
    consult proxy variables, follow redirects, or accept endpoint configuration.
    Socket timeouts bound each blocking operation; remaining time is checked
    between operations/chunks. Python cannot forcibly kill an in-flight syscall.
    """
    endpoint = ENDPOINT

    def __init__(self, token_file, *, token_reader, host, deadline, rpc_timeout=10.0):
        if host not in HOSTS or not isinstance(deadline, Deadline):
            raise InventoryError("IdentityMismatch")
        deadline.timeout(rpc_timeout)
        self.host, self.deadline, self.rpc_timeout = host, deadline, rpc_timeout
        self._session, self._sequence, self._closed = None, 0, False
        self._lock = threading.Lock()
        self._token = token_reader(token_file)
        if (not isinstance(self._token, str) or not 0 < len(self._token) <= 256
                or any(ord(c) < 33 or ord(c) > 126 for c in self._token)):
            self._token = None
            raise InventoryError("ProtocolInvalid")
        try:
            self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                     "clientInfo": {"name": "hepta-readonly-large-inventory-draft", "version": "1"}})
            self.rpc("notifications/initialized", {}, notify=True)
        except BaseException:
            self.close()
            raise

    def _timeout(self, requested):
        return self.deadline.timeout(min(requested, self.rpc_timeout))

    def rpc(self, method, params, notify=False, *, timeout_seconds=None):
        if (method not in {"initialize", "notifications/initialized", "tools/list", "tools/call"}
                or not isinstance(params, dict) or type(notify) is not bool
                or notify != (method == "notifications/initialized")):
            raise InventoryError("ProtocolInvalid")
        if method == "tools/call":
            name, arguments = params.get("name"), params.get("arguments")
            if name not in READ_TOOLS or not isinstance(arguments, dict):
                raise InventoryError("ProtocolInvalid")
            if name in {"process_list", "process_status", "pty_list", "pty_read"} and arguments.get("host") != self.host:
                raise InventoryError("IdentityMismatch")
            if name == "process_status":
                _identity(arguments.get("job_id"))
        requested = self.rpc_timeout if timeout_seconds is None else timeout_seconds
        self._timeout(requested)
        # The observer uses exactly one worker per host. Also reject direct reentry.
        if not self._lock.acquire(blocking=False):
            raise InventoryError("ProtocolInvalid")
        conn = None
        try:
            if self._closed:
                raise InventoryError("ProtocolInvalid")
            rpc_end = min(self.deadline.end, self.deadline.clock() + self._timeout(requested))
            def remaining():
                timeout = rpc_end - self.deadline.clock()
                if timeout <= 0:
                    raise InventoryError("DeadlineExpired")
                return min(timeout, self.deadline.timeout(requested))
            self._sequence += 1
            request = {"jsonrpc": "2.0", "method": method, "params": params}
            if not notify:
                request["id"] = self._sequence
            body = json.dumps(request, separators=(",", ":"), allow_nan=False).encode()
            if len(body) > 65536:
                raise InventoryError("ProtocolInvalid")
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "X-Hepta-Runtime-Token": self._token, "MCP-Protocol-Version": "2025-06-18"}
            if self._session is not None:
                headers["Mcp-Session-Id"] = self._session
            conn = http.client.HTTPConnection("127.0.0.1", 8790, timeout=remaining())
            conn.request("POST", "/mcp", body=body, headers=headers)
            active_socket = conn.sock
            if active_socket is not None:
                active_socket.settimeout(remaining())
            response = conn.getresponse()
            if not 200 <= response.status < 300:
                raise InventoryError("ProtocolInvalid")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdigit() or int(length) > HTTP_MAX_BYTES):
                raise InventoryError("HTTPOverflow")
            raw = bytearray()
            while len(raw) <= HTTP_MAX_BYTES:
                # read1 bounds each read; read(n) could loop on trickling input.
                if active_socket is not None:
                    active_socket.settimeout(remaining())
                else:
                    remaining()
                chunk = response.read1(min(65536, HTTP_MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > HTTP_MAX_BYTES or (length is not None and len(raw) != int(length)):
                raise InventoryError("HTTPOverflow")
            session = response.getheader("Mcp-Session-Id")
            if session is not None:
                if not 0 < len(session) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in session):
                    raise InventoryError("ProtocolInvalid")
                if self._session is not None and self._session != session:
                    raise InventoryError("SessionChanged")
                self._session = session
            if self._session is None:
                raise InventoryError("ProtocolInvalid")
            if notify:
                if raw.strip():
                    raise InventoryError("ProtocolInvalid")
                return None
            content_type = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type == "application/json":
                rows = [_json(raw)]
            elif content_type == "text/event-stream":
                # Exactly one data line per event, as in the reviewed legacy client.
                # Multiline/opaque streams are rejected rather than guessed complete.
                rows = [_json(line[5:].strip()) for line in raw.decode("utf-8").splitlines()
                        if line.startswith("data:") and line[5:].strip()]
            else:
                raise InventoryError("ProtocolInvalid")
            matches = [row for row in rows if isinstance(row, dict) and row.get("jsonrpc") == "2.0"
                       and type(row.get("id")) is int and row["id"] == request["id"]]
            if len(matches) != 1 or "error" in matches[0] or not isinstance(matches[0].get("result"), dict):
                raise InventoryError("ProtocolInvalid")
            return matches[0]["result"]
        except InventoryError:
            raise
        except Exception:
            raise InventoryError("ReadFailure") from None
        finally:
            if conn is not None:
                conn.close()
            self._lock.release()

    def call(self, name, arguments, *, timeout_seconds=None):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments}, timeout_seconds=timeout_seconds)
        if result.get("isError") is not False and "isError" in result:
            raise InventoryError("ProtocolInvalid")
        content = result.get("content")
        if not isinstance(content, list) or not content or any(not isinstance(block, dict)
                or block.get("type") != "text" or not isinstance(block.get("text"), str) for block in content):
            raise InventoryError("ProtocolInvalid")
        value = _json("\n".join(block["text"] for block in content))
        if not isinstance(value, dict):
            raise InventoryError("ProtocolInvalid")
        structured = result.get("structuredContent")
        if structured is not None and not _typed_json_equal(structured, value):
            raise InventoryError("ProtocolInvalid")
        return value

    def close(self):
        # No DELETE, logout, token rewrite, signal, replay or adoption RPC.
        self._token, self._session, self._closed = None, None, True


def _unknown(identity, host):
    return {"id": identity, "host": host, "state": "unknown", "status_observed": False,
            "status_shape_complete": False, "status_authoritative": False,
            "launch_nonce_present": None, "supervisor_binding_verified": False, "backend": None}


def _typed_json_equal(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_typed_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(_typed_json_equal(a, b) for a, b in zip(left, right))
    return left == right


def _row_identity(row):
    if not isinstance(row, dict):
        raise InventoryError("IdentityMismatch")
    identity = _identity(row.get("id", row.get("job_id")))
    if "id" in row and "job_id" in row and row["id"] != row["job_id"]:
        raise InventoryError("IdentityMismatch")
    return identity


def _status(row, identity, host):
    item = _unknown(identity, host)
    # Reviewed native jobs.rs check_ref binds the requested host, and STATUS_CODE
    # returns matching job_id but omits host. Do not invent status/binding flags.
    if _row_identity(row) != identity or ("host" in row and row["host"] != host):
        raise InventoryError("IdentityMismatch")
    item["status_observed"] = True
    state = row.get("state")
    item["status_shape_complete"] = isinstance(state, str) and state in STATES
    item["state"] = state if item["status_shape_complete"] else "unknown"
    item["status_authoritative"] = row.get("status_authoritative") is True
    item["launch_nonce_present"] = row.get("launch_nonce_present") if type(row.get("launch_nonce_present")) is bool else None
    item["supervisor_binding_verified"] = row.get("supervisor_binding_verified") is True
    item["backend"] = row.get("backend") if row.get("backend") in {"systemd", "detached"} else None
    if type(row.get("pid")) is int and 0 < row["pid"] <= 2147483647:
        item["pid"] = row["pid"]
    return item


def sanitized_inventory(value):
    """Bounded public jobs-only report, for a later controlled preflight import.

    This deliberately does not certify PTYs, streams or dispatch. A future
    independently tested collector must compose those domains separately.
    """
    if not isinstance(value, dict) or not isinstance(value.get("jobs"), list):
        raise InventoryError("ProtocolInvalid")
    if len(value["jobs"]) > MAX_RECORDS:
        raise InventoryError("InventoryOverflow")
    hosts = value.get("hosts", [])
    if (not isinstance(hosts, list) or len(hosts) > len(HOSTS)
            or any(not isinstance(host, str) or host not in HOSTS for host in hosts)
            or len(set(hosts)) != len(hosts)):
        raise InventoryError("IdentityMismatch")
    jobs, seen = [], set()
    for row in value["jobs"]:
        identity = _row_identity(row)
        if identity in seen:
            raise InventoryError("DuplicateIdentity")
        seen.add(identity)
        host = row.get("host")
        if host not in HOSTS:
            raise InventoryError("IdentityMismatch")
        item = _status(row, identity, host)
        item["status_observed"] = row.get("status_observed") is True
        item["status_shape_complete"] &= row.get("status_shape_complete") is True
        jobs.append(item)
    jobs.sort(key=lambda row: row["id"])
    errors = value.get("errors", [])
    if not isinstance(errors, list) or len(errors) > 128 or any(not isinstance(row, dict) for row in errors):
        raise InventoryError("ProtocolInvalid")
    result = {"hosts": sorted(hosts), "jobs": jobs, "ptys": [], "streams": [],
              "errors": [{"scope": row.get("scope") if row.get("scope") in {*HOSTS, "global", "registry"} else "global",
                          "error_type": row.get("error_type") if row.get("error_type") in ERROR_CODES else "ReadFailure"}
                         for row in errors],
              "membership_complete": value.get("membership_complete") is True and set(hosts) == set(HOSTS),
              "status_observation_complete": value.get("status_observation_complete") is True
                  and all(row["status_observed"] and row["status_shape_complete"] for row in jobs),
              "status_authoritative_complete": value.get("status_authoritative_complete") is True
                  and all(row["status_authoritative"] for row in jobs),
              "bindings_complete": value.get("bindings_complete") is True
                  and all(row["launch_nonce_present"] is True and row["supervisor_binding_verified"] for row in jobs),
              "ptys_complete": False, "streams_complete": False,
              "dispatch": {"native_complete": False, "facade_complete": False, "admission_frozen": False},
              "endpoint": ENDPOINT, "origin": "read_only_metadata_observation", "decision": "HOLD"}
    result["status_authoritative_complete"] &= result["status_observation_complete"]
    result["bindings_complete"] &= result["status_observation_complete"]
    result["jobs_complete"] = value.get("jobs_complete") is True and all(result[field] for field in
        ("membership_complete", "status_observation_complete", "status_authoritative_complete", "bindings_complete"))
    pin = value.get("registry_pin")
    if isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin):
        result["registry_pin"] = pin
    result["holds"] = [code for field, code in (("membership_complete", "JOB_MEMBERSHIP_INCOMPLETE"),
        ("status_observation_complete", "JOB_STATUS_INCOMPLETE"),
        ("status_authoritative_complete", "JOB_STATUS_NOT_AUTHORITATIVE"),
        ("bindings_complete", "JOB_BINDING_UNKNOWN")) if not result[field]]
    if any(row["state"] not in TERMINAL for row in jobs):
        result["holds"].append("ACTIVE_OR_UNKNOWN_JOB_PRESERVATION_REQUIRED")
    result["holds"].extend(["PTY_INVENTORY_INCOMPLETE", "STREAM_INVENTORY_INCOMPLETE", "DISPATCH_UNKNOWN"])
    return result


def observe_inventory(jobs_directory, client_factory, *, credential_identity=None,
                      hosts=HOSTS, budget_seconds=120.0, rpc_timeout=10.0, clock=time.monotonic):
    """Six independent host workers, one RPC at a time per host; global cap six.

    client_factory(host, deadline) must construct an independent bounded read
    client. The injected fixture seam is not an endpoint/SSH configuration API.
    In-flight reads are reported unresolved at deadline; no new work is submitted
    after expiry. Only the reviewed HTTP client guarantees bounded socket reads.
    """
    hosts = _hosts(hosts)
    deadline = Deadline(budget_seconds, clock)
    deadline_requested = rpc_timeout
    if (isinstance(rpc_timeout, bool) or not isinstance(rpc_timeout, (int, float))
            or not math.isfinite(rpc_timeout) or not 0 < rpc_timeout <= MAX_RPC_SECONDS):
        raise InventoryError("DeadlineExpired")
    result = {"hosts": [], "jobs": [], "ptys": [], "streams": [], "errors": [],
              "membership_complete": False, "status_observation_complete": False,
              "status_authoritative_complete": False, "bindings_complete": False,
              "jobs_complete": False, "ptys_complete": False, "streams_complete": False,
              "dispatch": {"native_complete": False, "facade_complete": False, "admission_frozen": False},
              "endpoint": ENDPOINT, "origin": "read_only_metadata_observation", "decision": "HOLD"}
    errors, rows, listings = set(), {}, {}
    def error(scope, code):
        errors.add((scope, code if code in ERROR_CODES else "ReadFailure"))
    try:
        before = read_registry(jobs_directory, hosts=hosts, credential_identity=credential_identity, deadline=deadline)
    except RegistryError as exc:
        before = exc.partial or _snapshot({}, {})
        error("registry", exc.code)
    for identity, host in before.jobs.items():
        rows[identity] = _unknown(identity, host)
    if before.missing:
        error("registry", "RegistryUnavailable")
    events = queue.SimpleQueue()
    def host_worker(host):
        client = None
        try:
            deadline.timeout(deadline_requested)
            client = client_factory(host, deadline)
            if getattr(client, "host", host) != host:
                raise InventoryError("IdentityMismatch")
            page = client.call("process_list", {"host": host}, timeout_seconds=deadline.timeout(deadline_requested))
            if not isinstance(page, dict) or not isinstance(page.get("jobs"), list):
                raise InventoryError("ProtocolInvalid")
            if len(page["jobs"]) > MAX_RECORDS:
                raise InventoryError("InventoryOverflow")
            membership = {}
            for row in page["jobs"]:
                identity = _row_identity(row)
                if row.get("host") != host:
                    raise InventoryError("IdentityMismatch")
                if identity in membership:
                    raise InventoryError("DuplicateIdentity")
                membership[identity] = host
            # Explicit incomplete pagination is not repaired by set equality.
            if (("has_more" in page and page["has_more"] is not False)
                    or ("inventory_complete" in page and page["inventory_complete"] is not True)
                    or page.get("nextCursor") is not None or page.get("next_after_job_id") is not None):
                raise InventoryError("ProtocolInvalid")
            events.put(("listing", host, membership))
            del page
            # Independent authority bounds total submitted statuses to MAX_RECORDS,
            # before any launch-record ID can trigger a per-ID RPC. An unknown,
            # omitted, or cross-host ID blocks all statuses for that host.
            expected = {identity: authority for identity, authority in before.jobs.items() if authority == host}
            if membership != expected:
                raise InventoryError("MembershipMismatch")
            for identity in sorted(membership):
                try:
                    timeout = deadline.timeout(deadline_requested)
                    response = client.call("process_status", {"host": host, "job_id": identity}, timeout_seconds=timeout)
                    item = _status(response, identity, host)
                    del response
                    events.put(("status", host, item))
                except InventoryError as exc:
                    events.put(("error", host, exc.code))
                    if exc.code == "DeadlineExpired":
                        break
                except Exception:
                    events.put(("error", host, "ReadFailure"))
        except InventoryError as exc:
            events.put(("error", host, exc.code))
        except Exception:
            events.put(("error", host, "ReadFailure"))
        finally:
            if client is not None:
                try:
                    client.close()
                except Exception:
                    events.put(("error", host, "ReadFailure"))
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(HOSTS), thread_name_prefix="inventory-read")
    futures = {}
    # Never start HTTP when the independent registry authority was incomplete.
    if before.complete:
        for host in hosts:
            if deadline.remaining() <= 0:
                error(host, "DeadlineExpired")
                break
            futures[executor.submit(host_worker, host)] = host
    else:
        error("registry", "RegistryInvalid")
    if futures:
        _, pending = concurrent.futures.wait(futures, timeout=deadline.remaining())
        for future in pending:
            future.cancel()  # This cancels only not-yet-running work, never kills a read.
            error(futures[future], "InFlightAtDeadline")
    executor.shutdown(wait=False, cancel_futures=True)
    while True:
        try:
            kind, host, value = events.get_nowait()
        except queue.Empty:
            break
        if kind == "error":
            error(host, value)
        elif kind == "listing":
            listings[host] = value
            for identity in value:
                if identity in rows and rows[identity]["host"] != host:
                    error(host, "DuplicateIdentity")
                elif identity not in rows:
                    if len(rows) >= MAX_RECORDS:
                        error(host, "InventoryOverflow")
                    else:
                        rows[identity] = _unknown(identity, host)
        elif kind == "status":
            identity = value["id"]
            if identity in rows and rows[identity]["host"] == host:
                rows[identity] = value
            else:
                error(host, "IdentityMismatch")
    result["hosts"] = sorted(listings)
    observed = {}
    for host in sorted(listings):
        for identity in listings[host]:
            if identity in observed:
                error(host, "DuplicateIdentity")
            observed[identity] = host
    if len(observed) > MAX_RECORDS:
        error("global", "InventoryOverflow")
    try:
        after = read_registry(jobs_directory, hosts=hosts, credential_identity=credential_identity, deadline=deadline)
    except RegistryError as exc:
        after = exc.partial or _snapshot({}, {})
        error("registry", exc.code)
    stable = before.complete and after.complete and before == after
    if not stable:
        error("registry", "RegistryChanged")
    if observed != before.jobs:
        error("registry", "MembershipMismatch")
    membership = (stable and set(listings) == set(hosts) and observed == before.jobs
                  and len(observed) <= MAX_RECORDS
                  and not any(code in {"DuplicateIdentity", "InventoryOverflow", "IdentityMismatch"}
                              for _, code in errors))
    canonical_rows = [rows[identity] for identity in sorted(rows)]
    # Empty only proves status completeness when independent membership is complete.
    shape_complete = (before.complete and (bool(canonical_rows) or membership)
                      and all(row["status_observed"] and row["status_shape_complete"] for row in canonical_rows))
    authoritative = shape_complete and all(row["status_authoritative"] for row in canonical_rows)
    bindings = shape_complete and all(row["launch_nonce_present"] is True and row["supervisor_binding_verified"] for row in canonical_rows)
    result.update(jobs=canonical_rows, membership_complete=membership, status_observation_complete=shape_complete,
                  status_authoritative_complete=authoritative, bindings_complete=bindings,
                  jobs_complete=membership and shape_complete and authoritative and bindings)
    if stable:
        result["registry_pin"] = after.fingerprint
    result["errors"] = [{"scope": scope, "error_type": code} for scope, code in sorted(errors)]
    result["holds"] = [code for field, code in (("membership_complete", "JOB_MEMBERSHIP_INCOMPLETE"),
        ("status_observation_complete", "JOB_STATUS_INCOMPLETE"),
        ("status_authoritative_complete", "JOB_STATUS_NOT_AUTHORITATIVE"),
        ("bindings_complete", "JOB_BINDING_UNKNOWN")) if result[field] is not True]
    if any(row["state"] not in TERMINAL for row in canonical_rows):
        result["holds"].append("ACTIVE_OR_UNKNOWN_JOB_PRESERVATION_REQUIRED")
    result["holds"].extend(["PTY_INVENTORY_INCOMPLETE", "STREAM_INVENTORY_INCOMPLETE", "DISPATCH_UNKNOWN"])
    return result
