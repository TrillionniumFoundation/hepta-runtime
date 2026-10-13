#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only production cutover observations and an optional private rollback packet.

No service command, activation, cancellation, admission change, Refresh, arbitrary
endpoint, or candidate execution is available. All validation precedes publication.
A successful preflight remains HOLD: live inventories are not an admission freeze.
"""
import argparse
import copy
import datetime
import hashlib
import http.client
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import sys

import stage_dc_successor as S

UNITS = ("hepta-runtime-operator.service", "hepta-openai-full-operator.service",
         "desktop-commander-remote.service")
HOSTS = ("main", "pocket4", "rog", "mac", "x230", "ai395")
ENDPOINT = "http://127.0.0.1:8790/mcp"
MAX_RESPONSE = 4 * 1024 * 1024
MAX_ROWS = 4096
MAX_PAGES = 64
ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}")
TERMINAL = {"succeeded", "failed", "cancelled", "timed_out", "exited", "completed"}
READ_TOOLS = {"host_list", "process_list", "process_status", "pty_list", "pty_read",
              "stream_handoff_list", "stream_handoff_status"}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_json(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def blocked(items, code, scope, reason):
    row = {"code": code, "scope": scope, "reason": reason}
    if row not in items:
        items.append(row)


def private_directory(path):
    path = S.absolute_path(path)
    parent, name = S.open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError("private directory identity refused")
    finally:
        os.close(fd)
    return path


def absent(path):
    path = S.absolute_path(path)
    parent, name = S.open_parent(path)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return path
        raise FileExistsError("create-only destination already exists")
    finally:
        os.close(parent)


def validate_stage(args):
    path = S.absolute_path(args.stage_manifest)
    folder = private_directory(path.parent)
    raw, metadata = S.read_pinned(path, args.stage_manifest_sha256, "stage manifest")
    if metadata["source_mode"] != "0600":
        raise PermissionError("private immutable manifest mode required")
    value = json.loads(raw)
    if (value.get("schema") != "hepta-dc-successor-stage-v1" or value.get("staged") is not True
            or value.get("activated") is not False or value.get("plan_status") != "HOLD"):
        raise ValueError("actual unactivated stage-only manifest required")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 128:
        raise ValueError("bounded staged artifact map required")
    material = {}
    for name, pin in artifacts.items():
        if not S.NAME.fullmatch(name) or set(pin) != {"bytes", "sha256", "mode"}:
            raise ValueError("invalid staged artifact reference")
        data, observed = S.read_pinned(folder / name, pin["sha256"], "stage artifact",
                                      S.MAX_NATIVE_BYTES if name.endswith("native") else S.MAX_RECEIPT_BYTES)
        if observed["bytes"] != pin["bytes"] or observed["source_mode"] != pin["mode"]:
            raise ValueError("stage artifact byte count or private mode changed")
        if pin["mode"] != ("0700" if name in ("candidate-native", "rollback-native") else "0600"):
            raise PermissionError("unexpected stage artifact mode")
        material[name] = data
    needed = {"candidate-native", "contract.json", "rollback-native", "rollback-contract.json",
              "chatgpt_full_operator.py", "mcp_tool_contract.py", "candidate-commands.json",
              "activation-plan.json", "rollback-plan.json", "native-dropin.conf"}
    if not needed <= set(material):
        raise ValueError("stage is missing concrete candidate or rollback artifacts")
    if set(p.name for p in folder.iterdir()) != set(artifacts) | {path.name}:
        raise ValueError("unexpected files in immutable stage")
    current = S.contract_from(material["contract.json"])
    original_raw, _ = S.read_pinned(S.ORIGINAL_V4, S.ORIGINAL_V4_SHA256, "original contract")
    original = S.contract_from(original_raw)
    S.require_original(current, original)
    S.require_original(S.contract_from(material["rollback-contract.json"]), original)
    if (current.catalog_sha256 != value["catalog"]["catalog_sha256"]
            or len(current.tools) != value["catalog"]["tool_count"]):
        raise ValueError("staged catalog metadata differs from exact definitions")
    for role, filename in {"native": "candidate-native", "facade": "chatgpt_full_operator.py",
                            "helper": "mcp_tool_contract.py", "contract": "contract.json",
                            "previous_contract": "previous-contract.json"}.items():
        pin = value["inputs"][role]
        if digest(material[filename]) != pin["sha256"] or len(material[filename]) != pin["bytes"]:
            raise ValueError("staged candidate differs from original input pin")
    for role, filename in {"native": "rollback-native", "facade": "rollback-facade.py",
                            "helper": "rollback-helper.py", "contract": "rollback-contract.json"}.items():
        pin = value["baseline"]["artifacts"][role]
        if digest(material[filename]) != pin["sha256"] or len(material[filename]) != pin["bytes"]:
            raise ValueError("rollback artifact differs from installed baseline pin")
    source = S.source_identity(args.source_root)
    if source != value["source"] or source["dirty_source"]:
        raise ValueError("current committed source differs from staged complete compile inputs")
    if source["source_code_fingerprint"] != value["compiled_source_fingerprint_supplied"]:
        raise ValueError("stage compiled-source pin differs")
    return value, material, {"path": str(path), "sha256": metadata["sha256"],
                            "source": source, "artifacts_verified": len(artifacts)}


def service_observation(token_path=None):
    """Only systemctl show. Raw ExecStart stays in memory, never in a receipt."""
    units = {}
    properties = "ActiveState,SubState,MainPID,InvocationID,ExecMainStartTimestampMonotonic,FragmentPath,DropInPaths,ExecStart"
    for unit in UNITS:
        result = subprocess.run(["systemctl", "--user", "show", unit, "--no-pager",
                                 "--property=" + properties], capture_output=True, text=True, timeout=15)
        if result.returncode or len(result.stdout) > 65536:
            raise ValueError("protected unit observation unavailable")
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        safe = {key: fields.get(key, "") for key in
                ("ActiveState", "SubState", "MainPID", "InvocationID", "ExecMainStartTimestampMonotonic")}
        safe["exec_start_sha256"] = digest(fields.get("ExecStart", "").encode())
        fragment = S.absolute_path(fields.get("FragmentPath", ""))
        if token_path is not None:
            refuse_token_source(fragment, token_path)
        _, info = S.snapshot(fragment, "installed unit fragment")
        safe["fragment"] = {"path": str(fragment), "sha256": info["sha256"]}
        safe["dropins"] = []
        for item in shlex.split(fields.get("DropInPaths", "")):
            path = S.absolute_path(item)
            if token_path is not None:
                refuse_token_source(path, token_path)
            _, info = S.snapshot(path, "installed unit drop-in")
            safe["dropins"].append({"path": str(path), "sha256": info["sha256"]})
        units[unit] = safe
    return {"units": units}


def process_observation(pid):
    """Main controller is Linux. Do not apply /proc semantics to six SSH targets."""
    def identity():
        raw = pathlib.Path("/proc", str(pid), "stat").read_text()
        ticks = int(raw.rsplit(") ", 1)[1].split()[19])
        return {"pid": pid, "uid": pathlib.Path("/proc", str(pid)).stat().st_uid, "start_ticks": ticks}
    before = identity()
    fd = os.open("/proc/" + str(pid) + "/exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > S.MAX_NATIVE_BYTES:
            raise ValueError("pinned installed executable is not a bounded ordinary file")
        h = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
        after = os.fstat(fd)
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or identity() != before:
            raise ValueError("installed executable or process identity changed during read")
        return {**before, "exe_sha256": h.hexdigest()}
    finally:
        os.close(fd)


def read_private_token(path):
    """Read one private credential without producing a digest or metadata record."""
    parent, name = S.open_parent(path)
    try:
        parent_before = os.fstat(parent)
        if (not stat.S_ISDIR(parent_before.st_mode) or parent_before.st_uid != os.getuid()
                or stat.S_IMODE(parent_before.st_mode) != 0o700):
            raise PermissionError("HTTP token parent requires owner-only 0700")

        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=parent)
        try:
            def validate(info):
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("HTTP token requires a single-link ordinary file")
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
                    raise PermissionError("HTTP token requires current owner and mode 0400 or 0600")

            before = os.fstat(descriptor)
            validate(before)
            if before.st_size > 512:
                raise ValueError("HTTP token exceeds bounded descriptor read")
            raw = bytearray()
            while len(raw) <= 512:
                chunk = os.read(descriptor, 513 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(descriptor)
            validate(after)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                      "st_uid", "st_nlink", "st_mode")
            if (any(getattr(before, field) != getattr(after, field) for field in fields)
                    or any(getattr(after, field) != getattr(linked, field) for field in fields)):
                raise ValueError("HTTP token changed during descriptor read")
            parent_after = os.fstat(parent)
            parent_fields = ("st_dev", "st_ino", "st_uid", "st_mode")
            if any(getattr(parent_before, field) != getattr(parent_after, field)
                   for field in parent_fields):
                raise ValueError("HTTP token parent changed during descriptor read")
            if len(raw) != before.st_size or len(raw) > 512:
                raise ValueError("HTTP token descriptor read was incomplete or oversized")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)
    # Credentials stay in memory for the loopback request; no snapshot, digest,
    # returned metadata, publication, or token-file mutation is permitted here.
    value = raw.decode("ascii").strip()
    if not value or len(value) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("private authentication format refused")
    return value


class LoopbackReadClient:
    """Direct HTTPConnection: proxy variables and redirects have no authority."""
    endpoint = ENDPOINT

    def __init__(self, token_file):
        self._token = read_private_token(token_file)
        self._session = None
        self._sequence = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "hepta-readonly-preflight", "version": "1"}})
        self.rpc("notifications/initialized", {}, notify=True)

    def rpc(self, method, params, notify=False):
        if method not in {"initialize", "notifications/initialized", "tools/list", "tools/call"}:
            raise ValueError("read-only RPC method refused")
        if method == "tools/call" and params.get("name") not in READ_TOOLS:
            raise ValueError("mutating tool refused")
        self._sequence += 1
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notify:
            request["id"] = self._sequence
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "X-Hepta-Runtime-Token": self._token, "MCP-Protocol-Version": "2025-06-18"}
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        conn = http.client.HTTPConnection("127.0.0.1", 8790, timeout=30)
        try:
            conn.request("POST", "/mcp", body=json.dumps(request).encode(), headers=headers)
            response = conn.getresponse()
            raw = response.read(MAX_RESPONSE + 1)
            if not 200 <= response.status < 300 or len(raw) > MAX_RESPONSE:
                raise ValueError("bounded loopback observation unavailable")
            session = response.getheader("Mcp-Session-Id")
            if session:
                if not 0 < len(session) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in session):
                    raise ValueError("native session identity malformed")
                if self._session and self._session != session:
                    raise ValueError("native session identity changed")
                self._session = session
            if notify:
                return None
            text = raw.decode("utf-8")
            rows = [json.loads(line[5:].strip()) for line in text.splitlines()
                    if line.startswith("data:") and line[5:].strip()]
            if not rows:
                rows = [json.loads(text)]
            rows = [row for row in rows if row.get("jsonrpc") == "2.0" and row.get("id") == request["id"]]
            if len(rows) != 1 or "error" in rows[0] or "result" not in rows[0]:
                raise ValueError("native read response identity unavailable")
            return rows[0]["result"]
        finally:
            conn.close()

    def call(self, name, arguments):
        result = self.rpc("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise ValueError("read-only inventory tool refused")
        text = "\n".join(block.get("text", "") for block in result.get("content", [])
                         if block.get("type") == "text")
        return json.loads(text)

    def close(self):
        # Never log/session DELETE/replay. Only discard local credential references.
        self._token = None
        self._session = None


def safe_identity(value, label):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(label + " malformed")
    return value


def registry_observation(manifest):
    """Independent bounded local durable references; no command/env/output content."""
    root = S.absolute_path(manifest["baseline"]["state_directory"])
    result = {"jobs": {}, "streams": [], "pins": {}, "missing_directories": []}
    for kind in ("jobs", "stream_handoffs"):
        base = root / kind
        if not base.exists():
            result["missing_directories"].append(kind)
            continue
        parent, name = S.open_parent(base)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            info = os.fstat(fd)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise PermissionError("durable registry directory owner/mode refused")
            names = sorted(os.listdir(fd))
            if len(names) > MAX_ROWS:
                raise ValueError("durable registry exceeds bounded observation")
            for name in names:
                if kind == "jobs" and name.endswith(".json"):
                    raw, pin = S.snapshot(base / name, "durable job metadata")
                    row = json.loads(raw)
                    identity = safe_identity(row["id"], "durable job")
                    host = safe_identity(row["host"], "durable host")
                    if name != identity + ".json" or host not in HOSTS:
                        raise ValueError("durable job logical authority differs")
                    result["jobs"][identity] = host
                    result["pins"][identity] = pin["sha256"]
                elif kind == "stream_handoffs" and re.fullmatch(r"stream-[0-9a-f]{64}", name):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        child_info = os.fstat(child)
                        if child_info.st_uid not in (0, os.getuid()) or child_info.st_mode & 0o022:
                            raise PermissionError("stream durable directory refused")
                    finally:
                        os.close(child)
                    result["streams"].append(name)
            if sorted(os.listdir(fd)) != names:
                raise ValueError("durable registry membership changed during observation")
        finally:
            os.close(fd)
    return result


def sanitized_inventory(value):
    """Only bounded identity/state fields can cross from an RPC into a report."""
    states = TERMINAL | {"running", "unknown", "owner_unknown", "lost", "launch_unknown",
                         "finalizing", "completed_unknown", "activating", "active", "inactive", "idle"}
    result = {"hosts": [], "jobs": [], "ptys": [], "streams": [], "errors": [],
              "jobs_complete": value.get("jobs_complete") is True,
              "ptys_complete": value.get("ptys_complete") is True,
              "streams_complete": value.get("streams_complete") is True,
              "dispatch": {key: value.get("dispatch", {}).get(key) is True for key in
                           ("native_complete", "facade_complete", "admission_frozen")},
              "endpoint": ENDPOINT, "origin": "read_only_metadata_observation"}
    result["hosts"] = sorted(safe_identity(host, "inventory host") for host in value.get("hosts", []))
    for kind, identity_key in (("jobs", "id"), ("ptys", "session_id"), ("streams", "session_id")):
        rows = value.get(kind, [])
        if not isinstance(rows, list) or len(rows) > MAX_ROWS:
            raise ValueError("inventory row count exceeds bounded metadata report")
        for row in rows:
            item = {identity_key: safe_identity(row[identity_key], kind),
                    "state": row.get("state") if row.get("state") in states else "unknown"}
            if kind != "streams":
                host = safe_identity(row["host"], "inventory authority")
                if host not in HOSTS:
                    raise ValueError("unexpected configured authority")
                item["host"] = host
            if kind == "jobs":
                item["launch_nonce_present"] = row.get("launch_nonce_present") if isinstance(row.get("launch_nonce_present"), bool) else None
                item["supervisor_binding_verified"] = row.get("supervisor_binding_verified") is True
                item["status_authoritative"] = row.get("status_authoritative") is True
                item["backend"] = row.get("backend") if row.get("backend") in {"systemd", "detached"} else None
            elif kind == "ptys":
                item["persistent_across_runtime_restart"] = row.get("persistent_across_runtime_restart") is True
            if isinstance(row.get("pid"), int) and not isinstance(row["pid"], bool) and 0 < row["pid"] <= 2147483647:
                item["pid"] = row["pid"]
            result[kind].append(item)
    for error in value.get("errors", [])[:128]:
        result["errors"].append({"scope": error.get("scope") if error.get("scope") in {*HOSTS, "global", "stream", "registry"} else "global",
                                 "error_type": error.get("error_type") if re.fullmatch(r"[A-Za-z_]{1,80}", str(error.get("error_type", ""))) else "ObservationError"})
    if isinstance(value.get("registry_pin"), str) and S.HASH.fullmatch(value["registry_pin"]):
        result["registry_pin"] = value["registry_pin"]
    return result


def inventory_observation(manifest):
    client = None
    result = {"hosts": [], "jobs": [], "ptys": [], "streams": [], "errors": [],
              "jobs_complete": False, "ptys_complete": False, "streams_complete": False,
              "dispatch": {"native_complete": False, "facade_complete": False, "admission_frozen": False},
              "origin": "fixed_loopback_read_tools", "endpoint": ENDPOINT,
              "dispatch_observation": "Installed native/facade expose no active-dispatch or freeze/drain inventory API"}
    try:
        client = LoopbackReadClient(manifest["baseline"]["auth_token_file"])
        registry_before = registry_observation(manifest)
        catalog = client.rpc("tools/list", {})
        if catalog.get("nextCursor"):
            raise ValueError("native catalog is incomplete")
        names = {row["name"] for row in catalog["tools"]}
        expected = json.loads(S.snapshot(manifest["baseline"]["artifacts"]["contract"]["path"], "installed contract")[0])
        if {row["name"]: row for row in catalog["tools"]} != {row["name"]: row for row in expected["tools"]}:
            raise ValueError("installed native exact catalog differs from baseline")
        hosts = client.call("host_list", {})["hosts"]
        result["hosts"] = sorted(safe_identity(row["name"], "host") for row in hosts)
        if set(result["hosts"]) != set(HOSTS):
            raise ValueError("configured six-host logical authority differs")
        complete_jobs = True
        job_listing_hosts = set()
        complete_ptys = True
        for host in HOSTS:
            try:
                page = client.call("process_list", {"host": host})
                rows = page.get("jobs", [])
                if not isinstance(rows, list) or len(rows) > MAX_ROWS:
                    raise ValueError("job inventory exceeds bounded observation")
                job_listing_hosts.add(host)
                # Count is observed, never a historical acceptance criterion.
                complete_jobs &= page.get("inventory_complete") is True and page.get("has_more", False) is False
                for row in rows:
                    jid = safe_identity(row.get("id", row.get("job_id")), "job")
                    if row.get("host", host) != host:
                        raise ValueError("job authority differs from requested configured host")
                    status = row if isinstance(row.get("state"), str) else client.call("process_status", {"host": host, "job_id": jid})
                    result["jobs"].append({"host": host, "id": jid, "state": status.get("state", "unknown"),
                        "launch_nonce_present": None, "supervisor_binding_verified": False,
                        "status_authoritative": status.get("status_authoritative", False),
                        "backend": status.get("backend") if status.get("backend") in {"systemd", "detached"} else None,
                        "pid": status.get("pid") if isinstance(status.get("pid"), int) else None})
                cursor = None
                seen = {}
                for _ in range(MAX_PAGES):
                    args = {"host": host, "limit": 128}
                    if cursor:
                        args["after_session_id"] = cursor
                    page = client.call("pty_list", args)
                    rows = page.get("sessions", [])
                    if not isinstance(rows, list) or len(rows) > 384:
                        raise ValueError("PTY page exceeds bounded observation")
                    for row in rows:
                        sid = safe_identity(row["session_id"], "PTY")
                        if row.get("host") != host:
                            raise ValueError("PTY logical authority differs")
                        persistent = row.get("persistent_across_runtime_restart") is True
                        status = row.get("status") or {}
                        if persistent and status.get("state") == "inspect_with_pty_read":
                            observed = client.call("pty_read", {"host": host, "session_id": sid, "offset": 0, "limit": 1})
                            status = observed.get("status", {})
                        item = {"host": host, "session_id": sid, "state": status.get("state", "unknown"),
                                "persistent_across_runtime_restart": persistent,
                                "pid": status.get("pid", row.get("pid"))}
                        if sid in seen and seen[sid] != item:
                            raise ValueError("PTY changed across pages")
                        seen[sid] = item
                    if page.get("has_more") is False:
                        break
                    next_cursor = page.get("next_after_session_id")
                    if not isinstance(next_cursor, str) or next_cursor == cursor:
                        complete_ptys = False
                        break
                    cursor = next_cursor
                else:
                    complete_ptys = False
                result["ptys"].extend(seen.values())
            except Exception as error:
                complete_jobs = False
                complete_ptys = False
                result["errors"].append({"scope": host, "error_type": type(error).__name__})
        registry_after = registry_observation(manifest)
        observed_job_ids = {row["id"]: row["host"] for row in result["jobs"]}
        # Actual v4 process_list has no complete flag. Independent complete
        # durable membership equality supplies an observational proof, not a freeze.
        registry_stable = registry_after == registry_before
        missing = set(registry_before["missing_directories"]) | set(registry_after["missing_directories"])
        result["jobs_complete"] = (registry_stable and "jobs" not in missing
                                   and job_listing_hosts == set(HOSTS)
                                   and observed_job_ids == registry_before["jobs"])
        result["registry_pin"] = digest(raw_json(registry_after))
        if missing:
            result["errors"].append({"scope": "registry", "error_type": "MissingDirectory"})
        if not registry_stable:
            result["errors"].append({"scope": "registry", "error_type": "MembershipChanged"})
        result["ptys_complete"] = complete_ptys
        if "stream_handoff_list" in names:
            try:
                page = client.call("stream_handoff_list", {"limit": 128})
                rows = page.get("sessions", [])
                if not isinstance(rows, list) or len(rows) > 128:
                    raise ValueError("stream inventory exceeds bounded observation")
                # API has no paging/fullness guarantee. Saturation can never imply completeness.
                result["streams_complete"] = (registry_stable and "stream_handoffs" not in missing
                                              and {row.get("session_id") for row in rows} == set(registry_before["streams"]))
                for row in rows:
                    sid = safe_identity(row["session_id"], "stream")
                    status = client.call("stream_handoff_status", {"session_id": sid})
                    result["streams"].append({"session_id": sid, "state": status.get("state", "unknown")})
            except Exception as error:
                result["errors"].append({"scope": "stream", "error_type": type(error).__name__})
    except Exception as error:
        result["errors"].append({"scope": "global", "error_type": type(error).__name__})
    finally:
        if client is not None:
            client.close()
    return result


def inventory_holds(value):
    reasons = []
    if set(value.get("hosts", [])) != set(HOSTS):
        blocked(reasons, "SIX_HOST_AUTHORITY_INCOMPLETE", "inventory", "All six configured logical authorities were not observed")
    for key, code in (("jobs_complete", "JOB_INVENTORY_INCOMPLETE"), ("ptys_complete", "PTY_INVENTORY_INCOMPLETE"),
                      ("streams_complete", "STREAM_INVENTORY_INCOMPLETE")):
        if value.get(key) is not True:
            blocked(reasons, code, "inventory", "API observation has no complete bounded inventory proof")
    for row in value.get("jobs", []):
        if row.get("state") not in TERMINAL:
            if row.get("launch_nonce_present") is not True or row.get("supervisor_binding_verified") is not True:
                blocked(reasons, "JOB_BINDING_UNKNOWN", row.get("host", "unknown"),
                        "Active/unknown same-ID job has no verified nonce/supervisor binding; never adopt, cancel or replay")
            blocked(reasons, "ACTIVE_JOB_PRESERVATION_REQUIRED", row.get("host", "unknown"),
                    "Retain this same job/archive identity through freeze, cutover, recovery and rollback")
    for row in value.get("ptys", []):
        if row.get("state") not in TERMINAL:
            if row.get("persistent_across_runtime_restart") is not True:
                blocked(reasons, "ACTIVE_NONPERSISTENT_PTY", row.get("host", "unknown"),
                        "Live controller-owned PTY is not restart-preserved; do not close or replace it automatically")
            else:
                blocked(reasons, "ACTIVE_PERSISTENT_PTY_PRESERVATION_REQUIRED", row.get("host", "unknown"),
                        "Retain same session/PID/archive and input deduplication identity")
    if any(row.get("state") not in TERMINAL for row in value.get("streams", [])):
        blocked(reasons, "ACTIVE_OR_UNKNOWN_STREAM", "main", "Same-ID stream handoff must be reconciled without new attach or replay")
    dispatch = value.get("dispatch", {})
    if dispatch.get("native_complete") is not True or dispatch.get("facade_complete") is not True:
        blocked(reasons, "DISPATCH_INVENTORY_UNAVAILABLE", "native/facade", "No authoritative current in-flight and queued-dispatch inventory is exposed")
    if dispatch.get("admission_frozen") is not True:
        blocked(reasons, "ADMISSION_NOT_FROZEN", "native/facade", "Observing does not freeze admissions or drain in-flight requests; fresh inventory after an authorized freeze is required")
    if value.get("errors"):
        blocked(reasons, "INVENTORY_OBSERVATION_ERROR", "inventory", "A read-only observation failed; error types only are retained")
    return reasons


def receipt_summaries(manifest):
    summaries = []
    holds = []
    source = manifest["source"]
    binary = manifest["inputs"]["native"]["sha256"]
    contract = manifest["inputs"]["contract"]["sha256"]
    ci_seen = False
    rollback_seen = False
    for reference in manifest["receipts"]:
        raw, observed = S.read_pinned(reference["path"], reference["sha256"], "qualification receipt", S.MAX_RECEIPT_BYTES)
        if observed["bytes"] != reference["bytes"] or observed["source_mode"] != reference["source_mode"]:
            raise ValueError("pinned receipt metadata changed")
        value = json.loads(raw)
        summary = {"name": reference["name"], "sha256": observed["sha256"],
                   "bytes": observed["bytes"], "recognized": False, "bindings_valid": False}
        if isinstance(value, dict):
            proof_source = value.get("source_before", value.get("source", {}))
            bound_source = isinstance(proof_source, dict) and (
                proof_source.get("base_HEAD") == source["base_HEAD"] and
                proof_source.get("source_code_fingerprint") == source["source_code_fingerprint"])
            native = value.get("candidate_binary_sha256", value.get("binary_sha256", value.get("native_sha256")))
            definition = value.get("candidate_contract_sha256", value.get("reviewed_contract_file_sha256", value.get("contract_sha256")))
            summary["bindings_valid"] = bound_source and native == binary and definition == contract
            if value.get("complete_six_configured_target_cohort") is True:
                summary["recognized"] = True
                summary["complete"] = value.get("complete") is True and set(value.get("selected_hosts", [])) == set(HOSTS)
                rollback_seen |= summary["bindings_valid"] and summary["complete"] and value.get("sealed_inputs_stable") is True
            url = value.get("url", "")
            if isinstance(url, str) and re.fullmatch(r"https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/[0-9]+", url):
                summary["recognized"] = True
                summary["github_run_url"] = url
                summary["ci_declared_completed_success"] = (
                    value.get("headSha", value.get("head_sha")) == source["base_HEAD"] and
                    value.get("status") == "completed" and value.get("conclusion") == "success")
                ci_seen |= summary["ci_declared_completed_success"]
            if "complete" in value:
                summary["complete"] = value["complete"] is True
        summaries.append(summary)
        if not summary["recognized"] or ("github_run_url" not in summary and not summary["bindings_valid"]):
            blocked(holds, "RECEIPT_PROOF_UNBOUND", reference["name"], "Digest is verified; unsupported or unbound receipt is not execution/qualification proof")
    if not ci_seen:
        blocked(holds, "CI_SUCCESS_UNPROVEN", "source", "No pinned completed-success GitHub Actions receipt for this exact committed HEAD")
    if not rollback_seen:
        blocked(holds, "SIX_TARGET_ROLLBACK_UNPROVEN", "candidate", "No bound complete six-target same-ID forward/reverse fixture receipt for this exact artifact/source/contract")
    return summaries, holds


def refuse_token_source(path, token_path):
    candidate = S.absolute_path(path)
    token = S.absolute_path(token_path)
    if candidate == token:
        raise ValueError("authentication token cannot be a backup or observed unit-file role")
    # Only inode identity is compared; token contents/hash are never observed here.
    a = candidate.lstat(); b = token.lstat()
    if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
        raise ValueError("authentication inode cannot be a backup role")



PROFILE_REVIEW_KEYS = {
    "schema", "status", "stage_manifest", "source", "inputs", "candidate_profile",
    "candidate_installed_manifest", "changed_profile_fields",
    "changed_installed_manifest_fields", "candidate_facade_argv",
    "other_profile_fields_preserved", "other_installed_manifest_fields_preserved",
    "live_files_changed", "services_restarted", "app_refreshed", "token_read_or_copied",
    "candidate_started", "administrator_profile_review_completed",
    "full_dc_replacement_qualified", "services_before",
}


def private_json_object(raw):
    """JSON only, with no duplicate fields or non-finite numeric values."""
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate private configuration field")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("non-finite private configuration value")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise ValueError("private JSON configuration object required")
    # parse_constant does not catch an exponent such as 1e999 overflowing to inf.
    json.dumps(value, allow_nan=False)
    return value


def read_private_profile_artifact(path, expected_sha256, token_path):
    """Pin private configuration bytes; never digest a credential inode."""
    path = S.absolute_path(path)
    token_path = S.absolute_path(token_path)
    if not isinstance(expected_sha256, str) or not S.HASH.fullmatch(expected_sha256):
        raise ValueError("explicit private artifact SHA256 pin required")
    refuse_token_source(path, token_path)
    token_before = token_path.lstat()
    if (not stat.S_ISREG(token_before.st_mode) or token_before.st_nlink != 1
            or token_before.st_uid != os.getuid()
            or stat.S_IMODE(token_before.st_mode) not in (0o400, 0o600)):
        raise PermissionError("authentication reference requires its private ordinary inode")
    token_identity = (token_before.st_dev, token_before.st_ino)
    parent, name = S.open_parent(path)
    try:
        parent_before = os.fstat(parent)
        if (not stat.S_ISDIR(parent_before.st_mode) or parent_before.st_uid != os.getuid()
                or stat.S_IMODE(parent_before.st_mode) != 0o700):
            raise PermissionError("private configuration parent requires owner-only 0700")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        try:
            def validate(info):
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("private configuration requires a single-link ordinary file")
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    raise PermissionError("private configuration requires current owner and mode 0600")

            before = os.fstat(fd)
            validate(before)
            current_token = token_path.lstat()
            if ((current_token.st_dev, current_token.st_ino) != token_identity
                    or (before.st_dev, before.st_ino) == token_identity):
                raise ValueError("private configuration cannot alias changed authentication")
            if before.st_size > S.MAX_TEXT_BYTES:
                raise ValueError("private configuration exceeds bounded descriptor read")
            raw = bytearray()
            while len(raw) <= S.MAX_TEXT_BYTES:
                chunk = os.read(fd, min(65536, S.MAX_TEXT_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            after = os.fstat(fd)
            validate(after)
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns",
                      "st_uid", "st_nlink", "st_mode")
            if (any(getattr(before, field) != getattr(after, field) for field in fields)
                    or any(getattr(after, field) != getattr(linked, field) for field in fields)):
                raise ValueError("private configuration changed during descriptor read")
            parent_after = os.fstat(parent)
            if any(getattr(parent_before, field) != getattr(parent_after, field)
                   for field in ("st_dev", "st_ino", "st_uid", "st_mode")):
                raise ValueError("private configuration parent changed during descriptor read")
            token_after = token_path.lstat()
            if ((token_after.st_dev, token_after.st_ino) != token_identity
                    or len(raw) != before.st_size or len(raw) > S.MAX_TEXT_BYTES):
                raise ValueError("private configuration or authentication identity changed")
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    raw = bytes(raw)
    observed_sha256 = digest(raw)
    if observed_sha256 != expected_sha256:
        raise ValueError("private artifact differs from its supplied SHA256 pin")
    return raw, {"path": str(path), "sha256": observed_sha256, "bytes": len(raw), "mode": "0600"}


def validate_private_profile_review(args, manifest, material, stage_pin):
    """Verify a private candidate packet; metadata never grants administration."""
    supplied_path = getattr(args, "profile_review_manifest", None)
    supplied_sha256 = getattr(args, "profile_review_manifest_sha256", None)
    if supplied_path is None and supplied_sha256 is None:
        return None
    if supplied_path is None or supplied_sha256 is None:
        raise ValueError("private profile review path and SHA256 must be supplied together")
    path = S.absolute_path(supplied_path)
    folder = path.parent
    if path.name != "review.json":
        raise ValueError("private profile review requires the fixed packet manifest name")
    forbidden = [S.absolute_path(args.source_root), S.ROOT.resolve(),
                 S.absolute_path(args.output_directory)]
    if args.prepare_backups:
        forbidden.append(S.absolute_path(args.backup_directory))
    if any(folder == root or root in folder.parents or folder in root.parents for root in forbidden):
        raise ValueError("private profile packet must be isolated from source and publication paths")
    if any((ancestor / ".git").exists() for ancestor in (folder, *folder.parents)):
        raise ValueError("private profile packet must be outside Git checkouts")
    private_directory(folder)
    names = set()
    for child in folder.iterdir():
        names.add(child.name)
        if len(names) > 3:
            raise ValueError("private profile packet has unexpected entries")
    if names != {"review.json", "candidate-profile.yaml", "candidate-installed.json"}:
        raise ValueError("private profile packet requires exactly its three pinned files")
    token_path = manifest["baseline"]["auth_token_file"]
    raw, review_pin = read_private_profile_artifact(path, supplied_sha256, token_path)
    review = private_json_object(raw)
    if (set(review) != PROFILE_REVIEW_KEYS or review["schema"] != "hepta-successor-private-profile-review-v1"
            or review["status"] != "HOLD"):
        raise ValueError("unsupported private profile review manifest")
    if any(review[key] is not False for key in (
            "live_files_changed", "services_restarted", "app_refreshed", "token_read_or_copied",
            "candidate_started", "administrator_profile_review_completed", "full_dc_replacement_qualified")):
        raise ValueError("private profile metadata cannot assert activation or administrator approval")
    if (review["other_profile_fields_preserved"] is not True
            or review["other_installed_manifest_fields_preserved"] is not True
            or not isinstance(review["services_before"], dict)):
        raise ValueError("private profile preservation metadata is inconsistent")
    expected_stage = {"path": str(S.absolute_path(args.stage_manifest)), "sha256": stage_pin["sha256"]}
    if (raw_json(review["stage_manifest"]) != raw_json(expected_stage)
            or raw_json(review["source"]) != raw_json(manifest["source"])):
        raise ValueError("private profile review is bound to a different exact stage or source")
    references = manifest["baseline"]["live_files"]
    expected_inputs = {role: references[role] for role in ("profile", "installed_manifest")}
    if raw_json(review["inputs"]) != raw_json(expected_inputs):
        raise ValueError("private profile review differs from current pinned live authorities")
    current = {}
    for role, pin in expected_inputs.items():
        current_raw, _ = read_private_profile_artifact(pin["path"], pin["sha256"], token_path)
        current[role] = private_json_object(current_raw)
    stage_folder = S.absolute_path(args.stage_manifest).parent
    facade_expected = ["/usr/bin/python3", str(stage_folder / "chatgpt_full_operator.py"),
                       "--stdio", "--upstream", ENDPOINT, "--token-file", str(token_path),
                       "--contract", str(stage_folder / "contract.json"),
                       "--contract-sha256", manifest["inputs"]["contract"]["sha256"],
                       "--acknowledge-full-operator"]
    if (review["candidate_facade_argv"] != facade_expected
            or json.loads(material["candidate-commands.json"])["facade_argv"] != facade_expected):
        raise ValueError("private profile candidate changes staged facade or loopback authority")
    old = manifest["baseline"]["artifacts"]
    old_argv = ["/usr/bin/python3", old["facade"]["path"], "--stdio", "--token-file", str(token_path),
                "--contract", old["contract"]["path"], "--contract-sha256", old["contract"]["sha256"],
                "--acknowledge-full-operator"]
    mcp = current["profile"].get("mcp")
    commands = mcp.get("commands") if isinstance(mcp, dict) else None
    if (not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], dict)
            or commands[0].get("channel") != "main" or not isinstance(commands[0].get("command"), str)
            or shlex.split(commands[0]["command"]) != old_argv
            or current["installed_manifest"].get("release") != str(pathlib.Path(old["facade"]["path"]).parent)):
        raise ValueError("private installed command or release differs from pinned rollback authority")
    updates = {"release": str(stage_folder), "facade_sha256": manifest["inputs"]["facade"]["sha256"],
               "contract_sha256": manifest["inputs"]["contract"]["sha256"],
               "tool_contract_catalog_sha256": manifest["catalog"]["catalog_sha256"],
               "tools": manifest["catalog"]["tool_count"]}
    activation = json.loads(material["activation-plan.json"])
    if (raw_json(activation["installed_manifest_field_updates"]) != raw_json(updates)
            or review["changed_profile_fields"] != ["mcp.commands[0].command"]
            or review["changed_installed_manifest_fields"] != sorted(updates)):
        raise ValueError("private profile review claims unsupported field changes")
    candidates = {}
    for role, filename in (("candidate_profile", "candidate-profile.yaml"),
                           ("candidate_installed_manifest", "candidate-installed.json")):
        pin = review[role]
        if (not isinstance(pin, dict) or set(pin) != {"path", "sha256", "bytes", "mode"}
                or pin["path"] != str(folder / filename) or pin["mode"] != "0600"
                or type(pin["bytes"]) is not int or not 1 <= pin["bytes"] <= S.MAX_TEXT_BYTES):
            raise ValueError("private profile candidate requires fixed path and bounded exact metadata")
        candidate_raw, observed = read_private_profile_artifact(pin["path"], pin["sha256"], token_path)
        if observed["bytes"] != pin["bytes"]:
            raise ValueError("private profile candidate byte count differs")
        candidates[role] = (private_json_object(candidate_raw), observed)
    expected_profile = copy.deepcopy(current["profile"])
    expected_profile["mcp"]["commands"][0]["command"] = shlex.join(facade_expected)
    expected_installed = copy.deepcopy(current["installed_manifest"])
    expected_installed.update(updates)
    if (raw_json(candidates["candidate_profile"][0]) != raw_json(expected_profile)
            or raw_json(candidates["candidate_installed_manifest"][0]) != raw_json(expected_installed)):
        raise ValueError("private profile candidate changes fields outside the exact staged update")
    return {"prepared": True, "administrator_review_completed": False, "status": "HOLD",
            "format": "json-only", "review_manifest": review_pin,
            "stage_manifest_sha256": stage_pin["sha256"],
            "source_head": manifest["source"]["base_HEAD"],
            "source_code_fingerprint": manifest["source"]["source_code_fingerprint"],
            "candidate_profile": candidates["candidate_profile"][1],
            "candidate_installed_manifest": candidates["candidate_installed_manifest"][1],
            "only_declared_fields_changed": True, "raw_configuration_or_token_value_saved": False}


def prepare_preflight(args, service_probe=None, inventory_probe=None, process_probe=None):
    """Read only; even late failure cannot leave an output directory or backup."""
    output = absent(args.output_directory)
    if args.prepare_backups:
        if args.backup_directory is None:
            raise ValueError("explicit absent private backup directory required")
        backup = absent(args.backup_directory)
        source_root = S.absolute_path(args.source_root)
        if backup == source_root or source_root in backup.parents or backup == output or backup in output.parents or output in backup.parents:
            raise ValueError("secret-bearing backups must be separate and outside the Git source checkout")
    elif args.backup_directory is not None:
        raise ValueError("backup path requires explicit --prepare-backups")
    manifest, material, stage_pin = validate_stage(args)
    summaries, holds = receipt_summaries(manifest)
    live = {}
    backups = {}
    token_path = S.absolute_path(manifest["baseline"]["auth_token_file"])
    baseline_artifacts = {}
    for role, pin in manifest["baseline"]["artifacts"].items():
        refuse_token_source(pin["path"], token_path)
        _, current_pin = S.read_pinned(pin["path"], pin["sha256"], "actual baseline artifact",
                                      S.MAX_NATIVE_BYTES if role == "native" else S.MAX_TEXT_BYTES)
        if current_pin["bytes"] != pin["bytes"] or current_pin["source_mode"] != pin["source_mode"]:
            raise ValueError("actual baseline artifact metadata changed")
        baseline_artifacts[role] = current_pin
    references = manifest["baseline"]["live_files"]
    if set(references) != S.LIVE_ROLES:
        raise ValueError("all live baseline pointers are required")
    for role, pin in references.items():
        path = S.absolute_path(pin["path"])
        refuse_token_source(path, token_path)
        raw, observed = S.read_pinned(path, pin["sha256"], "actual live baseline")
        live[role] = {"path": str(path), "sha256": observed["sha256"], "bytes": observed["bytes"],
                      "mode": observed["source_mode"]}
        if role in {"profile", "installed_manifest"}:
            backups["profile.bin" if role == "profile" else "installed-manifest.bin"] = (raw, 0o600)
        if role == "runtime_config":
            config = json.loads(raw)
            if (config.get("state_dir") != manifest["baseline"]["state_directory"]
                    or set(config.get("hosts", {})) != set(HOSTS)):
                raise ValueError("actual state-directory or six-host logical authorities differ")
    service_probe = service_probe or (lambda: service_observation(token_path))
    process_probe = process_probe or process_observation
    before = service_probe()
    units = before.get("units", {})
    if set(units) != set(UNITS):
        raise ValueError("all protected production units must be observed")
    process_pins = {}
    dropins = []
    for unit in UNITS:
        observed = units[unit]
        pid = str(observed.get("MainPID", "0"))
        if observed.get("ActiveState") != "active" or not pid.isdigit() or int(pid) <= 0:
            raise ValueError("protected production service lacks a live PID")
        process = process_probe(int(pid))
        if process.get("pid") != int(pid) or process.get("uid") != os.getuid() or not isinstance(process.get("start_ticks"), int):
            raise ValueError("protected production PID/start/owner differs")
        process_pins[unit] = process
        for pin in observed.get("dropins", []):
            refuse_token_source(pin["path"], token_path)
            raw, info = S.read_pinned(pin["path"], pin["sha256"], "actual installed drop-in")
            dropins.append({"unit": unit, "path": pin["path"], "sha256": info["sha256"], "bytes": info["bytes"], "mode": info["source_mode"]})
            backups["dropin-" + format(len(dropins) - 1, "04d") + ".conf"] = (raw, 0o600)
        fragment = observed.get("fragment", {})
        if not fragment:
            raise ValueError("actual protected unit fragment is unobserved")
        refuse_token_source(fragment["path"], token_path)
        S.read_pinned(fragment["path"], fragment["sha256"], "actual installed unit fragment")
    native_pin = process_pins[UNITS[0]]
    if native_pin["exe_sha256"] != manifest["baseline"]["artifacts"]["native"]["sha256"]:
        raise ValueError("actual installed native /proc executable differs from staged rollback baseline")
    if references["unit_dropin"] not in [{"path": row["path"], "sha256": row["sha256"]}
                                         for row in dropins if row["unit"] == UNITS[0]]:
        raise ValueError("baseline native drop-in is not in the actual loaded drop-in set")
    activation = json.loads(material["activation-plan.json"])
    new_dropin = S.absolute_path(activation["new_dropin_path"])
    expected_dropin = pathlib.Path(references["unit_dropin"]["path"]).parent / "70-parity-successor.conf"
    if (new_dropin != expected_dropin or activation.get("native_unit") != UNITS[0]
            or activation.get("facade_unit") != UNITS[1] or activation.get("protected_rescue_unit") != UNITS[2]
            or activation.get("performed") is not False or activation.get("status") != "HOLD"):
        raise ValueError("staged activation plan does not preserve exact production unit/drop-in authority")
    absent(new_dropin)
    command_plan = json.loads(material["candidate-commands.json"])
    if command_plan.get("commands_executed") is not False or command_plan.get("status") != "HOLD":
        raise ValueError("non-starting candidate commands required")
    # Validate the actual path-only commands, not a catalog/projection substitute.
    stage_folder = pathlib.Path(args.stage_manifest).parent
    facade_expected = ["/usr/bin/python3", str(stage_folder / "chatgpt_full_operator.py"),
                       "--stdio", "--upstream", ENDPOINT, "--token-file", str(token_path),
                       "--contract", str(stage_folder / "contract.json"),
                       "--contract-sha256", manifest["inputs"]["contract"]["sha256"],
                       "--acknowledge-full-operator"]
    if command_plan.get("facade_argv") != facade_expected:
        raise ValueError("preflight only accepts exact staged facade/contract and fixed loopback endpoint")
    native_argv = command_plan.get("native_argv", [])
    if not isinstance(native_argv, list) or len(native_argv) != 10:
        raise ValueError("exact non-starting native command required")
    workspace = str(S.absolute_path(native_argv[3]))
    native_expected = [str(stage_folder / "candidate-native"), "mcp", "--path", workspace,
                       "--bind", "127.0.0.1:8790", "--runtime-config", references["runtime_config"]["path"],
                       "--auth-token-file", str(token_path)]
    if native_argv != native_expected:
        raise ValueError("candidate command changes preserved token/config or loopback authority")
    dropin_line = shlex.join(native_expected).replace("%", "%%").replace("$", "$$")
    if material["native-dropin.conf"] != ("[Service]\nExecStart=\nExecStart=" + dropin_line + "\n").encode():
        raise ValueError("native drop-in bytes do not match the exact non-starting command")
    private_profile_review = validate_private_profile_review(args, manifest, material, stage_pin)
    inventory = sanitized_inventory((inventory_probe or inventory_observation)(manifest))
    holds.extend(inventory_holds(inventory))
    after = service_probe()
    if after != before or any(process_probe(pin["pid"]) != pin for pin in process_pins.values()):
        raise ValueError("protected production identities/drop-ins changed during observation")
    source_after = S.source_identity(args.source_root)
    if source_after != manifest["source"]:
        raise ValueError("source changed during read-only preflight")
    for role, pin in references.items():
        S.read_pinned(pin["path"], pin["sha256"], "final live baseline")
    for row in dropins:
        S.read_pinned(row["path"], row["sha256"], "final drop-in")
    for role, pin in baseline_artifacts.items():
        S.read_pinned(pin["path"], pin["sha256"], "final baseline artifact",
                      S.MAX_NATIVE_BYTES if role == "native" else S.MAX_TEXT_BYTES)
    # Re-read stage and external receipts after slower remote observations.
    final_manifest, _, final_pin = validate_stage(args)
    if final_manifest != manifest or final_pin != stage_pin:
        raise ValueError("stage changed during preflight")
    receipt_summaries(manifest)
    final_profile_review = validate_private_profile_review(args, manifest, material, stage_pin)
    if raw_json(final_profile_review) != raw_json(private_profile_review):
        raise ValueError("private profile packet changed during preflight")
    blocked(holds, "AUTHORIZED_CUTOVER_NOT_PERFORMED", "production", "This helper cannot freeze admission, alter live files, restart services or activate a candidate")
    if private_profile_review is None:
        blocked(holds, "PRIVATE_PROFILE_MERGE_UNPREPARED", "facade", "Path-only stage template must be merged into a separately reviewed private exact profile before changing the live pointer")
    else:
        blocked(holds, "PRIVATE_PROFILE_REVIEW_REQUIRED", "facade", "Exact private candidate profile is prepared; an authorized administrator must review it before any live pointer change")
    blocked(holds, "WORKSPACE_REFRESH_REQUIRED", "ChatGPT", "Authorized administrator must Refresh the existing connection, review changed metadata and test affected tools in a new conversation; no Refresh API is claimed")
    blocked(holds, "REAL_BUSINESS_DC_OFF_ACCEPTANCE_PENDING", "qualification", "Independent operation, recovery, rollback and genuine business replacement/DC-off remain separate acceptance")
    if not args.prepare_backups:
        blocked(holds, "EXACT_PRIVATE_ROLLBACK_BACKUPS_UNPREPARED", "rollback", "Explicit --prepare-backups can create private exact profile/manifest/drop-in copies without copying the token")
    restore_entries = {
        "profile.bin": {"role": "profile", "original_path": live["profile"]["path"],
                        "original_sha256": live["profile"]["sha256"], "original_mode": live["profile"]["mode"]},
        "installed-manifest.bin": {"role": "installed_manifest", "original_path": live["installed_manifest"]["path"],
                                   "original_sha256": live["installed_manifest"]["sha256"], "original_mode": live["installed_manifest"]["mode"]}}
    for index, row in enumerate(dropins):
        restore_entries["dropin-" + format(index, "04d") + ".conf"] = {
            "role": "unit_dropin", "unit": row["unit"], "original_path": row["path"],
            "original_sha256": row["sha256"], "original_mode": row["mode"]}
    report = {"schema": "hepta-successor-readonly-production-preflight-v1",
              "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "status": "HOLD", "validation_complete": True, "activated": False,
              "live_files_changed": False, "live_configuration_files_changed": False,
              "native_read_tool_metadata_updates_not_suppressed": True,
              "services_restarted": False, "app_refreshed": False,
              "full_dc_replacement_qualified": False, "stage": stage_pin,
              "baseline": {"live_files": live, "artifacts": baseline_artifacts, "services_before": before, "services_after": after,
                           "process_pins": process_pins, "dropins": dropins, "state_directory_preserved": True,
                           "token_copied": False, "token_value_or_headers_saved": False},
              "receipts": summaries, "receipt_success_not_inferred_from_names_or_counts": True,
              "inventory": inventory, "blockers": holds,
              "rollback_backup_prepared": bool(args.prepare_backups),
              "inventory_scope": "Read observations only; no atomic admission freeze or complete dispatch telemetry",
              "future_commands": {"status": "HOLD", "executed": False,
                  "native_unit": UNITS[0], "facade_unit": UNITS[1], "DC_rescue_unit_preserved": UNITS[2],
                  "install_successor_dropin": ["install", "-m", "0600", str(pathlib.Path(args.stage_manifest).parent / "native-dropin.conf"), str(new_dropin)],
                  "daemon_reload": ["systemctl", "--user", "daemon-reload"],
                  "restart_native": ["systemctl", "--user", "restart", UNITS[0]],
                  "restart_facade": ["systemctl", "--user", "restart", UNITS[1]],
                  "rollback_remove_only_owned_successor_dropin": {"path": str(new_dropin), "expected_sha256": digest(material["native-dropin.conf"])},
                  "rollback_restore_exact_private_profile_manifest_dropins": "Use packet manifest original paths and SHA pins after fresh same-ID inventories; preserve state/token/DC"}}
    if private_profile_review is not None:
        report["private_profile_review"] = private_profile_review
    # Internal backup bytes may contain profile credentials, never report/public output.
    return {"report": report, "backups": backups if args.prepare_backups else {},
            "pins": {"stage_manifest_sha256": stage_pin["sha256"], "live_files": live, "dropins": dropins,
                     "output_directory": str(output),
                     "backup_directory": str(backup) if args.prepare_backups else None,
                     "prepare_backups": bool(args.prepare_backups), "source_root": str(S.absolute_path(args.source_root)),
                     "restore_entries": restore_entries,
                     "private_profile_review": ({"path": private_profile_review["review_manifest"]["path"],
                          "sha256": private_profile_review["review_manifest"]["sha256"]}
                          if private_profile_review is not None else None)}}


def write_private_bundle(path, files):
    path = absent(path)
    parent, name = S.open_parent(path)
    directory = None
    identity = None
    created = []
    made = False
    try:
        S.require_trusted_publication_parent(parent)
        os.mkdir(name, mode=0o700, dir_fd=parent)
        made = True
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        observed = os.fstat(directory)
        if observed.st_uid != os.getuid():
            raise PermissionError("publication owner differs")
        identity = observed
        os.fchmod(directory, 0o700)
        for filename, (raw, mode) in files.items():
            if not S.NAME.fullmatch(filename):
                raise ValueError("bounded safe publication name required")
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
            created.append(filename)
            with os.fdopen(fd, "wb") as writer:
                writer.write(raw); writer.flush(); os.fchmod(writer.fileno(), mode); os.fsync(writer.fileno())
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            with os.fdopen(fd, "rb") as reader:
                info = os.fstat(reader.fileno())
                S.validate_inode(info, "published private artifact")
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode or reader.read() != raw:
                    raise ValueError("published artifact bytes/mode/owner differ")
        linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(linked.st_mode) or (linked.st_dev, linked.st_ino) != (identity.st_dev, identity.st_ino):
            raise ValueError("publication directory pathname changed")
        os.fsync(directory); os.fsync(parent)
    except BaseException:
        if directory is not None:
            for filename in reversed(created):
                try:
                    os.unlink(filename, dir_fd=directory)
                except FileNotFoundError:
                    pass
        if made:
            S.remove_owned_directory(parent, name, identity)
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def publish(prepared, args):
    """Only create isolated private output/rollback files. Never update originals."""
    output = absent(args.output_directory)
    pins = prepared["pins"]
    if (str(output) != pins["output_directory"] or bool(args.prepare_backups) != pins["prepare_backups"]
            or str(S.absolute_path(args.source_root)) != pins["source_root"]):
        raise ValueError("publication arguments differ from validated private destinations")
    if args.prepare_backups:
        backup = absent(args.backup_directory)
        if str(backup) != pins["backup_directory"]:
            raise ValueError("backup destination differs from validated private destination")
        root = S.absolute_path(args.source_root)
        if backup == root or root in backup.parents or backup == output or backup in output.parents or output in backup.parents:
            raise ValueError("private backup destination is not isolated")
    private_pin = pins.get("private_profile_review")
    supplied_path = getattr(args, "profile_review_manifest", None)
    supplied_sha256 = getattr(args, "profile_review_manifest_sha256", None)
    if private_pin is None:
        if supplied_path is not None or supplied_sha256 is not None:
            raise ValueError("private profile packet was not validated before publication")
    else:
        if (supplied_path is None or supplied_sha256 is None
                or str(S.absolute_path(supplied_path)) != private_pin["path"]
                or supplied_sha256 != private_pin["sha256"]):
            raise ValueError("private profile publication arguments differ from validated pins")
        current_stage, current_material, current_stage_pin = validate_stage(args)
        current_review = validate_private_profile_review(args, current_stage, current_material, current_stage_pin)
        if raw_json(current_review) != raw_json(prepared["report"].get("private_profile_review")):
            raise ValueError("private profile packet changed before publication")
    report = prepared["report"]
    if args.prepare_backups:
        absent(args.backup_directory)
        files = dict(prepared["backups"])
        packet = {"schema": "hepta-successor-private-exact-rollback-packet-v1",
                  "status": "HOLD", "activation_performed": False, "token_copied": False,
                  "source_pins": prepared["pins"], "restore_entries": prepared["pins"]["restore_entries"],
                  "files": {name: {"bytes": len(raw), "sha256": digest(raw), "mode": format(mode, "04o")}
                            for name, (raw, mode) in files.items()},
                  "do_not_commit_or_publish": True, "exact_private_profile_may_contain_provider_credentials": True,
                  "state_tokens_and_DC_unchanged": True}
        files["packet-manifest.json"] = (raw_json(packet), 0o600)
        write_private_bundle(args.backup_directory, files)
        report["private_rollback_packet"] = {"path": str(args.backup_directory),
            "manifest_sha256": digest(raw_json(packet)), "token_copied": False, "do_not_commit": True}
    data = raw_json(report)
    write_private_bundle(args.output_directory, {"report.json": (data, 0o600)})
    return {"status": "HOLD", "validation_complete": True, "activated": False,
            "report_path": str(S.absolute_path(args.output_directory) / "report.json"),
            "report_sha256": digest(data), "blocker_codes": sorted({row["code"] for row in report["blockers"]}),
            "rollback_backup_prepared": bool(args.prepare_backups)}


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stage-manifest", required=True, type=pathlib.Path)
    ap.add_argument("--stage-manifest-sha256", required=True)
    ap.add_argument("--source-root", required=True, type=pathlib.Path)
    ap.add_argument("--output-directory", required=True, type=pathlib.Path)
    ap.add_argument("--prepare-backups", action="store_true")
    ap.add_argument("--backup-directory", type=pathlib.Path)
    ap.add_argument("--profile-review-manifest", type=pathlib.Path)
    ap.add_argument("--profile-review-manifest-sha256")
    return ap


def main():
    args = parser().parse_args()
    try:
        prepared = prepare_preflight(args)
        result = publish(prepared, args)
    except Exception as error:
        diagnostic = {"status": "HOLD", "validation_complete": False, "activated": False,
                      "error_type": type(error).__name__, "credentials_or_headers_output": False}
        if args.prepare_backups and args.backup_directory is not None and args.backup_directory.is_dir():
            diagnostic["private_packet_may_be_retained"] = str(args.backup_directory)
            diagnostic["packet_not_activation_or_approval"] = True
        print(json.dumps(diagnostic), file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
