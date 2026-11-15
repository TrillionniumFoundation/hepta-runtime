#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only V4 state/snapshot compatibility probe for a separate native server.

This program never starts or stops a server and has no effect-tool dispatch path.
Its scope is durable job, terminal and cooperative-stream registries. It compares
all native memberships and terminal observations, plus bounded archive samples.
A PASS is evidence for this scope, not a full replacement or cutover approval.
Raw metadata, private keys, tool arguments and archive contents are never emitted.
Native read calls can append the server's ordinary observation audit records.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

from chatgpt_full_operator import NativeProxy, private_token
from mcp_tool_contract import ToolContract, canonical

JOB_ID = re.compile(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", re.ASCII)
PTY_ID = re.compile(r"dpty-[A-Za-z0-9-]{1,123}", re.ASCII)
STREAM_ID = re.compile(r"stream-[0-9a-f]{64}", re.ASCII)
HOST = re.compile(r"[A-Za-z0-9_.-]{1,128}", re.ASCII)
MAX_METADATA = 1024 * 1024
MAX_ENTRIES = 32768
MAX_ARTIFACT = 256 * 1024 * 1024
READ_TOOLS = frozenset(("host_list", "process_list", "process_status", "process_read", "pty_list",
                        "pty_read", "stream_handoff_list", "stream_handoff_status",
                        "stream_handoff_read"))
STREAM_METADATA = frozenset(("request.json", "ready.json", "state.json", "final.json",
                             "handoff_receipt.json"))
STREAM_ARTIFACTS = frozenset(("broker.py", "stdout.log", "stderr.log", "input_receipts.jsonl"))
JOB_TERMINAL = frozenset(("succeeded", "failed", "cancelled", "timed_out", "launch_failed"))


class ProbeError(Exception):
    """A public, fixed refusal class without underlying private exception text."""


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ProbeError("duplicate_json_key")
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProbeError("nonfinite_json")))
        canonical(value)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ProbeError("invalid_json") from exc


def metadata_key(info):
    return tuple(getattr(info, name) for name in (
        "st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_nlink", "st_mtime_ns", "st_ctime_ns"))


def private_directory(fd, *, root=False):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or (stat.S_IMODE(info.st_mode) != 0o700 if root else bool(info.st_mode & 0o022))):
        raise ProbeError("unsafe_directory")


def root_fd(path):
    path = pathlib.Path(path)
    if not path.is_absolute() or any(part in (".", "..") for part in str(path).split("/")):
        raise ProbeError("absolute_nonsymlink_state_root_required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        private_directory(fd, root=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def directory_at(parent, name, *, private=False):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        private_directory(fd, root=private)
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded_names(fd):
    names = sorted(os.listdir(fd))
    if len(names) > MAX_ENTRIES or len(names) != len(set(names)):
        raise ProbeError("registry_entry_limit_or_duplicate")
    return names


def regular_at(parent, name, *, limit=MAX_METADATA, executable=False, parse=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        permitted = (0o600, 0o700) if executable else (0o600,)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) not in permitted or before.st_nlink != 1
                or before.st_size > limit or before.st_size < 0):
            raise ProbeError("unsafe_or_oversized_regular_file")
        checksum = hashlib.sha256()
        raw = bytearray()
        size = 0
        while size < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - size))
            if not chunk:
                raise ProbeError("short_file_read")
            size += len(chunk)
            checksum.update(chunk)
            if parse:
                raw.extend(chunk)
        after = os.fstat(fd)
        leaf = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if metadata_key(before) != metadata_key(after) or metadata_key(before) != metadata_key(leaf):
            raise ProbeError("file_changed_during_read")
        result = {"bytes": size, "sha256": checksum.hexdigest(), "type": "regular"}
        if parse:
            value = strict_json(raw)
            if not isinstance(value, dict):
                raise ProbeError("metadata_object_required")
            result["json_type"] = "object"
            result["field_types_sha256"] = digest({key: type(item).__name__ for key, item in value.items()})
            return result, value
        return result
    finally:
        os.close(fd)


def stable_directory(parent, name, fd, before, names):
    if bounded_names(fd) != names or metadata_key(before) != metadata_key(os.fstat(fd)):
        raise ProbeError("registry_changed_during_read")
    if metadata_key(before) != metadata_key(os.stat(name, dir_fd=parent, follow_symlinks=False)):
        raise ProbeError("registry_replaced_during_read")


def identity_metadata(kind, identity, value):
    if kind == "stream_handoffs":
        if value.get("session_id") != identity or not isinstance(value.get("application_identities"), list):
            raise ProbeError("stream_identity_or_schema_mismatch")
        return {"id": identity}
    field = "id" if kind == "jobs" else "session_id"
    host = value.get("host")
    if value.get(field) != identity or not isinstance(host, str) or not HOST.fullmatch(host):
        raise ProbeError("record_identity_or_host_mismatch")
    required = ({"ssh_target": str, "unit": str, "remote_job_dir": str, "executable": str,
                 "args": list, "env_keys": list, "created_unix_ms": int,
                 "request_fingerprint": int} if kind == "jobs" else
                {"ssh_target": str, "remote_state_dir": str, "job_dir": str, "request": dict})
    for key, expected_type in required.items():
        if type(value.get(key)) is not expected_type:
            raise ProbeError("record_schema_mismatch")
    if kind == "jobs":
        if value.get("request_digest") is not None and not re.fullmatch("[0-9a-f]{64}", str(value["request_digest"])):
            raise ProbeError("invalid_job_request_digest")
        if value.get("idempotency_key") is not None and not isinstance(value["idempotency_key"], str):
            raise ProbeError("invalid_job_idempotency_type")
    elif value["request"].get("session_id") != identity:
        raise ProbeError("terminal_request_identity_mismatch")
    return {"id": identity, "host": host}


def issue(kind, name, exc):
    # Names can themselves contain secrets. Only a stable digest is returned for
    # unknown entries, while well-formed public registry identities are separate.
    return {"registry": kind, "entry_name_sha256": hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest(),
            "reason": str(exc) if isinstance(exc, ProbeError) else type(exc).__name__}


def scan_stream(parent, identity):
    fd = directory_at(parent, identity, private=True)
    try:
        before = os.fstat(fd)
        names = bounded_names(fd)
        records = {}
        request = None
        for name in names:
            if name in STREAM_METADATA:
                item, value = regular_at(fd, name, parse=True)
                if name == "request.json":
                    request = value
                if "session_id" in value and value["session_id"] != identity:
                    raise ProbeError("stream_artifact_identity_mismatch")
                records[name] = item
            elif name in STREAM_ARTIFACTS:
                records[name] = regular_at(fd, name, limit=MAX_ARTIFACT, executable=name == "broker.py")
            elif ".tmp" in name or ".history-" in name or ".new-" in name:
                raise ProbeError("temporary_stream_artifact_requires_reconciliation")
            else:
                raise ProbeError("unknown_stream_artifact")
        if request is None:
            raise ProbeError("stream_request_missing")
        metadata = identity_metadata("stream_handoffs", identity, request)
        stable_directory(parent, identity, fd, before, names)
        return {**metadata, "artifacts": records, "sha256": digest(records)}
    finally:
        os.close(fd)


def inventory(state):
    result = {"complete": True, "registries": {}, "issues": [], "scope": ["jobs", "terminals", "stream_handoffs"]}
    try:
        base = root_fd(state)
    except (OSError, ProbeError) as exc:
        result.update(complete=False, issues=[issue("state", "state", exc)])
        return result
    try:
        info = os.fstat(base)
        result["state_root_identity"] = [info.st_dev, info.st_ino]
        for kind, pattern in (("jobs", JOB_ID), ("terminals", PTY_ID), ("stream_handoffs", STREAM_ID)):
            entries, temporary = [], []
            reg = {"present": True, "records": entries, "temporary": temporary}
            result["registries"][kind] = reg
            try:
                fd = directory_at(base, kind, private=kind == "stream_handoffs")
            except FileNotFoundError:
                reg["present"] = False
                # V4 creates jobs at startup; terminals/streams are lazy stores.
                if kind == "jobs":
                    result["issues"].append(issue(kind, kind, ProbeError("required_jobs_registry_missing")))
                reg.update(count=0, sha256=digest(entries))
                continue
            except (OSError, ProbeError) as exc:
                result["issues"].append(issue(kind, kind, exc))
                continue
            try:
                before = os.fstat(fd)
                names = bounded_names(fd)
                for name in names:
                    try:
                        if kind == "stream_handoffs":
                            if not pattern.fullmatch(name):
                                raise ProbeError("unknown_stream_registry_entry")
                            entries.append(scan_stream(fd, name))
                            continue
                        if ".json.tmp." in name:
                            identity = name.split(".json.tmp.", 1)[0]
                            if not pattern.fullmatch(identity):
                                raise ProbeError("unknown_temporary_registry_entry")
                            temporary.append({"id": identity, **regular_at(fd, name)})
                            raise ProbeError("temporary_metadata_requires_reconciliation")
                        identity = name.removesuffix(".json")
                        if not name.endswith(".json") or not pattern.fullmatch(identity):
                            raise ProbeError("unknown_registry_entry")
                        item, value = regular_at(fd, name, parse=True)
                        entries.append({**identity_metadata(kind, identity, value), **item})
                    except (OSError, ProbeError) as exc:
                        result["issues"].append(issue(kind, name, exc))
                stable_directory(base, kind, fd, before, names)
            except (OSError, ProbeError) as exc:
                result["issues"].append(issue(kind, kind, exc))
            finally:
                os.close(fd)
            reg.update(count=len(entries), temporary_count=len(temporary), sha256=digest(entries))
    finally:
        os.close(base)
    result["complete"] = not result["issues"]
    result["sha256"] = digest(result["registries"])
    return result


def incremental_shadow_delta(baseline, catchup):
    """Strict append-only frozen-state comparison; never authorizes an owner cutover.

    Inputs come only from inventory()'s checked, private metadata fingerprints.
    No raw identity, command argument, credential, or captured output is emitted.
    This is only a reproducible preflight for subsequent native owner fencing.
    """
    kinds = ("jobs", "terminals", "stream_handoffs")
    result = {"schema": "hepta-shadow-incremental-catchup-v1",
              "qualified": False, "cutover_eligible": False,
              "effect_tools_submitted": False, "independent_state_roots": False,
              "registries": {}, "issues": [],
              "scope": list(kinds),
              "note": "Read-only append-only check, NOT live admission freeze or owner transfer"}
    if (not isinstance(baseline, dict) or not isinstance(catchup, dict)
            or not baseline.get("complete") or not catchup.get("complete")):
        result["issues"].append("incomplete_or_untrusted_snapshot")
        return result
    old_identity = baseline.get("state_root_identity")
    new_identity = catchup.get("state_root_identity")
    if (not isinstance(old_identity, list) or len(old_identity) != 2
            or not isinstance(new_identity, list) or len(new_identity) != 2
            or old_identity == new_identity):
        result["issues"].append("independent_snapshot_required")
        return result
    result["independent_state_roots"] = True

    for kind in kinds:
        old = baseline.get("registries", {}).get(kind)
        new = catchup.get("registries", {}).get(kind)
        if (not isinstance(old, dict) or not isinstance(new, dict)
                or not isinstance(old.get("records"), list)
                or not isinstance(new.get("records"), list)
                or old.get("temporary_count", 0) != 0
                or new.get("temporary_count", 0) != 0):
            result["issues"].append("incomplete_or_untrusted_registry")
            continue

        def map_records(entries):
            by_id = {}
            for entry in entries:
                if (not isinstance(entry, dict) or not isinstance(entry.get("id"), str)
                        or not isinstance(entry.get("sha256"), str)
                        or len(entry["sha256"]) != 64):
                    raise ProbeError("invalid_record_projection")
                identity = entry["id"]
                if identity in by_id:
                    raise ProbeError("duplicate_shadow_identity")
                if kind in ("jobs", "terminals") and not HOST.fullmatch(str(entry.get("host", ""))):
                    raise ProbeError("invalid_shadow_host")
                by_id[identity] = entry
            return by_id

        try:
            original = map_records(old["records"])
            latest = map_records(new["records"])
        except ProbeError as exc:
            result["issues"].append(str(exc))
            continue
        missing = original.keys() - latest.keys()
        additional = latest.keys() - original.keys()
        existing = original.keys() & latest.keys()
        modified = {identity for identity in existing
                    if original[identity]["sha256"] != latest[identity]["sha256"]
                    or (kind != "stream_handoffs"
                        and original[identity].get("host") != latest[identity].get("host"))}
        hosts = {}
        if kind != "stream_handoffs":
            for identity in additional:
                host = latest[identity]["host"]
                hosts[host] = hosts.get(host, 0) + 1
        result["registries"][kind] = {
            "baseline": len(original), "latest": len(latest),
            "added": len(additional), "missing": len(missing),
            "rewritten": len(modified), "unchanged": len(existing) - len(modified),
            "added_by_host": dict(sorted(hosts.items()))}
        if missing:
            result["issues"].append("missing_existing_record")
        if modified:
            result["issues"].append("rewritten_existing_record")
    result["qualified"] = not result["issues"] and len(result["registries"]) == len(kinds)
    return result


def audit_legacy_idempotency(state):
    """Read-only V4 historical host/key binding audit; no key or argv leaves memory.

    The source is a private, independently frozen or continuously observed
    registry. A fully clean audit does not authorize takeover: the successor
    still needs a durable inherited no-replay namespace and fenced ingress.
    """
    result = {
        "complete": False,
        "total_valid_jobs": 0, "keyed_jobs": 0,
        "jobs_without_key": 0, "unique_host_keys": 0,
        "host_job_counts": {},
        "cross_generation_replay_filter_installed": False,
        "cutover_eligible": False,
        "issues": [],
        "scope": "legacy_host_and_idempotency_key_bound_to_original_job",
    }
    root = None
    directory = None
    seen = {}
    try:
        root = root_fd(state)
        directory = directory_at(root, "jobs")
        before = os.fstat(directory)
        names = bounded_names(directory)
        by_host = {}
        for name in names:
            # A remaining .json.tmp file cannot be converted to authority.
            if (not name.endswith(".json")
                    or JOB_ID.fullmatch(name[:-5]) is None):
                result["issues"].append("temporary_or_unknown_registry_entry")
                continue
            try:
                _, record = regular_at(directory, name, parse=True)
                identity_metadata("jobs", name[:-5], record)
                host = record["host"]
                key = record.get("idempotency_key")
                if host not in HOSTS_ALLOWED_FOR_LEGACY:
                    raise ProbeError("invalid_legacy_host")
                result["total_valid_jobs"] += 1
                by_host[host] = by_host.get(host, 0) + 1
                if key is None:
                    result["jobs_without_key"] += 1
                    continue
                if (not isinstance(key, str) or not 1 <= len(key.encode("utf-8")) <= 256):
                    raise ProbeError("invalid_legacy_idempotency_key")
                result["keyed_jobs"] += 1
                full_digest = record.get("request_digest")
                if not isinstance(full_digest, str) or re.fullmatch(r"[0-9a-f]{64}", full_digest) is None:
                    result["issues"].append("legacy_key_without_full_digest")
                previous = seen.get((host, key))
                if previous is not None:
                    result["issues"].append("same_host_idempotency_collision")
                else:
                    seen[(host, key)] = (name[:-5], full_digest)
            except (OSError, ProbeError, ValueError, UnicodeError, TypeError) as exc:
                result["issues"].append(
                    str(exc) if isinstance(exc, ProbeError) else "invalid_or_changed_legacy_record")
        stable_directory(root, "jobs", directory, before, names)
        result["host_job_counts"] = dict(sorted(by_host.items()))
        result["unique_host_keys"] = len(seen)
    except (OSError, ProbeError, ValueError, TypeError) as exc:
        result["issues"].append(
            str(exc) if isinstance(exc, ProbeError) else "legacy_registry_unavailable_or_changed")
    finally:
        if directory is not None:
            os.close(directory)
        if root is not None:
            os.close(root)
    result["issues"] = sorted(set(result["issues"]))
    result["complete"] = not result["issues"]
    return result


HOSTS_ALLOWED_FOR_LEGACY = frozenset(("main", "pocket4", "rog", "mac", "x230", "ai395"))


class ReadClient:
    def __init__(self, upstream, token_file, contract_file, contract_sha256):
        contract = ToolContract.load(contract_file, contract_sha256)
        self.proxy = NativeProxy(upstream, private_token(token_file), contract, timeout=40)
        self.proxy._ensure_native()
        self.proxy._verify_catalog()

    def call(self, name, arguments):
        if name not in READ_TOOLS or not self.proxy.contract.allows(name) or not self.proxy.contract.read_only(name):
            raise ProbeError("probe_tool_outside_read_whitelist")
        value = self.proxy.exchange({"jsonrpc": "2.0", "id": self.proxy._next_native_id("state-probe"),
                                     "method": "tools/call", "params": {"name": name, "arguments": arguments}})
        if "error" in value or not isinstance(value.get("result"), dict):
            raise ProbeError("native_rpc_error")
        result = value["result"]
        blocks = result.get("content")
        if result.get("isError") or not isinstance(blocks, list) or len(blocks) != 1:
            raise ProbeError("native_tool_error_or_ambiguous_content")
        if not isinstance(blocks[0], dict) or blocks[0].get("type") != "text" or not isinstance(blocks[0].get("text"), str):
            raise ProbeError("native_text_result_required")
        parsed = strict_json(blocks[0]["text"])
        if not isinstance(parsed, dict):
            raise ProbeError("native_object_result_required")
        return parsed


def members(records, *, stream=False):
    return sorted((item["id"] if stream else (item["host"], item["id"])) for item in records)


def native_membership(client):
    # Both old full records and new redacted summaries can exceed their wire
    # budgets across all hosts. The configured host set bounds complete shards.
    hosts = client.call("host_list", {}).get("hosts")
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= 128:
        raise ProbeError("configured_host_inventory_unavailable")
    host_names = []
    for host in hosts:
        if (not isinstance(host, dict) or not isinstance(host.get("name"), str)
                or not HOST.fullmatch(host["name"])):
            raise ProbeError("configured_host_shape")
        host_names.append(host["name"])
    if len(set(host_names)) != len(host_names):
        raise ProbeError("duplicate_configured_host")
    job_members = []
    for host in sorted(host_names):
        jobs = client.call("process_list", {"host": host})
        rows = jobs.get("jobs")
        if (not isinstance(rows, list) or len(rows) > MAX_ENTRIES or jobs.get("inventory_complete") is False
                or jobs.get("has_more") or jobs.get("nextCursor") or ("total" in jobs and jobs["total"] != len(rows))):
            raise ProbeError("incomplete_native_job_inventory")
        for item in rows:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str) or not JOB_ID.fullmatch(item["id"])
                    or item.get("host") != host):
                raise ProbeError("native_job_identity_shape")
            job_members.append((host, item["id"]))
        if len(job_members) > MAX_ENTRIES:
            raise ProbeError("native_job_inventory_bound")
    terminals, after = [], None
    while True:
        arguments = {"limit": 128}
        if after is not None:
            arguments["after_session_id"] = after
        page = client.call("pty_list", arguments)
        rows, more = page.get("sessions"), page.get("has_more")
        if not isinstance(rows, list) or type(more) is not bool or len(rows) > 128:
            raise ProbeError("incomplete_native_terminal_inventory")
        ids = []
        for item in rows:
            if (not isinstance(item, dict) or not isinstance(item.get("session_id"), str)
                    or not PTY_ID.fullmatch(item["session_id"]) or not isinstance(item.get("host"), str)
                    or not HOST.fullmatch(item["host"]) or item.get("persistent_across_runtime_restart") is not True):
                raise ProbeError("nonpersistent_or_invalid_terminal_identity")
            identity = item["session_id"]
            if after is not None and identity <= after:
                raise ProbeError("nonprogressing_terminal_page")
            ids.append(identity)
            terminals.append((item["host"], identity))
        if len(terminals) > MAX_ENTRIES or ids != sorted(ids):
            raise ProbeError("terminal_inventory_bound_or_order")
        if not more:
            if page.get("next_after_session_id") is not None:
                raise ProbeError("unexpected_terminal_cursor")
            break
        cursor = page.get("next_after_session_id")
        if not ids or cursor != ids[-1] or (after is not None and cursor <= after):
            raise ProbeError("nonprogressing_terminal_cursor")
        after = cursor
    stream_page = client.call("stream_handoff_list", {"limit": 128})
    rows = stream_page.get("sessions")
    if (not isinstance(rows, list) or len(rows) > 128 or stream_page.get("has_more")
            or stream_page.get("nextCursor")):
        raise ProbeError("incomplete_native_stream_inventory")
    streams = []
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("session_id"), str) or not STREAM_ID.fullmatch(item["session_id"]):
            raise ProbeError("native_stream_identity_shape")
        streams.append(item["session_id"])
    result = {"jobs": sorted(job_members), "terminals": sorted(terminals), "stream_handoffs": sorted(streams)}
    if any(len(items) != len(set(items)) for items in result.values()):
        raise ProbeError("duplicate_native_identity")
    return result


def without_observation_audit(value):
    if not isinstance(value, dict):
        return value
    return {key: item for key, item in value.items() if key not in ("audit_recorded", "audit_warning")}


def validate_archive_page(value, *, stream=False, maximum=16384):
    if not isinstance(value, dict):
        raise ProbeError("archive_page_object_required")
    try:
        data = (base64.b64decode(value["data_base64"], validate=True) if stream
                else bytes.fromhex(value["bytes_hex"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ProbeError("invalid_archive_bytes") from exc
    offset, following = value.get("offset"), value.get("next_offset")
    end = value.get("available_end", value.get("size"))
    if (type(offset) is not int or type(following) is not int or type(end) is not int
            or offset != 0 or not 0 <= offset <= following <= end
            or following - offset != len(data) or len(data) > maximum
            or value.get("truncated_before_offset", False) is not False):
        raise ProbeError("invalid_or_truncated_archive_cursor")
    if "chunk_sha256" in value and value["chunk_sha256"] != hashlib.sha256(data).hexdigest():
        raise ProbeError("archive_chunk_digest_mismatch")


def observation(client, kind, host, identity, *, sample=False):
    if kind == "jobs":
        if sample:
            value = client.call("process_read", {"host": host, "job_id": identity,
                                                 "stdout_offset": 0, "stderr_offset": 0, "limit": 16384})
            for stream in ("stdout", "stderr"):
                validate_archive_page(value.get(stream))
            return without_observation_audit(value)
        value = client.call("process_status", {"host": host, "job_id": identity})
        if value.get("state") not in JOB_TERMINAL:
            raise ProbeError("nonterminal_or_unknown_job")
        return without_observation_audit(value)
    if kind == "terminals":
        value = client.call("pty_read", {"host": host, "session_id": identity,
                                         "offset": 0, "limit": 16384 if sample else 1, "raw_bytes": True})
        status_value = value.get("status")
        if (not isinstance(status_value, dict) or status_value.get("state") != "exited"
                or status_value.get("output_complete") is not True):
            raise ProbeError("nonterminal_or_incomplete_terminal")
        validate_archive_page(value, maximum=16384 if sample else 1)
        return without_observation_audit(value)
    if sample:
        result = {stream: client.call("stream_handoff_read", {"session_id": identity, "stream": stream,
                                                              "offset": 0, "limit": 16384})
                  for stream in ("stdout", "stderr")}
        for value in result.values():
            validate_archive_page(value, stream=True)
        return result
    value = client.call("stream_handoff_status", {"session_id": identity})
    if value.get("state") != "exited" or value.get("output_complete") is not True:
        raise ProbeError("nonterminal_or_incomplete_stream")
    return value


def compare_native(old, new, source, candidate, *, sample_count=8, all_observations=False):
    result = {"complete": True, "issues": [], "memberships": {}, "observations": [], "archive_samples": [], "coverage": {}}
    try:
        old_members, new_members = native_membership(old), native_membership(new)
    except Exception as exc:
        result.update(complete=False, issues=[issue("native", "membership", exc)])
        return result
    for kind in ("jobs", "terminals", "stream_handoffs"):
        expected = members(source["registries"][kind]["records"], stream=kind == "stream_handoffs")
        copied = members(candidate["registries"][kind]["records"], stream=kind == "stream_handoffs")
        same = old_members[kind] == expected == copied == new_members[kind]
        result["memberships"][kind] = {"equal": same, "old_count": len(old_members[kind]),
                                         "new_count": len(new_members[kind]), "expected_count": len(expected),
                                         "sha256": digest(expected)}
        if not same:
            result["issues"].append(issue(kind, "membership", ProbeError("native_membership_mismatch")))
            continue
        if expected and sample_count == 0:
            result["issues"].append(issue(kind, "sample", ProbeError("archive_samples_not_requested")))
        checked = len(expected) if all_observations else min(sample_count, len(expected))
        result["coverage"][kind] = {"identities": len(expected), "terminal_observations_checked": checked,
                                     "all_terminal_observations_checked": checked == len(expected),
                                     "archive_samples": min(sample_count, len(expected))}
        if checked < len(expected):
            result["issues"].append(issue(kind, "coverage", ProbeError("terminal_observation_coverage_incomplete")))
        for index, item in enumerate(expected[:checked]):
            host, identity = (None, item) if kind == "stream_handoffs" else item
            record = {"registry": kind, "id": identity}
            if host is not None:
                record["host"] = host
            for sample in (False, True) if index < sample_count else (False,):
                try:
                    a = observation(old, kind, host, identity, sample=sample)
                    b = observation(new, kind, host, identity, sample=sample)
                    equal = canonical(a) == canonical(b)
                    receipt = {**record, "equal": equal, "old_sha256": digest(a), "new_sha256": digest(b)}
                    result["archive_samples" if sample else "observations"].append(receipt)
                    if not equal:
                        raise ProbeError("archive_sample_mismatch" if sample else "historical_observation_mismatch")
                except Exception as exc:
                    result["issues"].append(issue(kind, identity, exc))
    result["complete"] = not result["issues"]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, help="Original account-owned private V4 state root")
    parser.add_argument("--candidate-state", help="Independent byte-preserving state snapshot served by candidate")
    parser.add_argument("--sample-count", type=int, default=8, help="Archive and terminal-observation samples per registry; partial coverage remains HOLD")
    parser.add_argument("--all-observations", action="store_true", help="Read terminal status for every identity; may require many remote reads")
    parser.add_argument("--shadow-delta", action="store_true",
                        help="Compare two independent frozen inventories append-only; always retain HOLD cutover decision")
    parser.add_argument("--legacy-idempotency", action="store_true",
                        help="Read-only legacy host/key collision audit; never authorizes cross-generation replay")
    parser.add_argument("--out", required=True, help="New private JSON evidence file; never overwritten")
    for prefix in ("old", "new"):
        parser.add_argument(f"--{prefix}-upstream")
        parser.add_argument(f"--{prefix}-token-file")
        parser.add_argument(f"--{prefix}-contract")
        parser.add_argument(f"--{prefix}-contract-sha256")
    args = parser.parse_args(argv)
    if not 0 <= args.sample_count <= MAX_ENTRIES:
        parser.error("sample-count must be within 0..32768")
    endpoints = [getattr(args, prefix + "_" + key) for prefix in ("old", "new")
                 for key in ("upstream", "token_file", "contract", "contract_sha256")]
    if any(endpoints) and (not all(endpoints) or not args.candidate_state):
        parser.error("native comparison requires both complete endpoint configurations and candidate-state")
    if args.shadow_delta and not args.candidate_state:
        parser.error("shadow-delta requires --candidate-state and two independent frozen state roots")
    report = {"schema": "hepta-state-upgrade-probe-v1", "decision": "HOLD",
              "scope": "durable registry compatibility, complete membership and terminal observations, sampled archive parity",
              "full_desktop_commander_replacement_proven": False, "effect_tools_submitted": False,
              "source": inventory(args.state)}
    if args.legacy_idempotency:
        report["legacy_idempotency"] = audit_legacy_idempotency(args.state)
    if args.candidate_state:
        report["candidate"] = inventory(args.candidate_state)
        report["independent_snapshot"] = (report["source"].get("state_root_identity") is not None
                                            and report["source"].get("state_root_identity") != report["candidate"].get("state_root_identity"))
        report["snapshot_registry_bytes_equal"] = (report["source"].get("sha256") == report["candidate"].get("sha256")
                                                    and report["source"]["complete"] and report["candidate"]["complete"])
        if args.shadow_delta:
            report["shadow_delta"] = incremental_shadow_delta(report["source"], report["candidate"])
    if all(endpoints) and report.get("snapshot_registry_bytes_equal") and report.get("independent_snapshot"):
        try:
            old = ReadClient(args.old_upstream, args.old_token_file, args.old_contract, args.old_contract_sha256)
            new = ReadClient(args.new_upstream, args.new_token_file, args.new_contract, args.new_contract_sha256)
            if (old.proxy.upstream.hostname, old.proxy.upstream.port or 80) == (new.proxy.upstream.hostname, new.proxy.upstream.port or 80):
                raise ProbeError("independent_native_endpoints_required")
            if any(new.proxy.contract.by_name.get(name) != tool for name, tool in old.proxy.contract.by_name.items()):
                raise ProbeError("original_tool_contract_drift")
            report["native"] = compare_native(old, new, report["source"], report["candidate"],
                                               sample_count=args.sample_count, all_observations=args.all_observations)
        except Exception as exc:
            report["native"] = {"complete": False, "issues": [issue("native", "connection", exc)]}
        report["source_after"] = inventory(args.state)
        report["candidate_after"] = inventory(args.candidate_state)
        stable = all(report[side]["complete"] and report[side + "_after"]["complete"]
                     and report[side].get("sha256") == report[side + "_after"].get("sha256")
                     for side in ("source", "candidate"))
        report["registries_unchanged_during_probe"] = stable
        if report["native"]["complete"] and stable:
            report["decision"] = "PASS"
    # This audit cannot prove that a successor has installed a no-replay
    # binding for the original 20K+ host/key namespace. Even successful native
    # read parity therefore remains HOLD when explicitly requested.
    if args.legacy_idempotency:
        report["decision"] = "HOLD"
    output = pathlib.Path(args.out)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"decision": report["decision"], "source_complete": report["source"]["complete"],
                      "native_complete": report.get("native", {}).get("complete", False),
                      "effect_tools_submitted": False}))
    return 0 if report["decision"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())
