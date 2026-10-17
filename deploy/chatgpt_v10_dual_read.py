#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Optional V10 facade with original V4 job, PTY and stream read custody.

Without the explicit effect-owner flag, all state changes are refused.
With it, original effect names dispatch only to V4. A second opt-in admits
six native typed-read workflow lifecycle tools in V10's separate state scope.
Read-only historical job, terminal and cooperative stream operations
preserve original ownership, identities, and byte cursors.
Opt-in job/terminal discovery reconciles both bounded registries; it does
not freeze metadata or make the two observations a global transaction.
This source is not installed as the production ChatGPT connector.
"""
from __future__ import annotations
import argparse
import json
import os
import pathlib
import re
import stat
import threading

from chatgpt_full_operator import (
    NativeProxy, private_token, valid_request, request_era, error,
    RequestNotSubmitted, MODERN_VERSION, MAX_REQUEST, MAX_RESPONSE,
)
from mcp_tool_contract import ToolContract, canonical

READ_ROUTES = {
    "process_status": ("jobs", "job_id", "id"),
    "process_read": ("jobs", "job_id", "id"),
    "process_wait": ("jobs", "job_id", "id"),
    "pty_read": ("terminals", "session_id", "session_id"),
}
HOSTS = frozenset(("main", "pocket4", "rog", "mac", "x230", "ai395"))
JOB_ID = re.compile(r"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+", re.ASCII)
PTY_ID = re.compile(r"dpty-[A-Za-z0-9-]{1,91}", re.ASCII)
STREAM_ID = re.compile(r"stream-[0-9a-f]{64}", re.ASCII)
STREAM_READ_NAMES = frozenset(("stream_handoff_list", "stream_handoff_status", "stream_handoff_read"))
STREAM_EFFECT_BINDING = frozenset(("stream_handoff_write", "stream_handoff_close"))
MAX_STREAM_SESSIONS = 128
# The facade admits at most 4 MiB of request JSON. A legal persisted launch
# record can retain almost that much argv, plus the runtime's fixed wrapper.
# Keep the same finite bound for discovery and later direct owner lookups.
MAX_METADATA = 4 * 1024 * 1024 + 64 * 1024
REGISTRY_LIST_NAMES = frozenset(("process_list", "pty_list"))
MAX_DISCOVERY_ROWS = 16384
MAX_DISCOVERY_PAGES = 128
MAX_REGISTRY_ENTRIES = 32768
V10_READ_WORKFLOWS = frozenset(("operation_start", "operation_cancel", "request_start",
                               "request_cancel", "search_start", "search_stop"))
# These pin reviewed routing policy, independently of the backend's installed
# catalog. Upgrading its binary never grants it another owner's new workflows.
ORIGINAL_EFFECT_CATALOG_SHA256 = "63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad"
CURRENT_RETAINED_CATALOG_SHA256 = "61ffd5277dd653cab0f22674b6f3860f7f596291463cf6d761b2b0fef0ac3616"
OPERATION_READ_TOOLS = frozenset(("read_multiple_files", "file_info", "binary_read", "process_status",
                                "process_read", "process_wait", "process_list", "hardware_snapshot",
                                "service_status", "network_inspect"))
REQUEST_READ_TOOLS = frozenset(("host_list", "host_health", "effective_config"))
WORKFLOW_ID = re.compile(r"[0-9a-f]{64}", re.ASCII)


class UnsafeProvenance(Exception):
    """Only a public refusal reason; no filesystem content is returned."""


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeProvenance("duplicate_metadata_key")
        result[key] = value
    return result


def directory_fd(path):
    """Open one caller-configured root without following the final component."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    s = os.fstat(fd)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or (s.st_mode & 0o077):
        os.close(fd)
        raise UnsafeProvenance("state_root_not_private")
    return fd


def read_owned_record(root: pathlib.Path, kind: str, identity: str, expected_field: str):
    """Return this controller's validated record, or None when absent.

    Root and subdirectory are preconfigured. The leaf is a validated single
    filename, never a request-supplied path. A malformed present entry causes
    an explicit refusal, not a fallback to the other backend.
    """
    dirfd = directory_fd(root)
    try:
        try:
            subfd = os.open(kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
        except FileNotFoundError:
            if kind == "terminals":
                return None
            raise
        try:
            subinfo = os.fstat(subfd)
            if subinfo.st_uid != os.getuid() or (subinfo.st_mode & 0o022):
                raise UnsafeProvenance("state_directory_not_private")
            try:
                filefd = os.open(identity + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=subfd)
            except FileNotFoundError:
                return None
            try:
                before = os.fstat(filefd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_mode & 0o077 or before.st_nlink != 1
                        or not (0 < before.st_size <= MAX_METADATA)):
                    raise UnsafeProvenance("owner_record_shape")
                raw = bytearray()
                while len(raw) < before.st_size:
                    block = os.read(filefd, min(16384, before.st_size - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                after = os.fstat(filefd)
                leaf = os.stat(identity + ".json", dir_fd=subfd, follow_symlinks=False)
                fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
                if (len(raw) != before.st_size
                        or any(getattr(before, name) != getattr(after, name)
                               or getattr(before, name) != getattr(leaf, name)
                               for name in fields)):
                    raise UnsafeProvenance("owner_record_changed")
                try:
                    record = json.loads(raw, object_pairs_hook=strict_pairs,
                                        parse_constant=lambda _: (_ for _ in ()).throw(UnsafeProvenance("invalid_number")))
                except (ValueError, UnicodeError, TypeError) as exc:
                    raise UnsafeProvenance("invalid_owner_record") from exc
                if (not isinstance(record, dict) or record.get(expected_field) != identity
                        or not isinstance(record.get("host"), str) or record["host"] not in HOSTS):
                    raise UnsafeProvenance("owner_record_identity_mismatch")
                return record
            finally:
                os.close(filefd)
        finally:
            os.close(subfd)
    finally:
        os.close(dirfd)


def inspect_owned_record(root: pathlib.Path, kind: str, identity: str, host: str, expected_field: str) -> bool:
    record = read_owned_record(root, kind, identity, expected_field)
    if record is None:
        return False
    if record["host"] != host:
        raise UnsafeProvenance("owner_record_identity_mismatch")
    return True


def registry_members(root, kind):
    """Bound committed member identities; native writers' other entries stay untouched."""
    descriptor = directory_fd(root)
    try:
        try:
            base = os.open(kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
        except FileNotFoundError:
            if kind == "terminals":
                return {}, [], None
            raise
        try:
            info = os.fstat(base)
            if info.st_uid != os.getuid() or info.st_mode & 0o022:
                raise UnsafeProvenance("state_directory_not_private")
            names = sorted(os.listdir(base))
            if len(names) > MAX_REGISTRY_ENTRIES:
                raise UnsafeProvenance("registry_entry_bound")
            members = {}
            pattern, field = (JOB_ID, "id") if kind == "jobs" else (PTY_ID, "session_id")
            for name in names:
                if not name.endswith(".json"):
                    continue
                identity = name[:-5]
                if pattern.fullmatch(identity) is None or len(members) >= MAX_DISCOVERY_ROWS:
                    raise UnsafeProvenance("registry_member_shape_or_bound")
                record = read_owned_record(root, kind, identity, field)
                if record is None:
                    raise UnsafeProvenance("registry_member_disappeared")
                members[identity] = record["host"]
            if names != sorted(os.listdir(base)):
                raise UnsafeProvenance("registry_membership_changed")
            return members, names, (info.st_dev, info.st_ino, info.st_uid, info.st_mode)
        finally:
            os.close(base)
    finally:
        os.close(descriptor)


def inspect_owned_stream(root: pathlib.Path, identity: str) -> bool:
    """Resolve one account-owned stream request, never opening its FIFO/socket."""
    if not isinstance(identity, str) or not STREAM_ID.fullmatch(identity):
        return False
    fd = directory_fd(root)
    try:
        try:
            base = os.open("stream_handoffs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            return False
        try:
            sb = os.fstat(base)
            if sb.st_uid != os.getuid() or (sb.st_mode & 0o077) or not stat.S_ISDIR(sb.st_mode):
                raise UnsafeProvenance("stream_registry_not_private")
            try:
                target = os.open(identity, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
            except FileNotFoundError:
                return False
            try:
                sd = os.fstat(target)
                if sd.st_uid != os.getuid() or (sd.st_mode & 0o077) or not stat.S_ISDIR(sd.st_mode):
                    raise UnsafeProvenance("stream_owner_directory_not_private")
                filefd = os.open("request.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=target)
                try:
                    before = os.fstat(filefd)
                    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                            or before.st_nlink != 1 or before.st_mode & 0o077
                            or not 0 < before.st_size <= MAX_METADATA):
                        raise UnsafeProvenance("stream_request_shape")
                    raw = bytearray()
                    while len(raw) < before.st_size:
                        chunk = os.read(filefd, min(16384, before.st_size - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                    after = os.fstat(filefd)
                    leaf = os.stat("request.json", dir_fd=target, follow_symlinks=False)
                    fields = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
                    if len(raw) != before.st_size or any(
                            getattr(before, key) != getattr(after, key)
                            or getattr(before, key) != getattr(leaf, key) for key in fields):
                        raise UnsafeProvenance("stream_request_changed")
                    try:
                        record = json.loads(raw, object_pairs_hook=strict_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(UnsafeProvenance("invalid_number")))
                    except (ValueError, TypeError, UnicodeError) as exc:
                        raise UnsafeProvenance("invalid_stream_request") from exc
                    if (not isinstance(record, dict) or record.get("session_id") != identity
                            or not isinstance(record.get("application_identities"), list)):
                        raise UnsafeProvenance("stream_request_identity_mismatch")
                    return True
                finally:
                    os.close(filefd)
            finally:
                os.close(target)
        finally:
            os.close(base)
    finally:
        os.close(fd)


def owned_stream_names(root: pathlib.Path) -> list[str]:
    """Bounded stable member set; future dual-populated lists explicitly refuse."""
    fd = directory_fd(root)
    try:
        try:
            base = os.open("stream_handoffs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        except FileNotFoundError:
            return []
        try:
            sb = os.fstat(base)
            if sb.st_uid != os.getuid() or (sb.st_mode & 0o077) or not stat.S_ISDIR(sb.st_mode):
                raise UnsafeProvenance("stream_registry_not_private")
            names = os.listdir(base)
            if len(names) > MAX_STREAM_SESSIONS or len(names) != len(set(names)):
                raise UnsafeProvenance("stream_list_bound_or_duplicate")
            if any(STREAM_ID.fullmatch(name) is None for name in names):
                raise UnsafeProvenance("unknown_stream_registry_entry")
            for name in names:
                if not inspect_owned_stream(root, name):
                    raise UnsafeProvenance("stream_member_unbound")
            if set(names) != set(os.listdir(base)):
                raise UnsafeProvenance("stream_membership_changed")
            return sorted(names)
        finally:
            os.close(base)
    finally:
        os.close(fd)


class OriginalOwner:
    def __init__(self, original_root, new_root):
        self.original_root = pathlib.Path(original_root)
        self.new_root = pathlib.Path(new_root)
        if not self.original_root.is_absolute() or not self.new_root.is_absolute():
            raise UnsafeProvenance("absolute_state_roots_required")
        if self.original_root == self.new_root:
            raise UnsafeProvenance("state_roots_must_be_distinct")
        # Validate both private root directories once, and again at each lookup.
        for root in (self.original_root, self.new_root):
            fd = directory_fd(root)
            os.close(fd)

    def route(self, name, arguments):
        if name in STREAM_READ_NAMES:
            if not isinstance(arguments, dict):
                return None
            if name == "stream_handoff_list":
                old = owned_stream_names(self.original_root)
                new = owned_stream_names(self.new_root)
                if old and new:
                    raise UnsafeProvenance("two_active_stream_registries_cannot_be_silently_collapsed")
                return "legacy" if old else "native"
            identity = arguments.get("session_id")
            if not isinstance(identity, str) or STREAM_ID.fullmatch(identity) is None:
                return None
            old = inspect_owned_stream(self.original_root, identity)
            new = inspect_owned_stream(self.new_root, identity)
            if old and new:
                raise UnsafeProvenance("ambiguous_original_and_new_stream_identity")
            return "legacy" if old else "native"
        if name not in READ_ROUTES or not isinstance(arguments, dict):
            return None
        kind, key, record_field = READ_ROUTES[name]
        identity, host = arguments.get(key), arguments.get("host")
        if not isinstance(identity, str) or not isinstance(host, str) or host not in HOSTS:
            return None
        valid = JOB_ID.fullmatch(identity) if kind == "jobs" else PTY_ID.fullmatch(identity)
        if valid is None or len(identity) > 128:
            return None
        old = inspect_owned_record(self.original_root, kind, identity, host, record_field)
        new = inspect_owned_record(self.new_root, kind, identity, host, record_field)
        if old and new:
            raise UnsafeProvenance("ambiguous_original_and_new_job_identity")
        return "legacy" if old else "native"


class DualReadNativeProxy(NativeProxy):
    def __init__(self, upstream, token, contract, original_upstream, original_token,
                 original_contract, original_state, new_state, route_original_effects=False,
                 route_v10_read_workflows=False, *, retained_backends_current=False,
                 original_route_contract=None):
        super().__init__(upstream, token, contract)
        self.route_original_effects = bool(route_original_effects)
        self.route_v10_read_workflows = bool(route_v10_read_workflows)
        if self.route_v10_read_workflows and not self.route_original_effects:
            raise UnsafeProvenance("v10_read_workflows_require_original_v4_effect_owner")
        # Old effectful definitions must remain exact. No role/annotation change
        # can silently turn a new V10 tool into an original V4 mutation.
        self.retained_backends_current = bool(retained_backends_current)
        if self.retained_backends_current:
            if (not self.route_original_effects or not self.route_v10_read_workflows
                    or original_route_contract is None):
                raise UnsafeProvenance("current_backends_require_explicit_original_routing_contract")
            for reviewed in (contract, original_contract, original_route_contract):
                reviewed.verify_integrity()
            if (contract.catalog_sha256 != CURRENT_RETAINED_CATALOG_SHA256
                    or original_contract.catalog_sha256 != contract.catalog_sha256
                    or original_route_contract.catalog_sha256 != ORIGINAL_EFFECT_CATALOG_SHA256):
                raise UnsafeProvenance("current_backends_reviewed_catalog_mismatch")
            route_contract = original_route_contract
        else:
            if original_route_contract is not None:
                raise UnsafeProvenance("original_routing_contract_requires_current_backends_mode")
            route_contract = original_contract
        original_tools = {tool["name"]: tool for tool in route_contract.tools}
        current_tools = {tool["name"]: tool for tool in contract.tools}
        if self.route_original_effects and (len(original_tools) != 50 or
                any(current_tools.get(name) != definition for name, definition in original_tools.items())):
            raise UnsafeProvenance("original_fifty_tool_contract_drift")
        self._original_effect_names = frozenset(name for name, definition in original_tools.items()
                                                if not definition["annotations"]["readOnlyHint"])
        if self.route_v10_read_workflows:
            for name in V10_READ_WORKFLOWS:
                if (not contract.allows(name) or contract.read_only(name)
                        or route_contract.allows(name)):
                    raise UnsafeProvenance("v10_read_workflow_definition_drift")
            for name in OPERATION_READ_TOOLS | REQUEST_READ_TOOLS:
                if not contract.allows(name) or not contract.read_only(name):
                    raise UnsafeProvenance("v10_nested_read_definition_drift")
        for tool in tuple(READ_ROUTES) + tuple(sorted(STREAM_READ_NAMES)):
            if not self.contract.allows(tool) or not self.contract.read_only(tool):
                raise UnsafeProvenance("v10_read_definition_missing")
            if not original_contract.allows(tool) or not original_contract.read_only(tool):
                raise UnsafeProvenance("legacy_read_definition_missing")
        for tool in REGISTRY_LIST_NAMES:
            if (not self.contract.allows(tool) or not self.contract.read_only(tool)
                    or not original_contract.allows(tool) or not original_contract.read_only(tool)):
                raise UnsafeProvenance("registry_list_read_definition_missing")
        self.provenance = OriginalOwner(original_state, new_state)
        self.legacy = NativeProxy(original_upstream, original_token, original_contract, timeout=38)
        if self.legacy.upstream == self.upstream:
            raise UnsafeProvenance("legacy_upstream_must_be_independent")
        self._legacy_read_lock = threading.RLock()
        self.registry_pager = None
        if contract.allows("process_list_page"):
            if not self.route_original_effects or not contract.read_only("process_list_page"):
                raise UnsafeProvenance("registry_pages_require_read_only_original_owner_route")
            from runtime_registry_page import RuntimeRegistryPager
            self.registry_pager = RuntimeRegistryPager(original_state, new_state)

    def _registry_page(self, request, context, era):
        identity = request["id"]
        try:
            if self.registry_pager is None:
                raise UnsafeProvenance("registry_page_not_configured")
            # Re-attest both execution contracts before exposing their fixed registries.
            # This read never submits a process or a native tool call.
            with self._state_lock:
                self._ensure_native(context)
                self._verify_catalog(context)
            with self._legacy_read_lock:
                with self.legacy._state_lock:
                    self.legacy._ensure_native()
                    self.legacy._verify_catalog()
            self._attest_additional_registry_backend()
            payload = self.registry_pager.page(request["params"].get("arguments", {}))
            result = {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False,
                                                                       separators=(",", ":"))}]}
            response = ({"jsonrpc": "2.0", "id": identity, "result": result}
                        if era == "legacy" else self._modern_result(identity, result))
            if len(canonical(response)) > 64 * 1024:
                raise UnsafeProvenance("registry_page_wire_bound")
            return response
        except Exception:
            return error(identity, -32603, "Durable registry page unavailable or snapshot changed; restart at the first page",
                         outcome="not_submitted", automatic_retry=False,
                         original_request_replayed=False, partial_inventory_returned=False)

    def _original(self, request, context, era, *, mutating):
        identity = request.get("id")
        try:
            if context is not None:
                with self._active_lock:
                    if context.cancel_requested or self._closing.is_set():
                        return self._not_submitted(context, era)
            # Both native contracts are re-attested before delegating. The
            # separate V4 session is the only allowed effect owner.
            with self._state_lock:
                self._ensure_native(context)
                self._verify_catalog(context)
            with self._legacy_read_lock:
                with self.legacy._state_lock:
                    self.legacy._ensure_native()
                    self.legacy._verify_catalog()
                    native_id = self.legacy._next_native_id("owned-effect" if mutating else "original-read")
                    binding = (self.legacy.session, self.legacy.protocol)
                native_request = {
                    "jsonrpc": "2.0", "id": native_id,
                    "method": "tools/call",
                    "params": {"name": request["params"]["name"], "arguments": request["params"].get("arguments", {})},
                }
                # Setting context.transmitting/posted on the ORIGINAL V4 POST
                # ensures a lost response is never misreported as unsubmitted.
                # Do not give the V10 cancellation machinery this V4 binding.
                # Cancellation is intent-only; no cross-controller signals.
                original = self.legacy.exchange(native_request, binding=binding, context=context, timeout=38)
            response = {**original, "id": identity}
            if era == "modern" and "error" not in response:
                value = response.get("result")
                if not isinstance(value, dict) or not isinstance(value.get("content"), list):
                    raise ValueError("invalid original result")
                return self._modern_result(identity, value)
            return response
        except RequestNotSubmitted:
            return self._not_submitted(context, era)
        except Exception:
            return error(identity, -32603,
                         "Original V4 operation response unavailable; no request was replayed",
                         outcome="unknown" if mutating else "unavailable",
                         automatic_retry=False, original_request_replayed=False)

    @staticmethod
    def _inventory_payload(response, identity):
        """Accept one complete native text result without dropping extra metadata."""
        if (not isinstance(response, dict) or response.get("jsonrpc") != "2.0"
                or response.get("id") != identity or "error" in response):
            raise UnsafeProvenance("registry_list_backend_unavailable")
        result = response.get("result")
        if not isinstance(result, dict) or result.get("isError", False) is not False:
            raise UnsafeProvenance("registry_list_backend_error")
        content = result.get("content")
        if (not isinstance(content, list) or len(content) != 1
                or not isinstance(content[0], dict) or content[0].get("type") != "text"
                or not isinstance(content[0].get("text"), str)):
            raise UnsafeProvenance("registry_list_result_shape")
        payload = json.loads(content[0]["text"], object_pairs_hook=strict_pairs,
                             parse_constant=lambda _: (_ for _ in ()).throw(UnsafeProvenance("invalid_number")))
        if (not isinstance(payload, dict)
                or payload.get("inventory_complete", True) is not True
                or payload.get("partial", False) is not False
                or payload.get("truncated", False) is not False):
            raise UnsafeProvenance("registry_list_partial")
        return payload, {"result": {k: v for k, v in result.items() if k != "content"},
                         "content": {k: v for k, v in content[0].items() if k != "text"}}

    def _native_registry_backend(self, request, context, era):
        return super()._dispatch(request, context)

    def _attest_additional_registry_backend(self):
        """Optional retained read owner; the ordinary two-controller bridge has none."""

    def _registry_inventory(self, request, context, era, backend):
        """Collect one bounded backend; only PTY lists have a native cursor."""
        name = request["params"]["name"]
        requested = request["params"].get("arguments", {})
        rows_key, identity_key = (("jobs", "id") if name == "process_list"
                                  else ("sessions", "session_id"))
        rows, metadata, seen = [], [], set()
        after = None
        consumed_bytes = 0
        hosts = [requested["host"]] if requested.get("host") is not None else sorted(HOSTS)
        for page_number in range(MAX_DISCOVERY_PAGES):
            arguments = {"host": requested["host"]} if requested.get("host") is not None else {}
            if name == "process_list":
                # The V4 all-host response can exceed the transport bound even
                # when each configured host has a complete bounded inventory.
                arguments["host"] = hosts[page_number]
            else:
                arguments["limit"] = 128
                if after is not None:
                    arguments["after_session_id"] = after
            page_request = {**request, "params": {**request["params"], "arguments": arguments}}
            if backend == "legacy":
                response = self._original(page_request, context, era, mutating=False)
            else:
                response = self._native_registry_backend(page_request, context, era)
            consumed_bytes += len(canonical(response))
            if consumed_bytes > MAX_RESPONSE:
                raise UnsafeProvenance("registry_list_response_bound")
            payload, envelope = self._inventory_payload(response, request["id"])
            page = payload.get(rows_key)
            if not isinstance(page, list) or len(rows) + len(page) > MAX_DISCOVERY_ROWS:
                raise UnsafeProvenance("registry_list_row_bound")
            previous = after
            for row in page:
                if not isinstance(row, dict):
                    raise UnsafeProvenance("registry_list_row_shape")
                identity, host = row.get(identity_key), row.get("host")
                pattern = JOB_ID if name == "process_list" else PTY_ID
                if (not isinstance(identity, str) or len(identity) > 128
                        or pattern.fullmatch(identity) is None or host not in HOSTS
                        or (requested.get("host") is not None and requested["host"] != host)
                        or (name == "process_list" and host != arguments["host"])
                        or identity in seen):
                    raise UnsafeProvenance("registry_list_identity_or_duplicate")
                if name == "pty_list" and previous is not None and identity <= previous:
                    raise UnsafeProvenance("registry_list_cursor_order")
                previous = identity
                seen.add(identity)
                rows.append(row)
            metadata.append({"payload": {k: v for k, v in payload.items() if k != rows_key},
                             **envelope})
            if name == "process_list":
                if (("total" in payload and
                     (type(payload["total"]) is not int or payload["total"] != len(page)))
                        or payload.get("has_more", False) is not False):
                    raise UnsafeProvenance("registry_list_incomplete_job_count")
                if page_number + 1 == len(hosts):
                    return rows, metadata
                continue
            more, following = payload.get("has_more"), payload.get("next_after_session_id")
            if type(more) is not bool or len(page) > 128:
                raise UnsafeProvenance("registry_list_page_shape")
            if not more:
                if following is not None:
                    raise UnsafeProvenance("registry_list_terminal_cursor")
                return rows, metadata
            if not page or following != previous or (after is not None and following <= after):
                raise UnsafeProvenance("registry_list_nonadvancing_cursor")
            after = following
        raise UnsafeProvenance("registry_list_page_bound")

    def _registry_list(self, request, context, era):
        """Union observations, not a global freeze, admission change or effect route."""
        name, identity = request["params"]["name"], request["id"]
        arguments = request["params"].get("arguments", {})
        permitted = {"host"} if name == "process_list" else {"host", "limit", "after_session_id"}
        limit = arguments.get("limit")
        after = arguments.get("after_session_id")
        if (set(arguments) - permitted
                or (arguments.get("host") is not None and
                    (not isinstance(arguments["host"], str) or arguments["host"] not in HOSTS))
                or (name == "pty_list" and limit is not None and (type(limit) is not int or limit < 0))
                or (after is not None and (not isinstance(after, str) or len(after) > 128))):
            return error(identity, -32602, "Invalid bounded registry list arguments",
                         outcome="not_submitted", automatic_retry=False)
        try:
            kind = "jobs" if name == "process_list" else "terminals"
            states = {"legacy": self.provenance.original_root, "native": self.provenance.new_root}
            before = {backend: registry_members(root, kind) for backend, root in states.items()}
            old, old_metadata = self._registry_inventory(request, context, era, "legacy")
            new, new_metadata = self._registry_inventory(request, context, era, "native")
            identity_key = "id" if name == "process_list" else "session_id"
            all_ids = [row[identity_key] for row in old + new]
            if len(all_ids) != len(set(all_ids)) or len(all_ids) > MAX_DISCOVERY_ROWS:
                raise UnsafeProvenance("registry_list_cross_controller_collision_or_bound")
            # A list response is not authority to mutate an identity. Independently
            # confirm that every row still resolves to the backend that listed it.
            read_name = "process_status" if name == "process_list" else "pty_read"
            argument_key = "job_id" if name == "process_list" else "session_id"
            for backend, rows in (("legacy", old), ("native", new)):
                after_members = registry_members(states[backend], kind)
                if before[backend] != after_members:
                    raise UnsafeProvenance("registry_list_membership_changed")
                expected = {key for key, host in after_members[0].items()
                            if arguments.get("host") is None or arguments["host"] == host}
                if {row[identity_key] for row in rows} != expected:
                    raise UnsafeProvenance("registry_list_missing_or_extra_members")
                for row in rows:
                    state_root = (self.provenance.original_root if backend == "legacy"
                                  else self.provenance.new_root)
                    if not inspect_owned_record(state_root, kind, row[identity_key],
                                                row["host"], identity_key):
                        raise UnsafeProvenance("registry_list_owner_record_missing")
                    owner = self.provenance.route(read_name, {
                        "host": row["host"], argument_key: row[identity_key]})
                    if owner != backend:
                        raise UnsafeProvenance("registry_list_owner_changed")
            combined = sorted(old + new, key=lambda row: row[identity_key])
            provenance = {"semantics": "bounded_union_of_independent_observations_not_global_freeze",
                          "effect_owner_changed": False,
                          "original_v4": old_metadata, "native_v10": new_metadata}
            if name == "process_list":
                payload = {"jobs": combined, "total": len(combined), "inventory_complete": True,
                           "status_authoritative": False, "dual_controller_inventory": provenance}
            else:
                selected = [row for row in combined if after is None or row[identity_key] > after]
                page_limit = min(128, max(1, 128 if limit is None else limit))
                page = selected[:page_limit]
                more = len(selected) > len(page)
                payload = {"sessions": page, "has_more": more,
                           "next_after_session_id": page[-1][identity_key] if more else None,
                           "dual_controller_inventory": provenance}
            result = {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False,
                                                                       separators=(",", ":"))}]}
            response = ({"jsonrpc": "2.0", "id": identity, "result": result}
                        if era == "legacy" else self._modern_result(identity, result))
            if len(canonical(response)) > MAX_RESPONSE:
                raise UnsafeProvenance("registry_list_union_response_bound")
            return response
        except Exception:
            return error(identity, -32603, "Both registry inventories could not be reconciled completely",
                         outcome="unavailable", automatic_retry=False,
                         original_request_replayed=False, partial_inventory_returned=False)

    @staticmethod
    def _workflow_object_shape(arguments, schema):
        """Check closed object boundaries; the unchanged native handler owns policy and ranges."""
        if not isinstance(arguments, dict) or not isinstance(schema, dict):
            raise UnsafeProvenance("read_workflow_object_required")
        properties = schema.get("properties", {})
        if (not isinstance(properties, dict) or set(arguments) - set(properties)
                or set(schema.get("required", [])) - set(arguments)):
            raise UnsafeProvenance("read_workflow_unknown_or_missing_arguments")
        types = {"string": str, "integer": int, "boolean": bool, "array": list, "object": dict}
        for key, value in arguments.items():
            definition = properties[key]
            expected = types.get(definition.get("type"))
            # Optional Rust fields can accept null even where the cleaned model
            # catalog describes only their populated form. Native serde decides.
            if value is None and key not in schema.get("required", []):
                continue
            if expected is not None and type(value) is not expected:
                raise UnsafeProvenance("read_workflow_argument_type")
            if isinstance(value, list):
                item_type = types.get(definition.get("items", {}).get("type"))
                if item_type is not None and any(type(item) is not item_type for item in value):
                    raise UnsafeProvenance("read_workflow_array_item_type")

    def _v10_read_workflow(self, request, context):
        """Admit exactly six original V10 handlers; never delegate or replay them in V4."""
        identity = request["id"]
        try:
            if not getattr(self, "route_original_effects", False):
                raise UnsafeProvenance("v10_read_workflows_require_original_v4_effect_owner")
            if len(canonical(request)) > MAX_REQUEST:
                raise UnsafeProvenance("read_workflow_request_bound")
            name = request["params"]["name"]
            arguments = request["params"].get("arguments", {})
            self._workflow_object_shape(arguments, self.contract.by_name[name]["inputSchema"])
            if name in ("operation_start", "request_start"):
                operation = arguments.get("operation")
                key = arguments.get("idempotency_key")
                if (not isinstance(operation, dict) or set(operation) != {"tool", "arguments"}
                        or not isinstance(key, str) or not 1 <= len(key.encode("utf-8")) <= 128
                        or re.search(r"[\x00-\x1f\x7f-\x9f]", key)):
                    raise UnsafeProvenance("read_workflow_typed_operation_or_key_required")
                tool, inner = operation["tool"], operation["arguments"]
                allowed = OPERATION_READ_TOOLS if name == "operation_start" else REQUEST_READ_TOOLS
                if not isinstance(tool, str) or tool not in allowed:
                    raise UnsafeProvenance("read_workflow_nested_tool_outside_closed_set")
                self._workflow_object_shape(inner, self.contract.by_name[tool]["inputSchema"])
                if "host" in inner and (inner["host"] is not None and inner["host"] not in HOSTS):
                    raise UnsafeProvenance("read_workflow_host_not_configured")
                if tool == "process_list":
                    # A queued V10 handler sees only V10 records. Checking that
                    # V4 is empty now cannot keep it empty until later dispatch.
                    # Direct process_list supplies the bounded two-owner union.
                    raise UnsafeProvenance("nested_process_list_requires_shared_registry")
                if tool in ("process_status", "process_read", "process_wait"):
                    job, host = inner.get("job_id"), inner.get("host")
                    if (not isinstance(job, str) or len(job) > 128 or JOB_ID.fullmatch(job) is None
                            or not isinstance(host, str) or host not in HOSTS
                            or self.provenance.route(tool, inner) != "native"
                            or not inspect_owned_record(self.provenance.new_root, "jobs", job, host, "id")):
                        raise UnsafeProvenance("nested_job_not_owned_by_native_v10")
            elif name == "search_start":
                if arguments.get("host") not in HOSTS:
                    raise UnsafeProvenance("read_workflow_host_not_configured")
                if arguments.get("kind") not in ("files", "content"):
                    raise UnsafeProvenance("read_workflow_literal_search_kind_required")
            else:
                field = {"operation_cancel": "operation_id", "request_cancel": "request_id",
                         "search_stop": "search_id"}[name]
                value = arguments.get(field)
                if not isinstance(value, str) or WORKFLOW_ID.fullmatch(value) is None:
                    raise UnsafeProvenance("read_workflow_native_identity_required")
        except Exception as exc:
            reason = str(exc) if isinstance(exc, UnsafeProvenance) else "read_workflow_provenance_unavailable"
            return error(identity, -32603,
                         "V10 read workflow is outside the bounded native ownership; no dispatch submitted",
                         outcome="not_submitted", automatic_retry=False,
                         original_request_replayed=False, reason=reason)
        # Preserve native argument validation, durable key bindings, credentials,
        # cancellation mapping and unknown transport outcomes. In particular a
        # failed or lost admission response never falls back to the old owner.
        return super()._dispatch(request, context)

    def _dispatch(self, request, context=None):
        if not isinstance(request, dict) or request.get("method") != "tools/call":
            return super()._dispatch(request, context)
        params = request.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return super()._dispatch(request, context)
        name = params["name"]
        if not self.contract.allows(name):
            return super()._dispatch(request, context)
        invalid = valid_request(request, self.contract)
        if invalid is not None:
            return invalid
        era, _ = request_era(request)
        if era not in ("modern", "legacy"):
            return super()._dispatch(request, context)
        identity = request.get("id")
        if era == "legacy" and not getattr(self, "legacy_ready", False):
            return error(identity, -32071, "Legacy MCP initialization required before tool calls",
                         outcome="not_submitted", automatic_retry=False,
                         original_request_replayed=False)
        if name == "process_list_page":
            return self._registry_page(request, context, era)
        if name in REGISTRY_LIST_NAMES and getattr(self, "route_original_effects", False):
            return self._registry_list(request, context, era)
        if name in V10_READ_WORKFLOWS and getattr(self, "route_v10_read_workflows", False):
            return self._v10_read_workflow(request, context)
        if not self.contract.read_only(name):
            old_effect = (getattr(self, "route_original_effects", False)
                          and name in self._original_effect_names)
            if not old_effect:
                return error(identity, -32603,
                             "V10 effects require one shared admission owner; no native dispatch submitted",
                             outcome="not_submitted", automatic_retry=False,
                             original_request_replayed=False)
            # A new V10-owned job or terminal must never be mutated in V4
            # based on a borrowed/recycled identifier. Provenance has to be
            # the original V4 registry identity, otherwise refuse.
            ownership = {
                "process_cancel": ("process_status", "job_id"),
                "pty_write": ("pty_read", "session_id"),
                "pty_close": ("pty_read", "session_id"),
                "stream_handoff_write": ("stream_handoff_status", "session_id"),
                "stream_handoff_close": ("stream_handoff_status", "session_id"),
            }
            if name in ownership:
                target, key = ownership[name]
                try:
                    owner = self.provenance.route(target, params.get("arguments", {}))
                except (UnsafeProvenance, OSError):
                    owner = None
                if owner != "legacy":
                    return error(identity, -32603,
                                 "The requested effect is not bound to an original V4-owned job or PTY",
                                 outcome="not_submitted", automatic_retry=False,
                                 original_request_replayed=False)
            # The original effect names never dispatch to V10. The old 50 tools
            # retain original V4 policy, durable idempotency and result ownership.
            return self._original(request, context, era, mutating=True)

        if name not in READ_ROUTES and name not in STREAM_READ_NAMES:
            return super()._dispatch(request, context)
        try:
            owner = self.provenance.route(name, params.get("arguments", {}))
        except (UnsafeProvenance, OSError):
            return error(identity, -32603, "Original task provenance cannot be resolved safely",
                         outcome="unavailable", automatic_retry=False,
                         original_request_replayed=False)
        if owner != "legacy":
            return super()._dispatch(request, context)
        return self._original(request, context, era, mutating=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stdio", action="store_true", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--legacy-upstream", required=True)
    parser.add_argument("--legacy-token-file", required=True)
    parser.add_argument("--legacy-contract", required=True)
    parser.add_argument("--legacy-contract-sha256", required=True)
    parser.add_argument("--legacy-state", required=True)
    parser.add_argument("--new-state", required=True)
    parser.add_argument("--route-original-v4-effects", action="store_true",
                        help="Route the original 50 effect names solely to V4; never enable by default")
    parser.add_argument("--route-v10-read-workflows", action="store_true",
                        help="Opt in six original V10 typed-read workflow lifecycle tools; requires original V4 effect owner")
    parser.add_argument("--acknowledge-full-operator", action="store_true", required=True)
    args = parser.parse_args()
    if args.route_v10_read_workflows and not args.route_original_v4_effects:
        parser.error("--route-v10-read-workflows requires --route-original-v4-effects")
    native_contract = ToolContract.load(args.contract, args.contract_sha256)
    legacy_contract = ToolContract.load(args.legacy_contract, args.legacy_contract_sha256)
    proxy = DualReadNativeProxy(
        args.upstream, private_token(args.token_file), native_contract,
        args.legacy_upstream, private_token(args.legacy_token_file), legacy_contract,
        args.legacy_state, args.new_state, route_original_effects=args.route_original_v4_effects,
        route_v10_read_workflows=args.route_v10_read_workflows,
    )
    proxy.serve(__import__("sys").stdin.buffer, __import__("sys").stdout.buffer)


if __name__ == "__main__":
    main()
