#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Optional V10 facade with original V4 job, PTY and stream read custody.

Without the explicit effect-owner flag, all state changes are refused.
With it, only the original V4 effect names may dispatch to V4, never V10.
Read-only historical job, terminal and cooperative stream operations
preserve original ownership, identities, and byte cursors.
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
    RequestNotSubmitted, MODERN_VERSION,
)
from mcp_tool_contract import ToolContract

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
MAX_METADATA = 65536


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


def inspect_owned_record(root: pathlib.Path, kind: str, identity: str, host: str, expected_field: str) -> bool:
    """Return whether this controller contains the exact owner record.

    Root and subdirectory are preconfigured. The leaf is a validated single
    filename, never a request-supplied path. A malformed present entry causes
    an explicit refusal, not a fallback to the other backend.
    """
    dirfd = directory_fd(root)
    try:
        subfd = os.open(kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
        try:
            subinfo = os.fstat(subfd)
            if subinfo.st_uid != os.getuid() or (subinfo.st_mode & 0o022):
                raise UnsafeProvenance("state_directory_not_private")
            try:
                filefd = os.open(identity + ".json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=subfd)
            except FileNotFoundError:
                return False
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
                if not isinstance(record, dict) or record.get(expected_field) != identity or record.get("host") != host:
                    raise UnsafeProvenance("owner_record_identity_mismatch")
                return True
            finally:
                os.close(filefd)
        finally:
            os.close(subfd)
    finally:
        os.close(dirfd)


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
                 original_contract, original_state, new_state, route_original_effects=False):
        super().__init__(upstream, token, contract)
        self.route_original_effects = bool(route_original_effects)
        # Old effectful definitions must remain exact. No role/annotation change
        # can silently turn a new V10 tool into an original V4 mutation.
        original_tools = {tool["name"]: tool for tool in original_contract.tools}
        current_tools = {tool["name"]: tool for tool in contract.tools}
        if self.route_original_effects and (len(original_tools) != 50 or
                any(current_tools.get(name) != definition for name, definition in original_tools.items())):
            raise UnsafeProvenance("original_fifty_tool_contract_drift")
        for tool in tuple(READ_ROUTES) + tuple(sorted(STREAM_READ_NAMES)):
            if not self.contract.allows(tool) or not self.contract.read_only(tool):
                raise UnsafeProvenance("v10_read_definition_missing")
            if not original_contract.allows(tool) or not original_contract.read_only(tool):
                raise UnsafeProvenance("legacy_read_definition_missing")
        self.provenance = OriginalOwner(original_state, new_state)
        self.legacy = NativeProxy(original_upstream, original_token, original_contract, timeout=38)
        if self.legacy.upstream == self.upstream:
            raise UnsafeProvenance("legacy_upstream_must_be_independent")
        self._legacy_read_lock = threading.RLock()

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
        if not self.contract.read_only(name):
            old_effect = (getattr(self, "route_original_effects", False) and self.legacy.contract.allows(name)
                          and not self.legacy.contract.read_only(name))
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
            # No V10 effect is sent from this bridge. The old 50 tool names
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
    parser.add_argument("--acknowledge-full-operator", action="store_true", required=True)
    args = parser.parse_args()
    native_contract = ToolContract.load(args.contract, args.contract_sha256)
    legacy_contract = ToolContract.load(args.legacy_contract, args.legacy_contract_sha256)
    proxy = DualReadNativeProxy(
        args.upstream, private_token(args.token_file), native_contract,
        args.legacy_upstream, private_token(args.legacy_token_file), legacy_contract,
        args.legacy_state, args.new_state, route_original_effects=args.route_original_v4_effects,
    )
    proxy.serve(__import__("sys").stdin.buffer, __import__("sys").stdout.buffer)


if __name__ == "__main__":
    main()
