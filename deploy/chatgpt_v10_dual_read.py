#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Optional V10 stdio facade with legacy V4 read-only result custody.

All new work and all write/cancel operations go to V10. Only four pinned
read-only lookup tools may consult original V4 jobs/PTYs. Ownership is
identified through distinct local, controller-owned durable registries;
ambiguous/mismatched records fail closed. Never replay an original effect.
This is a separate candidate entrypoint, not the installed V4 bridge.
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
                 original_contract, original_state, new_state):
        super().__init__(upstream, token, contract)
        for tool in READ_ROUTES:
            if not self.contract.allows(tool) or not self.contract.read_only(tool):
                raise UnsafeProvenance("v10_read_definition_missing")
            if not original_contract.allows(tool) or not original_contract.read_only(tool):
                raise UnsafeProvenance("legacy_read_definition_missing")
        self.provenance = OriginalOwner(original_state, new_state)
        self.legacy = NativeProxy(original_upstream, original_token, original_contract, timeout=38)
        if self.legacy.upstream == self.upstream:
            raise UnsafeProvenance("legacy_upstream_must_be_independent")
        self._legacy_read_lock = threading.RLock()

    def _dispatch(self, request, context=None):
        if not isinstance(request, dict) or request.get("method") != "tools/call":
            return super()._dispatch(request, context)
        params = request.get("params")
        # Until both admission domains share one durable launch/idempotency
        # authority, ANY native effect could repeat a legacy V4 effect under
        # the same request key. This transitional bridge permits reads only.
        if isinstance(params, dict) and isinstance(params.get("name"), str):
            name = params["name"]
            if self.contract.allows(name) and not self.contract.read_only(name):
                invalid = valid_request(request, self.contract)
                if invalid is not None:
                    return invalid
                return error(request.get("id"), -32603,
                             "Dual-controller transition refuses effectful calls until shared admission is qualified",
                             outcome="not_submitted", automatic_retry=False,
                             original_request_replayed=False)
        if not isinstance(params, dict) or params.get("name") not in READ_ROUTES:
            return super()._dispatch(request, context)
        invalid = valid_request(request, self.contract)
        if invalid is not None:
            return invalid
        era, _ = request_era(request)
        if era not in ("modern", "legacy"):
            return super()._dispatch(request, context)
        identity = request.get("id")
        try:
            owner = self.provenance.route(params["name"], params.get("arguments", {}))
        except (UnsafeProvenance, OSError):
            return error(identity, -32603, "Original task provenance cannot be resolved safely",
                         outcome="unavailable", automatic_retry=False, original_request_replayed=False)
        if owner != "legacy":
            return super()._dispatch(request, context)
        try:
            if context is not None:
                with self._active_lock:
                    if context.cancel_requested or self._closing.is_set():
                        return self._not_submitted(context, era)
            # Continue to attest that V10 still exposes the entire unchanged
            # 66-tool contract. The V4 backend has its own pinned 50-tool one.
            with self._state_lock:
                self._ensure_native(context)
                self._verify_catalog(context)
            with self._legacy_read_lock:
                with self.legacy._state_lock:
                    self.legacy._ensure_native()
                    self.legacy._verify_catalog()
                    native_id = self.legacy._next_native_id("original-read")
                    binding = (self.legacy.session, self.legacy.protocol)
                native_request = {
                    "jsonrpc": "2.0", "id": native_id,
                    "method": "tools/call",
                    "params": {"name": params["name"], "arguments": params.get("arguments", {})},
                }
                original = self.legacy.exchange(native_request, binding=binding, timeout=38)
            response = {**original, "id": identity}
            if era == "modern" and "error" not in response:
                value = response.get("result")
                if not isinstance(value, dict) or not isinstance(value.get("content"), list):
                    raise ValueError("invalid original read result")
                return self._modern_result(identity, value)
            return response
        except RequestNotSubmitted:
            return self._not_submitted(context, era)
        except Exception:
            return error(identity, -32603, "Original task read unavailable; no request was replayed",
                         outcome="unavailable", automatic_retry=False, original_request_replayed=False)


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
    parser.add_argument("--acknowledge-full-operator", action="store_true", required=True)
    args = parser.parse_args()
    native_contract = ToolContract.load(args.contract, args.contract_sha256)
    legacy_contract = ToolContract.load(args.legacy_contract, args.legacy_contract_sha256)
    proxy = DualReadNativeProxy(
        args.upstream, private_token(args.token_file), native_contract,
        args.legacy_upstream, private_token(args.legacy_token_file), legacy_contract,
        args.legacy_state, args.new_state,
    )
    proxy.serve(__import__("sys").stdin.buffer, __import__("sys").stdout.buffer)


if __name__ == "__main__":
    main()
