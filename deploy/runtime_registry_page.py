#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only pagination of the original two controller job registries.

This is a new API implementation, not an extension of process_list's frozen
schema. It reads no task output and invokes no native execution handler. An
initial stable scan freezes only the public metadata projection in a bounded
process-local cache. Later job changes do not prevent completion of that frozen
inventory. Root identity changes, expired snapshots and invalid cursors refuse.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import threading
import time

from chatgpt_v10_dual_read import (
    HOSTS, JOB_ID, MAX_METADATA, MAX_REGISTRY_ENTRIES,
    UnsafeProvenance, directory_fd, strict_pairs,
)
from mcp_tool_contract import canonical

# Headroom for controller marker files within MAX_REGISTRY_ENTRIES.
# V4 writes durable jobs continuously; 16,384 is no longer sufficient.
MAX_JOB_ROWS = MAX_REGISTRY_ENTRIES - 8
MAX_TOTAL_METADATA_BYTES = 128 * 1024 * 1024
MAX_PAGE_ROWS = 128
MAX_PAGE_ROW_BYTES = 64 * 1024
# Reserve the JSON-RPC id/envelope budget in addition to counting the full MCP
# text-content result. Escaped quotes and control characters count twice on wire.
MAX_PAGE_ENVELOPE_BYTES = 1024
MAX_SNAPSHOTS = 16
SNAPSHOT_TTL_SECONDS = 300
MAX_SNAPSHOT_CACHE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_CACHE_ROWS = 131072
# A fresh read-only scan may race a newly created V4 job. Re-observe at most
# twice more; never retry a submitted tool or mask an integrity refusal.
MAX_INITIAL_MEMBERSHIP_SCANS = 3
CURSOR = re.compile(r"rjp1-[A-Za-z0-9_-]{43}", re.ASCII)
FILE_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode", "st_size",
               "st_mtime_ns", "st_ctime_ns", "st_nlink")
ROOT_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode")


def _stamp(info, fields=FILE_FIELDS):
    return tuple(getattr(info, field) for field in fields)


def _memory_bytes(value):
    """Conservative live-object size, including Python containers and strings."""
    seen = set()
    def size(item):
        if id(item) in seen:
            return 0
        seen.add(id(item))
        total = sys.getsizeof(item)
        if isinstance(item, dict):
            total += sum(size(key) + size(child) for key, child in item.items())
        elif isinstance(item, (list, tuple)):
            total += sum(size(child) for child in item)
        return total
    return size(value)


def _private_record(base, name, budget):
    """Read one stable, no-follow regular leaf relative to an already open root."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                 dir_fd=base)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_mode & 0o077 or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_METADATA):
            raise UnsafeProvenance("registry_page_record_shape")
        budget[0] += before.st_size
        if budget[0] > MAX_TOTAL_METADATA_BYTES:
            raise UnsafeProvenance("registry_page_source_byte_bound")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(16384, before.st_size - len(raw)))
            if not block:
                break
            raw.extend(block)
        if (len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd))
                or _stamp(before) != _stamp(os.stat(name, dir_fd=base,
                                                   follow_symlinks=False))):
            raise UnsafeProvenance("registry_page_record_changed")
        try:
            record = json.loads(raw, object_pairs_hook=strict_pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(
                                    UnsafeProvenance("invalid_number")))
        except (ValueError, TypeError, UnicodeError) as exc:
            raise UnsafeProvenance("registry_page_invalid_record") from exc
        return record, _stamp(before), hashlib.sha256(raw).digest()
    finally:
        os.close(fd)


class RuntimeRegistryPager:
    """Read both registries with finite work and authenticated opaque cursors."""

    def __init__(self, legacy_state, native_state, *, cursor_key=None, clock=None):
        self.roots = {"legacy": pathlib.Path(legacy_state),
                      "native": pathlib.Path(native_state)}
        if any(not root.is_absolute() for root in self.roots.values()):
            raise UnsafeProvenance("registry_page_absolute_roots_required")
        self._cursor_key = secrets.token_bytes(32) if cursor_key is None else cursor_key
        if not isinstance(self._cursor_key, bytes) or len(self._cursor_key) < 32:
            raise UnsafeProvenance("registry_page_private_cursor_key_required")
        self._clock = time.monotonic if clock is None else clock
        self._lock = threading.RLock()
        self._snapshots = []
        # Validate now as well as on every page, including aliases of one inode.
        descriptors = []
        try:
            for root in self.roots.values():
                descriptors.append(directory_fd(root))
            if len({_stamp(os.fstat(fd), ("st_dev", "st_ino"))
                    for fd in descriptors}) != 2:
                raise UnsafeProvenance("registry_page_distinct_roots_required")
        finally:
            for fd in descriptors:
                os.close(fd)

    def _token(self, domain, payload):
        value = hmac.digest(self._cursor_key, domain + b"\0" + payload, "sha256")
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    def _cursor(self, snapshot, row):
        return "rjp1-" + self._token(b"job-page-cursor-v1", snapshot + b"\0" +
                                    canonical([row["owner"], row["id"]]))

    def _collect(self, host):
        """Keep root/subdirectory descriptors open through final member checks."""
        opened, rows, fingerprints, identities = [], [], [], set()
        budget = [0]
        try:
            for owner, root in self.roots.items():
                rootfd = directory_fd(root)
                entry = {"owner": owner, "root": root, "rootfd": rootfd}
                opened.append(entry)
                entry["root_stamp"] = _stamp(os.fstat(rootfd), ROOT_FIELDS)
                base = os.open("jobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                               os.O_CLOEXEC, dir_fd=rootfd)
                entry["base"] = base
                info = os.fstat(base)
                if info.st_uid != os.getuid() or info.st_mode & 0o022:
                    raise UnsafeProvenance("registry_page_directory_not_private")
                entry["base_stamp"] = _stamp(info, ROOT_FIELDS)
                names = sorted(os.listdir(base))
                if len(names) > MAX_REGISTRY_ENTRIES:
                    raise UnsafeProvenance("registry_page_entry_bound")
                members = [name for name in names if name.endswith(".json")]
                entry["members"], entry["records"] = members, []
                for name in members:
                    identity = name[:-5]
                    if (len(identity) > 128 or JOB_ID.fullmatch(identity) is None
                            or identity in identities or len(identities) >= MAX_JOB_ROWS):
                        raise UnsafeProvenance("registry_page_member_shape_collision_or_bound")
                    record, stamp, digest = _private_record(base, name, budget)
                    if (not isinstance(record, dict) or record.get("id") != identity
                            or not isinstance(record.get("host"), str)
                            or record["host"] not in HOSTS):
                        raise UnsafeProvenance("registry_page_record_identity_mismatch")
                    created = record.get("created_unix_ms")
                    mode = record.get("execution_mode", "isolated")
                    launch = record.get("launch_state", "launched")
                    if (type(created) is not int or not 0 <= created < 2 ** 128
                            or mode not in ("isolated", "operator")
                            or not isinstance(launch, str)):
                        raise UnsafeProvenance("registry_page_projection_shape")
                    row = {"owner": owner, "id": identity, "host": record["host"],
                           "created_unix_ms": created, "execution_mode": mode,
                           "launch_state": launch}
                    identities.add(identity)
                    entry["records"].append((name, stamp))
                    # Hash full private metadata internally; only keyed opaque
                    # identifiers leave this module. No argv/path/secret is emitted.
                    fingerprints.append([owner, identity, list(stamp), digest.hex()])
                    if host is None or host == row["host"]:
                        rows.append(row)
            if len({entry["root_stamp"][:2] for entry in opened}) != 2:
                raise UnsafeProvenance("registry_page_distinct_roots_required")
            for entry in opened:
                base, rootfd = entry["base"], entry["rootfd"]
                current = sorted(os.listdir(base))
                if (len(current) > MAX_REGISTRY_ENTRIES
                        or [name for name in current if name.endswith(".json")] != entry["members"]):
                    raise UnsafeProvenance("registry_page_membership_changed")
                for name, stamp in entry["records"]:
                    if _stamp(os.stat(name, dir_fd=base, follow_symlinks=False)) != stamp:
                        raise UnsafeProvenance("registry_page_record_changed")
                if (_stamp(os.fstat(base), ROOT_FIELDS) != entry["base_stamp"]
                        or _stamp(os.stat("jobs", dir_fd=rootfd, follow_symlinks=False),
                                  ROOT_FIELDS) != entry["base_stamp"]
                        or _stamp(os.fstat(rootfd), ROOT_FIELDS) != entry["root_stamp"]
                        or _stamp(os.stat(entry["root"], follow_symlinks=False),
                                  ROOT_FIELDS) != entry["root_stamp"]):
                    raise UnsafeProvenance("registry_page_root_or_directory_changed")
            snapshot = hashlib.sha256(canonical({
                "roots": [[entry["owner"], list(entry["root_stamp"]),
                           list(entry["base_stamp"])] for entry in opened],
                "host": host, "records": fingerprints,
            })).digest()
            bindings = [(entry["owner"], entry["root_stamp"], entry["base_stamp"])
                        for entry in opened]
            return sorted(rows, key=lambda row: (row["id"], row["owner"])), snapshot, bindings
        finally:
            for entry in reversed(opened):
                if "base" in entry:
                    os.close(entry["base"])
                os.close(entry["rootfd"])

    def _validate_roots(self, bindings):
        for owner, root_stamp, base_stamp in bindings:
            rootfd = directory_fd(self.roots[owner])
            base = None
            try:
                base = os.open("jobs", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                               os.O_CLOEXEC, dir_fd=rootfd)
                if (_stamp(os.fstat(rootfd), ROOT_FIELDS) != root_stamp
                        or _stamp(os.fstat(base), ROOT_FIELDS) != base_stamp
                        or _stamp(os.stat("jobs", dir_fd=rootfd, follow_symlinks=False),
                                  ROOT_FIELDS) != base_stamp
                        or _stamp(os.stat(self.roots[owner], follow_symlinks=False),
                                  ROOT_FIELDS) != root_stamp):
                    raise UnsafeProvenance("registry_page_root_or_directory_changed")
            finally:
                if base is not None:
                    os.close(base)
                os.close(rootfd)

    def page(self, arguments):
        with self._lock:
            return self._page(arguments)

    def _page(self, arguments):
        """Return one complete page or raise; a failure never returns partial rows."""
        if not isinstance(arguments, dict) or set(arguments) - {"host", "limit", "cursor"}:
            raise UnsafeProvenance("registry_page_invalid_arguments")
        host, limit, cursor = (arguments.get("host"), arguments.get("limit", MAX_PAGE_ROWS),
                               arguments.get("cursor"))
        if (host is not None and (not isinstance(host, str) or host not in HOSTS)
                or type(limit) is not int or not 1 <= limit <= MAX_PAGE_ROWS
                or cursor is not None and (not isinstance(cursor, str)
                                          or CURSOR.fullmatch(cursor) is None)):
            raise UnsafeProvenance("registry_page_invalid_arguments")
        now = self._clock()
        self._snapshots = [entry for entry in self._snapshots if entry["expires"] > now]
        start = 0
        if cursor is not None:
            chosen = None
            for entry in self._snapshots:
                if entry["host"] != host:
                    continue
                for index, row in enumerate(entry["rows"]):
                    if hmac.compare_digest(cursor, self._cursor(entry["snapshot"], row)):
                        chosen, start = entry, index + 1
                        break
                if chosen is not None:
                    break
            if chosen is None:
                raise UnsafeProvenance("registry_page_snapshot_expired_or_cursor_invalid")
            self._validate_roots(chosen["bindings"])
            # LRU fairness: an authenticated active cursor must remain recent
            # while unrelated readers create snapshots. Absolute TTL unchanged.
            self._snapshots.remove(chosen)
            self._snapshots.append(chosen)
        else:
            # V4 remains a live writer while we construct this read-only
            # observation. Retry only a benign membership race and only from
            # the beginning. Changed records, roots, identities and privileges
            # must still refuse immediately; no effects are submitted.
            for attempt in range(MAX_INITIAL_MEMBERSHIP_SCANS):
                try:
                    rows, observed, bindings = self._collect(host)
                    break
                except UnsafeProvenance as exc:
                    if (str(exc) != "registry_page_membership_changed"
                            or attempt + 1 == MAX_INITIAL_MEMBERSHIP_SCANS):
                        raise
            chosen = {"host": host, "rows": rows, "bindings": bindings,
                      "snapshot": hashlib.sha256(secrets.token_bytes(32) + observed).digest(),
                      "expires": self._clock() + SNAPSHOT_TTL_SECONDS}
            chosen["bytes"] = _memory_bytes(chosen) + 1024
            if (chosen["bytes"] > MAX_SNAPSHOT_CACHE_BYTES
                    or len(rows) > MAX_SNAPSHOT_CACHE_ROWS):
                raise UnsafeProvenance("registry_page_snapshot_cache_bound")
            while (len(self._snapshots) >= MAX_SNAPSHOTS
                   or sum(entry["bytes"] for entry in self._snapshots) + chosen["bytes"]
                        > MAX_SNAPSHOT_CACHE_BYTES
                   or sum(len(entry["rows"]) for entry in self._snapshots) + len(rows)
                        > MAX_SNAPSHOT_CACHE_ROWS):
                self._snapshots.pop(0)
            self._snapshots.append(chosen)
        rows, snapshot = chosen["rows"], chosen["snapshot"]
        def response(page):
            more = start + len(page) < len(rows)
            return {"jobs": [dict(row) for row in page], "total": len(rows), "returned": len(page),
                    "has_more": more,
                    "next_cursor": self._cursor(snapshot, page[-1]) if more else None,
                    "snapshot_id": "rjs1-" + self._token(b"job-page-snapshot-v1", snapshot),
                    "page_complete": True, "inventory_complete": not more,
                    "status_authoritative": False,
                    "snapshot_semantics": "frozen_initial_observed_metadata_not_live_status_or_effect_authority",
                    "cursor_scope": "current_facade_process",
                    "snapshot_ttl_seconds": SNAPSHOT_TTL_SECONDS}

        def fits(payload):
            wire = {"content": [{"type": "text", "text": canonical(payload).decode("utf-8")}],
                    "isError": False}
            return len(canonical(wire)) + MAX_PAGE_ENVELOPE_BYTES <= MAX_PAGE_ROW_BYTES

        page = []
        for row in rows[start:start + limit]:
            candidate = page + [row]
            if not fits(response(candidate)):
                if not page:
                    raise UnsafeProvenance("registry_page_single_row_byte_bound")
                break
            page = candidate
        return response(page)
