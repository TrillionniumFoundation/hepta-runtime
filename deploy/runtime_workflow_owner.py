#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only workflow custody proof across two administrator-fixed state roots.

No parameters, payloads, argv or credential material leave this module. Membership
is routing evidence only; the selected native handler still verifies caller scope.
Missing complete uncreated stores are absent; a partial intents store, changed
observation, unsafe inode or cross-controller collision always refuses.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import sys

ID = re.compile(r"[0-9a-f]{64}", re.ASCII)
MAX_RECORD_BYTES = 16 * 1024
IDENTITY_FIELDS = ("st_dev", "st_ino", "st_uid", "st_mode")
STABLE_FIELDS = IDENTITY_FIELDS + ("st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
KINDS = {
    "search": (("search",), "id"),
    "request": (("request-async-v9", ".intents"), "request_id"),
    "operation": (("request-operations-v10", ".intents"), "request_id"),
}


class UnsafeWorkflowOwner(ValueError):
    """A public refusal code, never private filesystem content."""


def _stamp(info, fields=STABLE_FIELDS):
    return tuple(getattr(info, field) for field in fields)


def _identity(value):
    return isinstance(value, str) and ID.fullmatch(value) is not None


def _root_path(value):
    try:
        raw = os.fspath(value)
    except TypeError as exc:
        raise UnsafeWorkflowOwner("workflow_absolute_fixed_roots_required") from exc
    if (not isinstance(raw, str) or not raw.startswith("/") or "\0" in raw
            or any(part in (".", "..") for part in raw.split("/"))):
        raise UnsafeWorkflowOwner("workflow_absolute_fixed_roots_required")
    return pathlib.Path(raw)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise UnsafeWorkflowOwner("workflow_duplicate_record_key")
        result[key] = value
    return result


def _invalid_number(_):
    raise UnsafeWorkflowOwner("workflow_invalid_record_number")


def _directory_flags(*, ancestor=False):
    # Linux sandboxes can allow the selected roots without allowing ancestor
    # directory listings. O_PATH retains a no-follow identity handle without
    # requesting READ_DIR; the configured root and its stores still need read access.
    access = os.O_PATH if ancestor and sys.platform == "linux" and hasattr(os, "O_PATH") else os.O_RDONLY
    return access | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class _Observation:
    """Hold every descriptor through final pathname and stable-parent checks."""

    def __init__(self):
        self.descriptors = []
        self.bindings = []
        self.stable_directories = []

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        try:
            if kind is None:
                self.validate()
        finally:
            for descriptor in reversed(self.descriptors):
                os.close(descriptor)

    def keep(self, descriptor):
        self.descriptors.append(descriptor)
        return descriptor

    def child_directory(self, parent, name, *, private, stable, ancestor=False):
        descriptor = self.keep(os.open(name, _directory_flags(ancestor=ancestor), dir_fd=parent))
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or private and
                (info.st_uid != os.getuid() or info.st_mode & 0o077)):
            raise UnsafeWorkflowOwner("workflow_directory_not_private")
        self.bindings.append((parent, name, descriptor, _stamp(info, IDENTITY_FIELDS)))
        if stable:
            self.stable_directories.append((descriptor, _stamp(info)))
        return descriptor

    def root(self, path, expected=None):
        components = path.parts[1:]
        descriptor = self.keep(os.open("/", _directory_flags(ancestor=bool(components))))
        for index, component in enumerate(components):
            descriptor = self.child_directory(descriptor, component, private=False, stable=False,
                                              ancestor=index < len(components) - 1)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise UnsafeWorkflowOwner("workflow_root_not_private")
        identity = _stamp(info, IDENTITY_FIELDS)
        if expected is not None and identity != expected:
            raise UnsafeWorkflowOwner("workflow_root_identity_changed")
        self.stable_directories.append((descriptor, _stamp(info)))
        return descriptor, identity

    def store(self, root, components, *, private=True):
        descriptor = root
        for index, component in enumerate(components):
            try:
                descriptor = self.child_directory(descriptor, component,
                                                  private=private, stable=True)
            except FileNotFoundError as exc:
                if index == 0:
                    return None
                raise UnsafeWorkflowOwner("workflow_partial_store_refused") from exc
        return descriptor

    def validate(self):
        for parent, name, descriptor, identity in self.bindings:
            if (_stamp(os.fstat(descriptor), IDENTITY_FIELDS) != identity
                    or _stamp(os.stat(name, dir_fd=parent, follow_symlinks=False),
                              IDENTITY_FIELDS) != identity):
                raise UnsafeWorkflowOwner("workflow_ancestor_or_directory_changed")
        for descriptor, stamp in self.stable_directories:
            if _stamp(os.fstat(descriptor)) != stamp:
                raise UnsafeWorkflowOwner("workflow_parent_changed_during_observation")


def _record(observation, directory, identity, field):
    if directory is None:
        return None
    filename = identity + ".json"
    try:
        descriptor = observation.keep(os.open(filename, os.O_RDONLY | os.O_NOFOLLOW |
                                               os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory))
    except FileNotFoundError:
        return None
    before = os.fstat(descriptor)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_RECORD_BYTES):
        raise UnsafeWorkflowOwner("workflow_record_shape_refused")
    raw = bytearray()
    while len(raw) < before.st_size:
        block = os.read(descriptor, before.st_size - len(raw))
        if not block:
            break
        raw.extend(block)
    stamp = _stamp(before)
    if (len(raw) != before.st_size or _stamp(os.fstat(descriptor)) != stamp
            or _stamp(os.stat(filename, dir_fd=directory, follow_symlinks=False)) != stamp):
        raise UnsafeWorkflowOwner("workflow_record_changed")
    try:
        record = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_invalid_number)
    except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
        raise UnsafeWorkflowOwner("workflow_invalid_record") from exc
    if (not isinstance(record, dict) or record.get(field) != identity
            or not _identity(record.get("owner"))):
        raise UnsafeWorkflowOwner("workflow_record_identity_or_owner_mismatch")
    # Re-check leaves after the other controller has been inspected as well.
    observation.bindings.append((directory, filename, descriptor,
                                  _stamp(before, IDENTITY_FIELDS)))
    observation.stable_directories.append((descriptor, stamp))
    return record["owner"]


class RuntimeWorkflowOwner:
    """Closed workflow namespaces and immutable administrator-selected roots."""

    def __init__(self, predecessor_state, native_state):
        self._roots = {"predecessor": _root_path(predecessor_state),
                       "native": _root_path(native_state)}
        self._pins = {}
        try:
            with _Observation() as observation:
                for backend, root in self._roots.items():
                    _, self._pins[backend] = observation.root(root)
                if len({pin[:2] for pin in self._pins.values()}) != 2:
                    raise UnsafeWorkflowOwner("workflow_distinct_roots_required")
        except OSError as exc:
            raise UnsafeWorkflowOwner("workflow_fixed_root_unavailable") from exc

    @staticmethod
    def _membership(observation, root, kind, identity):
        if kind == "audit":
            owners = []
            for folder in ("request-audit", "request-archive-v11"):
                directory = observation.store(root, (folder,))
                owner = _record(observation, directory, identity, "request_id")
                if owner is not None:
                    owners.append(owner)
            if len(set(owners)) > 1:
                raise UnsafeWorkflowOwner("workflow_audit_owner_disagreement")
            return bool(owners)
        components, field = KINDS[kind]
        return _record(observation, observation.store(root, components), identity, field) is not None

    def owner(self, kind, identity):
        if (not isinstance(kind, str) or kind not in KINDS and kind != "audit"
                or not _identity(identity)):
            raise UnsafeWorkflowOwner("workflow_closed_kind_and_identity_required")
        found = []
        try:
            with _Observation() as observation:
                for backend, root in self._roots.items():
                    descriptor, _ = observation.root(root, self._pins[backend])
                    if self._membership(observation, descriptor, kind, identity):
                        found.append(backend)
                if len(found) > 1:
                    raise UnsafeWorkflowOwner("workflow_cross_controller_collision")
        except OSError as exc:
            raise UnsafeWorkflowOwner("workflow_membership_unavailable") from exc
        return found[0] if found else "absent"

    def assert_native_effect_registries_empty(self):
        try:
            with _Observation() as observation:
                descriptor, _ = observation.root(self._roots["native"], self._pins["native"])
                _empty_effect_registries(observation, descriptor)
        except OSError as exc:
            raise UnsafeWorkflowOwner("workflow_native_registry_unavailable") from exc


def _empty_effect_registries(observation, root):
    for folder in ("jobs", "terminals"):
        directory = observation.store(root, (folder,), private=False)
        if directory is None:
            continue
        info = os.fstat(directory)
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise UnsafeWorkflowOwner("workflow_native_registry_not_trusted")
        with os.scandir(directory) as entries:
            if next(entries, None) is not None:
                raise UnsafeWorkflowOwner("workflow_native_effect_registry_not_empty")


def assert_native_effect_registries_empty(native_state):
    """Standalone preflight for a fixed administrator-configured native root."""
    try:
        with _Observation() as observation:
            descriptor, _ = observation.root(_root_path(native_state))
            _empty_effect_registries(observation, descriptor)
    except OSError as exc:
        raise UnsafeWorkflowOwner("workflow_native_registry_unavailable") from exc
