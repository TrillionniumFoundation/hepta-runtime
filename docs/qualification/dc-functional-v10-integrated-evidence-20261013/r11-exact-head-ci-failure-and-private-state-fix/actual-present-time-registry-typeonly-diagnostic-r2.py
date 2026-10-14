# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""SOURCE-ONLY proposal. Root must review and explicitly launch; do not auto-run.

Read one strict, pinned registry snapshot through the unmodified a198 reader.
Output fixed phases, file metadata, and a fixed JSON field-type whitelist only.
Never access a credential path, instantiate a client, call RPC, or write files.
This present-time probe cannot establish the historical R39 cause.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import stat
import sys
import types


SOURCE = "/home/qian-qi/hepta-runtime-dc-functional-20261013/deploy/dc_successor_inventory.py"
SOURCE_SHA256 = "a198944235a8b71763a612d077bf41c8915028487beb96888da003868e24e5c9"
SOURCE_LIMIT = 1024 * 1024
KNOWN_R39_JOB = "1a137f7ea32-b2f-d42"
STAT_FIELDS = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
               "st_size", "st_mtime_ns", "st_ctime_ns")
FIELD_NAMES = (
    "id", "host", "executable", "args", "cwd", "env", "created_ms", "unit",
    "launch_state", "state", "pid", "backend", "launch_nonce",
    "status_authoritative", "launch_nonce_present", "supervisor_binding_verified",
)
PHASES = {
    215: "credential_identity_required", 217: "credential_identity_shape",
    228: "deadline_before_open", 229: "ancestor_open",
    231: "parent_private_metadata", 233: "registry_open",
    238: "registry_private_metadata", 239: "registry_enumerate",
    242: "entry_count_cap", 244: "deadline_before_entry",
    246: "entry_name_shape", 247: "entry_open",
    250: "entry_metadata_before", 253: "credential_alias",
    254: "entry_private_metadata_before", 256: "record_size_cap",
    259: "deadline_before_read", 260: "record_read",
    264: "entry_metadata_after", 265: "entry_private_metadata_after",
    266: "linked_entry_metadata", 268: "entry_stat_drift",
    270: "record_read_length", 271: "json_parse",
    273: "json_object_shape", 274: "id_host_shape",
    276: "id_host_binding", 282: "registry_metadata_after",
    283: "linked_registry_metadata", 284: "registry_private_metadata_after",
    285: "parent_private_metadata_after", 286: "registry_reenumerate",
    290: "registry_names_or_metadata_drift", 296: "inventory_error_conversion",
    298: "unexpected_error_conversion",
}
SAFE_EXCEPTION_TYPES = frozenset({
    "DiagnosticRefused", "InventoryError", "RegistryError", "FileNotFoundError", "NotADirectoryError",
    "PermissionError", "IsADirectoryError", "BlockingIOError", "InterruptedError",
    "OSError", "ValueError", "TypeError", "OverflowError",
})


class DiagnosticRefused(Exception):
    pass


class FixedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default includes unknown argument values in stderr.
        raise DiagnosticRefused()

    def exit(self, status=0, message=None):
        raise DiagnosticRefused()


def canonical_path(value):
    path = pathlib.Path(value)
    if (not path.is_absolute() or not path.name or ".." in path.parts
            or str(path) != value or any(ord(c) < 32 for c in value)):
        raise DiagnosticRefused()
    return path


def metadata(info):
    if stat.S_ISREG(info.st_mode):
        kind = "regular"
    elif stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISLNK(info.st_mode):
        kind = "symlink"
    elif stat.S_ISFIFO(info.st_mode):
        kind = "fifo"
    else:
        kind = "other"
    return {**{field: int(getattr(info, field)) for field in STAT_FIELDS},
            "kind": kind}


def stat_pin(info):
    return tuple(getattr(info, field) for field in STAT_FIELDS)


def open_parent(path):
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def source_bytes(path_value, expected_sha256, credential_pair):
    """Source hashing only; reject credential inode before reading any bytes."""
    path = canonical_path(path_value)
    parent = descriptor = None
    try:
        parent = open_parent(path)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) == credential_pair
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) not in (0o400, 0o600, 0o644)
                or before.st_size > SOURCE_LIMIT):
            raise DiagnosticRefused()
        raw = bytearray()
        while len(raw) <= SOURCE_LIMIT:
            chunk = os.read(descriptor, min(65536, SOURCE_LIMIT + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (stat_pin(before) != stat_pin(after) or stat_pin(after) != stat_pin(linked)
                or len(raw) != before.st_size or len(raw) > SOURCE_LIMIT
                or hashlib.sha256(raw).hexdigest() != expected_sha256):
            raise DiagnosticRefused()
        return bytes(raw)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def registry_metadata(path_value, expected_pair):
    path = canonical_path(path_value)
    if path.name != "jobs":
        raise DiagnosticRefused()
    parent = descriptor = None
    try:
        parent = open_parent(path)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        before_parent = os.fstat(parent)
        before = os.fstat(descriptor)
        linked = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        after = os.fstat(descriptor)
        after_parent = os.fstat(parent)
        for info in (before_parent, after_parent, before, after, linked):
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise DiagnosticRefused()
        if ((before.st_dev, before.st_ino) != expected_pair
                or stat_pin(before) != stat_pin(after)
                or stat_pin(after) != stat_pin(linked)
                or (before_parent.st_dev, before_parent.st_ino,
                    before_parent.st_uid, before_parent.st_gid, before_parent.st_mode)
                != (after_parent.st_dev, after_parent.st_ino,
                    after_parent.st_uid, after_parent.st_gid, after_parent.st_mode)):
            raise DiagnosticRefused()
        return metadata(after)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def json_type(value):
    names = {type(None): "null", bool: "boolean", int: "integer", float: "number",
             str: "string", list: "array", dict: "object"}
    return names.get(type(value), "unsupported")


def fixed_error_type(exc):
    name = type(exc).__name__
    return name if name in SAFE_EXCEPTION_TYPES else "OtherException"


def capture_reader_exception(frame, exception_tuple, observer):
    """No locals/values/messages are returned; only explicit safe projections."""
    exc = exception_tuple[1]
    values = frame.f_locals
    result = {
        "reader_line": frame.f_lineno,
        "phase": PHASES.get(frame.f_lineno, "unmapped_reader_phase"),
        "exception_type": fixed_error_type(exc),
        "public_code": exc.code if isinstance(exc, observer.InventoryError) else None,
    }
    names, name = values.get("names"), values.get("name")
    if isinstance(names, list):
        result["observed_directory_entry_count"] = len(names)
        result["count_is_actual_job_total"] = False
        # Outside this interval name is the last successful iteration, not the
        # cause of a final registry-directory error.
        if 244 <= frame.f_lineno <= 278 and isinstance(name, str) and name in names:
            result["entry_ordinal"] = names.index(name) + 1
            result["entry_name_shape"] = {
                "length": len(name),
                "ends_json": name.endswith(".json"),
                "valid_id_json": bool(name.endswith(".json") and
                                      observer.ID.fullmatch(name[:-5])),
                "publisher_tmp_shape": bool(re.fullmatch(r".+\.json\.tmp\.[0-9]+", name)),
                "matches_known_r39_json": name == KNOWN_R39_JOB + ".json",
                "matches_known_r39_tmp_prefix": name.startswith(KNOWN_R39_JOB + ".json.tmp."),
            }
    # Previous-loop stat locals remain in the original reader. Only project a
    # record stat after the current iteration has assigned it at its source line.
    stat_keys = ["before_directory", "after_directory", "parent_before", "linked_directory"]
    if 252 <= frame.f_lineno <= 278:
        stat_keys.append("before")
    if 265 <= frame.f_lineno <= 278:
        stat_keys.append("after")
    if 267 <= frame.f_lineno <= 278:
        stat_keys.append("linked")
    for key in stat_keys:
        value = values.get(key)
        if isinstance(value, os.stat_result):
            result[key + "_metadata"] = metadata(value)
    child, descriptor = values.get("child"), values.get("descriptor")
    if type(child) is int and 250 <= frame.f_lineno <= 278:
        try:
            result["current_fd_metadata"] = metadata(os.fstat(child))
        except OSError as error:
            result["current_fd_metadata_error"] = fixed_error_type(error)
    if (244 <= frame.f_lineno <= 278 and type(descriptor) is int
            and isinstance(name, str) and isinstance(names, list) and name in names):
        try:
            result["current_linked_metadata"] = metadata(
                os.stat(name, dir_fd=descriptor, follow_symlinks=False))
        except OSError as error:
            result["current_linked_metadata_error"] = fixed_error_type(error)
    if "row" in values and 273 <= frame.f_lineno <= 276:
        row = values["row"]
        result["row_type"] = json_type(row)
        if type(row) is dict:
            result["fixed_field_types"] = {
                field: {"present": field in row,
                        "type": json_type(row[field]) if field in row else None}
                for field in FIELD_NAMES
            }
    return result


def main():
    parser = FixedArgumentParser(description=__doc__)
    parser.add_argument("--expected-driver-sha256", required=True)
    parser.add_argument("--registry-dir", required=True)
    parser.add_argument("--expected-registry-dev", required=True, type=int)
    parser.add_argument("--expected-registry-ino", required=True, type=int)
    parser.add_argument("--expected-token-dev", required=True, type=int)
    parser.add_argument("--expected-token-ino", required=True, type=int)
    parser.add_argument("--budget-seconds", type=float, default=60.0)
    report = {
        "schema": "hepta-r39-registry-typeonly-diagnostic/v1",
        "qualification": "HOLD", "historical_r39_cause_established": False,
        "actual_job_total": None, "full_dc_replacement": False,
        "rpc_called_by_this_driver": False, "record_payload_hash": False,
        "raw_record_or_values_persisted": False, "credential_path_access": False,
        "credential_inode_is_external_metadata_pin": True,
        "root_must_guard_live_credential_metadata_before_after": True,
        "registry_dir_requires_root_binding_to_pinned_stage": True,
        "reader_called": False, "reader_complete": False,
        "deadline_is_checkpoint_not_os_syscall_interrupt": True,
        "pty_complete": False, "stream_complete": False,
        "dispatch_complete": False, "admission_complete": False,
    }
    try:
        args = parser.parse_args()
        credential_pair = (args.expected_token_dev, args.expected_token_ino)
        registry_pair = (args.expected_registry_dev, args.expected_registry_ino)
        if (os.getuid() != 1000 or credential_pair[0] < 0 or credential_pair[1] <= 0
                or registry_pair[0] < 0 or registry_pair[1] <= 0
                or not re.fullmatch(r"[0-9a-f]{64}", args.expected_driver_sha256)
                or not math.isfinite(args.budget_seconds)
                or not 0 < args.budget_seconds <= 60):
            raise DiagnosticRefused()
        own = source_bytes(str(pathlib.Path(__file__).absolute()),
                           args.expected_driver_sha256, credential_pair)
        del own
        raw_source = source_bytes(SOURCE, SOURCE_SHA256, credential_pair)
        report["source_sha256"] = SOURCE_SHA256
        report["registry_before_metadata"] = registry_metadata(args.registry_dir, registry_pair)
        module_name = "_hepta_r39_registry_diagnostic_pinned_a198"
        if module_name in sys.modules or sys.gettrace() is not None:
            raise DiagnosticRefused()
        observer = types.ModuleType(module_name)
        observer.__file__ = SOURCE
        sys.modules[module_name] = observer
        try:
            exec(compile(raw_source, SOURCE, "exec"), observer.__dict__)
            del raw_source
            first = []

            def trace(frame, event, argument):
                if frame.f_code is not observer.read_registry.__code__:
                    return None
                if event == "exception" and not first:
                    first.append(capture_reader_exception(frame, argument, observer))
                return trace

            snapshot = None
            try:
                report["reader_called"] = True
                sys.settrace(trace)
                try:
                    snapshot = observer.read_registry(
                        args.registry_dir, hosts=observer.HOSTS,
                        credential_identity=credential_pair,
                        deadline=observer.Deadline(args.budget_seconds), fixture=False)
                    report["reader_returned_normally"] = True
                except observer.RegistryError as error:
                    snapshot = error.partial
                    report["reader_returned_normally"] = False
                    report["primary_public_error"] = error.code
            finally:
                sys.settrace(None)
            report["first_reader_exception"] = first[0] if first else None
            report["first_exception_may_have_been_handled"] = bool(first)
            if snapshot is not None:
                report["reader_complete"] = snapshot.complete is True
                report["reader_missing"] = snapshot.missing is True
                report["validated_prefix_count"] = len(snapshot.jobs)
                report["known_r39_job_in_validated_prefix"] = KNOWN_R39_JOB in snapshot.jobs
                report["known_r39_job_absence_is_not_full_absence_proof"] = not snapshot.complete
            report["registry_after_metadata"] = registry_metadata(args.registry_dir, registry_pair)
            report["registry_metadata_stable"] = (
                report["registry_before_metadata"] == report["registry_after_metadata"])
            checked = source_bytes(SOURCE, SOURCE_SHA256, credential_pair)
            del checked
            own_checked = source_bytes(str(pathlib.Path(__file__).absolute()),
                                       args.expected_driver_sha256, credential_pair)
            del own_checked
            report["source_before_after_pinned"] = True
            report["validation_completed"] = True
        finally:
            sys.modules.pop(module_name, None)
    except BaseException as error:
        report["validation_completed"] = False
        report["diagnostic_failure_type"] = fixed_error_type(error)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
