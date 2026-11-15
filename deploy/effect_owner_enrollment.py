#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only attestation of actual V4/V10/V11 admission-fence enrollment.

This only establishes necessary prerequisites for a later maintenance handoff.
It never changes a unit, rotates a token, freezes the owner, or promotes V11.
The public report omits raw environment, configured paths, tokens and argv.
"""
from __future__ import annotations

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

UNITS = {"v4": "hepta-runtime-operator.service",
         "v10": "hepta-runtime-successor-canary.service",
         "v11": "hepta-runtime-v11.service"}
KEYS = frozenset(("HEPTA_EFFECT_OWNER_FENCE_DIR",
                  "HEPTA_EFFECT_OWNER_FENCE_REQUIRED",
                  "HEPTA_EFFECT_OWNER_SELF"))
SCHEMA = "hepta-effect-owner-fence-v1"
MAX_PROC_BYTES = 1024 * 1024


def strict_json(raw: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def selected_environ(raw: bytes) -> dict:
    if len(raw) > MAX_PROC_BYTES or not raw.endswith(b"\0"):
        raise ValueError("incomplete_environment")
    selected = {}
    for assignment in raw.rstrip(b"\0").split(b"\0"):
        key, sep, val = assignment.partition(b"=")
        if not sep:
            raise ValueError("invalid_environment")
        if key.decode("ascii", errors="replace") not in KEYS:
            continue
        key = key.decode("ascii")
        if key in selected:
            raise ValueError("duplicate_fence_environment")
        selected[key] = val.decode("utf-8")
    return selected


def start_ticks(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2:].split()[19]


def observe_unit(role: str) -> dict:
    unit = UNITS[role]
    proc = subprocess.run(
        ["systemctl", "--user", "show", unit,
         "-p", "ActiveState", "-p", "MainPID", "-p", "LoadState"],
        capture_output=True, text=True, timeout=8, check=True)
    fields = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    pid = int(fields.get("MainPID", 0))
    if fields.get("ActiveState") != "active" or pid <= 0:
        raise ValueError("unit_not_running")
    before = start_ticks(pid)
    env = selected_environ(Path(f"/proc/{pid}/environ").read_bytes())
    args = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
    if args.count(b"--runtime-config") != 1:
        raise ValueError("runtime_configuration_not_unique")
    index = args.index(b"--runtime-config")
    if index + 1 >= len(args):
        raise ValueError("runtime_configuration_missing")
    config_path = Path(os.fsdecode(args[index + 1]))
    config = strict_json(config_path.read_bytes())
    state_root = config.get("state_dir")
    if not isinstance(state_root, str) or not os.path.isabs(state_root):
        raise ValueError("runtime_state_root_invalid")
    # The actual running executable is attested, not merely unit-file text.
    exe = Path(os.readlink(f"/proc/{pid}/exe"))
    exe_digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    if before != start_ticks(pid):
        raise ValueError("process_changed_during_inspection")
    return {"role": role, "pid": pid, "runtime_binary_sha256": exe_digest,
            "env": env, "state_root": state_root, "load_state": fields.get("LoadState")}


def _private_directory(path: str) -> int:
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        raise ValueError("invalid_private_authority_root")
    components = path.split("/")
    if any(part in (".", "..", "") for part in components[1:]):
        raise ValueError("special_authority_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in components[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                              os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("authority_root_not_private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _private_file(rootfd: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                 os.O_NONBLOCK, dir_fd=rootfd)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise ValueError("authority_record_not_private")
    return fd


def inspect_authority(path: str) -> dict:
    fd = _private_directory(path)
    lockfd = -1
    try:
        lockfd = _private_file(fd, ".owner.lock")
        fcntl.flock(lockfd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        recfd = _private_file(fd, ".owner.json")
        try:
            before = os.fstat(recfd)
            if not 0 < before.st_size <= 4096:
                raise ValueError("authority_size_invalid")
            raw = os.read(recfd, 4097)
            after = os.fstat(recfd)
            other_fd = _private_file(fd, ".owner.json")
            try:
                other = os.fstat(other_fd)
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                            after.st_mtime_ns, after.st_ctime_ns) or (
                    before.st_dev, before.st_ino, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns) != (
                    other.st_dev, other.st_ino, other.st_size,
                    other.st_mtime_ns, other.st_ctime_ns):
                    raise ValueError("authority_record_changed")
            finally:
                os.close(other_fd)
            record = strict_json(raw)
            if (record.get("schema") != SCHEMA
                    or record.get("owner") not in ("v4", "v11")
                    or record.get("phase") not in ("admitting", "frozen")
                    or type(record.get("epoch")) is not int
                    or record["epoch"] < 1):
                raise ValueError("authority_schema_invalid")
            # A current pathname must still name the pinned authority and
            # lock inodes; held-open descriptors alone are not sufficient.
            another_lock = _private_file(fd, ".owner.lock")
            try:
                first, final = os.fstat(lockfd), os.fstat(another_lock)
                if (first.st_dev, first.st_ino) != (final.st_dev, final.st_ino):
                    raise ValueError("authority_lock_replaced")
            finally:
                os.close(another_lock)
            another_root = _private_directory(path)
            try:
                first, final = os.fstat(fd), os.fstat(another_root)
                if (first.st_dev, first.st_ino) != (final.st_dev, final.st_ino):
                    raise ValueError("authority_root_rebound")
            finally:
                os.close(another_root)
            return record
        finally:
            os.close(recfd)
    finally:
        if lockfd >= 0:
            os.close(lockfd)
        os.close(fd)


def assess(observed: dict, authority: dict | None,
           expected_binary_sha256: str | None = None) -> dict:
    problems = []
    if set(observed) != set(UNITS):
        problems.append("controller_inventory_incomplete")
    for role in UNITS:
        item = observed.get(role, {})
        if not item.get("pid"):
            problems.append(f"{role}_controller_not_observed")
            continue
        flags = item.get("env", {})
        if flags.get("HEPTA_EFFECT_OWNER_FENCE_REQUIRED") != "1":
            problems.append(f"{role}_fence_not_enforced")
        if role in ("v4", "v11") and flags.get("HEPTA_EFFECT_OWNER_SELF") != role:
            problems.append(f"{role}_owner_identity_not_bound")
        # The V10 predecessor must be an explicit reject-all effect ingress:
        # required=1 with NO directory/owner pair is rejected by native fence.
        # It can continue serving its existing read handles and cancellations.
        if role == "v10" and any(key in flags for key in (
                "HEPTA_EFFECT_OWNER_FENCE_DIR", "HEPTA_EFFECT_OWNER_SELF")):
            problems.append("v10_must_not_claim_new_effect_owner")
        if (expected_binary_sha256 is not None
                and item.get("runtime_binary_sha256") != expected_binary_sha256):
            problems.append(f"{role}_unreviewed_binary")
    if expected_binary_sha256 is None:
        problems.append("reviewed_binary_sha256_not_supplied")
    v4, v11 = observed.get("v4", {}), observed.get("v11", {})
    fence_dir = v4.get("env", {}).get("HEPTA_EFFECT_OWNER_FENCE_DIR")
    if (not fence_dir or fence_dir != v11.get("env", {}).get("HEPTA_EFFECT_OWNER_FENCE_DIR")):
        problems.append("controller_fence_root_not_shared")
    if v4.get("state_root") == v11.get("state_root"):
        problems.append("successor_state_not_independent")
    predecessor = observed.get("v10", {})
    if predecessor.get("state_root") in (
            v4.get("state_root"), v11.get("state_root")):
        problems.append("predecessor_state_aliases_effect_owner")
    if authority is None:
        problems.append("authority_not_verified")
    else:
        if authority.get("owner") != "v4" or authority.get("phase") not in ("admitting", "frozen"):
            problems.append("unexpected_authority_owner_or_phase")
        if authority.get("state_root") != v4.get("state_root"):
            problems.append("authority_v4_state_binding_mismatch")
    # Never certify a switch based on a config check. The native promotion
    # still requires freeze/drain, identity replay and a reviewed ownerctl path.
    return {"schema": "hepta-live-owner-enrollment-preflight-v1",
            "stage": "READY_FOR_FROZEN_PHASE_TEST_ONLY" if not problems else "HOLD",
            "cutover_authorized": False, "checks_failed": sorted(set(problems)),
            "unit_presence": {k: bool(observed.get(k, {}).get("pid")) for k in UNITS},
            "all_fence_required": all(observed.get(k, {}).get("env", {}).get(
                "HEPTA_EFFECT_OWNER_FENCE_REQUIRED") == "1" for k in UNITS),
            "authority_owner": authority.get("owner") if authority else None,
            "authority_phase": authority.get("phase") if authority else None,
            "v11_execution_migration_proven": False,
            "raw_paths_environment_tokens_not_emitted": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewed-binary-sha256", help="Exact attested native release SHA256")
    parser.add_argument("--out", help="Optional create-only private JSON receipt")
    args = parser.parse_args()
    if args.reviewed_binary_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", args.reviewed_binary_sha256):
        parser.error("reviewed binary SHA256 must be 64 lowercase hex digits")
    observed, errors = {}, []
    for role in UNITS:
        try:
            observed[role] = observe_unit(role)
        except Exception:
            errors.append(role + "_observation_unavailable")
    authority = None
    roots = [observed.get(role, {}).get("env", {}).get("HEPTA_EFFECT_OWNER_FENCE_DIR")
             for role in ("v4", "v11")]
    if roots[0] and roots[0] == roots[1]:
        try:
            authority = inspect_authority(roots[0])
        except Exception:
            errors.append("owner_authority_unavailable")
    result = assess(observed, authority, args.reviewed_binary_sha256)
    result["checks_failed"] = sorted(set(result["checks_failed"] + errors))
    if errors:
        result["stage"] = "HOLD"
    result["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["stage"] != "HOLD" else 2


if __name__ == "__main__":
    raise SystemExit(main())
