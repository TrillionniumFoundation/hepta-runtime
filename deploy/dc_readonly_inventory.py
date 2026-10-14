#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Read-only configured-host archive inventory; no admission, actions, signals, or cleanup.

Reads configured operator account metadata and verifies named target archive
receipts. A matched exit receipt is not proof of a production cutover or a
coherent global admission freeze. Private results are created with mode 0600.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import stat
import subprocess
import sys
import time

import inventory_host_readonly as core

MAX_TRANSPORT_STDOUT = 8 * 1024 * 1024
MAX_TRANSPORT_STDERR = 64 * 1024
MAX_TRANSPORT_INPUT = 8 * 1024 * 1024
MAX_HOSTS = 16
MAX_WORKERS = 2
MAX_CONTROLLER_ENTRIES = 16_384


class InventoryError(Exception):
    """Does not contain remote command lines or raw terminal output."""


def source_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_private(path: Path, data: object) -> None:
    raw = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as sink:
        sink.write(raw)
        sink.flush()
        os.fsync(sink.fileno())


def bounded_capture(argv: list[str], payload: bytes, *, timeout: int = 100,
                    max_stdout: int = MAX_TRANSPORT_STDOUT,
                    max_stderr: int = MAX_TRANSPORT_STDERR) -> bytes:
    if len(payload) > MAX_TRANSPORT_INPUT:
        raise InventoryError("input_limit")
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True
    )
    assert process.stdin is not None and process.stdout is not None
    assert process.stderr is not None
    streams = {
        "stdin": process.stdin, "stdout": process.stdout, "stderr": process.stderr
    }
    selector = selectors.DefaultSelector()
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    sent = 0
    deadline = time.monotonic() + min(max(timeout, 1), 120)
    try:
        for name, pipe in streams.items():
            os.set_blocking(pipe.fileno(), False)
            selector.register(
                pipe,
                selectors.EVENT_WRITE if name == "stdin" else selectors.EVENT_READ,
                name
            )
        if not payload:
            selector.unregister(process.stdin)
            process.stdin.close()
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise InventoryError("transport_timeout")
            for key, _ in selector.select(timeout=min(0.3, deadline - time.monotonic())):
                name = key.data
                pipe = key.fileobj
                if name == "stdin":
                    try:
                        count = os.write(pipe.fileno(), payload[sent:sent + 65536])
                    except BrokenPipeError:
                        selector.unregister(pipe)
                        pipe.close()
                        raise InventoryError("remote_closed_input_early")
                    sent += count
                    if sent == len(payload):
                        selector.unregister(pipe)
                        pipe.close()
                    continue
                data = os.read(pipe.fileno(), 65536)
                if not data:
                    selector.unregister(pipe)
                    pipe.close()
                    continue
                bound = max_stdout if name == "stdout" else max_stderr
                if len(buffers[name]) + len(data) > bound:
                    raise InventoryError(name + "_bound_exceeded")
                buffers[name].extend(data)
        if process.wait(timeout=5) != 0:
            raise InventoryError("remote_helper_nonzero")
        return bytes(buffers["stdout"])
    finally:
        selector.close()
        for pipe in streams.values():
            if not pipe.closed:
                pipe.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def read_private_config(path: Path) -> dict:
    """Reject symlinks, changed bytes and unbounded config before parsing."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_size > 1024 * 1024
                or (before.st_mode & 0o022)):
            raise InventoryError("config_identity_or_mode")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        leaf = os.stat(path, follow_symlinks=False)
        if (len(raw) != before.st_size
                or core.version(before) != core.version(after)
                or core.version(after) != core.version(leaf)):
            raise InventoryError("config_changed")
        return core.strict_json(raw)
    finally:
        os.close(fd)


def check_config(config: dict, expected_hosts: list[str] | None) -> tuple[Path, dict]:
    if type(config) is not dict:
        raise InventoryError("invalid_config")
    configured = config.get("hosts")
    if not isinstance(configured, dict) or not 1 <= len(configured) <= MAX_HOSTS:
        raise InventoryError("invalid_host_count")
    if expected_hosts is not None and set(configured) != set(expected_hosts):
        raise InventoryError("host_set_mismatch")
    state = config.get("state_dir")
    if not isinstance(state, str) or not state.startswith("/"):
        raise InventoryError("invalid_controller_state_root")
    for name, host in configured.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
            raise InventoryError("invalid_host_name")
        if not isinstance(host, dict):
            raise InventoryError("invalid_host_record")
        if host.get("platform") not in ("linux", "macos"):
            raise InventoryError("unsupported_host_platform")
        for key in ("remote_state_dir", "ssh_target"):
            value = host.get(key)
            if not isinstance(value, str) or not value or len(value) > 1024:
                raise InventoryError("missing_target_binding")
        # The configured SSH destination must be one literal alias/address
        # argument, never a leading dash or source of extra SSH options.
        if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]{0,127}", host["ssh_target"]) is None:
            raise InventoryError("invalid_ssh_target")
        if not host["remote_state_dir"].startswith("/") or ".." in Path(host["remote_state_dir"]).parts:
            raise InventoryError("invalid_remote_root")
    return Path(state), configured


def scan_controller(state: Path, hosts: dict) -> tuple[dict, list, dict, dict]:
    rows = {name: [] for name in hosts}
    unresolved = []
    snapshots: dict[str, dict] = {}
    manifests: dict[str, str] = {}
    budget = [0]
    for kind in ("jobs", "terminals"):
        dirfd = core.open_directory(str(state / kind), observe_group_writable=True)
        try:
            names = core.bounded_names(dirfd, limit=MAX_CONTROLLER_ENTRIES)
            snapshots[kind] = {"before": names}
            for filename in names:
                try:
                    if not filename.endswith(".json"):
                        raise core.Refusal("uncommitted_or_other_entry")
                    value, hash_value = core.read_record(dirfd, filename, budget)
                    field = "id" if kind == "jobs" else "session_id"
                    uid = value.get(field)
                    host_name = value.get("host")
                    if not isinstance(uid, str) or filename != uid + ".json" or host_name not in hosts:
                        raise core.Refusal("controller_record_identity")
                    configured = hosts[host_name]
                    target = configured["remote_state_dir"].rstrip("/") + "/" + kind + "/" + uid
                    pathkey = "remote_job_dir" if kind == "jobs" else "job_dir"
                    if value.get("ssh_target") != configured["ssh_target"] or value.get(pathkey) != target:
                        raise core.Refusal("remote_target_binding")
                    if kind == "terminals" and value.get("remote_state_dir") != configured["remote_state_dir"]:
                        raise core.Refusal("terminal_root_binding")
                    row = {"kind": kind, "id": uid}
                    if kind == "jobs":
                        if value.get("execution_mode") != "operator" or value.get("system_jobctl") is not False:
                            raise core.Refusal("unsupported_job_backend")
                        fingerprint = value.get("request_fingerprint")
                        if type(fingerprint) is not int or not 0 <= fingerprint < 2**64:
                            raise core.Refusal("invalid_request_fingerprint")
                        digest = value.get("request_digest")
                        if digest is not None:
                            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                                raise core.Refusal("invalid_request_digest")
                            row["fingerprint"] = digest
                        else:
                            row["fingerprint"] = f"{fingerprint:016x}"
                    rows[host_name].append(row)
                    manifests[kind + "/" + filename] = hash_value
                except (OSError, ValueError, TypeError, KeyError, core.Refusal) as error:
                    unresolved.append({
                        "kind": kind, "name": filename,
                        "reason": str(error) if isinstance(error, core.Refusal) else type(error).__name__
                    })
            snapshots[kind]["after_local_scan"] = core.bounded_names(dirfd, limit=MAX_CONTROLLER_ENTRIES)
        finally:
            os.close(dirfd)
    return rows, unresolved, snapshots, manifests


def host_observation(
    name: str, host: dict, rows: list, helper_source: bytes
) -> dict:
    payload = json.dumps({
        "host": name, "platform": host["platform"],
        "root": host["remote_state_dir"], "rows": rows
    }, separators=(",", ":")).encode()
    argv = [
        "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
        host["ssh_target"],
        "python3 -c " + shlex.quote(helper_source.decode())
    ]
    try:
        raw = bounded_capture(argv, payload)
        result = core.strict_json(raw)
        if not isinstance(result, dict) or result.get("host") != name or result.get("schema") != core.SCHEMA:
            raise InventoryError("invalid_host_response_binding")
        actual_rows = result.get("rows")
        if not isinstance(actual_rows, list) or len(actual_rows) != len(rows):
            raise InventoryError("missing_or_extra_host_rows")
        expected = {(x["kind"], x["id"]) for x in rows}
        actual = [(x.get("kind"), x.get("id")) for x in actual_rows]
        if len(set(actual)) != len(actual) or set(actual) != expected:
            raise InventoryError("duplicated_or_unmatched_host_rows")
        return result
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError,
            UnicodeError, core.Refusal, InventoryError) as error:
        return {
            "schema": core.SCHEMA, "host": name, "rows": [],
            "requested_count": len(rows),
            "transport_error": str(error) if isinstance(error, InventoryError) else type(error).__name__,
            "metadata_scan_finished": False, "all_records_resolved": False,
            "observation_only_not_authorization": True
        }


def final_controller_reread(state: Path, snapshots: dict, manifests: dict) -> tuple[bool, list]:
    changed = []
    reread_budget = [0]
    for kind in ("jobs", "terminals"):
        fd = core.open_directory(str(state / kind), observe_group_writable=True)
        try:
            snapshots[kind]["after_remote_scan"] = core.bounded_names(fd, limit=MAX_CONTROLLER_ENTRIES)
            for name, expected in manifests.items():
                prefix, _, leaf = name.partition("/")
                if prefix != kind:
                    continue
                try:
                    _, actual = core.read_record(fd, leaf, reread_budget)
                    if actual != expected:
                        changed.append(name)
                except (OSError, ValueError, TypeError, KeyError, core.Refusal):
                    changed.append(name)
        finally:
            os.close(fd)
    stable = not changed and all(
        v["before"] == v["after_local_scan"] == v["after_remote_scan"]
        for v in snapshots.values()
    )
    return stable, changed


def inspect_known_dc_processes(identities: list[str]) -> list[dict]:
    result = []
    for item in identities:
        if not re.fullmatch(r"[1-9][0-9]{0,9}:[1-9][0-9]{0,15}", item):
            raise InventoryError("invalid_dc_identity")
        pid, ticks = map(int, item.split(":"))
        if pid <= 1 or pid > 2147483647:
            raise InventoryError("invalid_dc_pid")
        proc = Path("/proc") / str(pid)
        try:
            raw = (proc / "stat").read_text()
            after = raw[raw.rfind(")") + 2:].split()
            observed_ticks = int(after[19])
            rec = {
                "pid": pid, "present": True,
                "start_identity_match": observed_ticks == ticks,
                "uid_match": proc.stat().st_uid == os.getuid(),
                "process_state": after[0]
            }
        except (FileNotFoundError, ProcessLookupError):
            rec = {"pid": pid, "present": False}
        except (OSError, ValueError, IndexError):
            rec = {"pid": pid, "observation_unknown": True}
        result.append(rec)
    return result


def run(args: argparse.Namespace) -> tuple[Path, dict]:
    output = Path(args.output)
    if output.exists():
        raise InventoryError("output_exists")
    config = read_private_config(Path(args.config))
    state, hosts = check_config(config, args.hosts)
    helper_path = Path(__file__).with_name("inventory_host_readonly.py")
    helper_source = helper_path.read_bytes()
    if len(helper_source) > 128 * 1024:
        raise InventoryError("remote_helper_source_bound")
    helper_sha = source_sha256(helper_source)
    output.mkdir(mode=0o700)
    if stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise InventoryError("output_directory_not_private")
    start = time.time()
    rows, unresolved, snapshots, manifests = scan_controller(state, hosts)
    write_private(output / "controller-manifest.json", manifests)
    answers = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        pending = {
            name: pool.submit(host_observation, name, host, rows[name], helper_source)
            for name, host in hosts.items()
        }
        for name, future in pending.items():
            answer = future.result()
            answers[name] = answer
            write_private(output / (name + ".json"), answer)
    stable, changed = final_controller_reread(state, snapshots, manifests)
    if source_sha256(helper_path.read_bytes()) != helper_sha:
        raise InventoryError("helper_source_mutated")
    host_summaries = {}
    for name, answer in answers.items():
        state_counts = {
            kind: dict(collections.Counter(
                row["state"] for row in answer["rows"] if row["kind"] == kind
            )) for kind in ("jobs", "terminals")
        }
        unresolved_rows = [
            {key: row.get(key) for key in ("id", "kind", "state", "reason", "recorded_owner_pid")}
            for row in answer["rows"]
            if row.get("state") in ("unknown", "nonterminal_or_missing_receipt")
        ]
        host_summaries[name] = {
            "state_counts": state_counts,
            "requested_rows": len(rows[name]),
            "returned_rows": len(answer["rows"]),
            "observation_complete": answer["metadata_scan_finished"],
            "all_records_resolved": answer["all_records_resolved"],
            "source_root_integrity_qualified": False,
            "observed_root_mode": answer.get("root_mode"),
            "root_group_writable": answer.get("root_group_writable"),
            "output_size_and_receipt_verified": sum(
                bool(row.get("output_verified_by_size_and_receipt", False))
                for row in answer["rows"]
            ),
            "residual_rows": unresolved_rows,
            "transport_error": answer.get("transport_error")
        }
    report = {
        "schema": "hepta-configured-host-readonly-inventory-v1",
        "started_unix": start, "finished_unix": time.time(),
        "helper_source_sha256": helper_sha,
        "controller_manifest_sha256": source_sha256(
            (output / "controller-manifest.json").read_bytes()
        ),
        "configured_hosts": sorted(hosts),
        "controller_records_selected": len(manifests),
        "controller_unresolved_entries": unresolved,
        "controller_record_changes": changed,
        "controller_cohort_stable": stable,
        "observations": host_summaries,
        "known_dc_processes": inspect_known_dc_processes(args.dc_identity),
        "every_host_response_complete": all(
            answer.get("metadata_scan_finished") is True for answer in answers.values()
        ),
        "count_matched": len(manifests) == sum(
            len(a.get("rows", [])) for a in answers.values()
        ),
        "private_raw_receipts_retained": True,
        "log_contents_read": False,
        "source_root_integrity_qualified": False,
        "global_admission_or_dispatch_frozen": False,
        "dc_stream_custody_proven": False,
        "model_origin_catalog_tested": False,
        "can_retire_desktop_commander": False,
        "full_replacement_qualified": False
    }
    write_private(output / "membership.json", snapshots)
    write_private(output / "summary.json", report)
    return output, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="local configured operator runtime.json")
    parser.add_argument("--output", required=True, help="new private output directory, must not exist")
    parser.add_argument("--hosts", type=lambda value: value.split(","))
    parser.add_argument(
        "--dc-identity", action="append", default=[],
        help="optional PID:proc-start-ticks; read-only classification, never a stop permit"
    )
    args = parser.parse_args()
    try:
        output, report = run(args)
    except (OSError, ValueError, TypeError, core.Refusal, InventoryError) as error:
        print(json.dumps({
            "observation": "failed",
            "error_type": type(error).__name__,
            "dc_retirement_qualified": False,
            "automatic_cleanup_or_retry": False
        }), file=sys.stderr)
        return 2
    print(json.dumps({
        "summary": str(output / "summary.json"),
        "selected": report["controller_records_selected"],
        "complete": report["every_host_response_complete"],
        "cohort_stable": report["controller_cohort_stable"],
        "dc_retirement_qualified": False
    }))
    return 0 if report["every_host_response_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
