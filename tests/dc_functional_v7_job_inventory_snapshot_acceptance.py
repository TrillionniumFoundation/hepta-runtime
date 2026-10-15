#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only V7 inventory acceptance from a private copy of live job metadata.

Reads only the explicit jobs directory, never existing configuration or tokens.
The candidate owns a disposable state directory and disabled generic host config.
Only discovery and process_list run. No job, status/cancel, SSH or service action
is invoked. Raw metadata, disposable tokens/config/logs are deleted on every exit.
Receipts contain counts, schema and aggregate hashes, never job arguments or IDs.
This qualifies bounded inventory output only, not live state or DC replacement.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
from mcp_tool_contract import ToolContract
from dc_successor_contract import V7_SHA256
from runtime_http_acceptance import Client
from dc_functional_v7_search_six_host_acceptance import source_identity

MAX_WIRE = 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_SOURCE_RECORDS = 20000
SUMMARY_FIELDS = {"id", "host", "created_unix_ms", "execution_mode", "launch_state"}
LEGACY_FIELDS = {
    "execution_mode", "system_jobctl", "id", "host", "ssh_target", "unit", "remote_job_dir",
    "executable", "args", "cwd", "env_keys", "created_unix_ms", "idempotency_key",
    "request_fingerprint", "request_digest", "launch_state", "launch_error"}
DEFAULTS = {
    "execution_mode": "isolated", "system_jobctl": False, "cwd": None, "idempotency_key": None,
    "request_digest": None, "launch_state": "launched", "launch_error": None}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    with pathlib.Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def wire_bytes(value):
    # Compact UTF-8 JSON matches serde_json::to_vec(CallToolResult); JSON-RPC HTTP
    # framing is deliberately not counted as part of the CallToolResult budget.
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())


def summary(record):
    value = {field: record.get(field, DEFAULTS.get(field)) for field in SUMMARY_FIELDS}
    assert isinstance(value["id"], str) and re.fullmatch("[A-Za-z0-9._-]{1,96}", value["id"])
    assert isinstance(value["host"], str) and re.fullmatch("[A-Za-z0-9._-]{1,96}", value["host"])
    assert type(value["created_unix_ms"]) is int and 0 <= value["created_unix_ms"] < 2**128
    assert value["execution_mode"] in ("operator", "isolated")
    assert isinstance(value["launch_state"], str)
    return value


def private_write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def source_records(directory, destination=None):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        assert info.st_uid == os.getuid() and info.st_mode & 0o022 == 0, "source directory owner/mode refused"
        names = sorted(name for name in os.listdir(fd) if pathlib.Path(name).suffix == ".json")
        assert 0 < len(names) <= MAX_SOURCE_RECORDS, "source registry record count outside finite fixture budget"
        manifest = {}
        records = []
        total_bytes = 0
        for name in names:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                assert before.st_mode & 0o077 == 0 and before.st_nlink == 1, "source record is not private ordinary metadata"
                raw = stream.read(MAX_RECORD_BYTES + 1)
                after = os.fstat(stream.fileno())
            assert len(raw) <= MAX_RECORD_BYTES, "source metadata record exceeds finite fixture budget"
            assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "source record changed during snapshot"
            total_bytes += len(raw)
            assert total_bytes <= MAX_SOURCE_BYTES, "source registry exceeds finite fixture byte budget"
            record = json.loads(raw)
            value = summary(record)
            assert value["id"] == name[:-5], "filename/record identity mismatch"
            normalized = {field: record.get(field, DEFAULTS.get(field)) for field in LEGACY_FIELDS}
            assert all(field in record or field in DEFAULTS for field in LEGACY_FIELDS), "source job record missing required field"
            manifest[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            records.append(normalized)
            if destination is not None:
                private_write(destination / name, raw)
        assert sorted(name for name in os.listdir(fd) if pathlib.Path(name).suffix == ".json") == names, "source registry changed during snapshot"
        ids = [record["id"] for record in records]
        assert len(set(ids)) == len(ids), "duplicate source job identity"
        return records, {
            "input_records": len(records), "input_bytes": total_bytes,
            "source_metadata_sha256": hashlib.sha256(canonical(manifest)).hexdigest(),
            "expected_summary_sha256": hashlib.sha256(canonical(sorted(
                [summary(record) for record in records], key=lambda row: row["id"]))).hexdigest()}
    finally:
        os.close(fd)


def expected_legacy_wire(records):
    # This reconstruction normalizes only JobRecord's declared fields/defaults,
    # then uses serde_json's pretty indent and sorted Value object keys.
    text = json.dumps({"jobs": records}, sort_keys=True, ensure_ascii=False, indent=2)
    return wire_bytes({"content": [{"type": "text", "text": text}], "isError": False})


def inventory(client, params, expected):
    raw = client.rpc("tools/call", {"name": "process_list", "arguments": params})
    assert raw.get("isError") is not True, "bounded inventory unexpectedly refused"
    measured = wire_bytes(raw)
    assert measured <= MAX_WIRE, "whole CallToolResult exceeded 1 MiB"
    assert len(raw.get("content", [])) == 1 and raw["content"][0]["type"] == "text"
    value = json.loads(raw["content"][0]["text"])
    assert set(value) == {"jobs", "total", "inventory_complete", "status_authoritative"}
    assert value["inventory_complete"] is True and value["status_authoritative"] is False
    assert value["total"] == len(expected) and len(value["jobs"]) == len(expected)
    actual = {}
    for row in value["jobs"]:
        assert set(row) == SUMMARY_FIELDS, "private metadata escaped bounded summary DTO"
        assert row["id"] not in actual, "duplicate output job identity"
        actual[row["id"]] = row
    assert actual == {row["id"]: row for row in expected}, "whole inventory omitted or altered identity"
    return {"input_records": len(expected), "output_records": len(value["jobs"]),
            "whole_call_tool_result_bytes": measured, "inventory_complete": True,
            "status_authoritative": False, "exact_all_ids_and_summary_fields": True,
            "inventory_summary_sha256": hashlib.sha256(canonical(sorted(
                value["jobs"], key=lambda row: row["id"]))).hexdigest()}


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def controller(binary, contract, base, records, expected_binary, children):
    workspace = base / "workspace"; workspace.mkdir(mode=0o700)
    token_path = base / "token"; token = secrets.token_hex(32)
    private_write(token_path, token.encode())
    config_path = base / "runtime.json"
    hosts = sorted({record["host"] for record in records})
    config = {"state_dir": str(base / "state"), "controller_workspace_roots": [str(workspace)], "hosts": {
        host: {"ssh_target": "inventory-fixture-no-ssh.invalid", "platform": "linux",
               "remote_state_dir": str(base / "unused-remote"), "execution_mode": "isolated",
               "allow_execute": False, "allow_pty": False, "allow_write": False,
               "allowed_read_path_prefixes": [], "allowed_write_path_prefixes": []}
        for host in hosts}}
    private_write(config_path, json.dumps(config).encode())
    bindir = base / "bin"; bindir.mkdir(mode=0o700)
    marker = base / "ssh-attempt"
    trap = bindir / "ssh"
    private_write(trap, ("#!/usr/bin/python3\nimport pathlib,sys\npathlib.Path("
                        + repr(str(marker)) + ").write_text('blocked')\nraise SystemExit(87)\n").encode())
    trap.chmod(0o700)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    env = dict(os.environ); env["PATH"] = str(bindir) + ":" + env.get("PATH", "")
    assert digest(binary) == expected_binary, "candidate artifact changed before inventory fixture"
    log_path = base / "controller.log"
    with log_path.open("xb") as writer:
        log_path.chmod(0o600)
        proc = subprocess.Popen([str(binary), "mcp", "--path", str(workspace),
            "--bind", f"127.0.0.1:{port}", "--runtime-config", str(config_path),
            "--auth-token-file", str(token_path)], stdin=subprocess.DEVNULL,
            stdout=writer, stderr=writer, env=env)
    children.append(proc)
    client = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert proc.poll() is None, "disposable inventory controller exited"
        try:
            client = Client(f"http://127.0.0.1:{port}/mcp", token)
            break
        except (OSError, RuntimeError):
            time.sleep(.05)
    assert client is not None, "disposable inventory controller readiness deadline"
    tools = client.rpc("tools/list", {})["tools"]
    contract.verify(tools)
    process_tool = next(row for row in tools if row["name"] == "process_list")
    assert process_tool["annotations"]["readOnlyHint"] is True
    return client, proc, marker


def synthetic_overflow(base):
    jobs = base / "state" / "jobs"; jobs.mkdir(parents=True, mode=0o700)
    (base / "state").chmod(0o700)
    records = []
    for index in range(8192):
        identity = "overflow-" + str(index).zfill(6) + "-" + ("0" * 64)
        record = {"id": identity, "host": "fixture-" + str(index % 3),
            "created_unix_ms": 1790000000000 + index, "execution_mode": "isolated",
            "system_jobctl": False, "launch_state": "launched", "launch_error": None,
            "ssh_target": "synthetic-no-ssh.invalid", "unit": "fixture-unused",
            "remote_job_dir": "/synthetic-unused", "executable": "/synthetic-unused",
            "args": ["SYNTHETIC_PRIVATE_METADATA_" + ("x" * 512)], "cwd": None, "env_keys": [],
            "idempotency_key": None, "request_fingerprint": index, "request_digest": None}
        private_write(jobs / (identity + ".json"), json.dumps(record).encode())
        records.append(record)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--source-jobs-dir", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-fingerprint", required=True)
    parser.add_argument("--min-input-records", type=int, default=1)
    parser.add_argument("--min-legacy-metadata-wire-bytes", type=int, default=0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    for value in (args.expected_binary_sha256, args.expected_source_fingerprint):
        assert re.fullmatch("[0-9a-f]{64}", value), "explicit SHA256 required"
    assert args.min_input_records >= 1 and args.min_legacy_metadata_wire_bytes >= 0
    binary = pathlib.Path(args.binary).resolve(strict=True)
    assert digest(binary) == args.expected_binary_sha256, "candidate binary does not match release pin"
    contract_path = pathlib.Path(args.contract).resolve(strict=True)
    contract = ToolContract.load(contract_path, V7_SHA256)
    before_source = source_identity()
    assert before_source["source_code_fingerprint"] == args.expected_source_fingerprint, "candidate source does not match release pin"
    helper_paths = [pathlib.Path(__file__), ROOT / "tests/runtime_http_acceptance.py",
                    ROOT / "tests/dc_successor_contract.py", ROOT / "deploy/mcp_tool_contract.py",
                    ROOT / "tests/dc_functional_v7_search_six_host_acceptance.py",
                    ROOT / "tests/dc_parity_release_six_host_acceptance.py"]
    before_helpers = {path.relative_to(ROOT).as_posix(): digest(path) for path in helper_paths}
    outfile = pathlib.Path(args.out).resolve()
    assert not outfile.exists(), "never overwrite a prior evidence receipt"
    outfile.parent.mkdir(parents=True, exist_ok=True)
    source_jobs = pathlib.Path(args.source_jobs_dir).absolute()
    report = {
        "schema": "hepta-private-live-metadata-inventory-snapshot-v7",
        "origin": "native_python_authenticated_mcp_client",
        "binary_sha256": args.expected_binary_sha256,
        "source_code_fingerprint": args.expected_source_fingerprint,
        "source_before": before_source, "helpers_before": before_helpers,
        "reviewed_contract_file_sha256": V7_SHA256,
        "summary_fields": sorted(SUMMARY_FIELDS), "whole_call_tool_result_budget_bytes": MAX_WIRE,
        "existing_config_or_token_read": False, "live_state_used_by_candidate": False,
        "source_registry_modified": False, "job_execution_attempted": False,
        "live_status_or_cancel_tested": False, "production_service_changed": False,
        "model_origin_qualified": False, "full_dc_replacement_qualified": False,
        "complete": False, "raw_private_snapshot_deleted": False}
    children = []
    temporary = None
    try:
        temporary = tempfile.TemporaryDirectory(prefix="hepta-job-inventory-private-")
        private_root = pathlib.Path(temporary.name); private_root.chmod(0o700)
        base = private_root / "actual"; base.mkdir(mode=0o700)
        jobs = base / "state" / "jobs"; jobs.mkdir(parents=True, mode=0o700)
        (base / "state").chmod(0o700)
        assert source_jobs != jobs, "candidate must never use the live registry directory"
        records, metadata = source_records(source_jobs, jobs)
        assert metadata["input_records"] >= args.min_input_records, "snapshot too small for requested acceptance"
        metadata["legacy_full_metadata_call_tool_result_bytes_reconstructed"] = expected_legacy_wire(records)
        metadata["legacy_size_method"] = "JobRecord declared fields/defaults, pretty sorted UTF-8 JSON, compact success CallToolResult"
        assert metadata["legacy_full_metadata_call_tool_result_bytes_reconstructed"] >= args.min_legacy_metadata_wire_bytes, "snapshot lacks requested legacy wire pressure"
        report["snapshot"] = metadata
        client, proc, marker = controller(binary, contract, base, records, args.expected_binary_sha256, children)
        expected = [summary(record) for record in records]
        report["global_inventory"] = inventory(client, {}, expected)
        report["scoped_inventory"] = []
        for host in sorted({record["host"] for record in records}):
            report["scoped_inventory"].append(inventory(client, {"host": host},
                [row for row in expected if row["host"] == host]))
        assert not marker.exists(), "inventory unexpectedly attempted SSH"
        report["actual_snapshot_ssh_attempts"] = 0
        stop(proc)
        _, after_metadata = source_records(source_jobs)
        assert {key: metadata[key] for key in after_metadata} == after_metadata, "live registry changed; snapshot is not a stable source qualification"
        report["source_registry_snapshot_stable"] = True

        overflow = private_root / "overflow"; overflow.mkdir(mode=0o700)
        oversized = synthetic_overflow(overflow)
        client, proc, marker = controller(binary, contract, overflow, oversized, args.expected_binary_sha256, children)
        raw = client.rpc("tools/call", {"name": "process_list", "arguments": {}})
        assert raw.get("isError") is True, "oversized inventory silently succeeded or returned a partial list"
        assert wire_bytes(raw) <= MAX_WIRE
        text = "\n".join(item.get("text", "") for item in raw.get("content", []) if item.get("type") == "text")
        assert "1 MiB" in text and "No partial inventory returned" in text
        assert "SYNTHETIC_PRIVATE_METADATA_" not in text and "overflow-" not in text
        report["oversized_inventory"] = {
            "synthetic_input_records": len(oversized), "explicit_error": True,
            "silent_partial_inventory": False, "whole_call_tool_result_bytes": wire_bytes(raw),
            "scoped_inventory": [inventory(client, {"host": host},
                [summary(record) for record in oversized if record["host"] == host])
                for host in sorted({record["host"] for record in oversized})]}
        assert not marker.exists(), "synthetic inventory unexpectedly attempted SSH"
        report["synthetic_ssh_attempts"] = 0
        stop(proc)
        report["complete"] = True
    except BaseException as error:
        # Never copy arbitrary candidate errors, raw metadata, argv, paths or token
        # material into the receipt. The finite failing phase/type is reviewable.
        report["failure"] = {"type": type(error).__name__,
            "phase": "inventory_snapshot_fixture", "detail": str(error) if isinstance(error, AssertionError) and len(error.args) == 1 and isinstance(error.args[0], str) else "private fixture refused; raw details withheld"}
    finally:
        for proc in children:
            try:
                stop(proc)
            except BaseException:
                report["complete"] = False
        report["disposable_controllers_stopped"] = all(proc.poll() is not None for proc in children)
        try:
            if temporary is not None:
                root_path = pathlib.Path(temporary.name)
                temporary.cleanup()
                report["raw_private_snapshot_deleted"] = not root_path.exists()
            else:
                report["raw_private_snapshot_deleted"] = True
        except BaseException:
            report["complete"] = False
            report["raw_private_snapshot_deleted"] = False
        try:
            after_source = source_identity()
            after_helpers = {path.relative_to(ROOT).as_posix(): digest(path) for path in helper_paths}
            report["artifact_identity_stable"] = (digest(binary) == args.expected_binary_sha256
                and after_source == before_source and after_helpers == before_helpers
                and digest(contract_path) == V7_SHA256)
            report["helpers_after"] = after_helpers
            report["source_after"] = after_source
            report["complete"] = (report["complete"] and report["artifact_identity_stable"]
                and report["disposable_controllers_stopped"] and report["raw_private_snapshot_deleted"])
        except BaseException:
            report["complete"] = False
            report["artifact_identity_stable"] = False
        with outfile.open("x") as stream:
            stream.write(json.dumps(report, indent=2) + "\n")
        outfile.chmod(0o600)
    print("INVENTORY complete", report["complete"], "records", report.get("snapshot", {}).get("input_records"),
          "raw_private_snapshot_deleted", report["raw_private_snapshot_deleted"], flush=True)
    if not report["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
