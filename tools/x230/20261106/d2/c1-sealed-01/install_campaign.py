#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Install a sealed D2 C1 source package once; never launch the campaign.

Every sealed member is read and checked before creating any destination.
Linux installs the fixed tool directory and two actual input receipts. macOS
installs only the unchanged held-agent program and its identical sealed parent.
The original native installer terminal/read remains a separate receipt.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path("/home/qian/hepta-runtime-validation-cost-20261106-d2")
TOOLS = ROOT / "c1-tools-01"
MAC_ROOT = Path("/Users/qianqi/work/hepta-runtime-d2-launchers-01")
MAC_OUTPUT = Path("/Users/qianqi/work/hepta-runtime-d2-c1-holder-01")
SOCKET_PARENT = Path("/home/qian/hd2c01")
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_FILES = 128
HEX = re.compile(r"[0-9a-f]{64}\Z")
HOLDER_SHA = "715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65"
CLARIFICATION_SHA = "7848ccc640e8d44fd042632eda69a93d2b24e07cabb65e83aeef683faeeb8704"
LINUX_NAMES = (
    "c1-campaign-inputs-01.json",
    "c1-prerequisites-01.json",
    "c1-tools-01/compiler-monitor-policy-01.json",
    "c1-tools-01/compiler_monitor.py",
    "c1-tools-01/compiler_state.py",
    "c1-tools-01/d2_campaign.py",
    "c1-tools-01/d2_prerequisites.py",
    "c1-tools-01/pre-execution-clarification-01.json",
    "c1-tools-01/reference/allocator_environment.py",
    "c1-tools-01/reference/allocator_environment_audit.py",
    "c1-tools-01/reference/analyze_native_observation.py",
    "c1-tools-01/reference/audit_native_evidence.py",
    "c1-tools-01/reference/correlate_trace.py",
    "c1-tools-01/reference/observation_resources.py",
    "c1-tools-01/reference/run_native_observation.py",
    "c1-tools-01/reference/summarize_trace.py",
    "c1-tools-01/reference/x230_observation_benchmark.py",
    "c1-tools-01/run_c1_phase_cost.py",
    "c1-tools-01/validate_compiler_monitor.py",
)
MAC_NAMES = ("d2_campaign.py", "held_agent_campaign_02.py")


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def identity(path, raw):
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def stamp(value):
    return tuple(getattr(value, name) for name in
                 ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns"))


def regular(path, maximum=MAX_FILE):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, "indirect source path: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
             and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             "unsafe or oversized source: " + str(path))
        chunks, total = [], 0
        while total <= maximum:
            block = os.read(fd, min(1024 * 1024, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        need(total == before.st_size and total <= maximum
             and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             "source changed while reading: " + str(path))
        return b"".join(chunks)
    finally:
        os.close(fd)


def directory(path, private=False):
    need(path.is_absolute() and path.resolve() == path, "indirect destination directory")
    status = path.lstat()
    need(stat.S_ISDIR(status.st_mode) and status.st_uid == os.getuid()
         and not stat.S_ISLNK(status.st_mode)
         and stat.S_IMODE(status.st_mode) & 0o022 == 0,
         "destination directory is not owned and protected: " + str(path))
    if private:
        need(stat.S_IMODE(status.st_mode) == 0o700, "new destination is not private")
    return status


def sync_directory(path):
    directory(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, raw):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            need(count > 0, "new file write made no progress")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    actual = regular(path)
    need(actual == raw, "new file readback differs")
    sync_directory(path.parent)
    return identity(path, actual)


def install(args):
    need(not sys.flags.optimize, "normal Python execution is required")
    need(os.getuid() != 0 and args.target in {"x230", "mac"}, "non-root fixed target required")
    need((args.target == "x230" and sys.platform == "linux" and os.getuid() == 1000)
         or (args.target == "mac" and sys.platform == "darwin"), "selected platform differs")
    need(HEX.fullmatch(args.manifest_sha256) is not None, "exact sealed manifest SHA is required")
    sealed_dir = Path(args.sealed_dir)
    directory(sealed_dir)
    manifest_path = sealed_dir / "seal-manifest.json"
    manifest_raw = regular(manifest_path)
    need(hashlib.sha256(manifest_raw).hexdigest() == args.manifest_sha256,
         "actual sealed manifest differs")
    manifest = json.loads(manifest_raw)
    need(manifest.get("schema") == "hepta-d2-c1-outer-seal/v1" and manifest.get("sealed") is True
         and manifest.get("source_sealing_only") is True and manifest.get("workload_started") is False
         and manifest.get("installed") is False and manifest.get("actual_measurement") is None
         and manifest.get("automatic_retries") == 0 and manifest.get("performance_acceptance_claim") is False,
         "actual source-only seal is required")
    ordinary = manifest.get("ordinary_supplement")
    need(isinstance(ordinary, dict) and ordinary.get("passed") is True
         and ordinary.get("original_postflight_revalidated") is True
         and ordinary["inputs"] == manifest.get("ordinary_inputs")
         and ordinary["validation"].get("ordinary_five_stages_passed") is True
         and ordinary["validation"]["qualified_feature_programs_after"]
             == manifest["qualification_and_exact_ci"]["binaries"],
         "mandatory actual ordinary closure is absent from the source seal")
    need(manifest.get("holder_sha256") == HOLDER_SHA
         and manifest.get("pre_execution_clarification_sha256") == CLARIFICATION_SHA
         and manifest.get("mac_holder_output") == str(MAC_OUTPUT), "holder or mandatory clarification differs")
    expected = {
        **{"x230/" + name: ("x230", ROOT / name) for name in LINUX_NAMES},
        **{"mac/" + name: ("mac", MAC_ROOT / name) for name in MAC_NAMES},
    }
    rows = manifest["files"]
    need(isinstance(rows, list) and len(rows) == len(expected) == manifest["file_count"]
         and len(rows) <= MAX_FILES, "sealed fixed member inventory differs")
    payload, seen, total = {}, set(), 0
    for row in rows:
        name = row["staged_path"]
        need(name in expected and name not in seen, "unknown or duplicate sealed member")
        target, destination = expected[name]
        need(row["target"] == target and row["destination"] == str(destination)
             and type(row["bytes"]) is int and 0 <= row["bytes"] <= MAX_FILE
             and HEX.fullmatch(row["sha256"]) is not None, "invalid member identity")
        raw = regular(sealed_dir / name)
        need(len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"],
             "sealed member bytes differ: " + name)
        payload[name] = raw
        seen.add(name)
        total += len(raw)
        need(total <= MAX_TOTAL, "sealed payload exceeds the total bound")
    need(seen == set(expected) and total == manifest["payload_bytes"], "sealed payload inventory is incomplete")
    need(payload["x230/c1-tools-01/d2_campaign.py"] == payload["mac/d2_campaign.py"],
         "macOS holder would transmit a different parent")
    need(hashlib.sha256(payload["mac/held_agent_campaign_02.py"]).hexdigest() == HOLDER_SHA
         and hashlib.sha256(payload["x230/c1-tools-01/pre-execution-clarification-01.json"]).hexdigest()
         == CLARIFICATION_SHA, "unchanged holder or clarification bytes differ")
    for key, name, path in (
        ("parent", "x230/c1-tools-01/d2_campaign.py", TOOLS / "d2_campaign.py"),
        ("adapter", "x230/c1-tools-01/run_c1_phase_cost.py", TOOLS / "run_c1_phase_cost.py"),
        ("prerequisites", "x230/c1-prerequisites-01.json", ROOT / "c1-prerequisites-01.json"),
    ):
        need(manifest[key] == identity(path, payload[name]), "sealed core identity differs: " + key)
    expected_argv = ["/usr/bin/python3", "-B", str(MAC_ROOT / "held_agent_campaign_02.py"),
                     "--remote-script", str(MAC_ROOT / "d2_campaign.py"), "--out", str(MAC_OUTPUT),
                     "--timeout-seconds", "3600"]
    need(manifest["operator_argv"] == expected_argv, "the original held-agent invocation differs")
    selected = [(name, expected[name][1], payload[name])
                for name in sorted(payload) if expected[name][0] == args.target]
    if args.target == "x230":
        directory(ROOT)
        fresh_directories = [TOOLS, TOOLS / "reference"]
        receipt_path = ROOT / "c1-parent-install-01.json"
        guards = [TOOLS, ROOT / "c1-prerequisites-01.json", ROOT / "c1-campaign-inputs-01.json",
                  ROOT / "c1-campaign-01", ROOT / "c1-observation-01",
                  ROOT / "c1-adapter-evidence-01", SOCKET_PARENT, receipt_path]
    else:
        directory(MAC_ROOT.parent)
        fresh_directories = [MAC_ROOT]
        receipt_path = MAC_ROOT / "install-report-01.json"
        guards = [MAC_ROOT, MAC_OUTPUT]
    need(all(not os.path.lexists(path) for path in guards)
         and all(not os.path.lexists(path) for _, path, _ in selected),
         "a fixed destination or campaign namespace already exists")
    # All original bytes and all absent destination checks precede the first mutation.
    # A partial failure leaves every created artifact intact for reconciliation.
    os.umask(0o077)
    created_directories, written = [], []
    for path in fresh_directories:
        path.mkdir(mode=0o700)
        directory(path, private=True)
        created_directories.append(str(path))
        sync_directory(path.parent)
    for _, destination, raw in selected:
        written.append(write_new(destination, raw))
    for path in reversed(fresh_directories):
        sync_directory(path)
    need(regular(manifest_path) == manifest_raw, "seal manifest changed during installation")
    receipt = {
        "schema": "hepta-d2-c1-source-install/v1", "target": args.target,
        "sealed_manifest": identity(manifest_path, manifest_raw),
        "file_count": len(written), "payload_bytes": sum(row["bytes"] for row in written),
        "created_directories": created_directories, "files": written,
        "installed": True, "campaign_started": False, "host_requests": 0,
        "source_or_test_execution": False, "automatic_retries": 0,
        "cleanup_or_overwrite_performed": False,
        "operator_argv": expected_argv if args.target == "mac" else None,
        "partial_failure_policy": "Any failure keeps original native logs and all created files; do not replay or remove them.",
    }
    receipt_id = write_new(receipt_path, canonical(receipt))
    print(json.dumps({"receipt": receipt_id, "target": args.target,
                      "file_count": len(written), "payload_bytes": receipt["payload_bytes"],
                      "campaign_started": False}, sort_keys=True), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sealed-dir", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--target", choices=("x230", "mac"), required=True)
    install(parser.parse_args())


if __name__ == "__main__":
    main()
