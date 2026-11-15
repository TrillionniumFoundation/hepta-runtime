#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Prepare immutable local receipts; run one qualified libtest's owned/projected ABBA.

This measures guarded local decoding and retained routing cohorts, not SSH
throughput. GNU time directly parents each Rust process to avoid Python's
inherited RSS high-water floor. No runtime service or remote job is touched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

TEST = "mcp::runtime::jobs::operation_record_bench::guarded_operation_receipt_projection_benchmark"
PREFIX = "OPERATION_PROJECTION_BENCH "
SIZE = 4 * 1024 * 1024 - 32
MAX_RSS_KIB = 300 * 1024


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def identity(path):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "not a direct single-link file")
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def create(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def prepare(directory):
    need(directory.is_absolute() and directory.resolve() == directory, "fixtures require a direct absolute path")
    directory.mkdir(mode=0o700)
    record = {
        "execution_mode": "operator", "system_jobctl": False, "id": "operation-projection",
        "host": "owner", "ssh_target": "never-connect.invalid",
        "unit": "hepta-runtime-job-operation-projection",
        "remote_job_dir": "/never-launch/state/jobs/operation-projection",
        "executable": "/usr/bin/true", "args": [""], "cwd": None, "env_keys": [],
        "created_unix_ms": 1, "idempotency_key": "local-operation-projection",
        "request_fingerprint": 7, "request_digest": "a" * 64,
        "launch_state": "launched", "launch_error": None,
    }
    budget = SIZE - len(encoded(record))
    rows = []
    for payload in ("plain", "escaped"):
        child = directory / payload
        child.mkdir(mode=0o700)
        record["args"] = ["x" * budget if payload == "plain"
                          else "\n" * (budget // 2) + "x" * (budget % 2)]
        data = encoded(record)
        need(len(data) == SIZE and json.loads(data) == record, "fixture length/roundtrip differs")
        path = child / "operation-projection.json"
        create(path, data)
        rows.append({"payload": payload, "relative_path": str(path.relative_to(directory)),
                     "bytes": len(data), "decoded_argument_bytes": len(record["args"][0]),
                     "sha256": digest(path), "identity": identity(path)})
    manifest = {"schema": "hepta-operation-projection-fixtures/v1", "fixtures": rows,
                "generator_sha256": digest(__file__), "remote_effects": 0}
    create(directory / "manifest.json", encoded(manifest))
    return manifest


def validate_fixture(directory, row):
    path = directory / row["relative_path"]
    need(path.resolve().is_relative_to(directory) and path.resolve() == path, "fixture escaped root")
    need(identity(path) == row["identity"] and digest(path) == row["sha256"], "fixture changed")
    need(path.stat().st_size == row["bytes"] == SIZE and stat.S_IMODE(path.stat().st_mode) == 0o600
         and path.stat().st_uid == os.getuid(), "fixture owner/mode/length differs")
    return path


def parse_stdout(data):
    rows = [json.loads(line.split(PREFIX, 1)[1])
            for line in data.decode("utf-8").splitlines() if PREFIX in line]
    need(len(rows) == 1, "exactly one benchmark result required")
    need(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", data.decode()),
         "the exact ignored test did not pass once")
    return rows[0]


def usage(path):
    parts = path.read_text().strip().split("\t")
    need(len(parts) == 6 and parts[0] == "HEPTA_TIME", "GNU time receipt is incomplete")
    return {"wall_seconds": float(parts[1]), "user_seconds": float(parts[2]),
            "system_seconds": float(parts[3]), "max_rss_kib": int(parts[4]),
            "exit_code": int(parts[5])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--pins", type=int, nargs="+", default=[8, 32])
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--gnu-time", type=Path, default=Path("/usr/bin/time"))
    args = parser.parse_args()
    if args.prepare_only:
        print(json.dumps(prepare(args.fixtures), sort_keys=True))
        return 0
    need(args.binary and args.out and re.fullmatch(r"[0-9a-f]{64}", args.binary_sha256 or ""),
         "binary, explicit qualified binary SHA256 and fresh output are required")
    need(args.pins == [8, 32] and 1 <= args.rounds <= 4 and 1 <= args.timeout <= 600,
         "bounded campaign requires pins 8 32, 1..4 rounds and timeout <=600")
    for path in (args.fixtures, args.binary, args.out):
        need(path.is_absolute() and path.resolve() == path, "direct absolute paths required")
    time_binary = args.gnu_time.resolve()
    original_binary = identity(args.binary)
    need(digest(args.binary) == args.binary_sha256, "qualified binary SHA256 differs")
    time_id, time_sha = identity(time_binary), digest(time_binary)
    manifest_path = args.fixtures / "manifest.json"
    manifest_sha = digest(manifest_path)
    manifest = json.loads(manifest_path.read_bytes())
    need(manifest["schema"] == "hepta-operation-projection-fixtures/v1"
         and [r["payload"] for r in manifest["fixtures"]] == ["plain", "escaped"], "fixture manifest differs")
    args.out.mkdir(mode=0o700)
    (args.out / "samples").mkdir(mode=0o700)
    create(args.out / "fixture-manifest.json", manifest_path.read_bytes())
    report = {"schema": "hepta-operation-projection-abba/v1", "passed": False,
              "started_unix": time.time(), "binary": str(args.binary),
              "binary_sha256": args.binary_sha256, "binary_identity": original_binary,
              "gnu_time": str(time_binary), "gnu_time_sha256": time_sha,
              "fixture_manifest": str(manifest_path), "fixture_manifest_sha256": manifest_sha,
              "fixtures": manifest["fixtures"], "driver_sha256": digest(__file__),
              "order": ["owned", "projected", "projected", "owned"],
              "pins": args.pins, "rounds": args.rounds, "automatic_retries": 0,
              "remote_effects": 0, "samples": [],
              "scope": "same qualified libtest; guarded local decode; held cohort; warm fixture",
              "rss_scope": "GNU time direct-child peak and benchmark current VmRSS; not allocation counts",
              "rss_limit": "observed child peak checked against 300 MiB; no allocator or OS limit changed"}
    def save():
        temporary = args.out / "report.next"
        temporary.write_bytes(encoded(report))
        temporary.replace(args.out / "report.json")
    save()
    try:
        for fixture in manifest["fixtures"]:
            for pins in args.pins:
                for position, mode in enumerate(report["order"]):
                    path = validate_fixture(args.fixtures, fixture)
                    need(identity(args.binary) == original_binary and digest(args.binary) == args.binary_sha256,
                         "binary changed before sample")
                    need(identity(time_binary) == time_id and digest(time_binary) == time_sha,
                         "GNU time changed before sample")
                    name = f"{fixture['payload']}-p{pins}-{position}-{mode}"
                    prefix = args.out / "samples" / name
                    stdout_path, stderr_path = Path(str(prefix)+".stdout"), Path(str(prefix)+".stderr")
                    usage_path = Path(str(prefix)+".native-usage")
                    row = {"payload": fixture["payload"], "pins": pins, "mode": mode, "position": position,
                           "fixture_sha256": fixture["sha256"], "returncode": None,
                           "stdout": str(stdout_path.relative_to(args.out)),
                           "stderr": str(stderr_path.relative_to(args.out)),
                           "native_usage": str(usage_path.relative_to(args.out))}
                    report["samples"].append(row)
                    save()
                    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                           "RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2",
                           "HEPTA_OPERATION_BENCH_FIXTURE": str(path),
                           "HEPTA_OPERATION_BENCH_MODE": mode,
                           "HEPTA_OPERATION_BENCH_PINS": str(pins),
                           "HEPTA_OPERATION_BENCH_ROUNDS": str(args.rounds)}
                    command = [str(time_binary), "-f", "HEPTA_TIME\t%e\t%U\t%S\t%M\t%x",
                               "-o", str(usage_path), str(args.binary), "--exact", "--ignored",
                               "--test-threads=1", "--nocapture", TEST]
                    row["command"] = command
                    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                        process = subprocess.Popen(command, stdout=stdout, stderr=stderr,
                                                   cwd=args.out, env=env, start_new_session=True)
                        try:
                            row["returncode"] = process.wait(timeout=args.timeout)
                        except BaseException:
                            if process.poll() is None:
                                os.killpg(process.pid, signal.SIGKILL)
                            process.wait()
                            raise
                    row["stdout_sha256"], row["stderr_sha256"] = digest(stdout_path), digest(stderr_path)
                    need(row["returncode"] == 0, "benchmark process failed; original logs retained")
                    result, native = parse_stdout(stdout_path.read_bytes()), usage(usage_path)
                    row.update(result=result, native=native, native_usage_sha256=digest(usage_path))
                    need(result["schema"] == "hepta-operation-projection-bench/v1"
                         and result["mode"] == mode and result["pins"] == pins
                         and result["rounds"] == args.rounds and result["successes"] == pins * args.rounds
                         and result["failures"] == 0 and result["remote_effects"] == 0
                         and result["fixture_sha256"] == fixture["sha256"]
                         and native["exit_code"] == 0, "benchmark identity or result differs")
                    need(0 < native["max_rss_kib"] < MAX_RSS_KIB, "observed child RSS exceeds campaign budget")
                    validate_fixture(args.fixtures, fixture)
                    save()
                    print(json.dumps({"sample": name, "passed": True}), flush=True)
        need(digest(manifest_path) == manifest_sha, "fixture manifest changed")
        need(identity(args.binary) == original_binary and digest(args.binary) == args.binary_sha256
             and identity(time_binary) == time_id and digest(time_binary) == time_sha,
             "bound executable changed after campaign")
        need(report["driver_sha256"] == digest(__file__), "driver changed")
        report["passed"] = True
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        report["finished_unix"] = time.time()
        save()
    print(json.dumps({"passed": report["passed"], "report": str(args.out / "report.json")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
