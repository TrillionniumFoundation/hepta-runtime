#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Pinned ABBA of guarded receipt work and empty-pool idle overhead; no remote effects."""
import argparse
import datetime
import difflib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time


TESTS = {
    "receipt": "mcp::runtime::jobs::record_read_bench::guarded_receipt_reads_and_complete_comparisons_benchmark",
    "idle": "mcp::runtime::ssh::observation_pool::tests::maintenance::idle_maintenance_benchmark",
}
HARNESSES = ("src/mcp/runtime/jobs_record_read_bench.rs",
             "src/mcp/runtime/ssh_observation_maintenance_tests.rs")
MODES = ("strict_read", "strict_rescan", "fresh_lookup")
SIZES = (1024, 64 * 1024, 768 * 1024)


def need(okay, reason):
    if not okay:
        raise ValueError(reason)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def number(value, positive=False):
    return (type(value) in (int, float) and math.isfinite(value)
            and (value > 0 if positive else value >= 0))


def source_map(root):
    files = [root / name for name in ("Cargo.toml", "Cargo.lock")]
    files += [root / name for name in ("build.rs", "rustfmt.toml", ".cargo/config", ".cargo/config.toml")
              if (root / name).exists()]
    for directory in ("src", "tests", "examples"):
        files += [path for path in (root / directory).rglob("*") if path.is_file()]
    need(all(path.is_file() and not path.is_symlink() for path in files), "missing/symlink compiler input")
    return {str(path.relative_to(root)): digest(path) for path in sorted(files)}


def parse_receipt(stdout):
    waves, finals = [], []
    for line in stdout.splitlines():
        match = re.search(r"GUARDED_RECEIPT_(WAVE|BENCH) (\{.*\})$", line)
        if match:
            (waves if match[1] == "WAVE" else finals).append(json.loads(match[2]))
    need(len(finals) == 1 and len(waves) == 36, "receipt requires 36 waves and exactly one final BENCH")
    final = finals[0]
    need(final.get("schema") == "hepta-guarded-receipt-cpu-v1"
         and final.get("repetitions") == 4 and final.get("calls_per_wave") == 64
         and final.get("remote_effects") == 0 and final.get("allocations_measured") is False
         and final.get("rows") == waves, "receipt final inventory/metadata differs from wave records")
    expected = [(repetition, size, mode) for repetition in range(4)
                for size in (SIZES if repetition % 2 == 0 else tuple(reversed(SIZES)))
                for mode in (MODES if repetition % 2 == 0 else tuple(reversed(MODES)))]
    need([(row.get("repetition"), row.get("receipt_bytes"), row.get("mode")) for row in waves] == expected,
         "receipt has missing, duplicate, reordered or unexpected waves")
    for row in waves:
        need(type(row.get("successes")) is int and row["successes"] == 64
             and type(row.get("failures")) is int and row["failures"] == 0, "receipt call failure/count mismatch")
        need(number(row.get("wall_seconds"), positive=True)
             and number(row.get("user_cpu_seconds")) and number(row.get("system_cpu_seconds")),
             "receipt timing must be finite and nonnegative")
        need(type(row.get("process_lifetime_maxrss_kib")) is int
             and row["process_lifetime_maxrss_kib"] > 0, "receipt process-lifetime maxRSS missing")
        computed = {"calls_per_second": 64 / row["wall_seconds"],
                    "cpu_seconds_per_call": (row["user_cpu_seconds"] + row["system_cpu_seconds"]) / 64}
        need(all(number(row.get(key)) and math.isclose(row[key], value, rel_tol=1e-9, abs_tol=1e-12)
                 for key, value in computed.items()), "receipt derived metrics disagree with raw counters")
    return {"waves": waves, "final": final}


def parse_idle(stdout, requested_seconds):
    rows = []
    for line in stdout.splitlines():
        start = line.find('{"benchmark":"observation-empty-pool-idle/v1"')
        if start >= 0:
            rows.append(json.loads(line[start:]))
    need(len(rows) == 1, "idle requires exactly one benchmark record")
    row = rows[0]
    need(row.get("benchmark") == "observation-empty-pool-idle/v1"
         and number(row.get("seconds"), positive=True)
         and row["seconds"] >= requested_seconds, "idle duration/identity mismatch")
    for field in ("maintenance_passes", "cpu_micros", "voluntary_context_switches", "involuntary_context_switches"):
        need(type(row.get(field)) is int and row[field] >= 0, "invalid idle counter: " + field)
    return row


def run_child(argv, cwd, environment, output, name, seconds, result):
    """Only this exact Popen child is killed/reaped; no PID guessing or group signals."""
    result.update(argv=argv, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  exit_code=None, timed_out=False, interrupted=False)
    paths = {stream: output / f"{name}.{stream}.log" for stream in ("stdout", "stderr")}
    started = time.monotonic()
    process = None
    try:
        with paths["stdout"].open("xb") as stdout, paths["stderr"].open("xb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr)
                result["pid"] = process.pid
                result["exit_code"] = process.wait(timeout=seconds)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                result["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
                result["interrupted"] = isinstance(error, KeyboardInterrupt)
                if process is not None:
                    process.kill()
                    result["exit_code"] = process.wait(timeout=10)
            except OSError as error:
                result["launch_error"] = str(error)
    finally:
        result["process_wall_seconds"] = time.monotonic() - started
        for stream, path in paths.items():
            if path.exists():
                result[stream] = {"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}
    need(paths["stdout"].stat().st_size <= 16 * 1024 * 1024, "benchmark output exceeds parser bound")
    return paths["stdout"].read_text(encoding="utf-8", errors="strict")


def aggregate(samples):
    need(all(sample["passed"] for sample in samples), "incomplete/failed ABBA cannot publish comparison")
    result = {"per_arm": {}, "candidate_over_baseline": {"receipt": {}, "idle": {}}}
    for arm in ("A", "B"):
        receipts = {}
        for mode in MODES:
            receipts[mode] = {}
            for size in SIZES:
                rows = [{"sample_index": sample["index"], **row} for sample in samples
                        if sample["arm"] == arm and sample["kind"] == "receipt"
                        for row in sample["raw"]["waves"] if row["mode"] == mode and row["receipt_bytes"] == size]
                calls = sum(row["successes"] for row in rows)
                wall = sum(row["wall_seconds"] for row in rows)
                cpu = sum(row["user_cpu_seconds"] + row["system_cpu_seconds"] for row in rows)
                receipts[mode][str(size)] = {"calls": calls, "wave_count": len(rows),
                    "summed_wave_wall_seconds": wall, "cpu_seconds": cpu,
                    "calls_per_second": calls / wall, "cpu_seconds_per_call": cpu / calls,
                    "wall_seconds_per_call": wall / calls, "raw_rows": rows}
        rows = [{"sample_index": sample["index"], **sample["raw"]} for sample in samples
                if sample["arm"] == arm and sample["kind"] == "idle"]
        seconds = sum(row["seconds"] for row in rows)
        cpu = sum(row["cpu_micros"] for row in rows) / 1_000_000
        idle = {"seconds": seconds, "cpu_seconds": cpu, "cpu_percent_one_core": 100 * cpu / seconds,
                "raw_samples": rows}
        for field in ("maintenance_passes", "voluntary_context_switches", "involuntary_context_switches"):
            idle[field] = sum(row[field] for row in rows)
            idle[field + "_per_second"] = idle[field] / seconds
        result["per_arm"][arm] = {"receipt": receipts, "idle": idle}
    ratio = lambda a, b: b / a if a else None
    for mode in MODES:
        result["candidate_over_baseline"]["receipt"][mode] = {}
        for size in SIZES:
            a, b = (result["per_arm"][arm]["receipt"][mode][str(size)] for arm in ("A", "B"))
            result["candidate_over_baseline"]["receipt"][mode][str(size)] = {
                key: ratio(a[key], b[key]) for key in ("calls_per_second", "cpu_seconds_per_call", "wall_seconds_per_call")}
    a, b = (result["per_arm"][arm]["idle"] for arm in ("A", "B"))
    result["candidate_over_baseline"]["idle"] = {key: ratio(a[key], b[key]) for key in (
        "cpu_percent_one_core", "maintenance_passes_per_second", "voluntary_context_switches_per_second",
        "involuntary_context_switches_per_second")}
    return result


def run(args, output, report, environment):
    variants = {}
    for arm, label in (("A", "baseline"), ("B", "candidate")):
        original_binary, original_source = getattr(args, label), getattr(args, label + "_source")
        need(original_binary.is_absolute() and original_source.is_absolute(), "binary/source paths must be absolute")
        binary, source = original_binary.resolve(strict=True), original_source.resolve(strict=True)
        need(binary.is_file() and source.is_dir(), "binary/source type mismatch")
        need(not output.is_relative_to(source), "output must be outside both measured source trees")
        expected = getattr(args, label + "_sha256").lower()
        need(re.fullmatch(r"[0-9a-f]{64}", expected) is not None and digest(binary) == expected,
             label + " binary SHA256 mismatch")
        inputs = source_map(source)
        variants[arm] = {"label": label, "binary": str(binary), "sha256": expected,
                         "source": str(source), "source_map": inputs}
        save(output / (label + "-source-map.json"), inputs)
    report["variants"] = variants
    need(variants["A"]["sha256"] != variants["B"]["sha256"], "baseline/candidate binaries are identical")
    for harness in HARNESSES:
        need(harness in variants["A"]["source_map"] and harness in variants["B"]["source_map"]
             and variants["A"]["source_map"][harness] == variants["B"]["source_map"][harness],
             "benchmark harnesses are not byte-identical: " + harness)
    differences = []
    patch = []
    for path in sorted(set(variants["A"]["source_map"]) | set(variants["B"]["source_map"])):
        a, b = (variants[arm]["source_map"].get(path) for arm in ("A", "B"))
        if a == b:
            continue
        differences.append({"path": path, "baseline_sha256": a, "candidate_sha256": b})
        # Configuration inputs are bound by hashes, not disclosed in plaintext.
        if path.startswith("src/") and path.endswith(".rs"):
            contents = [(Path(variants[arm]["source"]) / path).read_text(encoding="utf-8").splitlines(keepends=True)
                        if variants[arm]["source_map"].get(path) else [] for arm in ("A", "B")]
            patch.extend(difflib.unified_diff(*contents, fromfile="baseline/" + path, tofile="candidate/" + path))
    save(output / "source-differences.json", differences)
    (output / "source-differences.patch").write_text("".join(patch), encoding="utf-8")
    report["source_differences"] = differences
    report["source_diff_sha256"] = digest(output / "source-differences.patch")

    def verify():
        for variant in variants.values():
            need(digest(Path(variant["binary"])) == variant["sha256"], "binary changed during comparison")
            need(source_map(Path(variant["source"])) == variant["source_map"], "source changed during comparison")

    for sample in report["samples"]:
        verify()
        variant = variants[sample["arm"]]
        sample["executed"] = True
        argv = [variant["binary"], "--ignored", "--exact", TESTS[sample["kind"]], "--nocapture", "--test-threads=1"]
        try:
            stdout = run_child(argv, variant["source"], environment, output,
                               f"sample-{sample['index']:02d}-{sample['kind']}-{sample['arm']}", args.timeout, sample)
            need(sample["exit_code"] == 0 and not sample["timed_out"] and not sample["interrupted"],
                 "benchmark child failed/interrupted/timed out; no automatic retry")
            need(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout) is not None,
                 "exact one-test successful libtest completion missing")
            sample["raw"] = (parse_receipt(stdout) if sample["kind"] == "receipt"
                             else parse_idle(stdout, args.idle_seconds))
            verify()
            sample["passed"] = True
        except (Exception, KeyboardInterrupt) as error:
            sample["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            save(output / "report.json", report)
            print(json.dumps({key: sample.get(key) for key in ("index", "kind", "arm", "passed", "error")}), flush=True)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, type=Path, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--blocks", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--idle-seconds", type=int, choices=range(1, 31), default=10)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    need(number(args.timeout, positive=True), "timeout must be positive and finite")
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = dict(os.environ)
    removed = sorted(name for name in environment if name.startswith(("HEPTA_", "SSH_", "RUST_TEST_")))
    for name in removed:
        environment.pop(name)
    supplied = {"RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2",
                "HEPTA_IDLE_MAINTENANCE_SECONDS": str(args.idle_seconds)}
    environment.update(supplied)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    plan = [(kind, arm) for kind in TESTS for arm in "ABBA" * args.blocks]
    report = {"schema": "hepta-record-idle-abba/v1", "passed": False, "automatic_retries": 0,
        "scope": "isolated guarded receipt and empty-pool idle comparisons; no general throughput or allocation claim",
        "source_binding": "observed source map and binary SHA256; actual matching build provenance must be supplied separately",
        "termination_scope": "only original Popen child is killed/reaped on timeout; descendants are not signaled",
        "order_per_test": "ABBA" * args.blocks, "idle_seconds": args.idle_seconds, "timeout_seconds": args.timeout,
        "removed_inherited_environment_names": removed, "supplied_test_environment": supplied,
        "rss_note": "raw receipt maxRSS is Linux process-lifetime high-water; not per-wave allocation count",
        "runner_sha256": digest(Path(__file__)), "statistics": None,
        "samples": [{"index": index, "kind": kind, "arm": arm, "executed": False, "passed": False}
                    for index, (kind, arm) in enumerate(plan)]}
    started = time.monotonic()
    try:
        run(args, output, report, environment)
        report["statistics"] = aggregate(report["samples"])
        report["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}", statistics=None)
    report["elapsed_seconds"] = time.monotonic() - started
    save(output / "report.json", report)
    print(json.dumps({"report": str(output / "report.json"), "passed": report["passed"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
