#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Direct ABBA of two pinned libtest builds; not release or remote-launch TPS."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import signal
import time

from run_isolated_tests import command, digest, inventory

TEST = "mcp::runtime::jobs::registry_concurrency_bench::cold_positive_and_absent_concurrency_benchmark"
BENCH = "src/mcp/runtime/jobs_registry_concurrency_bench.rs"
KINDS = ("fresh_positive", "absent", "known_invalidated")
WIDTHS = (1, 4, 8)


def need(okay, reason):
    if not okay:
        raise ValueError(reason)


def source_map(root):
    files = [root / name for name in ("Cargo.toml", "Cargo.lock")]
    if (root / "build.rs").exists():
        files.append(root / "build.rs")
    for name in ("src", "examples"):
        files += [path for path in (root / name).rglob("*") if path.is_file()]
    need(all(not path.is_symlink() for path in files), "source symlink refused")
    return {str(path.relative_to(root)): digest(path) for path in sorted(files)}


def percentile(values, quantile):
    values = sorted(values)
    return values[math.ceil(len(values) * quantile) - 1]


def parse(stdout):
    waves, finals = [], []
    for line in stdout.splitlines():
        match = re.search(r"REGISTRY_CONCURRENCY_(WAVE|BENCH) (\{.*\})$", line)
        if match:
            (waves if match[1] == "WAVE" else finals).append(json.loads(match[2]))
    need(len(finals) == 1 and len(waves) == 36, "expected exactly 36 wave records and one final record")
    final = finals[0]
    need(final.get("schema") == "hepta-registry-cold-concurrency-v1"
         and final.get("records") == 6000 and final.get("actual_worker_limit") == 4
         and final.get("repetitions") == 4 and final.get("remote_effects") == 0
         and final.get("rows") == waves, "final metadata/rows differ from original wave records")
    expected = [(r, kind, c) for r in range(4)
                for kind in (KINDS if r % 2 == 0 else tuple(reversed(KINDS)))
                for c in (WIDTHS if r % 2 == 0 else tuple(reversed(WIDTHS)))]
    actual = [(row.get("repetition"), row.get("kind"), row.get("concurrency")) for row in waves]
    need(actual == expected, "missing, duplicate, reordered or unexpected wave")
    for row in waves:
        c = row["concurrency"]
        values = row.get("latencies_ms")
        need(type(c) is int and row.get("successes") == c and row.get("failures") == 0
             and isinstance(values, list) and len(values) == c, "wave call inventory/failure mismatch")
        need(row.get("primed_strict_bindings") == (c if row["kind"] == "known_invalidated" else 0),
             "wave strict-ownership priming does not match its category")
        for value in [*values, row["wall_seconds"], row["user_cpu_seconds"], row["system_cpu_seconds"]]:
            need(type(value) in (int, float) and math.isfinite(value) and value >= 0, "invalid timing/CPU number")
        need(row["wall_seconds"] > 0, "nonpositive wave duration")
        computed = {"calls_per_second": c / row["wall_seconds"],
                    "cpu_seconds_per_call": (row["user_cpu_seconds"] + row["system_cpu_seconds"]) / c,
                    "p50_ms": percentile(values, .5), "p95_ms": percentile(values, .95)}
        need(all(math.isclose(row[key], value, rel_tol=1e-9, abs_tol=1e-12)
                 for key, value in computed.items()), "reported wave metrics differ from raw values")
    need(sum(row["successes"] for row in waves) == 156, "expected exactly 156 timed calls")
    return waves


def aggregate(samples):
    summary = {}
    for arm in ("A", "B"):
        summary[arm] = {}
        for kind in KINDS:
            summary[arm][kind] = {}
            for c in WIDTHS:
                rows = [row for sample in samples if sample["arm"] == arm for row in sample["waves"]
                        if row["kind"] == kind and row["concurrency"] == c]
                latencies = [value for row in rows for value in row["latencies_ms"]]
                wall = sum(row["wall_seconds"] for row in rows)
                cpu = sum(row["user_cpu_seconds"] + row["system_cpu_seconds"] for row in rows)
                summary[arm][kind][str(c)] = {"waves": len(rows), "calls": len(latencies),
                    "summed_wave_seconds": wall, "calls_per_second": len(latencies) / wall,
                    "cpu_seconds": cpu, "cpu_ms_per_call": 1000 * cpu / len(latencies),
                    **{f"p{q}_ms": percentile(latencies, q / 100) for q in (50, 95, 99)},
                    "max_ms": max(latencies), "latencies_ms": latencies}
    return summary


def run(args, output, report):
    variants = {}
    for arm, label in (("A", "baseline"), ("B", "candidate")):
        binary = getattr(args, label).resolve(strict=True)
        source = getattr(args, label + "_source").resolve(strict=True)
        need(not output.is_relative_to(source), "output cannot mutate source")
        expected = getattr(args, label + "_sha256")
        need(digest(binary) == expected, label + " ELF SHA256 mismatch")
        inputs = source_map(source)
        variants[arm] = {"label": label, "binary": str(binary), "sha256": expected,
                         "source": str(source), "source_map": inputs}
        (output / (label + "-source-map.json")).write_text(json.dumps(inputs, indent=2) + "\n")
    report["variants"] = variants
    need(variants["A"]["sha256"] != variants["B"]["sha256"], "identical baseline/candidate ELF hashes")
    need(variants["A"]["source_map"][BENCH] == variants["B"]["source_map"][BENCH],
         "benchmark source modules are not byte-identical")

    def verify():
        for variant in variants.values():
            need(digest(Path(variant["binary"])) == variant["sha256"], "ELF changed")
            need(source_map(Path(variant["source"])) == variant["source_map"], "compiler inputs changed")

    report["enumerations"] = []
    for arm, variant in variants.items():
        result, stdout = command([variant["binary"], "--ignored", "--list", "--format", "terse"],
                                 output, arm + "-inventory", args.timeout, True)
        report["enumerations"].append({"arm": arm, **result})
        need(result["exit_code"] == 0 and not result["timed_out"] and inventory(stdout).count(TEST) == 1,
             "exact ignored benchmark not present exactly once")
    for sample in report["samples"]:
        verify()
        sample["executed"] = True
        try:
            result, stdout = command([variants[sample["arm"]]["binary"], "--ignored", "--exact",
                                      TEST, "--nocapture"], output,
                                     f"sample-{sample['index']:02d}-{sample['arm']}", args.timeout, True)
            sample.update(result)
            need(result["exit_code"] == 0 and not result["timed_out"], "benchmark process failed/timed out")
            need(re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout) is not None,
                 "exact libtest completion missing")
            sample["waves"] = parse(stdout)
            sample["passed"] = True
        except Exception as error:
            sample["error"] = f"{type(error).__name__}: {error}"
        verify()
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({key: sample.get(key) for key in ("index", "arm", "passed", "error")}), flush=True)
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, type=Path, required=True)
        parser.add_argument("--" + label + "-sha256", required=True)
        parser.add_argument("--" + label + "-source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--blocks", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args()
    need(math.isfinite(args.timeout) and args.timeout > 0, "timeout must be positive and finite")
    removed = sorted(name for name in os.environ if name.startswith(("HEPTA_", "SSH_", "RUST_TEST_")))
    for name in removed:
        os.environ.pop(name)
    os.environ.update(RUST_TEST_THREADS="1", TOKIO_WORKER_THREADS="2")
    output = args.out.resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    report = {"schema": "hepta-registry-microbench-abba/v1", "passed": False,
        "scope": "isolated libtest-build lookup comparison; not release or launch TPS; no qualification claim",
        "source_binding": "observed compiler inputs and supplied ELF identity; compilation provenance is separate",
        "order": "ABBA" * args.blocks, "automatic_retries": 0, "timeout_seconds": args.timeout,
        "removed_inherited_environment_names": removed,
        "test_environment": {"RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2"},
        "percentiles": "nearest-rank pooled original call latencies; small cohorts are not production tails",
        "resource_note": "CPU uses per-wave RUSAGE_SELF; maxRSS in raw rows is process-lifetime, not per-wave",
        "runner_sha256": digest(Path(__file__)), "helper_sha256": digest(Path(__file__).with_name("run_isolated_tests.py")),
        "samples": [{"index": i, "arm": arm, "executed": False, "passed": False}
                    for i, arm in enumerate("ABBA" * args.blocks)]}
    started = time.monotonic()
    try:
        run(args, output, report)
        report["passed"] = all(sample["passed"] for sample in report["samples"])
        report["statistics"] = aggregate(report["samples"]) if report["passed"] else None
    except (Exception, KeyboardInterrupt) as error:
        report.update(passed=False, error=f"{type(error).__name__}: {error}", statistics=None)
    report["elapsed_seconds"] = time.monotonic() - started
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"report": str(output / "report.json"), "passed": report["passed"]}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
