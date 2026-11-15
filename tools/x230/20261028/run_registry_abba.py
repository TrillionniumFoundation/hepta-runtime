#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Retain every A62/candidate libtest registry microbenchmark run in ABBA order."""
import argparse
import json
from pathlib import Path
import re
import shutil
import signal
import statistics
import time

from run_isolated_tests import append, command, digest, inventory


SUFFIX = "positive_reuse_microbenchmark_6000_synthetic_records"
FIELDS = ("cold_lookup_ms", "hot_reuse_ms", "legacy_sorted_median_ms", "streamed_median_ms")
RESULT = re.compile(r"isolated_fixture_records=(\d+) " + " ".join(
    field + r"=(\d+(?:\.\d+)?)" for field in FIELDS))


def run(args, output, summary):
    variants = {}
    summary["variants"] = variants
    for label in ("baseline", "candidate"):
        path = Path(getattr(args, label)).resolve(strict=True)
        source = Path(getattr(args, label + "_source_manifest")).resolve(strict=True)
        snapshot = output / (label + "-source-manifest.input")
        shutil.copyfile(source, snapshot)
        variant = {"path": str(path), "sha256": digest(path), "source_manifest_path": str(source),
                   "source_manifest_sha256": digest(snapshot)}
        variants[label] = variant
        result, listing = command([str(path), "--ignored", "--list", "--format", "terse"],
                                  output, label + "-inventory", args.timeout, True)
        if result["exit_code"] != 0 or result["timed_out"]:
            raise ValueError(f"{label} ignored-test enumeration failed")
        names = [name for name in inventory(listing) if name.split("::")[-1] == SUFFIX]
        if len(names) != 1:
            raise ValueError(f"{label} requires exactly one ignored {SUFFIX}: {names}")
        variant["test_name"] = names[0]
    if variants["baseline"]["sha256"] == variants["candidate"]["sha256"]:
        raise ValueError("baseline and candidate executables have the same SHA256")
    rows = []
    for block in range(args.blocks):
        for position, label in enumerate(("baseline", "candidate", "candidate", "baseline")):
            variant = variants[label]
            row = {"sample": len(rows) + 1, "block": block + 1, "position": position + 1,
                   "variant": label, "binary_sha256": variant["sha256"], "attempt": 1}
            try:
                if digest(Path(variant["path"])) != variant["sha256"]:
                    raise ValueError("executable changed before sample")
                result, stdout = command([variant["path"], variant["test_name"], "--ignored",
                                          "--exact", "--nocapture", "--test-threads=1"],
                                         output, f"sample-{row['sample']:03d}-{label}", args.timeout, True)
                row.update(result)
                matches = RESULT.findall(stdout)
                if result["exit_code"] != 0 or result["timed_out"]:
                    raise ValueError("microbenchmark process failed or timed out")
                if len(matches) != 1 or int(matches[0][0]) != 6000:
                    raise ValueError(f"expected one complete 6000-record result; found {matches}")
                row["metrics"] = dict(zip(FIELDS, map(float, matches[0][1:])))
                if digest(Path(variant["path"])) != variant["sha256"]:
                    raise ValueError("executable changed during sample")
                row["success"] = True
            except Exception as error:
                row.update(success=False, error=f"{type(error).__name__}: {error}")
            rows.append(row)
            append(output / "samples.jsonl", row)
            print(json.dumps({key: row.get(key) for key in
                              ("sample", "block", "variant", "success", "metrics", "error")}), flush=True)
    summary["samples"] = len(rows)
    summary["failed_samples"] = sum(not row["success"] for row in rows)
    summary["per_variant"] = {}
    for label in variants:
        selected = [row for row in rows if row["variant"] == label and row["success"]]
        summary["per_variant"][label] = {field: {
            "samples": [row["metrics"][field] for row in selected],
            "median": statistics.median(row["metrics"][field] for row in selected) if selected else None,
        } for field in FIELDS}
    summary["paired_blocks"] = []
    for block in range(1, args.blocks + 1):
        selected = [row for row in rows if row["block"] == block]
        pair = {"block": block, "complete": all(row["success"] for row in selected)}
        if pair["complete"]:
            pair["candidate_to_baseline"] = {}
            for field in FIELDS:
                means = {label: statistics.mean(row["metrics"][field] for row in selected
                                                if row["variant"] == label) for label in variants}
                pair["candidate_to_baseline"][field] = (
                    means["candidate"] / means["baseline"] if means["baseline"] else None)
        summary["paired_blocks"].append(pair)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for label in ("baseline", "candidate"):
        parser.add_argument("--" + label, required=True, help=label + " compiled libtest executable")
        parser.add_argument("--" + label + "-source-manifest", required=True)
    parser.add_argument("--output", required=True, help="new evidence directory; must not exist")
    parser.add_argument("--blocks", type=int, default=4, help="ABBA blocks; default 4 = 8 samples per binary")
    parser.add_argument("--timeout", type=float, default=180, help="per-process timeout in seconds")
    args = parser.parse_args()
    if args.blocks < 1 or not 0 < args.timeout < float("inf"):
        parser.error("--blocks and finite --timeout must be positive")
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    summary = {"schema": "hepta-registry-abba/v1", "blocks": args.blocks, "order": "ABBA", "retries": 0,
               "scope": "synchronous isolated fixture lookup; not async/native throughput",
               "cold_definition": "empty in-process cache, not cold operating-system page cache",
               "internal_samples": "libtest emits one cold, one hot and two six-run medians per process; internal raw timings are unavailable",
               "timing_note": "command elapsed includes fixture creation; reported metric milliseconds do not",
               "runner_path": str(Path(__file__).resolve()), "runner_sha256": digest(Path(__file__)),
               "helper_sha256": digest(Path(__file__).with_name("run_isolated_tests.py"))}
    started = time.monotonic()
    try:
        run(args, output, summary)
    except (Exception, KeyboardInterrupt) as error:
        summary["fatal_error"] = f"{type(error).__name__}: {error}"
    summary["elapsed_seconds"] = time.monotonic() - started
    summary["success"] = not (summary.get("fatal_error") or summary.get("failed_samples"))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(output / "summary.json"), "success": summary["success"]}), flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
