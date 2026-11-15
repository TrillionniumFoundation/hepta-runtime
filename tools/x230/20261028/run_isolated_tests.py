#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run Cargo's compiled libtest inventory in isolated processes, without retries."""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time

from audit_isolated_tests import case_stdout_proof


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def append(path, value):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.flush()


def command(argv, output, name, timeout, capture=False):
    started = time.monotonic()
    result = {"argv": argv, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "exit_code": None, "timed_out": False}
    interrupted = None
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = None
        try:
            process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, start_new_session=True)
            result["pid"] = process.pid
            result["exit_code"] = process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            result["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
            interrupted = error if isinstance(error, KeyboardInterrupt) else None
            # wait() timed out without reaping: this is our original child group.
            os.killpg(process.pid, signal.SIGKILL)
            result["exit_code"] = process.wait(timeout=30)
        except OSError as error:
            result["launch_error"] = str(error)
        finally:
            result["elapsed_seconds"] = time.monotonic() - started
            for label, source in (("stdout", stdout), ("stderr", stderr)):
                result[label + "_bytes"] = source.seek(0, os.SEEK_END)
                source.seek(0)
                filename = f"{name}.{label}.log.gz"
                with gzip.open(output / filename, "wb") as compressed:
                    shutil.copyfileobj(source, compressed)
                result[label + "_gzip"] = filename
            append(output / "commands.jsonl", result)
        stdout.seek(0)
        captured = stdout.read().decode("utf-8", errors="strict") if capture else None
    if interrupted is not None:
        raise interrupted
    return result, captured


def inventory(text):
    names, totals = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        total = re.fullmatch(r"(\d+) tests?, (\d+) benchmarks?", line)
        if total:
            totals.append(tuple(int(value) for value in total.groups()))
            continue
        if not line.endswith(": test"):
            raise ValueError(f"unsupported libtest listing line: {line!r}")
        names.append(line[:-6])
    if len(names) != len(set(names)):
        raise ValueError("duplicate libtest names in one executable")
    if totals and totals != [(len(names), 0)]:
        raise ValueError("inventory totals disagree with exact test names or contain benchmarks")
    return names


def run(args, output, summary):
    artifacts = Path(args.artifacts).resolve()
    source = Path(args.source_manifest).resolve()
    shutil.copyfile(artifacts, output / "cargo-artifacts.jsonl")
    shutil.copyfile(source, output / "source-manifest.input")
    summary.update({"artifacts_path": str(artifacts), "artifacts_sha256": digest(output / "cargo-artifacts.jsonl"),
                    "source_manifest_path": str(source), "source_manifest_sha256": digest(output / "source-manifest.input"),
                    "case_timeout_seconds": args.timeout, "filter": args.filter, "retries": 0, "binaries": []})
    binaries, finished = {}, 0
    for number, line in enumerate((output / "cargo-artifacts.jsonl").read_text().splitlines(), 1):
        if not line.strip():
            continue
        event = json.loads(line)  # Any malformed build record fails the run.
        if not isinstance(event, dict):
            raise ValueError(f"Cargo artifact line {number} is not an object")
        if event.get("reason") == "build-finished":
            if event.get("success") is not True:
                raise ValueError("Cargo reports an unsuccessful build")
            finished += 1
        if event.get("reason") == "compiler-artifact" and event.get("profile", {}).get("test") is True:
            if event.get("executable"):
                path = Path(event["executable"]).resolve()
                binaries[str(path)] = {"path": str(path), "sha256": digest(path), "target": event.get("target")}
    if finished != 1:
        raise ValueError("expected exactly one successful Cargo build-finished record")
    if not binaries:
        raise ValueError("no compiled test executables found")
    summary["binaries"] = list(binaries.values())
    selected = 0
    for binary_index, binary in enumerate(binaries.values()):
        prefix = f"binary-{binary_index:03d}"
        try:
            listings = []
            for ignored in (False, True):
                argv = [binary["path"], "--list", "--format", "terse"] + (["--ignored"] if ignored else [])
                result, text = command(argv, output, prefix + ("-ignored" if ignored else "-list"), args.timeout, True)
                if result["exit_code"] != 0 or result["timed_out"]:
                    raise ValueError(f"libtest enumeration failed: {result}")
                listings.append(inventory(text))
            names, ignored_names = listings[0], set(listings[1])
            if not ignored_names.issubset(names):
                raise ValueError("ignored inventory is not a subset of the full inventory")
        except Exception as error:
            summary["enumeration_errors"].append({"binary": binary["path"], "error": str(error)})
            continue
        binary.update({"inventory_count": len(names), "ignored_names": sorted(ignored_names)})
        for name in names:
            if args.filter and args.filter not in name:
                continue
            selected += 1
            row = {"binary": binary["path"], "binary_sha256": binary["sha256"], "name": name, "attempt": 1}
            if name in ignored_names:
                row.update({"status": "ignored", "executed": False, "attempt": 0})
            else:
                result, _ = command([binary["path"], name, "--exact", "--test-threads=1"],
                                    output, f"case-{selected:06d}", args.timeout)
                row.update(result, executed=True)
                proof = case_stdout_proof(output / result["stdout_gzip"], name, len(names), result["stdout_bytes"])
                row["stdout_proof"] = proof
                row["status"] = "passed" if result["exit_code"] == 0 and not result["timed_out"] and proof["passed"] else "failed"
            summary[row["status"]] += 1
            append(output / "tests.jsonl", row)
            if selected % 25 == 0 or row["status"] == "failed":
                print(json.dumps({"selected": selected, **{key: summary[key] for key in ("passed", "failed", "ignored")}}), flush=True)
        if digest(Path(binary["path"])) != binary["sha256"]:
            raise ValueError(f"test executable changed during execution: {binary['path']}")
    summary["selected"] = selected
    if summary["passed"] + summary["failed"] == 0:
        raise ValueError("no runnable tests matched the requested inventory/filter")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, help="Cargo no-run --message-format=json stdout JSONL")
    parser.add_argument("--source-manifest", required=True, help="source manifest whose path and SHA256 are recorded")
    parser.add_argument("--output", required=True, help="new evidence directory; existing paths are refused")
    parser.add_argument("--filter", default="", help="optional test-name substring")
    parser.add_argument("--timeout", type=float, default=180, help="per-case/enumeration timeout in seconds")
    args = parser.parse_args()
    if not 0 < args.timeout < float("inf"):
        parser.error("--timeout must be positive and finite")
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    summary = {"schema": "hepta-isolated-libtest/v1", "passed": 0, "failed": 0, "ignored": 0, "enumeration_errors": []}
    started = time.monotonic()
    try:
        run(args, output, summary)
    except (Exception, KeyboardInterrupt) as error:
        summary["fatal_error"] = f"{type(error).__name__}: {error}"
    summary["elapsed_seconds"] = time.monotonic() - started
    summary["success"] = not (summary["failed"] or summary["enumeration_errors"] or summary.get("fatal_error"))
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(output / "summary.json"), "success": summary["success"]}), flush=True)
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
