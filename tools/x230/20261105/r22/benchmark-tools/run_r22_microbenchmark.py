#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run one qualified, retained ignored test; report mechanism timing separately."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

NAME = ("mcp::runtime::ssh::observation_pool::profile::reference_tests::"
        "ssh_reference_complete_read_abba_microbenchmark")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=3600)
    args = parser.parse_args()
    root = args.root.resolve()
    qualification = root / "qualification-01"
    report_path = qualification / "report.json"
    deadline = time.monotonic() + args.wait_seconds
    while True:
        qualified = json.loads(report_path.read_text())
        if qualified.get("finished_utc"):
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("qualification did not finish; no measurement started")
        time.sleep(3)
    assert qualified["qualified"] is True, qualified.get("error")
    assert qualified["source_tested"] == qualified["source_after"]
    assert all(type(s["returncode"]) is int and s["returncode"] == 0
               for s in qualified["stages"])
    for relative, sha in qualified["source_after"].items():
        assert digest(root / "source" / relative) == sha, relative
    qualification_sha = digest(report_path)
    isolated = json.loads((qualification / "isolated-tests/summary.json").read_text())
    assert isolated["success"] is True and isolated["retries"] == 0
    output = root / "microbenchmark-01"
    output.mkdir(mode=0o700)
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("HEPTA_", "SSH_", "RUST_TEST_")) or key in {
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", "PYTHONPATH", "PYTHONHOME", "RUST_LOG"}:
            env.pop(key)
    env.update({"RUST_TEST_THREADS": "1", "TOKIO_WORKER_THREADS": "2",
                "MALLOC_ARENA_MAX": "1", "PYTHONNOUSERSITE": "1"})
    report = {"schema": "hepta-r22-qualified-mechanism-benchmark/v1", "passed": False,
              "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "qualification_sha256": qualification_sha, "exact_name": NAME,
              "profile": "retained cargo test dev profile, opt-level=1; not release RPC throughput",
              "rss_comparable": False, "automatic_retries": 0, "listings": []}
    try:
        selected = []
        for index, entry in enumerate(isolated["binaries"]):
            binary = Path(entry["path"])
            assert digest(binary) == entry["sha256"]
            command = [str(binary), "--list", "--ignored"]
            result = subprocess.run(command, env=env, capture_output=True, timeout=30)
            prefix = output / f"listing-{index:02d}"
            prefix.with_suffix(".stdout").write_bytes(result.stdout)
            prefix.with_suffix(".stderr").write_bytes(result.stderr)
            assert result.returncode == 0
            names = [line[:-6] for line in result.stdout.decode().splitlines()
                     if line.endswith(": test")]
            report["listings"].append({"binary": str(binary), "sha256": entry["sha256"],
                                       "command": command, "ignored_count": len(names),
                                       "target_found": NAME in names})
            if NAME in names:
                selected.append(entry)
        assert len(selected) == 1, "must identify exactly one retained target executable"
        entry = selected[0]
        report["binary"] = entry
        command = [entry["path"], "--exact", NAME, "--ignored", "--nocapture", "--test-threads=1"]
        report["command"] = command
        with (output / "run.stdout").open("xb") as stdout, (output / "run.stderr").open("xb") as stderr:
            result = subprocess.run(command, env=env, stdout=stdout, stderr=stderr, timeout=180)
        report["returncode"] = result.returncode
        raw = (output / "run.stdout").read_text()
        assert result.returncode == 0
        assert re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;", raw)
        assert "running 1 test" in raw
        rows = [json.loads(line.split("SSH_REFERENCE_ABBA ", 1)[1])
                for line in raw.splitlines() if "SSH_REFERENCE_ABBA " in line]
        setups = [r for r in rows if r["kind"] == "setup"]
        samples = [r for r in rows if r["kind"] == "sample"]
        assert len(setups) == 1 and len(samples) == 12
        setup = setups[0]
        assert setup["blocks"] == 3 and setup["iterations_per_arm"] == 128
        assert setup["rss_comparable"] is False
        assert setup["sha256"] == digest(Path(setup["path"]))
        for i, row in enumerate(samples):
            assert row["block"] == i // 4 and row["position"] == i % 4
            assert row["arm"] == ["sha", "reference", "reference", "sha"][i % 4]
            assert row["iterations"] == 128
            for clock in ("wall", "thread_cpu", "process_cpu"):
                assert row[f"{clock}_ns"] == row[f"{clock}_end_ns"] - row[f"{clock}_start_ns"] > 0
        means = {}
        for arm in ("sha", "reference"):
            group = [r for r in samples if r["arm"] == arm]
            count = sum(r["iterations"] for r in group)
            means[arm] = {clock + "_ns_per_verification": sum(r[clock + "_ns"] for r in group) / count
                          for clock in ("wall", "thread_cpu", "process_cpu")}
        report.update({"setup": setup, "samples": samples, "means": means,
                       "reference_over_sha": {k: means["reference"][k] / means["sha"][k]
                                              for k in means["sha"]}})
        assert digest(Path(entry["path"])) == entry["sha256"]
        assert digest(report_path) == qualification_sha
        for relative, sha in qualified["source_after"].items():
            assert digest(root / "source" / relative) == sha, relative
        report["passed"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["logs"] = {str(p.relative_to(output)): {"sha256": digest(p), "bytes": p.stat().st_size}
                          for p in sorted(output.iterdir()) if p.is_file()}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: report.get(k) for k in ("passed", "means", "reference_over_sha", "error")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
