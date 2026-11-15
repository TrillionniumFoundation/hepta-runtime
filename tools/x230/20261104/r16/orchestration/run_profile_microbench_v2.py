#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run and independently summarize the preserved R16 test-profile microbenchmarks."""
from pathlib import Path
import hashlib
import json
import os
import re
import statistics
import subprocess
import time

ROOT = Path("/home/qian/hepta-runtime-optimization-20261104-r16")


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    qualification = ROOT / "qualification-01"
    report = json.loads((qualification / "report.json").read_text())
    assert report["qualified"] and report["source_tested"] == report["source_after"]
    events = [json.loads(line) for line in (qualification / "retained-artifacts.jsonl").read_text().splitlines()]
    assert sum(event.get("reason") == "build-finished" and event.get("success") is True for event in events) == 1
    candidates = [event for event in events if event.get("reason") == "compiler-artifact"
                  and event.get("profile", {}).get("test") is True and event.get("executable")]
    output = ROOT / "diagnostics/profile-microbench-test-profile-02"
    output.mkdir(mode=0o700)
    wanted = ("profile_path_open", "profile_pin_set_buffer")
    matches, enumerations = [], []
    for index, candidate_event in enumerate(candidates):
        candidate_binary = Path(candidate_event["executable"])
        assert candidate_binary.parent == qualification / "test-binaries"
        argv = [str(candidate_binary), "--list", "--ignored"]
        listing = subprocess.run(argv, capture_output=True, timeout=30)
        prefix = "binary-" + str(index)
        (output / (prefix + ".list.stdout")).write_bytes(listing.stdout)
        (output / (prefix + ".list.stderr")).write_bytes(listing.stderr)
        enumerations.append({"argv": argv, "returncode": listing.returncode,
                             "target": candidate_event["target"],
                             "stdout_sha256": hashlib.sha256(listing.stdout).hexdigest(),
                             "stderr_sha256": hashlib.sha256(listing.stderr).hexdigest()})
        assert listing.returncode == 0, "retained test artifact enumeration failed"
        names = [line.removesuffix(": test") for line in listing.stdout.decode().splitlines()
                 if line.endswith(": test")]
        found = {name: [full for full in names if full.endswith("::" + name + "_microbenchmark")
                       or full == name + "_microbenchmark"] for name in wanted}
        if any(found.values()):
            assert all(len(values) == 1 for values in found.values()), "microbench ownership is incomplete or ambiguous"
            matches.append((candidate_event, {name: values[0] for name, values in found.items()}))
    assert len(matches) == 1, "exactly one retained artifact must own both microbenchmarks"
    event, selected_tests = matches[0]
    binary = Path(event["executable"])
    result = {"schema": "hepta-r16-pin-microbench-test-profile/v1", "passed": False,
              "classification": "qualification test-profile mechanism diagnostic; not release throughput",
              "binary_sha256": sha(binary), "cargo_profile": event["profile"],
              "qualification_report_sha256": sha(qualification / "report.json"),
              "cases": [], "automatic_retries": 0, "enumerations": enumerations,
              "selection": "enumerated exact ignored test names in every retained artifact",
              "prior_attempt": "profile-microbench-test-profile-01 selected CLI target and executed zero tests"}
    environment = dict(os.environ)
    for name in list(environment):
        if name.startswith(("HEPTA_", "SSH_", "RUST_TEST_", "MALLOC_")) or name in {"GLIBC_TUNABLES", "RUST_LOG"}:
            environment.pop(name)
    environment.update(MALLOC_ARENA_MAX="1", RUST_TEST_THREADS="1", TOKIO_WORKER_THREADS="2")
    cases = [("path", "profile_path_open", "legacy", "parsed", 2000, "microseconds/open"),
             ("buffer", "profile_pin_set_buffer", "one_buffer_per_pin", "one_buffer_per_set", 128, "microseconds/pin-set")]
    try:
        for label, name, baseline, candidate, passes, unit in cases:
            argv = [str(binary), selected_tests[name], "--exact", "--ignored", "--test-threads=1", "--nocapture"]
            row = {"name": name, "argv": argv, "unit": unit}
            result["cases"].append(row)
            started = time.monotonic_ns()
            with (output / (label + ".stdout")).open("xb") as stdout, (output / (label + ".stderr")).open("xb") as stderr:
                completed = subprocess.run(argv, env=environment, stdout=stdout, stderr=stderr, timeout=180)
            row.update(returncode=completed.returncode, runner_seconds=(time.monotonic_ns() - started) / 1e9)
            stdout = (output / (label + ".stdout")).read_text()
            stderr = (output / (label + ".stderr")).read_text()
            for stream in ("stdout", "stderr"):
                row[stream + "_sha256"] = sha(output / (label + "." + stream))
            assert completed.returncode == 0 and len(re.findall(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", stdout)) == 1, "expected one passing microbenchmark"
            samples = [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]
            assert len(samples) == 12
            expected_order = [(round_, variant) for round_ in range(6)
                              for variant in ((baseline, candidate) if round_ % 2 == 0 else (candidate, baseline))]
            assert [(sample["round"], sample["variant"]) for sample in samples] == expected_order
            for sample in samples:
                assert sample["benchmark"] == name and sample["passes"] == passes and sample["pins_per_pass"] == 6
                assert sample["wall_ns"] > 0 and sample["process_cpu_ns"] > 0
                if label == "buffer":
                    assert sample["buffer_bytes"] == 16384 and sample["bytes_per_pass"] == 1282329
            divisor = passes * (6 if label == "path" else 1) * 1000
            row["samples"] = samples
            row["statistics"] = {}
            for metric in ("process_cpu_ns", "wall_ns"):
                values = {variant: [sample[metric] / divisor for sample in samples if sample["variant"] == variant]
                          for variant in (baseline, candidate)}
                paired = [100 * (1 - values[candidate][index] / values[baseline][index]) for index in range(6)]
                row["statistics"][metric] = {
                    "variants": {variant: {"median": statistics.median(v), "min": min(v), "max": max(v)}
                                 for variant, v in values.items()},
                    "paired_improvement_percent": paired,
                    "paired_median_improvement_percent": statistics.median(paired),
                    "paired_range_percent": [min(paired), max(paired)],
                    "candidate_faster_pairs": sum(value > 0 for value in paired),
                }
        assert sha(binary) == result["binary_sha256"]
        result["passed"] = True
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        with (output / "summary.json").open("x") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
        print(json.dumps({"passed": result["passed"], "error": result.get("error"), "output": str(output)}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
