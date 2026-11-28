#!/usr/bin/env python3
"""Record a new normal corpus from the already freshly built target SDK binary."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attempt", required=True)
    args = parser.parse_args()
    assert args.attempt.replace("-", "").isalnum()
    evidence = ROOT / "evidence"
    out = evidence / "oracle-runs" / args.attempt
    out.mkdir(parents=True)
    build_raw = (evidence / "oracle-build.json").read_bytes()
    build = json.loads(build_raw)
    binary = ROOT / build["binary_relative_path"]
    assert sha(binary.read_bytes()) == build["binary_sha256"]
    assert sha((ROOT / "oracle/main.rs").read_bytes()) == build["source_sha256"]
    assert sha((ROOT / "oracle/generated_get_info.rs").read_bytes()) == build["get_info_sha256"]
    assert sha((ROOT / "oracle/Cargo.lock").read_bytes()) == build["fixture_lock_sha256"]
    case_raw = (ROOT / "cases/normal.jsonl").read_bytes()
    cases = [json.loads(line) for line in case_raw.splitlines()]
    for case in cases:
        for event in case["events"]:
            request = json.loads(event["wire"])
            assert request["method"] in {"server/discover", "initialize", "ping", "notifications/initialized", "completion/complete"}
            assert "\n" not in event["wire"]
    (out / "cases.jsonl").write_bytes(case_raw)
    started = time.monotonic()
    process = subprocess.run([str(binary)], input=case_raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    (out / "stdout.jsonl").write_bytes(process.stdout)
    (out / "stderr").write_bytes(process.stderr)
    receipt = {"schema": "hepta.g2.target-normal-observation.v1", "attempt": args.attempt,
        "oracle_build_sha256": sha(build_raw), "binary_sha256": sha(binary.read_bytes()),
        "cases_sha256": sha(case_raw), "observations_sha256": sha(process.stdout),
        "stderr_sha256": sha(process.stderr), "exit_code": process.returncode,
        "elapsed_seconds": time.monotonic() - started, "fresh_build_reused_unchanged": True,
        "fresh_observation": True, "all_frames_lf_terminated": True}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    assert process.returncode == 0 and not process.stderr
    results = [json.loads(line) for line in process.stdout.splitlines()]
    assert len(results) == len(cases)
    for case, observed in zip(cases, results, strict=True):
        assert case["label"] == observed["label"]
        for event, response in zip(case["events"], observed["events"], strict=True):
            if event["response"]:
                assert "result" in response["response"], (case["label"], response)
    receipt["all_normal_responses_succeeded"] = True
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    (evidence / "oracle-normal.jsonl").write_bytes(process.stdout)
    (evidence / "oracle-observation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
