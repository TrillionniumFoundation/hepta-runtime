#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Collect immutable qualification evidence and redact private execution paths."""

import argparse
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    source = args.qualification.resolve()
    work = source / "rpc-attempt-1-work"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    identities = []

    def write(path, data):
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        identities.append({"path": path, "bytes": len(data), "sha256": sha(data)})

    def write_json(path, value):
        write(path, (json.dumps(value, indent=2, allow_nan=False) + "\n").encode())

    def redact(value):
        if isinstance(value, str):
            value = value.replace(str(work), "<WORK>")
            value = value.replace(str(root) + "-target", "<TARGET>")
            value = value.replace(str(root), "<WORKTREE>")
            if "/home/" in value or "/workspace/" in value:
                raise ValueError("unclassified local path in public evidence")
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    local_bytes = (source / "attempt-1/qualification.json").read_bytes()
    rpc_bytes = (source / "rpc-attempt-1.json").read_bytes()
    raw_bytes = (work / "raw-receipts.json").read_bytes()
    local, rpc, raw = map(json.loads, [local_bytes, rpc_bytes, raw_bytes])
    assert local["passed"] and local["completed"]
    assert local["source_unchanged_after_format"]
    assert len(local["commands"]) == 6
    assert all(row["exit_code"] == 0 and not row["timed_out"] for row in local["commands"])
    assert rpc["passed"] and rpc["completed"] and rpc["failure"] is None
    assert rpc["executed_binary_unchanged"]
    assert local["binary"]["sha256"] == rpc["binary_sha256"]
    assert len(raw["plans"]) == 7 and len(raw["guards"]) == 4
    assert len(rpc["norm_checks"]) == 60 and len(rpc["negative_controls"]) == 4
    assert redact(local) == local and redact(rpc) == rpc
    write("local_attempt_1.json", local_bytes)
    write("rpc_attempt_1.json", rpc_bytes)
    write_json("source_manifest.json", local["source_after_format"])

    for row in raw["plans"]:
        assert redact(row) == row
        write_json("planners/" + row["case"] + ".json", row)
    for row in raw["guards"]:
        write_json("guards/" + row["case"] + "_" + row["kind"] + ".json", redact(row))

    norm_reports = []
    fields = ["evaluation_id", "accepted", "outcome", "gain", "f32_update_budget",
              "f32_update_budget_source_bytes_authenticated", "native_operation_wall_seconds"]
    for row in raw["norms"]:
        report = row["report"]
        norm_reports.append({"case": row["case"], "report": {key: report[key] for key in fields}})
    write_json("norm_receipts.json", norm_reports)

    logs = []
    for index in [2, 3, 4, 5]:
        data = (source / f"attempt-1/command-{index}.log").read_bytes()
        assert sha(data) == local["commands"][index - 1]["log_sha256"]
        clean = redact(data.decode()).encode()
        filename = f"logs/command-{index}.log"
        write(filename, clean)
        logs.append({"file": filename, "original_bytes": len(data),
                     "original_sha256": sha(data), "published_sha256": sha(clean)})

    manifest = {
        "schema": "hepta.native-wsp-trust-region-evidence.v1",
        "collector_sha256": sha(Path(__file__).read_bytes()),
        "raw_receipts_bytes": len(raw_bytes),
        "raw_receipts_sha256": sha(raw_bytes),
        "raw_receipts_published": False,
        "redaction": "Guard local paths replaced by <WORK>; log checkout and target paths replaced by <WORKTREE> and <TARGET>. Planner, source, local and RPC summary records are unmodified. Norm records retain explicitly listed budget and outcome fields.",
        "logs": logs,
        "files": identities,
        "qualifies": "Frozen source and binary, focused Rust checks, and the predeclared public/synthetic actual-MCP cases only.",
        "new_end_to_end_utility_evidence": False,
        "production_eligible": False,
    }
    (output / "evidence_manifest.json").write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"published_files": len(identities) + 1,
                      "norm_receipts": len(norm_reports), "binary_sha256": rpc["binary_sha256"]}))


if __name__ == "__main__":
    main()
