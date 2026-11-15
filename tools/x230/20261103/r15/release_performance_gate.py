#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Root-invoked one-shot release of R15 performance after reviewed archive I/O completion.
This does not run any test or benchmark. It creates one exclusive gate file.
"""
import argparse
import json
import os
from pathlib import Path
import run_local_campaigns as local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configuration-qualification-sha256", required=True)
    parser.add_argument("--local-ready-sha256", required=True)
    parser.add_argument("--archive-io-finished", action="store_true", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    path = local.CONFIG_QUAL / "report.json"
    local.bind(path, args.configuration_qualification_sha256)
    local.bind(local.LOCAL_READY, args.local_ready_sha256)
    qualification = json.loads(path.read_bytes())
    ready = json.loads(local.LOCAL_READY.read_bytes())
    local.require(ready.get("success") is True, "local ready receipt is unsuccessful")
    for item in ready["files"]:
        local.bind(item["path"], item["sha256"])
    local.require(qualification.get("success") is True
        and qualification["local_orchestrator_ready_sha256"] == args.local_ready_sha256
        and qualification["configuration_ready_sha256"] == local.CONFIG_READY_SHA
        and qualification["runtime_sha256"] == local.CANDIDATE_SHA
        and qualification["tests"] == {"passed": 1637, "failed": 0, "ignored": 33, "selected": 1670, "retries": 0},
        "configuration qualification is not successful and completely bound")
    for name in ("summary", "audit"):
        local.bind(qualification[name]["path"], qualification[name]["sha256"])
    value = {"schema": "hepta-x230-r15-performance-release/v1", "success": True,
        "release_performance": True, "archive_io_finished": True, "released_utc": local.utc(),
        "reason": args.reason, "configuration_qualification_path": str(path),
        "configuration_qualification_sha256": args.configuration_qualification_sha256,
        "local_orchestrator_ready_sha256": args.local_ready_sha256,
        "configuration_ready_sha256": local.CONFIG_READY_SHA,
        "candidate_runtime_sha256": local.CANDIDATE_SHA,
        "authority": "Explicit root invocation after archive I/O completion; no automatic release"}
    local.validate_perf_gate(value, args.configuration_qualification_sha256, args.local_ready_sha256)
    # Rename an exclusive temporary file only if the final destination is absent.
    # Hard-link publication prevents clobbering an existing gate and exposes only complete bytes.
    temporary = local.ROOT / "perf-ready-01.preparing"
    local.write_once(temporary, value)
    try:
        os.link(temporary, local.PERF_GATE, follow_symlinks=False)
    finally:
        temporary.unlink()
    print(json.dumps({"path": str(local.PERF_GATE), "sha256": local.sha(local.PERF_GATE),
                      "workloads_started": 0}), flush=True)


if __name__ == "__main__":
    main()
