#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run the 14 local-only R25 harness gates on native Linux; skipped tests fail."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import unittest

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.absolute()
    if out.resolve() != out or os.path.lexists(out):
        raise ValueError("fresh canonical tool-test output required")
    out.mkdir(mode=0o700)
    started = time.time_ns()
    raw = Path("/proc/self/stat").read_text()
    visible = int(raw.split("(", 1)[0]) == os.getpid()
    report = {"schema":"hepta-r25-lifecycle-tool-tests/v1", "passed":False,
              "started_realtime_ns":started, "proc_pid_namespace_matches":visible,
              "remote_connections":0,"remote_effects":0,"automatic_retries":0}
    if sys.platform != "linux" or not visible:
        report["error"] = "native Linux /proc PID namespace is required; no identity gate is relaxed"
    else:
        suite = unittest.defaultTestLoader.loadTestsFromNames(
            ["test_r25_lifecycle_tools", "test_verify_saturation_extension"])
        with (out / "tests.stderr").open("x", encoding="utf-8") as stream:
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        report.update(tests_run=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                      skipped=len(result.skipped), passed=result.wasSuccessful() and result.testsRun == 14 and not result.skipped)
        test_raw = (out / "tests.stderr").read_bytes()
        report["stderr"] = {"bytes":len(test_raw),"sha256":hashlib.sha256(test_raw).hexdigest()}
    report["finished_realtime_ns"] = time.time_ns()
    with (out / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report,stream,sort_keys=True,indent=2)
        stream.write("\n")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
