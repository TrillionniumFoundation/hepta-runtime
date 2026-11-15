#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run one already built probe once, preserving its complete evidence and failure."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from prepare_hash_probe import receipt, write_new
from summarize_hash_probe import summarize


def need(value, message):
    if not value:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    result = {"schema": "hepta-x230-full-file-hash-microprobe-run/v1", "passed": False,
              "started_unix": time.time(), "automatic_retries": 0, "probe_launches": 0,
              "interrupted": False, "sigint_forwarded": False}
    child = None

    def wait_owned():
        while True:
            if result["interrupted"] and not result["sigint_forwarded"]:
                result["sigint_forwarded"] = True
                try:
                    child.send_signal(signal.SIGINT)
                except OSError as error:
                    result["signal_error"] = {"type": type(error).__name__, "reason": str(error)}
            try:
                result["probe_returncode"] = child.wait()
                return
            except KeyboardInterrupt:
                result["interrupted"] = True

    try:
        result["build"], raw = receipt(args.build.absolute(), True)
        build = json.loads(raw)
        need(build.get("schema") == "hepta-x230-full-file-hash-microprobe-build/v1"
             and build.get("prepared") is True and build.get("compiled") is True
             and build.get("error") is None and build.get("probe_executed") is False
             and build.get("format_returncode") == 0 and build.get("compile_returncode") == 0,
             "completed formatted standalone build required")
        need(build.get("inputs_before") == build.get("inputs_after"), "build inputs changed")
        need(build.get("source_to_publish") == build["inputs_after"].get(
            str(args.build.absolute().parent / "hash_buffer_probe.rs")),
            "actual formatted compilation source is not bound for publication")
        result["build_inputs_before_run"] = {path: receipt(Path(path)) for path in build["inputs_after"]}
        need(result["build_inputs_before_run"] == build["inputs_after"], "bound build inputs changed before probe")
        binary = Path(build["probe_binary"]["path"])
        result["probe_binary_before"] = receipt(binary)
        need(result["probe_binary_before"] == build["probe_binary"], "compiled standalone probe changed")
        result["target_before"] = receipt(Path("/usr/bin/ssh"))
        write_new(args.output_dir / "run-start.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
        with (args.output_dir / "raw.jsonl").open("xb") as stdout, (args.output_dir / "stderr.log").open("xb") as stderr:
            child = subprocess.Popen([str(binary)], stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, start_new_session=True)
            result["probe_launches"] = 1
            wait_owned()
            for stream in (stdout, stderr):
                stream.flush()
                os.fsync(stream.fileno())
        result["target_after"] = receipt(Path("/usr/bin/ssh"))
        result["probe_binary_after"] = receipt(binary)
        result["build_inputs_after_run"] = {path: receipt(Path(path)) for path in build["inputs_after"]}
        need(result["target_before"] == result["target_after"], "fixed target changed during probe")
        need(result["probe_binary_before"] == result["probe_binary_after"], "probe binary changed during execution")
        need(result["build_inputs_before_run"] == result["build_inputs_after_run"], "bound build inputs changed during probe")
        need(not result["interrupted"], "interrupted probe cannot support a decision")
    except BaseException as error:
        result["error"] = {"type": type(error).__name__, "reason": str(error)}
        if child is not None:
            result["interrupted"] |= isinstance(error, KeyboardInterrupt)
            wait_owned()
    finally:
        try:
            path = args.output_dir / "raw.jsonl"
            if path.is_file():
                result["raw"], raw = receipt(path, True)
                analysis = summarize(raw, result.get("probe_returncode"), result.get("target_before", {}).get("sha256"))
                if "error" in result:
                    analysis["valid_complete_experiment"] = False
                    analysis["eligible_for_separate_runtime_candidate"] = False
                    analysis["decision"] = "no decision: run integrity or execution failed"
                    analysis["errors"].append("run wrapper recorded a failure")
                write_new(args.output_dir / "analysis.json", (json.dumps(analysis, indent=2, sort_keys=True) + "\n").encode())
                result["analysis"] = receipt(args.output_dir / "analysis.json")
                result["passed"] = analysis["valid_complete_experiment"]
                result["eligible_for_separate_runtime_candidate"] = analysis["eligible_for_separate_runtime_candidate"]
            if (args.output_dir / "stderr.log").is_file():
                result["stderr"] = receipt(args.output_dir / "stderr.log")
            result["runner"] = receipt(Path(__file__))
            result["analyzer"] = receipt(Path(__file__).with_name("summarize_hash_probe.py"))
        except BaseException as error:
            result["collection_error"] = {"type": type(error).__name__, "reason": str(error)}
            result["passed"] = False
            result["eligible_for_separate_runtime_candidate"] = False
        result["finished_unix"] = time.time()
        write_new(args.output_dir / "run.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"run": str(args.output_dir / "run.json"), "passed": result["passed"],
                      "eligible_for_separate_runtime_candidate": result.get("eligible_for_separate_runtime_candidate", False)}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
