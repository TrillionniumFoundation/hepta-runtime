# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual static, empty-PATH stdio processes for all observed SDK sessions."""
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
from connection_test_context import Suite, sha


def main():
    with Suite("elf") as suite:
        context = suite.context
        binary, metadata = context.fixture()
        counts = {"actual_processes": 0, "input_events": 0, "response_lines": 0, "empty_path_launches": 0}
        exports = {}
        for domain in ["lifecycle-core", "lifecycle-matrix"]:
            cases = context.rows(domain, "requests.jsonl")
            originals = context.rows(domain, "lifecycle.stdout")
            rows = []
            for case, reference in zip(cases, originals, strict=True):
                assert case["label"] == reference["label"]
                frames = [bytes.fromhex(event["wire_hex"]) if "wire_hex" in event else event["wire"].encode()
                          for event in case["events"]]
                request = b"\n".join(frames) + b"\n"
                expected = b"".join(event["response_raw"].encode() for event in reference["events"] if "response_raw" in event)
                begin = time.monotonic()
                try:
                    process = subprocess.run([str(binary)], input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             env={"PATH": "", "LC_ALL": "C"}, timeout=10)
                    out, err, code, timeout = process.stdout, process.stderr, process.returncode, False
                except subprocess.TimeoutExpired as error:
                    out, err, code, timeout = error.stdout or b"", error.stderr or b"", None, True
                row = {"label": case["label"], "command": [str(binary)], "input_sha256": sha(request),
                       "input_bytes": len(request), "stdout_hex": out.hex(), "stderr_hex": err.hex(),
                       "stdout_sha256": sha(out), "stderr_sha256": sha(err), "exit_code": code,
                       "timed_out": timeout, "timeout_seconds": 10, "elapsed_seconds": time.monotonic() - begin}
                rows.append(row)
                if timeout or code != 0 or err or out != expected:
                    suite.rows(domain + ".partial.jsonl", rows)
                    raise AssertionError((case["label"], "actual ELF result differs", code, timeout, err, out, expected))
                counts["actual_processes"] += 1
                counts["empty_path_launches"] += 1
                counts["input_events"] += len(frames)
                counts["response_lines"] += out.count(b"\n")
            exports[domain] = suite.rows(domain + ".jsonl", rows)
        context.fixture()
        assert counts == {"actual_processes": 2203, "empty_path_launches": 2203, "input_events": 6414, "response_lines": 6126}
        suite.summary.update(counts=counts, exports=exports, elf_sha256=metadata["elf_sha256"], runtime_python_or_rust=False,
                             fixture_handler_is_test_only=True)


if __name__ == "__main__":
    main()
