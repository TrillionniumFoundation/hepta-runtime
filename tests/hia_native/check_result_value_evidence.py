# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Mutate completed result evidence only after all original recipes have drained."""
from pathlib import Path
import argparse
import copy
import gzip
import json
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import hia_native_result_qualification as q
from qualify_hia_runtime_native import completed_test_summary
from result_value_registry import DOMAINS, REFERENCE, encoded, regular, require, sha, source_pins


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "output", "report", "result"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root, output = args.repo.resolve(strict=True), args.output.resolve(strict=True)
    report = q.object_at(args.report)
    full = lambda value=report: {domain: q.original_evidence(root, output, value, completed_test_summary, domain) for domain in DOMAINS}
    baseline, pins = full(), source_pins(root)
    original, native = output / "result-values-original", output / "result-values-native"
    inspect = lambda: q.inspect_original_domain(root, original, native, "binary32")
    original_baseline = inspect()
    controls = []
    started = time.monotonic()

    def reject(label, check, updates=None):
        updates = updates or {}
        old = {path: (regular(path), path.stat().st_mode & 0o777) for path in updates}
        try:
            for path, raw in updates.items():
                path.chmod(old[path][1] | 0o200)
                path.write_bytes(raw)
                # Keep mode admission valid while testing changed bytes.
                path.chmod(old[path][1])
            try:
                check()
            except (ValueError, AssertionError, KeyError, TypeError, OSError, EOFError) as error:
                controls.append(dict(label=label, rejected=True, exception=type(error).__name__))
            else:
                raise AssertionError("damaged original result evidence accepted: " + label)
        finally:
            for path, (raw, mode) in old.items():
                path.chmod(mode | 0o200)
                path.write_bytes(raw)
                path.chmod(mode)
        require(all(regular(path) == raw and path.stat().st_mode & 0o777 == mode for path, (raw, mode) in old.items()),
            "original evidence restoration changed bytes or mode")

    def record(label, name, field, value):
        changed = copy.deepcopy(report)
        next(row for row in changed["checks"] if row["name"] == name)[field] = value
        reject(label, lambda: q.original_evidence(root, output, changed, completed_test_summary, "binary32"))

    def changed(path, edit):
        value = q.object_at(path)
        edit(value)
        return encoded(value)

    record("actual-original-nonzero", "result-binary32-rust-compare", "exit_code", 1)
    record("actual-original-timeout", "result-binary32-rust-compare", "timed_out", True)
    record("actual-original-limit", "result-binary32-rust-compare", "timeout_seconds", 181)
    command = next(row["command"] for row in report["checks"] if row["name"] == "result-binary32-rust-compare")
    record("actual-original-command", "result-binary32-rust-compare", "command", [*command, "--unexecuted"])
    path = original / "build/result.json"
    reject("original-environment", inspect, {path: changed(path, lambda value: value.update(environment_removed=[]))})
    path = original / "build/compile.receipt.json"
    reject("missing-actual-compile", inspect, {path: b"{}\n"})
    path = original / "build/bin/hia-binary32-reference"
    raw = regular(path)
    reject("compiled-original-image", inspect, {path: raw[:100] + bytes([raw[100] ^ 1]) + raw[101:]})
    path = root / REFERENCE / "request_result.rs"
    reject("original-function-custody", inspect, {path: regular(path) + b"\n// damaged control\n"})
    path = original / "binary32/result.json"
    reject("incomplete-original-domain", inspect, {path: changed(path, lambda value: value.update(cases=541692))})
    path = original / "binary32/main.receipt.json"
    reject("fresh-replay-timeout", inspect, {path: changed(path, lambda value: value.update(timed_out=True))})
    path = original / "binary32/main.stdout.gz"
    raw = gzip.decompress(regular(path)); damaged = b"1" + raw[1:]
    reject("complete-original-output", inspect, {path: gzip.compress(damaged, mtime=0)})
    path = original / "request/cases.stdout.gz"
    raw = regular(path)
    reject("large-original-output-truncated", lambda: q.inspect_original_domain(root, original, native, "request"),
        {path: raw[:-8]})
    path = original / "build/registry-archives/rmcp-3.4.1.crate"
    raw = regular(path)
    reject("locked-registry-archive", inspect, {path: raw[:100] + bytes([raw[100] ^ 1]) + raw[101:]})
    require(len(controls) == 13 and inspect() == original_baseline and full() == baseline and source_pins(root) == pins,
        "complete original/native evidence did not restore")
    result = dict(schema="hepta.result-values.original-controls.v1", status="PASS", rejections=13,
        restorations=14, complete_original_admissions=6, controls=controls,
        report_sha256=sha(regular(args.report)), baseline_evidence_sha256=sha(encoded(baseline)),
        final_evidence_sha256=sha(encoded(baseline)), restored_file_bytes_and_modes=True,
        actual_native_calls_added=0, actual_rust_calls_added=0, elapsed_seconds=time.monotonic() - started)
    args.result.write_bytes(encoded(result))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
