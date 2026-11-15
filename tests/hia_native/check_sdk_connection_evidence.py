#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Reject damaged completion, source, image, corpus and original SDK evidence.

Run only after every process using this qualification workspace has finished.
Each physical change is restored in finally, followed by full baseline admission.
No native image or Rust program is executed by these controls.
"""
from pathlib import Path
import argparse
import copy
import json
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_connection_qualification import (encoded, native_evidence, original_evidence,
    object_at, read, require, sha)


def completed(output, report, name):
    rows = [r for r in report["checks"] if r["name"] == name]
    require(len(rows) == 1, "expected one actual completed process")
    check = rows[0]
    out, err = read(output / (name + ".stdout")), read(output / (name + ".stderr"))
    require(sha(out) == check["stdout_sha256"] and sha(err) == check["stderr_sha256"], "actual process streams changed")
    summary = json.loads(out)
    require(summary == check.get("summary"), "actual stdout summary changed")
    return check, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--inactive-workspace", action="store_true", required=True)
    args = parser.parse_args()
    root, output = args.repo.resolve(strict=True), args.output.resolve(strict=True)
    require(root == ROOT, "control source does not own selected root")
    report = object_at(args.report)
    started = time.monotonic()
    initial = original_evidence(root, output, report, completed)
    baseline = sha(encoded(initial))
    records = []
    bundle_path = output / "build/connection-build.json"
    bundle = object_at(bundle_path)

    def reject(label, change, admission=original_evidence):
        candidate = copy.deepcopy(report)
        saved = {}

        def write(path, value):
            path = Path(path)
            if path not in saved:
                saved[path] = read(path)
            path.write_bytes(value)

        try:
            change(candidate, write)
            try:
                admission(root, output, candidate, completed)
            except (AssertionError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError) as error:
                records.append({"label": label, "refused": True, "reason": type(error).__name__ + ": " + str(error)})
            else:
                raise AssertionError("damaged evidence was admitted: " + label)
        finally:
            for path, raw in saved.items():
                path.write_bytes(raw)
        require(sha(encoded(original_evidence(root, output, report, completed))) == baseline,
                "baseline did not recover after control: " + label)

    reject("source-byte", lambda r, w: w(root / "native/sdk_connection.hepta", read(root / "native/sdk_connection.hepta") + b"\n"))
    reject("missing-completed-test", lambda r, w: r["checks"].__setitem__(slice(None), [c for c in r["checks"] if c["name"] != "test_sdk_message.py"]))
    reject("incomplete-test-exit", lambda r, w: next(c for c in r["checks"] if c["name"] == "test_sdk_connection.py").update(timed_out=True, exit_code=-9))
    reject("actual-stdout", lambda r, w: w(output / "test_sdk_connection_elf.py.stdout", b"{}\n"))
    module = Path(bundle["modules"]["message"]["path"]).parent
    reject("compiler-empty-stdout", lambda r, w: w(module / "module.stdout.log", b"{}\n"))
    reject("compiler-output-buffer", lambda r, w: w(module / "module.output.bin", read(module / "module.output.bin")[:-1]))
    fixture = Path(bundle["fixture"]["path"])

    def rehash_elf(report, write):
        meta = object_at(fixture)
        binary = fixture.parent / meta["executable"]
        body = bytearray(read(binary))
        body[meta["members"][0]["offset"]] ^= 1
        write(binary, bytes(body))
        meta["elf_sha256"] = sha(body)
        write(fixture, encoded(meta))
        changed = copy.deepcopy(bundle)
        changed["fixture"]["sha256"] = sha(read(fixture))
        write(bundle_path, encoded(changed))
        report["modules"]["sdk_connection"]["sha256"] = sha(read(bundle_path))
    reject("rehashed-embedded-image", rehash_elf)
    reject("packer-call-result", lambda r, w: w(fixture.parent / "pack.result.json", encoded({**object_at(fixture.parent / "pack.result.json"), "result_u32": 1})))
    reject("native-corpus-truncated", lambda r, w: w(output / "connection-native/elf/lifecycle-matrix.jsonl.gz", read(output / "connection-native/elf/lifecycle-matrix.jsonl.gz")[:-1]))
    reject("retained-original-corpus", lambda r, w: w(Path(bundle["reference_data"]) / "lifecycle-matrix/lifecycle.stdout", b"{}\n"))
    reject("native-derived-result", lambda r, w: w(output / "connection-native/result.json", encoded({**object_at(output / "connection-native/result.json"), "actual_native_elf_processes": 1})))
    reject("missing-original-wrapper", lambda r, w: r["checks"].__setitem__(slice(None), [c for c in r["checks"] if c["name"] != "connection-rust-compare"]))
    reject("original-partial-output", lambda r, w: w(output / "connection-original/lifecycle-matrix.stdout", read(output / "connection-original/lifecycle-matrix.stdout")[:-1]))
    original = object_at(output / "connection-original/result.json")
    binary = Path(next(iter(original["binaries"].values()))["path"])
    reject("original-binary-byte", lambda r, w: w(binary, read(binary) + b"\0"))
    require(len(records) == 14, "evidence control inventory incomplete")
    require(sha(encoded(original_evidence(root, output, report, completed))) == baseline, "final full original/native admission changed")
    result = {"schema": "hepta.sdk-connection.evidence-controls.v1", "status": "PASS", "controls": records,
              "refusals": 14, "restored_full_baselines": 15, "baseline_sha256": baseline,
              "native_calls_added": 0, "rust_calls_added": 0, "elapsed_seconds": time.monotonic() - started}
    (output / "connection-evidence-controls.json").write_bytes(encoded(result))
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
