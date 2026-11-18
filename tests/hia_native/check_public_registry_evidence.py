#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Damage retained evidence in a quiescent directory; reject and fully restore."""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import os
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_public_registry_qualification import original_evidence, read, object_at
from public_registry_registry import TESTS

sha = lambda raw: hashlib.sha256(raw).hexdigest()
encoded = lambda value: (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def completed(folder, report, name):
    matches = [row for row in report["checks"] if row["name"] == name]
    if len(matches) != 1:
        raise ValueError("actual process record missing or duplicated")
    return matches[0], json.loads(read(Path(folder) / (name + ".stdout")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    root, output = args.repo.resolve(strict=True), args.output.resolve(strict=True)
    if root != ROOT:
        raise ValueError("selected source root does not own this checker")
    raw_report = args.report.read_bytes()
    report = json.loads(raw_report)
    before = original_evidence(root, output, report, completed)
    begun = time.monotonic()
    controls = []

    def reject(label, *, updates=None, changed_report=None):
        saved = {}
        try:
            for path, value in (updates or {}).items():
                path = Path(path)
                saved[path] = (read(path), stat.S_IMODE(path.stat().st_mode))
                path.chmod(0o600)
                path.write_bytes(value)
            try:
                original_evidence(root, output, changed_report if changed_report is not None else report, completed)
            except Exception as error:
                controls.append({"label": label, "rejected": True, "exception": type(error).__name__})
            else:
                raise AssertionError("damaged retained evidence was admitted: " + label)
        finally:
            for path, (raw, mode) in saved.items():
                path.write_bytes(raw)
                path.chmod(mode)
        if original_evidence(root, output, report, completed) != before:
            raise AssertionError("complete evidence did not restore: " + label)

    def mutate_record(label, name, key, value):
        changed = copy.deepcopy(report)
        selected = next(row for row in changed["checks"] if row["name"] == name)
        selected[key] = value
        reject(label, changed_report=changed)

    def alter_json(path, edit):
        value = object_at(path)
        edit(value)
        return encoded(value)

    changed = copy.deepcopy(report)
    changed["checks"] = [row for row in changed["checks"] if row["name"] != TESTS[0]]
    reject("missing-actual-native-completion", changed_report=changed)
    mutate_record("nonzero-native-exit", TESTS[0], "exit_code", 1)
    mutate_record("native-timeout", TESTS[1], "timed_out", True)
    command = next(row["command"] for row in report["checks"] if row["name"] == TESTS[2])
    mutate_record("changed-actual-native-command", TESTS[2], "command", [*command, "--not-executed"])
    mutate_record("nonzero-original-exit", "public-registry-rust-compare", "exit_code", 1)
    mutate_record("changed-original-deadline", "public-registry-rust-compare", "timeout_seconds", 181)
    folder = output / "public-registry-native"
    path = folder / "cases/result.json"
    reject("incomplete-native-session-report", updates={path: alter_json(path, lambda value: value.update(completed_sessions=151))})
    path = folder / "cases/output.jsonl"
    reject("omitted-native-response-session", updates={path: b"\n".join(read(path).splitlines()[:-1]) + b"\n"})
    path = folder / "cases/processes.jsonl"
    rows = read(path).splitlines()
    first = json.loads(rows[0])
    first["input_sha256"] = "0" * 64
    reject("changed-actual-native-request-custody", updates={path: encoded(first).replace(b"\n", b"") + b"\n" + b"\n".join(rows[1:]) + b"\n"})
    bundle = object_at(output / "build/public-registry-build.json")
    manifest = Path(bundle["executable"]["path"])
    meta = object_at(manifest)
    path = manifest.parent / meta["executable"]
    raw = bytearray(read(path))
    raw[meta["members"][5]["offset"] + 16] ^= 1
    reject("changed-actual-embedded-router-image", updates={path: bytes(raw)})
    module = Path(bundle["modules"]["mcp"]["path"])
    module_meta = object_at(module)
    path = module.parent / module_meta["image"]
    raw = bytearray(read(path));raw[-1] ^= 1
    reject("changed-compiled-router-image", updates={path: bytes(raw)})
    build_record = object_at(module.parent / "build.json")
    build_record["compile_receipt"] = {}
    reject("rehashed-empty-native-compiler-observer", updates={module.parent / "module.stdout.log": b"{}\n",
        module.parent / "module.receipt.json": b"{}\n", module.parent / "build.json": encoded(build_record)})
    path = manifest.parent / "pack.input.bin"
    raw = bytearray(read(path));raw[-1] ^= 1
    reject("changed-native-packer-input", updates={path: bytes(raw)})
    path = root / "native/public_tool_dispatch.hepta"
    reject("changed-executed-HIA-source", updates={path: read(path) + b"\n"})
    path = folder / "controls/result.json"
    reject("missing-private-receipt-control", updates={path: alter_json(path, lambda value: value.update(receipt_refusals=47))})
    original = output / "public-registry-original"
    path = original / "original/output.jsonl"
    reject("omitted-original-response-session", updates={path: b"\n".join(read(path).splitlines()[:-1]) + b"\n"})
    path = original / "result.json"
    reject("missing-actual-original-build", updates={path: alter_json(path, lambda value: value.update(fresh_actual_cargo_build=False))})
    path = original / "target/release/hia-runtime-config-mcp"
    raw = bytearray(read(path));raw[-1] ^= 1
    reject("changed-original-executable", updates={path: bytes(raw)})
    path = original / "project/mcp/oracle_mcp.rs"
    reject("changed-whole-original-wrapper", updates={path: read(path) + b"\n"})
    sdk = object_at(original / "result.json")["sdk_files"]
    path = original / "sdk" / sorted(sdk)[0]
    reject("changed-locked-SDK-source", updates={path: read(path) + b"\n"})
    assert len(controls) == 20 and args.report.read_bytes() == raw_report
    final = original_evidence(root, output, report, completed)
    assert final == before
    result = {"schema": "hepta.public-registry.evidence-controls.v1", "status": "PASS",
        "controls": controls, "rejections": 20, "full_baseline_admissions": 22,
        "elapsed_seconds": time.monotonic() - begun, "report_sha256": sha(raw_report),
        "baseline_evidence_sha256": sha(encoded(before)), "final_evidence_sha256": sha(encoded(final)),
        "restored_file_bytes_and_modes": True, "actual_native_calls_added": 0, "actual_rust_calls_added": 0}
    with args.result.open("xb") as stream:
        stream.write(encoded(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
