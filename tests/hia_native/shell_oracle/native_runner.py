# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Capture actual native calls; fresh original Rust replay is a separate gate."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
from hia_native_loader import NativeModule
from hia_native_shell_reference import original_sources, pin_bytes, pin_file


def sibling(name):
    spec = importlib.util.spec_from_file_location("_hia_shell_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cases = sibling("cases")
CONFIG = {
    "terminal": {"manifest": "HIA_TERMINAL_MANIFEST", "corpus": "HIA_TERMINAL_CORPUS_DIR",
                 "source": "native/terminal_clean.hepta"},
    "gate": {"manifest": "HIA_SHELL_GATE_MANIFEST", "corpus": "HIA_SHELL_GATE_CORPUS_DIR",
             "source": "native/shell_gate.hepta"},
}


def capacities(mode, wire):
    if mode == "terminal":
        return max(1024, 9 * len(wire) + 128), max(128, 9 * len(wire) + 128)
    # At most one borrowed span per byte plus fixed headers; the original
    # diagnostic ops emit at most 16 bytes per span. No semantic quota is added.
    return max(2048, 16 * len(wire) + 128), max(256, 32 * len(wire) + 128)


def run_native(mode):
    config = CONFIG[mode]
    selected = os.environ.get(config["manifest"])
    if mode == "terminal" and not selected:
        selected = os.environ.get("HIA_TERMINAL_CLEAN_MANIFEST")
    corpus = os.environ.get(config["corpus"])
    if not selected or not corpus:
        raise RuntimeError(f"set {config['manifest']} and {config['corpus']}")
    folder = Path(corpus).absolute()
    folder.mkdir(parents=True, exist_ok=False)
    source_receipt, _ = original_sources(ROOT)
    manifest = Path(selected).resolve(strict=True)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    result = {"schema": "hepta.runtime.shell-native-corpus.v1", "mode": mode, "status": "FAIL",
              "semantic_case_count": 0, "transport_control_count": 0,
              "categories": {}, "rust_oracle_executed_by_this_suite": False,
              "production_shell_execution_qualified": False, "whole_runtime_replaced": False,
              "manifest_sha256": manifest_sha, "manifest_path": str(manifest),
              "source_path": config["source"], "source_provenance": source_receipt,
              "output_tail_unchanged": True, "borrowed_guards_checked": True,
              "files": {}}
    failure = None
    start = time.monotonic()
    try:
        with NativeModule(manifest, manifest_sha256=manifest_sha) as module:
            source_pin = pin_file(ROOT / config["source"])
            if module.metadata["source_sha256"] != source_pin["sha256"]:
                raise ValueError("selected image is not built from this exact HIA source")
            result["source_sha256"] = source_pin["sha256"]
            result["module"] = module.metadata
            with ((folder / "input.bin").open("xb") as inputs,
                  (folder / "native-output.bin").open("xb") as outputs,
                  (folder / "cases.jsonl").open("x") as rows):
                for case in cases.iter_cases(mode, ROOT):
                    wire = case["input"]
                    out_cap, work_cap = capacities(mode, wire)
                    code, output, workspace = module.invoke_raw(wire, output_capacity=out_cap,
                        workspace_capacity=work_cap, output_fill=0xA7, workspace_fill=0x5C)
                    if code >= 0xFFFF0000 or code > out_cap:
                        raise AssertionError({"id": case["id"], "category": case["category"],
                                              "native_return": code, "wire": wire.hex()})
                    body = output[:code]
                    if output[code:] != b"\xa7" * (out_cap - code):
                        raise AssertionError(f"native successful output tail changed: {case['id']}")
                    if case["known_expected"] is not None and body != case["known_expected"]:
                        raise AssertionError({"id": case["id"], "literal_expected": case["known_expected"].hex(),
                                              "actual": body.hex()})
                    inputs.write(struct.pack("<Q", len(wire)) + wire)
                    outputs.write(struct.pack("<Q", code) + body)
                    row = {"id": case["id"], "category": case["category"],
                           "input_bytes": len(wire), "input_sha256": hashlib.sha256(wire).hexdigest(),
                           "native_return": code, "output_bytes": len(body),
                           "output_sha256": hashlib.sha256(body).hexdigest(),
                           "output_capacity": out_cap, "workspace_capacity": work_cap,
                           "literal_expected_checked": case["known_expected"] is not None}
                    rows.write(json.dumps(row, sort_keys=True) + "\n")
                    result["semantic_case_count"] += 1
                    category = case["category"]
                    result["categories"][category] = result["categories"].get(category, 0) + 1
            with (folder / "transport-controls.jsonl").open("x") as controls:
                for spec in cases.control_specs(mode):
                    wire = spec["input"]
                    out_cap, work_cap = spec["output_capacity"], spec["workspace_capacity"]
                    code, output, workspace = module.invoke_raw(wire, output_capacity=out_cap,
                        workspace_capacity=work_cap, output_fill=0xA7, workspace_fill=0x5C)
                    row = {"id": spec["id"], "category": "transport_refusal", "input_hex": wire.hex(),
                           "output_capacity": out_cap, "workspace_capacity": work_cap,
                           "output_before_hex": (b"\xa7" * out_cap).hex(),
                           "output_after_hex": output.hex(),
                           "workspace_before_hex": (b"\x5c" * work_cap).hex(),
                           "workspace_after_hex": workspace.hex(),
                           "native_return": code, "expected_code": spec["expected_code"],
                           "borrowed_guards_checked": True}
                    controls.write(json.dumps(row, sort_keys=True) + "\n")
                    result["transport_control_count"] += 1
                    if code != spec["expected_code"] or output != b"\xa7" * out_cap:
                        raise AssertionError({"control": spec["id"], "expected": spec["expected_code"],
                                              "actual": code, "output_unchanged": output == b"\xa7" * out_cap})
        # Optional development-only true original comparison; no build or Rust
        # fallback occurs in a native shard. The aggregate always rebuilds fresh.
        oracle = os.environ.get("HIA_SHELL_ORACLE_BIN")
        if oracle:
            exe = Path(oracle).resolve(strict=True)
            with ((folder / "input.bin").open("rb") as source,
                  (folder / "development-original-output.bin").open("xb") as out,
                  (folder / "development-original.stderr").open("xb") as err):
                replay_start = time.monotonic()
                proc = subprocess.run([str(exe), mode], stdin=source, stdout=out, stderr=err,
                                      timeout=120, check=False)
            result["development_original_process"] = {
                "command": [str(exe), mode], "exit_code": proc.returncode,
                "timeout_seconds": 120, "duration_seconds": time.monotonic() - replay_start,
                "executable": pin_file(exe)}
            if proc.returncode:
                raise AssertionError("development original oracle failed")
            if (folder / "development-original-output.bin").read_bytes() != (folder / "native-output.bin").read_bytes():
                raise AssertionError("development original output differs from native")
            result["rust_oracle_executed_by_this_suite"] = True
        result["status"] = "PASS"
    except BaseException as exc:
        failure = exc
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["duration_seconds"] = time.monotonic() - start
        for name in ("input.bin", "native-output.bin", "cases.jsonl", "transport-controls.jsonl"):
            path = folder / name
            if path.is_file():
                result["files"][name] = pin_file(path)
        (folder / "native-corpus.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"mode": mode, "status": result["status"],
                          "semantic_cases": result["semantic_case_count"],
                          "transport_controls": result["transport_control_count"],
                          "report": str(folder / "native-corpus.json"),
                          "rust_oracle_executed_by_this_suite": result["rust_oracle_executed_by_this_suite"],
                          "error": result.get("error")}, sort_keys=True))
    if failure is not None:
        raise failure
    return result
