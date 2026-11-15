#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Run focused shell component qualification without claiming full runtime adoption.

This fast gate uses the same native suites, evidence reader and fresh original
recipes as the complete runtime aggregate. It does not substitute for the full
compiler cold gate or for any other required runtime component.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualify_hia_runtime_native as q
import hia_native_shell_qualification as shell
from hia_native_build import NativeBuild, HEPTA_COMMIT, HEPTA_TREE


def run(args):
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=False)
    hepta = args.hepta.resolve(strict=True)
    result = {"schema": "hepta.runtime.shell-focused-qualification.v1", "status": "RUNNING",
              "phase": "shell_native_build", "started_at": datetime.now(timezone.utc).isoformat(),
              "checks": [], "modules": {}, "original_rust_comparisons": {},
              "whole_runtime_replaced": False, "production_activated": False,
              "old_stack_removal_qualified": False, "production_shell_execution_qualified": False,
              "matching_source_full_cold_qualified": False, "compiler_commit": HEPTA_COMMIT,
              "compiler_tree": HEPTA_TREE, "source_sha256": q.sources()}
    started = time.monotonic()
    q.save_report(output / "result.json", result)
    try:
        result["inventory"] = q.inspect(q.ROOT)
        build = NativeBuild(hepta, output / "build")
        env = q.qualification_env()
        variables = {"terminal_clean": "HIA_TERMINAL_MANIFEST", "shell_gate": "HIA_SHELL_GATE_MANIFEST"}
        for key, profile in shell.COMPONENTS.items():
            manifest = build.compile(profile["folder"], q.ROOT / profile["source"], standalone="filter")
            result["modules"][key] = {"manifest": manifest.relative_to(output).as_posix(),
                                      "sha256": q.sha(manifest)}
            env[variables[key]] = str(manifest)
        result["compiler_image_sha256"] = build.compiler_sha256
        env.update({"HIA_TERMINAL_CORPUS_DIR": str(output / "terminal-clean"),
                    "HIA_SHELL_GATE_CORPUS_DIR": str(output / "shell-gate"),
                    "HIA_SHELL_QUALIFICATION_OUTPUT": str(output)})
        result["phase"] = "shell_native_suites"
        for name in ("test_shell_native.py", "test_shell_gate_native.py", "test_shell_evidence.py"):
            q.record_check(output, result, name=name,
                command=[sys.executable, "-I", "-B", str(q.ROOT / "tests/hia_native" / name)],
                timeout=180, env=env, report_path=output / "result.json")
        result["shell_evidence"] = shell.qualification_evidence(q.ROOT, output, result, q.completed_test_summary)
        if not args.native_only:
            rustc, cargo = args.rustc.absolute(), args.cargo.absolute()
            result["rust_compiler"] = {"invocation_path": str(rustc), "sha256": q.sha(rustc.resolve(strict=True))}
            result["phase"] = "shell_original_rust"
            for key in shell.COMPONENTS:
                result["original_rust_comparisons"][key] = shell.compare_original(q.ROOT, output, result, key,
                    rustc, cargo, q.completed_test_summary, q.record_check, q.qualification_env)
        shell.exact(result["shell_evidence"], shell.qualification_evidence(q.ROOT, output, result, q.completed_test_summary),
                    "focused shell evidence changed after execution")
        if q.sources() != result["source_sha256"]:
            raise ValueError("runtime source closure changed during focused shell qualification")
        result["status"] = "NATIVE_ONLY_PASS" if args.native_only else "PASS"
        result["phase"] = "complete"
    except BaseException as exc:
        result["status"] = "FAIL"
        result["error"] = f"{type(exc).__name__}: {exc}"
        (output / "failure.txt").write_text(traceback.format_exc())
    result["elapsed_seconds"] = time.monotonic() - started
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    q.save_report(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--native-only", action="store_true", help="development run; returns NATIVE_ONLY_PASS")
    args = parser.parse_args()
    if not args.native_only and (args.rustc is None or args.cargo is None):
        parser.error("fresh original comparison requires absolute --rustc and --cargo paths")
    if not args.native_only and (not args.rustc.is_absolute() or not args.cargo.is_absolute()):
        parser.error("reference tool paths must be absolute selected toolchain executables")
    result = run(args)
    actual_native = sum(row["name"] in ("test_shell_native.py", "test_shell_gate_native.py", "test_shell_evidence.py")
                        for row in result["checks"])
    print(json.dumps({"status": result["status"], "report": str(args.output.absolute() / "result.json"),
                      "native_suite_records": actual_native, "original_recipes": len(result["original_rust_comparisons"]),
                      "whole_runtime_replaced": False, "production_shell_execution_qualified": False,
                      "matching_source_full_cold_qualified": False, "error": result.get("error")}, sort_keys=True))
    return 0 if result["status"] in ("PASS", "NATIVE_ONLY_PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
