#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Fresh qualification of prepared HIA shell process, output and text owners.

This component gate builds native images, executes real processes, preserves the
unchanged original Rust tests, compares actual outputs, and rechecks retained
evidence.  It does not activate a production dispatcher or replace the complete
compiler cold/runtime gate.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import qualify_hia_runtime_native as q
import hia_native_shell_capture_gate as capture_gate
import hia_native_shell_process_build as process_build
import hia_native_shell_process_evidence as process_evidence
import hia_native_shell_process_reference as original
import hia_native_shell_outcome_build as outcome_build
import hia_native_shell_outcome_qualification as outcome_original
import hia_native_shell_output_build as output_build
import hia_native_shell_output_qualification as output_original
import hia_native_shell_foreground_build as foreground_build
import hia_native_shell_foreground_qualification as foreground_original
from hia_native_build import HEPTA_COMMIT, HEPTA_TREE


def load_test(name: str):
    path = ROOT / "tests/hia_native" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the registered component suite")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def source_closure() -> dict[str, str]:
    result = q.sources()
    for name in (
        "scripts/qualify_hia_shell_process.py",
        "scripts/hia_native_shell_process_build.py",
        "scripts/hia_native_shell_process_reference.py",
        "scripts/hia_native_shell_process_qualification.py",
        "scripts/hia_native_shell_process_evidence.py",
        "scripts/shell_process_adapter.S",
        ".github/workflows/hia-runtime-shell-process.yml",
        "src/mcp/mod.rs",
        "src/mcp/request_ctx.rs",
        "src/mcp/fs/shell.rs",
        "src/mcp/fs/shell_tests.rs",
        "src/mcp/fs/background.rs",
        "src/mcp/fs/background_tests.rs",
        "src/mcp/fs/remote.rs",
        "Cargo.toml",
        "Cargo.lock",
    ):
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("missing regular qualification source: " + name)
        result[name] = q.sha(path)
    return dict(sorted(result.items()))


def json_path(value):
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"unexpected non-JSON evidence value: {type(value).__name__}")


def json_data(value):
    return json.loads(json.dumps(value, default=json_path))


def read_foreground_build(manifest: Path, process: Path, output_io: Path, outcome: Path) -> dict:
    result = foreground_build.read_evidence(manifest, source_root=ROOT)
    metadata = json.loads(manifest.read_bytes())
    for field, path in (("process_manifest", process), ("output_manifest", output_io),
                        ("outcome_manifest", outcome)):
        if metadata.get(field) != str(path) or metadata.get(field + "_sha256") != q.sha(path):
            raise ValueError("foreground component differs from this same qualification: " + field)
    return result


def run(args) -> dict:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    began = time.monotonic_ns()
    report = {
        "schema": "hepta.runtime.shell-process-focused-qualification.v1",
        "status": "RUNNING",
        "phase": "source_admission",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "checkout_head": None,
        "source_identity_authority": "source_sha256",
        "source_sha256": {},
        "compiler_commit": HEPTA_COMMIT,
        "compiler_tree": HEPTA_TREE,
        "checks": [],
        "modules": {},
        "readers": {},
        "retired_fixtures": {},
        "whole_runtime_replaced": False,
        "production_activated": False,
        "old_stack_removal_qualified": False,
        "production_shell_execution_qualified": False,
        "matching_source_full_cold_qualified": False,
        "fresh_original_rust_build_qualified": False,
    }
    q.save_report(output / "result.json", report)
    env = None

    def check(name: str, argv: list[str], timeout: float = 180):
        return q.record_check(output, report, name=name, command=argv,
                              timeout=timeout, env=env,
                              report_path=output / "result.json")

    def python_script(relative: str) -> list[str]:
        return [sys.executable, "-I", "-B", str(ROOT / relative)]

    try:
        hepta = args.hepta.resolve(strict=True)
        state_suite = load_test("shell_process_state")
        transport_suite = load_test("shell_process_transport")
        background_suite = load_test("shell_background_text")
        outcome_suite = load_test("shell_outcome_state")
        output_suite = load_test("shell_output_io")
        foreground_state_suite = load_test("shell_foreground_controller")
        foreground_io_suite = load_test("shell_foreground_io")
        controls_suite = load_test("shell_process_evidence_controls")
        report["checkout_head"] = q.git_head()
        env = q.qualification_env()
        report["source_sha256"] = source_closure()
        report["inventory"] = q.inspect(ROOT)
        report["phase"] = "native_build"
        build_root = output / "build"
        check("shell-process-build", python_script("scripts/hia_native_shell_process_build.py") + [
            "--hepta", str(hepta), "--build", str(build_root), "--source-root", str(ROOT)])
        process_manifest = build_root / "shell-process/manifest.json"
        native = json.loads(process_manifest.read_text())
        executable = process_manifest.parent / native["elf"]
        if native["compiler_commit"] != HEPTA_COMMIT:
            raise ValueError("native process compiler pin differs")
        report["compiler_image_sha256"] = native["compiler_sha256"]
        report["modules"]["shell_process"] = {"manifest": str(process_manifest), "sha256": q.sha(process_manifest)}
        report["readers"]["process_build"] = process_build.read_evidence(process_manifest)
        check("shell-background-build", python_script("scripts/hia_native_build.py") + [
            "--hepta", str(hepta), "--build-root", str(build_root),
            "--source", str(ROOT / "native/shell_background_text.hepta"),
            "--name", "shell-background-text", "--transport", "image"])
        background_manifest = build_root / "modules/shell-background-text/manifest.json"
        report["modules"]["shell_background_text"] = {"manifest": str(background_manifest), "sha256": q.sha(background_manifest)}
        check("shell-outcome-build", python_script("scripts/hia_native_shell_outcome_build.py") + [
            "--hepta", str(hepta), "--build", str(build_root), "--source-root", str(ROOT)])
        outcome_manifest = build_root / "shell-outcome/manifest.json"
        report["modules"]["shell_outcome"] = {"manifest": str(outcome_manifest), "sha256": q.sha(outcome_manifest)}
        report["readers"]["outcome_build"] = outcome_build.read_evidence(outcome_manifest, source_root=ROOT)
        check("shell-output-build", python_script("scripts/hia_native_shell_output_build.py") + [
            "--hepta", str(hepta), "--build", str(build_root), "--source-root", str(ROOT)])
        output_manifest = build_root / "shell-output/manifest.json"
        report["modules"]["shell_output_io"] = {"manifest": str(output_manifest), "sha256": q.sha(output_manifest)}
        report["readers"]["output_build"] = output_build.read_evidence(output_manifest, source_root=ROOT)
        check("shell-foreground-build", python_script("scripts/hia_native_shell_foreground_build.py") + [
            "--hepta", str(hepta), "--build", str(build_root), "--source-root", str(ROOT),
            "--process-manifest", str(process_manifest), "--output-manifest", str(output_manifest),
            "--outcome-manifest", str(outcome_manifest)])
        foreground_manifest = build_root / "shell-foreground/manifest.json"
        report["modules"]["shell_foreground"] = {"manifest": str(foreground_manifest), "sha256": q.sha(foreground_manifest)}
        report["readers"]["foreground_build"] = read_foreground_build(
            foreground_manifest, process_manifest, output_manifest, outcome_manifest)
        for manifest in (outcome_manifest, output_manifest, foreground_manifest):
            metadata = json.loads(manifest.read_text())
            if (metadata["compiler_commit"] != HEPTA_COMMIT
                    or metadata["compiler_sha256"] != report["compiler_image_sha256"]):
                raise ValueError("native output/outcome uses a different compiler artifact")

        report["phase"] = "native_suites"
        for item in capture_gate.MODULES:
            key, name = item["key"], item["name"]
            report["phase"] = "native_build"
            check(name + "-build", python_script("scripts/hia_native_" + key + "_build.py") + [
                "--hepta", str(hepta), "--build", str(build_root), "--source-root", str(ROOT)]
                + capture_gate.build_child_arguments(key, build_root))
            capture_manifest = build_root / name / "manifest.json"
            report["modules"][key] = {"manifest": str(capture_manifest), "sha256": q.sha(capture_manifest)}
            metadata = capture_gate.compiler_identity(output, report, key)
            if (metadata["compiler_commit"] != HEPTA_COMMIT
                    or metadata["compiler_sha256"] != report["compiler_image_sha256"]):
                raise ValueError("capture owner uses a different compiler artifact")
        report["phase"] = "native_components"
        for name, command in capture_gate.test_commands(output, report).items():
            check(name, command)
        for key in capture_gate.KEYS:
            report[key + "_evidence"] = capture_gate.native_evidence(output, report, key)
        report["phase"] = "native_suites"
        state_output = output / "shell-process/state"
        transport_output = output / "shell-process/transport"
        native_os_output = output / "shell-process/native-os"
        background_output = output / "shell-background-text/native"
        outcome_output = output / "shell-outcome/native"
        output_io_output = output / "shell-output/native"
        check("shell-process-state", python_script("tests/hia_native/shell_process_state.py") + [
            "--native-manifest", str(process_manifest), "--output", str(state_output)])
        check("shell-process-transport", python_script("tests/hia_native/shell_process_transport.py") + [
            "--native-manifest", str(process_manifest), "--output", str(transport_output)])
        native_os_argv = python_script("scripts/hia_native_shell_process_qualification.py") + [
            "--native-executable", str(executable), "--native-manifest", str(process_manifest),
            "--output", str(native_os_output), "--jobs", str(args.jobs)]
        check("shell-process-native-os", native_os_argv)
        check("shell-background-native", python_script("tests/hia_native/shell_background_text.py") + [
            "--native-manifest", str(background_manifest), "--output", str(background_output)])
        check("shell-outcome-native", python_script("tests/hia_native/shell_outcome_state.py") + [
            "--native-manifest", str(outcome_manifest), "--output", str(outcome_output)])
        check("shell-output-native", python_script("tests/hia_native/shell_output_io.py") + [
            "--native-manifest", str(output_manifest), "--outcome-manifest", str(outcome_manifest),
            "--output", str(output_io_output)])
        foreground_state = output / "shell-foreground/state"
        foreground_io = output / "shell-foreground/native"
        check("shell-foreground-state", python_script("tests/hia_native/shell_foreground_controller.py") + [
            "--native-manifest", str(foreground_manifest), "--output", str(foreground_state)])
        check("shell-foreground-native", python_script("tests/hia_native/shell_foreground_io.py") + [
            "--native-manifest", str(foreground_manifest), "--output", str(foreground_io)])
        report["readers"]["state"] = state_suite.read_evidence(state_output, process_manifest)
        report["readers"]["transport"] = transport_suite.read_evidence(transport_output, process_manifest)
        report["readers"]["native_os"] = process_evidence.read_native_evidence(native_os_output, process_manifest)
        report["readers"]["background_native"] = background_suite.read_evidence(background_output, background_manifest)
        report["readers"]["outcome_native"] = outcome_suite.read_evidence(outcome_output, native_manifest=outcome_manifest)
        report["readers"]["output_native"] = output_suite.read_evidence(
            output_io_output, native_manifest=output_manifest, outcome_manifest=outcome_manifest, require_full=True)
        report["readers"]["foreground_state"] = foreground_state_suite.read_evidence(
            foreground_state, native_manifest=foreground_manifest)
        report["readers"]["foreground_native"] = foreground_io_suite.read_evidence(
            foreground_io, native_manifest=foreground_manifest, require_full=True)
        report["retired_fixtures"]["native_os"] = json_data(process_evidence.retire_fixtures(native_os_output, process_manifest))
        report["readers"]["native_os"] = process_evidence.read_native_evidence(native_os_output, process_manifest)
        check("shell-process-native-evidence-controls", python_script("tests/hia_native/shell_process_evidence_controls.py") + [
            "--evidence", str(native_os_output), "--native-manifest", str(process_manifest),
            "--output", str(output / "shell-process/native-evidence-controls"), "--native-only"])

        original_result = None
        compared_output = None
        if not args.native_only:
            rustc, cargo = args.rustc.resolve(strict=True), args.cargo.resolve(strict=True)
            report["reference_tools"] = {
                "rustc": {"path": str(rustc), "sha256": q.sha(rustc)},
                "cargo": {"path": str(cargo), "sha256": q.sha(cargo)},
            }
            report["phase"] = "unchanged_original_rust_build"
            original_output = output / "shell-process-original"
            reference_args = ["--runtime", str(ROOT), "--rustc", str(rustc), "--cargo", str(cargo)]
            check("shell-process-original-build", python_script("scripts/hia_native_shell_process_reference.py") + reference_args + [
                "--output", str(original_output)], timeout=900)
            original_result = original_output / "result.json"
            built_original = json.loads(original_result.read_text())
            original_executable = Path(built_original["executable"]["path"])
            report["readers"]["original_build"] = original.read_evidence(ROOT, original_output, rustc, cargo)
            if report["readers"]["original_build"].get("fresh_original_rust_build_qualified") is not True:
                raise ValueError("fresh original Rust build was not independently admitted")
            report["fresh_original_rust_build_qualified"] = True

            report["phase"] = "real_original_process_comparison"
            compared_output = output / "shell-process/original-os"
            check("shell-process-original-os", python_script("scripts/hia_native_shell_process_qualification.py") + [
                "--native-executable", str(executable), "--native-manifest", str(process_manifest),
                "--oracle-executable", str(original_executable), "--oracle-build-manifest", str(original_result),
                "--output", str(compared_output), "--jobs", str(args.jobs)])
            report["readers"]["original_os"] = process_evidence.read_evidence(compared_output, process_manifest, original_result)
            report["retired_fixtures"]["original_os"] = json_data(process_evidence.retire_fixtures(compared_output, process_manifest, original_result))
            report["readers"]["original_os"] = process_evidence.read_evidence(compared_output, process_manifest, original_result)

            report["phase"] = "original_background_text_comparison"
            background_original = output / "shell-background-text/original"
            check("shell-background-original", python_script("scripts/hia_native_shell_process_reference.py") + reference_args + [
                "--reference-build", str(original_output), "--background-corpus", str(background_output),
                "--output", str(background_original)], timeout=300)
            report["readers"]["background_original"] = original.read_background_evidence(
                ROOT, original_output, background_output, background_original, rustc, cargo)
            report["phase"] = "original_outcome_comparison"
            outcome_comparison = output / "shell-outcome/original"
            check("shell-outcome-original", python_script("scripts/hia_native_shell_outcome_qualification.py") + reference_args + [
                "--reference-build", str(original_output), "--native-corpus", str(outcome_output),
                "--native-manifest", str(outcome_manifest), "--output", str(outcome_comparison)], timeout=300)
            report["readers"]["outcome_original"] = outcome_original.read_evidence(
                ROOT, original_output, outcome_output, outcome_manifest, outcome_comparison, rustc, cargo)
            report["phase"] = "original_output_io_comparison"
            output_comparison = output / "shell-output/original"
            check("shell-output-original", python_script("scripts/hia_native_shell_output_qualification.py") + reference_args + [
                "--reference-build", str(original_output), "--native-corpus", str(output_io_output),
                "--native-manifest", str(output_manifest), "--outcome-manifest", str(outcome_manifest),
                "--output", str(output_comparison)], timeout=300)
            report["readers"]["output_original"] = output_original.read_evidence(
                ROOT, original_output, output_io_output, output_manifest, outcome_manifest,
                output_comparison, rustc, cargo)
            report["phase"] = "original_foreground_composition_comparison"
            foreground_comparison = output / "shell-foreground/original"
            check("shell-foreground-original", python_script("scripts/hia_native_shell_foreground_qualification.py") + reference_args + [
                "--reference-build", str(original_output),
                "--original-io-corpus", str(output_comparison / "original-io"),
                "--native-corpus", str(foreground_io), "--native-manifest", str(foreground_manifest),
                "--output", str(foreground_comparison)], timeout=300)
            report["readers"]["foreground_original"] = foreground_original.read_evidence(
                ROOT, original_output, output_comparison / "original-io", foreground_io,
                foreground_manifest, foreground_comparison, rustc, cargo)
            check("shell-process-original-evidence-controls", python_script("tests/hia_native/shell_process_evidence_controls.py") + [
                "--evidence", str(compared_output), "--native-manifest", str(process_manifest),
                "--original-manifest", str(original_result),
                "--output", str(output / "shell-process/original-evidence-controls")])

            report["phase"] = "original_rust_comparison"
            for key in capture_gate.KEYS:
                report["readers"][key + "_original"] = capture_gate.compare(output, report, key, rustc)

        report["phase"] = "fixture_retirement_and_final_readback"
        for key in capture_gate.KEYS:
            capture_gate.exact(report[key + "_evidence"], capture_gate.native_evidence(output, report, key),
                               "capture native evidence changed during focused gate")
            if not args.native_only:
                capture_gate.exact(report["readers"][key + "_original"],
                    capture_gate.original_evidence(output, report, key, rustc),
                    "capture original evidence changed during focused gate")
        report["retired_fixtures"]["native_os"] = json_data(process_evidence.retire_fixtures(native_os_output, process_manifest))
        report["readers"]["native_os"] = process_evidence.read_native_evidence(native_os_output, process_manifest)
        if compared_output is not None:
            report["retired_fixtures"]["original_os"] = json_data(process_evidence.retire_fixtures(compared_output, process_manifest, original_result))
            report["readers"]["original_os"] = process_evidence.read_evidence(compared_output, process_manifest, original_result)
        report["readers"]["process_build"] = process_build.read_evidence(process_manifest)
        report["readers"]["state"] = state_suite.read_evidence(state_output, process_manifest)
        report["readers"]["transport"] = transport_suite.read_evidence(transport_output, process_manifest)
        report["readers"]["background_native"] = background_suite.read_evidence(background_output, background_manifest)
        report["readers"]["native_evidence_controls"] = controls_suite.read_evidence(
            output / "shell-process/native-evidence-controls", process_manifest)
        report["readers"]["foreground_build"] = read_foreground_build(
            foreground_manifest, process_manifest, output_manifest, outcome_manifest)
        report["readers"]["foreground_state"] = foreground_state_suite.read_evidence(
            foreground_state, native_manifest=foreground_manifest)
        report["readers"]["foreground_native"] = foreground_io_suite.read_evidence(
            foreground_io, native_manifest=foreground_manifest, require_full=True)
        report["readers"]["outcome_build"] = outcome_build.read_evidence(outcome_manifest, source_root=ROOT)
        report["readers"]["output_build"] = output_build.read_evidence(output_manifest, source_root=ROOT)
        report["readers"]["outcome_native"] = outcome_suite.read_evidence(outcome_output, native_manifest=outcome_manifest)
        report["readers"]["output_native"] = output_suite.read_evidence(
            output_io_output, native_manifest=output_manifest, outcome_manifest=outcome_manifest, require_full=True)
        if original_result is not None:
            report["readers"]["original_build"] = original.read_evidence(
                ROOT, original_output, rustc, cargo)
            report["readers"]["background_original"] = original.read_background_evidence(
                ROOT, original_output, background_output, background_original, rustc, cargo)
            report["readers"]["original_evidence_controls"] = controls_suite.read_evidence(
                output / "shell-process/original-evidence-controls", process_manifest, original_result)
            report["readers"]["outcome_original"] = outcome_original.read_evidence(
                ROOT, original_output, outcome_output, outcome_manifest, outcome_comparison, rustc, cargo)
            report["readers"]["output_original"] = output_original.read_evidence(
                ROOT, original_output, output_io_output, output_manifest, outcome_manifest,
                output_comparison, rustc, cargo)
            report["readers"]["foreground_original"] = foreground_original.read_evidence(
                ROOT, original_output, output_comparison / "original-io", foreground_io,
                foreground_manifest, foreground_comparison, rustc, cargo)
        if source_closure() != report["source_sha256"]:
            raise ValueError("qualification source closure changed during actual execution")
        report["status"] = "NATIVE_ONLY_PASS" if args.native_only else "PASS"
        report["phase"] = "complete"
    except BaseException as exc:
        report["status"] = "FAIL"
        report["error"] = f"{type(exc).__name__}: {exc}"
        (output / "failure.txt").write_text(traceback.format_exc())
    report["elapsed_ns"] = time.monotonic_ns() - began
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    # Readers return JSON data; path values are only artifact locations.
    report = json_data(report)
    q.save_report(output / "result.json", report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    if not args.native_only and (args.rustc is None or args.cargo is None or not args.rustc.is_absolute() or not args.cargo.is_absolute()):
        parser.error("fresh original comparison requires absolute selected --rustc and --cargo executables")
    report = run(args)
    print(json.dumps({
        "status": report["status"], "report": str(args.output.resolve() / "result.json"),
        "check_processes": len(report["checks"]),
        "fresh_original_rust_build_qualified": report["fresh_original_rust_build_qualified"],
        "whole_runtime_replaced": False, "production_shell_execution_qualified": False,
        "matching_source_full_cold_qualified": False, "error": report.get("error"),
    }, sort_keys=True))
    return 0 if report["status"] in ("PASS", "NATIVE_ONLY_PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
