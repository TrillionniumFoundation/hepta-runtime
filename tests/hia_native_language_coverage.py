#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Run the original language witnesses against admitted native-cold B3 and M3.

This external qualification observer preserves the selected Hepta fixture
generators, independent Core VM oracles and native result assertions. It never
builds a Python seed or replaces the selected native source contract. Reference
observations precede this language run; the separate native cold report owns
the original before-B0 reference requirement.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
import unittest


SPEC = importlib.util.spec_from_file_location(
    "hia_native_helper_mcp_integration", Path(__file__).with_name("hia_native_helper_mcp_integration.py"))
custody = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(custody)


def cold_successors(cold_path, binding):
    """Bind every retained cold generation and the actual independent observer."""
    cold_bytes = custody.ordinary_bytes(cold_path, 64 * 1024 * 1024)
    custody.require(sha256(cold_bytes).hexdigest() == binding["cold_report_sha256"],
                    "native cold report changed after post-cold admission")
    cold = custody.native_json(cold_bytes)
    original, modified = cold.get("generation_sha256"), cold.get("modified_generation_sha256")
    custody.require(type(original) is list and original == [binding["compiler_sha256"]] * 3
                    and type(modified) is list and len(modified) == 3
                    and all(type(pin) is str and re.fullmatch(r"[0-9a-f]{64}", pin)
                            and pin != "0" * 64 for pin in [cold.get("seed_sha256"), *modified])
                    and modified[0] != modified[1] == modified[2] != original[2],
                    "native language requires both exact original and modified cold fixed points")
    base = cold_path.parent / "qualification/base"
    captured = {}
    for name, pin in zip(("B0", "B1", "B2", "B3", "M1", "M2", "M3"),
                         [cold["seed_sha256"], *original, *modified]):
        path = base / (name + ".flat")
        raw = custody.ordinary_bytes(path, 1024 * 1024)
        custody.require(sha256(raw).hexdigest() == pin,
                        "native language generation differs from the original cold report: " + name)
        captured[name] = {"path": str(path), "sha256": pin, "bytes": len(raw)}
    raw_observer = custody.ordinary_bytes(base / "native-observer.elf", 1107)
    custody.require(len(raw_observer) == 1107 and raw_observer.hex() == cold.get("native_flat_observer_hex"),
                    "native language observer differs from the admitted independent cold observer")
    captured["observer"] = {"path": str(base / "native-observer.elf"),
                            "sha256": sha256(raw_observer).hexdigest(), "bytes": len(raw_observer)}
    return {name: Path(captured[name]["path"]) for name in ("B3", "M3")}, raw_observer, captured


def phase_evidence(cold_path):
    """Retain physical native journals and archives instead of inventing v1 logs."""
    cold = custody.native_json(custody.ordinary_bytes(cold_path, 64 * 1024 * 1024))
    rows = cold.get("phases")
    custody.require(type(rows) is list and len(rows) == 60,
                    "native language requires the complete sixty-phase original cold evidence")
    captured, names = [], set()
    for row in rows:
        name = row.get("id")
        custody.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,126}", name)
                        and name not in names, "native cold phase evidence has an invalid or duplicate identity")
        names.add(name)
        for kind, relative in (("archive", name + ".hiaqar"), ("journal", name + "/evidence.hiaqj")):
            path = cold_path.parent / "qualification" / relative
            before = path.stat(follow_symlinks=False)
            custody.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                            and not any(part.is_symlink() for part in (path, *path.parents)),
                            "native cold evidence must retain ordinary single-link files")
            value = sha256()
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                custody.require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                                "native cold evidence changed while opening")
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    value.update(block)
                after = os.fstat(stream.fileno())
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            custody.require(identity(before) == identity(after) == identity(path.stat(follow_symlinks=False))
                            and value.hexdigest() == row.get(kind + "_sha256"),
                            "native cold " + kind + " differs from the original phase report: " + name)
            captured.append({"phase": name, "kind": kind, "path": str(path),
                             "sha256": value.hexdigest(), "bytes": before.st_size})
    return captured


def run_fixtures(language, compiler_api, compilers, observer, directory, report):
    """Preserve the original complete positive, refusal and trap observations."""
    from tools.hia_evidence_archive import OWNER, archive_completed_stage

    positive = language.positive_fixtures()
    negative = language.rejected_fixtures()
    traps = (language.shift_trap_cases() + language.checked_arithmetic_trap_cases()
             + language.checked_cast_trap_cases() + language.word_trap_fixtures(language.Assembly, language.HEADER))
    for label, compiler in compilers.items():
        case_directory = directory / label
        case_directory.mkdir(mode=0o700)
        archive_token = secrets.token_hex(32)
        (case_directory / OWNER).write_text(archive_token)
        for fixture in positive:
            name = label + "-" + fixture["id"]
            image, build = compiler_api.compile_stage(case_directory, name + "-build", compiler,
                                                       fixture["source"], flat_observer=observer)
            result, observed = compiler_api.invoke(case_directory, name, image, fixture["input"],
                capacity=fixture["capacity"], workspace_size=fixture["workspace_size"], flat_observer=observer)
            good = (result.get("status") == "returned" and result.get("abi_status") == 0
                and result.get("core_u32") == fixture["expected_result"] and result.get("source_unchanged")
                and not result.get("forbidden_compiler_modules_loaded") and observed == fixture["expected_output"])
            report["checks"][name] = bool(good)
            report["positive"].append({"compiler": label, "id": fixture["id"], "case_ids": fixture["case_ids"],
                "build": build, "execution": result, "expected_result": fixture["expected_result"],
                "expected_output_sha256": sha256(fixture["expected_output"]).hexdigest(),
                "observed_output_sha256": sha256(observed).hexdigest()})
        for fixture in negative:
            name = label + "-reject-" + fixture["id"]
            result, observed = compiler_api.invoke(case_directory, name, compiler, fixture["source"],
                                                   capacity=512, flat_observer=observer)
            good = (result.get("status") == "returned" and result.get("abi_status") == 0
                and result.get("core_u32") == compiler_api.INVALID and result.get("source_unchanged")
                and result.get("output_unchanged") and observed == bytes([165]) * 512
                and not result.get("forbidden_compiler_modules_loaded"))
            report["checks"][name] = bool(good)
            report["negative"].append({"compiler": label, "id": fixture["id"], "execution": result,
                                        "transactional_rejection": bool(good)})
        for fixture in traps:
            name = label + "-" + fixture["id"]
            image, build = compiler_api.compile_stage(case_directory, name + "-build", compiler,
                                                       fixture["source"], flat_observer=observer)
            result, observed = compiler_api.invoke(case_directory, name, image, fixture.get("input", b""),
                capacity=8, workspace_size=0, observe_trap_writes=True, flat_observer=observer)
            good = (result.get("status") == "child_failed" and result.get("returncode") == -4
                and result.get("shared_output_observation", {}).get("available")
                and observed == fixture["expected_output"])
            report["checks"][name] = bool(good)
            report["traps"].append({"compiler": label, "id": fixture["id"], "kind": fixture["kind"],
                "prior_store": fixture.get("prior_store", False), "operand_type": fixture["operand_type"],
                "result_type": fixture.get("result_type"), "runtime_input_hex": fixture.get("input", b"").hex(),
                "expected_output_hex": fixture["expected_output"].hex(), "observed_output_hex": observed.hex(),
                "build": build, "execution": result})
        report.setdefault("fixture_archives", []).append(archive_completed_stage(case_directory, archive_token))
    for kind, fixtures in (("positive", positive), ("negative", negative), ("traps", traps)):
        expected = {(compiler, row["id"]) for compiler in ("B3", "M3") for row in fixtures}
        actual = [(row["compiler"], row["id"]) for row in report[kind]]
        custody.require(len(expected) == len(actual) and set(actual) == expected,
                        "native language run omitted or duplicated an original " + kind + " witness")
    return {"positive_programs_per_compiler": len(positive), "rejections_per_compiler": len(negative),
            "traps_per_compiler": len(traps), "shift_traps_per_compiler": len(language.shift_trap_cases()),
            "checked_arithmetic_traps_per_compiler": len(language.checked_arithmetic_trap_cases()),
            "checked_cast_traps_per_compiler": len(language.checked_cast_trap_cases()),
            "word_memory_traps_per_compiler": len(language.word_trap_fixtures(language.Assembly, language.HEADER)),
            "compilers": 2}


def original_assertions(language, report, output, cold_path):
    class NativeColdInvocationAssertions(language.SelfhostLanguageNativeTests):
        @classmethod
        def setUpClass(cls):
            cls.temporary, cls.output, cls.report = None, output, report

        def test_all_generations_and_raw_evidence_are_retained(self):
            # Preserve this obligation using the actual native-cold wire domain.
            # Hosted B0 receipts and generation stdout filenames do not exist in
            # this execution and must not be synthesized from unrelated files.
            _, _, captured = cold_successors(cold_path, report["cold_source_binding"])
            self.assertEqual(captured, report["cold_generations"])
            self.assertEqual(phase_evidence(cold_path), report["cold_phase_evidence"])
            self.assertTrue((output.with_suffix(".evidence") / "independent-reference.json").is_file())

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(NativeColdInvocationAssertions)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = (result.testsRun == 11 and result.wasSuccessful() and not result.skipped
              and not result.expectedFailures and not result.unexpectedSuccesses)
    custody.write_json(output.with_suffix(".assertions.json"), {
        "schema": "hepta.runtime.native-cold-language-assertions.v1", "report_sha256": custody.digest(output),
        "tests_run": result.testsRun, "passed": passed,
        "failures": [{"test": test.id(), "detail": detail} for test, detail in result.failures],
        "errors": [{"test": test.id(), "detail": detail} for test, detail in result.errors],
        "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
        "generation_retention_domain": "actual_native_cold_flat_images_and_lossless_phase_journals",
        "additional_native_execution": False})
    return passed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hepta", type=Path, required=True)
    parser.add_argument("--runtime-source", type=Path, required=True)
    parser.add_argument("--expected-hepta-source", required=True)
    parser.add_argument("--expected-runtime-source", required=True)
    parser.add_argument("--cold-report", type=Path, required=True)
    parser.add_argument("--native-source-bootstrap", type=Path, required=True)
    parser.add_argument("--bootstrap-distribution", type=Path, required=True)
    parser.add_argument("--expected-bootstrap-distribution", required=True)
    parser.add_argument("--native-bootstrap", type=Path, required=True)
    parser.add_argument("--native-toolchain", type=Path, required=True)
    parser.add_argument("--prebuild-execution", type=Path, required=True)
    parser.add_argument("--cold-execution", type=Path, required=True)
    parser.add_argument("--post-execution", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    custody.require(sys.platform == "linux" and os.uname().machine == "x86_64",
                    "native cold language qualification requires Linux x86-64")
    hepta, runtime = args.hepta.resolve(), args.runtime_source.resolve()
    output = args.output.absolute()
    custody.require(not output.exists() and not any(part.is_symlink() for part in (output, *output.parents)),
                    "native language qualification requires a fresh ordinary output path")
    directory = output.with_suffix(".evidence")
    directory.mkdir(mode=0o700)
    report = {"schema": "hepta.runtime.native-cold-language-qualification.v1", "status": "FAIL",
              "checks": {}, "positive": [], "negative": [], "traps": [],
              "claims": {"whole_HIA_language_self_hosted": False, "compiler_correctness_formally_proved": False,
                         "finite_witnesses_prove_all_inputs": False, "Python_seed_constructed": False,
                         "native_cold_reference_timing_replaced": False}}
    started = time.monotonic_ns()
    language = None
    try:
        report["sources"] = {"runtime": custody.source_identity(runtime, args.expected_runtime_source),
                             "hepta": custody.source_identity(hepta, args.expected_hepta_source)}
        report["python_source_imports"] = custody.prepare_source_imports(
            [hepta, runtime], directory / "import-cache")
        _, _, binding = custody.admit_native_cold_compiler(hepta, args.cold_report, args.native_source_bootstrap)
        report["cold_source_binding"] = binding
        report["native_execution_observations"] = custody.admit_native_execution_observations(hepta, args)
        compilers, observer, report["cold_generations"] = cold_successors(args.cold_report, binding)
        report["cold_phase_evidence"] = phase_evidence(args.cold_report)
        report["profile"] = binding["profile"]
        sys.path.insert(0, str(hepta))
        from tools import qualify_hia_selfhost as compiler_api
        spec = importlib.util.spec_from_file_location(
            "selected_hepta_language_witnesses", hepta / "tests/test_hia_selfhost_language_coverage.py")
        language = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(language)
        inventory = language.validate_inventory()
        custody.require(inventory["profile"] == binding["profile"], "language inventory belongs to another profile")
        report["inventory_sha256"] = custody.digest(hepta / language.COVERAGE_PATH)
        reference = language.independent_references()
        reference_path = directory / "independent-reference.json"
        custody.write_json(reference_path, reference)
        report["reference"] = {"path": str(reference_path), "sha256": custody.digest(reference_path),
                               "scalar_cases": len(reference["scalar"]), "before_B0": False,
                               "before_this_language_execution": True}
        report["checks"].update(reference_vm_matches_all_scalar_oracles=True,
            inventory_matches_actual_compiler_source=True, original_fixed_point=True, modified_fixed_point=True,
            raw_native_cold_evidence_retained=True)
        report["counts"] = run_fixtures(language, compiler_api, compilers, observer, directory, report)
        _, _, following = custody.admit_native_cold_compiler(hepta, args.cold_report, args.native_source_bootstrap)
        custody.require(following == binding, "native language source/cold/bootstrap inputs changed during execution")
        custody.require(custody.admit_native_execution_observations(hepta, args) == report["native_execution_observations"],
            "native execution observations changed during language qualification")
        custody.require([custody.source_import_inventory(root) for root in (hepta, runtime)]
                        == report["python_source_imports"], "native language observer source changed during execution")
        report["checks"]["source_closure_unchanged"] = True
        report["counts"].update(scalar_witnesses=len(reference["scalar"]), checks_total=len(report["checks"]),
                                checks_passed=sum(report["checks"].values()))
        report["status"] = "SELFHOST_LANGUAGE_COVERAGE_PASS" if all(report["checks"].values()) else "FAIL"
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        report["wall_elapsed_ns"] = time.monotonic_ns() - started
        custody.write_json(output, report)
    passed = original_assertions(language, report, output, args.cold_report)
    custody.require(passed and report["status"] == "SELFHOST_LANGUAGE_COVERAGE_PASS",
                    "original language witnesses or native-cold custody assertions failed")
    print(json.dumps({"status": report["status"], "counts": report["counts"],
                      "report_sha256": custody.digest(output)}, sort_keys=True))


if __name__ == "__main__":
    main()
