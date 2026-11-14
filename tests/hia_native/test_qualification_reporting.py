"""Regressions for qualification failures and preserved subprocess evidence."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from qualify_hia_runtime_native import (MODULES, file_info_evidence, io_reference_evidence, local_service_reference_evidence,
                                       native_composition_evidence, nonce_composition_evidence,
                                       operation_aead_evidence, operation_kdf_evidence, operation_nonce_evidence,
                                       operation_record_evidence, record_composition_evidence,
                                       qualification_env, record_check, sources)
from qualify_hia_runtime_native import FILE_INFO_SUITES, validate_file_info_guard_times
from compare_hia_runtime_rust import run as compare_rust
from compare_hia_runtime_rust import RECIPES, NEW_COMPONENTS, PYTHON_REFERENCE_COMPONENTS
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, check_original_sources
from hia_native_build import HEPTA_COMMIT, HEPTA_TREE


class QualificationReportingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="hia-reporting-")
        self.addCleanup(self.folder.cleanup)
        self.output = Path(self.folder.name)
        self.report = {"phase": "reporting-regression", "checks": []}

    def test_success_retains_exact_streams(self):
        row = record_check(self.output, self.report, name="success", timeout=5,
                           command=[sys.executable, "-I", "-c", "print('ready')"])
        self.assertEqual(row.stdout, b"ready\n")
        self.assertEqual((self.output / "success.stdout").read_bytes(), row.stdout)
        self.assertEqual(self.report["checks"][0]["exit_code"], 0)
        self.assertFalse(self.report["checks"][0]["timed_out"])

    def test_nonzero_retains_stderr_and_failed_check(self):
        with self.assertRaisesRegex(RuntimeError, "failed"):
            record_check(self.output, self.report, name="failure", timeout=5,
                         command=[sys.executable, "-I", "-c", "import sys; sys.stderr.write('original error'); sys.exit(7)"])
        self.assertEqual((self.output / "failure.stderr").read_bytes(), b"original error")
        saved = json.loads((self.output / "result.json").read_bytes())
        self.assertEqual(saved["checks"][0]["exit_code"], 7)

    def test_timeout_retains_output_and_failed_check(self):
        program = "import sys,time; print('before timeout',flush=True); print('original stderr',file=sys.stderr,flush=True); time.sleep(30)"
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            record_check(self.output, self.report, name="timeout", timeout=0.5,
                         command=[sys.executable, "-I", "-c", program])
        self.assertEqual((self.output / "timeout.stdout").read_bytes(), b"before timeout\n")
        self.assertEqual((self.output / "timeout.stderr").read_bytes(), b"original stderr\n")
        saved = json.loads((self.output / "result.json").read_bytes())
        self.assertTrue(saved["checks"][0]["timed_out"])
        self.assertNotEqual(saved["checks"][0]["exit_code"], 0)

    def test_missing_executable_retains_start_failure(self):
        with self.assertRaisesRegex(RuntimeError, "could not start"):
            record_check(self.output, self.report, name="missing", timeout=5,
                         command=[str(self.output / "missing-executable")])
        self.assertEqual(self.report["checks"][0]["start_error"]["type"], "FileNotFoundError")
        self.assertIsNone(self.report["checks"][0]["exit_code"])

    def test_failed_phase_cannot_be_relabelled_by_comparison(self):
        original = b'{"schema":"hepta.runtime.hia-native-qualification.v1","status":"FAIL"}\n'
        (self.output / "result.json").write_bytes(original)
        with self.assertRaisesRegex(ValueError, "pending Rust comparison"):
            compare_rust(self.output, "rustc")
        self.assertEqual((self.output / "result.json").read_bytes(), original)

    def test_empty_native_inventory_cannot_pass_without_oracles(self):
        report = {"schema": "hepta.runtime.hia-native-qualification.v1", "status": "NATIVE_COMPONENTS_PASS",
                  "native_components_status": "PASS", "rust_comparison_status": "PENDING",
                  "source_sha256": sources(), "rust_oracle_inputs": {}, "modules": {}, "checks": []}
        (self.output / "result.json").write_text(json.dumps(report))
        result = compare_rust(self.output, "missing-rustc")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["rust_comparison_status"], "FAIL")
        self.assertIn("module inventory differs", result["error"]["message"])
        self.assertTrue((self.output / "rust-comparison-failure.txt").is_file())

    def test_every_component_has_one_explicit_reference_domain(self):
        declared = {item['key'] for item in MODULES}
        domains = (set(RECIPES), NEW_COMPONENTS, PYTHON_REFERENCE_COMPONENTS)
        self.assertEqual(declared, set.union(*domains))
        for left in range(len(domains)):
            for right in range(left + 1, len(domains)):
                self.assertFalse(domains[left] & domains[right])
        self.assertIn('file_info_service', PYTHON_REFERENCE_COMPONENTS)
        self.assertNotIn('file_info_service', RECIPES)

    def test_every_copied_original_owner_is_pinned_to_baseline_bytes(self):
        fixture = self.output / "reference"
        for name in ORIGINAL_RUNTIME_BLOBS:
            path = fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes())
        self.assertEqual(set(check_original_sources(fixture)), set(ORIGINAL_RUNTIME_BLOBS))
        for name in ORIGINAL_RUNTIME_BLOBS:
            with self.subTest(owner=name):
                path = fixture / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n// source changed after copied oracle\n")
                with self.assertRaisesRegex(ValueError, "differs from pinned baseline"):
                    check_original_sources(fixture)
                path.write_bytes(original)

    def test_cold_summary_flag_cannot_replace_the_actual_report(self):
        import hashlib
        bootstrap = self.output / "build/bootstrap"
        bootstrap.mkdir(parents=True)
        raw = json.dumps({"dependency": {"commit": HEPTA_COMMIT, "tree": HEPTA_TREE, "files": {}}}).encode()
        (bootstrap / "bootstrap.json").write_bytes(raw)
        for label in ("B1", "B2", "B3"):
            (bootstrap / (label + ".image.bin")).write_bytes(b"compiler")
        report = {"schema": "hepta.runtime.hia-native-qualification.v1", "status": "NATIVE_COMPONENTS_PASS",
                  "native_components_status": "PASS", "rust_comparison_status": "PENDING",
                  "source_sha256": sources(), "rust_oracle_inputs": {}, "checks": [],
                  "modules": {item["key"]: {} for item in MODULES},
                  "inventory": {"original_sources": check_original_sources(ROOT)},
                  "compiler_bootstrap_sha256": hashlib.sha256(raw).hexdigest(),
                  "compiler_image_sha256": hashlib.sha256(b"compiler").hexdigest(),
                  "matching_source_full_cold_qualified": True, "compiler_cold_status": "PASS"}
        (self.output / "result.json").write_text(json.dumps(report))
        result = compare_rust(self.output, "missing-rustc")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["error"]["type"], "ValueError")
        self.assertIn("compiler-cold.json", result["error"]["message"])
        self.assertEqual(result["checks"], [])

    def test_io_reference_suite_cannot_pass_with_zero_original_comparisons(self):
        record_check(self.output, self.report, name="test_native_io.py", timeout=5,
                     command=[sys.executable, "-I", "-c",
                              "print('{\"native_io\": {\"elf_requests\": 119, \"original_read_comparisons\": 0}}')"])
        with self.assertRaisesRegex(ValueError, "retained-reference coverage differs"):
            io_reference_evidence(self.output, self.report)

    def test_service_reference_suite_cannot_pass_without_live_comparisons(self):
        summary = {"schema": "hepta.runtime.native-local-service-test.v1", "status": "pass",
                   "counts": {"elf_requests": 234, "original_read_comparisons": 0,
                              "protocol_errors": 20, "domain_errors": 21, "native_controller_calls": 8}}
        record_check(self.output, self.report, name="test_local_service.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps(summary)) + ")"])
        with self.assertRaisesRegex(ValueError, "retained-reference coverage differs"):
            local_service_reference_evidence(self.output, self.report)

    def test_composition_cannot_replace_its_fixed_authority_table(self):
        import hashlib
        proof = json.loads((ROOT / "native/local_service_observation.json").read_bytes())
        profile = proof["profile"]
        profile[0]["call_mask"] |= 1  # Root recursion is outside the declared service table.
        metadata = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                    "transport": "newline-json", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": proof["compiler_sha256"], "executable": "native-local-read.elf",
                    "runtime_python_required": False, "runtime_libc_required": False,
                    "whole_runtime_replaced": False, "profile": profile, "members": proof["modules"]}
        raw = json.dumps(metadata).encode()
        (self.output / "manifest.json").write_bytes(raw)
        report = {"compiler_image_sha256": proof["compiler_sha256"], "modules": {"local_service": {
            "builder": "composition", "manifest": "manifest.json", "sha256": hashlib.sha256(raw).hexdigest()}}}
        with self.assertRaisesRegex(ValueError, "fixed seven-image authority table differs"):
            native_composition_evidence(self.output, report)

    def test_kdf_reference_suite_cannot_drop_its_capacity_reference_domain(self):
        summary = {"status": "PASS", "counts": {
            "native_calls": 1378, "standard_reference_cases": 867, "original_binding_cases": 388,
            "exact_capacity_reference_cases": 0, "capacity_refusal_cases": 14, "elf_requests": 5}}
        record_check(self.output, self.report, name="test_operation_kdf.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps(summary)) + ")"])
        with self.assertRaisesRegex(ValueError, "reference/capacity accounting differs"):
            operation_kdf_evidence(self.output, self.report)

    def test_aead_reference_suite_cannot_drop_authentication_refusals(self):
        summary = {"status": "PASS", "counts": {
            "native_calls": 1856, "encryption_reference_cases": 671, "decryption_reference_cases": 671,
            "authentication_refusals": 0, "admission_refusals": 119, "capacity_refusals": 15,
            "exact_capacity_successes": 4, "original_record_projection_cases": 33, "elf_requests": 6}}
        record_check(self.output, self.report, name="test_operation_aead.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps(summary)) + ")"])
        with self.assertRaisesRegex(ValueError, "reference/authentication/capacity accounting differs"):
            operation_aead_evidence(self.output, self.report)

    def test_nonce_reference_suite_cannot_replace_persistent_elf_calls_with_direct_calls(self):
        summary = {"status": "PASS", "counts": {
            "native_calls": 17830, "initializations": 9, "destructions": 4,
            "accepted_reservations": 17183, "nonce_refusals": 287, "admission_refusals": 325,
            "state_refusals": 13, "capacity_refusals": 9, "elf_requests": 16401,
            "elf_processes": 4, "composed_elf_requests": 0}}
        record_check(self.output, self.report, name="test_operation_nonce.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps(summary)) + ")"])
        with self.assertRaisesRegex(ValueError, "state/capacity/ELF accounting differs"):
            operation_nonce_evidence(self.output, self.report)

    def test_nonce_fixture_cannot_grant_its_leaf_continuation_authority(self):
        import hashlib
        profile = [{"id": 0, "name": "nonce-hex-fixture", "flags": 1, "call_mask": 2,
                    "input_capacity": 8 << 20, "output_capacity": 8 << 20,
                    "workspace_capacity": 16 << 20,
                    "source_sha256": hashlib.sha256((ROOT / "tests/hia_native/nonce_hex_transport.hepta").read_bytes()).hexdigest()},
                   {"id": 1, "name": "operation-nonce", "flags": 1, "call_mask": 1,
                    "input_capacity": 164, "output_capacity": 64, "workspace_capacity": 1576960,
                    "source_sha256": hashlib.sha256((ROOT / "native/operation_nonce.hepta").read_bytes()).hexdigest()}]
        metadata = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                    "transport": "newline-json", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": "fixture-compiler", "executable": "native-local-read.elf",
                    "runtime_python_required": False, "runtime_libc_required": False,
                    "whole_runtime_replaced": False, "profile": profile, "members": [{}, {}]}
        raw = json.dumps(metadata).encode()
        (self.output / "manifest.json").write_bytes(raw)
        report = {"compiler_image_sha256": "fixture-compiler", "nonce_composition": {
            "builder": "composition_fixture", "manifest": "manifest.json",
            "sha256": hashlib.sha256(raw).hexdigest()}}
        with self.assertRaisesRegex(ValueError, "fixed two-image authority table differs"):
            nonce_composition_evidence(self.output, report, {})

    def test_nonce_summary_cannot_replace_all_nine_executable_test_groups(self):
        historical = json.loads((ROOT / "native/operation_nonce_original_rust_comparison.json").read_bytes())
        summary = {"status": "PASS", "counts": historical["native_corpus"]["counts"]}
        record_check(self.output, self.report, name="test_operation_nonce.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps(summary)) + ")"])
        with self.assertRaisesRegex(ValueError, "all nine completed executable test groups"):
            operation_nonce_evidence(self.output, self.report)

    def test_qualification_child_cannot_inherit_external_loader_source_or_probe(self):
        external = {"HIA_NATIVE_LOADER": "/external/loader.py",
                    "HIA_PROTOCOL_SOURCE": "/external/protocol.hepta",
                    "HIA_IO_PROBE_MANIFEST": "/external/probe/manifest.json",
                    "HIA_SERVICE_SOURCE": "/external/service.hepta",
                    "HIA_KDF_SOURCE_ROOT": "/external/kdf-source",
                    "HIA_AEAD_SOURCE_ROOT": "/external/aead-source",
                    "HIA_NONCE_SOURCE_ROOT": "/external/nonce-source",
                    "HIA_NONCE_COMPOSITION_MANIFEST": "/external/nonce-composition/manifest.json",
                    "HIA_RECORD_SOURCE_ROOT": "/external/record-source",
                    "HIA_RECORD_MANIFEST": "/external/record-composition/manifest.json",
                    "HIA_RUNTIME_REPO": "/external/repository",
                    "HIA_COMPOSITION_MANIFEST": "/external/composition/manifest.json",
                    "HIA_FUTURE_DEVELOPMENT_OVERRIDE": "/external/future",
                    "QUALIFICATION_HOST_MARKER": "preserved"}
        child = qualification_env(external)
        child["HIA_HEPTA_DIR"] = "/qualifier-owned/compiler"
        program = "import json,os; print(json.dumps(dict(os.environ),sort_keys=True))"
        row = record_check(self.output, self.report, name="closed-input-environment", timeout=5,
                           command=[sys.executable, "-I", "-c", program], env=child)
        actual = json.loads(row.stdout)
        for key in external:
            if key.startswith("HIA_"):
                with self.subTest(override=key):
                    self.assertNotIn(key, actual)
        self.assertEqual(actual["HIA_HEPTA_DIR"], "/qualifier-owned/compiler")
        self.assertEqual(actual["QUALIFICATION_HOST_MARKER"], "preserved")

    def test_record_summary_cannot_replace_nine_executable_groups(self):
        historical = json.loads((ROOT / "native/operation_record_original_rust_comparison.json").read_bytes())
        counts = historical["native_observation"]["native_record_counts"]
        record_check(self.output, self.report, name="test_operation_record.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps({"native_record_counts": counts})) + ")"])
        with self.assertRaisesRegex(ValueError, "all nine completed executable test groups"):
            operation_record_evidence(self.output, self.report)

    def test_record_summary_cannot_drop_fatal_child_controls(self):
        historical = json.loads((ROOT / "native/operation_record_original_rust_comparison.json").read_bytes())
        counts = historical["native_observation"]["native_record_counts"]
        counts["child_contract_refusals"] = 0
        record_check(self.output, self.report, name="test_operation_record.py", timeout=5,
                     command=[sys.executable, "-I", "-c", "print(" + repr(json.dumps({"native_record_counts": counts})) + ")"])
        with self.assertRaisesRegex(ValueError, "refusal/capacity/continuation/ELF accounting differs"):
            operation_record_evidence(self.output, self.report)

    def test_record_fixture_cannot_grant_its_owner_root_recursion(self):
        import hashlib
        proof = json.loads((ROOT / "native/operation_record_composition.json").read_bytes())
        profile = [{key: value for key, value in row.items() if key != "source"} for row in proof["members"]]
        profile[1]["call_mask"] |= 1
        metadata = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64",
                    "transport": "newline-json", "compiler_commit": HEPTA_COMMIT,
                    "compiler_sha256": proof["compiler_sha256"], "executable": "native-local-read.elf",
                    "runtime_python_required": False, "runtime_libc_required": False,
                    "whole_runtime_replaced": False, "profile": profile, "members": [{}, {}, {}, {}, {}]}
        raw = json.dumps(metadata).encode()
        (self.output / "manifest.json").write_bytes(raw)
        report = {"compiler_image_sha256": proof["compiler_sha256"], "modules": {"operation_record": {
            "builder": "record_composition", "manifest": "manifest.json", "sha256": hashlib.sha256(raw).hexdigest()}}}
        with self.assertRaisesRegex(ValueError, "fixed five-image authority table differs"):
            record_composition_evidence(self.output, report)

    def test_record_build_imports_ignore_inherited_reference_source_override(self):
        external = self.output / "external"
        (external / "scripts").mkdir(parents=True)
        (external / "scripts/hia_native_composition_build.py").write_text(
            "raise RuntimeError('external record build code was executed')\n")
        env = qualification_env()
        env["HIA_REFERENCE_RUNTIME"] = str(external)
        program = ("import pathlib,sys; sys.path.insert(0," + repr(str(ROOT / "scripts")) + "); "
                   "import hia_native_record_build,hia_native_composition_build; "
                   "assert pathlib.Path(hia_native_composition_build.__file__).resolve()==pathlib.Path("
                   + repr(str(ROOT / "scripts/hia_native_composition_build.py")) + ").resolve(); print('PASS')")
        row = record_check(self.output, self.report, name="record-build-import-custody", timeout=5,
                           command=[sys.executable, "-I", "-B", "-c", program], env=env)
        self.assertEqual(row.stdout, b"PASS\n")

    def file_info_receipt_fixture(self):
        """Recorded receipts are validator fixtures, never new native executions."""
        from copy import deepcopy
        from unittest.mock import patch
        evidence = json.loads((ROOT / "native/file_info_deadline_observation.json").read_bytes())["evidence"]
        keys = ("original_file_info", "hia_controller_fixtures", "hia_io_fixtures",
                "hia_deadline_fixtures", "actual_metadata_faults", "actual_fixed_deadline",
                "actual_blocking_pipe")
        rows = {}
        for (test, receipt, _, _), key in zip(FILE_INFO_SUITES, keys):
            summary = deepcopy(evidence[key])
            rows[test] = summary
            (self.output / receipt).write_text(json.dumps(summary))
        mocked = patch("qualify_hia_runtime_native.completed_test_summary",
                       side_effect=lambda output, report, test: (
                           {"stdout_sha256": "explicit-validator-fixture",
                            "stderr_sha256": "explicit-validator-fixture"}, rows[test]))
        return rows, mocked

    def test_file_info_guard_cannot_replace_actual_cancellation_with_fixture_counts(self):
        rows, mocked = self.file_info_receipt_fixture()
        rows["test_file_info_guard.py"]["counts"]["worker_cancellations"] = 0
        with mocked, self.assertRaisesRegex(ValueError, "exact test/reference/effect accounting differs"):
            file_info_evidence(self.output, self.report)

    def test_file_info_original_comparisons_cannot_be_dropped(self):
        rows, mocked = self.file_info_receipt_fixture()
        rows["test_info_service.py"]["counts"]["original_info_comparisons"] = 0
        with mocked, self.assertRaisesRegex(ValueError, "exact test/reference/effect accounting differs"):
            file_info_evidence(self.output, self.report)

    def test_file_info_receipt_cannot_replace_its_completed_stdout(self):
        _, mocked = self.file_info_receipt_fixture()
        (self.output / "file-info-io-state.json").write_text('{"status":"pass"}')
        with mocked, self.assertRaisesRegex(ValueError, "receipt differs from completed executable stdout"):
            file_info_evidence(self.output, self.report)

    def test_file_info_fixed_duration_cannot_be_shortened_or_relabelled(self):
        from copy import deepcopy
        actual = json.loads((ROOT / "native/file_info_deadline_observation.json").read_bytes())
        valid = actual["evidence"]["actual_fixed_deadline"]["timings"]
        validate_file_info_guard_times(valid)
        mutations = [[], valid[:1], valid + valid[:1]]
        for field, value in (("fixed_deadline_seconds", 0.2), ("elapsed_seconds", 0.2),
                             ("elapsed_seconds", 34), ("elapsed_seconds", float('nan')),
                             ("hold_seconds_until_response", 0), ("hold_seconds_until_response", 40)):
            changed = deepcopy(valid)
            changed[0][field] = value
            mutations.append(changed)
        for invalid in mutations:
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                validate_file_info_guard_times(invalid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
