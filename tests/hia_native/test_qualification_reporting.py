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
                                       completed_test_summary, process_summary,
                                       qualification_env, record_check, sources)
from qualify_hia_runtime_native import FILE_INFO_SUITES, validate_file_info_guard_times
from compare_hia_runtime_rust import run as compare_rust
from compare_hia_runtime_rust import RECIPES, NEW_COMPONENTS, PYTHON_REFERENCE_COMPONENTS
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, check_original_sources
from hia_native_build import HEPTA_COMMIT, HEPTA_TREE
from hia_native_entropy_qualification import (SUITES as ENTROPY_SUITES, completion as entropy_completion,
                                             exact_counts as entropy_counts, kernel_cases,
                                             native_receipt as entropy_native_receipt,
                                             normalized_kernel_report)
from hia_native_scope_qualification import (COUNTS as SCOPE_COUNTS, SPECS as SCOPE_SPECS,
                                           check_row as check_scope_row,
                                           composition_evidence as scope_composition_evidence,
                                           test_coverage as scope_test_coverage)
from hia_native_editable_qualification import (COUNTS as EDITABLE_COUNTS, exact_counts as editable_counts,
                                              exact_filter_image as editable_filter_image)
from hia_native_line_verify_qualification import (COUNTS as LINE_VERIFY_COUNTS,
                                                 exact_counts as line_verify_counts,
                                                 exact_filter_image as line_verify_filter_image)
from hia_native_view_qualification import (NATIVE_COUNTS as VIEW_COUNTS, TRANSPORT_COUNTS as VIEW_TRANSPORT_COUNTS,
                                          exact_counts as view_counts, exact_filter_image as view_filter_image,
                                          stream_identity as view_stream_identity)


class QualificationReportingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="hia-reporting-")
        self.addCleanup(self.folder.cleanup)
        self.output = Path(self.folder.name)
        self.report = {"phase": "reporting-regression", "checks": []}

    def test_editable_defaults_follow_an_arbitrarily_named_checkout(self):
        import shutil
        import subprocess
        checkout = self.output / "runtime"
        for relative in ("tests/hia_native/test_editable_content.py",
                         "tests/hia_native/editable_oracle_transport.rs",
                         "src/mcp/fs/text_editing.rs"):
            destination = checkout / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        oracle = self.output / "original-editable.rs"
        completed = subprocess.run(
            [sys.executable, "-I", "-B", str(checkout / "tests/hia_native/test_editable_content.py"),
             "--emit-oracle", str(oracle)], cwd=self.output, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertEqual(oracle.read_bytes(), (ROOT / "tests/hia_native/oracle_editable_content.rs").read_bytes())

    def test_editable_and_view_capture_domains_cannot_be_shortened_or_boolean(self):
        for expected, check in ((EDITABLE_COUNTS, editable_counts),
                                (LINE_VERIFY_COUNTS, line_verify_counts),
                                (VIEW_COUNTS, lambda value: view_counts(value, VIEW_COUNTS)),
                                (VIEW_TRANSPORT_COUNTS, lambda value: view_counts(value, VIEW_TRANSPORT_COUNTS))):
            check(dict(expected))
            for field in expected:
                for value in (expected[field] - 1, True):
                    with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                        check(dict(expected, **{field: value}))
                missing = dict(expected)
                del missing[field]
                with self.subTest(missing=field), self.assertRaises(ValueError):
                    check(missing)

    def test_text_filter_metadata_cannot_authorize_a_different_image_or_prefix(self):
        image = b"owned test image"
        prefix = bytearray(489)
        for offset in (96, 104):
            prefix[offset:offset + 8] = (len(prefix) + len(image)).to_bytes(8, "little")
        prefix[338:342] = (147).to_bytes(4, "little")
        candidate = prefix + image
        for check in (editable_filter_image, view_filter_image, line_verify_filter_image):
            with self.assertRaisesRegex(ValueError, "transport|filter"):
                check(candidate, image)
            with self.assertRaisesRegex(ValueError, "exact admitted native image"):
                check(candidate, b"changed test image")
            with self.assertRaisesRegex(ValueError, "exact admitted native image"):
                check(candidate + b"extra", image)

    def test_view_streamed_corpus_requires_all_rows_within_its_byte_domain(self):
        import gzip
        path = self.output / "corpus.gz"
        path.write_bytes(gzip.compress(b"OK 00\n" * 3124))
        with self.assertRaisesRegex(ValueError, "row accounting"):
            view_stream_identity(path, 1 << 20)
        path.write_bytes(gzip.compress(b"OK 00\n" * 3125))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            view_stream_identity(path, 100)
        size, _ = view_stream_identity(path, 1 << 20)
        self.assertEqual(size, 6 * 3125)

    def test_entropy_requires_all_four_exact_test_groups_without_skips(self):
        self.assertEqual([row[3] for row in ENTROPY_SUITES], [11, 5, 8, 6])
        for _, _, _, expected, counts in ENTROPY_SUITES:
            complete = {"status": "PASS", "tests_run": expected, "expected_tests": expected,
                        "failures": 0, "errors": 0, "skipped": 0,
                        "expected_failures": 0, "unexpected_successes": 0}
            entropy_completion(complete, expected)
            entropy_counts(counts, counts)
            for field, value in (("tests_run", expected - 1), ("expected_tests", expected - 1),
                                 ("failures", 1), ("errors", 1), ("skipped", 1),
                                 ("expected_failures", 1), ("unexpected_successes", 1),
                                 ("errors", False), ("status", "FAIL")):
                with self.subTest(expected=expected, field=field), self.assertRaises(ValueError):
                    entropy_completion(dict(complete, **{field: value}), expected)
            for field in counts:
                with self.subTest(count=field), self.assertRaises(ValueError):
                    entropy_counts(dict(counts, **{field: counts[field] - 1}), counts)

    def test_entropy_receipt_cannot_detach_native_output_from_compiler_or_source(self):
        import hashlib
        sha = lambda raw: hashlib.sha256(raw).hexdigest()
        image, source, produced, output = b"fixture compiler", b"fixture input", b"native bytes", b"native bytes\0\0"
        receipt = {"status": "returned", "abi_status": 0, "core_u32": len(produced),
                   "result_u64": len(produced), "source_unchanged": True, "input_bytes": len(source),
                   "input_sha256": sha(source), "source_sha256": sha(source),
                   "artifact_sha256": sha(image), "image_sha256": sha(image),
                   "output_sha256": sha(output), "forbidden_compiler_modules_loaded": []}
        args = dict(image=image, source=source, output=output, produced=produced)
        entropy_native_receipt(receipt, **args)
        for field, value in (("core_u32", len(produced) - 1), ("result_u64", 1 << 32),
                             ("source_unchanged", 1), ("abi_status", False),
                             ("artifact_sha256", "0" * 64), ("source_sha256", "0" * 64),
                             ("output_sha256", "0" * 64), ("forbidden_compiler_modules_loaded", ["fallback"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                entropy_native_receipt(dict(receipt, **{field: value}), **args)
        with self.assertRaises(ValueError):
            entropy_native_receipt(receipt, **dict(args, produced=b"other bytes"))

    def test_entropy_case_summary_does_not_replace_full_kernel_traces(self):
        import hashlib
        from hia_native_entropy_qualification import KERNEL_SOURCES
        self.assertEqual(len(kernel_cases()), 25)
        self.assertEqual(sum(len(sizes) for _, sizes, _ in kernel_cases()), 56)
        pins = {name: hashlib.sha256((ROOT / "tests/hia_native" / name).read_bytes()).hexdigest()
                for name in KERNEL_SOURCES}
        summary = {"schema": ENTROPY_SUITES[2][2], "status": "PASS", "tests_run": 8, "expected_tests": 8,
                   "failures": 0, "errors": 0, "skipped": 0, "expected_failures": 0, "unexpected_successes": 0,
                   "counts": dict(ENTROPY_SUITES[2][4], original_owner_calls=56, kernel_completions=91),
                   "source_sha256": pins, "source_unchanged": True,
                   "provenance": {"owner": "original Rust SystemEntropy", "binary_sha256": "fixture"},
                   "traces": []}
        with self.assertRaisesRegex(ValueError, "trace coverage"):
            normalized_kernel_report(ROOT, summary, original=True, binary_sha256="fixture")
        with self.assertRaisesRegex(ValueError, "source"):
            normalized_kernel_report(ROOT, dict(summary, source_sha256={}), original=True, binary_sha256="fixture")
        with self.assertRaisesRegex(ValueError, "executable identity"):
            normalized_kernel_report(ROOT, summary, original=True, binary_sha256="different")

    def test_scope_requires_all_twelve_groups_and_complete_control_counts(self):
        summary = {"native_scope_counts": SCOPE_COUNTS}
        stderr = "\nRan 12 tests in 1.234s\n\nOK\n"
        scope_test_coverage(summary, stderr)
        for invalid in (stderr.replace("12", "11"), stderr.replace("OK", "OK (skipped=1)"),
                        stderr.replace("OK", "OK (expected failures=1)"), stderr + stderr):
            with self.assertRaises(ValueError):
                scope_test_coverage(summary, invalid)
        for field in ("direct_requests_6", "fault_sessions_excluded_from_rust",
                      "fault_session_prefix_rows_excluded", "actual_elf_fatal_contract_controls"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                scope_test_coverage({"native_scope_counts": dict(SCOPE_COUNTS, **{field: SCOPE_COUNTS[field] - 1})}, stderr)

    def test_scope_fixture_cannot_grant_direct_raw_record_authority(self):
        import hashlib
        profile = [{"id": index, "name": name, "source_sha256": hashlib.sha256((ROOT / source).read_bytes()).hexdigest(),
                    "flags": flags, "call_mask": mask, "input_capacity": inp, "output_capacity": out,
                    "workspace_capacity": work}
                   for index, (name, source, flags, mask, inp, out, work) in enumerate(SCOPE_SPECS)]
        profile[0]["call_mask"] |= 2
        manifest = self.output / "build/composition/fixture/manifest.json"
        manifest.parent.mkdir(parents=True)
        metadata = {"schema": "hepta.runtime.native-composition.v1", "target": "linux-x86_64", "transport": "newline-json",
                    "compiler_commit": HEPTA_COMMIT, "compiler_sha256": "fixture", "executable": "native-local-read.elf",
                    "runtime_python_required": False, "runtime_libc_required": False, "whole_runtime_replaced": False,
                    "profile": profile, "members": [{} for _ in range(8)]}
        manifest.write_text(json.dumps(metadata))
        report = {"compiler_image_sha256": "fixture", "modules": {"operation_scope": {
            "builder": "scope_composition", "source": "native/operation_scope.hepta",
            "manifest": str(manifest.relative_to(self.output)), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()}}}
        with self.assertRaisesRegex(ValueError, "authority table"):
            scope_composition_evidence(ROOT, self.output, report)

    def test_scope_fault_records_must_retain_full_mutated_completion_words(self):
        from copy import deepcopy
        row = {"session": 4, "target": 6, "input_hex": "", "code": 0xffffffe8, "output_hex": "",
               "scope_state": 4, "scope_references": 0, "entropy_calls": 0, "nonce_count": 0,
               "native_ordinal": 16391, "output_capacity": 128, "export_requested": False,
               "injected_fault_reason": "fixture completion fault",
               "child_events": [{"caller": 6, "phase": 1, "target": 2, "input_bytes": 32,
                                 "output_capacity": 128, "code": 128, "fixture_completion_words": [0] * 14}]}
        check_scope_row(row, control=True)
        missing = deepcopy(row)
        del missing["child_events"][0]["fixture_completion_words"]
        shortened = deepcopy(row)
        shortened["child_events"][0]["fixture_completion_words"].pop()
        granted = deepcopy(row)
        granted["child_events"][0]["target"] = 0
        for invalid in (missing, shortened, granted):
            with self.assertRaises(ValueError):
                check_scope_row(invalid, control=True)

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

    def test_authority_registry_preserves_all_suites_sources_and_original_owners(self):
        from hia_native_authority_qualification import SUITES, ORIGINAL_PINS
        entry = next(item for item in MODULES if item["key"] == "caller_authority")
        self.assertEqual((entry["test"], *entry["additional_tests"]), tuple(row[0] for row in SUITES))
        self.assertEqual([row[3] for row in SUITES], [8, 5, 6, 4, 7])
        self.assertEqual(entry["builder"], "authority_composition")
        self.assertEqual(entry["manifest_env"], "HIA_AUTHORITY_ELF_MANIFEST")
        self.assertIn("caller_authority", RECIPES)
        self.assertTrue(set(ORIGINAL_PINS) <= set(ORIGINAL_RUNTIME_BLOBS))
        pinned = sources()
        for name in (entry["source"], *entry["companion_sources"], *ORIGINAL_PINS,
                     "rustfmt.toml", "scripts/hia_native_authority_build.py",
                     "scripts/hia_native_authority_probe_build.py",
                     "scripts/hia_native_authority_layout.py",
                     "scripts/hia_native_authority_qualification.py"):
            self.assertIn(name, pinned)

    def test_batch_registry_requires_full_native_and_original_domains(self):
        from hia_native_batch_plan_qualification import SOURCE_FILES, REFERENCE_FILES, ORIGINALS
        entry = next(item for item in MODULES if item["key"] == "batch_plan")
        self.assertEqual((entry["test"], *entry["additional_tests"]),
                         ("test_batch_plan.py", "test_batch_plan_evidence.py"))
        self.assertEqual(entry["builder"], "batch_plan")
        self.assertEqual(entry["manifest_env"], "HIA_BATCH_PLAN_BUNDLE")
        self.assertIn("batch_plan", RECIPES)
        self.assertTrue(set(ORIGINALS) <= set(ORIGINAL_RUNTIME_BLOBS))
        pinned = sources()
        self.assertTrue(set(SOURCE_FILES) | set(REFERENCE_FILES) | set(ORIGINALS) <= set(pinned))
        self.assertIn("native/batch_plan_original_rust_comparison.json", pinned)
        inherited = {key: "/outside/fixture" for key in (
            "HIA_BATCH_PLAN_BUNDLE", "HIA_BATCH_PLAN_MANIFEST", "HIA_BATCH_ENDPOINT_MANIFEST",
            "HIA_BATCH_VERIFY_MANIFEST", "HIA_BATCH_PLAN_ELF_MANIFEST", "HIA_BATCH_PLAN_CORPUS_DIR",
            "HIA_BATCH_PLAN_EVIDENCE_RESULT", "HIA_REFERENCE_RUNTIME")}
        self.assertEqual(qualification_env(dict(inherited, PATH="/usr/bin")), {"PATH": "/usr/bin"})

    def test_batch_complete_progress_is_bound_to_the_actual_process_stream(self):
        progress = [
            {"phase": "maximum_plain", "status": "PASS", "output_bytes": 524298089,
             "workspace_bytes": 534831101},
            {"phase": "maximum_stale", "status": "PASS", "output_bytes": 524301763,
             "workspace_bytes": 534835575},
        ]
        # This is a reporting fixture, not a semantic batch execution.
        final = {"fixture": "process framing only", "status": "PASS"}
        wire = "\n".join(json.dumps(row) for row in [*progress, final]) + "\n"
        record_check(self.output, self.report, name="test_batch_plan.py",
                     command=[sys.executable, "-c", "import sys;sys.stdout.write(sys.argv[1])", wire],
                     timeout=5)
        _, observed = completed_test_summary(self.output, self.report, "test_batch_plan.py")
        self.assertEqual(observed, final)
        for rows in ([final], [progress[0], final], [*reversed(progress), final],
                     [*progress, final, final],
                     [dict(progress[0], status="FAIL"), progress[1], final],
                     [dict(progress[0], output_bytes=524298088), progress[1], final]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                process_summary("test_batch_plan.py", "\n".join(json.dumps(row) for row in rows).encode())
        with self.assertRaises(ValueError):
            process_summary("another-suite.py", wire.encode())

    def test_batch_wide_profile_cannot_claim_a_standard_standalone_transport(self):
        from unittest.mock import patch
        from hia_native_build import BUFFER_PROFILES, NativeBuild
        from hia_native_loader import BUFFER_PROFILES as LOADER_PROFILES
        self.assertEqual(BUFFER_PROFILES, LOADER_PROFILES)
        self.assertEqual(BUFFER_PROFILES["standard"], (8 << 20, 8 << 20, 32 << 20))
        self.assertEqual(BUFFER_PROFILES["view-render.v1"], (16 << 20, 16 << 20, 256 << 20))
        self.assertEqual(BUFFER_PROFILES["batch-plan.v1"], (512 << 20, 1024 << 20, 1152 << 20))
        builder = object.__new__(NativeBuild)
        with patch.object(builder, "bootstrap") as bootstrap:
            for transport in ("filter", "stdio"):
                with self.subTest(transport=transport), self.assertRaisesRegex(ValueError, "image-only"):
                    builder.compile("capacity-refusal-fixture", self.output / "absent.hepta",
                                    standalone=transport, buffer_profile="batch-plan.v1")
            bootstrap.assert_not_called()

    def test_batch_original_stream_is_complete_binary_and_bounded(self):
        import gzip
        import hashlib
        from compare_hia_runtime_rust import batch_replay_stream_identity
        raw = b"\x00\xff\r" * 349527  # More than one read chunk; no newline row grammar.
        path = self.output / "binary-result.gz"
        path.write_bytes(gzip.compress(raw, mtime=0))
        self.assertEqual(batch_replay_stream_identity(path, len(raw)),
                         (len(raw), hashlib.sha256(raw).hexdigest()))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            batch_replay_stream_identity(path, len(raw) - 1)
        link = self.output / "linked-result.gz"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            batch_replay_stream_identity(link, len(raw))

    def test_batch_outer_timeout_kills_and_reaps_the_actual_reference_child(self):
        import ctypes
        import gzip
        import hashlib
        import os
        import signal
        import time
        from hia_native_batch_plan_qualification import ORIGINALS
        # The test invokes the real comparison lifecycle with a deliberately
        # blocking executable. Typed source/corpus fixtures are explicitly
        # substituted; this control adds no native or original semantic cases.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        child = None
        reaped = False
        try:
            marker = self.output / "reference-child.json"
            binary = self.output / "blocking-reference"
            binary.write_text("#!" + sys.executable + "\nimport json,os,signal\n"
                              "from pathlib import Path\n"
                              "Path(" + repr(str(marker)) + ").write_text(json.dumps({"
                              "'pid':os.getpid(),'parent':os.getppid(),'group':os.getpgrp()}))\n"
                              "signal.pause()\n")
            binary.chmod(0o700)
            corpus = self.output / "timeout-corpus"
            corpus.mkdir()
            metadata = {"report": {"reference_rows": 1}, "requests": {"file": "requests.bin.gz"},
                        "native_output": {"file": "native-output.bin.gz", "raw_bytes": 0,
                                          "raw_sha256": hashlib.sha256(b"").hexdigest()},
                        "history": {"file": "history.jsonl.gz"}}
            (corpus / "native-corpus.json").write_text(json.dumps(metadata))
            for name in ("requests.bin.gz", "native-output.bin.gz", "history.jsonl.gz"):
                (corpus / name).write_bytes(gzip.compress(b"", mtime=0))
            source_map = {name: row["sha256"] for name, row in ORIGINALS.items()}
            source_map.update({name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                              for name in ("tests/hia_native/batch_plan_oracle/Cargo.toml",
                                           "tests/hia_native/batch_plan_oracle/Cargo.lock")})
            receipt = self.output / "fixture-build.json"
            receipt.write_text(json.dumps({"schema": "hepta.runtime.batch-plan.original-build.v1",
                "status": "PASS", "exit_code": 0, "timed_out": False,
                "oracle_sha256": hashlib.sha256((ROOT / "tests/hia_native/oracle_batch_plan.rs").read_bytes()).hexdigest(),
                "source_map": source_map, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
            program = "\n".join((
                "import sys", "from pathlib import Path",
                "sys.path.insert(0, sys.argv[1] + '/tests/hia_native')",
                "import compare_batch_plan_original as owner",
                "owner.source_bindings = lambda *args: {'fixture': 'process lifetime only'}",
                "owner.stream_identity = lambda *args: None",
                "owner.compare(Path(sys.argv[1]), Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), binary=Path(sys.argv[4]), build_receipt=Path(sys.argv[5]))",
            ))
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                record_check(self.output, self.report, name="batch-reference-timeout-control",
                    command=[sys.executable, "-I", "-B", "-c", program, str(ROOT), str(corpus),
                             str(self.output / "timeout-replay"), str(binary), str(receipt)], timeout=2)
            observed = json.loads(marker.read_bytes())
            child = observed["pid"]
            self.assertEqual(observed["group"], observed["parent"])
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                waited, status = os.waitpid(child, os.WNOHANG)
                if waited:
                    reaped = True
                    self.assertTrue(os.WIFSIGNALED(status))
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                    break
                time.sleep(0.01)
            self.assertTrue(reaped, "outer qualification timeout left its actual reference child alive")
            self.assertTrue(self.report["checks"][-1]["timed_out"])
            control_receipt = {"schema": "hepta.runtime.batch-reference-timeout-control.v1", "status": "PASS",
                "native_semantic_calls_added": 0, "original_semantic_calls_added": 0,
                "actual_child_processes": 1, "child": observed, "child_reaped": reaped,
                "wait_status": status, "termination_signal": os.WTERMSIG(status),
                "fixture_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "comparison_source_sha256": hashlib.sha256((ROOT / "tests/hia_native/compare_batch_plan_original.py").read_bytes()).hexdigest(),
                "actual_outer_check": self.report["checks"][-1]}
        finally:
            if child is None and 'marker' in locals() and marker.is_file():
                child = json.loads(marker.read_bytes())["pid"]
            if child is not None and not reaped:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child, 0)
                except ChildProcessError:
                    pass
            self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)
        print(json.dumps(control_receipt, sort_keys=True))

    def test_authority_rust_format_uses_only_the_selected_toolchain(self):
        from unittest.mock import patch
        from compare_hia_runtime_rust import compare_caller_authority
        selected = self.output / "selected-toolchain" / "bin"
        selected.mkdir(parents=True)
        for name in ("rustc", "cargo", "cargo-fmt", "rustfmt"):
            path = selected / name
            path.write_text("explicit command-selection fixture; never executed\n")
            path.chmod(0o700)
        captured = {}

        def inspect_recipe(*args, **kwargs):
            captured.update(kwargs)
            captured["environment"] = kwargs["qualification_env"]()
            return {"fixture": "command selection only"}

        with patch.dict("os.environ", {"RUSTFMT": "/unrelated/formatter"}), \
                patch("compare_hia_runtime_rust.compare_authority_original", side_effect=inspect_recipe):
            self.assertEqual(compare_caller_authority(self.output, self.report, selected / "rustc"),
                             {"fixture": "command selection only"})
        self.assertEqual(captured["cargo"], selected / "cargo")
        self.assertEqual(captured["environment"]["PATH"].split(":")[0], str(selected))
        self.assertEqual(captured["environment"]["RUSTFMT"], str(selected / "rustfmt"))
        for missing in ("cargo-fmt", "rustfmt", "cargo"):
            path = selected / missing
            saved = path.read_bytes()
            path.unlink()
            with self.subTest(missing=missing), \
                    patch("compare_hia_runtime_rust.compare_authority_original") as recipe, \
                    self.assertRaises(FileNotFoundError):
                compare_caller_authority(self.output, self.report, selected / "rustc")
            recipe.assert_not_called()
            path.write_bytes(saved)
            path.chmod(0o700)

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
