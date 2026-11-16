#!/usr/bin/env python3
"""Source/receipt controls for focused orchestration; no native or Rust entry."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("canonical_focused_controls", HERE / "canonical_target_ci.py")
focus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(focus)


class CanonicalFocusedControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="canonical-focused-control-")
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)

    def row(self, name, phase="native_components", timeout=180, command=None):
        for suffix in ("stdout", "stderr"):
            (self.output / (name + "." + suffix)).write_bytes(b"")
        return {"name": name, "phase": phase,
                "command": command or [sys.executable, "-I", "-B", str(focus.ROOT / "tests/hia_native" / name)],
                "timeout_seconds": timeout, "elapsed_seconds": 0.01, "exit_code": 0, "timed_out": False,
                **{suffix + field: value for suffix in ("stdout", "stderr")
                   for field, value in (("_bytes", 0), ("_sha256", hashlib.sha256(b"").hexdigest()))}}

    def test_frozen_public_trace_is_checked_before_execution(self):
        relative = focus.filesystem_public_pipeline.DRIVERS
        source = focus.ROOT / relative
        target = self.output / relative
        target.mkdir(parents=True)
        for name in (*focus.filesystem_public_pipeline.DRIVER_FILES, "source_manifest.json"):
            shutil.copyfile(source / name, target / name)
        focus.filesystem_public_pipeline.producer_sources(self.output)
        with (target / "strict_trace.py").open("ab") as stream:
            stream.write(b"\n# changed retained trace\n")
        with self.assertRaisesRegex(ValueError, "frozen SDK producer/reader source: strict_trace.py"):
            focus.filesystem_public_pipeline.producer_sources(self.output)

    def native(self):
        prepared = {"status": "NATIVE_BUILD_READY", "phase": "native_build_complete",
                    "native_components_status": "PENDING", "rust_comparison_status": "PENDING",
                    "checks": [{"name": "compiler-cold"}], "source_sha256": {"owned": "fixed"},
                    **{flag: False for flag in focus.FALSE_FLAGS}}
        binding = {"group": "directory", "focus": focus.FOCUS}
        report = copy.deepcopy(prepared)
        report.update(status="CANONICAL_NATIVE_GROUP_PASS", phase="canonical_native_complete",
                      native_components_status="PARTIAL", qualification_shard=binding,
                      native_parallel_receipts={}, shard_elapsed_seconds=0.1, shard_finished_at="control",
                      directory_service_evidence={"source_control_fixture": True},
                      checks=prepared["checks"] + [self.row(name) for name in focus.TESTS["directory"]])
        return prepared, report, binding

    def validate_native(self, prepared, report, binding):
        with patch.object(focus.q, "native_commands", return_value={}):
            focus.validate_native_report(self.output, report, prepared, binding)

    def original(self):
        native = {"status": "CANONICAL_NATIVE_GROUP_PASS", "phase": "canonical_native_complete",
                  "rust_comparison_status": "PENDING", "checks": [{"name": "actual-native-predecessor"}],
                  "qualification_shard": {"focus": focus.FOCUS, "group": "public"},
                  **{flag: False for flag in focus.FALSE_FLAGS}}
        report = copy.deepcopy(native)
        names = {"view_read": ["view-process"], "view_params": ["view-process"],
                 "view_call": ["view-process"], "runtime_mcp": ["public-process"],
                 "filesystem_public": ["filesystem-process"]}
        version_name = focus.rp.version_name("canonical-public")
        version = "release: 1.95.0\ncommit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n"
        row = self.row(version_name, "original_rust_comparison", 15, ["/fixed/rustc", "--version", "--verbose"])
        (self.output / (version_name + ".stdout")).write_text(version)
        row.update(stdout_bytes=len(version), stdout_sha256=hashlib.sha256(version.encode()).hexdigest())
        report.update(status="CANONICAL_ORIGINAL_GROUP_PASS", phase="canonical_original_complete",
                      rust_comparison_status="PARTIAL", original_shard=focus.original_binding(native, "a" * 64, "public"),
                      original_rust_comparisons={key: {"source_control_fixture": True} for key in focus.GROUPS["public"]},
                      rust_compiler={"invocation_path": "/fixed/rustc", "resolved_path": "/fixed/rustc",
                                     "invocation_executable_sha256": "b" * 64, "version": version},
                      rust_parallel_receipts={}, rust_recipe_processes=names,
                      rust_recipe_shared_processes={"view_params": "view_read", "view_call": "view_read"},
                      original_shard_elapsed_seconds=0.2, original_shard_finished_at="control",
                      checks=native["checks"] + [row] + [self.row(name, "original_rust_comparison")
                              for name in ("view-process", "public-process", "filesystem-process")],
                      **{name: {"source_control_fixture": True} for name in focus.PUBLIC_REFERENCE_FIELDS})
        return native, report

    def test_complete_existing_domains_and_recipe_order(self):
        actual = focus.registry()
        self.assertEqual([len(value["tests"]) for value in actual.values()], [5, 3, 17, 18])
        self.assertEqual(sum(len(value["recipes"]) for value in actual.values()), 9)
        self.assertNotIn("test_batch_plan_input.py", sum((list(v) for v in focus.TESTS.values()), []))
        self.assertNotIn("test_bellman_commitment.py", sum((list(v) for v in focus.TESTS.values()), []))

    def test_omitted_native_suite_is_refused(self):
        changed = dict(focus.TESTS, directory=focus.TESTS["directory"][:-1])
        with patch.object(focus, "TESTS", changed), self.assertRaises(ValueError):
            focus.registry()

    def test_reordered_public_producer_is_refused(self):
        changed = dict(focus.GROUPS, public=("view_params", "view_read", "view_call", "runtime_mcp", "filesystem_public"))
        with patch.object(focus, "GROUPS", changed), self.assertRaises(ValueError):
            focus.registry()

    def test_frozen_selected_source_is_complete(self):
        profile = focus.read_object(focus.ROOT / focus.PROFILE)
        self.assertEqual(len(profile["files"]), 49)
        for name, expected in profile["files"].items():
            self.assertEqual(focus.canonical.pin(focus.canonical.regular(focus.ROOT, name)), expected)
        policy = focus.canonical.source_evidence(focus.ROOT)
        self.assertEqual(policy["target_commit"], profile["target_commit"])
        self.assertFalse(policy["whole_runtime_target_qualified"])

    def test_native_complete_process_receipts_are_admitted(self):
        self.validate_native(*self.native())

    def test_native_missing_and_duplicate_processes_are_refused(self):
        prepared, report, binding = self.native()
        for changed in (report["checks"][:-1], report["checks"] + [report["checks"][-1]]):
            altered = copy.deepcopy(report)
            altered["checks"] = changed
            with self.assertRaises(ValueError):
                self.validate_native(prepared, altered, binding)

    def test_native_deadline_remains_180(self):
        prepared, report, binding = self.native()
        report["checks"][-1]["timeout_seconds"] = 181
        with self.assertRaises(ValueError):
            self.validate_native(prepared, report, binding)

    def test_native_prepared_source_and_cold_receipt_are_immutable(self):
        prepared, report, binding = self.native()
        for key, value in (("source_sha256", {"owned": "changed"}), ("checks", [{"name": "invented-cold"}, *report["checks"][1:]])):
            altered = copy.deepcopy(report)
            altered[key] = value
            with self.assertRaises(ValueError):
                self.validate_native(prepared, altered, binding)

    def test_native_real_stream_bytes_must_match(self):
        prepared, report, binding = self.native()
        (self.output / (focus.TESTS["directory"][0] + ".stdout")).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.validate_native(prepared, report, binding)

    def test_no_global_qualification_flag_can_advance(self):
        prepared, report, binding = self.native()
        for flag in focus.FALSE_FLAGS:
            changed = copy.deepcopy(report)
            changed[flag] = True
            with self.assertRaises(ValueError):
                self.validate_native(prepared, changed, binding)

    def test_delta_cannot_replace_a_predecessor(self):
        source, target = self.output / "source", self.output / "target"
        source.mkdir(); target.mkdir()
        (source / "owned").write_bytes(b"new")
        (target / "owned").write_bytes(b"predecessor")
        files, directories = focus.p.inventory(source)
        with self.assertRaises(ValueError):
            focus.import_delta(target, source, files, directories)
        self.assertEqual((target / "owned").read_bytes(), b"predecessor")

    def test_export_checks_every_file_and_empty_directory(self):
        export = self.output / "export"
        data = export / "data"
        (data / "empty").mkdir(parents=True)
        (data / "stream").write_bytes(b"complete stream")
        report = {"source_control_fixture": True}
        focus.q.save_report(export / "report.json", report)
        files, directories = focus.p.inventory(data)
        seal = {"schema": "control", "binding": {"group": "control"}, "files": files,
                "directories": directories, "report_sha256": focus.q.sha(export / "report.json")}
        focus.q.save_report(export / "seal.json", seal)
        sha = focus.q.sha(export / "seal.json")
        (data / "empty").rmdir()
        focus.exact_export(export, "seal.json", "report.json", sha, "control", {"group": "control"})
        self.assertTrue((data / "empty").is_dir())
        (data / "undeclared").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            focus.exact_export(export, "seal.json", "report.json", sha, "control", {"group": "control"})

    def test_original_shared_process_has_one_physical_owner(self):
        native, report = self.original()
        focus.validate_original_report(self.output, report, native, "a" * 64, "public")
        self.assertEqual(len(focus.r.original_process_attribution(report, focus.GROUPS["public"])), 3)

    def test_original_shared_consumer_cannot_invent_a_fresh_process(self):
        native, report = self.original()
        report["rust_recipe_processes"]["view_params"] = ["invented-second-build"]
        with self.assertRaises(ValueError):
            focus.validate_original_report(self.output, report, native, "a" * 64, "public")

    def test_original_missing_raw_reference_receipt_is_refused(self):
        native, report = self.original()
        del report["span_raw_value_reference_builds"]
        with self.assertRaises(ValueError):
            focus.validate_original_report(self.output, report, native, "a" * 64, "public")

    def test_original_unknown_process_or_larger_limit_is_refused(self):
        native, report = self.original()
        changed = copy.deepcopy(report)
        changed["checks"].append(self.row("unknown-process", "original_rust_comparison"))
        with self.assertRaises(ValueError):
            focus.validate_original_report(self.output, changed, native, "a" * 64, "public")
        report["checks"][-1]["timeout_seconds"] = 181
        with self.assertRaises(ValueError):
            focus.validate_original_report(self.output, report, native, "a" * 64, "public")

    def test_original_does_not_rewrite_native_predecessor(self):
        native, report = self.original()
        report["checks"][0] = {"name": "substituted-native"}
        with self.assertRaises(ValueError):
            focus.validate_original_report(self.output, report, native, "a" * 64, "public")

    def test_native_export_and_relocated_delta_admission_keep_complete_predecessor(self):
        # Host-only transport fixture: compile, native calls and semantic
        # readers are explicitly replaced.  File/seal code is exercised as-is.
        prepared, _, _ = self.native()
        build = self.output / "build-origin"
        restored = self.output / "restored"
        artifact = self.output / "native-export"
        build.mkdir(); restored.mkdir()
        (build / "compiler-owned.bin").write_bytes(b"immutable prepared bytes")
        focus.q.save_report(build / focus.p.BUILD_REPORT, prepared)
        files, directories = focus.p.inventory(build)
        seal = {"files": files, "directories": directories}
        focus.q.save_report(build / focus.p.BUILD_SEAL, seal)
        for path in build.iterdir():
            shutil.copyfile(path, restored / path.name)
        wanted = {"focus": focus.FOCUS, "group": "directory", "source_control_fixture": True}

        def execute(output, report, tests, environment, **kwargs):
            self.assertEqual(kwargs["timeout"], 180)
            report["native_parallel_receipts"] = {}
            for name in tests:
                row = self.row(name)
                for suffix in ("stdout", "stderr"):
                    (output / (name + "." + suffix)).write_bytes(b"")
                report["checks"].append(row)

        evidence = {"directory_service_evidence": {"source_control_fixture": True}}
        with patch.object(focus.p, "admit_prepared", return_value=(seal, prepared, None)), \
             patch.object(focus, "binding", return_value=wanted), \
             patch.object(focus, "graph_evidence", return_value={"source_control_fixture": True}), \
             patch.object(focus.q, "native_commands", return_value={}), \
             patch.object(focus.q, "native_environment", return_value={}), \
             patch.object(focus.q, "run_native_checks", side_effect=execute), \
             patch.object(focus, "native_evidence", return_value=evidence):
            result = focus.native_group(build, self.output, "a" * 64, "control", "directory", artifact)
            baseline, report = focus.import_native(restored, self.output, "a" * 64, "control",
                                                   "directory", artifact, result["sha256"])
            self.assertEqual(report["checks"][0], prepared["checks"][0])
            self.assertEqual((restored / "compiler-owned.bin").read_bytes(), b"immutable prepared bytes")
            self.assertIn(focus.NATIVE_REPORT, baseline["files"])
            original = copy.deepcopy(report)
            version_name = focus.rp.version_name("canonical-directory")
            version = "release: 1.95.0\ncommit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860\n"
            version_row = self.row(version_name, "original_rust_comparison", 15,
                                   ["/source-control/rustc", "--version", "--verbose"])
            version_row.update(stdout_bytes=len(version), stdout_sha256=hashlib.sha256(version.encode()).hexdigest())
            reference_row = self.row("source-control-reference", "original_rust_comparison")
            for row in (version_row, reference_row):
                for suffix in ("stdout", "stderr"):
                    (restored / (row["name"] + "." + suffix)).write_bytes(
                        version.encode() if row is version_row and suffix == "stdout" else b"")
            original.update(status="CANONICAL_ORIGINAL_GROUP_PASS", phase="canonical_original_complete",
                rust_comparison_status="PARTIAL", original_shard=focus.original_binding(report, result["sha256"], "directory"),
                original_rust_comparisons={"directory_service": {"source_control_fixture": True}},
                rust_compiler={"invocation_path": "/source-control/rustc", "resolved_path": "/source-control/rustc",
                               "invocation_executable_sha256": "b" * 64, "version": version},
                rust_parallel_receipts={}, rust_recipe_processes={"directory_service": ["source-control-reference"]},
                rust_recipe_shared_processes={}, original_shard_elapsed_seconds=0.1, original_shard_finished_at="control",
                checks=report["checks"] + [version_row, reference_row])
            focus.q.save_report(restored / focus.ORIGINAL_REPORT, original)
            original_artifact = self.output / "original-export"
            original_sha = focus.export_original(restored, original_artifact, baseline, original)
            with patch.object(focus, "retained_original", return_value=original["original_rust_comparisons"]):
                admitted = focus.verify_original(restored, self.output, "a" * 64, "control", "directory",
                                                 result["sha256"], original_artifact, original_sha)
            self.assertEqual(admitted["actual_original_processes"], 2)
            self.assertEqual(admitted["new_native_processes"], 0)
            self.assertEqual(admitted["new_rust_processes"], 0)
            (restored / "compiler-owned.bin").write_bytes(b"changed prepared bytes")
            with self.assertRaises(ValueError):
                focus.admit_native(restored, self.output, "a" * 64, "control", "directory", result["sha256"], exact=True)

    def test_workflow_preserves_job_and_process_limits(self):
        workflow = (focus.ROOT / ".github/workflows/hia-runtime-canonical-group.yml").read_text()
        main = (focus.ROOT / ".github/workflows/hia-runtime-canonical-target.yml").read_text()
        self.assertEqual(workflow.count("timeout-minutes: 15"), 1)
        self.assertEqual(main.count("timeout-minutes: 15"), 2)
        self.assertIn("verify-original", workflow)
        self.assertIn("--output \"$RUNNER_TEMP/canonical-diagnostics\"", workflow)
        self.assertIn("cancel-in-progress: false", main)
        self.assertNotIn("actions/cache", workflow + main)
        for group in focus.GROUPS:
            self.assertIn("native_" + group + ":", main)
            self.assertIn("original_" + group + ":", main)

    def test_final_join_requires_all_pinned_independent_admissions(self):
        folder = self.output / "admissions"
        folder.mkdir()
        head, invocation = "1" * 40, "source-control"
        source = {"source_control_fixture": True}
        context = {"invocation": invocation, "checkout_head": head, "source": "/same/source", "output": "/same/output"}
        expected = []
        for group in focus.GROUPS:
            native = {"focus": focus.FOCUS, "group": group, "context": context, "source": source,
                      "prepared_sha256": "a" * 64, "tests": list(focus.TESTS[group]), "recipes": list(focus.GROUPS[group])}
            value = {"schema": "hepta.runtime.canonical-focused-admission.v1", "status": "PASS", "group": group,
                "binding": {"focus": focus.FOCUS, "group": group, "native_sha256": "b" * 64,
                            "native_binding": native, "recipes": list(focus.GROUPS[group])},
                "original_sha256": "c" * 64, "native_sha256": "b" * 64,
                "full_retained_files": 1, "full_retained_bytes": 1, "native_tests": list(focus.TESTS[group]),
                "original_recipes": list(focus.GROUPS[group]), "actual_original_processes": 1,
                "all_existing_owner_readers_rerun": True, "new_native_processes": 0, "new_rust_processes": 0,
                "direct_canonical_abi_suite_qualified": False, **{flag: False for flag in focus.FALSE_FLAGS}}
            path = folder / (group + ".json")
            focus.q.save_report(path, value)
            expected.append(group + "=" + "c" * 64 + ":" + focus.q.sha(path))
        with patch.object(focus, "source_identity", return_value=source):
            joined = focus.collect_admissions(folder, expected, head, invocation)
            self.assertEqual(joined["existing_native_suites"], 43)
            self.assertFalse(joined["whole_runtime_replaced"])
            with self.assertRaises(ValueError):
                focus.collect_admissions(folder, expected[:-1], head, invocation)
            path = folder / "public.json"
            changed = focus.read_object(path)
            changed["new_native_processes"] = False
            focus.q.save_report(path, changed)
            altered = expected[:-1] + ["public=" + "c" * 64 + ":" + focus.q.sha(path)]
            with self.assertRaises(ValueError):
                focus.collect_admissions(folder, altered, head, invocation)


if __name__ == "__main__":
    unittest.main(verbosity=2)
