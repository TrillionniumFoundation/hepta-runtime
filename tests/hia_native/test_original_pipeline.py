# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual small-process controls for original-recipe partition admission.

The temporary Python programs are explicitly process-reporting fixtures. They
do not compile Rust, execute HIA, or qualify any production semantic component.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_rust_pipeline as p
import hia_native_artifact_bundle as bundle_transport
import hia_native_pipeline as native
import qualify_hia_runtime_native as q
import compare_hia_runtime_rust as r

REAL_GIT_HEAD = q.git_head


class OriginalPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-original-reporting-")
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "source"; cls.source.mkdir()
        cls.compiler = cls.root / "compiler"; cls.compiler.mkdir()
        cls.output = cls.root / "output"; cls.output.mkdir()
        cls.shards = cls.root / "shards"; cls.shards.mkdir()
        cls.invocation = "12345-1"
        cls.source_file = cls.source / "owner.py"
        cls.source_file.write_text("print('actual fixture, no Rust or HIA')\n")
        cls.source_map = {"owner.py": native.digest(cls.source_file)}
        cls.recipe = cls.source / "recipe.py"
        cls.recipe.write_text("import json,sys\nprint(json.dumps({'fixture_recipe':sys.argv[1]}))\n")
        cls.version = cls.source / "compiler-version-fixture"
        cls.version.write_text("#!" + sys.executable + "\nprint('rustc reporting fixture\\nrelease: 1.95.0\\n"
            "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860')\n")
        cls.version.chmod(0o700)
        cls.json_build = {"schema": "hepta.runtime.json-reference-build.v1",
                          "actual_python_process_fixture_only": True,
                          "fixture_identity": "one shared build, two separately completed replays"}
        def fixture_admission(output, report):
            # Semantic owners are explicit fixtures here. Keep the real current
            # workflow receipt join exercised when the collector delegates it.
            if "original_qualification_pipeline" in report:
                p.verify_collected_receipts(output, report)
        cls.patches = [patch.object(q, "ROOT", cls.source), patch.object(q, "sources", return_value=cls.source_map),
                      patch.object(q, "git_head", autospec=True, return_value="a" * 40),
                      patch.object(r, "check_input_pins", side_effect=fixture_admission),
                      patch.object(r.service_pipeline, "original_fixture_transport", return_value={"fixture_only": True})]
        for item in cls.patches:
            item.start()
        baseline = {"schema": "hepta.runtime.hia-native-qualification.v1", "checks": [],
            "status": "RUNNING", "phase": "native_components", "native_components_status": "RUNNING",
            "rust_comparison_status": "PENDING", "source_sha256": cls.source_map,
            "compiler_checkout": str(cls.compiler), "modules": {item["key"]: {} for item in q.MODULES},
            "production_activated": False, "whole_runtime_replaced": False, "old_stack_removal_qualified": False}
        q.record_check(cls.output, baseline, name="actual-native-reporting-fixture",
                       command=[sys.executable, "-I", str(cls.recipe), "native-fixture"], timeout=180)
        baseline.update(status="NATIVE_COMPONENTS_PASS", phase="awaiting_original_rust_comparison",
                        native_components_status="PASS")
        (cls.output / "immutable-native.bin").write_bytes(b"unchanged native reporting fixture")
        q.save_report(cls.output / "result.json", baseline)
        cls.native_sha = p.prepare(cls.output, cls.compiler, cls.invocation)["native_sha256"]
        cls.baseline = copy.deepcopy(baseline)
        cls.native_copy = cls.root / "native-copy"
        shutil.copytree(cls.output, cls.native_copy)

        def fixture(key):
            def run(output, report, rustc, *, report_path=None):
                names = (r.PARALLEL_RUST_RECIPES[key][1] if key in r.PARALLEL_RUST_RECIPES
                         else ("fixture-original-" + key,))
                for name in names:
                    q.record_check(output, report, name=name,
                        command=[sys.executable, "-I", str(cls.recipe), key], timeout=180, report_path=report_path)
                (output / ("fixture-original-" + key + ".bin")).write_bytes(key.encode())
                result = {"status": "PASS", "actual_python_process_fixture_only": True, "key": key}
                if key in ("fence_json", "serde_json"):
                    report.setdefault("json_reference_build", copy.deepcopy(cls.json_build))
                    result["reference_build"] = copy.deepcopy(report["json_reference_build"])
                return result
            return run

        cls.expected = {}
        with patch.object(r, "RECIPES", {key: fixture(key) for key in r.RECIPES}):
            for group in p.groups():
                shutil.rmtree(cls.output); shutil.copytree(cls.native_copy, cls.output)
                result = p.shard(cls.output, cls.compiler, cls.native_sha, cls.invocation, group,
                                 cls.shards / group, str(cls.version))
                cls.expected[group] = result["sha256"]
        cls.shards_copy = cls.root / "shards-copy"
        shutil.copytree(cls.shards, cls.shards_copy)

    @classmethod
    def tearDownClass(cls):
        for item in reversed(cls.patches):
            item.stop()
        cls.temporary.cleanup()

    def setUp(self):
        if self.output.exists():
            shutil.rmtree(self.output)
        shutil.copytree(self.native_copy, self.output)
        shutil.rmtree(self.shards); shutil.copytree(self.shards_copy, self.shards)
        self.expected = dict(type(self).expected)
        for name in ("stage-bundle", "stage-artifacts", "controls-bundle"):
            path = self.root / name
            if path.exists():
                shutil.rmtree(path)

    def control(self, name):
        def run(output, report):
            q.record_check(output, report, name=name,
                command=[sys.executable, "-I", str(self.recipe), name], timeout=180)
            report[name.replace("-", "_")] = {"actual_python_process_fixture_only": True}
        return run

    def collect(self, **kwargs):
        with patch.object(r, "run_result_values_controls", self.control(p.CONTROLS[0])), \
             patch.object(r, "run_public_registry_controls", self.control(p.CONTROLS[1])), \
             patch.object(r, "run_result_storage_controls", self.control(p.CONTROLS[2])), \
             patch.object(r, "run_audit_readiness_controls", self.control(p.CONTROLS[3])), \
             patch.object(r, "run_audit_activity_controls", self.control(p.CONTROLS[4])), \
             patch.object(r, "run_audit_stamp_controls", self.control(p.CONTROLS[5])):
            return p.collect(self.output, self.compiler, self.native_sha, self.invocation,
                             self.shards, self.expected, **kwargs)

    def prepare_collection(self):
        result = self.collect(stage_only=True)
        self.assertEqual(result["status"], p.COLLECTED_STATUS)
        pending = native.read_json(self.output / "result.json")
        self.assertEqual(pending["rust_comparison_status"], "PARTIAL")
        self.assertFalse(set(p.CONTROLS) & {row["name"] for row in pending["checks"]})
        artifact_root, bundle = self.root / "stage-artifacts", self.root / "stage-bundle"
        artifact_root.mkdir()
        name = bundle_transport.source_name("a" * 40, self.invocation, "native")
        shutil.copytree(self.native_copy, artifact_root / name)
        for group in p.groups():
            name = bundle_transport.source_name("a" * 40, self.invocation, group)
            shutil.copytree(self.shards / group, artifact_root / name)
        exported = bundle_transport.export(self.output, bundle, "a" * 40, self.invocation,
            self.native_sha, self.expected, collection=True)
        self.assertEqual(exported["status"], "COLLECTION_BUNDLE_EXPORTED")
        self.assertEqual(exported["semantic_checks_executed"], 0)
        shutil.rmtree(self.output)
        return bundle, exported["sha256"], artifact_root

    def complete(self, args, **kwargs):
        with patch.object(r, "run_result_values_controls", self.control(p.CONTROLS[0])), \
             patch.object(r, "run_public_registry_controls", self.control(p.CONTROLS[1])), \
             patch.object(r, "run_result_storage_controls", self.control(p.CONTROLS[2])), \
             patch.object(r, "run_audit_readiness_controls", self.control(p.CONTROLS[3])), \
             patch.object(r, "run_audit_activity_controls", self.control(p.CONTROLS[4])), \
             patch.object(r, "run_audit_stamp_controls", self.control(p.CONTROLS[5])):
            return p.complete_collection(self.output, self.compiler, self.native_sha,
                kwargs.get("invocation", self.invocation), kwargs.get("expected", self.expected), *args,
                controls_only=kwargs.get("controls_only", False))

    def prepare_controls(self):
        args = self.prepare_collection()
        with patch.object(r, "check_input_pins", side_effect=AssertionError("premature final admission")):
            self.assertEqual(self.complete(args, controls_only=True)["status"], p.CONTROLLED_STATUS)
        report = native.read_json(self.output / "result.json")
        self.assertEqual((report["status"], report["phase"], report["rust_comparison_status"]),
                         (p.CONTROLLED_STATUS, p.CONTROLLED_PHASE, "PARTIAL"))
        self.assertEqual([row["name"] for row in report["checks"]][-len(p.CONTROLS):], list(p.CONTROLS))
        bundle = self.root / "controls-bundle"
        result = bundle_transport.export(self.output, bundle, "a" * 40, self.invocation,
            self.native_sha, self.expected, controls=True)
        self.assertEqual(result["status"], "CONTROLS_BUNDLE_EXPORTED")
        shutil.rmtree(self.output)
        return bundle, result["sha256"], args[2]

    def finalize(self, args, **kwargs):
        return p.finalize_collection(self.output, self.compiler, self.native_sha,
            kwargs.get("invocation", self.invocation), kwargs.get("expected", self.expected), *args)

    def rehash_report(self, bundle, mutation):
        path = bundle / "data/result.json"
        report = native.read_json(path); mutation(report); q.save_report(path, report)
        manifest_path = bundle / bundle_transport.MANIFEST
        manifest = native.read_json(manifest_path)
        old = manifest["files"]["result.json"]["bytes"]
        manifest["files"]["result.json"].update(native.file_identity(path))
        manifest["full_evidence_bytes"] += path.stat().st_size - old
        q.save_report(manifest_path, manifest)
        return native.digest(manifest_path)

    def change_report(self, group, mutation, *, update_workflow=False):
        folder = self.shards / group
        part = native.read_json(folder / p.SHARD_REPORT)
        mutation(part)
        q.save_report(folder / p.SHARD_REPORT, part)
        seal = native.read_json(folder / p.SHARD_SEAL)
        seal["report_sha256"] = native.digest(folder / p.SHARD_REPORT)
        q.save_report(folder / p.SHARD_SEAL, seal)
        if update_workflow:
            self.expected[group] = native.digest(folder / p.SHARD_SEAL)

    def test_registry_covers_every_recipe_once_and_keeps_shared_builds_together(self):
        flat = [key for keys in p.groups().values() for key in keys]
        self.assertEqual(len(flat), 65)
        self.assertEqual(p.GROUPS["public"], ("public_lifecycle",))
        self.assertEqual(set(flat), set(r.RECIPES))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(p.GROUPS["config"], ("runtime_config",))
        self.assertEqual(p.GROUPS["storage_types"], ("request_storage_json", "request_record_validation",
                                                   "request_safe_dto", "request_retention"))
        self.assertEqual(p.GROUPS["storage_files"], ("request_record_io", "request_store_directory",
                                                   "request_archive_metadata", "request_archive_publish",
                                                   "request_archive_store"))
        self.assertEqual(p.GROUPS["storage_types"] + p.GROUPS["storage_files"], tuple(r.storage_pipeline.KEYS))
        self.assertEqual(p.GROUPS["audit"], tuple(r.stamp_pipeline.KEYS) + tuple(r.audit_pipeline.KEYS) + tuple(r.activity_pipeline.KEYS))
        self.assertTrue(set(r.result_qualification.KEYS) <= set(p.GROUPS["json"]))
        self.assertTrue(set(r.PARALLEL_RUST_RECIPES) <= set(p.GROUPS["system"]))
        self.assertTrue({"write_chain", "workdir_service"} <= set(p.GROUPS["services"]))

    def test_workflow_keeps_independent_hash_outputs_and_original_job_deadlines(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        reusable = (ROOT / ".github/workflows/hia-runtime-original-shard.yml").read_text()
        for group in p.GROUPS:
            section = workflow.split("\n  original_" + group + ":\n", 1)[1]
            section = re.split(r"\n  [a-z_]+:\n", section, maxsplit=1)[0]
            self.assertIn("uses: ./.github/workflows/hia-runtime-original-shard.yml", section)
            self.assertIn("needs: native_collect", section)
            self.assertIn("group: " + group, section)
            self.assertIn('--shard-sha256 "' + group + '=${{ needs.original_' + group + '.outputs.sha256 }}"', workflow)
        self.assertEqual(set(re.findall(r"timeout-minutes: (\d+)", workflow + reusable)), {"15"})
        self.assertIn("value: ${{ jobs.original.outputs.sha256 }}", reusable)
        self.assertIn("sha256: ${{ steps.shard.outputs.sha256 }}", reusable)
        self.assertIn('timeout --signal=KILL 180 python3', workflow)
        self.assertNotIn("Compare all declared original owners", workflow)
        self.assertNotIn("Retain original failure bytes and prepared artifacts", workflow)
        self.assertIn("Retain immutable original failure diagnostics\n        if:", reusable)

    def test_collection_and_completion_jobs_keep_independent_external_seals_and_limits(self):
        text = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        stage = text.split("\n  original_collect:\n", 1)[1].split("\n  original_controls:\n", 1)[0]
        controls = text.split("\n  original_controls:\n", 1)[1].split("\n  qualify:\n", 1)[0]
        final = text.split("\n  qualify:\n", 1)[1]
        self.assertIn("hia_native_rust_pipeline.py collect --stage-only", stage)
        self.assertIn("hia_native_artifact_bundle.py export-collection", stage)
        self.assertIn("collection_sha256: ${{ steps.bundle.outputs.sha256 }}", stage)
        self.assertNotIn("id: regex", stage)
        self.assertIn("original_collect]", controls)
        self.assertIn("hia_native_rust_pipeline.py complete --controls-only", controls)
        self.assertIn('--collection-sha256 "${{ needs.original_collect.outputs.collection_sha256 }}"', controls)
        self.assertIn("hia_native_artifact_bundle.py export-controls", controls)
        self.assertIn("controls_sha256: ${{ steps.bundle.outputs.sha256 }}", controls)
        self.assertNotIn("id: regex", controls)
        self.assertNotIn("hia_native_rust_pipeline.py finalize", controls)
        self.assertIn("original_collect, original_controls]", final)
        self.assertIn("hia_native_rust_pipeline.py finalize", final)
        self.assertNotIn("hia_native_rust_pipeline.py complete", final)
        self.assertIn('--controls-sha256 "${{ needs.original_controls.outputs.controls_sha256 }}"', final)
        self.assertIn('--source-artifacts "$RUNNER_TEMP/hia-retained-inputs"', final)
        self.assertIn('name: hia-original-controls-${{ github.event.pull_request.head.sha || github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}', final)
        for section in (stage, controls, final):
            self.assertIn("timeout-minutes: 15", section)
            for group in p.groups():
                self.assertIn('--shard-sha256 "' + group + '=${{ needs.original_' + group + '.outputs.sha256 }}"', section)

    def test_control_stage_is_nonpass_and_final_job_rechecks_without_executing_controls(self):
        args = self.prepare_controls()
        retained = native.read_json(args[0] / "data/result.json")
        observed = []
        def admit(output, report):
            observed.append(report["status"])
            self.assertEqual(native.read_json(output / "result.json")["status"], "RUNNING")
            self.assertEqual(report["checks"], retained["checks"])
            self.assertEqual(set(report["original_rust_comparisons"]), set(r.RECIPES))
            p.verify_collected_receipts(output, report)
        with patch.object(r, "check_input_pins", side_effect=admit), \
             patch.object(p, "finish_collection", side_effect=AssertionError("controls reexecuted")):
            self.assertEqual(self.finalize(args)["status"], "PASS")
        self.assertEqual(observed, ["PASS"])
        report = native.read_json(self.output / "result.json")
        self.assertEqual(report["checks"], retained["checks"])
        self.assertAlmostEqual(report["original_collection_elapsed_seconds"],
            report["original_collection_assembly_elapsed_seconds"] +
            report["original_collection_controls_elapsed_seconds"] +
            report["original_collection_final_admission_elapsed_seconds"])

    def test_finalizer_requires_control_job_digest_and_exact_original_workflow_sources(self):
        bundle, digest, artifacts = self.prepare_controls()
        with self.assertRaisesRegex(ValueError, "successful workflow job SHA256"):
            self.finalize((bundle, "f" * 64, artifacts))
        with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
            self.finalize((bundle, digest, artifacts), invocation="12345-2")
        with patch.object(q, "git_head", new=lambda: "b" * 40):
            with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
                self.finalize((bundle, digest, artifacts))
        changed = dict(self.expected); changed["audit"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
            self.finalize((bundle, digest, artifacts), expected=changed)
        self.assertFalse(self.output.exists())

    def test_finalizer_rejects_uncontrolled_collection_and_changes_before_output_creation(self):
        bundle, digest, artifacts = self.prepare_controls()
        stage = self.root / "stage-bundle"
        with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
            self.finalize((stage, native.digest(stage / bundle_transport.MANIFEST), artifacts))
        native_name = bundle_transport.source_name("a" * 40, self.invocation, "native")
        for path in (artifacts / native_name / "immutable-native.bin",
                     bundle / ("data/" + p.CONTROLS[-1] + ".stdout")):
            raw = path.read_bytes(); path.write_bytes(raw + b"changed after controlled job")
            try:
                with self.assertRaises(ValueError): self.finalize((bundle, digest, artifacts))
                self.assertFalse(self.output.exists())
            finally:
                path.write_bytes(raw)

    def test_rehashed_control_report_cannot_omit_reorder_duplicate_or_forge_completions(self):
        bundle, _, artifacts = self.prepare_controls()
        original = (bundle / "data/result.json").read_bytes()
        manifest = (bundle / bundle_transport.MANIFEST).read_bytes()
        changes = {
            "omitted": lambda x: x["checks"].pop(),
            "duplicate": lambda x: x["checks"].append(copy.deepcopy(x["checks"][-1])),
            "reordered": lambda x: x["checks"].__setitem__(slice(-2, None), x["checks"][-2:][::-1]),
            "failed": lambda x: x["checks"][-1].__setitem__("exit_code", 7),
            "timed_out": lambda x: x["checks"][-1].__setitem__("timed_out", True),
            "deadline": lambda x: x["checks"][-1].__setitem__("timeout_seconds", 179),
            "missing_result": lambda x: x.pop(p.CONTROLS[-1].replace("-", "_")),
            "premature_pass": lambda x: x.__setitem__("status", "PASS"),
            "nonfinite_elapsed": lambda x: x.__setitem__("original_collection_controls_elapsed_seconds", float("inf")),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                (bundle / "data/result.json").write_bytes(original)
                (bundle / bundle_transport.MANIFEST).write_bytes(manifest)
                digest = self.rehash_report(bundle, change)
                with self.assertRaises(ValueError): self.finalize((bundle, digest, artifacts))
                if name == "premature_pass":
                    self.assertFalse(self.output.exists())
                else:
                    failure = native.read_json(self.output / "result.json")
                    self.assertEqual((failure["status"], failure["phase"]), ("FAIL", "original_finalize"))
                    shutil.rmtree(self.output)

    def test_rehashed_control_report_still_requires_original_receipts_and_current_sources(self):
        bundle, _, artifacts = self.prepare_controls()
        digest = self.rehash_report(bundle, lambda x: x["original_rust_comparisons"].pop("delta"))
        with self.assertRaisesRegex(ValueError, "differs from all actual original"):
            self.finalize((bundle, digest, artifacts))
        self.assertEqual(native.read_json(self.output / "result.json")["status"], "FAIL")

    def test_control_job_failure_cannot_be_exported_as_a_completed_control_stage(self):
        args = self.prepare_collection()
        real = self.control
        def control(name):
            if name != p.CONTROLS[-1]: return real(name)
            def failed(output, report):
                q.record_check(output, report, name=name,
                    command=[sys.executable, "-I", "-c", "raise SystemExit(7)"], timeout=180)
            return failed
        with patch.object(self, "control", side_effect=control):
            with self.assertRaisesRegex(RuntimeError, "failed; original stdout/stderr retained"):
                self.complete(args, controls_only=True)
        report = native.read_json(self.output / "result.json")
        self.assertEqual((report["status"], report["phase"]), ("FAIL", "original_complete"))
        self.assertEqual(report["checks"][-1]["exit_code"], 7)
        with self.assertRaises(ValueError):
            bundle_transport.export(self.output, self.root / "controls-bundle", "a" * 40,
                self.invocation, self.native_sha, self.expected, controls=True)

    def test_final_semantic_refusal_after_control_job_never_writes_pass(self):
        args = self.prepare_controls()
        with patch.object(r, "check_input_pins", side_effect=ValueError("final source/corpus refusal")):
            with self.assertRaisesRegex(ValueError, "final source/corpus refusal"):
                self.finalize(args)
        report = native.read_json(self.output / "result.json")
        self.assertEqual((report["status"], report["phase"]), ("FAIL", "original_finalize"))

    def test_staged_actual_process_merge_completes_every_control_before_one_final_admission(self):
        args = self.prepare_collection()
        observed = []
        def admit(output, report):
            observed.append(report["status"])
            self.assertNotEqual(native.read_json(output / "result.json")["status"], "PASS")
            self.assertEqual([row["name"] for row in report["checks"]][-len(p.CONTROLS):], list(p.CONTROLS))
            p.verify_collected_receipts(output, report)
        with patch.object(r, "check_input_pins", side_effect=admit):
            self.assertEqual(self.complete(args)["status"], "PASS")
        self.assertEqual(observed, ["PASS"])
        report = native.read_json(self.output / "result.json")
        self.assertEqual(set(report["original_rust_comparisons"]), set(r.RECIPES))
        self.assertGreater(report["original_collection_elapsed_seconds"],
                           report["original_collection_completion_elapsed_seconds"])

    def test_staged_completion_uses_real_zero_argument_checkout_head_api(self):
        args = self.prepare_collection()
        git_directory = self.source / ".git"
        self.assertFalse(git_directory.exists())
        # This is only Git metadata for the explicit process-reporting fixture.
        # No source is staged and no local commit is created.
        subprocess.run(["git", "init", "--quiet", str(self.source)], check=True)
        try:
            (git_directory / "HEAD").write_text("a" * 40 + "\n")
            with patch.object(q, "git_head", REAL_GIT_HEAD):
                self.assertEqual(q.git_head(), "a" * 40)
                self.assertEqual(self.complete(args)["status"], "PASS")
        finally:
            shutil.rmtree(git_directory)

    def test_staged_completion_requires_workflow_digest_and_same_head_invocation_and_sources(self):
        bundle, digest, artifacts = self.prepare_collection()
        with self.assertRaisesRegex(ValueError, "successful workflow job SHA256"):
            self.complete((bundle, "f" * 64, artifacts))
        with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
            self.complete((bundle, digest, artifacts), invocation="12345-2")
        with patch.object(q, "git_head", new=lambda: "b" * 40):
            with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
                self.complete((bundle, digest, artifacts))
        changed = dict(self.expected); changed["audit"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "another head, invocation or source seal"):
            self.complete((bundle, digest, artifacts), expected=changed)
        self.assertFalse(self.output.exists())

    def test_staged_completion_refuses_changed_retained_bytes_before_creating_output(self):
        bundle, digest, artifacts = self.prepare_collection()
        name = bundle_transport.source_name("a" * 40, self.invocation, "native")
        (artifacts / name / "immutable-native.bin").write_bytes(b"modified during transfer")
        with self.assertRaises(ValueError):
            self.complete((bundle, digest, artifacts))
        self.assertFalse(self.output.exists())

    def test_rehashed_stage_report_cannot_change_the_original_workflow_receipts(self):
        bundle, digest, artifacts = self.prepare_collection()
        path = bundle / "data/result.json"
        report = native.read_json(path)
        report["original_rust_comparisons"].pop("delta")
        q.save_report(path, report)
        manifest = native.read_json(bundle / bundle_transport.MANIFEST)
        old = manifest["files"]["result.json"]["bytes"]
        manifest["files"]["result.json"].update(native.file_identity(path))
        manifest["full_evidence_bytes"] += path.stat().st_size - old
        q.save_report(bundle / bundle_transport.MANIFEST, manifest)
        digest = native.digest(bundle / bundle_transport.MANIFEST)
        with self.assertRaisesRegex(ValueError, "differs from all actual original"):
            self.complete((bundle, digest, artifacts))
        self.assertEqual(native.read_json(self.output / "result.json")["status"], "FAIL")

    def test_staged_final_semantic_failure_cannot_leave_a_published_pass(self):
        args = self.prepare_collection()
        with patch.object(r, "check_input_pins", side_effect=ValueError("final staged admission refusal")):
            with self.assertRaisesRegex(ValueError, "final staged admission refusal"):
                self.complete(args)
        report = native.read_json(self.output / "result.json")
        self.assertEqual((report["status"], report["phase"]), ("FAIL", "original_complete"))

    def test_changed_native_bytes_during_staged_controls_are_refused(self):
        args = self.prepare_collection()
        original = self.control
        def control(name):
            run = original(name)
            def changed(output, report):
                run(output, report)
                if name == p.CONTROLS[-1]:
                    (output / "immutable-native.bin").write_bytes(b"changed after restored stage")
            return changed
        with patch.object(self, "control", side_effect=control):
            with self.assertRaises(ValueError):
                self.complete(args)
        self.assertEqual(native.read_json(self.output / "result.json")["status"], "FAIL")

    def test_storage_type_and_filesystem_recipe_swap_is_refused(self):
        changed = dict(p.GROUPS)
        left, right = list(changed["storage_types"]), list(changed["storage_files"])
        left[0], right[0] = right[0], left[0]
        changed.update(storage_types=tuple(left), storage_files=tuple(right))
        with patch.dict(p.GROUPS, changed, clear=True):
            with self.assertRaisesRegex(ValueError, "independent type and filesystem"):
                p.groups()

    def test_either_complete_storage_group_is_required_by_final_merge(self):
        for group in ("storage_types", "storage_files"):
            with self.subTest(group=group):
                expected = dict(self.expected)
                del expected[group]
                with self.assertRaises(ValueError):
                    p.collect(self.output, self.compiler, self.native_sha, self.invocation,
                              self.shards, expected)

    def test_unshared_group_executes_only_the_selected_actual_recipe(self):
        report = copy.deepcopy(self.baseline)
        report.update(phase="original_rust_comparison", original_rust_comparisons={})
        def selected(output, report, rustc):
            q.record_check(output, report, name="isolated-config-fixture",
                command=[sys.executable, "-I", str(self.recipe), "selected-config"], timeout=180)
            return {"fixture_only": True}
        def forbidden(*args, **kwargs):
            self.fail("unselected recipe executed")
        replacements = {key: (selected if key == "runtime_config" else forbidden) for key in r.RECIPES}
        with patch.object(r, "RECIPES", replacements):
            r.run_rust_recipes(self.output, report, self.version, recipe_keys=("runtime_config",))
            self.assertEqual(report["rust_recipe_processes"], {"runtime_config": ["isolated-config-fixture"]})
            self.assertEqual(report["rust_parallel_receipts"], {})
            with self.assertRaisesRegex(ValueError, "empty, duplicated or undeclared"):
                r.run_rust_recipes(self.output, report, self.version, recipe_keys=("runtime_config", "runtime_config"))

    def test_complete_actual_process_fixture_merge_retains_every_record(self):
        result = self.collect()
        self.assertEqual(result["status"], "PASS")
        report = native.read_json(self.output / "result.json")
        self.assertEqual(set(report["original_rust_comparisons"]), set(r.RECIPES))
        self.assertTrue(all(item["actual_python_process_fixture_only"]
                            for item in report["original_rust_comparisons"].values()))
        self.assertEqual([row["name"] for row in report["checks"]][-len(p.CONTROLS):], list(p.CONTROLS))
        self.assertEqual(report["json_reference_build"], self.json_build)
        p.verify_collected_receipts(self.output, report)

    def test_full_readmission_occurs_once_after_all_controls_before_publishing_pass(self):
        observed = []
        def admit(output, report):
            observed.append(report["status"])
            self.assertEqual(report["phase"], "complete")
            self.assertEqual([row["name"] for row in report["checks"]][-len(p.CONTROLS):], list(p.CONTROLS))
            self.assertNotEqual(native.read_json(output / "result.json")["status"], "PASS")
            p.verify_collected_receipts(output, report)
        with patch.object(r, "check_input_pins", side_effect=admit):
            self.assertEqual(self.collect()["status"], "PASS")
        self.assertEqual(observed, ["PASS"])

    def test_changed_native_bytes_during_controls_refuse_final_admission(self):
        original = self.control
        def control(name):
            run = original(name)
            def changed(output, report):
                run(output, report)
                if name == p.CONTROLS[-1]:
                    (output / "immutable-native.bin").write_bytes(b"damaged after current seal admission")
            return changed
        with patch.object(self, "control", side_effect=control):
            with self.assertRaises(ValueError):
                self.collect()
        self.assertEqual(native.read_json(self.output / "result.json")["status"], "FAIL")

    def test_final_semantic_refusal_cannot_leave_a_published_pass(self):
        def refuse(output, report):
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(len(report["checks"][-len(p.CONTROLS):]), len(p.CONTROLS))
            raise ValueError("explicit final semantic fixture refusal")
        with patch.object(r, "check_input_pins", side_effect=refuse):
            with self.assertRaisesRegex(ValueError, "final semantic fixture refusal"):
                self.collect()
        report = native.read_json(self.output / "result.json")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["phase"], "original_collect")

    def test_json_shared_build_is_required_even_with_a_rehashed_shard(self):
        self.change_report("json", lambda part: part.pop("json_reference_build"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.collect()

    def test_json_shared_build_cannot_differ_from_either_actual_replay(self):
        self.change_report("json", lambda part: part["json_reference_build"].update(
            fixture_identity="unexecuted replacement"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "shared Cargo build differs"):
            self.collect()

    def test_one_json_replay_cannot_claim_another_shared_build(self):
        self.change_report("json", lambda part: part["original_rust_comparisons"]["serde_json"][
            "reference_build"].update(fixture_identity="another build"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "shared Cargo build differs"):
            self.collect()

    def test_other_groups_and_unknown_json_fields_remain_rejected(self):
        self.change_report("bytes", lambda part: part.update(
            json_reference_build=copy.deepcopy(self.json_build)), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.collect()
        self.setUp()
        self.change_report("json", lambda part: part.update(unexecuted_extra_receipt={}), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.collect()

    def test_shared_build_is_still_bound_after_collection(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        report["json_reference_build"]["fixture_identity"] = "changed after collection"
        with self.assertRaisesRegex(ValueError, "differs from all actual"):
            p.verify_collected_receipts(self.output, report)
        report.pop("json_reference_build")
        with self.assertRaisesRegex(ValueError, "differs from all actual"):
            p.verify_collected_receipts(self.output, report)

    def test_missing_group_cannot_become_complete(self):
        shutil.rmtree(self.shards / "config")
        with self.assertRaisesRegex(ValueError, "every declared"):
            self.collect()

    def test_duplicate_group_cannot_replace_another_group(self):
        shutil.rmtree(self.shards / "config")
        shutil.copytree(self.shards / "bytes", self.shards / "duplicate")
        with self.assertRaisesRegex(ValueError, "duplicate or unknown"):
            self.collect()

    def test_missing_workflow_hash_is_not_a_self_attested_success(self):
        self.expected.pop("json")
        with self.assertRaisesRegex(ValueError, "every successful original workflow"):
            self.collect()

    def test_rehashed_command_change_does_not_change_workflow_digest(self):
        self.change_report("bytes", lambda part: part["checks"][-1]["command"].append("--unexecuted"))
        with self.assertRaisesRegex(ValueError, "successful workflow job SHA256"):
            self.collect()

    def test_rehashed_deadline_change_does_not_change_workflow_digest(self):
        self.change_report("bytes", lambda part: part["checks"][-1].update(timeout_seconds=181))
        with self.assertRaisesRegex(ValueError, "successful workflow job SHA256"):
            self.collect()

    def test_omitted_recipe_is_rejected_even_with_an_updated_group_seal(self):
        self.change_report("bytes", lambda part: part["original_rust_comparisons"].pop("delta"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.collect()

    def test_duplicate_process_attribution_is_rejected(self):
        self.change_report("bytes", lambda part: part["rust_recipe_processes"].update(
            delta=part["rust_recipe_processes"]["text_budget"]), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "omitted, duplicated"):
            self.collect()

    def test_failed_completed_process_is_rejected(self):
        self.change_report("bytes", lambda part: part["checks"][-1].update(exit_code=7), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "process is incomplete"):
            self.collect()

    def test_timed_out_process_is_rejected(self):
        self.change_report("bytes", lambda part: part["checks"][-1].update(timed_out=True), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "process is incomplete"):
            self.collect()

    def test_actual_stdout_bytes_cannot_be_replaced(self):
        path = self.shards / "bytes/data/fixture-original-runtime_bytes.stdout"
        path.write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
            self.collect()

    def test_retained_original_binary_bytes_are_bound(self):
        path = self.shards / "json/data/fixture-original-serde_json.bin"
        path.write_bytes(b"not the executed artifact")
        with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
            self.collect()

    def test_native_corpus_cannot_change_between_jobs(self):
        (self.output / "immutable-native.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
            self.collect()

    def test_native_source_map_cannot_change_between_jobs(self):
        with patch.object(q, "sources", return_value={"owner.py": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "complete, unchanged"):
                self.collect()

    def test_shard_cannot_replace_a_native_input(self):
        folder = self.shards / "bytes"
        path = folder / "data/immutable-native.bin"
        shutil.copyfile(self.output / "immutable-native.bin", path)
        seal = native.read_json(folder / p.SHARD_SEAL)
        seal["files"]["immutable-native.bin"] = native.file_identity(path)
        q.save_report(folder / p.SHARD_SEAL, seal)
        self.expected["bytes"] = native.digest(folder / p.SHARD_SEAL)
        with self.assertRaisesRegex(ValueError, "replace native evidence"):
            self.collect()

    def test_unexpected_file_and_symlink_are_not_admitted(self):
        folder = self.shards / "bytes/data"
        (folder / "undeclared").write_bytes(b"unadmitted")
        with self.assertRaisesRegex(ValueError, "extra or missing"):
            self.collect()
        shutil.rmtree(self.output); shutil.copytree(self.native_copy, self.output)
        (folder / "undeclared").unlink()
        (folder / "foreign").symlink_to(self.source)
        with self.assertRaisesRegex(ValueError, "directory is not owned"):
            self.collect()

    def test_collected_evidence_remains_bound_after_aggregate_success(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        (self.output / "fixture-original-runtime_bytes.bin").write_bytes(b"changed after collection")
        with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
            p.verify_collected_receipts(self.output, report)

    def test_control_omission_and_duplicate_after_collection_are_rejected(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        report["checks"].pop()
        with self.assertRaisesRegex(ValueError, "omitted quiescent"):
            p.verify_collected_receipts(self.output, report)
        report["checks"].append(copy.deepcopy(report["checks"][-1]))
        with self.assertRaisesRegex(ValueError, "differs from all actual"):
            p.verify_collected_receipts(self.output, report)


if __name__ == "__main__":
    unittest.main()
