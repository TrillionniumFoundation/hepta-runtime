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
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_rust_pipeline as p
import hia_native_pipeline as native
import qualify_hia_runtime_native as q
import compare_hia_runtime_rust as r


class OriginalPipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hia-original-reporting-")
        cls.root = Path(cls.temporary.name)
        cls.source = cls.root / "source"; cls.source.mkdir()
        cls.compiler = cls.root / "compiler"; cls.compiler.mkdir()
        cls.output = cls.root / "output"; cls.output.mkdir()
        cls.shards = cls.root / "shards"; cls.shards.mkdir()
        cls.invocation = "actual-python-reporting-fixtures-only"
        cls.source_file = cls.source / "owner.py"
        cls.source_file.write_text("print('actual fixture, no Rust or HIA')\n")
        cls.source_map = {"owner.py": native.digest(cls.source_file)}
        cls.recipe = cls.source / "recipe.py"
        cls.recipe.write_text("import json,sys\nprint(json.dumps({'fixture_recipe':sys.argv[1]}))\n")
        cls.version = cls.source / "compiler-version-fixture"
        cls.version.write_text("#!" + sys.executable + "\nprint('rustc reporting fixture\\nrelease: 1.95.0\\n"
            "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860')\n")
        cls.version.chmod(0o700)
        cls.patches = [patch.object(q, "ROOT", cls.source), patch.object(q, "sources", return_value=cls.source_map),
                      patch.object(q, "git_head", return_value="reporting-fixture"),
                      patch.object(r, "check_input_pins"),
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
                return {"status": "PASS", "actual_python_process_fixture_only": True, "key": key}
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
        shutil.rmtree(self.output); shutil.copytree(self.native_copy, self.output)
        shutil.rmtree(self.shards); shutil.copytree(self.shards_copy, self.shards)
        self.expected = dict(type(self).expected)

    def control(self, name):
        def run(output, report):
            q.record_check(output, report, name=name,
                command=[sys.executable, "-I", str(self.recipe), name], timeout=180)
            report[name.replace("-", "_")] = {"actual_python_process_fixture_only": True}
        return run

    def collect(self):
        with patch.object(r, "run_result_values_controls", self.control(p.CONTROLS[0])), \
             patch.object(r, "run_public_registry_controls", self.control(p.CONTROLS[1])):
            return p.collect(self.output, self.compiler, self.native_sha, self.invocation, self.shards, self.expected)

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
        self.assertEqual(len(flat), 41)
        self.assertEqual(set(flat), set(r.RECIPES))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(p.GROUPS["config"], ("runtime_config",))
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
        self.assertEqual([row["name"] for row in report["checks"]][-2:], list(p.CONTROLS))
        p.verify_collected_receipts(self.output, report)

    def test_missing_group_cannot_become_complete(self):
        shutil.rmtree(self.shards / "config")
        with self.assertRaisesRegex(ValueError, "exactly seven"):
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
