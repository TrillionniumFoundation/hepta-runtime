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
import os
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
import hia_native_span_raw_value_qualification as span
import hia_native_runtime_mcp_original as original


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
        cls.version = cls.source / "rustc"
        cls.version.write_text("#!" + sys.executable + "\nimport sys\n"
            "print('rustc reporting fixture\\nrelease: 1.95.0\\n"
            "commit-hash: 59807616e1fa2540724bfbac14d7976d7e4a3860' if '--verbose' in sys.argv "
            "else 'rustc reporting fixture')\n")
        cls.version.chmod(0o700)
        cls.cargo = cls.source / "cargo"
        cls.cargo.write_text("#!" + sys.executable + "\nfrom pathlib import Path\nimport shutil,sys\n"
            "args=sys.argv[1:]\ntarget=Path(args[args.index('--target-dir')+1])/'release'\n"
            "target.mkdir(parents=True)\n"
            "name='hia-serde-json-reference' if target.parent.parent.name=='value' else 'hepta-workdir-original-oracle'\n"
            "shutil.copy2(" + repr(shutil.which("true")) + ",target/name)\n")
        cls.cargo.chmod(0o700)
        cls.span_sources = {"public_source_binding": {"actual_python_process_fixture_only": True}, "files": {}}
        for name in span.SOURCE_FILES:
            path = cls.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            raw = ("actual process-reporting fixture source: " + name + "\n").encode()
            path.write_bytes(raw)
            cls.span_sources["files"][name] = span.pin(raw)
            cls.source_map[name] = native.digest(path)
        cls.json_build = {"schema": "hepta.runtime.json-reference-build.v1",
                          "actual_python_process_fixture_only": True,
                          "fixture_identity": "one shared build, two separately completed replays"}
        cls.shared_rereads = {}
        cls.patches = [patch.object(q, "ROOT", cls.source), patch.object(q, "sources", return_value=cls.source_map),
                      patch.object(q, "git_head", return_value="reporting-fixture"),
                      patch.object(r, "check_input_pins"),
                      patch.object(original, "RUSTC_SHA", native.digest(cls.version)),
                      patch.object(original, "CARGO_SHA", native.digest(cls.cargo)),
                      patch.object(original, "RUST_VERSION", b"rustc reporting fixture\n"),
                      patch.object(span, "LEAF_CASES", 1), patch.object(span, "SDK_CASES", 1),
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
        span_folder = cls.output / span.FOLDER; span_folder.mkdir()
        for name, raw in (("requests.hex", b"fixture Value input\n"),
                          ("sdk-requests.hex", b"fixture SDK input\n"), ("native-output.txt", b"")):
            (span_folder / name).write_bytes(raw)
        baseline["runtime_mcp_evidence"] = {"span_raw_value": {
            "source_inputs": cls.span_sources, "actual_python_process_fixture_only": True,
            "artifact_sha256": {str(path.relative_to(cls.output)): native.digest(path)
                                for path in span_folder.iterdir()}}}
        q.save_report(cls.output / "result.json", baseline)
        cls.native_sha = p.prepare(cls.output, cls.compiler, cls.invocation)["native_sha256"]
        cls.baseline = copy.deepcopy(baseline)
        cls.native_copy = cls.root / "native-copy"
        shutil.copytree(cls.output, cls.native_copy)

        def fixture(key):
            def run(output, report, rustc, *, report_path=None):
                owner = r.SHARED_RUST_PROCESS_RECIPES.get(key)
                if owner is not None:
                    # These are genuine re-reads of the producer's actual Python
                    # process bytes. The fixture does not invent another launch.
                    for name in report["rust_recipe_processes"][owner]:
                        rows = [row for row in report["checks"] if row["name"] == name]
                        if len(rows) != 1:
                            raise ValueError("fixture shared owner process is absent or duplicated")
                        p.validate_process(output, rows[0], owner)
                        if native.read_json(output / (name + ".stdout"))["fixture_recipe"] != owner:
                            raise ValueError("fixture shared owner original bytes changed")
                    cls.shared_rereads[key] = cls.shared_rereads.get(key, 0) + 1
                    if key.startswith("view_"):
                        return copy.deepcopy(report["original_rust_comparisons"][owner])
                    result = {"status": "PASS", "actual_python_process_fixture_only": True, "key": key}
                    bundle = report["request_context_reference"]
                    result.update(comparison=bundle["result"]["native_response_to_original"],
                        shared_fresh_reference=p.context_reference.FOLDER + "/RESULT.json",
                        shared_fresh_reference_sha256=bundle["artifact_sha256"][p.context_reference.FOLDER + "/RESULT.json"])
                    return result
                names = (r.PARALLEL_RUST_RECIPES[key][1] if key in r.PARALLEL_RUST_RECIPES
                         else ("fixture-original-" + key,))
                for reference, component in ((p.context_reference, "request_context"),
                                             (p.publication_reference, "result_publication"),
                                             (p.scope_reference, "request_scope_lifecycle")):
                    if key == component:
                        names = reference.CHECKS
                if key == "local_create_file":
                    names = r.local_create_qualification.PROCESS_NAMES
                if key == "local_create_spec":
                    names = r.local_create_spec_qualification.PROCESS_NAMES
                if key == "view_read":
                    names = (*names, *r.VIEW_SEARCH_ORIGINAL_CHECKS, *r.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS)
                deadlines = {name: timeout for name, (component, timeout) in r.RUST_PROCESS_DEADLINES.items()
                             if component == key}
                names = (*deadlines, *names)
                for name in names:
                    q.record_check(output, report, name=name,
                        command=[sys.executable, "-I", str(cls.recipe), key],
                        timeout=deadlines.get(name, 180), report_path=report_path)
                (output / ("fixture-original-" + key + ".bin")).write_bytes(key.encode())
                result = {"status": "PASS", "actual_python_process_fixture_only": True, "key": key}
                if key in ("fence_json", "serde_json"):
                    report.setdefault("json_reference_build", copy.deepcopy(cls.json_build))
                    result["reference_build"] = copy.deepcopy(report["json_reference_build"])
                if key in ("request_context", "result_publication", "request_scope_lifecycle"):
                    reference, field, schema = {
                        "request_context": (p.context_reference, "request_context_reference", "request-context"),
                        "result_publication": (p.publication_reference, "result_publication_reference", "result-publication"),
                        "request_scope_lifecycle": (p.scope_reference, "request_scope_reference", "request-scope"),
                    }[key]
                    observation = {"actual_python_process_fixture_only": True}
                    if key == "request_context":
                        observation.update(native_context_to_original={"fixture_domain": "context"},
                                           native_response_to_original={"fixture_domain": "response"})
                    elif key == "result_publication":
                        observation.update(output_comparison={"actual_python_process_fixture_only": True},
                                           publisher_output_comparison={"actual_python_process_fixture_only": True})
                    else:
                        observation.update(comparison={"actual_python_process_fixture_only": True},
                                           counts={"actual_python_process_fixture_only": True})
                    relative = reference.FOLDER + "/RESULT.json"
                    (output / relative).parent.mkdir()
                    q.save_report(output / relative, observation)
                    bundle = {"schema": "hepta.runtime." + schema + "-reference.v1", "result": observation,
                              "artifact_sha256": {relative: native.digest(output / relative)}}
                    report[field] = bundle
                    if key == "request_context":
                        result.update(comparison=observation["native_context_to_original"],
                            shared_fresh_reference=relative, shared_fresh_reference_sha256=bundle["artifact_sha256"][relative])
                    else:
                        result = reference.comparison_receipt(bundle)
                if key == "view_read":
                    for stem, checks in (("view_search", r.VIEW_SEARCH_ORIGINAL_CHECKS),
                                         ("view_regex_search", r.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS)):
                        slug = stem.replace("_", "-")
                        folder = slug + "-original"
                        (output / folder).mkdir()
                        pins = {"immutable-native.bin": native.digest(output / "immutable-native.bin")}
                        for name in ("result.json", "process-receipts.json", "input.bin", "original.stdout"):
                            relative = folder + "/" + name
                            q.save_report(output / relative, {"actual_python_process_fixture_only": True,
                                                            "artifact": relative})
                            pins[relative] = native.digest(output / relative)
                        report[stem + "_original_comparison"] = {
                            "schema": "hepta.runtime." + slug + "-original-comparison.v1", "status": "PASS",
                            "actual_python_process_fixture_only": True, "original_output": folder,
                            "required_original_checks": list(checks), "artifact_sha256": pins}
                    for relative in p.public_fixtures.VIEW_ORIGINAL:
                        tree = output / relative
                        tree.mkdir(parents=True)
                        payload = tree / "complete.bin"
                        payload.write_bytes(b"complete original reporting fixture\0\xff")
                        payload.chmod(0o640)
                        os.link(payload, tree / "same-inode.bin")
                        (tree / "dangling").symlink_to("missing")
                if key == "runtime_mcp":
                    for stem in ("view_search", "view_regex_search"):
                        report[stem + "_public_original_comparison"] = {
                            "schema": "hepta.runtime." + stem.replace("_", "-") + "-public-original-comparison.v1",
                            "status": "PASS", "actual_python_process_fixture_only": True,
                            "artifact_sha256": copy.deepcopy(report[stem + "_original_comparison"]["artifact_sha256"])}
                    result["span_raw_value"] = cls.span_fixture(output, report, rustc)
                    for relative in p.public_fixtures.ORIGINAL:
                        tree = output / relative
                        tree.mkdir(parents=True)
                        payload = tree / "complete.bin"
                        payload.write_bytes(b"complete public original reporting fixture\0\xff")
                        payload.chmod(0o640)
                        os.link(payload, tree / "same-inode.bin")
                        (tree / "dangling").symlink_to("missing")
                        os.mkfifo(tree / "owned-fifo", 0o600)
                    workdir = {"actual_python_process_fixture_only": True}
                    retirement = p.public_fixtures.retired(output, "original",
                        dict(public=copy.deepcopy(result), workdir=workdir), str(output), create=True)
                    report["runtime_mcp_original_fixture_retirement"] = copy.deepcopy(retirement)
                    result["pipeline"] = {"native_fixture_retirement": {
                        "execution_output_root": str(output)}, "shared_workdir": workdir,
                        "original_fixture_retirement": copy.deepcopy(retirement)}
                    result["artifact_sha256"] = copy.deepcopy(retirement["artifact_sha256"])
                return result
            return run

        cls.fixture_recipes = {key: fixture(key) for key in r.RECIPES}
        cls.expected = {}
        with patch.object(r, "RECIPES", cls.fixture_recipes):
            for group in p.groups():
                shutil.rmtree(cls.output); shutil.copytree(cls.native_copy, cls.output)
                result = p.shard(cls.output, cls.compiler, cls.native_sha, cls.invocation, group,
                                 cls.shards / group, str(cls.version))
                cls.expected[group] = result["sha256"]
        cls.shards_copy = cls.root / "shards-copy"
        shutil.copytree(cls.shards, cls.shards_copy)

    @classmethod
    def span_fixture(cls, output, report, rustc):
        """Two Python materializers and true(1) replays exercise receipt custody."""
        state = {"schema": "hepta.runtime.span-raw-value.reference-builds.v1",
            "source_inputs": copy.deepcopy(cls.span_sources),
            "native_evidence_sha256": span.sha(span.compact(report["runtime_mcp_evidence"]["span_raw_value"])),
            "cleared_environment": list(original.CLEARED), "removed_environment": [],
            "rustc": {"invocation": str(rustc), "sha256": native.digest(rustc)},
            "cargo": {"invocation": str(cls.cargo), "sha256": native.digest(cls.cargo)},
            "execution": {"runtime_root": str(cls.source), "output_root": str(output)}, "builds": {}}
        names = ["span-raw-value-rustc-version"]
        q.record_check(output, report, name=names[0], command=[str(rustc), "--version"], timeout=180)
        artifacts = {span.FOLDER + "/" + name for name in ("requests.hex", "sdk-requests.hex", "native-output.txt")}
        references = {}
        for key in ("value", "sdk"):
            base = output / span.FOLDER / "original" / key; base.mkdir(parents=True)
            source_pins = {}
            for name, relative in span.reference_files(key).items():
                target = base / name; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((cls.source / relative).read_bytes())
                source_pins[name] = span.pin(target.read_bytes())
                artifacts.add(str(target.relative_to(output)))
            compile_name, replay_name = "span-" + key + "-rust-compile", "span-" + key + "-rust-replay"
            names.extend((compile_name, replay_name))
            q.record_check(output, report, name=compile_name,
                command=[str(cls.cargo), "build", "--locked", "--release", "--manifest-path", str(base / "Cargo.toml"),
                         "--target-dir", str(base / "target")], timeout=180)
            compiled = report["checks"][-1]
            binary = base / "target/release" / ("hia-serde-json-reference" if key == "value" else "hepta-workdir-original-oracle")
            executable = str(binary.relative_to(output)); binary_pin = span.pin(binary.read_bytes())
            artifacts.add(executable)
            state["builds"][key] = {"sources": source_pins, "executable": executable, "binary": binary_pin,
                "compile_stdout_sha256": compiled["stdout_sha256"], "compile_stderr_sha256": compiled["stderr_sha256"]}
            wire = (output / span.FOLDER / ("requests.hex" if key == "value" else "sdk-requests.hex")).read_bytes()
            replayed = q.record_check(output, report, name=replay_name, command=[str(binary)], input_bytes=wire, timeout=180)
            report["checks"][-1].update(stdin_bytes=len(wire), stdin_sha256=span.sha(wire))
            references[key] = {"cases": 1, "input": span.pin(wire), "output": span.pin(replayed.stdout),
                               "executable": executable, "binary": binary_pin}
        artifacts.update(name + "." + suffix for name in names for suffix in ("stdout", "stderr"))
        comparison = {"schema": "hepta.runtime.span-raw-value.original-comparison.v1", "status": "PASS",
            "source_inputs": copy.deepcopy(cls.span_sources), "native_evidence_sha256": state["native_evidence_sha256"],
            "references": references, "actual_fresh_rust_builds": 2, "actual_rust_replays": 2,
            "actual_compiler_version_processes": 1, "native_cases_added_by_replay": 0, "typed_sdk_handler_fixture": True,
            **{flag: False for flag in span.FALSE_FLAGS},
            "artifact_sha256": {name: native.digest(output / name) for name in sorted(artifacts)}}
        q.save_report(output / span.FOLDER / "rust-comparison.json", comparison)
        report[span.REFERENCE_KEY] = state
        return comparison

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
             patch.object(r, "run_public_registry_controls", self.control(p.CONTROLS[1])), \
             patch.object(r, "run_result_storage_controls", self.control(p.CONTROLS[2])):
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
        self.assertEqual(len(flat), 81)
        self.assertEqual(set(flat), set(r.RECIPES))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(p.GROUPS["config"], ("runtime_config", "runtime_config_span"))
        self.assertEqual(p.GROUPS["storage"], tuple(r.storage_pipeline.KEYS))
        self.assertTrue(set(r.result_qualification.KEYS) <= set(p.GROUPS["json"]))
        self.assertTrue(set(r.PARALLEL_RUST_RECIPES) <= set(p.GROUPS["system"]))
        self.assertTrue({"write_chain", "workdir_service"} <= set(p.GROUPS["services"]))
        self.assertEqual(r.SHARED_RUST_PROCESS_RECIPES,
            {"response_hints": "request_context", "view_params": "view_read", "view_call": "view_read"})
        for keys in p.GROUPS.values():
            self.assertEqual(keys, tuple(key for key in r.RECIPES if key in keys))
        for consumer, owners in r.RUST_RECIPE_DEPENDENCIES.items():
            self.assertTrue(any({consumer, *owners} <= set(keys) for keys in p.GROUPS.values()))

    def test_local_create_keeps_its_twelve_actual_processes_in_system_group(self):
        self.assertIn("local_create_file", p.GROUPS["system"])
        part = native.read_json(self.shards / "system" / p.SHARD_REPORT)
        self.assertEqual(part["rust_recipe_processes"]["local_create_file"],
                         list(r.local_create_qualification.PROCESS_NAMES))
        owners = r.original_process_attribution(part, p.GROUPS["system"])
        for name in r.local_create_qualification.PROCESS_NAMES:
            self.assertEqual(owners[name], "local_create_file")
            row = next(row for row in part["checks"] if row["name"] == name)
            self.assertEqual(row["timeout_seconds"], 180)
            self.assertEqual(row["exit_code"], 0)

    def test_local_create_process_omission_reordering_and_renaming_are_rejected(self):
        original = list(r.local_create_qualification.PROCESS_NAMES)
        variants = (original[:-1], original[::-1],
                    ["unregistered-create-build", *original[1:]],
                    [*original, "unregistered-extra-create-process"])
        for names in variants:
            with self.subTest(names=names):
                self.setUp()
                self.change_report("system", lambda part: part["rust_recipe_processes"].update(
                    local_create_file=names), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "exact twelve ordered original processes"):
                    self.collect()

    def test_complete_local_create_keeps_all_six_actual_processes(self):
        self.assertIn("local_create_spec", p.GROUPS["system"])
        part = native.read_json(self.shards / "system" / p.SHARD_REPORT)
        self.assertEqual(part["rust_recipe_processes"]["local_create_spec"],
                         list(r.local_create_spec_qualification.PROCESS_NAMES))
        owners = r.original_process_attribution(part, p.GROUPS["system"])
        for name in r.local_create_spec_qualification.PROCESS_NAMES:
            self.assertEqual(owners[name], "local_create_spec")
            row = next(row for row in part["checks"] if row["name"] == name)
            self.assertEqual(row["timeout_seconds"], 180)
            self.assertEqual(row["exit_code"], 0)

    def test_complete_local_create_refuses_missing_reordered_or_invented_processes(self):
        original = list(r.local_create_spec_qualification.PROCESS_NAMES)
        variants = (original[:-1], original[::-1], ["invented-spec-build", *original[1:]],
                    [*original, "invented-spec-process"])
        for names in variants:
            with self.subTest(names=names):
                self.setUp()
                self.change_report("system", lambda part: part["rust_recipe_processes"].update(
                    local_create_spec=names), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "exact six ordered original processes"):
                    self.collect()

    def test_collection_consumes_staging_and_preserves_every_complete_artifact(self):
        expected = {}
        for group in p.groups():
            seal = native.read_json(self.shards / group / p.SHARD_SEAL)
            for name, pin in seal["files"].items():
                expected[name] = (self.shards / group / "data" / name, pin)
        self.assertEqual(self.collect()["status"], "PASS")
        for name, (staged, pin) in expected.items():
            self.assertFalse(staged.exists(), name)
            self.assertEqual(native.file_identity(self.output / name), pin, name)
            self.assertEqual((self.output / name).stat().st_nlink, 1, name)

    def add_sealed_file(self, group, name, raw):
        folder = self.shards / group
        path = folder / "data" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        seal = native.read_json(folder / p.SHARD_SEAL)
        seal["files"], seal["directories"] = native.inventory(folder / "data")
        q.save_report(folder / p.SHARD_SEAL, seal)
        self.expected[group] = native.digest(folder / p.SHARD_SEAL)
        return path

    def test_cross_group_equal_artifact_is_refused_before_any_staging_move(self):
        name = "workdir-original/build.stdout"
        paths = [self.add_sealed_file(group, name, b"complete stream\n")
                 for group in ("bytes", "services")]
        with self.assertRaisesRegex(ValueError, "duplicate an artifact: " + name):
            self.collect()
        self.assertTrue(all(path.read_bytes() == b"complete stream\n" for path in paths))
        self.assertFalse((self.output / name).exists())

    def test_cross_group_different_artifact_is_refused_without_overwrite(self):
        name = "workdir-original/result.json"
        expected = (b'{"owner":"public-mcp"}\n', b'{"owner":"service"}\n')
        paths = [self.add_sealed_file(group, name, raw)
                 for group, raw in zip(("bytes", "services"), expected, strict=True)]
        with self.assertRaisesRegex(ValueError, "duplicate an artifact: " + name):
            self.collect()
        self.assertEqual(tuple(path.read_bytes() for path in paths), expected)
        self.assertFalse((self.output / name).exists())

    def test_separate_workdir_originals_keep_both_complete_streams_after_collection(self):
        expected = {"workdir-original/result.json": b'{"owner":"public-mcp"}\n',
                    r.service_pipeline.WORKDIR_ORIGINAL + "/result.json": b'{"owner":"service"}\n'}
        paths = [self.add_sealed_file(group, name, expected[name])
                 for group, name in zip(("bytes", "services"), expected, strict=True)]
        self.assertEqual(self.collect()["status"], "PASS")
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual({name: (self.output / name).read_bytes() for name in expected}, expected)
        p.verify_collected_receipts(self.output, native.read_json(self.output / "result.json"))

    def test_shared_view_original_archive_survives_actual_shard_transport(self):
        part = native.read_json(self.shards / "bytes" / p.SHARD_REPORT)
        expected = part["view_original_fixture_retirement"]
        self.assertEqual(expected["profile"], "view-original")
        self.assertEqual(expected["fixture_directories"], list(p.public_fixtures.VIEW_ORIGINAL))
        self.assertEqual((expected["files"], expected["symlinks"], expected["hardlink_groups"]), (6, 3, 3))
        self.assertEqual(expected["semantic_invocations_added"], 0)
        self.collect()
        report = native.read_json(self.output / "result.json")
        self.assertEqual(report["view_original_fixture_retirement"], expected)
        self.assertEqual(p.view_original_retirement(self.output, report), expected)
        for relative in p.public_fixtures.VIEW_ORIGINAL:
            self.assertFalse((self.output / relative).exists())
        self.assertTrue((self.output / "view-search-original/original.stdout").is_file())
        self.assertTrue((self.output / "view-regex-search-original/input.bin").is_file())

    def test_original_view_archive_cannot_be_omitted_or_recounted_in_resigned_report(self):
        for mutation in (lambda part: part.pop("view_original_fixture_retirement"),
                         lambda part: part["view_original_fixture_retirement"].update(files=0)):
            self.setUp()
            self.change_report("bytes", mutation, update_workflow=True)
            with self.assertRaisesRegex(ValueError, "original shard is incomplete|fixture archive differs"):
                self.collect()

    def test_public_original_archive_is_owned_by_bytes_and_survives_collection(self):
        field = "runtime_mcp_original_fixture_retirement"
        self.assertIn(field, p.reference_fields("bytes"))
        self.assertTrue(all(field not in p.reference_fields(group) for group in p.groups() if group != "bytes"))
        part = native.read_json(self.shards / "bytes" / p.SHARD_REPORT)
        expected = part[field]
        self.assertEqual(expected["fixture_directories"], list(p.public_fixtures.ORIGINAL))
        self.assertEqual((expected["files"], expected["symlinks"], expected["fifos"],
                          expected["hardlink_groups"]), (4, 2, 2, 2))
        self.assertEqual(expected["semantic_invocations_added"], 0)
        self.collect()
        report = native.read_json(self.output / "result.json")
        self.assertEqual(report[field], expected)
        self.assertEqual(p.retained_public_original_retirement(self.output, report,
                         native.inventory(self.output)[0]), expected)

    def test_public_original_archive_refuses_recounted_or_rebound_resigned_reports(self):
        field = "runtime_mcp_original_fixture_retirement"
        def mutate_both(part, values):
            part[field].update(values)
            part["original_rust_comparisons"]["runtime_mcp"]["pipeline"][
                "original_fixture_retirement"].update(values)
        for values in ({"files": 0}, {"complete_evidence_sha256": "0" * 64},
                       {"execution_output_root": "/another-original-output"},
                       {"semantic_invocations_added": False}):
            with self.subTest(values=values):
                self.setUp()
                self.change_report("bytes", lambda part: mutate_both(part, values), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "public original fixture"):
                    self.collect()

    def test_public_original_archive_refuses_physical_receipt_rebinding_after_rehash(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        field = "runtime_mcp_original_fixture_retirement"
        name = "runtime-mcp-original/retired-fixtures.json"
        receipt = native.read_json(self.output / name)
        receipt["complete_evidence_sha256"] = "0" * 64
        q.save_report(self.output / name, receipt)
        digest = native.digest(self.output / name)
        comparison = report["original_rust_comparisons"]["runtime_mcp"]
        for value in (report[field], comparison["pipeline"]["original_fixture_retirement"]):
            value["artifact_sha256"][name] = digest
        comparison["artifact_sha256"][name] = digest
        with self.assertRaisesRegex(ValueError, "public original fixture retirement binding differs"):
            p.retained_public_original_retirement(self.output, report, native.inventory(self.output)[0])

    def test_public_original_archive_reads_all_payload_bytes_after_outer_rehash(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        field = "runtime_mcp_original_fixture_retirement"
        name = "runtime-mcp-original/retired-fixtures.bin.gz"
        receipt_name = "runtime-mcp-original/retired-fixtures.json"
        raw = bytearray((self.output / name).read_bytes())
        raw[-8] ^= 1
        (self.output / name).write_bytes(raw)
        receipt = native.read_json(self.output / receipt_name)
        receipt["archive"] = p.public_fixtures.file_pin(self.output / name)
        q.save_report(self.output / receipt_name, receipt)
        pins = {key: native.digest(self.output / key) for key in (name, receipt_name)}
        comparison = report["original_rust_comparisons"]["runtime_mcp"]
        for value in (report[field], comparison["pipeline"]["original_fixture_retirement"]):
            value["artifact_sha256"] = dict(pins)
        comparison["artifact_sha256"].update(pins)
        with self.assertRaises((ValueError, OSError, EOFError)):
            p.retained_public_original_retirement(self.output, report, native.inventory(self.output)[0])

    def test_public_original_archive_refuses_reappearing_retired_trees(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        files = native.inventory(self.output)[0]
        (self.output / p.public_fixtures.ORIGINAL[0]).mkdir()
        with self.assertRaisesRegex(ValueError, "retired public fixture root reappeared"):
            p.retained_public_original_retirement(self.output, report, files)

    def test_shared_view_archive_rejects_changed_binding_and_reappearing_targets(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        changed = copy.deepcopy(report)
        changed["original_rust_comparisons"]["runtime_mcp"]["extra"] = "resigned result"
        with self.assertRaisesRegex(ValueError, "retirement binding differs"):
            p.view_original_retirement(self.output, changed)
        target = self.output / p.public_fixtures.VIEW_ORIGINAL[0]
        target.mkdir()
        with self.assertRaisesRegex(ValueError, "reappeared"):
            p.view_original_retirement(self.output, report)

    def test_workflow_keeps_independent_hash_outputs_and_distinct_wall_budgets(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        reusable = (ROOT / ".github/workflows/hia-runtime-original-shard.yml").read_text()
        for group in p.GROUPS:
            section = workflow.split("\n  original_" + group + ":\n", 1)[1]
            section = re.split(r"\n  [a-z_]+:\n", section, maxsplit=1)[0]
            self.assertIn("uses: ./.github/workflows/hia-runtime-original-shard.yml", section)
            self.assertIn("needs: native_collect", section)
            self.assertIn("group: " + group, section)
            self.assertIn('--shard-sha256 "' + group + '=${{ needs.original_' + group + '.outputs.sha256 }}"', workflow)
        # Native jobs retain their original wall budget. Whole-artifact reads
        # and the final eight-group join have a separate infrastructure budget;
        # every actual oracle/compare deadline is still checked independently.
        native_jobs, collector = workflow.split("\n  qualify:\n", 1)
        self.assertEqual(set(re.findall(r"timeout-minutes: (\d+)", native_jobs)), {"15"})
        self.assertEqual(re.findall(r"timeout-minutes: (\d+)", reusable), ["45"])
        self.assertEqual(re.findall(r"timeout-minutes: (\d+)", collector), ["60"])
        self.assertIn("value: ${{ jobs.original.outputs.sha256 }}", reusable)
        self.assertIn("sha256: ${{ steps.shard.outputs.sha256 }}", reusable)
        self.assertIn('timeout --signal=KILL 180 python3', workflow)
        self.assertNotIn("Compare all declared original owners", workflow)
        self.assertNotIn("Retain original failure bytes and prepared artifacts", workflow)
        self.assertIn("Retain immutable original failure diagnostics\n        if:", reusable)
        self.assertIn('--output "$RUNNER_TEMP/hia-original-diagnostics"', reusable)
        self.assertNotIn("--destination", reusable)
        self.assertIn("tests/oracles", reusable)

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
            with self.assertRaisesRegex(ValueError, "empty, duplicated, undeclared or out of source order"):
                r.run_rust_recipes(self.output, report, self.version, recipe_keys=("runtime_config", "runtime_config"))

    def test_complete_actual_process_fixture_merge_retains_every_record(self):
        result = self.collect()
        self.assertEqual(result["status"], "PASS")
        report = native.read_json(self.output / "result.json")
        self.assertEqual(set(report["original_rust_comparisons"]), set(r.RECIPES))
        self.assertTrue(all(item.get("actual_python_process_fixture_only")
                           or item.get("comparison", {}).get("actual_python_process_fixture_only")
                            for item in report["original_rust_comparisons"].values()))
        self.assertEqual([row["name"] for row in report["checks"]][-len(p.CONTROLS):], list(p.CONTROLS))
        self.assertEqual(report["json_reference_build"], self.json_build)
        self.assertEqual(report["rust_recipe_shared_processes"], r.SHARED_RUST_PROCESS_RECIPES)
        names = [row["name"] for row in report["checks"]]
        self.assertEqual(len(names), len(set(names)))
        for consumer, owner in r.SHARED_RUST_PROCESS_RECIPES.items():
            self.assertEqual(report["rust_recipe_processes"][consumer], report["rust_recipe_processes"][owner])
            self.assertGreater(self.shared_rereads[consumer], 0)
        for field in p.REFERENCE_OWNERS:
            self.assertIn(field, report)
        p.verify_collected_receipts(self.output, report)

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

    def test_source_declared_shared_attribution_is_required(self):
        self.change_report("json", lambda part: part.pop("rust_recipe_shared_processes"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            self.collect()
        self.setUp()
        self.change_report("json", lambda part: part["rust_recipe_shared_processes"].update(
            response_hints="serde_json"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "declared producer"):
            self.collect()

    def test_shared_consumer_requires_the_complete_producer_process_set(self):
        self.change_report("bytes", lambda part: part["rust_recipe_processes"]["view_params"].pop(),
                           update_workflow=True)
        with self.assertRaisesRegex(ValueError, "producer's complete process set"):
            self.collect()

    def test_unrelated_recipe_cannot_declare_a_shared_execution(self):
        self.change_report("bytes", lambda part: part["rust_recipe_shared_processes"].update(
            delta="text_budget"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "declared producer"):
            self.collect()

    def test_shared_consumer_does_not_create_a_new_process(self):
        report = copy.deepcopy(self.baseline)
        report.update(phase="original_rust_comparison", original_rust_comparisons={})
        recipes = dict(self.fixture_recipes)
        actual = recipes["response_hints"]
        def duplicate(output, report, rustc):
            result = actual(output, report, rustc)
            q.record_check(output, report, name="invented-second-context-run",
                command=[sys.executable, "-I", str(self.recipe), "response_hints"], timeout=180)
            return result
        recipes["response_hints"] = duplicate
        with patch.object(r, "RECIPES", recipes):
            with self.assertRaisesRegex(ValueError, "invented a second execution"):
                r.run_rust_recipes(self.output, report, self.version,
                                   recipe_keys=("request_context", "response_hints"))

    def test_shared_consumer_cannot_rewrite_a_previously_completed_record(self):
        report = copy.deepcopy(self.baseline)
        report.update(phase="original_rust_comparison", original_rust_comparisons={})
        recipes = dict(self.fixture_recipes)
        actual = recipes["response_hints"]
        def rewrite(output, report, rustc):
            result = actual(output, report, rustc)
            report["checks"][-1]["timeout_seconds"] = 179
            return result
        recipes["response_hints"] = rewrite
        with patch.object(r, "RECIPES", recipes):
            with self.assertRaisesRegex(ValueError, "changed a completed process"):
                r.run_rust_recipes(self.output, report, self.version,
                                   recipe_keys=("request_context", "response_hints"))

    def test_shared_recipe_rechecks_its_producers_actual_bytes(self):
        report = copy.deepcopy(self.baseline)
        report.update(phase="original_rust_comparison", original_rust_comparisons={})
        recipes = dict(self.fixture_recipes)
        actual = recipes["request_context"]
        def replace_after_run(output, report, rustc):
            result = actual(output, report, rustc)
            (output / (p.context_reference.CHECKS[-1] + ".stdout")).write_bytes(b"changed actual bytes\n")
            return result
        recipes["request_context"] = replace_after_run
        with patch.object(r, "RECIPES", recipes):
            with self.assertRaisesRegex(ValueError, "actual native process output bytes differ"):
                r.run_rust_recipes(self.output, report, self.version,
                                   recipe_keys=("request_context", "response_hints"))

    def test_shared_consumers_and_shell_lifetimes_cannot_be_selected_without_their_producer(self):
        for key in ("response_hints", "view_params", "view_call", "runtime_mcp",
                    "shell_background_text", "shell_outcome", "shell_output_io", "shell_foreground"):
            with self.subTest(key=key):
                report = copy.deepcopy(self.baseline)
                report.update(phase="original_rust_comparison", original_rust_comparisons={})
                with self.assertRaisesRegex(ValueError, "omits or reorders its producer"):
                    r.run_rust_recipes(self.output, report, self.version, recipe_keys=(key,))

    def test_shared_build_lifetimes_and_source_order_cannot_cross_groups(self):
        changed = dict(p.GROUPS)
        changed["json"] = tuple(key for key in changed["json"] if key != "response_hints")
        changed["services"] = tuple(key for key in r.RECIPES if key in {*changed["services"], "response_hints"})
        with patch.object(p, "GROUPS", changed):
            with self.assertRaisesRegex(ValueError, "lifetime crosses"):
                p.groups()
        changed = dict(p.GROUPS)
        changed["state"] = tuple(reversed(changed["state"]))
        with patch.object(p, "GROUPS", changed):
            with self.assertRaisesRegex(ValueError, "producer order"):
                p.groups()

    def test_every_owner_reference_field_is_required_after_rehashing(self):
        for group in p.groups():
            for field in p.reference_fields(group):
                with self.subTest(group=group, field=field):
                    self.setUp()
                    self.change_report(group, lambda part, field=field: part.pop(field), update_workflow=True)
                    with self.assertRaisesRegex(ValueError, "incomplete or changed"):
                        self.collect()

    def test_owner_reference_cannot_cite_unretained_or_replaced_bytes(self):
        for field in ("request_context_reference", "result_publication_reference", "request_scope_reference"):
            with self.subTest(field=field):
                self.setUp()
                def change(part):
                    pins = part[field]["artifact_sha256"]
                    pins[next(iter(pins))] = "0" * 64
                self.change_report("json", change, update_workflow=True)
                with self.assertRaisesRegex(ValueError, "artifact differs from the retained"):
                    self.collect()

    def test_context_reference_result_and_consumer_must_match_the_same_completed_bytes(self):
        self.change_report("json", lambda part: part["request_context_reference"]["result"].update(
            unexecuted_replacement=True), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "completed result bytes"):
            self.collect()
        self.setUp()
        self.change_report("json", lambda part: part["original_rust_comparisons"]["response_hints"].update(
            shared_fresh_reference="another-build/RESULT.json"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "another completed owner reference"):
            self.collect()
        self.setUp()
        self.change_report("json", lambda part: part["original_rust_comparisons"]["response_hints"].update(
            comparison={"unexecuted_replacement": True}), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "shared original reference"):
            self.collect()

    def test_publication_and_scope_comparisons_are_recomputed_from_their_retained_reference(self):
        for component in ("result_publication", "request_scope_lifecycle"):
            with self.subTest(component=component):
                self.setUp()
                self.change_report("json", lambda part: part["original_rust_comparisons"][component].update(
                    comparison={"unexecuted_replacement": True}), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "comparison differs from its completed reference"):
                    self.collect()

    def test_public_search_requires_each_original_stream_and_both_actual_wrappers(self):
        for stem in ("view_search", "view_regex_search"):
            with self.subTest(stem=stem):
                self.setUp()
                relative = stem.replace("_", "-") + "-original/original.stdout"
                self.change_report("bytes", lambda part: part[stem + "_public_original_comparison"][
                    "artifact_sha256"].pop(relative), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "different shared original artifact"):
                    self.collect()
                self.setUp()
                self.change_report("bytes", lambda part: part[stem + "_original_comparison"][
                    "required_original_checks"].pop(), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "shared search original receipt"):
                    self.collect()

    def test_all_reference_fields_remain_immutable_after_collection(self):
        self.collect()
        baseline = native.read_json(self.output / "result.json")
        for field in p.REFERENCE_OWNERS:
            with self.subTest(field=field):
                report = copy.deepcopy(baseline)
                report[field]["unexecuted_replacement"] = True
                with self.assertRaisesRegex(ValueError, "differs from all actual"):
                    p.verify_collected_receipts(self.output, report)

    def test_existing_shell_owner_limits_are_exact_and_confined_to_their_declared_process(self):
        self.assertEqual(r.RUST_PROCESS_DEADLINES, {
            "shell-process-rust-build": ("shell_process", 900),
            "shell-background-rust-compare": ("shell_background_text", 300),
            "shell-outcome-rust-compare": ("shell_outcome", 300),
            "shell-output-rust-compare": ("shell_output_io", 300),
            "shell-foreground-rust-compare": ("shell_foreground", 300),
            "shell-capture-path-rust-build": ("shell_capture_path", 300),
            "shell-capture-path-rust-compare": ("shell_capture_path", 300),
            "shell-capture-mkdir-rust-build": ("shell_capture_mkdir", 300),
            "shell-capture-mkdir-rust-compare": ("shell_capture_mkdir", 300),
            "shell-capture-file-rust-build": ("shell_capture_file", 300),
            "shell-capture-file-rust-compare": ("shell_capture_file", 300),
            "shell-capture-prepare-rust-build": ("shell_capture_prepare", 300),
            "shell-capture-prepare-rust-compare": ("shell_capture_prepare", 300),
        })
        part = native.read_json(self.shards / "state" / p.SHARD_REPORT)
        for name, (owner, timeout) in r.RUST_PROCESS_DEADLINES.items():
            row = next(row for row in part["checks"] if row["name"] == name)
            self.assertEqual(row["timeout_seconds"], timeout)
            p.validate_process(self.shards / "state/data", row, owner)
            for changed in (timeout - 1, timeout + 1, True):
                with self.subTest(name=name, deadline=changed):
                    with self.assertRaisesRegex(ValueError, "unchanged maximum deadline"):
                        p.validate_process(self.shards / "state/data", dict(row, timeout_seconds=changed), owner)
            with self.assertRaisesRegex(ValueError, "unchanged maximum deadline"):
                p.validate_process(self.shards / "state/data", row, "runtime_bytes")
            with self.subTest(name=name, undeclared_process=True):
                with self.assertRaisesRegex(ValueError, "unchanged maximum deadline"):
                    p.validate_process(self.shards / "state/data",
                        dict(row, name=name + "-undeclared", timeout_seconds=300), owner)

    def test_span_references_stay_in_bytes_with_all_five_actual_processes(self):
        self.assertIn(span.REFERENCE_KEY, p.reference_fields("bytes"))
        self.assertTrue(all(span.REFERENCE_KEY not in p.reference_fields(group)
                            for group in p.groups() if group != "bytes"))
        self.collect()
        report = native.read_json(self.output / "result.json")
        expected = ["span-raw-value-rustc-version", "span-value-rust-compile", "span-value-rust-replay",
                    "span-sdk-rust-compile", "span-sdk-rust-replay"]
        self.assertEqual([name for name in report["rust_recipe_processes"]["runtime_mcp"]
                          if name.startswith("span-")], expected)
        for name in expected:
            self.assertEqual(sum(row["name"] == name for row in report["checks"]), 1)
        self.assertEqual(set(report[span.REFERENCE_KEY]["builds"]), {"value", "sdk"})

    def test_span_cannot_omit_an_actual_process_even_with_rehashed_process_ledger(self):
        def change(part):
            name = "span-value-rust-compile"
            part["checks"] = [row for row in part["checks"] if row["name"] != name]
            part["rust_recipe_processes"]["runtime_mcp"].remove(name)
        self.change_report("bytes", change, update_workflow=True)
        with self.assertRaisesRegex(ValueError, "five actual owner processes"):
            self.collect()

    def test_span_source_and_native_bindings_cannot_be_replaced(self):
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["source_inputs"]["files"][
            span.SOURCE_FILES[0]].update(sha256="0" * 64), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "source custody differs"):
            self.collect()
        self.setUp()
        def change(part):
            part[span.REFERENCE_KEY]["native_evidence_sha256"] = "0" * 64
            part["original_rust_comparisons"]["runtime_mcp"]["span_raw_value"]["native_evidence_sha256"] = "0" * 64
        self.change_report("bytes", change, update_workflow=True)
        with self.assertRaisesRegex(ValueError, "native evidence digest differs"):
            self.collect()

    def test_span_original_compiler_and_environment_custody_is_required(self):
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["cargo"].update(sha256="0" * 64),
                           update_workflow=True)
        with self.assertRaisesRegex(ValueError, "compiler or Cargo identity differs"):
            self.collect()
        self.setUp()
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["removed_environment"].append(
            "UNDECLARED_OVERRIDE"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "environment declaration differs"):
            self.collect()

    def test_span_requires_two_separate_materialized_builds(self):
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["builds"].pop("sdk"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "two separate original builds"):
            self.collect()
        self.setUp()
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["builds"]["value"]["sources"][
            "Cargo.toml"].update(sha256="0" * 64), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "materialized build source inventory differs"):
            self.collect()

    def test_span_build_receipt_cannot_name_the_other_reference_executable(self):
        def change(part):
            state = part[span.REFERENCE_KEY]
            state["builds"]["value"]["executable"] = state["builds"]["sdk"]["executable"]
        self.change_report("bytes", change, update_workflow=True)
        with self.assertRaisesRegex(ValueError, "compiled executable or actual build streams differ"):
            self.collect()

    def test_span_replay_must_consume_the_admitted_complete_native_input(self):
        def change(part):
            row = next(row for row in part["checks"] if row["name"] == "span-sdk-rust-replay")
            row["stdin_sha256"] = "0" * 64
        self.change_report("bytes", change, update_workflow=True)
        with self.assertRaisesRegex(ValueError, "replay input, output or executable binding differs"):
            self.collect()

    def test_span_command_and_exact_deadline_cannot_be_relabeled(self):
        for field, value in (("timeout_seconds", 179), ("command", [str(self.version), "--version"])):
            with self.subTest(field=field):
                self.setUp()
                def change(part):
                    row = next(row for row in part["checks"] if row["name"] == "span-value-rust-replay")
                    row[field] = value
                self.change_report("bytes", change, update_workflow=True)
                with self.assertRaisesRegex(ValueError, "command or 180-second deadline differs"):
                    self.collect()

    def test_span_build_stream_and_all_required_artifact_pins_are_retained(self):
        self.change_report("bytes", lambda part: part[span.REFERENCE_KEY]["builds"]["sdk"].update(
            compile_stdout_sha256="0" * 64), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "compiled executable or actual build streams differ"):
            self.collect()
        self.setUp()
        self.change_report("bytes", lambda part: part["original_rust_comparisons"]["runtime_mcp"][
            "span_raw_value"]["artifact_sha256"].pop("span-sdk-rust-replay.stdout"), update_workflow=True)
        with self.assertRaisesRegex(ValueError, "omitted required source, process or native artifacts"):
            self.collect()

    def test_span_retains_its_completed_comparison_bytes(self):
        relative = span.FOLDER + "/rust-comparison.json"
        folder = self.shards / "bytes"
        path = folder / "data" / relative
        changed = native.read_json(path); changed["unexecuted_replacement"] = True
        q.save_report(path, changed)
        seal = native.read_json(folder / p.SHARD_SEAL)
        seal["files"][relative] = native.file_identity(path)
        q.save_report(folder / p.SHARD_SEAL, seal)
        self.expected["bytes"] = native.digest(folder / p.SHARD_SEAL)
        with self.assertRaisesRegex(ValueError, "stored complete comparison differs"):
            self.collect()

    def test_span_process_counts_and_scope_cannot_be_promoted(self):
        for field, value in (("actual_compiler_version_processes", True), ("whole_runtime_replaced", True),
                             ("actual_fresh_rust_builds", 1)):
            with self.subTest(field=field):
                self.setUp()
                self.change_report("bytes", lambda part: part["original_rust_comparisons"]["runtime_mcp"][
                    "span_raw_value"].update({field: value}), update_workflow=True)
                with self.assertRaisesRegex(ValueError, "scope or completed process counts differ"):
                    self.collect()

    def test_rehashed_general_deadline_extension_is_still_rejected(self):
        self.change_report("bytes", lambda part: part["checks"][-1].update(timeout_seconds=181),
                           update_workflow=True)
        with self.assertRaisesRegex(ValueError, "unchanged maximum deadline"):
            self.collect()

    def test_shared_process_mapping_remains_immutable_after_collection(self):
        self.collect()
        report = native.read_json(self.output / "result.json")
        report["rust_recipe_shared_processes"]["response_hints"] = "serde_json"
        with self.assertRaisesRegex(ValueError, "differs from all actual"):
            p.verify_collected_receipts(self.output, report)

    def test_missing_group_cannot_become_complete(self):
        shutil.rmtree(self.shards / "config")
        with self.assertRaisesRegex(ValueError, "exactly eight"):
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
