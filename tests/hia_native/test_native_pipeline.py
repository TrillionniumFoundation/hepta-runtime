"""Actual-process controls for native artifact partitioning and evidence admission.

Small temporary programs test the reporting machinery. They never qualify a
production HIA image or stand in for a compiler cold replay.
"""
from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_pipeline as p
import hia_native_failure as failure
import qualify_hia_runtime_native as q
import hia_native_service_pipeline as service


class NativePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-pipeline-reporting-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_ci_path_filters_cover_every_required_source_for_push_and_pull_request(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        events = workflow.split("\npermissions:", 1)[0]
        push, pull_request = events.split("  pull_request:\n", 1)
        parse = lambda text: re.findall(r"^      - '([^']+)'$", text, re.MULTILINE)
        push, pull_request = parse(push), parse(pull_request)
        self.assertEqual(push, pull_request)
        self.assertEqual(len(push), len(set(push)))
        uncovered = [name for name in q.sources() if not any(fnmatch.fnmatchcase(name, pattern) for pattern in push)]
        self.assertEqual(uncovered, [], "required source changes must trigger the actual native gate")

    def test_service_original_inventory_keeps_streams_outside_all_workdir_fixtures(self):
        output = self.root / "actual"; output.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        sentinel = outside / "keep"; sentinel.write_bytes(b"external fixture target")
        folder = output / "workdir-original"; folder.mkdir()
        streams = {}
        for domain in ("probe-v1", "public", "regex"):
            fixture = folder / domain / "fixture"; fixture.mkdir(parents=True)
            (fixture / "link").symlink_to(outside, target_is_directory=True)
            (fixture / "ordinary").write_bytes(b"transient live state")
            retained = folder / domain / "stdout.bin"
            retained.write_bytes(domain.encode())
            streams[retained.relative_to(output).as_posix()] = service.sha(domain.encode())
        target = folder / "target"; target.mkdir()
        (target / "generated-link").symlink_to(outside, target_is_directory=True)
        result = service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES + ("workdir-original/target",))
        self.assertEqual(result, streams)
        self.assertEqual(sentinel.read_bytes(), b"external fixture target")

    def test_service_original_inventory_refuses_unknown_or_replaced_fixture_links(self):
        output = self.root / "actual"; output.mkdir()
        folder = output / "workdir-original"; folder.mkdir()
        outside = self.root / "outside"; outside.mkdir()
        unknown = folder / "undeclared-link"
        unknown.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory is not owned"):
            service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES)
        unknown.unlink()
        declared = folder / "probe-v1/fixture"; declared.parent.mkdir()
        declared.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory is not owned"):
            service.retained_files(output, folder, service.WORKDIR_ORIGINAL_FIXTURES)
        self.assertTrue(declared.is_symlink())

    def test_service_fixture_retirement_preserves_external_targets_and_exact_receipt(self):
        output = self.root / "actual"; output.mkdir()
        folder = output / "workdir-native/regex"; folder.mkdir(parents=True)
        fixture = folder / "fixture"; fixture.mkdir()
        denied = fixture / "denied"; denied.mkdir()
        (denied / "state").write_bytes(b"closed fixture")
        outside = self.root / "outside"; outside.mkdir()
        sentinel = outside / "keep"; sentinel.write_bytes(b"must remain")
        (fixture / "directory-link").symlink_to(outside, target_is_directory=True)
        (fixture / "file-link").symlink_to(sentinel)
        denied.chmod(0)
        self.addCleanup(lambda: denied.chmod(0o700) if denied.exists() else None)
        receipt = output / "workdir-native/retired-fixtures.json"
        evidence = {"status": "PASS", "actual_corpus_sha256": "a" * 64}
        fixtures = ("workdir-native/regex/fixture",)
        result = service.retire_fixtures(output, fixtures, receipt, evidence, create=True)
        self.assertFalse(fixture.exists())
        self.assertEqual(sentinel.read_bytes(), b"must remain")
        self.assertEqual(result, service.retire_fixtures(output, fixtures, receipt, evidence))
        with self.assertRaisesRegex(ValueError, "evidence differs"):
            service.retire_fixtures(output, fixtures, receipt, dict(evidence, actual_corpus_sha256="b" * 64))
        fixture.mkdir()
        with self.assertRaisesRegex(ValueError, "reappeared"):
            service.retire_fixtures(output, fixtures, receipt, evidence)

    def test_service_fixture_retirement_checks_every_target_before_removal(self):
        output = self.root / "actual"; output.mkdir()
        fixture = output / "safe/fixture"; fixture.mkdir(parents=True)
        sentinel = fixture / "keep"; sentinel.write_bytes(b"not admitted")
        with self.assertRaisesRegex(ValueError, "path escaped"):
            service.retire_fixtures(output, ("safe/fixture", "../outside/fixture"), output / "receipt.json", {}, create=True)
        self.assertEqual(sentinel.read_bytes(), b"not admitted")
        outside = self.root / "outside/fixture"; outside.mkdir(parents=True)
        link = output / "replaced/fixture"; link.parent.mkdir()
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "not an owned directory"):
            service.retire_fixtures(output, ("safe/fixture", "replaced/fixture"), output / "receipt.json", {}, create=True)
        self.assertEqual(sentinel.read_bytes(), b"not admitted")
        self.assertFalse((output / "receipt.json").exists())

    def test_partition_is_complete_unique_and_keeps_evidence_dependencies(self):
        partitions = p.partition_tests()
        flat = [name for tests in partitions.values() for name in tests]
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat), set(q.native_tests()))
        self.assertEqual(set(partitions), {"batch", "text", "json", "config", "system", "storage"})
        self.assertEqual(partitions["storage"], q.storage_pipeline.TESTS)
        config = next(row for row in q.MODULES if row["key"] == "runtime_config")
        self.assertEqual(partitions["config"], (config["test"], *config["additional_tests"]))
        self.assertTrue(set(partitions["config"]).isdisjoint(partitions["json"]))
        self.assertEqual(tuple(partitions["batch"]),
            ("test_batch_plan.py", "test_batch_plan_evidence.py", "test_batch_apply.py",
             "test_batch_apply_contract.py", "test_batch_apply_artifacts.py", "test_batch_apply_evidence.py",
             "test_atomic_write_policy.py", "test_atomic_write_kernel.py", "test_atomic_write_boundary.py",
             "test_atomic_write_evidence.py", "test_shared_atomic.py", "test_write_chain_controller.py",
             "test_write_chain_files.py", "test_write_chain_kernel.py", "test_write_chain_concurrency.py",
             "test_write_chain_evidence.py", "test_batch_write_controller.py", "test_batch_render.py",
             "test_utf8_probe.py", "test_batch_write_files.py", "test_batch_write_kernel.py",
             "test_batch_write_concurrency.py", "test_batch_write_wide.py", "test_batch_write_evidence.py"))
        for bad in ("missing", "duplicate", "unknown", "new_module", "split_ordered"):
            changed = copy.deepcopy(p.PARTITIONS)
            modules = q.MODULES
            if bad == "missing":
                changed["text"] = changed["text"][1:]
            elif bad == "duplicate":
                changed["text"] += ("batch_apply",)
            elif bad == "unknown":
                changed["text"] += ("unregistered",)
            elif bad == "new_module":
                modules += ({"key": "unpartitioned", "test": "unpartitioned.py"},)
            else:
                modules = tuple(dict(row, additional_tests=()) if row["key"] == "serde_json" else
                                dict(row, additional_tests=("test_serde_json_transport.py", "test_json_evidence.py"))
                                if row["key"] == "runtime_bytes" else row for row in modules)
            with self.subTest(bad=bad), patch.object(q, "MODULES", modules), self.assertRaises(ValueError):
                p.partition_tests(changed)

    def test_workflow_requires_all_six_partitions_with_unchanged_process_and_job_limits(self):
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        block = workflow.split("\n  native:\n", 1)[1].split("\n  aggregate:\n", 1)[0]
        groups = re.search(r"^        group: \[([^\]]+)\]$", block, re.MULTILINE)
        self.assertIsNotNone(groups)
        self.assertEqual(tuple(value.strip() for value in groups[1].split(",")), tuple(p.PARTITIONS))
        self.assertIn("    timeout-minutes: 15\n", block)
        self.assertIn("      fail-fast: false\n", block)
        changed = copy.deepcopy(p.PARTITIONS)
        changed["json"] += changed["config"]
        changed["config"] = ()
        with self.assertRaisesRegex(ValueError, "independent partition"):
            p.partition_tests(changed)

    def test_failure_diagnostics_survive_denied_fixtures_without_mutation(self):
        source = self.root / "failed"; source.mkdir()
        denied = source / "atomic-write-original/native-kernel/0012-denied-parent/fixture/denied"
        denied.mkdir(parents=True)
        (denied / "private.json").write_bytes(b"not diagnostic evidence")
        denied.chmod(0)
        self.addCleanup(denied.chmod, 0o700)
        report = {"status": "FAIL", "failure": "original comparison refused",
                  "checks": [{"name": "atomic-write-rust-compare", "exit_code": 1, "timed_out": False}]}
        (source / "result.json").write_text(json.dumps(report))
        nested = source / "atomic-write-original/result.json"
        nested.write_text('{"status":"FAIL","failure":"kernel observation mismatch"}')
        raw = b"actual stderr: \xff\x00\n"
        (source / "atomic-write-rust-compare.stderr").write_bytes(raw)
        outside = self.root / "outside.json"; outside.write_bytes(b"outside")
        (source / "escape.json").symlink_to(outside)
        (source / "escape-directory").symlink_to(self.root, target_is_directory=True)
        before = {path: path.read_bytes() for path in
                  (source / "result.json", nested, source / "atomic-write-rust-compare.stderr", outside)}
        destination = self.root / "diagnostics"
        receipt = failure.capture(source, destination)
        self.assertEqual(receipt["original_status"], "FAIL")
        self.assertEqual(receipt["failed_checks"][0]["name"], "atomic-write-rust-compare")
        self.assertFalse(receipt["qualification_admitted"])
        self.assertTrue(receipt["diagnostic_subset_only"])
        self.assertEqual((destination / "data/atomic-write-rust-compare.stderr").read_bytes(), raw)
        self.assertEqual((destination / "data/atomic-write-original/result.json").read_bytes(), before[nested])
        self.assertFalse((destination / "data/escape.json").exists())
        self.assertFalse((destination / "data/escape-directory").exists())
        self.assertFalse((destination / "data/atomic-write-original/native-kernel/0012-denied-parent/fixture").exists())
        self.assertEqual(denied.stat().st_mode & 0o7777, 0)
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertTrue(any(row["path"].endswith("/fixture") for row in receipt["skipped"]))
        self.assertTrue(any(row["path"] == "escape.json" for row in receipt["errors"]))
        with self.assertRaises(FileExistsError):
            failure.capture(source, destination)
        with self.assertRaisesRegex(ValueError, "separate"):
            failure.capture(source, source / "nested-diagnostics")

    def test_original_failure_capture_keeps_raw_domains_and_excludes_live_cargo_cache(self):
        source = self.root / "partial-original"; source.mkdir()
        target = source / "connection-original/target/release/deps"
        target.mkdir(parents=True)
        (target / "rmetaFZWET8").symlink_to(self.root / "already-retired-cargo-temporary")
        retained = {
            "connection-original/project/src/main.rs": b"// exact original source\n",
            "connection-original/project/Cargo.lock": b"version = 4\n",
            "connection-original/requests.bin": b"\x00\xff\x80\n",
            "connection-original/partial-output.bin.gz": b"complete captured gzip bytes\x00",
            "connection-original/build.stderr.log": b"actual interrupted compiler log\xff",
        }
        for name, raw in retained.items():
            path = source / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        destination = self.root / "stable-diagnostics"
        receipt = failure.capture(source, destination)
        self.assertEqual(receipt["capture_errors"], 0)
        self.assertEqual(set(receipt["files"]), set(retained))
        for name, raw in retained.items():
            self.assertEqual((destination / "data" / name).read_bytes(), raw)
            self.assertEqual((source / name).read_bytes(), raw)
        self.assertTrue(any(row["path"] == "connection-original/target" for row in receipt["skipped"]))
        self.assertFalse((destination / "data/connection-original/target").exists())
        self.assertTrue((target / "rmetaFZWET8").is_symlink())

    def test_transport_mode_restore_requires_all_exact_owned_bytes(self):
        folder = self.root / "data"; folder.mkdir()
        for name in ("a.elf", "b.bin"):
            (folder / name).write_bytes(b"\x7fELF" + name.encode())
            (folder / name).chmod(0o700)
        files, _ = p.inventory(folder)
        for name in files:
            (folder / name).chmod(0o644)
        p.verify_files(folder, files, restore_modes=True)
        self.assertEqual((folder / "a.elf").stat().st_mode & 0o7777, 0o700)
        (folder / "a.elf").chmod(0o644)
        (folder / "b.bin").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            p.verify_files(folder, files, restore_modes=True)
        self.assertEqual((folder / "a.elf").stat().st_mode & 0o7777, 0o644)

    def test_file_lock_corpus_producer_cannot_move_after_or_away_from_service(self):
        suites = p.partition_tests()["text"]
        ordered = q.file_lock_pipeline.ORDERED_SUITES
        self.assertEqual(tuple(name for name in suites if name in ordered), ordered)
        for mutation in ("split", "reverse"):
            changed = copy.deepcopy(p.PARTITIONS)
            if mutation == "split":
                changed["text"] = tuple(key for key in changed["text"] if key != "file_lock_service")
                changed["system"] += ("file_lock_service",)
            else:
                changed["text"] = tuple("file_lock_service" if key == "file_locks" else
                                        "file_locks" if key == "file_lock_service" else key
                                        for key in changed["text"])
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "file-lock"):
                p.partition_tests(changed)

    def test_diagnostic_capture_resources_and_controls_stay_in_order(self):
        suites = p.partition_tests()["text"]
        expected = q.serde_error_pipeline.TESTS
        self.assertEqual(tuple(name for name in suites if name in expected), expected)
        for changed in (expected[::-1], (expected[0], expected[2], expected[1])):
            modules = tuple(dict(row, test=changed[0], additional_tests=changed[1:])
                            if row["key"] == "serde_error" else row for row in q.MODULES)
            with self.subTest(order=changed), patch.object(q, "MODULES", modules), \
                    self.assertRaisesRegex(ValueError, "producer and evidence"):
                p.partition_tests()

    def test_diagnostic_launcher_and_completed_outer_receipt_are_exact(self):
        source = self.root / "source"; source.mkdir()
        output = self.root / "output"; output.mkdir()
        launcher = source / "fixed_launcher.py"
        launcher.write_text("import json,sys\nassert sys.argv[1:]==['--phase','base']\n"
                            "print(json.dumps({'reporting_fixture':True}))\n")
        name = q.serde_error_pipeline.TESTS[0]
        command = [sys.executable, "-I", "-B", str(launcher), "--phase", "base"]
        report = {"phase": "native_components", "checks": []}
        with patch.object(q, "ROOT", source), \
                patch.object(q.serde_error_pipeline, "test_commands", return_value={name: command}):
            for changed in (command + ["--skip"], command[:-1] + ["controls"],
                            [sys.executable, "-I", "-B", str(source / "tests/hia_native" / name)]):
                with self.subTest(command=changed), self.assertRaisesRegex(ValueError, "source-owned"):
                    q.run_native_checks(output, report, (name,), q.qualification_env(),
                        parallel_tests=(), ordered_groups=(), commands={name: changed})
                self.assertEqual(report["checks"], [])
            q.run_native_checks(output, report, (name,), q.qualification_env(),
                parallel_tests=(), ordered_groups=(), commands={name: command})
        row, summary = q.serde_error_pipeline.complete(source, output, report, name,
                                                       command, q.completed_test_summary)
        self.assertEqual(summary, {"reporting_fixture": True})
        for field, changed in (("command", command + ["extra"]), ("timeout_seconds", 181),
                               ("elapsed_seconds", 180.01), ("timed_out", True), ("exit_code", 1)):
            broken = copy.deepcopy(report); broken["checks"][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                q.serde_error_pipeline.complete(source, output, broken, name,
                                                command, q.completed_test_summary)

    def test_artifact_path_symlink_and_special_mode_refusals(self):
        folder = self.root / "data"; folder.mkdir()
        (folder / "plain").write_bytes(b"real")
        files, _ = p.inventory(folder)
        for name in ("../outside", "/absolute", "a/../plain", "./plain", "a//plain", "a\\plain", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                p.relative_path(name)
        altered = copy.deepcopy(files); altered["plain"]["mode"] = 0o4755
        with self.assertRaisesRegex(ValueError, "permission bits"):
            p.verify_files(folder, altered, restore_modes=True)
        altered = copy.deepcopy(files); altered["plain"]["bytes"] = True
        with self.assertRaises(ValueError):
            p.verify_files(folder, altered)
        (folder / "link").symlink_to(folder / "plain")
        with self.assertRaises(ValueError):
            p.inventory(folder)
        (folder / "link").unlink()
        (folder / "subdir").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            p.inventory(folder)

    def test_duplicate_json_fields_are_never_accepted(self):
        path = self.root / "receipt.json"
        path.write_text('{"status":"FAIL","status":"PASS"}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            p.read_json(path)

    def actual_fixture(self):
        source = self.root / "source"
        tests = source / "tests/hia_native"; tests.mkdir(parents=True)
        output = self.root / "output"; output.mkdir()
        (output / "empty-evidence/before").mkdir(parents=True)
        (output / "empty-evidence/after").mkdir()
        script = tests / "check.py"
        script.write_text("import json,sys\nprint(json.dumps({'actual_reporting_fixture':True}))\n"
                          "print('retained fixture stderr',file=sys.stderr)\n")
        prepared = {"status": "NATIVE_BUILD_READY", "phase": "native_build_complete",
                    "native_components_status": "PENDING", "source_sha256": {"fixture": "unchanged"},
                    "whole_runtime_replaced": False, "checks": [{"name": "compiler-full-cold",
                        "command": ["synthetic-cold-identity-only", "--output", str(output / "compiler-cold.json")]}]}
        report = copy.deepcopy(prepared)
        report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
            qualification_shard={"group": "text", "invocation": "reporting-fixture", "prepared_sha256": "a" * 64,
                                 "tests": ["check.py"]})
        with patch.object(q, "ROOT", source):
            q.run_native_checks(output, report, ("check.py",), p.q.qualification_env(),
                                parallel_tests=(), ordered_groups=(), timeout=180)
        report.update(status="NATIVE_SHARD_PASS", phase="native_shard_complete", native_components_status="PARTIAL",
                      shard_elapsed_seconds=report["checks"][-1]["elapsed_seconds"], shard_finished_at="fixture")
        destination = self.root / "export"
        p.export_shard(output, destination, {"files": {}}, report)
        return source, prepared, report, destination

    def admit_fixture(self, source, prepared, destination):
        with patch.object(q, "ROOT", source), patch.object(p, "partition_tests", return_value={"text": ("check.py",)}), \
                patch.object(q, "native_commands", return_value={}):
            return p.admit_shard(destination / "data", destination / "shard.json", destination / "shard-report.json",
                                 prepared, "a" * 64, "reporting-fixture", "text", exact_files=True)

    def reseal_fixture(self, destination, report):
        q.save_report(destination / "shard-report.json", report)
        seal = p.read_json(destination / "shard.json")
        seal["report_sha256"] = p.digest(destination / "shard-report.json")
        seal["files"] = p.inventory(destination / "data")[0]
        q.save_report(destination / "shard.json", seal)

    def test_actual_completed_process_survives_transport_and_admission(self):
        source, prepared, report, destination = self.actual_fixture()
        receipt, admitted = self.admit_fixture(source, prepared, destination)
        self.assertEqual(report, admitted)
        self.assertEqual(admitted["checks"][-1]["exit_code"], 0)
        self.assertGreater(admitted["checks"][-1]["stderr_bytes"], 0)
        self.assertEqual(set(receipt["files"]), {"check.py.stdout", "check.py.stderr"})
        # Extra bytes are refused even when the required process files remain.
        (destination / "data/undeclared").write_bytes(b"not admitted")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.admit_fixture(source, prepared, destination)

    def test_actual_empty_evidence_directories_survive_artifact_transport(self):
        source, prepared, _, destination = self.actual_fixture()
        receipt = p.read_json(destination / "shard.json")
        self.assertEqual(receipt["schema"], "hepta.runtime.native-shard.v2")
        self.assertEqual(set(receipt["directories"]),
                         {"empty-evidence", "empty-evidence/before", "empty-evidence/after"})
        before = destination / "data/empty-evidence/before"
        after = destination / "data/empty-evidence/after"
        before.rmdir(); after.rmdir()
        self.admit_fixture(source, prepared, destination)
        self.assertTrue(before.is_dir() and after.is_dir())
        before.rmdir(); before.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.admit_fixture(source, prepared, destination)
        before.unlink(); before.mkdir()
        (destination / "data/undeclared-empty").mkdir()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            self.admit_fixture(source, prepared, destination)

    def test_rehashed_report_cannot_hide_failed_partial_or_relabelled_process(self):
        source, prepared, report, destination = self.actual_fixture()
        mutations = {
            "failed": lambda r: r["checks"][-1].update(exit_code=9),
            "timed_out": lambda r: r["checks"][-1].update(timed_out=True),
            "started": lambda r: r["checks"][-1].update(start_error={"message": "missing"}),
            "larger_limit": lambda r: r["checks"][-1].update(timeout_seconds=181),
            "boolean_code": lambda r: r["checks"][-1].update(exit_code=False),
            "nan_elapsed": lambda r: r["checks"][-1].update(elapsed_seconds=float("nan")),
            "command": lambda r: r["checks"][-1]["command"].append("--skip"),
            "omitted": lambda r: r["checks"].pop(),
            "duplicate": lambda r: r["checks"].append(copy.deepcopy(r["checks"][-1])),
            "source": lambda r: r["source_sha256"].update(fixture="different"),
            "summary": lambda r: r["checks"][-1].update(summary={"invented": True}),
            "promoted": lambda r: r.update(whole_runtime_replaced=True),
            "boolean_retyped": lambda r: r.update(whole_runtime_replaced=0),
            "cold": lambda r: r["checks"][0].update(name="different-cold"),
            "group": lambda r: r["qualification_shard"].update(group="batch"),
            "invocation": lambda r: r["qualification_shard"].update(invocation="other-run"),
            "unreported_failure": lambda r: r.update(native_parallel_drain_errors=[{"failed": True}]),
        }
        for name, change in mutations.items():
            altered = copy.deepcopy(report); change(altered)
            self.reseal_fixture(destination, altered)
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                self.admit_fixture(source, prepared, destination)
        self.reseal_fixture(destination, report)
        self.admit_fixture(source, prepared, destination)

    def test_physical_output_corruption_is_refused_even_after_manifest_rehash(self):
        source, prepared, report, destination = self.actual_fixture()
        for name in ("check.py.stdout", "check.py.stderr"):
            path = destination / "data" / name; original = path.read_bytes()
            path.write_bytes(original + b"changed")
            self.reseal_fixture(destination, report)
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "output bytes differ"):
                self.admit_fixture(source, prepared, destination)
            path.write_bytes(original)
        self.reseal_fixture(destination, report)
        self.admit_fixture(source, prepared, destination)

    def test_stale_build_hash_and_cross_invocation_fail_before_execution(self):
        output = self.root / "prepared"; output.mkdir()
        q.save_report(output / p.BUILD_SEAL, {"schema": "hepta.runtime.native-build.v1",
            "context": {"invocation": "another-workflow"}, "files": {}, "directories": [], "partitions": {}})
        with self.assertRaisesRegex(ValueError, "workflow build SHA256"):
            p.admit_prepared(output, self.root, "f" * 64, "expected")
        with self.assertRaisesRegex(ValueError, "source, invocation"):
            p.admit_prepared(output, self.root, p.digest(output / p.BUILD_SEAL), "expected")

    def test_missing_or_duplicate_shards_cannot_reach_evidence_owners(self):
        source, prepared, report, destination = self.actual_fixture()
        shards = self.root / "shards"; shards.mkdir()
        for group in ("one", "two", "three", "four", "five", "six"):
            shutil.copytree(destination, shards / group)
        output = self.root / "collect"; output.mkdir()
        with patch.object(p, "admit_prepared", return_value=({"files": {}}, prepared, object())), \
                patch.object(p, "admit_shard", return_value=(p.read_json(destination / "shard.json"), report)), \
                patch.object(q, "collect_native_evidence") as evidence:
            with self.assertRaisesRegex(ValueError, "duplicate or unknown"):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()
            self.assertEqual(p.read_json(output / "result.json")["status"], "FAIL")
            shutil.rmtree(shards / "six")
            with self.assertRaisesRegex(ValueError, "exactly six"):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()

    def test_six_actual_partitions_merge_once_and_retained_bytes_stay_binding(self):
        from contextlib import ExitStack
        from datetime import datetime, timezone
        source = self.root / "source"
        tests = source / "tests/hia_native"; tests.mkdir(parents=True)
        output = self.root / "aggregate"; output.mkdir()
        artifacts = self.root / "shards"; artifacts.mkdir()
        registry = {group: (group + "_fixture.py",) for group in p.PARTITIONS}
        names = tuple(name for group in registry.values() for name in group)
        prepared = {"status": "NATIVE_BUILD_READY", "phase": "native_build_complete",
            "native_components_status": "PENDING", "compiler_checkout": str(self.root / "compiler"),
            "started_at": datetime.now(timezone.utc).isoformat(), "whole_runtime_replaced": False,
            "source_sha256": {"synthetic_reporting_fixture": "unchanged"},
            "checks": [{"name": "compiler-full-cold", "command":
                       ["synthetic-cold-identity-only", "--output", str(output / "compiler-cold.json")]}]}
        for group, (name,) in registry.items():
            (tests / name).write_text("import json\nprint(json.dumps({'actual_reporting_group':" + repr(group) + "}))\n")
            run = self.root / group; run.mkdir()
            report = copy.deepcopy(prepared)
            report.update(status="RUNNING", phase="native_components", native_components_status="RUNNING",
                qualification_shard={"group": group, "invocation": "five-actual-processes",
                                     "prepared_sha256": "b" * 64, "tests": [name]})
            with patch.object(q, "ROOT", source):
                q.run_native_checks(run, report, (name,), q.qualification_env(), parallel_tests=(),
                                    ordered_groups=(), timeout=180)
            report.update(status="NATIVE_SHARD_PASS", phase="native_shard_complete", native_components_status="PARTIAL",
                          shard_elapsed_seconds=report["checks"][-1]["elapsed_seconds"], shard_finished_at="fixture")
            p.export_shard(run, artifacts / group, {"files": {}}, report)
        def finish(_, report, builder):
            report.update(status="NATIVE_COMPONENTS_PASS", native_components_status="PASS")
        with ExitStack() as stack:
            stack.enter_context(patch.object(q, "ROOT", source))
            stack.enter_context(patch.object(p, "partition_tests", return_value=registry))
            stack.enter_context(patch.object(q, "native_tests", return_value=names))
            stack.enter_context(patch.object(q, "native_commands", return_value={}))
            stack.enter_context(patch.object(p, "admit_prepared", return_value=({"files": {}}, prepared, object())))
            evidence = stack.enter_context(patch.object(q, "collect_native_evidence"))
            stack.enter_context(patch.object(q, "finish_native", side_effect=finish))
            result = p.collect(output, self.root / "compiler", "b" * 64, "five-actual-processes", artifacts)
            self.assertEqual(result["checks"], 7)
            evidence.assert_called_once()
            report = p.read_json(output / "result.json")
            self.assertEqual([row["name"] for row in report["checks"][1:]], list(names))
            p.verify_pipeline_receipts(output, report)
            # A native row cannot be counted a second time as a later phase.
            duplicated = copy.deepcopy(report); duplicated["checks"].append(report["checks"][1])
            with self.assertRaisesRegex(ValueError, "aggregate process records"):
                p.verify_pipeline_receipts(output, duplicated)
            # Complete raw shard reports remain binding after collection.
            saved = output / "qualification-shards/text/shard-report.json"
            original = saved.read_bytes(); saved.write_bytes(original + b" ")
            with self.assertRaisesRegex(ValueError, "retained shard receipt changed"):
                p.verify_pipeline_receipts(output, report)
            saved.write_bytes(original)
            path = output / (names[0] + ".stderr"); path.write_bytes(b"later corruption")
            with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
                p.verify_pipeline_receipts(output, report)


if __name__ == "__main__":
    unittest.main()
