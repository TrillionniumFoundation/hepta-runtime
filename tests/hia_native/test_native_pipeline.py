"""Actual-process controls for native artifact partitioning and evidence admission.

Small temporary programs test the reporting machinery. They never qualify a
production HIA image or stand in for a compiler cold replay.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import hia_native_pipeline as p
import qualify_hia_runtime_native as q


class NativePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-pipeline-reporting-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_partition_is_complete_unique_and_keeps_evidence_dependencies(self):
        partitions = p.partition_tests()
        flat = [name for tests in partitions.values() for name in tests]
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(set(flat), set(q.native_tests()))
        self.assertEqual(tuple(partitions["batch"]),
            ("test_batch_plan.py", "test_batch_plan_evidence.py", "test_batch_apply.py",
             "test_batch_apply_contract.py", "test_batch_apply_artifacts.py", "test_batch_apply_evidence.py",
             "test_atomic_write_policy.py", "test_atomic_write_kernel.py", "test_atomic_write_boundary.py",
             "test_atomic_write_evidence.py"))
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
        for group in ("one", "two", "three", "four"):
            shutil.copytree(destination, shards / group)
        output = self.root / "collect"; output.mkdir()
        with patch.object(p, "admit_prepared", return_value=({"files": {}}, prepared, object())), \
                patch.object(p, "admit_shard", return_value=(p.read_json(destination / "shard.json"), report)), \
                patch.object(q, "collect_native_evidence") as evidence:
            with self.assertRaisesRegex(ValueError, "duplicate or unknown"):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()
            self.assertEqual(p.read_json(output / "result.json")["status"], "FAIL")
            shutil.rmtree(shards / "four")
            with self.assertRaisesRegex(ValueError, "exactly four"):
                p.collect(output, self.root, "a" * 64, "reporting-fixture", shards)
            evidence.assert_not_called()

    def test_four_actual_partitions_merge_once_and_retained_bytes_stay_binding(self):
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
                qualification_shard={"group": group, "invocation": "four-actual-processes",
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
            result = p.collect(output, self.root / "compiler", "b" * 64, "four-actual-processes", artifacts)
            self.assertEqual(result["checks"], 5)
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


class ShellProcessPipelineTests(unittest.TestCase):
    """Small actual reporting processes; none of these replace native OS cases."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hia-shell-pipeline-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def registry_report(self):
        return {"phase": "native_components", "checks": [], "modules": {
            "shell_process": {"manifest": "build/shell-process/manifest.json"},
            "shell_background_text": {"manifest": "build/modules/shell-background-text/manifest.json"}}}

    def test_shell_registry_keeps_process_text_and_original_domains_distinct(self):
        import compare_hia_runtime_rust as original
        from check_hia_native_inventory import inspect
        self.assertEqual(len(q.MODULES), 42)
        self.assertEqual(len(q.native_tests()), 100)
        self.assertEqual(len(original.RECIPES), 37)
        self.assertEqual(q.SHELL_PROCESS_TESTS, (
            "shell_process_state.py", "shell_process_transport.py",
            "hia_native_shell_process_qualification.py", "shell_process_evidence_controls.py"))
        text = p.partition_tests()["text"]
        required = (*q.SHELL_PROCESS_TESTS, q.SHELL_BACKGROUND_TEST)
        self.assertEqual(tuple(name for name in text if name in required), required)
        self.assertNotIn("shell_process", original.NEW_COMPONENTS)
        self.assertNotIn("shell_background_text", original.NEW_COMPONENTS)
        self.assertIs(original.RECIPES["shell_process"], original.compare_shell_process)
        self.assertIs(original.RECIPES["shell_background_text"], original.compare_shell_background)
        inventory = inspect(ROOT)
        self.assertEqual(len(inventory["native_sources"]), 69)
        self.assertEqual(inventory["legacy_tool_count"], 125)
        self.assertEqual(inventory["native_production_tool_count"], 0)
        self.assertIs(inventory["whole_runtime_replaced"], False)
        self.assertIs(inventory["production_activated"], False)

    def test_shell_source_closure_includes_every_new_owner_producer_and_reader(self):
        source = q.sources()
        for relative in (
                "native/shell_process.hepta", "native/shell_process_packer.hepta",
                "native/shell_background_text.hepta",
                "scripts/hia_native_shell_process_build.py",
                "scripts/hia_native_shell_process_qualification.py",
                "scripts/hia_native_shell_process_reference.py",
                "scripts/hia_native_shell_process_evidence.py",
                "scripts/shell_process_adapter.S", "scripts/qualify_hia_shell_process.py",
                ".github/workflows/hia-runtime-shell-process.yml",
                "tests/hia_native/shell_process_state.py",
                "tests/hia_native/shell_process_transport.py",
                "tests/hia_native/shell_process_cases.py",
                "tests/hia_native/shell_process_evidence_controls.py",
                "tests/hia_native/shell_background_text.py",
                "src/mcp/fs/background.rs", "src/mcp/fs/background_tests.rs"):
            with self.subTest(relative=relative):
                self.assertEqual(source.get(relative), q.sha(ROOT / relative))

    def progress_rows(self, original=False):
        module = q._shell_test_module("shell_process_cases.py")
        rows = [{"name": row["name"], "status": "PASS", "duration_ns": 1, "error": None}
                for row in module.specs()]
        rows.reverse()  # Completion order need not equal declaration order.
        rows.append({"status": "ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS",
                     "case_count": 38, "report": str(self.root / "actual-case-report.json")})
        return rows

    def actual_progress(self, folder, rows, *, original=False, raw=None):
        folder.mkdir()
        program = folder / "progress.py"
        data = raw if raw is not None else b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)
        program.write_text("import sys\nsys.stdout.buffer.write(" + repr(data) + ")\n")
        name = "shell-process-rust-compare" if original else q.SHELL_PROCESS_TESTS[2]
        report = {"phase": "reporting-regression", "checks": []}
        q.record_check(folder, report, name=name,
                       command=[sys.executable, "-I", "-B", str(program),
                                "--output", str(folder / "case-output")], timeout=2)
        return name, report

    def test_actual_shell_progress_requires_all_38_successful_case_records(self):
        for original in (False, True):
            folder = self.root / ("original" if original else "native")
            rows = self.progress_rows(original)
            rows[-1]["report"] = str(folder / "case-output/report.json")
            name, report = self.actual_progress(folder, rows, original=original)
            row, summary = q.completed_test_summary(folder, report, name)
            q.shell_completed_process(folder, report, name, row["command"],
                phase="reporting-regression", timeout=2,
                status="ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")
            wrong_command = list(row["command"])
            wrong_command[-1] = str(folder / "foreign-case-output")
            changed = copy.deepcopy(report)
            changed["checks"][0]["command"] = wrong_command
            with self.assertRaisesRegex(ValueError, "different output directory"):
                q.shell_completed_process(folder, changed, name, wrong_command,
                    phase="reporting-regression", timeout=2,
                    status="ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")
            self.assertEqual(row["exit_code"], 0)
            self.assertEqual(summary["case_count"], 38)
            self.assertEqual(summary["status"], "ORIGINAL_COMPARISON_PASS" if original else "NATIVE_ONLY_PASS")

    def test_trailing_pass_cannot_cover_actual_missing_duplicate_or_failed_progress(self):
        changes = {
            "missing": lambda rows: rows.pop(0),
            "duplicate": lambda rows: rows.__setitem__(0, dict(rows[1])),
            "failed": lambda rows: rows[0].update(status="FAIL", error="actual failure"),
            "unknown": lambda rows: rows[0].update(name="unregistered"),
            "boolean_duration": lambda rows: rows[0].update(duration_ns=True),
            "negative_duration": lambda rows: rows[0].update(duration_ns=-1),
            "extra_field": lambda rows: rows[0].update(ignored=False),
            "wrong_scope": lambda rows: rows[-1].update(status="ORIGINAL_COMPARISON_PASS"),
            "relative_report": lambda rows: rows[-1].update(report="report.json"),
            "boolean_count": lambda rows: rows[-1].update(case_count=True),
            "extra_pass": lambda rows: rows.append(dict(rows[-1])),
        }
        for label, change in changes.items():
            rows = self.progress_rows()
            change(rows)
            folder = self.root / label
            name, report = self.actual_progress(folder, rows)
            with self.subTest(label=label), self.assertRaises(ValueError):
                q.completed_test_summary(folder, report, name)
            self.assertNotIn("summary", report["checks"][0])
            self.assertEqual(report["checks"][0]["exit_code"], 0)
            self.assertTrue((folder / (name + ".stdout")).is_file())

        rows = self.progress_rows()
        raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)
        raw = raw.replace(b'"status": "PASS"', b'"status": "FAIL", "status": "PASS"', 1)
        folder = self.root / "duplicate-json-field"
        name, report = self.actual_progress(folder, rows, raw=raw)
        with self.assertRaisesRegex(ValueError, "duplicate real-OS shell progress field"):
            q.completed_test_summary(folder, report, name)

    def test_shell_launcher_refuses_partial_or_foreign_cli_before_start(self):
        report = self.registry_report()
        name = q.SHELL_PROCESS_TESTS[2]
        commands = q.shell_process_test_commands(self.root, report)
        command = commands[name]
        self.assertEqual(command[3], str(ROOT / "scripts/hia_native_shell_process_qualification.py"))
        self.assertEqual(command[command.index("--output") + 1], str(self.root / "shell-process/native-os"))
        mutations = [
            command + ["--case", "only-one"],
            command + ["--oracle-executable", "/different/reference"],
            command[:-2],
            [*command[:3], str(ROOT / "tests/hia_native/shell_process_cases.py"), *command[4:]],
        ]
        wrong_output = list(command)
        wrong_output[wrong_output.index("--output") + 1] = str(self.root / "foreign")
        mutations.append(wrong_output)
        for bad in mutations:
            with self.subTest(command=bad), patch.object(q, "record_check") as launch:
                with self.assertRaisesRegex(ValueError, "source-owned suite"):
                    q.run_native_checks(self.root, report, (name,), q.qualification_env(),
                        parallel_tests=(), ordered_groups=(), commands={name: bad})
                launch.assert_not_called()

    def test_actual_control_process_starts_only_after_fixture_retirement(self):
        source = self.root / "source"
        tests = source / "tests/hia_native"
        tests.mkdir(parents=True)
        name = q.SHELL_PROCESS_TESTS[3]
        (tests / name).write_text(
            "from pathlib import Path\nimport json,sys\n"
            "folder=Path(sys.argv[sys.argv.index('--output')+1])\n"
            "assert (folder.parent/'native-os'/'retired').read_bytes()==b'complete snapshot'\n"
            "print(json.dumps({'status':'PASS','actual_retirement_order_fixture':True}))\n")
        output = self.root / "output"
        output.mkdir()
        (output / "shell-process/native-os").mkdir(parents=True)
        def retirement(folder, report):
            (folder / "shell-process/native-os/retired").write_bytes(b"complete snapshot")
        report = self.registry_report()
        with patch.object(q, "ROOT", source), patch.object(q, "retire_shell_process_native", side_effect=retirement) as retire:
            commands = q.shell_process_test_commands(output, report)
            q.run_native_checks(output, report, (name,), q.qualification_env(),
                                parallel_tests=(), ordered_groups=(), commands={name: commands[name]})
            retire.assert_called_once_with(output, report)
        self.assertEqual(report["checks"][0]["exit_code"], 0)
        self.assertIs(report["checks"][0]["summary"]["actual_retirement_order_fixture"], True)

        refused = self.root / "refused"
        refused.mkdir()
        report = self.registry_report()
        with patch.object(q, "ROOT", source), patch.object(q, "retire_shell_process_native", side_effect=ValueError("unreaped child")):
            commands = q.shell_process_test_commands(refused, report)
            with self.assertRaisesRegex(ValueError, "unreaped child"):
                q.run_native_checks(refused, report, (name,), q.qualification_env(),
                                    parallel_tests=(), ordered_groups=(), commands={name: commands[name]})
        self.assertFalse((refused / (name + ".stdout")).exists())
        self.assertEqual(report["checks"], [])

    def test_shell_completed_record_rejects_retyped_or_recounted_actual_receipts(self):
        program = self.root / "pass.py"
        program.write_text("import json\nprint(json.dumps({'status':'PASS'}))\n")
        name = "shell-reporting-fixture"
        command = [sys.executable, "-I", "-B", str(program)]
        report = {"phase": "native_components", "checks": []}
        q.record_check(self.root, report, name=name, command=command, timeout=180)
        q.shell_completed_process(self.root, report, name, command, phase="native_components", timeout=180)
        changes = {
            "boolean_exit": {"exit_code": False},
            "short_stdout": {"stdout_bytes": 0},
            "boolean_stderr": {"stderr_bytes": False},
            "negative_elapsed": {"elapsed_seconds": -1},
            "nan_elapsed": {"elapsed_seconds": float("nan")},
            "empty_start_error": {"start_error": {}},
            "changed_phase": {"phase": "original_rust_comparison"},
            "larger_deadline": {"timeout_seconds": 181},
        }
        for name_mutation, values in changes.items():
            altered = copy.deepcopy(report)
            altered["checks"][0].update(values)
            with self.subTest(mutation=name_mutation), self.assertRaises(ValueError):
                q.shell_completed_process(self.root, altered, name, command,
                                          phase="native_components", timeout=180)

    def test_original_commands_require_one_fresh_build_and_separate_os_fixtures(self):
        import compare_hia_runtime_rust as original
        report = self.registry_report()
        rustc = self.root / "selected/rustc"
        cargo = self.root / "selected/cargo"
        with patch.object(original, "executable", return_value=cargo):
            commands = original.shell_process_original_commands(self.root, report, rustc)
        build = commands["shell-process-rust-build"]
        compare = commands["shell-process-rust-compare"]
        background = commands["shell-background-rust-compare"]
        build_output = self.root / "shell-process-original/build"
        self.assertEqual(build[build.index("--output") + 1], str(build_output))
        self.assertEqual(compare[compare.index("--oracle-build-manifest") + 1], str(build_output / "result.json"))
        self.assertEqual(compare[compare.index("--output") + 1], str(self.root / "shell-process-original/cases"))
        self.assertEqual(background[background.index("--reference-build") + 1], str(build_output))
        self.assertEqual(background[background.index("--background-corpus") + 1],
                         str(self.root / "shell-background-text/native"))
        self.assertNotIn("--offline", build)
        self.assertNotIn("--case", compare)


    def test_original_dependency_order_survives_actual_sorted_json_round_trip(self):
        import compare_hia_runtime_rust as original
        program = self.root / "original-reporting-fixture.py"
        program.write_text(
            "from pathlib import Path\nimport json,sys\n"
            "kind=sys.argv[1];root=Path(sys.argv[2])\n"
            "if kind=='producer': (root/'fresh-build').write_bytes(b'complete')\n"
            "elif kind=='consumer':\n"
            " assert (root/'fresh-build').read_bytes()==b'complete'\n"
            " (root/'compared').write_bytes(b'complete')\n"
            "print(json.dumps({'status':'PASS','actual_reporting_role':kind}))\n")
        report = {"phase": "original_rust_comparison", "checks": [],
                  "modules": {"shell_process": {}, "shell_background_text": {}, "system_entropy": {}},
                  "original_rust_comparisons": {}, "whole_runtime_replaced": False}
        q.save_report(self.root / "round-trip.json", report)
        report = json.loads((self.root / "round-trip.json").read_bytes())
        self.assertEqual(next(iter(report["modules"])), "shell_background_text")

        def recipe(kind, name):
            def run(output, report, rustc, *, report_path=None):
                q.record_check(output, report, name=name,
                    command=[sys.executable, "-I", "-B", str(program), kind, str(self.root)],
                    timeout=2, report_path=report_path)
                return {"status": "PASS", "actual_reporting_role": kind}
            return run
        recipes = {
            "shell_process": recipe("producer", "process-producer-fixture"),
            "shell_background_text": recipe("consumer", "background-consumer-fixture"),
            "system_entropy": recipe("worker", "independent-worker-fixture")}
        parallel = {"system_entropy": ("independent-worker.execution.json", ("independent-worker-fixture",))}
        with patch.object(original, "RECIPES", recipes), patch.object(original, "PARALLEL_RUST_RECIPES", parallel):
            original.run_rust_recipes(self.root, report, Path(sys.executable))
        names = [row["name"] for row in report["checks"]]
        self.assertLess(names.index("process-producer-fixture"), names.index("background-consumer-fixture"))
        self.assertEqual((self.root / "compared").read_bytes(), b"complete")
        self.assertEqual(set(report["original_rust_comparisons"]), set(recipes))
        private = json.loads((self.root / "independent-worker.execution.json").read_bytes())
        self.assertEqual(private["checks"][0]["name"], "independent-worker-fixture")
        self.assertEqual(private["checks"][0]["exit_code"], 0)
        with self.assertRaisesRegex(ValueError, "producer must precede"):
            original.rust_recipe_order({"modules": {"shell_background_text": {}}})
        with self.assertRaisesRegex(ValueError, "module inventory"):
            original.rust_recipe_order({"modules": {"unregistered": {}}})
        reversed_modules = tuple(reversed(original.MODULES))
        with patch.object(original, "MODULES", reversed_modules), self.assertRaisesRegex(ValueError, "producer must precede"):
            original.rust_recipe_order(report)



if __name__ == "__main__":
    unittest.main()
