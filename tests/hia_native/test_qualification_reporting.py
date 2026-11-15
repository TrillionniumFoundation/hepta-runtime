"""Regressions for qualification failures and preserved subprocess evidence."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def wait_fixture(self, programs):
        root = self.output / "source"
        folder = root / "tests/hia_native"
        folder.mkdir(parents=True)
        prefix = "from pathlib import Path\nimport json, os, sys, time\nroot=Path(__file__).resolve().parents[2]\n"
        for name, program in programs.items():
            (folder / name).write_text(prefix + program)
        return root

    def test_storage_actual_completion_binds_wait_pid_and_complete_streams(self):
        import qualify_hia_runtime_native as qualifier
        helper = qualifier.storage_pipeline
        name = helper.NAMES['storage_json']
        command = [sys.executable, '-I', '-B', '-c',
            "import json,os;print(json.dumps({'status':'PASS','actual_pid':os.getpid()}))"]
        qualifier.record_check(self.output, self.report, name=name, command=command, timeout=180)
        receipt, summary = helper.completed_process(ROOT, self.output, self.report, name,
            command, qualifier.completed_test_summary)
        self.assertEqual(receipt['pid'], summary['actual_pid'])
        self.assertTrue(receipt['process_reaped'])
        self.assertFalse(receipt['outer_parent_death_cleanup_qualified'])
        self.assertEqual(receipt['actual_aggregate_check'], self.report['checks'][0])
        folder = helper.process_folder(self.output, name)
        original = (folder / 'stdout').read_bytes()
        (folder / 'stdout').write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'stream changed'):
            helper.completed_process(ROOT, self.output, self.report, name,
                command, qualifier.completed_test_summary)
        (folder / 'stdout').write_bytes(original)
        helper.completed_process(ROOT, self.output, self.report, name,
            command, qualifier.completed_test_summary)

    def test_storage_control_launcher_imports_under_isolation_from_any_cwd(self):
        import subprocess
        import qualify_hia_runtime_native as qualifier
        helper = qualifier.storage_pipeline
        command = helper.control_command(ROOT, self.output) + ['--help']
        actual = subprocess.run(command, cwd=self.output, env=qualifier.qualification_env(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False)
        self.assertEqual(actual.returncode, 0, actual.stderr.decode(errors='replace'))
        self.assertFalse(actual.stderr)
        self.assertIn(b'--run-controls', actual.stdout)

    def test_storage_success_retires_its_actual_descendant_group(self):
        import os
        import time
        import qualify_hia_runtime_native as qualifier
        helper = qualifier.storage_pipeline;name = helper.NAMES['record_validation']
        pid_file = self.output / 'owned-child.pid'
        program = ("import subprocess,sys,pathlib,json\n"
            "p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(60)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "pathlib.Path(sys.argv[1]).write_text(str(p.pid))\n"
            "print(json.dumps({'status':'PASS','owned_child':p.pid}))\n")
        command = [sys.executable, '-I', '-B', '-c', program, str(pid_file)]
        qualifier.record_check(self.output, self.report, name=name, command=command, timeout=180)
        child = int(pid_file.read_text());deadline = time.monotonic() + 3
        while True:
            path = Path('/proc') / str(child) / 'stat'
            if not path.exists() or path.read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                break
            if time.monotonic() >= deadline:
                os.kill(child, 9)
                self.fail('the source-owned process group retained a live descendant')
            time.sleep(.005)
        helper.completed_process(ROOT, self.output, self.report, name,
            command, qualifier.completed_test_summary)

    def test_storage_failure_and_timeout_preserve_actual_refusals(self):
        import qualify_hia_runtime_native as qualifier
        helper = qualifier.storage_pipeline
        cases = ((helper.NAMES['safe_dto'], "print('original failure',flush=True);raise SystemExit(7)", 180),
                 (helper.NAMES['retention'], "import time;print('before timeout',flush=True);time.sleep(60)", 1))
        for name, program, timeout in cases:
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                qualifier.record_check(self.output, self.report, name=name,
                    command=[sys.executable, '-I', '-B', '-c', program], timeout=timeout)
            row = json.loads((helper.process_folder(self.output, name) / 'result.json').read_bytes())
            self.assertNotEqual(row['exit_code'], 0)
            self.assertTrue(row['process_reaped'])
            self.assertEqual(row['timed_out'], timeout != 180)
            self.assertTrue((helper.process_folder(self.output, name) / 'stdout').read_bytes())

    def test_storage_completion_refuses_changed_limits_and_consistent_argv_edits(self):
        import copy
        import qualify_hia_runtime_native as qualifier
        helper = qualifier.storage_pipeline;name = helper.NAMES['storage_json']
        command = [sys.executable, '-I', '-B', '-c', "print('{\"status\":\"PASS\"}')"]
        qualifier.record_check(self.output, self.report, name=name, command=command, timeout=180)
        folder = helper.process_folder(self.output, name);path = folder / 'result.json'
        original = path.read_bytes();baseline = copy.deepcopy(self.report['checks'][0])
        for key, changed in (('command', command + ['--unobserved']), ('timeout_seconds', 181), ('timed_out', True)):
            row = copy.deepcopy(baseline);row[key] = changed;self.report['checks'][0] = row
            private = json.loads(original);private[key] = changed;private['actual_aggregate_check'] = row
            path.write_text(json.dumps(private))
            with self.subTest(key=key), self.assertRaises(ValueError):
                helper.completed_process(ROOT, self.output, self.report, name,
                    command, qualifier.completed_test_summary)
        self.report['checks'][0] = baseline;path.write_bytes(original)
        helper.completed_process(ROOT, self.output, self.report, name,
            command, qualifier.completed_test_summary)

    def test_independent_wait_process_runs_during_sequential_work(self):
        import qualify_hia_runtime_native as qualifier
        root = self.wait_fixture({
            "wait.py": "(root/'ready').write_text('ready')\n"
                       "deadline=time.monotonic()+3\n"
                       "while not (root/'release').exists():\n"
                       " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                       "print(json.dumps({'owner':'wait','released':True}))\n",
            "serial.py": "deadline=time.monotonic()+3\n"
                         "while not (root/'ready').exists():\n"
                         " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                         "(root/'release').write_text('release')\n"
                         "print(json.dumps({'owner':'serial','observed_wait':True}))\n",
        })
        with patch.object(qualifier, "ROOT", root):
            qualifier.run_native_checks(self.output, self.report, ("serial.py", "wait.py"),
                                        {}, parallel_tests=("wait.py",), timeout=5)
        self.assertEqual([row["name"] for row in self.report["checks"]], ["serial.py", "wait.py"])
        self.assertEqual([row["exit_code"] for row in self.report["checks"]], [0, 0])
        private = json.loads((self.output / "wait.py.execution.json").read_bytes())
        self.assertEqual(private["checks"], [self.report["checks"][1]])
        self.assertEqual(len(self.report["native_parallel_receipts"]), 1)
        self.assertEqual(json.loads((self.output / "result.json").read_bytes()), self.report)

    def test_independent_wait_failure_retains_the_actual_failed_process(self):
        import qualify_hia_runtime_native as qualifier
        root = self.wait_fixture({"serial.py": "print(json.dumps({'serial':True}))\n",
                                  "failed.py": "print(json.dumps({'original_failure':True}))\nsys.exit(7)\n"})
        with patch.object(qualifier, "ROOT", root), self.assertRaisesRegex(RuntimeError, "failed.py failed"):
            qualifier.run_native_checks(self.output, self.report, ("serial.py", "failed.py"),
                                        {}, parallel_tests=("failed.py",), timeout=5)
        self.assertEqual([row["exit_code"] for row in self.report["checks"]], [0, 7])
        self.assertFalse(self.report["checks"][1]["timed_out"])
        self.assertEqual(json.loads((self.output / "failed.py.stdout").read_bytes()), {"original_failure": True})
        self.assertEqual(json.loads((self.output / "failed.py.execution.json").read_bytes())["checks"],
                         [self.report["checks"][1]])

    def test_sequential_failure_drains_already_submitted_wait_process(self):
        import qualify_hia_runtime_native as qualifier
        root = self.wait_fixture({"serial.py": "(root/'release').write_text('release')\n"
                                  "print(json.dumps({'original_failure':True}))\nsys.exit(9)\n",
                                  "wait.py": "deadline=time.monotonic()+3\n"
                                  "while not (root/'release').exists():\n"
                                  " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                                  "print(json.dumps({'finished_after_sequential_failure':True}))\n"})
        with patch.object(qualifier, "ROOT", root), self.assertRaisesRegex(RuntimeError, "serial.py failed"):
            qualifier.run_native_checks(self.output, self.report, ("serial.py", "wait.py"),
                                        {}, parallel_tests=("wait.py",), timeout=5)
        self.assertEqual([row["exit_code"] for row in self.report["checks"]], [9, 0])
        self.assertEqual(len(self.report["native_parallel_receipts"]), 1)
        self.assertNotIn("native_parallel_drain_errors", self.report)
        self.assertEqual(json.loads((self.output / "result.json").read_bytes()), self.report)

    def test_independent_wait_timeout_is_not_reported_as_completion(self):
        import qualify_hia_runtime_native as qualifier
        root = self.wait_fixture({"serial.py": "print(json.dumps({'serial':True}))\n",
                                  "timeout.py": "print(json.dumps({'entered':True}),flush=True)\ntime.sleep(60)\n"})
        with patch.object(qualifier, "ROOT", root), self.assertRaisesRegex(RuntimeError, "timeout.py timed out"):
            qualifier.run_native_checks(self.output, self.report, ("serial.py", "timeout.py"),
                                        {}, parallel_tests=("timeout.py",), timeout=.4)
        check = self.report["checks"][1]
        self.assertTrue(check["timed_out"])
        self.assertEqual(check["exit_code"], -9)
        self.assertEqual(check["timeout_seconds"], .4)
        self.assertEqual(json.loads((self.output / "timeout.py.stdout").read_bytes()), {"entered": True})
        self.assertEqual(json.loads((self.output / "timeout.py.execution.json").read_bytes())["checks"], [check])

    def test_ordered_independent_group_overlaps_and_preserves_internal_order(self):
        import qualify_hia_runtime_native as q
        root = self.wait_fixture({
            "first.py": "(root/'ready').write_text('ready')\n"
                        "deadline=time.monotonic()+3\nwhile not (root/'release').exists():\n"
                        " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                        "(root/'first-done').write_text('done')\nprint(json.dumps({'first':True}))\n",
            "second.py": "assert (root/'first-done').read_text()=='done'\n"
                         "assert sys.argv[1:]==['--owned-output','two words']\nprint(json.dumps({'second':True}))\n",
            "main.py": "deadline=time.monotonic()+3\nwhile not (root/'ready').exists():\n"
                       " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                       "(root/'release').write_text('release')\nprint(json.dumps({'main':True}))\n"})
        commands = {"second.py": [sys.executable, "-I", "-B", str(root / "tests/hia_native/second.py"),
                                   "--owned-output", "two words"]}
        with patch.object(q, "ROOT", root):
            q.run_native_checks(self.output, self.report, ("main.py", "first.py", "second.py"), {},
                parallel_tests=(), ordered_groups=(("first.py", "second.py"),), commands=commands, timeout=5)
        self.assertEqual([r["name"] for r in self.report["checks"]], ["main.py", "first.py", "second.py"])
        self.assertEqual(len(self.report["native_parallel_receipts"]), 2)
        self.assertTrue(all(r["exit_code"] == 0 and not r["timed_out"] for r in self.report["checks"]))

    def test_ordered_group_retains_failure_and_runs_its_submitted_successor(self):
        import qualify_hia_runtime_native as q
        root = self.wait_fixture({"main.py": "print('{}')\n", "first.py": "print('{}')\nsys.exit(17)\n",
                                  "second.py": "print(json.dumps({'successor_ran':True}))\n"})
        with patch.object(q, "ROOT", root), self.assertRaisesRegex(RuntimeError, "first.py failed"):
            q.run_native_checks(self.output, self.report, ("main.py", "first.py", "second.py"), {},
                parallel_tests=(), ordered_groups=(("first.py", "second.py"),), timeout=5)
        self.assertEqual([r["exit_code"] for r in self.report["checks"]], [0, 17, 0])
        self.assertEqual(len(self.report["native_parallel_receipts"]), 2)
        self.assertEqual(json.loads((self.output / "second.py.stdout").read_bytes()), {"successor_ran": True})

    def test_scheduler_refuses_partial_groups_and_foreign_commands_before_launch(self):
        import qualify_hia_runtime_native as q
        for settings in ({"ordered_groups": (("one.py", "missing.py"),)},
                         {"commands": {"one.py": ["/foreign/program"]}},
                         {"commands": {"missing.py": [sys.executable]}},
                         {"parallel_tests": ("one.py",), "ordered_groups": (("one.py",),)}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                q.run_native_checks(self.output, self.report, ("one.py",), {}, **settings)
        self.assertEqual(self.report["checks"], [])

    def test_config_registry_and_retained_original_require_complete_regex_dependency(self):
        import qualify_hia_runtime_native as q
        import compare_hia_runtime_rust as comparison
        helper = q.config_qualification
        entry = {row["key"]: row for row in MODULES}["runtime_config"]
        self.assertEqual((entry["test"], *entry["additional_tests"]), helper.TESTS)
        self.assertEqual(len(helper.CONFIG_TESTS), 6)
        self.assertEqual(len(helper.regex_qualification.TESTS), 9)
        native_sources = {entry["source"], *entry["companion_sources"]}
        for row in helper.MODULES.values():
            self.assertIn(row["source"], native_sources | {"native/serde_json.hepta",
                          "native/execution_shadow.hepta", "native/execution_json.hepta",
                          "native/execution_controller.hepta"})
        pinned = sources()
        for name in helper.regex_qualification.OWN:
            self.assertIn(name, pinned)
        self.assertIn("tests/hia_native/check_regex_evidence.py", pinned)
        with patch.object(helper, "original_evidence", return_value={"config": "actual-completed"}), \
                patch.object(helper, "regex_original_evidence", return_value={"regex": "actual-completed"}):
            self.assertEqual(comparison.retained_config_original(self.output, self.report),
                             {"configuration": {"config": "actual-completed"},
                              "regex": {"regex": "actual-completed"}})
        for missing in ("original_evidence", "regex_original_evidence"):
            with patch.object(helper, "original_evidence", return_value={}), \
                    patch.object(helper, "regex_original_evidence", return_value={}), \
                    patch.object(helper, missing, side_effect=ValueError("missing complete replay")), \
                    self.assertRaisesRegex(ValueError, "missing complete replay"):
                comparison.retained_config_original(self.output, self.report)

    def test_config_launcher_requires_the_complete_source_owned_command(self):
        import qualify_hia_runtime_native as q
        helper = q.config_qualification
        name = helper.TESTS[0]
        root = self.wait_fixture({name: "print(json.dumps({'actual_owned_launcher':True}))\n"})
        expected = helper.launch(root, "tests/hia_native/" + name, [])
        with patch.object(q, "ROOT", root), patch.object(helper, "test_commands", return_value={name: expected}):
            q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                ordered_groups=(), commands={name: expected}, timeout=5)
            self.assertEqual(self.report["checks"][0]["command"], expected)
            self.assertEqual(json.loads((self.output / (name + ".stdout")).read_bytes()),
                             {"actual_owned_launcher": True})
            for argv in (expected + ["--foreign-argument"], expected[:4] + ["print('{}')"] + expected[5:],
                         [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name)]):
                with self.subTest(command=argv), self.assertRaises(ValueError):
                    q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                        ordered_groups=(), commands={name: argv}, timeout=5)
        self.assertEqual(len(self.report["checks"]), 1)

    def test_public_registry_declares_full_frozen_source_and_reference_domains(self):
        import qualify_hia_runtime_native as q
        import compare_hia_runtime_rust as comparison
        import hia_native_pipeline as pipeline
        helper = q.public_registry_qualification
        entry = {row["key"]: row for row in MODULES}["public_registry"]
        self.assertEqual((entry["test"], *entry["additional_tests"]), helper.TESTS)
        self.assertEqual(entry["source"], "native/public_tool_dispatch.hepta")
        self.assertEqual(entry["companion_sources"], ("native/public_runtime_packer.hepta",))
        self.assertEqual(len(helper.source_pins(ROOT)), 72)
        self.assertTrue(set(helper.source_pins(ROOT)) <= set(sources()))
        self.assertIs(comparison.RECIPES["public_registry"], comparison.compare_public_registry)
        self.assertTrue(set(helper.TESTS) <= set(pipeline.partition_tests()["text"]))
        self.assertEqual(len(set(comparison.PUBLIC_REGISTRY_CONTROL_LABELS)), 20)
        self.assertEqual(comparison.public_registry_control_command(self.output)[-2:],
                         ["--result", str(self.output / "public-registry-evidence-controls.json")])

    def test_public_registry_launcher_rejects_changed_binary_or_appended_arguments(self):
        import qualify_hia_runtime_native as q
        helper = q.public_registry_qualification
        name = helper.TESTS[0]
        root = self.wait_fixture({name: "print(json.dumps({'actual_public_launcher':True}))\n"})
        expected = [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name),
                    "--binary", str(root / "declared.elf")]
        with patch.object(q, "ROOT", root), patch.object(helper, "test_commands", return_value={name: expected}):
            q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                ordered_groups=(), commands={name: expected}, timeout=5)
            self.assertEqual(self.report["checks"][0]["command"], expected)
            self.assertEqual(json.loads((self.output / (name + ".stdout")).read_bytes()),
                             {"actual_public_launcher": True})
            for argv in (expected + ["--not-executed"], expected[:-1] + ["/foreign.elf"], expected[:4]):
                with self.subTest(command=argv), self.assertRaises(ValueError):
                    q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                        ordered_groups=(), commands={name: argv}, timeout=5)
        self.assertEqual(len(self.report["checks"]), 1)

    def test_result_value_domains_preserve_original_counts_and_shared_reference(self):
        import qualify_hia_runtime_native as q
        import compare_hia_runtime_rust as comparison
        import hia_native_pipeline as pipeline
        import hia_native_result_reference as reference
        helper = q.result_qualification
        entries = {row["key"]: row for row in MODULES}
        for key, domain in helper.KEYS.items():
            self.assertEqual(entries[key]["source"], helper.MODULES[domain][0])
            self.assertEqual(entries[key]["builder"], "result_values")
            self.assertIn(key, comparison.RECIPES)
        self.assertEqual(sum(sum(values.values()) for values in helper.COUNTS.values()), 548914)
        self.assertEqual(len(reference.reference_inputs(ROOT)["blocks"]), 11)
        self.assertTrue(set(helper.source_pins(ROOT)) <= set(sources()))
        self.assertTrue(set((*helper.TESTS, helper.CONTROL_TEST)) <= set(pipeline.partition_tests()["json"]))
        self.assertEqual(len(set(comparison.RESULT_VALUE_CONTROL_LABELS)), 13)
        self.assertEqual(comparison.result_values_control_command(self.output)[-2:],
            ["--result", str(self.output / "result-values-evidence-controls.json")])

    def test_result_value_launcher_refuses_changed_manifest_and_appended_flags(self):
        import qualify_hia_runtime_native as q
        helper, name = q.result_qualification, q.result_qualification.TESTS[0]
        root = self.wait_fixture({name: "print(json.dumps({'actual_result_launcher':True}))\n"})
        expected = [sys.executable, "-I", "-B", str(root / "tests/hia_native" / name),
                    "--manifest", str(root / "declared.json")]
        with patch.object(q, "ROOT", root), patch.object(helper, "test_commands", return_value={name: expected}):
            q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                ordered_groups=(), commands={name: expected}, timeout=5)
            self.assertEqual(self.report["checks"][0]["command"], expected)
            self.assertEqual(json.loads((self.output / (name + ".stdout")).read_bytes()),
                {"actual_result_launcher": True})
            for argv in (expected + ["--not-executed"], expected[:-1] + ["/foreign.json"], expected[:4]):
                with self.subTest(command=argv), self.assertRaises(ValueError):
                    q.run_native_checks(self.output, self.report, (name,), {}, parallel_tests=(),
                        ordered_groups=(), commands={name: argv}, timeout=5)
        self.assertEqual(len(self.report["checks"]), 1)

    def test_registry_archive_inventory_rejects_nonregular_duplicate_and_escaping_members(self):
        import io
        import tarfile
        from hia_native_result_reference import archive_files
        from result_value_registry import sha

        def packed(names):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name, kind in names:
                    item = tarfile.TarInfo(name)
                    if kind == "link":
                        item.type = tarfile.SYMTYPE
                        item.linkname = "Cargo.toml"
                        archive.addfile(item)
                    else:
                        item.size = 4
                        archive.addfile(item, io.BytesIO(b"data"))
            return buffer.getvalue()

        good = [("fixture-1.0/Cargo.toml", "file"), ("fixture-1.0/src/lib.rs", "file")]
        expected = {name.split("/", 1)[1]: {"bytes": 4, "sha256": sha(b"data")} for name, _ in good}
        self.assertEqual(archive_files(packed(good), "fixture-1.0"), expected)
        for extra in (("fixture-1.0/Cargo.toml", "file"), ("/fixture-1.0/outside", "file"),
                      ("fixture-1.0/../outside", "file"), ("other-1.0/lib.rs", "file"),
                      ("fixture-1.0/link", "link"), ("fixture-1.0//duplicate", "file")):
            with self.subTest(member=extra), self.assertRaises(ValueError):
                archive_files(packed(good + [extra]), "fixture-1.0")

    def test_registry_source_inventory_excludes_only_root_cargo_markers(self):
        from hia_native_result_reference import files
        root = self.output / "package"
        root.mkdir()
        (root / "Cargo.toml").write_bytes(b"original")
        baseline = files(root)
        for name in (".cargo-ok", ".cargo-checksum.json"):
            (root / name).write_bytes(b"Cargo-owned metadata")
        self.assertEqual(files(root), baseline)
        nested = root / "extra"
        nested.mkdir()
        (nested / ".cargo-ok").write_bytes(b"unexpected source")
        self.assertIn("extra/.cargo-ok", files(root))
        (nested / "external").symlink_to(root / "Cargo.toml")
        with self.assertRaises(ValueError):
            files(root)

    def original_worker_fixture(self, *, serial_code=0, worker_code=0, blocked=False):
        import compare_hia_runtime_rust as comparison
        root = self.wait_fixture({
            "wait.py": "(root/'ready').write_text('ready')\n"
                       "deadline=time.monotonic()+3\nwhile not (root/'release').exists():\n"
                       " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                       + ("time.sleep(60)\n" if blocked else "") +
                       "print(json.dumps({'worker_complete':True}))\nsys.exit(" + str(worker_code) + ")\n",
            "serial.py": "deadline=time.monotonic()+3\nwhile not (root/'ready').exists():\n"
                         " assert time.monotonic()<deadline\n time.sleep(.005)\n"
                         "(root/'release').write_text('release')\nprint(json.dumps({'serial_complete':True}))\n"
                         "sys.exit(" + str(serial_code) + ")\n"})
        def worker(output, report, rustc, *, report_path):
            record_check(output, report, name="operation-scope-os-rust-compile",
                command=[sys.executable, "-I", "-c", "print('{}')"], timeout=5, report_path=report_path)
            record_check(output, report, name="operation-scope-os-rust-compare",
                command=[sys.executable, "-I", str(root / "tests/hia_native/wait.py")],
                timeout=.4 if blocked else 5, report_path=report_path)
            return {"worker_complete": True}
        def serial(output, report, rustc):
            record_check(output, report, name="serial-reference",
                command=[sys.executable, "-I", str(root / "tests/hia_native/serial.py")], timeout=5)
            return {"serial_complete": True}
        self.report.update(modules={"serial": {}, "operation_scope_os": {}}, original_rust_comparisons={})
        with patch.object(comparison, "RECIPES", {"serial": serial, "operation_scope_os": worker}):
            comparison.run_rust_recipes(self.output, self.report, Path(sys.executable))

    def test_original_os_worker_overlaps_main_and_retains_private_records(self):
        self.original_worker_fixture()
        self.assertEqual([r["name"] for r in self.report["checks"]],
            ["serial-reference", "operation-scope-os-rust-compile", "operation-scope-os-rust-compare"])
        self.assertEqual(set(self.report["original_rust_comparisons"]), {"serial", "operation_scope_os"})
        path = self.output / "operation-scope-os-rust.execution.json"
        private = json.loads(path.read_bytes())
        self.assertEqual(private["checks"], self.report["checks"][1:])
        self.assertEqual(len(self.report["rust_parallel_receipts"]), 1)
        self.assertEqual(json.loads((self.output / "result.json").read_bytes()), self.report)

    def test_main_original_failure_drains_submitted_os_worker(self):
        with self.assertRaisesRegex(RuntimeError, "serial-reference failed"):
            self.original_worker_fixture(serial_code=19)
        self.assertEqual([r["exit_code"] for r in self.report["checks"]], [19, 0, 0])
        self.assertEqual(set(self.report["original_rust_comparisons"]), {"operation_scope_os"})
        self.assertNotIn("rust_parallel_drain_errors", self.report)

    def test_original_os_worker_failure_cannot_become_pass(self):
        with self.assertRaisesRegex(RuntimeError, "operation-scope-os-rust-compare failed"):
            self.original_worker_fixture(worker_code=21)
        self.assertEqual([r["exit_code"] for r in self.report["checks"]], [0, 0, 21])
        self.assertNotIn("operation_scope_os", self.report["original_rust_comparisons"])
        self.assertEqual(len(self.report["rust_parallel_receipts"]), 1)

    def test_original_os_worker_timeout_is_killed_and_retained(self):
        with self.assertRaisesRegex(RuntimeError, "operation-scope-os-rust-compare timed out"):
            self.original_worker_fixture(blocked=True)
        row = self.report["checks"][-1]
        self.assertTrue(row["timed_out"])
        self.assertEqual(row["exit_code"], -9)
        self.assertEqual(row["timeout_seconds"], .4)
        self.assertNotIn("operation_scope_os", self.report["original_rust_comparisons"])

    def test_batch_original_stderr_requires_actual_bytes_and_typed_summary(self):
        import hashlib
        from hia_native_batch_apply_qualification import check_original_runtime_summary
        path = self.output / "original.stderr"
        expected = {"status": "PASS", "rust_oracle_cases": 14412, "output_bytes": 301354944}
        raw = json.dumps(expected).encode() + b"\n"
        record = {"original_stderr_sha256": hashlib.sha256(raw).hexdigest(), "original_stderr_bytes": len(raw)}
        path.write_bytes(raw)
        check_original_runtime_summary(path, record, expected)
        for changed in (raw + b"\n", raw.replace(b"14412", b"14413"), b"{}"):
            path.write_bytes(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                check_original_runtime_summary(path, record, expected)
        for changed in (b'{"status":"PASS","rust_oracle_cases":true,"output_bytes":301354944}',
                        b'{"status":"FAIL","status":"PASS","rust_oracle_cases":14412,"output_bytes":301354944}'):
            path.write_bytes(changed)
            rehashed = {"original_stderr_sha256": hashlib.sha256(changed).hexdigest(), "original_stderr_bytes": len(changed)}
            with self.subTest(rehashed=changed), self.assertRaises(ValueError):
                check_original_runtime_summary(path, rehashed, expected)

    def test_batch_apply_registry_keeps_all_processes_and_original_editable_recipe(self):
        import qualify_hia_runtime_native as q
        entry = {row["key"]: row for row in MODULES}["batch_apply"]
        self.assertEqual(entry["builder"], "batch_apply")
        self.assertEqual((entry["test"], *entry["additional_tests"]),
                         tuple(q.batch_apply_test_commands(self.output, self.output / "bundle.json")))
        self.assertIn("batch_apply", RECIPES)
        self.assertIn("editable_content", RECIPES)
        pinned = sources()
        for name in ("scripts/hia_native_batch_apply_build.py", "scripts/hia_native_batch_apply_qualification.py",
                     "native/batch_apply.hepta", "native/editable_bulk_composition.json"):
            self.assertIn(name, pinned)

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

    def test_atomic_registry_binds_all_four_processes_and_original_recipe(self):
        import qualify_hia_runtime_native as q
        import hia_native_atomic_write_qualification as owner
        entry = {row["key"]: row for row in MODULES}["atomic_write"]
        expected = ("test_atomic_write_policy.py", "test_atomic_write_kernel.py",
                    "test_atomic_write_boundary.py", "test_atomic_write_evidence.py")
        self.assertEqual((entry["test"], *entry["additional_tests"]), expected)
        self.assertEqual(entry["builder"], "atomic_write")
        self.assertEqual(entry["companion_sources"], ("native/atomic_write_packer.hepta",))
        self.assertIn("atomic_write", RECIPES)
        self.assertNotIn("atomic_write", PYTHON_REFERENCE_COMPONENTS)
        self.assertEqual(ORIGINAL_RUNTIME_BLOBS["src/mcp/fs/text_editing.rs"], owner.ORIGINAL_BLOB)
        self.assertTrue(set(owner.OWN_FILES) | set(owner.REFERENCE_FILES) <= set(sources()))
        bundle = self.output / "build/atomic/manifest.json"
        hepta = self.output / "compiler"
        commands = q.atomic_write_test_commands(self.output, bundle, hepta)
        self.assertEqual(tuple(commands), expected)
        for name, command in commands.items():
            self.assertEqual(command[:4], [sys.executable, "-I", "-B", str(ROOT / "tests/hia_native" / name)])
        evidence = commands["test_atomic_write_evidence.py"]
        for name in expected[:3]:
            self.assertIn(str(self.output / (name + ".stdout")), evidence)
        self.assertIn(str(bundle.parent / "policy.json"), commands[expected[0]])
        self.assertIn(str(hepta), commands[expected[2]])
        overrides = {name: "/external/source" for name in (
            "HIA_ATOMIC_MANIFEST", "HIA_ATOMIC_POLICY_MANIFEST", "HIA_ATOMIC_POLICY_CORPUS_DIR",
            "HIA_ATOMIC_KERNEL_DIR", "HIA_ATOMIC_BOUNDARY_DIR", "HIA_ATOMIC_POLICY_STDOUT",
            "HIA_ATOMIC_KERNEL_STDOUT", "HIA_ATOMIC_BOUNDARY_STDOUT")}
        self.assertEqual(qualification_env(dict(overrides, PATH="/usr/bin")), {"PATH": "/usr/bin"})

    def test_atomic_completed_check_requires_actual_command_deadline_and_streams(self):
        import copy
        import qualify_hia_runtime_native as q
        command = [sys.executable, "-I", "-B", "-c", "print('{\"reporting_fixture_only\":true}')"]
        self.report["phase"] = "native_components"
        record_check(self.output, self.report, name="atomic-reporting", command=command, timeout=180)
        q.atomic_write_completed_process(self.output, self.report, "atomic-reporting", command)
        mutations = ({"phase": "original_rust_comparison"}, {"timeout_seconds": 181},
            {"elapsed_seconds": float("nan")}, {"exit_code": False}, {"stderr_bytes": False},
            {"command": command + ["--omitted-domain"]}, {"stdout_bytes": 0}, {"timed_out": True})
        for changes in mutations:
            changed = copy.deepcopy(self.report); changed["checks"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                q.atomic_write_completed_process(self.output, changed, "atomic-reporting", command)
        (self.output / "atomic-reporting.stdout").write_bytes(b"{}\n")
        with self.assertRaises(ValueError):
            q.atomic_write_completed_process(self.output, self.report, "atomic-reporting", command)

    def test_atomic_inode_custody_distinguishes_replacements_and_closes_every_pin(self):
        import errno
        import os
        import stat
        import hia_native_atomic_write_qualification as owner
        from atomic_write_cases import PinnedIdentities, snapshot, semantic_snapshot
        fixture = self.output / "fixture"; fixture.mkdir()
        target = fixture / "target"; target.write_bytes(b"original object")
        unchanged = fixture / "unchanged"; unchanged.write_bytes(b"retained object")
        os.link(unchanged, fixture / "hardlink")
        (fixture / "symlink").symlink_to("target")
        denied = fixture / "denied"; denied.mkdir(); (denied / "inside").write_bytes(b"private")
        denied.chmod(0)
        receipt_path = self.output / "identity-custody.json"
        try:
            with PinnedIdentities(receipt_path) as pins:
                before = snapshot(fixture, self.output / "before", identity_pins=pins)
                self.assertEqual(stat.S_IMODE(denied.stat().st_mode), 0)
                original = next(p for p in pins.receipt["pins"] if p["path"] == b"target".hex())
                for value in (b"first replacement", b"second replacement"):
                    temporary = fixture / "replacement"; temporary.write_bytes(value)
                    temporary.replace(target)
                self.assertEqual(os.fstat(original["fd"]).st_nlink, 0)
                self.assertNotEqual(os.fstat(original["fd"]).st_ino, target.stat().st_ino)
                self.assertTrue(all(not os.get_inheritable(fd) for fd in pins.handles))
                after = snapshot(fixture, self.output / "after")
                pins.after_snapshot(before)
                handles = list(pins.handles)
            owner.identity_custody(pins.receipt, before)
            self.assertEqual(json.loads(receipt_path.read_bytes()), pins.receipt)
            states = {bytes.fromhex(r["path"]): r for r in semantic_snapshot(before, after)}
            self.assertFalse(states[b"target"]["identity_retained"])
            self.assertTrue(states[b"unchanged"]["identity_retained"])
            self.assertTrue(states[b"symlink"]["identity_retained"])
            self.assertEqual(states[b"hardlink"]["same_inode_paths"], [b"hardlink".hex(), b"unchanged".hex()])
            for fd in handles:
                with self.assertRaises(OSError) as closed:
                    os.fstat(fd)
                self.assertEqual(closed.exception.errno, errno.EBADF)
        finally:
            denied.chmod(0o700)

    def test_atomic_inode_custody_rejects_missing_lifetimes_and_preserves_failure(self):
        import copy
        import errno
        import os
        import hia_native_atomic_write_qualification as owner
        from atomic_write_cases import PinnedIdentities, snapshot
        fixture = self.output / "fixture"; fixture.mkdir(); (fixture / "target").write_bytes(b"object")
        with PinnedIdentities(self.output / "good.json") as pins:
            before = snapshot(fixture, identity_pins=pins)
            snapshot(fixture); pins.after_snapshot(before)
        bad_receipts = []
        for key, value in (("flags", os.O_RDONLY), ("pins", []), ("observed_after_snapshot", False),
                           ("all_closes_verified", False), ("closed_fds", []),
                           ("close_errors", [{"fd": 0, "error": "close failed"}]), ("body_error", "failed")):
            bad = copy.deepcopy(pins.receipt); bad[key] = value; bad_receipts.append(bad)
        for change in (lambda r: r["pins"][0].update(inheritable=True),
                       lambda r: r["pins"][0]["after"].update(inode=0),
                       lambda r: r["pins"][0]["before"].update(inode=0),
                       lambda r: r["pins"][0].update(fd=True),
                       lambda r: r["pins"][1].update(fd=r["pins"][0]["fd"])):
            bad = copy.deepcopy(pins.receipt); change(bad); bad_receipts.append(bad)
        for bad in bad_receipts:
            with self.subTest(receipt=bad), self.assertRaises(ValueError):
                owner.identity_custody(bad, before)
        failed_path = self.output / "failed.json"
        with self.assertRaisesRegex(RuntimeError, "original observation failure"):
            with PinnedIdentities(failed_path) as failed:
                snapshot(fixture, identity_pins=failed)
                handles = list(failed.handles)
                raise RuntimeError("original observation failure")
        retained = json.loads(failed_path.read_bytes())
        self.assertIn("original observation failure", retained["body_error"])
        self.assertTrue(retained["all_closes_verified"])
        for fd in handles:
            with self.assertRaises(OSError) as closed:
                os.fstat(fd)
            self.assertEqual(closed.exception.errno, errno.EBADF)
        with self.assertRaises(ValueError):
            owner.identity_custody(retained, before)

    def test_atomic_original_retirement_preserves_mismatch_and_both_writer_evidence(self):
        import hia_native_atomic_write_qualification as owner
        folder = self.output / "original"; folder.mkdir()
        outside = self.output / "outside"; outside.mkdir(); (outside / "sentinel").write_bytes(b"outside")
        receipts = {kind: {"reporting_fixture_only": True, "writer": kind} for kind in ("native", "original")}
        for kind in receipts:
            for index, case in enumerate(owner.case_module.cases()):
                entry = folder / (kind + "-kernel") / f"{index:04d}-{case['name']}"
                fixture = entry / "fixture"; fixture.mkdir(parents=True)
                (fixture / "outside").symlink_to(outside, target_is_directory=True)
                denied = fixture / "denied"; denied.mkdir(); (denied / "target").write_bytes(b"owned live target")
                denied.chmod(0)
                (entry / "observation.json").write_bytes(b"complete retained observation fixture\n")
        mismatch = [{"name": "reporting-fixture", "field": "semantic_snapshot", "native": True, "original": False}]
        (folder / "mismatches.json").write_text(json.dumps(mismatch))
        record = owner.original_fixture_retirement(folder, receipts, create=True)
        self.assertEqual(len(record["fixture_directories"]), 302)
        self.assertEqual(owner.original_fixture_retirement(folder, receipts), record)
        self.assertEqual(json.loads((folder / "mismatches.json").read_bytes()), mismatch)
        self.assertEqual((outside / "sentinel").read_bytes(), b"outside")
        for path in record["fixture_directories"]:
            fixture = folder / path
            self.assertFalse(fixture.exists())
            self.assertEqual((fixture.parent / "observation.json").read_bytes(), b"complete retained observation fixture\n")
        with self.assertRaises(ValueError):
            owner.original_fixture_retirement(folder, {"native": receipts["native"]})
        changed = dict(receipts, original={"reporting_fixture_only": True, "writer": "changed"})
        with self.assertRaises(ValueError):
            owner.original_fixture_retirement(folder, changed)

    def test_atomic_live_target_retirement_preserves_full_evidence_and_outside_paths(self):
        import qualify_hia_runtime_native as q
        folder = self.output / "atomic-write/kernel/0000-fixture"
        fixture = folder / "fixture"; fixture.mkdir(parents=True)
        outside = self.output / "outside"; outside.mkdir(); (outside / "sentinel").write_bytes(b"untouched")
        (fixture / "outside-link").symlink_to(outside, target_is_directory=True)
        denied = fixture / "denied"; denied.mkdir(); (denied / "target").write_bytes(b"live effect target")
        denied.chmod(0)
        retained = folder / "after-content"; retained.mkdir(); (retained / "content.bin.gz").write_bytes(b"retained full bytes fixture")
        receipt = folder / "retired.json"; evidence = {"reporting_fixture_only": True}
        paths = (fixture.relative_to(self.output).as_posix(),)
        record = q.atomic_write_retire_fixtures(self.output, paths, receipt, evidence, create=True)
        self.assertFalse(fixture.exists())
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")
        self.assertEqual((retained / "content.bin.gz").read_bytes(), b"retained full bytes fixture")
        self.assertEqual(q.atomic_write_retire_fixtures(self.output, paths, receipt, evidence), record)
        fixture.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "reappeared"):
            q.atomic_write_retire_fixtures(self.output, paths, receipt, evidence)
        fixture.unlink(); receipt.unlink(); fixture.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "owned real directory"):
            q.atomic_write_retire_fixtures(self.output, paths, receipt, evidence, create=True)
        self.assertEqual((outside / "sentinel").read_bytes(), b"untouched")

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

    def test_json_registry_retains_two_original_domains_and_exact_named_profile(self):
        from hia_native_json_qualification import COMPONENTS, source_inputs
        declared = {item['key']: item for item in MODULES}
        self.assertEqual(set(COMPONENTS), {'fence_json', 'serde_json'})
        self.assertTrue(set(COMPONENTS) <= set(RECIPES))
        self.assertEqual(declared['fence_json']['test'], 'test_fence_json.py')
        entry = declared['serde_json']
        self.assertEqual((entry['test'], *entry['additional_tests']),
                         ('test_serde_json.py', 'test_serde_json_transport.py', 'test_json_evidence.py'))
        self.assertEqual(entry['buffer_profile'], 'serde-json.v1')
        self.assertEqual(entry['companion_sources'], ('native/serde_filter_packer.hepta',))
        self.assertIn('src/mcp/runtime/effect_owner_fence.rs', ORIGINAL_RUNTIME_BLOBS)
        self.assertTrue(set(source_inputs(ROOT)['files']) <= set(sources()))
        inherited = {key: '/outside/fixture' for key in (
            'HIA_FENCE_JSON_MANIFEST', 'HIA_SERDE_JSON_MANIFEST', 'HIA_FENCE_JSON_CORPUS_DIR',
            'HIA_SERDE_JSON_CORPUS_DIR', 'HIA_JSON_QUALIFICATION_OUTPUT', 'HIA_JSON_REFERENCE_ROOT',
            'HIA_SERDE_JSON_TRANSPORT_REPORT')}
        self.assertEqual(qualification_env(dict(inherited, PATH='/usr/bin')), {'PATH': '/usr/bin'})

    def test_json_original_build_rejects_inherited_flags_and_target_overrides(self):
        from hia_native_json_qualification import REFERENCE_BUILD_VARIABLES, reference_environment
        rustc = Path('/selected/toolchain/rustc')
        inherited = {name: '/outside/custom-domain' for name in REFERENCE_BUILD_VARIABLES}
        inherited.update(RUSTC='/unselected/compiler', HIA_JSON_REFERENCE_ROOT='/outside/source', PATH='/usr/bin')
        selected, removed = reference_environment(qualification_env(inherited), rustc)
        self.assertEqual(selected, {'RUSTC': str(rustc), 'PATH': '/usr/bin'})
        self.assertEqual(removed, list(REFERENCE_BUILD_VARIABLES))
        self.assertEqual(inherited['RUSTC'], '/unselected/compiler')
        self.assertEqual(reference_environment({'PATH': '/usr/bin'}, rustc),
                         ({'PATH': '/usr/bin', 'RUSTC': str(rustc)}, []))

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

    def test_file_lock_registry_requires_actual_processes_and_both_original_owners(self):
        import hia_native_file_lock_pipeline as pipeline
        import hia_native_file_lock_qualification as locks
        import hia_native_file_lock_service_qualification as service
        import qualify_hia_runtime_native as q
        entries = {row["key"]: row for row in MODULES}
        report = {"modules": {key: {"manifest": "build/" + item["folder"] + "/manifest.json",
                    "builder": key, "source": item["source"]}
                  for key, item in pipeline.COMPONENTS.items()}}
        commands = pipeline.test_commands(ROOT, self.output, report)
        self.assertEqual(tuple(commands), pipeline.ORDERED_SUITES)
        self.assertFalse(set(commands) & set(q.PARALLEL_NATIVE_SUITES))
        for key, item in pipeline.COMPONENTS.items():
            self.assertEqual((entries[key]["test"], *entries[key]["additional_tests"]), item["tests"])
            self.assertEqual(entries[key]["builder"], key)
            self.assertIn(key, RECIPES)
            self.assertNotIn(key, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
            reference = pipeline.original_command(ROOT, self.output, report,
                                                  Path("/selected/1.95/bin/rustc"), key)
            for name in ("rustc", "cargo", "rustfmt"):
                self.assertEqual(reference[reference.index("--" + name) + 1], "/selected/1.95/bin/" + name)
        self.assertEqual(commands["test_file_lock_service.py"][6:8],
                         ["--state-corpus", str(self.output / "file-locks/state")])
        for name, option, producer in (("test_file_lock_evidence.py", "--state-stdout", "test_file_lock_state.py"),
                ("test_file_lock_evidence.py", "--key-stdout", "test_file_lock_key.py"),
                ("test_file_lock_service_evidence.py", "--native-stdout", "test_file_lock_service.py"),
                ("test_file_lock_service_evidence.py", "--contract-stdout", "test_file_lock_service_contract.py")):
            self.assertEqual(commands[name][commands[name].index(option) + 1], str(self.output / (producer + ".stdout")))
        pinned = sources()
        self.assertTrue(set(locks.pins(ROOT)) | set(service.pins(ROOT)) <= set(pinned))
        self.assertIn("scripts/hia_native_file_lock_pipeline.py", pinned)
        self.assertIn("src/mcp/fs/remote.rs", ORIGINAL_RUNTIME_BLOBS)
        self.assertIn("src/mcp/fs/text_editing.rs", ORIGINAL_RUNTIME_BLOBS)

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
