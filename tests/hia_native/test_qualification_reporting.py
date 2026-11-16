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
from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS, ORIGINAL_RUNTIME_COPIES, check_original_sources
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

    def original_worker_fixture(self, *, serial_code=0, worker_code=0, blocked=False, shared=False):
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
        recipes = {"serial": serial, "operation_scope_os": worker}
        if shared:
            self.report['modules'].update(runtime_mcp={}, filesystem_public={})

            def shared_domain(output, report, rustc):
                self.assertEqual(report['original_rust_comparisons']['operation_scope_os'], {'worker_complete': True})
                self.assertEqual(len(report['rust_parallel_receipts']), 1)
                record_check(output, report, name='shared-public-domain',
                    command=[sys.executable, '-I', '-c', "print('{}')"], timeout=5)
                return {'shared_graph_fixture_only': True}

            # Place the shared reader before the worker's registry position to
            # prove that real worker collection is a prerequisite to root moves.
            recipes = {'serial': serial, 'batch_public': shared_domain, 'operation_scope_os': worker}
        with patch.object(comparison, "RECIPES", recipes):
            comparison.run_rust_recipes(self.output, self.report, Path(sys.executable))

    def test_shared_graph_reference_drains_actual_workers_without_an_alias_module(self):
        self.original_worker_fixture(shared=True)
        self.assertNotIn('batch_public', self.report['modules'])
        self.assertEqual(self.report['original_rust_comparisons']['batch_public'], {'shared_graph_fixture_only': True})
        self.assertEqual([row['name'] for row in self.report['checks']],
                         ['serial-reference', 'operation-scope-os-rust-compile',
                          'operation-scope-os-rust-compare', 'shared-public-domain'])

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

    def test_sorted_report_runs_shared_view_original_before_public_consumer(self):
        import compare_hia_runtime_rust as comparison
        import hia_native_view_call_qualification as view
        import hia_native_runtime_mcp_pipeline as public
        import hia_native_view_search_public_qualification as public_search
        import hia_native_view_regex_search_public_qualification as public_regex_search
        actual = dict(comparison.RECIPES)
        providers = ("view_read", "view_params", "view_call")
        self.assertNotIn("view_search", actual)
        self.assertNotIn("view_regex_search", actual)
        selected = set(providers) | {"runtime_mcp", "operation_scope_os"}
        # Preserve the real registry's order. JSON persistence deliberately
        # destroys that ordering in the report, as it does in aggregate CI.
        declared = [key for key in actual if key in selected]
        for key in providers:
            self.assertLess(declared.index(key), declared.index("runtime_mcp"))
        native = {"corpora": {key: key for key in ("caller", "params", "wide")}}
        search_native = {"corpus": "view-search"}
        (self.output / "view-search").mkdir()
        (self.output / "view-search/native-cases.jsonl").write_bytes(b"")
        public_native = {"fixture": "public-native"}
        public_search_native = {"corpus": "view-search-public"}
        search_original = {"fixture": "search-original", "original_output": "view-search-original"}
        regex_native = {"corpus": "view-regex-search"}
        (self.output / "view-regex-search").mkdir()
        (self.output / "view-regex-search/native-cases.jsonl").write_bytes(b"")
        public_regex_native = {"corpus": "view-regex-search-public"}
        regex_original = {"fixture": "regex-original", "original_output": "view-regex-search-original"}
        self.report.update(modules={key: {} for key in declared},
            original_rust_comparisons={}, view_call_evidence=native,
            view_search_evidence=search_native, runtime_mcp_evidence=public_native,
            view_search_public_evidence=public_search_native,
            view_regex_search_evidence=regex_native,
            view_regex_search_public_evidence=public_regex_native)
        self.report = json.loads(json.dumps(self.report, sort_keys=True))
        self.assertLess(list(self.report["modules"]).index("runtime_mcp"),
                        list(self.report["modules"]).index("view_call"))
        executed = []

        def original_fixture(output, report, *, name, **kwargs):
            self.assertIn(name, (view.ORIGINAL_CHECK, *comparison.VIEW_SEARCH_ORIGINAL_CHECKS,
                                 *comparison.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS))
            # The fixture executes a real process; it makes no Rust/native
            # semantic claim. The original reader's missing-recipe guard stays
            # real, while its already-tested byte reader is isolated here.
            return record_check(output, report, name=name,
                command=[sys.executable, "-I", "-c", "print('{}')"], timeout=5)

        def worker(output, report, rustc, *, report_path):
            for name in comparison.PARALLEL_RUST_RECIPES["operation_scope_os"][1]:
                record_check(output, report, name=name,
                    command=[sys.executable, "-I", "-c", "print('{}')"],
                    timeout=5, report_path=report_path)
            return {"fixture": "independent-worker"}

        def serial(key):
            def execute(output, report, rustc):
                result = actual[key](output, report, rustc)
                executed.append(key)
                return result
            return execute

        recipes = {key: worker if key == "operation_scope_os" else serial(key) for key in declared}
        with patch.object(comparison, "view_call_evidence", return_value=native), \
             patch.object(comparison, "view_search_evidence", return_value=search_native), \
             patch.object(comparison, "view_search_public_evidence", return_value=public_search_native), \
             patch.object(comparison, "view_regex_search_evidence", return_value=regex_native), \
             patch.object(comparison, "view_regex_search_public_evidence", return_value=public_regex_native), \
             patch.object(comparison, "runtime_mcp_evidence", return_value=public_native), \
             patch.object(comparison, "record_check", side_effect=original_fixture), \
             patch.object(comparison, "executable", return_value=Path(sys.executable)), \
             patch.object(view, "_original_evidence", return_value={"original_output": "view-call-original"}), \
             patch.object(comparison, "_view_search_original_evidence", side_effect=lambda *args, regex=False:
                          regex_original if regex else search_original), \
             patch.object(public, "execute_original", return_value={"fixture": "public-original"}), \
             patch.object(public, "retained_original", return_value={"fixture": "public-original"}), \
             patch.object(public_search, "compare_public_reference", return_value={"fixture": "public-search-original"}), \
             patch.object(public_regex_search, "compare_public_reference", return_value={"fixture": "public-regex-original"}), \
             patch.object(comparison, "RECIPES", recipes):
            with self.assertRaisesRegex(ValueError, "fresh original recipe has not executed"):
                actual["runtime_mcp"](self.output, self.report, Path(sys.executable))
            self.assertEqual(self.report["checks"], [])
            comparison.run_rust_recipes(self.output, self.report, Path(sys.executable))
            required = self.report.pop("view_search_public_original_comparison")
            with self.assertRaisesRegex(ValueError, "required public literal search original comparison"):
                actual["runtime_mcp"](self.output, self.report, None)
            self.report["view_search_public_original_comparison"] = required
            required_regex = self.report.pop("view_regex_search_public_original_comparison")
            with self.assertRaisesRegex(ValueError, "required public regex search original comparison"):
                actual["runtime_mcp"](self.output, self.report, None)
            self.report["view_regex_search_public_original_comparison"] = required_regex
        self.assertEqual(executed, [key for key in declared if key != "operation_scope_os"])
        self.assertEqual(sum(row["name"] == view.ORIGINAL_CHECK for row in self.report["checks"]), 1)
        for name in (*comparison.VIEW_SEARCH_ORIGINAL_CHECKS, *comparison.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS):
            self.assertEqual(sum(row["name"] == name for row in self.report["checks"]), 1)
        self.assertEqual(self.report["view_search_original_comparison"], search_original)
        self.assertEqual(self.report["view_search_public_original_comparison"], {"fixture": "public-search-original"})
        self.assertEqual(self.report["view_regex_search_original_comparison"], regex_original)
        self.assertEqual(self.report["view_regex_search_public_original_comparison"], {"fixture": "public-regex-original"})
        self.assertEqual([self.report["original_rust_comparisons"][key] for key in providers],
                         [{"original_output": "view-call-original"}] * 3)
        self.assertEqual(set(self.report["original_rust_comparisons"]), selected)
        self.assertTrue(all(row["exit_code"] == 0 and row["timed_out"] is False
                            for row in self.report["checks"]))

    def test_search_original_readonly_consumer_requires_both_shared_wrappers(self):
        self._search_original_required_wrappers(False)

    def test_regex_original_readonly_consumer_requires_both_shared_wrappers(self):
        self._search_original_required_wrappers(True)

    def _search_original_required_wrappers(self, regex):
        import compare_hia_runtime_rust as comparison
        stem = "view_regex_search" if regex else "view_search"
        label = "regex" if regex else "literal"
        checks = comparison.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS if regex else comparison.VIEW_SEARCH_ORIGINAL_CHECKS
        native = {"fixture": "native-search"}
        self.report[stem + "_evidence"] = native
        with self.assertRaisesRegex(ValueError, f"fresh {label} search original recipe has not executed"):
            comparison.compare_view_search(self.output, self.report, native=native, regex=regex)
        self.report["checks"].append({"name": checks[0]})
        with self.assertRaisesRegex(ValueError, "original evidence controls have not executed"):
            comparison.compare_view_search(self.output, self.report, native=native, regex=regex)
        self.assertNotIn(stem + "_original_comparison", self.report)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_search_original_wrapper_rejects_missing_typed_or_changed_actual_receipts(self):
        self._search_original_wrapper_controls(False)

    def test_regex_original_wrapper_rejects_missing_typed_or_changed_actual_receipts(self):
        self._search_original_wrapper_controls(True)

    def _search_original_wrapper_controls(self, regex):
        import copy
        import compare_hia_runtime_rust as comparison
        name = (comparison.VIEW_REGEX_SEARCH_ORIGINAL_CHECKS if regex
                else comparison.VIEW_SEARCH_ORIGINAL_CHECKS)[0]
        command = [sys.executable, "-I", "-c", "print('{\"fixture\":true}')"]
        self.report["phase"] = "original_rust_comparison"
        record_check(self.output, self.report, name=name, command=command, timeout=180)
        actual = copy.deepcopy(self.report["checks"][0])
        summary = {"fixture": True}
        comparison._view_search_check(self.output, self.report, name, command, summary, regex=regex)
        changed = []
        for field in ("timed_out", "timeout_seconds"):
            row = copy.deepcopy(actual)
            del row[field]
            changed.append(row)
        for field, value in (("start_error", None), ("exit_code", False), ("timeout_seconds", 180.0),
                             ("elapsed_seconds", 0), ("phase", "native_components"),
                             ("command", command + ["extra"]), ("stdout_bytes", actual["stdout_bytes"] + 1),
                             ("stderr_bytes", False), ("summary", {"fixture": 1})):
            row = copy.deepcopy(actual)
            row[field] = value
            changed.append(row)
        for row in changed:
            self.report["checks"] = [row]
            with self.subTest(row=row), self.assertRaises(AssertionError):
                comparison._view_search_check(self.output, self.report, name, command, summary, regex=regex)
        self.report["checks"] = [actual, copy.deepcopy(actual)]
        with self.assertRaisesRegex(AssertionError, "exactly one"):
            comparison._view_search_check(self.output, self.report, name, command, summary, regex=regex)
        self.report["checks"] = [actual]
        raw = (self.output / (name + ".stdout")).read_bytes()
        (self.output / (name + ".stdout")).write_bytes(raw.replace(b"true", b"null"))
        with self.assertRaisesRegex(AssertionError, "stream hash"):
            comparison._view_search_check(self.output, self.report, name, command, summary, regex=regex)
        for changed_stdout in (b'{"fixture":true,"fixture":true}\n', b'{"fixture":1}\n'):
            rehashed = copy.deepcopy(actual)
            rehashed.update(stdout_bytes=len(changed_stdout), stdout_sha256=comparison.digest(changed_stdout))
            self.report["checks"] = [rehashed]
            (self.output / (name + ".stdout")).write_bytes(changed_stdout)
            with self.subTest(stdout=changed_stdout), self.assertRaises(AssertionError):
                comparison._view_search_check(self.output, self.report, name, command, summary, regex=regex)

    def test_search_original_checkout_uses_its_own_actual_wrapper(self):
        import copy
        import compare_hia_runtime_rust as comparison
        for regex in (False, True):
            reference, stem, slug, checks, capture = comparison._view_search_domain(regex)
            checkout = self.output / (slug + "-original-source")
            script = checkout / f"tests/hia_native/{stem}_oracle/run.py"
            script.parent.mkdir(parents=True)
            script.write_text('print(\'{"reporting_fixture_only":true}\')\n')
            command = [sys.executable, "-I", "-B", str(script),
                "--runtime-root", str(checkout), "--output", str(self.output / reference.ORACLE_OUTPUT_FOLDER),
                "--cargo", str(Path(sys.executable).with_name("cargo")), "--rustc", sys.executable,
                "--native-corpus", str(self.output / slug)]
            self.report["phase"] = "original_rust_comparison"
            self.report["checks"] = [{"name": f"test_{stem}.py", "command": [sys.executable, "-I", "-B",
                str(self.output / "different-native-source" / f"tests/hia_native/test_{stem}.py")]}]
            record_check(self.output, self.report, name=checks[0], command=command, timeout=180)
            self.assertEqual(comparison._view_search_original_origin(self.report, regex=regex),
                             (sys.executable, checkout))
            actual = copy.deepcopy(self.report["checks"][-1])
            comparison._view_search_check(self.output, self.report, checks[0], command,
                                          {"reporting_fixture_only": True}, regex=regex)
            for index, value in ((0, "python"), (3, str(script) + ".changed"), (4, "--different-root"),
                                 (5, str(checkout) + "/.."), (5, "relative/source"), (5, str(checkout) + "/"),
                                 (6, "--cargo"), (13, False)):
                changed = copy.deepcopy(actual)
                changed["command"][index] = value
                self.report["checks"][-1] = changed
                with self.subTest(regex=regex, index=index, value=value), self.assertRaises(AssertionError):
                    comparison._view_search_original_origin(self.report, regex=regex)
            self.report["checks"] = [actual, copy.deepcopy(actual)]
            with self.assertRaisesRegex(AssertionError, "exactly one"):
                comparison._view_search_original_origin(self.report, regex=regex)

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
        from compare_hia_runtime_rust import SHARED_GRAPH_RUST_RECIPES
        domains = (set(RECIPES) - SHARED_GRAPH_RUST_RECIPES.keys(), NEW_COMPONENTS, PYTHON_REFERENCE_COMPONENTS)
        self.assertTrue(all(owners <= declared for owners in SHARED_GRAPH_RUST_RECIPES.values()))
        self.assertFalse(set(SHARED_GRAPH_RUST_RECIPES) & declared)
        self.assertEqual(declared, set.union(*domains))
        for left in range(len(domains)):
            for right in range(left + 1, len(domains)):
                self.assertFalse(domains[left] & domains[right])
        self.assertIn('file_info_service', PYTHON_REFERENCE_COMPONENTS)
        self.assertNotIn('file_info_service', RECIPES)

    def test_filesystem_registry_keeps_native_and_original_domains_separate(self):
        import qualify_hia_runtime_native as q
        import hia_native_filesystem_parity_qualification as filesystem
        entry = next(item for item in MODULES if item["key"] == "filesystem_parity")
        expected = ("test_filesystem_parity_state.py", "test_filesystem_parity_build.py",
                    "test_filesystem_parity_kernel.py")
        self.assertEqual((entry["test"], *entry["additional_tests"]), expected)
        self.assertEqual(entry["builder"], "filesystem_parity")
        self.assertEqual(entry["manifest_env"], "HIA_FILESYSTEM_PARITY_MANIFEST")
        self.assertEqual(entry["source"], "native/filesystem_parity.hepta")
        self.assertEqual(entry["companion_sources"], ("native/filesystem_parity_packer.hepta",))
        command_output = self.output / "not-created-by-command-generation"
        manifest = command_output / "build/filesystem-parity/source-identity/manifest.json"
        descriptor = {"modules": {"filesystem_parity": {
            "manifest": str(manifest.relative_to(command_output))}}}
        commands = filesystem.test_commands(ROOT, command_output, descriptor)
        self.assertEqual(tuple(commands), expected)
        for name in expected:
            self.assertEqual(commands[name][:4], [sys.executable, "-I", "-B",
                                                  str(ROOT / "tests/hia_native" / name)])
        for name, owner, destination in (
                (expected[0], manifest.parent / "owner/manifest.json", "state"),
                (expected[1], manifest, "build-controls"),
                (expected[2], manifest, "native/captures-v1")):
            command = commands[name]
            self.assertEqual(command[command.index("--manifest") + 1], str(owner))
            self.assertEqual(command[command.index("--output") + 1],
                             str(command_output / "filesystem-parity" / destination))
        cross_device = Path(commands[expected[2]][-1])
        self.assertEqual(cross_device.parent, Path("/dev/shm"))
        self.assertNotEqual(cross_device, filesystem.cross_root(command_output / "different", "native"))
        self.assertFalse(command_output.exists())
        for name in ("../outside/manifest.json", "/outside/manifest.json"):
            with self.subTest(manifest=name), self.assertRaises(ValueError):
                filesystem.test_commands(ROOT, command_output,
                    {"modules": {"filesystem_parity": {"manifest": name}}})
        self.assertFalse(set(expected) & set(q.PARALLEL_NATIVE_SUITES))
        self.assertIn("filesystem_parity", RECIPES)
        self.assertNotIn("filesystem_parity", NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        self.assertEqual(ORIGINAL_RUNTIME_BLOBS["src/mcp/fs/parity_ops.rs"],
                         "65a861d8938ddb83af542a7acebb67d20be8a62a")
        self.assertEqual(ORIGINAL_RUNTIME_COPIES[
            "tests/hia_native/filesystem_parity/oracle/original_parity_ops.rs"], "src/mcp/fs/parity_ops.rs")
        pinned = sources()
        for name in (entry["source"], *entry["companion_sources"],
                     "native/filesystem_parity_layout.json", "native/filesystem_parity_composition.json",
                     "scripts/hia_native_filesystem_parity_build.py",
                     "scripts/hia_native_filesystem_parity_reference.py",
                     "scripts/hia_native_filesystem_parity_qualification.py",
                     "src/mcp/fs/parity_ops.rs",
                     "tests/hia_native/filesystem_parity/oracle/original_parity_ops.rs",
                     *("tests/hia_native/" + name for name in expected)):
            self.assertIn(name, pinned)
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        self.assertEqual(workflow.count("      - 'src/mcp/fs/parity_ops.rs'"), 2)
        before_native, native_and_qualify = workflow.split("\n  native:\n", 1)
        native_job, qualify_job = native_and_qualify.split("\n  qualify:\n", 1)
        install = "sudo apt-get install --no-install-recommends -y strace"
        self.assertNotIn(install, before_native)
        self.assertEqual(native_job.count(install), 1)
        self.assertIn("if: matrix.group == 'system'", native_job)
        self.assertEqual(qualify_job.count(install), 1)
        filesystem_controls = "runtime/tests/hia_native/filesystem_parity/qualify_pipeline.py"
        self.assertNotIn(filesystem_controls, before_native + native_job)
        self.assertEqual(qualify_job.count(filesystem_controls), 1)
        self.assertLess(qualify_job.index("runtime/scripts/compare_hia_runtime_rust.py"),
                        qualify_job.index(filesystem_controls))
        self.assertIn("timeout --signal=KILL 180 python3 -I -B " + filesystem_controls, qualify_job)
        self.assertIn('--controls "$RUNNER_TEMP/hia-runtime-native/filesystem-parity/pipeline-controls"', qualify_job)
        migration = json.loads((ROOT / "native/migration.json").read_bytes())
        self.assertEqual(len(MODULES), 56)
        self.assertEqual(len(migration["native_components"]), 131)
        self.assertEqual(len(q.native_tests()), 147)
        self.assertEqual(len(RECIPES), 52)
        self.assertEqual(len(migration["legacy_tool_handlers"]), 125)
        self.assertTrue(all(row["status"] == "not_ported" and row["native_owner"] is None
                            for row in migration["legacy_tool_handlers"]))
        for key in ("whole_runtime_replaced", "production_activated", "old_stack_removal_qualified"):
            self.assertIs(migration[key], False)

    def test_request_registry_uses_generic_image_and_complete_native_first_recipe(self):
        import qualify_hia_runtime_native as q
        import hia_native_request_registry_pipeline as registry
        import hia_native_request_registry_reference as reference
        entry = next(row for row in MODULES if row['key'] == registry.KEY)
        self.assertNotIn('builder', entry)
        self.assertIsNone(entry['standalone'])
        self.assertEqual(entry['buffer_profile'], 'history.v1')
        self.assertEqual((entry['test'], *entry['additional_tests']), registry.TESTS)
        self.assertEqual(entry['manifest_env'], 'HIA_REQUEST_REGISTRY_MANIFEST')
        self.assertNotIn(registry.KEY, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        self.assertIn(registry.KEY, RECIPES)
        commands = registry.test_commands(ROOT, self.output, self.report)
        self.assertEqual(tuple(commands), registry.TESTS)
        for name in registry.TESTS:
            self.assertEqual(commands[name], [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_native' / name)])
            self.assertNotIn(name, q.PARALLEL_NATIVE_SUITES)
        self.assertFalse((self.output / registry.FOLDER).exists())
        pinned = sources()
        for name, identity in registry.source_table(ROOT).items():
            self.assertEqual(pinned[name], identity['sha256'])
        self.assertEqual(ORIGINAL_RUNTIME_COPIES['tests/hia_native/request_registry_sdk/original/runtime-Cargo.lock'], 'Cargo.lock')
        fixture = {'reporting_fixture_only': True}
        with patch.object(registry, 'native_evidence', return_value=fixture) as called:
            self.assertEqual(q.request_registry_evidence(self.output, self.report), fixture)
        called.assert_called_once_with(ROOT, self.output, self.report, q.completed_test_summary)
        rustc = Path('/selected/1.95/bin/rustc')
        import compare_hia_runtime_rust as comparison
        with patch.object(reference, 'execute_original', return_value=fixture) as called:
            self.assertEqual(RECIPES[registry.KEY](self.output, self.report, rustc), fixture)
        called.assert_called_once_with(ROOT, self.output, self.report, rustc,
            record_check=comparison.record_check, completed=comparison.completed_test_summary,
            qualification_env=comparison.qualification_env)
        # A generic image keeps the ordinary compiler/manifest admission. Only
        # real bundles already checked by their reader may bypass that branch.
        source = (ROOT / 'scripts/compare_hia_runtime_rust.py').read_text()
        line = next(line for line in source.splitlines() if '"view_call", "batch_diff", "batch_call", "text_publication"' in line)
        self.assertNotIn('request_registry', line)

    def test_text_publication_registration_binds_real_native_and_original_stages(self):
        import qualify_hia_runtime_native as q
        import hia_native_text_publication_pipeline as text
        import hia_native_text_publication_reference as reference
        entry = next(row for row in MODULES if row['key'] == 'text_publication')
        expected = (text.NATIVE_TEST, text.CORPUS_TEST, text.EVIDENCE_TEST)
        self.assertEqual((entry['test'], *entry['additional_tests']), expected)
        self.assertEqual(entry['builder'], text.KEY)
        self.assertEqual(entry['source'], 'native/text_publication.hepta')
        self.assertEqual(entry['companion_sources'], ('native/text_publication_packer.hepta',))
        self.assertEqual(entry['manifest_env'], 'HIA_TEXT_PUBLICATION_MANIFEST')
        output = self.output / 'text-command-fixture'
        manifest = output / text.MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes(b'{"reporting_fixture_only":true}\n')
        descriptor = {'modules': {'text_publication': {'manifest': text.MANIFEST,
            'source': entry['source'], 'builder': entry['builder'], 'sha256': text.file_pin(manifest)['sha256']}}}
        commands = text.test_commands(ROOT, output, descriptor)
        self.assertEqual(tuple(commands), expected)
        for name in expected:
            self.assertEqual(commands[name][:4], [sys.executable, '-I', '-B', str(ROOT / 'tests/hia_native' / name)])
        self.assertEqual(list(output.rglob('*.json')), [manifest])
        self.assertFalse(set(expected) & set(q.PARALLEL_NATIVE_SUITES))
        self.assertIn(text.KEY, RECIPES)
        self.assertNotIn(text.KEY, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        self.assertEqual(ORIGINAL_RUNTIME_BLOBS['src/mcp/fs/text_file_write.rs'],
                         'f531d2a51ea2ad0bdf0e93576e5bb64bf3fbeb43')
        self.assertEqual(ORIGINAL_RUNTIME_COPIES[
            reference.ORACLE + '/ordinary/original/text_file_write.rs'], 'src/mcp/fs/text_file_write.rs')
        pinned = sources()
        for name in (*text.source_names(ROOT), reference.CONTRACT, *reference.WRAPPERS,
                     *(reference.ORACLE + '/' + name for name in json.loads((ROOT / reference.CONTRACT).read_bytes())['files']),
                     'src/mcp/fs/text_file_write.rs', 'authoring/diagnostics.json'):
            self.assertIn(name, pinned)
        self.assertEqual(len(reference.source_pins(ROOT, {'source_sha256': pinned})), 30)
        workflow = (ROOT / '.github/workflows/hia-runtime-native.yml').read_text()
        for name in ('src/mcp/fs/text_file_write.rs', 'authoring/diagnostics.json'):
            self.assertEqual(workflow.count("      - '" + name + "'"), 2)

    def test_text_publication_callbacks_keep_recording_and_retirement_separate(self):
        import compare_hia_runtime_rust as comparison
        import qualify_hia_runtime_native as q
        import hia_native_text_publication_pipeline as text
        import hia_native_text_publication_reference as reference
        fixture = {'reporting_fixture_only': True}
        rustc = Path('/selected/1.95/bin/rustc')
        with patch.object(reference, 'execute_original', return_value=fixture) as called:
            self.assertEqual(comparison.RECIPES['text_publication'](self.output, self.report, rustc), fixture)
        called.assert_called_once_with(ROOT, self.output, self.report, rustc,
            record_check=comparison.record_check, completed=comparison.completed_test_summary,
            qualification_env=comparison.qualification_env)
        with patch.object(text, 'native_evidence', return_value=fixture) as called:
            self.assertEqual(q.text_publication_evidence(self.output, self.report), fixture)
        called.assert_called_once_with(ROOT, self.output, self.report, q.completed_test_summary)
        with patch.object(text, 'retire_fixtures', return_value=fixture) as called:
            self.assertEqual(q.text_publication_retirement(self.output, self.report, create=True), fixture)
        called.assert_called_once_with(ROOT, self.output, self.report, q.completed_test_summary, create=True)

    def test_text_original_trace_accepts_pid_padding_without_skipping_records(self):
        import hashlib
        import hia_native_text_publication_reference as reference
        api = reference.load_api(ROOT)
        trace = api['ordinary_evidence'].__globals__['trace_evidence']
        oracle = ROOT / reference.ORACLE
        source_table = json.loads((ROOT / reference.CONTRACT).read_bytes())['files']
        for name, expected in source_table.items():
            data = (oracle / name).read_bytes()
            self.assertEqual({'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}, expected)
        for name, expected in api['race_evidence'].__globals__['ORDINARY_READER_PINS'].items():
            self.assertEqual(expected, source_table['readers/' + name])
        for name, expected in api['qualification_evidence'].__globals__['SOURCE_PINS'].items():
            self.assertEqual(expected, source_table[name])

        def capture(pid, padding):
            # CI run 43765626814 used the prefix "5499  1794780630.112251 ".
            prefix = pid + padding + '1794780630.112251 '
            bodies = (
                'getpgid(900000000) = -1 ESRCH (No such process) <0.000001>',
                'openat(AT_FDCWD, "missing", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000001>',
                'getpgid(900000001) = -1 ESRCH (No such process) <0.000001>',
                'exit_group(0) = ?',
                '+++ exited with 0 +++',
            )
            return ''.join(prefix + body + '\n' for body in bodies).encode('ascii')

        for pid, padding in [('1', '     '), ('12', '    '), ('123', '   '),
                             ('5499', '  '), ('12345', ' '), ('1234567', ' ')]:
            with self.subTest(pid=pid):
                proof = trace(capture(pid, padding), [0], {0: {'ok': False}})
                self.assertEqual((proof['trace_pid'], proof['line_count'],
                                  proof['syscalls'], proof['marker_pairs']),
                                 (int(pid), 5, 4, 1))
                self.assertEqual(proof['cases'][0]['syscall_count'], 1)
                self.assertEqual(proof['cases'][0]['syscalls'][0]['errno'], 'ENOENT')
                self.assertTrue(proof['all_lines_consumed'])

        raw = capture('5499', '  ')
        mutations = {
            'tab-in-pid-padding': raw.replace(b'5499  ', b'5499\t ', 1),
            'missing-pid-separator': raw.replace(b'5499  ', b'5499', 1),
            'signed-pid': raw.replace(b'5499  ', b'-5499  ', 1),
            'invalid-timestamp': raw.replace(b'1794780630.112251', b'1794780630.x', 1),
            'leading-record-space': b' ' + raw,
            'extra-body-space': raw.replace(b'112251 getpgid', b'112251  getpgid', 1),
            'unknown-record': raw.replace(b'openat(', b'unknown_call(', 1),
            'second-pid': raw.replace(b'5499  ', b'5500  ', 1),
            'lost-end-marker': raw.replace(b'900000001', b'900000003', 1),
            'blank-record': raw.replace(b'\n', b'\n\n', 1),
            'partial-final-record': raw[:-1],
            'unmatched-owned-close': raw.replace(
                b'openat(AT_FDCWD, "missing", O_RDONLY) = -1 ENOENT (No such file or directory)',
                b'close(3) = 0', 1),
        }
        for name, changed in mutations.items():
            with self.subTest(rejected=name), self.assertRaises(ValueError):
                trace(changed, [0], {0: {'ok': False}})

    def test_batch_params_registration_preserves_component_and_original_boundaries(self):
        import qualify_hia_runtime_native as q
        import hia_native_batch_edit_params_pipeline as params
        item = next(row for row in q.MODULES if row['key'] == params.KEY)
        self.assertEqual(item['source'], 'native/batch_edit_params.hepta')
        self.assertEqual(item['builder'], params.KEY)
        self.assertEqual((item['test'], *item.get('additional_tests', ())), (params.NATIVE_TEST,))
        self.assertIn(params.KEY, RECIPES)
        self.assertNotIn(params.KEY, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        pinned = q.sources()
        for name in ('native/batch_edit_params.hepta', 'native/batch_edit_params_abi.md',
                     'native/batch_edit_params_composition.json', params.PIPELINE_SOURCE,
                     'scripts/hia_native_batch_edit_params_build.py',
                     'scripts/hia_native_batch_edit_params_qualification.py',
                     'tests/hia_native/' + params.NATIVE_TEST, 'tests/hia_native/' + params.CONTROLS_TEST,
                     'tests/hia_native/batch_edit_params_oracle/src/original.rs',
                     'tests/hia_native/batch_edit_params_oracle/source_manifest.json'):
            self.assertIn(name, pinned)
        output = self.output / 'uncreated-batch-params'
        for bad in ('/outside/bundle.json', '../outside/bundle.json'):
            report = {'modules': {params.KEY: {'manifest': bad, 'source': item['source'], 'builder': params.KEY}}}
            with self.subTest(path=bad), self.assertRaises(ValueError):
                params.environment(ROOT, output, report)
        self.assertFalse(output.exists())
        self.assertNotIn(params.CONTROLS_TEST, q.native_tests())

    def test_batch_input_registration_preserves_native_and_original_phase_boundaries(self):
        import qualify_hia_runtime_native as q
        import hia_native_batch_plan_input_pipeline as bridge
        item = next(row for row in q.MODULES if row['key'] == bridge.KEY)
        self.assertEqual(item['source'], 'native/batch_plan_input.hepta')
        self.assertEqual(item['builder'], bridge.KEY)
        self.assertEqual((item['test'], *item.get('additional_tests', ())), (bridge.NATIVE_TEST,))
        self.assertEqual(set(item['companion_sources']), {
            'native/serde_json_span.hepta', 'native/batch_edit_params.hepta', 'native/editable_content.hepta',
            'native/batch_plan.hepta', 'native/line_endpoint.hepta', 'native/line_verify.hepta'})
        self.assertIn(bridge.KEY, RECIPES)
        self.assertNotIn(bridge.KEY, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        pinned = q.sources()
        for name in ('native/batch_plan_input.hepta', 'native/batch_plan_input_abi.md',
                     'native/batch_plan_input_composition.json', 'native/batch_plan_input_sources.json',
                     bridge.PIPELINE_SOURCE, 'scripts/hia_native_batch_plan_input_build.py',
                     'scripts/hia_native_batch_plan_input_qualification.py',
                     'tests/hia_native/' + bridge.NATIVE_TEST, 'tests/hia_native/' + bridge.CONTROLS_TEST,
                     'tests/hia_native/batch_plan_input_cases.py',
                     'tests/hia_native/batch_plan_input_oracle/src/original.rs',
                     'tests/hia_native/batch_plan_input_oracle/src/editable_original.rs',
                     'tests/hia_native/batch_plan_input_oracle/source_manifest.json'):
            self.assertIn(name, pinned)
        output = self.output / 'uncreated-batch-input'
        for bad in ('/outside/bundle.json', '../outside/bundle.json'):
            report = {'modules': {bridge.KEY: {'manifest': bad, 'source': item['source'], 'builder': bridge.KEY}}}
            with self.subTest(path=bad), self.assertRaises(ValueError):
                bridge.environment(ROOT, output, report)
        self.assertFalse(output.exists())
        self.assertNotIn(bridge.CONTROLS_TEST, q.native_tests())

    def test_batch_diff_registration_requires_complete_native_and_original_evidence(self):
        import qualify_hia_runtime_native as q
        import hia_native_batch_diff_pipeline as diff
        import hia_native_batch_diff_qualification as evidence
        item = next(row for row in q.MODULES if row['key'] == diff.KEY)
        self.assertEqual(item['source'], 'native/batch_diff.hepta')
        self.assertEqual(item['builder'], diff.KEY)
        self.assertEqual(item['manifest_env'], 'HIA_BATCH_DIFF_BUNDLE')
        self.assertEqual((item['test'], *item.get('additional_tests', ())), (diff.NATIVE_TEST,))
        self.assertEqual(set(item['companion_sources']),
                         {'native/batch_apply.hepta', 'native/editable_content.hepta',
                          'native/text_budget.hepta', 'native/result_publication.hepta'})
        self.assertIn(diff.KEY, RECIPES)
        self.assertNotIn(diff.KEY, NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        self.assertEqual(diff.ORIGINAL_CHECKS, ('batch_diff_original', diff.CONTROLS_TEST))
        self.assertNotIn(diff.CONTROLS_TEST, q.native_tests())
        pinned = q.sources()
        for name in (*evidence.NATIVE_SOURCES, diff.PIPELINE_SOURCE,
                     'scripts/hia_native_batch_diff_qualification.py',
                     'tests/hia_native/' + diff.CONTROLS_TEST,
                     'tests/hia_native/batch_diff_oracle/assemble.py',
                     'tests/hia_native/batch_diff_oracle/run.py',
                     'tests/hia_native/batch_diff_oracle/src/carrier.rs',
                     'tests/hia_native/oracle_batch_apply.rs', 'src/mcp/fs/delta.rs',
                     'src/mcp/fs/text_editing.rs', 'src/utils/line_hash.rs'):
            self.assertIn(name, pinned)
        output = self.output / 'uncreated-batch-diff'
        for bad in ('/outside/bundle.json', '../outside/bundle.json'):
            report = {'modules': {diff.KEY: {'manifest': bad, 'source': item['source'], 'builder': diff.KEY}}}
            with self.subTest(path=bad), self.assertRaises(ValueError):
                diff.environment(ROOT, output, report)
        self.assertFalse(output.exists())


    def test_batch_diff_main_receipts_require_complete_actual_streams(self):
        import copy
        import hia_native_batch_diff_pipeline as diff
        command = [sys.executable, '-I', '-B', '-c', 'print("{\\"mechanical_receipt\\":true}")']
        expected = {'mechanical_receipt': True}
        record_check(self.output, self.report, name=diff.ORIGINAL_CHECK,
                     command=command, timeout=180)
        row, streams, artifacts = diff._check(self.output, self.report, completed_test_summary,
                                              diff.ORIGINAL_CHECK, command, expected)
        self.assertEqual(set(artifacts), {diff.ORIGINAL_CHECK + '.stdout', diff.ORIGINAL_CHECK + '.stderr'})
        for change in ({'exit_code': False}, {'timed_out': True}, {'timeout_seconds': 181},
                       {'command': [*command, 'extra']}, {'start_error': {'type': 'OSError'}},
                       {'stdout_bytes': row['stdout_bytes'] + 1}, {'summary': {'mechanical_receipt': False}}):
            altered = copy.deepcopy(self.report)
            altered['checks'][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                diff._check(self.output, altered, completed_test_summary,
                            diff.ORIGINAL_CHECK, command, expected)
        base = self.output / 'retained'
        base.mkdir()
        record = diff._record(row, ROOT, 'original')
        diff._retain_process(base, record, streams, create=True)
        diff._retain_process(base, record, streams, create=False)
        (base / 'original.stdout').unlink()
        with self.assertRaises(ValueError):
            diff._retain_process(base, record, streams, create=False)
        self.assertFalse((base / 'original.stdout').exists())


    def test_config_span_registry_requires_native_capture_and_fresh_original(self):
        import qualify_hia_runtime_native as q
        import hia_native_config_span_pipeline as span
        from check_hia_native_inventory import ORIGINAL_RUNTIME_COPIES
        item = next(row for row in q.MODULES if row['key'] == 'runtime_config_span')
        owners = {'native/config_directory_owner_span.hepta', 'native/config_fs_span.hepta',
                  'native/config_json_span.hepta', 'native/config_validation_span.hepta',
                  'native/directory_move_guard.hepta'}
        self.assertEqual({item['source'], *item['companion_sources']}, owners)
        self.assertEqual((item['test'], *item['additional_tests']), span.TESTS)
        self.assertIn('runtime_config_span', RECIPES)
        self.assertNotIn('runtime_config_span', NEW_COMPONENTS | PYTHON_REFERENCE_COMPONENTS)
        report = {'modules': {'runtime_config_span': {'manifest': span.MANIFEST}}}
        output = self.output / 'uncreated-config-span'
        commands = span.test_commands(ROOT, output, report)
        self.assertEqual(set(commands), set(span.TESTS))
        self.assertIn(str(output / span.MANIFEST), commands[span.TESTS[0]])
        self.assertIn(str(output / 'config-span/native'), commands[span.TESTS[1]])
        self.assertFalse(output.exists())
        for path in ('/outside/result.json', '../outside/result.json'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                span.test_commands(ROOT, output, {'modules': {'runtime_config_span': {'manifest': path}}})
        self.assertEqual(ORIGINAL_RUNTIME_COPIES['tests/hia_native/config_span/guard_original/original/config.rs'],
                         'src/mcp/runtime/config.rs')
        pinned = q.sources()
        for name in (*owners, *span.SOURCE_FILES, 'native/config_span_sources.json',
                     'scripts/config_mcp_grow_adapter.S',
                     'tests/hia_native/config_span/guard_original/strict_reference.py'):
            self.assertIn(name, pinned)

    def test_public46_registration_retains_all_build_read_and_original_inputs(self):
        import qualify_hia_runtime_native as q
        from check_hia_native_inventory import ORIGINAL_RUNTIME_BLOBS
        item = next(row for row in q.MODULES if row["key"] == "runtime_mcp")
        new_owners = {
            "native/runtime_mcp_image_packer.hepta", "native/runtime_mcp_protocol.hepta",
            "native/serde_json_span.hepta", "native/workdir_gateway.hepta",
            "native/workdir_io.hepta", "native/workdir_params.hepta", "native/workdir_render.hepta",
        }
        self.assertLessEqual(new_owners, set(item["companion_sources"]))
        sources = q.sources()
        for name in (
            "scripts/hia_native_runtime_mcp_pipeline.py", "scripts/hia_native_runtime_mcp_fixtures.py",
            "scripts/hia_native_public_exchange_qualification.py", "scripts/hia_native_runtime_mcp_original.py",
            "scripts/hia_native_runtime_mcp_adapter.py", "scripts/hia_native_runtime_mcp_pack.py",
            "scripts/hia_native_workdir_reference.py", "scripts/runtime_mcp_execution_bridge.S",
            "scripts/runtime_mcp_transport.S", "scripts/runtime_mcp_view_bridge.S",
            "scripts/runtime_mcp_workdir_io_bridge.S", "tests/hia_native/workdir_oracle/run.py",
            "tests/hia_native/runtime_mcp_oracle/run.py", "tests/hia_native/test_runtime_mcp_original_evidence.py",
        ):
            self.assertEqual(sources[name], q.sha(ROOT / name))
        workflow = (ROOT / ".github/workflows/hia-runtime-native.yml").read_text()
        for name in ("src/mcp/fs/workdir.rs", "src/mcp/mod.rs"):
            self.assertIn(name, ORIGINAL_RUNTIME_BLOBS)
            self.assertEqual(workflow.count("      - '" + name + "'"), 2)
        self.assertNotIn("test_runtime_mcp_original_evidence.py", q.native_tests())
        self.assertEqual(item["additional_tests"], (
            "test_runtime_mcp_evidence.py", "test_view_search_public.py",
            "test_view_regex_search_public.py", "test_view_regex_search_public_evidence.py"))

    def test_filesystem_original_recipe_uses_the_selected_compiler_and_recording_callback(self):
        import compare_hia_runtime_rust as comparison
        import hia_native_filesystem_parity_qualification as filesystem
        import qualify_hia_runtime_native as q
        rustc = Path("/selected/1.95/bin/rustc")
        # This is an orchestration-only sentinel, never a native/original PASS.
        result = {"reporting_fixture_only": True, "native_trace_time_extent": (1.25, 2.5)}
        stored = {"reporting_fixture_only": True, "native_trace_time_extent": [1.25, 2.5]}
        with patch.object(filesystem, "compare_original", return_value=result) as actual:
            self.assertEqual(comparison.RECIPES["filesystem_parity"](self.output, self.report, rustc), stored)
        actual.assert_called_once_with(ROOT, self.output, self.report, rustc,
                                       comparison.record_check, comparison.completed_test_summary)
        with patch.object(filesystem, "retained_original", return_value=result) as retained:
            self.assertEqual(comparison.retained_filesystem_parity(self.output, self.report, rustc), stored)
        retained.assert_called_once_with(ROOT, self.output, self.report, rustc,
                                         comparison.completed_test_summary)
        with patch.object(filesystem, "native_evidence", return_value=result) as native:
            self.assertEqual(q.filesystem_parity_evidence(self.output, self.report), stored)
        native.assert_called_once_with(ROOT, self.output, self.report, q.completed_test_summary)
        with patch.object(filesystem, "retire_fixtures", return_value=result) as retirement:
            self.assertEqual(q.filesystem_parity_retirement(self.output, self.report), stored)
        retirement.assert_called_once_with(ROOT, self.output, self.report, q.completed_test_summary, create=False)
        self.assertIsInstance(result["native_trace_time_extent"], tuple)

    def test_public_filesystem_registration_keeps_real_pair_and_original_stages(self):
        import qualify_hia_runtime_native as q
        import hia_native_filesystem_public_pipeline as fs
        from hia_native_runtime_mcp_build import MEMBERS, BOUNDARIES, FIXTURE_BOUNDARIES
        entries = {row['key']: row for row in q.MODULES}
        order = [row['key'] for row in q.MODULES]
        self.assertLess(order.index('runtime_mcp'), order.index(fs.KEY))
        self.assertEqual(entries[fs.KEY]['builder'], fs.KEY)
        self.assertEqual(entries[fs.KEY]['source'], 'native/filesystem_gateway.hepta')
        self.assertEqual(entries[fs.KEY]['test'], fs.NATIVE_TEST)
        self.assertIn(fs.KEY, RECIPES)
        self.assertNotIn(fs.CONTROLS_TEST, q.native_tests())
        self.assertNotIn('test_filesystem_public_original.py', q.native_tests())
        members = {'native/' + name + '.hepta' for _, name, _ in MEMBERS}
        self.assertEqual(len(members), 71)
        import hia_native_runtime_mcp_evidence as public_reader
        self.assertEqual(public_reader.SOURCE_MANIFEST_SHA256, q.sha(ROOT / 'native/runtime_mcp_sources.json'))
        self.assertEqual(set(entries['runtime_mcp']['companion_sources']) | {entries['runtime_mcp']['source']},
                         members | {'native/runtime_mcp_image_packer.hepta'})
        self.assertTrue({'native/config_directory_owner_span.hepta', 'native/config_fs_span.hepta',
                         'native/config_json_span.hepta', 'native/config_validation_span.hepta'} <= members)
        self.assertFalse({'native/config_directory_owner.hepta', 'native/config_fs.hepta',
                          'native/config_json.hepta', 'native/config_validation.hepta'} & members)
        # The former public directory owner has no remaining executable consumer.
        # Keep its physical retirement and manifest retirement together.
        retired = 'native/config_directory_owner.hepta'
        self.assertFalse((ROOT / retired).exists())
        migration = json.loads((ROOT / 'native/migration.json').read_bytes())
        self.assertNotIn(retired, {row['source'] for row in migration['native_components']})
        pinned = q.sources()
        for name in (*fs.SOURCE_FILES, *BOUNDARIES, *FIXTURE_BOUNDARIES,
                     'native/runtime_mcp_filesystem_composition.json',
                     'native/filesystem_public_tools_provenance.json'):
            self.assertEqual(pinned[name], q.sha(ROOT / name))
        report = {'modules': {'runtime_mcp': {'manifest': fs.PUBLIC_MANIFEST},
                             fs.KEY: {'manifest': fs.FIXTURE_MANIFEST, 'source': entries[fs.KEY]['source'], 'builder': fs.KEY}}}
        commands = fs.test_commands(ROOT, self.output, report, strace='/selected/strace')
        self.assertEqual(set(commands), {fs.NATIVE_TEST})
        self.assertEqual(commands[fs.NATIVE_TEST], [sys.executable, '-I', '-B',
            str(ROOT / 'tests/hia_native' / fs.NATIVE_TEST), '--output', str(self.output),
            '--public-manifest', str(self.output / fs.PUBLIC_MANIFEST),
            '--fixture-manifest', str(self.output / fs.FIXTURE_MANIFEST), '--strace', '/selected/strace'])

    def test_public_filesystem_original_sources_are_exact_runtime_materializations(self):
        import hia_native_filesystem_public_reference_source as source
        document, original, sources = source.source_evidence(ROOT)
        self.assertEqual(len(original), 17)
        self.assertEqual(len(source.ORIGINALS), 11)
        self.assertFalse((ROOT / source.ORACLE / 'oracle/original').exists())
        for name, location in source.ORIGINALS.items():
            self.assertEqual(original['oracle/original/' + name], (ROOT / location).read_bytes())
            self.assertIn(location, ORIGINAL_RUNTIME_BLOBS)
        before = source.materialize(ROOT, self.output)
        self.assertEqual(source.verify_materialized(ROOT, self.output), before)
        self.assertIs(before['original_semantics_executed'], False)
        self.assertEqual(before['new_rust_processes'], 0)
        path = self.output / source.FOLDER / 'oracle/original/server.rs'
        raw = path.read_bytes()
        path.write_bytes(raw + b'\n')
        with self.assertRaisesRegex(ValueError, 'materialized original changed'):
            source.verify_materialized(ROOT, self.output)
        path.write_bytes(raw)
        extra = self.output / source.FOLDER / 'unbound-original.rs'
        extra.write_bytes(b'not an admitted original source')
        with self.assertRaisesRegex(ValueError, 'unexpected materialized input file'):
            source.verify_materialized(ROOT, self.output)

    def test_public_filesystem_recipe_records_only_actual_original_and_controls(self):
        import compare_hia_runtime_rust as comparison
        import hia_native_filesystem_public_pipeline as fs
        selected = Path('/selected/1.95/bin/rustc')
        sentinel = {'orchestration_fixture_only': True}
        with patch.object(fs, 'execute_original', return_value=sentinel) as execute:
            self.assertEqual(comparison.RECIPES[fs.KEY](self.output, self.report, selected), sentinel)
        execute.assert_called_once_with(ROOT, self.output, self.report, selected,
                                        comparison.record_check, comparison.completed_test_summary)

    def test_public_filesystem_wrapper_rechecks_phase_deadline_and_complete_streams(self):
        import copy
        import hia_native_filesystem_public_pipeline as fs
        expected = {'mechanical_process_fixture_only': True}
        command = [sys.executable, '-I', '-B', '-c', 'print(\'{"mechanical_process_fixture_only":true}\')']
        self.report['phase'] = 'native_components'
        record_check(self.output, self.report, name=fs.NATIVE_TEST, command=command, timeout=180)
        row, files = fs.wrapper(self.output, self.report, completed_test_summary,
                                fs.NATIVE_TEST, command, expected)
        self.assertEqual(row, self.report['checks'][0])
        self.assertEqual(set(files), {fs.NATIVE_TEST + '.stdout', fs.NATIVE_TEST + '.stderr'})
        for key, value in (('phase', 'original_rust_comparison'), ('timeout_seconds', 181),
                           ('exit_code', False), ('elapsed_seconds', float('nan')),
                           ('stdout_bytes', row['stdout_bytes'] + 1)):
            changed = copy.deepcopy(self.report)
            changed['checks'][0][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                fs.wrapper(self.output, changed, completed_test_summary, fs.NATIVE_TEST, command, expected)
        changed = copy.deepcopy(self.report)
        changed['checks'].append(copy.deepcopy(changed['checks'][0]))
        with self.assertRaisesRegex(ValueError, 'one actual complete wrapper'):
            fs.wrapper(self.output, changed, completed_test_summary, fs.NATIVE_TEST, command, expected)

    def test_public_filesystem_relocation_preserves_all_shared_source_roles(self):
        """Mechanical alias regression; no HIA or original semantic execution."""
        import hia_native_filesystem_public_pipeline as fs
        source = self.output / 'role-source'
        producer = source / 'tests/producer'
        native = self.output / 'role-native'
        producer.mkdir(parents=True)
        native.mkdir()
        for name in ('strict_native.py', 'strict_native_provenance.py', 'strict_observations.py',
                     'strict_trace.py', 'strict_original.py', 'strict_fixture.py', 'strict_transport.py',
                     'test_native_evidence.py', 'capture_common.py'):
            (producer / name).write_bytes(('mechanical source: ' + name).encode())
        for name in ('scripts/build.py', 'scripts/primitive.py', 'native/runtime_mcp_sources.json'):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
        original_reader = self.output / 'role-original-reader.py'
        original_reader.write_bytes(b'unchanged reference reader fixture')
        (native / 'NATIVE.json').write_bytes(b'{"fixture":true}')
        plan = dict(native_source=str(source), producer_source=str(producer),
                    original_driver_source=str(producer), native_capture=str(native),
                    original_capture=str(self.output / 'role-original'),
                    reference_source=str(self.output / 'role-reference'),
                    original_reader=str(original_reader), build_reader=str(source / 'scripts/build.py'),
                    build_primitive=str(source / 'scripts/primitive.py'))
        full = dict(provenance={'exact_artifact_names': []}, build={'artifacts': {}},
                    comparison={'original_evidence': {'artifact_sha256': {'producer-source/capture_common.py': 'fixture'}}})
        native_source = dict(driver_sources={'capture_common.py': 'fixture'}, native_source_files={})
        mapping, copies = fs.relocation_inventory(plan, full, native_source, Path.read_bytes)
        origin = str(producer / 'capture_common.py')
        first, second = 'native-producer/capture_common.py', 'original-producer/capture_common.py'
        self.assertEqual(mapping['files'][origin], first)
        self.assertEqual(copies[first], origin)
        self.assertEqual(copies[second], origin)
        self.assertEqual(mapping['copy_pins'][first], mapping['copy_pins'][second])
        self.assertEqual(len(mapping['copy_pins']), len(mapping['files']) + 1)
        self.assertEqual(set(mapping['copy_pins']), set(copies))

    def public_filesystem_archive_fixture(self):
        """Mechanical archive fixture; no native or original semantic claim."""
        import os
        import stat
        import hia_native_filesystem_public_fixtures as fixtures
        from hia_native_filesystem_public_reference_source import canonical
        owned = self.output / fixtures.ROOTS[0]
        allowed, outside = owned / 'allowed/s-000', owned / 'outside/s-000'
        allowed.mkdir(parents=True)
        outside.mkdir(parents=True)
        (allowed / 'empty').mkdir()
        raw_name = os.fsencode(allowed) + b'/raw-\xff'
        fd = os.open(raw_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, b'complete\x00archive\n')
        finally:
            os.close(fd)
        os.link(raw_name, os.fsencode(allowed / 'hard'))
        os.symlink(b'raw-\xff', os.fsencode(outside / 'link'))
        os.mkfifo(allowed / 'pipe', 0o600)
        entries = fixtures.archive.snapshot(self.output, fixtures.ROOTS)
        trees = []
        kinds = {'directory': stat.S_IFDIR, 'file': stat.S_IFREG,
                 'symlink': stat.S_IFLNK, 'fifo': stat.S_IFIFO}
        for target in (allowed, outside):
            relative = os.fsencode(target.relative_to(self.output))
            nodes = []
            for row in entries:
                path = bytes.fromhex(row['path_hex'])
                if path != relative and not path.startswith(relative + b'/'):
                    continue
                suffix = b'' if path == relative else path[len(relative) + 1:]
                node = dict(relative_hex=suffix.hex(), mode=kinds[row['kind']] | row['mode'],
                            uid=row['uid'], gid=row['gid'], device=row['source_device'],
                            inode=row['source_inode'], links=row['nlink'])
                if row['kind'] == 'file':
                    node['content_hex'] = (self.output / os.fsdecode(path)).read_bytes().hex()
                elif row['kind'] == 'symlink':
                    node['target_hex'] = row['target_hex']
                nodes.append(node)
            trees.append(dict(root_hex=os.fsencode(target).hex(), nodes=nodes))
        capture = self.output / 'filesystem-public/native'
        record = capture / 'public/scenario-000/records.jsonl'
        record.parent.mkdir(parents=True)
        record.write_bytes(canonical(dict(kind='scenario_end', scenario_id=0, filesystem=trees)))
        info = owned.lstat()
        (capture / 'HOST.json').write_bytes(canonical(dict(fixture_identity=[info.st_dev, info.st_ino, info.st_uid])))
        scene = dict(scenario_id=0, sessions=[0], observed_roots=[tree['root_hex'] for tree in trees])
        (capture / 'INPUTS.json').write_bytes(canonical(dict(groups=[dict(scenarios=[scene])])))
        (capture / 'NATIVE.json').write_bytes(canonical(dict(all_processes_terminated=True,
                                                          mechanical_archive_fixture_only=True)))
        binding = dict(execution_output_root=str(self.output), mechanical_archive_fixture_only=True)
        return fixtures, binding

    def test_public_filesystem_archive_reconstructs_and_retires_owned_complete_tree(self):
        fixtures, binding = self.public_filesystem_archive_fixture()
        retired = fixtures.retirement(ROOT, self.output, binding, create=True)
        self.assertEqual((retired['files'], retired['symlinks'], retired['fifos']), (2, 1, 1))
        self.assertFalse((self.output / fixtures.ROOTS[0]).exists())
        self.assertEqual(fixtures.retirement(ROOT, self.output, binding), retired)
        with fixtures.original_fixture(ROOT, self.output, binding, retired) as path:
            self.assertEqual(list(path.iterdir()), [])
            self.assertTrue((self.output / fixtures.HELD / 'allowed/s-000/hard').is_file())
            (path / 'actual-original-fixture').write_bytes(b'actual separate fixture bytes')
            report = self.output / 'filesystem-public/original/ORIGINAL.json'
            report.parent.mkdir()
            report.write_text('{"mechanical_archive_fixture_only":true}\n')
        proof = fixtures.retained_original(self.output, binding, retired)
        self.assertIs(proof['reconstructed_native_inode_preserved'], True)
        self.assertIs(proof['reconstructed_original_inodes'], False)
        self.assertIs(proof['original_fixture_retired'], True)
        self.assertEqual(proof['original_archive']['retained_file_bytes'], len(b'actual separate fixture bytes'))
        self.assertFalse((self.output / fixtures.ROOTS[0]).exists())
        self.assertFalse((self.output / fixtures.HELD).exists())
        self.assertEqual(fixtures.retirement(ROOT, self.output, binding), retired)
        receipt = self.output / fixtures.RESTORE
        saved = receipt.read_bytes()
        value = json.loads(saved)
        value['reconstructed_native_inode_preserved'] = False
        receipt.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'complete retained fixture reconstruction'):
            fixtures.retained_original(self.output, binding, retired)
        receipt.write_bytes(saved)
        archive = self.output / fixtures.NATIVE_ARCHIVE
        archive.write_bytes(archive.read_bytes() + b'changed')
        with self.assertRaises(ValueError):
            fixtures.retirement(ROOT, self.output, binding)

    def test_public_filesystem_failed_original_keeps_both_owned_trees(self):
        fixtures, binding = self.public_filesystem_archive_fixture()
        retired = fixtures.retirement(ROOT, self.output, binding, create=True)
        with self.assertRaisesRegex(RuntimeError, 'actual replay failed'):
            with fixtures.original_fixture(ROOT, self.output, binding, retired) as path:
                (path / 'partial-output').write_bytes(b'preserved failed replay')
                raise RuntimeError('actual replay failed')
        journal = json.loads((self.output / fixtures.RESTORE).read_bytes())
        self.assertEqual(journal['status'], 'FAIL')
        self.assertEqual((self.output / fixtures.ROOTS[0] / 'partial-output').read_bytes(), b'preserved failed replay')
        self.assertEqual((self.output / fixtures.HELD / 'allowed/s-000/hard').read_bytes(), b'complete\x00archive\n')
        self.assertFalse((self.output / fixtures.ORIGINAL_RECEIPT).exists())

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
        for name in (*ORIGINAL_RUNTIME_BLOBS, *ORIGINAL_RUNTIME_COPIES):
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
        for name in ORIGINAL_RUNTIME_COPIES:
            path = fixture / name
            original = path.read_bytes()
            with self.subTest(copied_owner=name):
                # Alter a byte outside the extracted local_linux module. The
                # complete original file, not just the extracted body, binds it.
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                with self.assertRaisesRegex(ValueError, "differs from complete pinned owner"):
                    check_original_sources(fixture)
                path.unlink()
                with self.assertRaisesRegex(ValueError, "regular unsymlinked"):
                    check_original_sources(fixture)
                path.symlink_to(ROOT / name)
                with self.assertRaisesRegex(ValueError, "regular unsymlinked"):
                    check_original_sources(fixture)
                path.unlink()
                path.write_bytes(original)
        self.assertEqual(set(check_original_sources(fixture)), set(ORIGINAL_RUNTIME_BLOBS))

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

    def test_batch_public_fd_inheritance_tracks_clone_and_owned_lifetimes(self):
        """Synthetic trace-order controls; no HIA, Rust or business invocation."""
        from hia_native_batch_public_pipeline import reader

        def q(raw):
            return '"' + "".join("\\x%02x" % b for b in raw) + '"'


        def controls():
            op = 'openat(AT_FDCWD, %s, O_RDONLY) = 3</fixture/file> <0.000001>' % q(b"/fixture/file")
            close = 'close(3</fixture/file>) = 0 <0.000001>'
            clone = 'clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = 101 <0.000002>'
            begin = 'clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD <unfinished ...>'
            resumed = '<... clone resumed>) = 101 <0.000010>'
            shared = 'clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = 101 <0.000002>'
            start = [(100, 'execve(%s, [], []) = 0 <0.000001>' % q(b"/fixture/carrier")), (100, op)]
            end = (100, 'exit(0) = ?')
            def wait(child):
                return (100, 'wait4(%d, [{WIFEXITED(s) && WEXITSTATUS(s) == 0}], 0, NULL) = %d <0.000002>' % (child, child))
            cases = [
                ('private-explicit-both-close', start + [(100, clone), (100, close), (101, close), (101, 'exit(0) = ?'), end], True, 1),
                ('private-inherited-exit-without-join', start + [(100, clone), (100, close), (101, 'exit(0) = ?'), end], False, None),
                ('resumed-child-close-visible-first', start + [(100, begin), (101, close), (100, resumed), (100, close), (101, 'exit(0) = ?'), end], True, 1),
                ('resumed-child-exit-visible-first-without-join', start + [(100, begin), (101, 'exit(0) = ?'), (100, resumed), (100, close), end], False, None),
                ('shared-child-closes-one-table', start + [(100, shared), (101, close), (101, 'exit(0) = ?'), end], True, 0),
                ('shared-parent-closes-one-table', start + [(100, shared), (100, close), (101, 'exit(0) = ?'), end], True, 0),
                ('shared-resumed-child-close-visible-first', start + [(100, begin.replace('CLONE_VM|SIGCHLD', 'CLONE_VM|CLONE_FILES|SIGCHLD')),
                    (101, close), (101, 'exit(0) = ?'), (100, resumed), end], True, 0),
                ('private-parent-reuses-own-fd', start + [(100, clone), (100, close),
                    (100, op.replace(q(b'/fixture/file'), q(b'/fixture/other')).replace('</fixture/file>', '</fixture/other>')),
                    (101, close), (100, close.replace('/fixture/file', '/fixture/other')), (101, 'exit(0) = ?'), end], True, 1),
                ('private-two-child-copies', start + [(100, clone), (100, clone.replace('= 101 ', '= 102 ')),
                    (100, close), (101, close), (102, close), (101, 'exit(0) = ?'), (102, 'exit(0) = ?'), end], True, 2),
                ('failed-clone-no-child-table', start + [(100, 'clone(child_stack=NULL, flags=CLONE_VM|SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable) <0.000002>'),
                    (100, close), end], True, 0),
                ('fork-copies-current-table', start + [(100, 'fork() = 101 <0.000002>'), (100, close), (101, close), (101, 'exit(0) = ?'), end], True, 1),
                ('vfork-copies-current-table', start + [(100, 'vfork() = 101 <0.000002>'), (101, close), (101, 'exit(0) = ?'), (100, close), end], True, 1),
                ('shared-parent-change-during-private-clone-ambiguous', start + [(100, shared),
                    (100, begin), (101, close), (100, resumed.replace('= 101 ', '= 102 ')),
                    (102, 'exit(0) = ?'), (101, 'exit(0) = ?'), wait(102), end], False, None),
            ]
            joined = {'private-explicit-both-close', 'resumed-child-close-visible-first',
                      'private-parent-reuses-own-fd', 'private-two-child-copies',
                      'fork-copies-current-table', 'vfork-copies-current-table'}
            cases = [(name, rows[:-1] + [wait(101)] + ([wait(102)] if name == 'private-two-child-copies' else []) + rows[-1:]
                      if name in joined else rows, accepted, copies) for name, rows, accepted, copies in cases]
            child_open = (101, 'openat(AT_FDCWD, %s, O_RDONLY) = 4</fixture/child> <0.000001>' % q(b'/fixture/child'))
            cases += [
                ('inherited-reference-exit-join-owner-close', start + [(100, clone), (101, 'exit(0) = ?'), wait(101), (100, close), end], True, 1),
                ('child-owned-open-without-explicit-close', start + [(100, clone), child_open, (101, 'exit(0) = ?'), wait(101), (100, close), end], False, None),
                ('child-owned-dup-without-explicit-close', start + [(100, clone), (101, 'dup(3</fixture/file>) = 4</fixture/file> <0.000001>'),
                     (101, 'exit(0) = ?'), wait(101), (100, close), end], False, None),
                ('inherited-reference-without-owner-close', start + [(100, clone), (101, 'exit(0) = ?'), wait(101), end], False, None),
                ('inherited-reference-wrong-wait-target', start + [(100, clone), (101, 'exit(0) = ?'),
                     (100, wait(101)[1].replace('wait4(101,', 'wait4(102,')), (100, close), end], False, None),
                ('inherited-reference-missing-child-exit', start + [(100, clone), wait(101), (100, close), end], False, None),
            ]
            for name, rows, accepted, copies in cases:
                raw = b''.join(('%d 1800000000.%06d %s\n' % (pid, i, body)).encode()
                               for i, (pid, body) in enumerate(rows, 1))
                yield name, raw, accepted, copies

        cases = list(controls())
        self.assertEqual(len(cases), 19)
        with reader(ROOT) as qualified:
            trace = qualified.trace
            for name, raw, accepted, copies in cases:
                with self.subTest(control=name):
                    parsed = trace.parse_trace(raw, markers=False)
                    if not accepted:
                        with self.assertRaises(ValueError):
                            trace.descriptor_lifetimes(parsed, b'/fixture')
                        continue
                    value = trace.descriptor_lifetimes(parsed, b'/fixture')
                    self.assertEqual(value['inherited_file_copies'], copies)
                    self.assertEqual(value['unretired_fixture_descriptors'], 0)
                    self.assertEqual(value['implicit_nonfixture_retirements'], [])
                    self.assertEqual(len(value['nonshared_child_reaps']), copies)
                    implicit = value['implicit_inherited_retirements']
                    if name == 'inherited-reference-exit-join-owner-close':
                        self.assertEqual(len(implicit), 1)
                        owned = implicit[0]
                        self.assertEqual((owned['owner_tid'], owned['owner_fd'],
                                          owned['copy_parent_tid'], owned['copy_child_tid'],
                                          owned['exit_tid'], owned['owner_close_tid']),
                                         (100, 3, 100, 101, 101, 100))
                        self.assertEqual(owned['path_hex'], b'/fixture/file'.hex())
                        self.assertLess(owned['owner_open_line'], owned['clone_start_line'])
                        self.assertLessEqual(owned['clone_start_line'], owned['clone_end_line'])
                        self.assertLess(owned['clone_end_line'], owned['exit_line'])
                        self.assertLess(owned['exit_line'], owned['wait_end_line'])
                        self.assertLess(owned['wait_end_line'], owned['owner_close_line'])
                    else:
                        self.assertEqual(implicit, [])
                    for reap in value['nonshared_child_reaps']:
                        self.assertEqual(reap['parent_tid'], 100)
                        self.assertIn(reap['child_tid'], (101, 102))
                        self.assertLess(reap['exit_line'], reap['wait_end_line'])

    def test_batch_public_fixture_absence_handles_missing_ancestors_safely(self):
        import errno
        import os
        import hia_native_batch_public_fixtures as fixtures

        controls = []
        with tempfile.TemporaryDirectory(prefix="batch-absence-", dir=self.output) as temporary:
            owned = Path(temporary)
            output = owned / "output"
            output.mkdir()
            (output / "one" / "two").mkdir(parents=True)
            (output / "batch-public" / "native").mkdir(parents=True)
            outside = owned / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"outside bytes must not be traversed or changed")
            sentinel_before = (sentinel.stat().st_dev, sentinel.stat().st_ino,
                               sentinel.stat().st_mode, sentinel.read_bytes())

            def entries():
                result = []
                for parent, dirs, files in os.walk(output, followlinks=False):
                    result.extend(str((Path(parent) / name).relative_to(output))
                                  for name in dirs + files)
                return sorted(result)

            def check(name, root, paths, errors=None, expected_errno=None):
                descriptors = sorted(os.listdir("/proc/self/fd"))
                names = entries()
                if errors is None:
                    fixtures.absent(root, paths)
                    result = "accepted"
                else:
                    with self.assertRaises(errors) as caught:
                        fixtures.absent(root, paths)
                    if expected_errno is not None:
                        self.assertIn(caught.exception.errno, expected_errno)
                    result = type(caught.exception).__name__
                self.assertEqual(sorted(os.listdir("/proc/self/fd")), descriptors)
                self.assertEqual(entries(), names)
                self.assertEqual((sentinel.stat().st_dev, sentinel.stat().st_ino,
                                  sentinel.stat().st_mode, sentinel.read_bytes()), sentinel_before)
                controls.append({"name": name, "result": result,
                                 "fd_set_unchanged": True, "directory_entries_unchanged": True})

            # This is the actual failed call shape: native's parent exists,
            # while the original producer has not created its own parent yet.
            with self.assertRaises(FileNotFoundError):
                fixtures.archive.absent(output, (fixtures.NATIVE, fixtures.HELD, fixtures.ORIGINAL))
            controls.append({"name": "legacy_missing_original_parent",
                             "result": "FileNotFoundError"})
            check("missing_first_ancestor", output, ("missing/parent/leaf",))
            check("missing_middle_ancestor", output, ("one/missing/leaf",))
            check("missing_leaf", output, ("one/two/missing",))
            check("native_held_original_initial_absence", output,
                  (fixtures.NATIVE, fixtures.HELD, fixtures.ORIGINAL))
            self.assertFalse((output / "batch-public/original").exists())

            (output / "one/two/directory").mkdir()
            (output / "one/two/file").write_bytes(b"owned existing file")
            (output / "one/two/symlink").symlink_to(outside, target_is_directory=True)
            (output / "one/two/dangling").symlink_to(owned / "not-present")
            for leaf in ("directory", "file", "symlink", "dangling"):
                check("existing_target_" + leaf, output, ("one/two/" + leaf,), ValueError)

            (output / "one/ancestor-file").write_bytes(b"not a directory")
            (output / "one/ancestor-link").symlink_to(outside, target_is_directory=True)
            (output / "one/ancestor-dangling").symlink_to(owned / "not-present")
            (output / "first-file").write_bytes(b"not a directory")
            (output / "first-link").symlink_to(outside, target_is_directory=True)
            for ancestor in ("one/ancestor-file", "one/ancestor-link",
                             "one/ancestor-dangling", "first-file", "first-link"):
                check("non_directory_ancestor_" + ancestor, output, (ancestor + "/missing",),
                      OSError, (errno.ENOTDIR, errno.ELOOP))

            for index, name in enumerate(("", "/absolute/leaf", "../leaf", "one//leaf",
                                          "one/./leaf", "one/../leaf", "one/\0/leaf", "one/")):
                check("unsafe_relative_path_%d" % index, output, (name,), ValueError)

            check("missing_output_root", owned / "absent-output", ("missing/leaf",),
                  FileNotFoundError)
            root_link = owned / "linked-output"
            root_link.symlink_to(output, target_is_directory=True)
            check("symlink_output_root", root_link, ("missing/leaf",), ValueError)
            root_file = owned / "file-output"
            root_file.write_bytes(b"not a directory")
            check("file_output_root", root_file, ("missing/leaf",), ValueError)
            aliased_parent = owned / "linked-parent"
            aliased_parent.symlink_to(owned, target_is_directory=True)
            check("symlink_above_output_root", aliased_parent / "output",
                  ("missing/leaf",), ValueError)
        self._batch_absence_controls = controls

    def test_batch_call_fixture_root_permissions_do_not_depend_on_ambient_umask(self):
        import ast
        import os
        import stat

        source = ROOT / "tests/hia_native/test_batch_call.py"
        tree = ast.parse(source.read_bytes(), filename=str(source))
        capture = next(node for node in tree.body
                       if isinstance(node, ast.ClassDef) and node.name == "Capture")
        constructor = next(node for node in capture.body
                           if isinstance(node, ast.FunctionDef) and node.name == "__init__")
        nodes = []
        for node in constructor.body:
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            call = node.value
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "mkdir":
                continue
            target = call.func.value
            if (isinstance(target, ast.BinOp) and isinstance(target.op, ast.Div)
                    and isinstance(target.left, ast.Name) and target.left.id == "output"
                    and isinstance(target.right, ast.Constant) and target.right.value == "files"):
                nodes.append(node)
        self.assertEqual(len(nodes), 1)
        create = compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec")
        saved = os.umask(0o022)
        try:
            for mask in (0o022, 0o077):
                with self.subTest(umask=oct(mask)):
                    os.umask(mask)
                    output = self.output / ("fixture-mask-" + format(mask, "03o"))
                    output.mkdir()
                    descriptors = sorted(os.listdir("/proc/self/fd"))
                    exec(create, {"output": output})
                    root = output / "files"
                    self.assertEqual(root.lstat().st_mode, stat.S_IFDIR | 0o700)
                    actual = int(next(line.split()[1] for line in
                        Path("/proc/self/status").read_bytes().splitlines()
                        if line.startswith(b"Umask:")), 8)
                    self.assertEqual(actual, mask)
                    ordinary = root / "ordinary"
                    ordinary.mkdir()
                    self.assertEqual(stat.S_IMODE(ordinary.stat().st_mode), 0o777 & ~mask)
                    before = root.lstat()
                    with self.assertRaises(FileExistsError):
                        exec(create, {"output": output})
                    after = root.lstat()
                    self.assertEqual((before.st_dev, before.st_ino, before.st_mode,
                                      before.st_uid, before.st_gid),
                                     (after.st_dev, after.st_ino, after.st_mode,
                                      after.st_uid, after.st_gid))
                    self.assertEqual(sorted(os.listdir("/proc/self/fd")), descriptors)
        finally:
            os.umask(saved)





    def test_public_source_manifest_complete_batch_import_contract(self):
        import copy
        import hia_native_runtime_mcp_evidence as reader
        manifest = ROOT / "native/runtime_mcp_sources.json"
        raw = manifest.read_bytes()
        proof = reader.decode(raw)
        self.assertEqual(sorted(proof), ["batch_development_import", "schema", "sources"])
        admitted = reader.source_identity(ROOT)
        self.assertEqual(admitted, {"manifest_sha256": reader.sha(raw), "files": proof["sources"]})
        self.assertEqual(len(admitted["files"]), 151)
        self.assertEqual(proof["batch_development_import"]["members"], 71)
        copied = self.output / "source/native/runtime_mcp_sources.json"
        copied.parent.mkdir(parents=True)
        for name in ("missing-import", "unknown-field"):
            with self.subTest(name=name):
                altered = copy.deepcopy(proof)
                if name == "missing-import":
                    del altered["batch_development_import"]
                else:
                    altered["unbound"] = True
                changed = reader.compact(altered)
                copied.write_bytes(changed)
                with patch.object(reader, "SOURCE_MANIFEST_SHA256", reader.sha(changed)):
                    with self.assertRaisesRegex(ValueError, "source manifest fields differ"):
                        reader.source_identity(copied.parent.parent)

    def test_request_registry_admits_actual_generic_build_record(self):
        import ast
        import copy
        import qualify_hia_runtime_native as main
        import hia_native_request_registry_pipeline as reader
        component = next(item for item in main.MODULES if item["key"] == reader.KEY)
        self.assertNotIn("builder", component)
        source = (ROOT / "scripts/qualify_hia_runtime_native.py").read_bytes()
        function = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef) and node.name == "prepare_native")
        assignments = [node for node in ast.walk(function) if isinstance(node, ast.Assign)
                       and len(node.targets) == 1
                       and ast.unparse(node.targets[0]) == "report['modules'][item['key']]"]
        self.assertEqual(len(assignments), 1)
        built = self.output / reader.MANIFEST
        built.parent.mkdir(parents=True)
        built.write_bytes(b'{"schema":"registration-metadata-fixture"}\n')
        report = {"modules": {}}
        program = ast.fix_missing_locations(ast.Module(body=assignments, type_ignores=[]))
        exec(compile(program, "actual-prepare-native-module-record", "exec"),
             {"item": component, "built": built, "output": self.output,
              "report": report, "sha": main.sha})
        self.assertEqual(report["modules"][reader.KEY]["builder"], "borrowed_bytes")
        reader._module(self.output, report)
        for bad in (None, "", "runtime_mcp", False, 0, {}):
            with self.subTest(builder=bad):
                altered = copy.deepcopy(report)
                altered["modules"][reader.KEY]["builder"] = bad
                with self.assertRaisesRegex(ValueError, "generic request-registry NativeBuild"):
                    reader._module(self.output, altered)
        altered = copy.deepcopy(report)
        del altered["modules"][reader.KEY]["builder"]
        with self.assertRaisesRegex(ValueError, "generic request-registry NativeBuild"):
            reader._module(self.output, altered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
