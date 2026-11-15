#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Synthetic file-binding regressions; never launch a runtime, helper or SSH.

The executable fixtures are inert bytes with an executable permission bit. Their
invented qualification/audit documents exercise this loader's integrity contract;
they are not represented as real build, test or native-validation evidence.
"""
import argparse
import ast
import copy
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock


ROOT = Path(__file__).resolve().parent
RUNNER = ROOT / "run_paired_native_validation.py"
# Public placement uses the unchanged historical directory. An isolated review
# bundle contains exact-SHA copies beside these tests instead; neither is run.
LEGACY = ROOT.parent / "20261028"
REFERENCE = LEGACY / "run_native_validation.py" if LEGACY.is_dir() else ROOT / "run_native_validation.original.py"
PROTOCOL = LEGACY / "pinned_native_protocol.py" if LEGACY.is_dir() else ROOT / "pinned_native_protocol.py"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


r = module(RUNNER, "paired_native_under_test")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o700 if executable else 0o600)
    return digest(raw)


def document(path, value):
    return write(path, (json.dumps(value, indent=2) + "\n").encode())


class QualificationFixture:
    """Build two retained test artifacts and complete, internally bound metadata."""
    def __init__(self, root, label):
        self.label = label
        self.root = root / label
        self.source = self.root / "source"
        self.qualification = self.root / "qualification"
        self.evidence = self.qualification / "isolated-tests"
        self.evidence.mkdir(parents=True)
        self.path = self.qualification / "report.json"
        self.map_path = self.qualification / "source-map.json"
        self.audit_path = self.qualification / "isolated-tests.audit.json"
        self.files = {
            "Cargo.toml": b"synthetic cargo manifest\n", "Cargo.lock": b"synthetic lock\n",
            "rustfmt.toml": b"hard_tabs = true\n",
            "src/lib.rs": ("synthetic fixture " + label + "\n").encode(),
            "examples/fixture.rs": b"synthetic example\n",
        }
        self.source_map = {name: write(self.source / name, raw) for name, raw in self.files.items()}
        self.harness_map = {name: write(self.source / "tools/x230/20261028" / name,
                                       ("synthetic helper " + name + "\n").encode())
                            for name in ("qualify.py", "run_isolated_tests.py", "audit_isolated_tests.py")}
        self.map_sha = document(self.map_path, self.source_map)
        write(self.evidence / "source-manifest.input", self.map_path.read_bytes())
        self.stages = []
        for name in r.GATES:
            item = {"name": name, "returncode": 0}
            for stream in ("stdout", "stderr"):
                filename = "cargo-no-run.jsonl" if (name, stream) == ("test-build", "stdout") else name + "." + stream
                item[stream + "_sha256"] = write(self.qualification / filename,
                                                  (name + " " + stream + "\n").encode())
            self.stages.append(item)
        self.releases = {}
        for name in ("hepta-runtime", "hepta-runtime-jobctl", "native_process_driver"):
            path = self.qualification / name
            sha = write(path, (label + " inert release " + name).encode(), executable=True)
            self.releases[name] = {"path": str(path), "sha256": sha}
        self.test_paths = [self.qualification / "test-binaries" / ("test-" + str(i)) for i in range(2)]
        self.test_shas = [write(path, (label + " inert test " + str(i)).encode(), executable=True)
                          for i, path in enumerate(self.test_paths)]
        retained_path = self.qualification / "retained-artifacts.jsonl"
        retained_raw = b'{"reason":"synthetic-binding-fixture"}\n'
        retained_sha = write(retained_path, retained_raw)
        write(self.evidence / "cargo-artifacts.jsonl", retained_raw)
        self.summary = {
            "schema": "hepta-isolated-libtest/v1", "success": True, "filter": "", "retries": 0,
            "passed": 2, "failed": 0, "ignored": 1, "selected": 3,
            "source_manifest_path": str(self.map_path), "source_manifest_sha256": self.map_sha,
            "artifacts_path": str(retained_path), "artifacts_sha256": retained_sha,
            "binaries": [{"path": str(path)} for path in self.test_paths],
        }
        document(self.evidence / "summary.json", self.summary)
        write(self.evidence / "commands.jsonl", b'{"synthetic":"commands"}\n')
        write(self.evidence / "tests.jsonl", b'{"synthetic":"tests"}\n')
        commands = []
        for tag in ("binary-000-list", "binary-000-ignored", "binary-001-list", "binary-001-ignored",
                    "case-000001", "case-000003"):
            item = {"stdout_gzip": tag + ".stdout.log.gz"}
            for stream in ("stdout", "stderr"):
                sha = write(self.evidence / (tag + "." + stream + ".log.gz"),
                            gzip.compress((tag + " " + stream).encode(), mtime=0))
                item[stream] = {"gzip_sha256": sha}
            commands.append(item)
        self.audit = {
            "schema": "hepta-isolated-libtest-audit/v1", "success": True, "expected_filter": "",
            "errors": [], "passed": 2, "failed": 0, "ignored": 1, "selected": 3, "executed": 2,
            "evidence": str(self.evidence), "auditor_sha256": self.harness_map["audit_isolated_tests.py"],
            "input_sha256": {name: digest((self.evidence / name).read_bytes()) for name in r.AUDIT_INPUTS},
            "binaries": [{"path": str(path), "recorded_before_sha256": sha, "current_after_sha256": sha,
                          "inventory_count": 2 if i == 0 else 1,
                          "ignored_names": ["ignored_fixture"] if i == 0 else []}
                         for i, (path, sha) in enumerate(zip(self.test_paths, self.test_shas))],
            "commands": commands,
        }
        self.report = {
            "schema": "hepta-x230-composed-qualification/v1", "qualified": True,
            "automatic_test_retries": 0, "source": str(self.source),
            "source_tested": self.source_map, "source_after": self.source_map,
            "stages": self.stages, "harness_before": self.harness_map, "harness_after": self.harness_map,
            "binaries": self.releases,
        }
        self.save()

    def save(self):
        self.report_sha = document(self.path, self.report)
        self.audit_sha = document(self.audit_path, self.audit)

    def arguments(self, namespace=None):
        value = namespace or argparse.Namespace()
        prefix = "" if self.label == "candidate" else "baseline_"
        for key, item in {"qualification": self.path, "qualification_sha256": self.report_sha,
                          "source_map": self.map_path, "source_map_sha256": self.map_sha,
                          "test_audit": self.audit_path, "test_audit_sha256": self.audit_sha}.items():
            setattr(value, prefix + key, item)
        return value


class BindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = r.load_protocol(PROTOCOL)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="paired-native-bindings-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sequence = 0

    def fixture(self, label="candidate"):
        self.sequence += 1
        return QualificationFixture(self.root / str(self.sequence), label)

    def load(self, fixture, args=None):
        self.sequence += 1
        output = self.root / ("evidence-" + str(self.sequence))
        output.mkdir()
        return r.load_candidate(self.p, args or fixture.arguments(), output, fixture.label)

    def test_both_arms_bind_their_complete_original_inventory(self):
        bundles = {}
        for label in ("baseline", "candidate"):
            fixture = self.fixture(label)
            bundle = self.load(fixture)
            bundles[label] = bundle
            self.assertEqual(bundle["version"], {"baseline": "R6a", "candidate": "R7b"}[label])
            self.assertEqual(bundle["source_kind"], "composed-compiler-inputs/v1")
            self.assertEqual(bundle["source_map_file"]["sha256"], fixture.map_sha)
            self.assertEqual(set(bundle["release_artifacts"]), set(fixture.releases))
            self.assertEqual(set(bundle["test_artifacts"]), {str(path) for path in fixture.test_paths})
            self.assertEqual(bundle["test_audit"]["selected"], 3)
            self.assertEqual(bundle["test_audit"]["executables"], 2)
            for name in r.AUDIT_INPUTS:
                self.assertIn(str(fixture.evidence / name), bundle["pinned"])
            r.assert_composed_bundle_unchanged(self.p, bundle)
        with self.assertRaisesRegex(RuntimeError, "accepted R6a"):
            r.validate_pair(bundles)

    def test_report_sha_and_final_success_are_required_for_each_arm(self):
        for label in ("baseline", "candidate"):
            with self.subTest(label=label):
                fixture = self.fixture(label)
                args = fixture.arguments()
                setattr(args, ("" if label == "candidate" else "baseline_") + "qualification_sha256", "0" * 64)
                with self.assertRaisesRegex(RuntimeError, "qualification SHA differs"):
                    self.load(fixture, args)
                fixture.report["qualified"] = False
                fixture.save()
                with self.assertRaisesRegex(RuntimeError, "not complete and successful"):
                    self.load(fixture)

    def test_all_eight_successful_gates_must_remain_in_original_order(self):
        for alteration in ("missing", "duplicate", "reordered", "failed", "boolean_returncode"):
            with self.subTest(alteration=alteration):
                fixture = self.fixture()
                if alteration == "missing":
                    fixture.stages.pop()
                elif alteration == "duplicate":
                    fixture.stages.append(copy.deepcopy(fixture.stages[-1]))
                elif alteration == "reordered":
                    fixture.stages[2], fixture.stages[3] = fixture.stages[3], fixture.stages[2]
                else:
                    fixture.stages[3]["returncode"] = 1 if alteration == "failed" else False
                fixture.save()
                with self.assertRaisesRegex(RuntimeError, "qualification has"):
                    self.load(fixture)

    def test_current_compiler_content_and_exact_map_bytes_are_required(self):
        fixture = self.fixture()
        write(fixture.source / "src/lib.rs", b"changed source\n")
        with self.assertRaisesRegex(RuntimeError, "tested/current source"):
            self.load(fixture)
        fixture = self.fixture()
        fixture.map_sha = write(fixture.map_path, json.dumps(fixture.source_map, separators=(",", ":")).encode())
        with self.assertRaisesRegex(RuntimeError, "exact original source-map bytes"):
            self.load(fixture)

    def test_audit_of_other_arm_and_source_map_copy_cannot_be_substituted(self):
        candidate, baseline = self.fixture(), self.fixture("baseline")
        args = candidate.arguments()
        args.test_audit, args.test_audit_sha256 = baseline.audit_path, baseline.audit_sha
        with self.assertRaisesRegex(RuntimeError, "original qualification output"):
            self.load(candidate, args)
        args = candidate.arguments()
        args.source_map = candidate.root / "source-map-copy.json"
        write(args.source_map, candidate.map_path.read_bytes())
        with self.assertRaisesRegex(RuntimeError, "original qualification output"):
            self.load(candidate, args)

    def test_full_audit_filter_counts_auditor_and_command_coverage_are_mandatory(self):
        changes = [("expected_filter", "one_test"), ("failed", 1), ("selected", 4),
                   ("passed", True), ("auditor_sha256", "0" * 64), ("commands", [])]
        for key, value in changes:
            with self.subTest(field=key):
                fixture = self.fixture()
                fixture.audit[key] = value
                fixture.save()
                with self.assertRaises(RuntimeError):
                    self.load(fixture)

    def test_missing_or_changed_second_test_executable_refuses_both_arms(self):
        for label in ("baseline", "candidate"):
            for change in ("missing", "changed"):
                with self.subTest(label=label, change=change):
                    fixture = self.fixture(label)
                    path = fixture.test_paths[1]
                    if change == "missing":
                        path.unlink()
                    else:
                        write(path, b"different retained test bytes", executable=True)
                    with self.assertRaises((RuntimeError, FileNotFoundError)):
                        self.load(fixture)

    def test_every_retained_test_stream_and_original_cargo_input_is_pinned(self):
        for name in ("binary-001-ignored.stderr.log.gz", "case-000003.stdout.log.gz",
                     "cargo-artifacts.jsonl", "commands.jsonl", "tests.jsonl"):
            with self.subTest(name=name):
                fixture = self.fixture()
                write(fixture.evidence / name, b"changed retained evidence")
                with self.assertRaisesRegex(RuntimeError, "changed"):
                    self.load(fixture)
        fixture = self.fixture()
        write(fixture.qualification / "retained-artifacts.jsonl", b"different original artifacts\n")
        with self.assertRaisesRegex(RuntimeError, "original retained Cargo artifacts changed"):
            self.load(fixture)

    def test_original_full_summary_cannot_claim_different_filter_map_or_counts(self):
        for field, value in (("filter", "only_subset"), ("retries", 1), ("passed", 1),
                             ("source_manifest_sha256", "0" * 64), ("success", False)):
            with self.subTest(field=field):
                fixture = self.fixture()
                fixture.summary[field] = value
                fixture.audit["input_sha256"]["summary.json"] = document(fixture.evidence / "summary.json", fixture.summary)
                fixture.save()
                with self.assertRaisesRegex(RuntimeError, "original isolated summary"):
                    self.load(fixture)

    def test_audit_input_set_and_retained_executable_inventory_cannot_shrink(self):
        fixture = self.fixture()
        del fixture.audit["input_sha256"]["tests.jsonl"]
        fixture.save()
        with self.assertRaisesRegex(RuntimeError, "audit-input inventory"):
            self.load(fixture)
        fixture = self.fixture()
        fixture.audit["binaries"].pop()
        fixture.save()
        with self.assertRaisesRegex(RuntimeError, "executable inventory differs"):
            self.load(fixture)

    def test_parsed_map_uses_guarded_bytes_and_later_mutation_is_detected(self):
        fixture = self.fixture()
        target = fixture.evidence / "source-manifest.input"
        original = self.p.receipt
        captured = []
        def replace_after_read(path, contents=False):
            result = original(path, contents=contents)
            if Path(path) == target and contents:
                captured.append(True)
                write(target, b'{"changed_after_guarded_read":true}\n')
            return result
        with mock.patch.object(self.p, "receipt", side_effect=replace_after_read):
            bundle = self.load(fixture)
        self.assertEqual(captured, [True])
        self.assertEqual(bundle["source_map"], fixture.source_map)
        with self.assertRaisesRegex(RuntimeError, "pinned input changed"):
            r.assert_composed_bundle_unchanged(self.p, bundle)

    def test_repeated_checks_cover_both_source_sets_and_all_retained_artifacts(self):
        for label in ("baseline", "candidate"):
            for target in ("source", "harness_addition", "report", "map", "audit", "test", "jobctl", "test_log"):
                with self.subTest(label=label, target=target):
                    fixture = self.fixture(label)
                    bundle = self.load(fixture)
                    path = {
                        "source": fixture.source / "src/lib.rs",
                        "harness_addition": fixture.source / "tools/x230/20261028/new.py",
                        "report": fixture.path, "map": fixture.map_path, "audit": fixture.audit_path,
                        "test": fixture.test_paths[1], "jobctl": fixture.qualification / "hepta-runtime-jobctl",
                        "test_log": fixture.evidence / "case-000003.stderr.log.gz",
                    }[target]
                    write(path, b"late modification\n", executable=target in {"test", "jobctl"})
                    with self.assertRaises(RuntimeError):
                        r.assert_composed_bundle_unchanged(self.p, bundle)

    def test_historical_bundle_cannot_use_composed_source_checker(self):
        fixture = self.fixture()
        bundle = self.load(fixture)
        bundle["source_kind"] = "historical-all-tree-map"
        with self.assertRaisesRegex(RuntimeError, "typed composed"):
            r.assert_composed_bundle_unchanged(self.p, bundle)

    def test_output_cannot_write_under_either_source_or_qualification_tree(self):
        baseline, candidate = self.fixture("baseline"), self.fixture()
        args = candidate.arguments(baseline.arguments())
        args.out, args.socket_parent = self.root / "safe-output", self.root / "safe-sockets"
        r.assert_output_placement(self.p, args)
        for fixture in (baseline, candidate):
            for tree in (fixture.source, fixture.qualification):
                for argument in ("out", "socket_parent"):
                    with self.subTest(label=fixture.label, tree=tree.name, argument=argument):
                        changed = copy.copy(args)
                        target = tree / "must-not-be-created"
                        setattr(changed, argument, target)
                        with self.assertRaisesRegex(RuntimeError, "outside both original"):
                            r.assert_output_placement(self.p, changed)
                        self.assertFalse(target.exists())

    def test_pair_requires_exact_baseline_binding_and_distinct_arm_identities(self):
        bundles = {label: self.load(self.fixture(label)) for label in ("baseline", "candidate")}
        baseline = bundles["baseline"]
        synthetic_binding = {"qualification_sha256": baseline["report"]["sha256"],
                             "source_map_sha256": baseline["source_map_file"]["sha256"],
                             "test_audit_sha256": baseline["test_audit"]["report"]["sha256"],
                             "binary_sha256": baseline["binary"]["sha256"]}
        with self.assertRaisesRegex(RuntimeError, "accepted R6a"):
            r.validate_pair(bundles)
        with mock.patch.dict(r.BASELINE_BINDING, synthetic_binding, clear=True):
            r.validate_pair(bundles)
            for field in ("label", "version", "source_kind", "binary", "source", "report", "source_map_file"):
                with self.subTest(field=field):
                    changed = copy.deepcopy(bundles)
                    changed["candidate"][field] = ("wrong" if field in {"label", "version", "source_kind"}
                                                   else copy.deepcopy(changed["baseline"][field]))
                    with self.assertRaises(RuntimeError):
                        r.validate_pair(changed)


class ProtocolPreservationTests(unittest.TestCase):
    def test_original_protocol_helpers_workload_and_stage_loops_are_preserved(self):
        self.assertEqual(digest(REFERENCE.read_bytes()), r.REFERENCE_RUNNER_SHA)
        self.assertEqual(digest(PROTOCOL.read_bytes()), r.PROTOCOL_SHA)
        old, new = ast.parse(REFERENCE.read_bytes()), ast.parse(RUNNER.read_bytes())
        def definitions(tree):
            return {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        before, after = definitions(old), definitions(new)
        for name in ("load_protocol", "candidate_sources", "harness_files", "load_gate", "LoadSamples",
                     "validate_files", "make_plan", "comparison"):
            self.assertEqual(ast.dump(before[name]), ast.dump(after[name]), name)
        def stage_loops(main):
            return [ast.dump(node) for node in main.body
                    if isinstance(node, ast.Try)
                    for node in node.body
                    if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == "stage"]
        self.assertEqual(len(stage_loops(before["main"])), 2)
        self.assertEqual(stage_loops(before["main"]), stage_loops(after["main"]))
        def constants(tree, name):
            return next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
        for name in ("TOOLS", "BUSY_NAMES", "SOAK_SECONDS", "DEV_ROOT", "HISTORY"):
            if name in {"DEV_ROOT", "HISTORY"}:
                continue
            self.assertEqual(constants(old, name), constants(new, name), name)
        self.assertEqual(constants(new, "SOAK_SECONDS"), 120)
        forbidden = [node for node in ast.walk(new) if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                     and node.func.value.id == "p" and node.func.attr in {"load_qualification", "assert_bundle_unchanged", "main"}]
        self.assertEqual(forbidden, [])

    def test_fixed_eight_stage_matrix_uses_r6a_and_r7b_with_no_execution(self):
        args = argparse.Namespace(out=Path("/tmp/paired-plan-fixture"), socket_parent=Path("/tmp/pnf"),
                                  tools_dir=Path("/tmp/pinned-tools"), profile_template=Path("/tmp/profile-fixture"),
                                  frozen_jobs=Path("/tmp/frozen-fixture"))
        bundles = {label: {"binary": {"path": "/tmp/" + label + "-inert", "sha256": label[0] * 64}}
                   for label in ("baseline", "candidate")}
        protocol = argparse.Namespace(direct=lambda path, exists=False: path)
        plan = r.make_plan(protocol, args, bundles, "syntheticonly")
        self.assertEqual([(row["name"], row["kind"], row["arm"], row["budget_seconds"]) for row in plan], [
            ("small-archive-abba", "small", "both", 300), ("inherited-pipes", "pipe", "candidate", 400),
            ("six-running-recovery", "recovery", "candidate", 480),
            ("file-abba-0-baseline", "file_abba", "baseline", 250),
            ("file-abba-1-candidate", "file_abba", "candidate", 250),
            ("file-abba-2-candidate", "file_abba", "candidate", 250),
            ("file-abba-3-baseline", "file_abba", "baseline", 250),
            ("candidate-c8-soak-120s", "soak", "candidate", 300)])
        for row in plan:
            self.assertIs(row["trace"], False)
            self.assertEqual(row["execution_count"], 0)
            self.assertIs(row["executed"], False)
        self.assertIn("--cancel-during-drain", plan[1]["argv"])
        self.assertEqual(plan[-1]["argv"][plan[-1]["argv"].index("--soak-seconds") + 1], "120")
        self.assertEqual(plan[-1]["argv"][plan[-1]["argv"].index("--candidate") + 1], "/tmp/candidate-inert")

    def test_cli_requires_explicit_both_arm_map_report_audit_pins(self):
        arguments = []
        for prefix in ("", "baseline-"):
            for name in ("qualification", "source-map", "test-audit"):
                arguments += ["--" + prefix + name, "/tmp/" + prefix + name,
                              "--" + prefix + name + "-sha256", "a" * 64]
        arguments += ["--out", "/tmp/native-fixture-out", "--socket-parent", "/tmp/nf",
                      "--protocol-library", str(PROTOCOL)]
        parsed = r.parse_args(arguments)
        self.assertEqual(parsed.baseline_source_map_sha256, "a" * 64)
        for option in ("--baseline-qualification", "--baseline-test-audit-sha256", "--source-map-sha256",
                       "--protocol-library"):
            missing = list(arguments)
            index = missing.index(option)
            del missing[index:index + 2]
            with self.subTest(option=option), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                r.parse_args(missing)
        for value in ("A" * 64, "f" * 63, "../" + "0" * 64, ""):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                r.sha_argument(value)

    def test_json_binding_refuses_ambiguous_keys_and_nonfinite_constants(self):
        for raw in (b'{"qualified":true,"qualified":false}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises((RuntimeError, ValueError)):
                r.decoded(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
