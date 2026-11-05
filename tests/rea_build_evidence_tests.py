#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# Licensed under the Apache License, Version 2.0.
"""Build receipt refusal regressions; synthetic artifacts never qualify Rust."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import rea_build_evidence as build
import rea_full_qualification as matrix
import rea_operation_evidence as evidence


def raw_json(value):
    # Preserve an original spelling different from the consumer's canonical JSON.
    return (json.dumps(value, indent=3, sort_keys=False) + "\n").encode()


class BuildFixture:
    """Independent minimal encoding of the observed matrix's original format."""

    def __init__(self, root):
        self.root = root
        self.artifacts = {}
        self.original_output = "/original/retained/build"
        self.source = {"schema": "hepta.rea.source-snapshot.v1", "selection": {"fixture": True},
                       "files": []}
        for name, raw in (("Cargo.lock", b"synthetic lock\n"), ("Cargo.toml", b"synthetic manifest\n"),
                          ("scripts/rea_full_qualification.py", b"synthetic producer\n"),
                          ("src/main.rs", b"synthetic source\n")):
            self.source["files"].append({"path": name, "bytes": len(raw), "mode": "0o644",
                                         "sha256": hashlib.sha256(raw).hexdigest()})
        self.source.update(file_count=4, total_bytes=sum(row["bytes"] for row in self.source["files"]),
                           tree_sha256=hashlib.sha256(json.dumps(self.source["files"], sort_keys=True,
                                             separators=(",", ":")).encode()).hexdigest())
        cargo, rustc = "/tools/cargo", "/tools/rustc"
        common = ["--locked", "--offline", "--all-targets"]
        controls = ["--test-threads", "1", "--retries", "0", "--no-fail-fast", "--profile", "default",
                    "--ignore-default-filter", "--no-tests", "fail"]
        commands = [
            ("cargo-version", [cargo, "--version", "--verbose"]),
            ("rustc-version", [rustc, "--version", "--verbose"]),
            ("nextest-version", [cargo, "nextest", "--version"]),
            ("fmt-check", [cargo, "fmt", "--all", "--", "--check"]),
            ("clippy-all-features", [cargo, "clippy"] + common + ["--all-features", "--jobs", "2", "--target-dir", "/original/target", "--", "-D", "warnings"]),
            ("clippy-no-default-features", [cargo, "clippy"] + common + ["--no-default-features", "--jobs", "2", "--target-dir", "/original/target", "--", "-D", "warnings"]),
            ("nextest-all-features", [cargo, "nextest", "run"] + common + ["--all-features", "--build-jobs", "2", "--target-dir", "/original/target"] + controls),
            ("nextest-no-default-features", [cargo, "nextest", "run"] + common + ["--no-default-features", "--build-jobs", "2", "--target-dir", "/original/target"] + controls),
            ("build-native-binary", [cargo, "build", "--locked", "--offline", "--all-features", "--bin", "hepta-runtime",
                                    "--message-format=json-render-diagnostics", "--jobs", "2", "--target-dir", "/original/target"]),
        ]
        self.native = {"path": "/selected/copied/native", "bytes": 12345, "sha256": "a" * 64}
        binary = {**self.native, "path": "/original/target/debug/hepta-runtime", "exists": True, "mode": "0o755"}
        producer = {**self.source["files"][2], "path": "/original/repo/scripts/rea_full_qualification.py"}
        self.report = {
            "schema": "hepta.rea.full-qualification.v1", "status": "passed", "qualified": True,
            "started_at": "2026-11-05T00:00:00+00:00", "finished_at": "2026-11-05T00:00:30+00:00",
            "inputs": {"repo": "/original/repo", "cargo_home": "/original/cargo", "target_dir": "/original/target",
                       "output_dir": self.original_output, "jobs": 2, "binary_relative_path": "debug/hepta-runtime",
                       "toolchain": "1.95.0", "child_launch_umask": "0022"},
            "executables": {"cargo": {"invoked": cargo, "resolved": "/tools/rustup"},
                            "rustc": {"invoked": rustc, "resolved": "/tools/rustup"}},
            "environment_overrides": {"CARGO_HOME": "/original/cargo", "CARGO_TARGET_DIR": "/original/target",
                "CARGO_BUILD_JOBS": "2", "CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never",
                "RUSTUP_TOOLCHAIN": "1.95.0", "RUSTC": rustc, "NEXTEST_TEST_THREADS": "1", "NEXTEST_RETRIES": "0"},
            "ambient_build_override_sha256": {}, "invalid_reasons": [], "interrupted_by_signal": None,
            "source_monitor_complete": True, "source_changed": False, "source_inventory_changed": False,
            "producer_source": {"repository_path": "scripts/rea_full_qualification.py", "before": producer,
                                "after": deepcopy(producer)},
            "stages": [], "planned_gates": [], "final_binary": binary,
            "binaries_after_nextest": [{**binary, "feature_set": features, "stage": "nextest-" + features,
                                        "stage_exit_code": 0} for features in ("all-features", "no-default-features")],
            "binary_after_build": {**binary, "feature_set": "all-features", "stage": "build-native-binary", "stage_exit_code": 0},
        }
        self.report["build_environment"] = {
            "schema": "hepta.rea.build-environment.v1",
            "selection": {"exact_names": sorted(build.BUILD_ENVIRONMENT_NAMES),
                          "prefixes": list(build.BUILD_ENVIRONMENT_PREFIXES)},
            "sha256": {name: hashlib.sha256(setting.encode()).hexdigest()
                       for name, setting in self.report["environment_overrides"].items()},
            "profiles": {"CARGO_PROFILE_DEV_DEBUG": None, "CARGO_PROFILE_TEST_DEBUG": None},
        }
        for key, name in (("source_before", "source-before.json"), ("source_after", "source-after.json")):
            self.artifacts[name] = raw_json(self.source)
            self.report[key] = {**self.ref(name), "tree_sha256": self.source["tree_sha256"]}
        self.artifacts["source-events.json"] = raw_json({"event_count": 0, "retained_events": [],
                                                        "events_truncated": False, "errors": []})
        self.report["source_events"] = self.ref("source-events.json")
        for index, (name, command) in enumerate(commands, 1):
            stdout = b""
            if index < 3:
                stdout = (f"{name.split('-')[0]} 1.95.0\nrelease: 1.95.0\n").encode()
            elif index == 3:
                stdout = b"cargo-nextest 0.9.99\n"
            elif index == 9:
                stdout = (json.dumps({"reason": "compiler-artifact", "package_id": "test fixture only",
                    "manifest_path": "/original/repo/Cargo.toml", "target": {"name": "hepta-runtime", "kind": ["bin"],
                    "crate_types": ["bin"], "src_path": "/original/repo/src/main.rs"},
                    "features": ["default", "remote-fs"], "profile": {"test": False, "debuginfo": 2}, "fresh": False,
                    "executable": binary["path"], "filenames": [binary["path"]]}) + "\n"
                    + '{"reason":"build-finished","success":true}\n').encode()
            stderr = b"Summary [ 0.010s] 9 tests run: 9 passed, 2 skipped\n" if index in (7, 8) else b""
            logs = {}
            for stream, raw in (("stdout", stdout), ("stderr", stderr)):
                filename = f"{index:02d}-{name}.{stream}.log"
                self.artifacts[filename] = raw
                item = self.ref(filename)
                logs[stream] = {**item, "sha256_at_stage_exit": item["sha256"], "final_bytes": item["bytes"]}
            self.report["stages"].append({"name": name, "command": command, "kind": "version" if index < 4 else "build" if index == 9 else "gate",
                "cwd": "/original/repo", "child_launch_umask": "0022", "exit_code": 0, "interrupted": False,
                "started_at": f"2026-11-05T00:00:{index * 2:02d}+00:00",
                "finished_at": f"2026-11-05T00:00:{index * 2 + 1:02d}+00:00", "duration_seconds": 1.0,
                "logs": logs, "status": "passed"})
            if 4 <= index <= 8:
                self.report["planned_gates"].append({"name": name, "command": command, "child_launch_umask": "0022"})

    def ref(self, name):
        raw = self.artifacts[name]
        return {"path": self.original_output + "/" + name, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    def validate(self):
        return build.validate_matrix(raw_json(self.report), self.artifacts.__getitem__, self.source, self.native)

    def write(self):
        self.root.mkdir()
        for name, raw in {**self.artifacts, "summary.json": raw_json(self.report)}.items():
            (self.root / name).write_bytes(raw)
        return self.root / "summary.json"

    def replace_log(self, index, stream, raw):
        stage = self.report["stages"][index - 1]
        name = f"{index:02d}-{stage['name']}.{stream}.log"
        self.artifacts[name] = raw
        item = self.ref(name)
        stage["logs"][stream] = {**item, "sha256_at_stage_exit": item["sha256"], "final_bytes": item["bytes"]}


class BuildEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = BuildFixture(self.root / "original")

    def tearDown(self):
        self.temporary.cleanup()

    def test_original_receipt_is_preserved_and_relocated_bundle_never_executes(self):
        fixture = self.fixture
        summary = fixture.write()
        output = self.root / "operation"
        output.mkdir()
        summary_raw = summary.read_bytes()
        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("must not execute")):
            bundle, result = build.capture_build(summary, hashlib.sha256(summary_raw).hexdigest(), output,
                                                 fixture.source, fixture.native)
            shutil.rmtree(summary.parent)
            relocated = self.root / "relocated"
            output.rename(relocated)
            self.assertEqual(build.validate_bundle(relocated, bundle, fixture.source, fixture.native), result)
        self.assertEqual((relocated / "build-evidence/summary.json").read_bytes(), summary_raw)
        self.assertEqual(len(bundle["artifacts"]), 21)
        self.assertEqual(result["selected_feature_set"], "all-features")
        self.assertNotIn("qualified", result)

    def test_unknown_custom_build_and_handwritten_pass_do_not_establish_a_matrix(self):
        for value in ({"schema": "hepta.rea.root-build.v1", "qualified": True},
                      {"schema": build.MATRIX_SCHEMA, "status": "PASS", "qualified": True}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build.validate_matrix(raw_json(value), lambda _: self.fail("must not read"),
                                      self.fixture.source, self.fixture.native)

    def test_summary_pin_is_checked_before_archiving(self):
        summary = self.fixture.write()
        with self.assertRaisesRegex(ValueError, "summary digest mismatch"):
            build.capture_build(summary, "f" * 64, self.root, self.fixture.source, self.fixture.native)
        self.assertFalse((self.root / "build-evidence").exists())

    def test_missing_duplicate_reordered_or_weakened_gates_fail_closed(self):
        original = deepcopy(self.fixture.report)
        for kind in ("missing", "duplicate", "reordered", "offline", "retry", "feature", "plan"):
            self.fixture.report = deepcopy(original)
            stages = self.fixture.report["stages"]
            if kind == "missing":
                stages.pop(4)
            elif kind == "duplicate":
                stages.append(deepcopy(stages[-1]))
            elif kind == "reordered":
                stages[4], stages[5] = stages[5], stages[4]
            elif kind == "offline":
                stages[4]["command"].remove("--offline")
            elif kind == "retry":
                command = stages[6]["command"]
                command[command.index("--retries") + 1] = "1"
            elif kind == "feature":
                command = stages[6]["command"]
                command[command.index("--all-features")] = "--no-default-features"
            else:
                self.fixture.report["planned_gates"].pop()
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.fixture.validate()

    def test_exit_failure_interruption_and_invalid_run_cannot_be_overridden_by_pass(self):
        original = deepcopy(self.fixture.report)
        for change in ({"exit_code": 1}, {"exit_code": False}, {"exit_code": "0"},
                       {"interrupted": True}, {"kind": "version"}, {"child_launch_umask": "0000"}):
            self.fixture.report = deepcopy(original)
            self.fixture.report["stages"][4].update(change, status="passed", qualified=True)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.fixture.validate()
        for change in ({"interrupted_by_signal": 15}, {"source_changed": True},
                       {"invalid_reasons": ["partial result"]}, {"source_monitor_complete": False}):
            self.fixture.report = {**deepcopy(original), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.fixture.validate()

    def test_original_log_tamper_and_change_after_stage_exit_are_rejected(self):
        name = "07-nextest-all-features.stderr.log"
        self.fixture.artifacts[name] += b"changed\n"
        with self.assertRaisesRegex(ValueError, "size/path/digest"):
            self.fixture.validate()
        log = self.fixture.report["stages"][6]["logs"]["stderr"]
        log.update(self.fixture.ref(name))
        log["final_bytes"] = log["bytes"]
        with self.assertRaisesRegex(ValueError, "changed after stage exit"):
            self.fixture.validate()

    def test_zero_tests_missing_or_failed_nextest_log_cannot_be_reported_as_pass(self):
        name = "07-nextest-all-features.stderr.log"
        for raw in (b"", b"Summary [ 0s] 0 tests run: 0 passed, 9 skipped\n",
                    b"Summary [ 0s] 9 tests run: 8 passed, 1 failed\n"):
            self.fixture.artifacts[name] = raw
            ref = self.fixture.ref(name)
            self.fixture.report["stages"][6]["logs"]["stderr"] = {
                **ref, "final_bytes": ref["bytes"], "sha256_at_stage_exit": ref["sha256"]}
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "nextest"):
                self.fixture.validate()

    def test_observed_nextest_slow_summaries_are_accepted(self):
        # These exact terminal lines came from the R4 real nextest runs. The
        # surrounding fixture remains synthetic and does not qualify Rust.
        self.fixture.replace_log(7, "stderr", b"Summary [1479.970s] 2216 tests run: 2216 passed (2 slow), 40 skipped\n")
        self.fixture.replace_log(8, "stderr", b"Summary [2084.619s] 2188 tests run: 2188 passed (2 slow), 28 skipped\n")
        result = self.fixture.validate()
        self.assertEqual(result["verified_stage_names"], list(build.STAGES))
        for slow in (0, 9):
            with self.subTest(slow=slow):
                self.fixture.replace_log(7, "stderr", f"Summary [0.010s] 9 tests run: 9 passed ({slow} slow)\n".encode())
                self.fixture.validate()

    def test_slow_annotation_does_not_allow_failed_empty_or_arbitrary_summaries(self):
        for raw in (b"Summary [0.010s] 0 tests run: 0 passed (0 slow), 9 skipped\n",
                    b"Summary [0.010s] 9 tests run: 8 passed (2 slow), 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (10 slow), 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (-1 slow), 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (2.0 slow), 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (2 slow, 1 flaky), 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (2 slow), 1 failed, 2 skipped\n",
                    b"Summary [0.010s] 9 tests run: 9 passed (2 slow), 2 skipped, interrupted\n"):
            for stage in (7, 8):
                fixture = BuildFixture(self.root / "invalid-summary")
                fixture.replace_log(stage, "stderr", raw)
                with self.subTest(raw=raw, stage=stage), self.assertRaisesRegex(ValueError, "nextest"):
                    fixture.validate()

    def test_slow_summary_still_requires_original_log_and_terminal_stage(self):
        raw = b"Summary [0.010s] 9 tests run: 9 passed (2 slow), 2 skipped\n"
        for stage in (7, 8):
            for change in ("duplicate", "exit", "interrupted", "digest", "exit-digest"):
                fixture = BuildFixture(self.root / "slow-integrity")
                fixture.replace_log(stage, "stderr", raw)
                row = fixture.report["stages"][stage - 1]
                if change == "duplicate":
                    fixture.replace_log(stage, "stdout", raw)
                elif change == "exit":
                    row["exit_code"] = 100
                elif change == "interrupted":
                    row["interrupted"] = True
                elif change == "digest":
                    row["logs"]["stderr"]["sha256"] = "f" * 64
                else:
                    row["logs"]["stderr"]["sha256_at_stage_exit"] = "f" * 64
                with self.subTest(stage=stage, change=change), self.assertRaises(ValueError):
                    fixture.validate()

    def test_original_references_cannot_read_an_arbitrary_absolute_or_parent_path(self):
        for path in ("/etc/passwd", "../source-before.json", "/original/retained/build/../secret"):
            report = deepcopy(self.fixture.report)
            report["source_before"]["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "fixed sibling"):
                build.validate_matrix(raw_json(report), lambda _: self.fail("must reject before any read"),
                                      self.fixture.source, self.fixture.native)

    def test_independent_source_tree_and_binary_identity_are_required(self):
        for native in ({**self.fixture.native, "sha256": "b" * 64},
                       {**self.fixture.native, "bytes": True}, {**self.fixture.native, "bytes": 12346}):
            with self.subTest(native=native), self.assertRaisesRegex(ValueError, "native binary"):
                build.validate_matrix(raw_json(self.fixture.report), self.fixture.artifacts.__getitem__,
                                      self.fixture.source, native)
        source = deepcopy(self.fixture.source)
        source["selection"]["different_checkout"] = True
        with self.assertRaisesRegex(ValueError, "build source differs"):
            build.validate_matrix(raw_json(self.fixture.report), self.fixture.artifacts.__getitem__,
                                  source, self.fixture.native)

    def test_monitor_events_or_lost_coverage_cannot_be_overridden_by_summary_flags(self):
        for change in ({"event_count": 1}, {"event_count": False}, {"events_truncated": True},
                       {"errors": ["coverage lost"]}, {"retained_events": [{"path": "src/main.rs"}]}):
            value = {"event_count": 0, "retained_events": [], "events_truncated": False, "errors": [], **change}
            self.fixture.artifacts["source-events.json"] = raw_json(value)
            self.fixture.report["source_events"] = self.fixture.ref("source-events.json")
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "monitor coverage"):
                self.fixture.validate()

    def test_executing_build_producer_is_bound_not_just_a_same_name_source_file(self):
        original = deepcopy(self.fixture.report["producer_source"])
        for change in (None, {"after": {**original["after"], "sha256": "b" * 64}},
                       {"before": {**original["before"], "path": "/other/producer.py"},
                        "after": {**original["before"], "path": "/other/producer.py"}}):
            self.fixture.report["producer_source"] = None if change is None else {**original, **change}
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "producer"):
                self.fixture.validate()

    def test_feature_binary_and_final_binary_cannot_be_spliced(self):
        for index in (0, 1):
            original = deepcopy(self.fixture.report["binaries_after_nextest"])
            self.fixture.report["binaries_after_nextest"][index]["stage_exit_code"] = False
            with self.assertRaisesRegex(ValueError, "feature-specific"):
                self.fixture.validate()
            self.fixture.report["binaries_after_nextest"] = original
        self.fixture.report["binaries_after_nextest"][-1]["sha256"] = "b" * 64
        # No-default nextest does not build the remote-fs-required MCP binary.
        # Its path observation must not be substituted for the explicit build.
        self.fixture.validate()
        self.fixture.report["binary_after_build"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "final executable differs"):
            self.fixture.validate()

    def test_links_special_files_and_path_traversal_are_refused(self):
        self.fixture.write()
        for kind in ("symlink", "hardlink", "fifo"):
            path = self.fixture.root / "hostile"
            if kind == "symlink":
                path.symlink_to(self.fixture.root / "summary.json")
            elif kind == "hardlink":
                os.link(self.fixture.root / "summary.json", path)
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                build.read_regular(self.fixture.root, "hostile")
            path.unlink()
        for name in ("../summary.json", "/etc/passwd", "x/../summary.json", "x\\y", "x//y"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                build.read_regular(self.fixture.root, name)

    def test_duplicate_nonfinite_missing_fields_and_aggregate_limit_fail_closed(self):
        for raw in (b'{"schema":1,"schema":2}', b'{"number":NaN}', b'{"number":1e400}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                build.parse_json(raw)
        self.fixture.report.pop("source_events")
        with self.assertRaisesRegex(ValueError, "malformed original"):
            self.fixture.validate()
        fixture = BuildFixture(self.root / "different")
        fixture.report["stages"][6]["logs"]["stderr"]["bytes"] = build.MAX_BUNDLE_BYTES
        with self.assertRaisesRegex(ValueError, "aggregate allowance"):
            fixture.validate()

    def test_bundle_pins_all_original_artifacts_and_rejects_unlisted_or_duplicate_rows(self):
        summary = self.fixture.write()
        bundle, _ = build.capture_build(summary, hashlib.sha256(summary.read_bytes()).hexdigest(), self.root,
                                         self.fixture.source, self.fixture.native)
        for change in (bundle["artifacts"][:-1], bundle["artifacts"] + [bundle["artifacts"][0]],
                       [bundle["artifacts"][1], bundle["artifacts"][0], *bundle["artifacts"][2:]]):
            with self.subTest(change=len(change)), self.assertRaises(ValueError):
                build.validate_bundle(self.root, {**bundle, "artifacts": change}, self.fixture.source, self.fixture.native)
        (self.root / "build-evidence/07-nextest-all-features.stderr.log").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            build.validate_bundle(self.root, bundle, self.fixture.source, self.fixture.native)

    def test_missing_or_bare_build_summary_never_closes_the_build_requirement(self):
        report = {"native_before": self.fixture.native, "build_binding": {"qualified": True}}
        self.assertIsNone(evidence.build_binding(self.root, report, self.fixture.source))
        raw = b'{"qualified":true,"status":"PASS"}\n'
        (self.root / "old-summary.json").write_bytes(raw)
        report["build_summary"] = build.reference(raw, "old-summary.json")
        self.assertIsNone(evidence.build_binding(self.root, report, self.fixture.source))
        assessment = evidence.derive_assessment({"case": {"passed": True}}, True, True, True,
                                                 evidence.q.UNIMPLEMENTED_REQUIREMENTS)
        self.assertIn(evidence.q.BUILD_REQUIREMENT, assessment["unimplemented_required_observations"])
        self.assertEqual(assessment["status"], "OPEN")

    def test_verified_build_still_cannot_qualify_the_operation(self):
        summary = self.fixture.write()
        bundle, _ = build.capture_build(summary, hashlib.sha256(summary.read_bytes()).hexdigest(), self.root,
                                         self.fixture.source, self.fixture.native)
        report = {"native_before": self.fixture.native, "build_summary": bundle["summary"],
                  "build_evidence": bundle, "build_binding": {"handwritten": "ignored"}}
        result = evidence.build_binding(self.root, report, self.fixture.source)
        self.assertEqual(result["native_binary_sha256"], self.fixture.native["sha256"])
        outstanding = [name for name in evidence.q.UNIMPLEMENTED_REQUIREMENTS if name != evidence.q.BUILD_REQUIREMENT]
        assessment = evidence.derive_assessment({"case": {"passed": True}}, True, True, True, outstanding)
        self.assertEqual(assessment["status"], "OPEN")
        self.assertEqual(len(assessment["unimplemented_required_observations"]), 4)
        self.assertNotIn("limits_and_cancellation", assessment["passed_gates"])

    def test_matrix_producer_observation_refuses_an_externally_executing_script(self):
        repo = self.root / "repo"
        selected = repo / "scripts/rea_full_qualification.py"
        selected.parent.mkdir(parents=True)
        selected.write_bytes(b"test producer bytes\n")
        with mock.patch.object(matrix, "__file__", str(selected)):
            observed = matrix.producer_source(repo)
        self.assertEqual(observed["sha256"], hashlib.sha256(selected.read_bytes()).hexdigest())
        with mock.patch.object(matrix, "__file__", str(self.root / "unexecuted.py")):
            with self.assertRaisesRegex(RuntimeError, "selected repository"):
                matrix.producer_source(repo)

    def test_cargo_debug_profiles_and_effective_overrides_are_preserved_and_checked(self):
        environment = {**self.fixture.report["environment_overrides"],
                       "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0",
                       "CARGO_PROFILE_RELEASE_LTO": "fat", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "clang",
                       "CARGO_BUILD_JOBS": "2", "CARGO_REGISTRIES_PRIVATE_TOKEN": "must-not-be-captured"}
        observed = matrix.build_environment(environment)
        self.assertNotIn("CARGO_REGISTRIES_PRIVATE_TOKEN", observed["sha256"])
        self.assertEqual(observed["profiles"], {"CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"})
        self.assertIn("CARGO_PROFILE_RELEASE_LTO", observed["sha256"])
        self.fixture.report["build_environment"] = observed
        with self.assertRaisesRegex(ValueError, "zero-debug dev profile"):
            self.fixture.validate()
        raw = self.fixture.artifacts["09-build-native-binary.stdout.log"].replace(b'"debuginfo": 2', b'"debuginfo": 0')
        self.fixture.replace_log(9, "stdout", raw)
        result = self.fixture.validate()
        self.assertEqual(result["build_environment"], observed)
        observed["profiles"]["CARGO_PROFILE_DEV_DEBUG"] = "2"
        with self.assertRaisesRegex(ValueError, "profile value differs"):
            self.fixture.validate()
        observed["profiles"]["CARGO_PROFILE_DEV_DEBUG"] = "0"
        observed["sha256"]["CARGO_BUILD_JOBS"] = hashlib.sha256(b"4").hexdigest()
        with self.assertRaisesRegex(ValueError, "actual stage profile"):
            self.fixture.validate()

    def test_unrecorded_build_environment_is_not_silently_authenticated(self):
        self.fixture.report.pop("build_environment")
        with self.assertRaisesRegex(ValueError, "environment observation is missing"):
            self.fixture.validate()

    def test_stale_binary_and_wrong_or_unfinished_cargo_artifact_cannot_attest_a_build(self):
        original = self.fixture.artifacts["09-build-native-binary.stdout.log"]
        messages = [json.loads(line) for line in original.splitlines()]
        for kind in ("missing", "duplicate", "failed", "unfinished", "path", "manifest", "target", "features", "test-profile"):
            changed = deepcopy(messages)
            if kind == "missing":
                changed.pop(0)
            elif kind == "duplicate":
                changed.insert(0, deepcopy(changed[0]))
            elif kind == "failed":
                changed[-1]["success"] = False
            elif kind == "unfinished":
                changed.pop()
            elif kind == "path":
                changed[0]["executable"] = "/unrelated/old-binary"
            elif kind == "manifest":
                changed[0]["manifest_path"] = "/unrelated/Cargo.toml"
            elif kind == "target":
                changed[0]["target"]["src_path"] = "/unrelated/main.rs"
            elif kind == "features":
                changed[0]["features"] = []
            else:
                changed[0]["profile"]["test"] = True
            self.fixture.replace_log(9, "stdout", b"".join(json.dumps(item).encode() + b"\n" for item in changed))
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "Cargo"):
                self.fixture.validate()


    @unittest.skipUnless(sys.platform == "linux", "the actual matrix source monitor requires Linux")
    def test_actual_runner_preserves_explicit_build_failure_and_emits_consumable_shape(self):
        # Real runner, monitor and original files; a clearly synthetic local
        # Cargo stand-in only exercises orchestration, never Rust qualification.
        fake_cargo = """#!/usr/bin/python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
if args == ["--version", "--verbose"]:
    print("synthetic version fixture\\nrelease: 1.95.0")
elif args == ["nextest", "--version"]:
    print("cargo-nextest synthetic-fixture")
elif args[:2] == ["nextest", "run"]:
    print("Summary [ 0.001s] 1 tests run: 1 passed, 1 skipped", file=sys.stderr)
elif args[0] == "build":
    if os.environ["FIXTURE_BUILD_EXIT"] != "0":
        print("synthetic explicit binary build failure", file=sys.stderr)
        raise SystemExit(int(os.environ["FIXTURE_BUILD_EXIT"]))
    executable = Path(args[args.index("--target-dir") + 1]) / "debug/hepta-runtime"
    executable.write_bytes(b"synthetic built executable; never executed\\n")
    executable.chmod(0o755)
    print(json.dumps({"reason": "compiler-artifact", "package_id": "synthetic fixture only",
        "manifest_path": str(Path.cwd() / "Cargo.toml"),
        "target": {"name": "hepta-runtime", "kind": ["bin"], "crate_types": ["bin"],
                   "src_path": str(Path.cwd() / "src/main.rs")},
        "features": ["default", "remote-fs"], "profile": {"test": False, "debuginfo": 0},
        "fresh": False, "executable": str(executable), "filenames": [str(executable)]}))
    print('{"reason":"build-finished","success":true}')
"""
        for code in (23, 0):
            with self.subTest(explicit_build_exit=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, target, output, cargo_home = (root / name for name in ("repo", "target", "output", "cargo"))
                (repo / "scripts").mkdir(parents=True)
                (repo / "src").mkdir()
                cargo_home.mkdir()
                (target / "debug").mkdir(parents=True)
                for name in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
                    (repo / name).write_text("synthetic orchestration fixture only\n")
                runner = repo / "scripts/rea_full_qualification.py"
                shutil.copyfile(matrix.__file__, runner)
                fake = root / "cargo-fixture"
                fake.write_text(fake_cargo)
                fake.chmod(0o755)
                binary = target / "debug/hepta-runtime"
                binary.write_bytes(b"preexisting synthetic target cache\n")
                binary.chmod(0o755)
                command = [sys.executable, "-B", str(runner), "--repo", str(repo),
                           "--cargo-home", str(cargo_home), "--target-dir", str(target),
                           "--output-dir", str(output), "--jobs", "2", "--cargo", str(fake), "--rustc", str(fake)]
                result = subprocess.run(command, capture_output=True, timeout=30,
                    env={"PATH": "/usr/bin:/bin", "FIXTURE_BUILD_EXIT": str(code),
                         "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0"})
                raw = (output / "summary.json").read_bytes()
                receipt = json.loads(raw)
                self.assertEqual(receipt["invalid_reasons"], [], result.stderr)
                self.assertEqual([stage["name"] for stage in receipt["stages"]], list(build.STAGES))
                self.assertEqual([stage["exit_code"] for stage in receipt["stages"][:-1]], [0] * 8)
                self.assertEqual(receipt["stages"][-1]["exit_code"], code)
                self.assertEqual(receipt["qualified"], code == 0)
                self.assertEqual(receipt["status"], "passed" if code == 0 else "failed")
                self.assertEqual(result.returncode, 0 if code == 0 else 1)
                if code == 0:
                    source = json.loads((output / "source-before.json").read_bytes())
                    measured = binary.read_bytes()
                    native = {"path": str(binary), "bytes": len(measured),
                              "sha256": hashlib.sha256(measured).hexdigest()}
                    bound = build.validate_matrix(raw, lambda name: build.read_regular(output, name), source, native)
                    self.assertEqual(bound["native_binary_sha256"], native["sha256"])


if __name__ == "__main__":
    unittest.main()
