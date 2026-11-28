"""Source contract for the current exact-HEAD and PR-merge Rust CI lanes.

These offline assertions check workflow configuration, not a GitHub runner or
native-runtime execution result. Runtime behavior has its own Rust regressions.
"""

from pathlib import Path
import os
import re
import subprocess
import tempfile
import textwrap
import unittest

from local_qualification import CHECKS, NEXTEST_VERSION, RUST_VERSION


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
COMMON_WORKFLOW = WORKFLOW.with_name("hia-common-native-integration.yml")
GUARD_SUITES = (
    "test_runtime_ci_contract.py",
    "test_source_byte_boundary.py",
    "test_qualification_path_fence.py",
    "test_local_qualification.py",
)


class RuntimeCiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.lanes = {}
        for job in ("runtime-head-ci", "runtime-merge-ci"):
            match = re.search(
                rf"^  {job}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
                cls.source,
                re.MULTILINE | re.DOTALL,
            )
            if match is None:
                raise AssertionError(f"required CI lane missing: {job}")
            cls.lanes[job] = match.group(1)

    def test_main_and_hia_branches_trigger_push_and_pull_request_ci(self):
        for event in ("push", "pull_request"):
            match = re.search(
                rf"^  {event}:\n    branches:\n((?:      .*\n)+)",
                self.source,
                re.MULTILINE,
            )
            self.assertIsNotNone(match, event)
            self.assertIn("      - main\n", match.group(1), event)
            self.assertIn("      - 'hia/**'\n", match.group(1), event)
        self.assertNotIn("continue-on-error: true", self.source)

    def test_head_is_checkout_bound_before_rust(self):
        source = self.lanes["runtime-head-ci"]
        self.assertIn("persist-credentials: false", source)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", source)
        identity = 'test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD_SHA"'
        self.assertIn(identity, source)
        self.assertLess(source.index(identity), source.index("- name: Install pinned Rust toolchain"))

    def test_merge_is_independently_checkout_bound(self):
        source = self.lanes["runtime-merge-ci"]
        self.assertIn("if: github.event_name == 'pull_request'", source)
        self.assertIn("persist-credentials: false", source)
        self.assertIn("ref: ${{ github.sha }}", source)
        identity = 'test "$(git rev-parse HEAD)" = "$EXPECTED_MERGE_SHA"'
        self.assertIn(identity, source)
        self.assertIn('test "$EXPECTED_MERGE_SHA" != "$EXPECTED_HEAD_SHA"', source)
        self.assertLess(source.index(identity), source.index("- name: Install pinned Rust toolchain"))

    def test_each_lane_keeps_locked_feature_matrix_and_isolated_tests(self):
        self.assertEqual(RUST_VERSION, "1.95.0")
        self.assertEqual(NEXTEST_VERSION, "0.9.137")
        for name, source in self.lanes.items():
            with self.subTest(lane=name):
                commands = " ".join(source.replace("\\\n", " ").split())
                for required in (
                    "runs-on: ubuntu-24.04",
                    f"rustup toolchain install {RUST_VERSION} --profile minimal",
                    f"rustup component add rustfmt clippy --toolchain {RUST_VERSION}",
                    f"cargo install --locked --version '={NEXTEST_VERSION}' cargo-nextest",
                    "cargo fmt --all -- --check",
                    "cargo build --locked --all-features --release --bins --examples",
                ):
                    self.assertIn(required, commands)
                for feature in ("--all-features", "--no-default-features"):
                    self.assertIn(f"cargo check --locked --all-targets {feature}", commands)
                    self.assertIn(f"cargo clippy --locked --all-targets {feature} -- -D warnings", commands)
                    self.assertIn(
                        f"cargo nextest run --locked --all-targets {feature} "
                        "--test-threads 1 --retries 0 --no-fail-fast",
                        commands,
                    )

    def test_guard_regressions_run_in_each_lane(self):
        for lane, source in self.lanes.items():
            for name in GUARD_SUITES:
                with self.subTest(lane=lane, suite=name):
                    command = f"/usr/bin/python3 -B -m unittest discover -s scripts -p '{name}' -v"
                    self.assertEqual(source.count(command), 1)

    def test_local_runner_keeps_both_feature_modes_and_zero_retries(self):
        commands = [command for _name, command in CHECKS]
        for feature in ("--all-features", "--no-default-features"):
            self.assertIn(("cargo", "check", "--locked", "--all-targets", feature), commands)
            self.assertIn(("cargo", "clippy", "--locked", "--all-targets", feature, "--", "-D", "warnings"), commands)
            self.assertIn(
                ("cargo", "nextest", "run", "--locked", "--all-targets", feature,
                 "--test-threads", "1", "--retries", "0", "--no-fail-fast"),
                commands,
            )
        self.assertFalse(any(command[:2] == ("cargo", "test") for command in commands))


class CommonNativeCandidateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = COMMON_WORKFLOW.read_text(encoding="utf-8")
        name = "      - name: Require both finalized native source and distribution commit pins\n"
        if cls.source.count(name) != 1:
            raise AssertionError("one original candidate pin admission step is required")
        cls.pin_step = cls.source.split(name, 1)[1].split("\n      - name: ", 1)[0]
        cls.pin_script = textwrap.dedent(cls.pin_step.split("        run: |\n", 1)[1])

    def run_pin_gate(self, event, requested_source, requested_distribution,
                     frozen_source="1" * 40, frozen_distribution="2" * 40):
        with tempfile.TemporaryDirectory(prefix="hia-candidate-pins-") as temporary:
            root = Path(temporary)
            output = root / "github-env"
            env = dict(os.environ, HIA_TRIGGER_EVENT=event,
                       REQUESTED_SOURCE_SHA=requested_source,
                       REQUESTED_DISTRIBUTION_SHA=requested_distribution,
                       HEPTA_SOURCE_SHA=frozen_source,
                       HEPTA_BOOTSTRAP_DISTRIBUTION_SHA=frozen_distribution,
                       GITHUB_ENV=str(output))
            result = subprocess.run(("/bin/bash", "--noprofile", "--norc", "-c", self.pin_script),
                                    cwd=root, env=env, capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertFalse((root / "unexpected-execution").exists())
            written = output.read_text(encoding="utf-8") if output.exists() else ""
            return result, written

    def test_unified_and_source_integration_pushes_reach_common_qualification(self):
        trigger = self.source.split("  push:\n", 1)[1].split("  pull_request:\n", 1)[0]
        for branch in ("codex/hia-native-helper-runtime-*", "codex/hia-three-loop-*",
                       "codex/hia-runtime-unified-*", "codex/hia-native-final-integration-*"):
            self.assertIn(f"      - '{branch}'\n", trigger)

    def test_manual_inputs_are_required_data_and_admitted_before_checkout(self):
        inputs = self.source.split("  workflow_dispatch:\n", 1)[1].split("\npermissions:", 1)[0]
        for name in ("source_sha", "distribution_sha"):
            self.assertIn("required: true", inputs.split(f"      {name}:\n", 1)[1])
            self.assertIn(f"REQUESTED_{'SOURCE' if name == 'source_sha' else 'DISTRIBUTION'}_SHA: "
                          "${{ inputs." + name + " }}", self.pin_step)
        self.assertEqual(inputs.count("required: true"), 2)
        self.assertEqual(inputs.count("type: string"), 2)
        self.assertNotIn("default:", inputs)
        self.assertNotIn("${{", self.pin_script)
        self.assertLess(self.source.index("        id: pins\n"),
                        self.source.index("      - name: Checkout the frozen Hepta source F\n"))

    def test_manual_dispatch_publishes_only_its_two_exact_pins(self):
        result, written = self.run_pin_gate("workflow_dispatch", "a" * 40, "b" * 40)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(written, f"HEPTA_SOURCE_SHA={'a' * 40}\n"
                         f"HEPTA_BOOTSTRAP_DISTRIBUTION_SHA={'b' * 40}\n")

    def test_missing_or_noncanonical_manual_pins_never_fall_back(self):
        invalid = ("", "a" * 39, "a" * 41, "A" * 40, "main",
                   "a" * 40 + "\nUNREVIEWED=1", "$(touch unexpected-execution)",
                   "`touch unexpected-execution`")
        for value in invalid:
            for source, distribution in ((value, "b" * 40), ("a" * 40, value)):
                with self.subTest(source=source, distribution=distribution):
                    result, written = self.run_pin_gate("workflow_dispatch", source, distribution)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("HOLD:", result.stderr)
                    self.assertEqual(written, "")
        result, written = self.run_pin_gate("workflow_dispatch", "a" * 40, "a" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(written, "")

    def test_automatic_events_preserve_the_frozen_tuple(self):
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                result, written = self.run_pin_gate(event, "$(touch unexpected-execution)", "b" * 40)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(written, f"HEPTA_SOURCE_SHA={'1' * 40}\n"
                                 f"HEPTA_BOOTSTRAP_DISTRIBUTION_SHA={'2' * 40}\n")
                result, written = self.run_pin_gate(event, "a" * 40, "b" * 40,
                                                   frozen_source="1" * 40,
                                                   frozen_distribution="1" * 40)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(written, "")

    def test_selected_tuple_keeps_distribution_execution_and_budget_gates(self):
        for required in (
            "ref: ${{ env.HEPTA_SOURCE_SHA }}",
            "ref: ${{ env.HEPTA_BOOTSTRAP_DISTRIBUTION_SHA }}",
            "cmp src/mcp/hia_tool_catalog.json hia-source/docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json",
            '--expected-hepta-source "$HEPTA_SOURCE_SHA"',
            '--expected-distribution "$HEPTA_BOOTSTRAP_DISTRIBUTION_SHA"',
            "Actual sixty-phase native cold replay with unchanged 180 plus 3 budget",
            '"cold_wall_seconds": 180, "cold_cleanup_seconds": 3',
            '"ordinary_release_wall_seconds": 1800',
            "--timeout-seconds 1800",
            "ActualExternalObserverControls -v",
        ):
            self.assertIn(required, self.source)
        self.assertNotIn("continue-on-error: true", self.source)


if __name__ == "__main__":
    unittest.main()
