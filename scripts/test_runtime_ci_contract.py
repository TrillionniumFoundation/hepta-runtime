"""Source contract for the current exact-HEAD and PR-merge Rust CI lanes.

These offline assertions check workflow configuration, not a GitHub runner or
native-runtime execution result. Runtime behavior has its own Rust regressions.
"""

from pathlib import Path
import re
import unittest

from local_qualification import CHECKS, NEXTEST_VERSION, RUST_VERSION


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"
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


if __name__ == "__main__":
    unittest.main()
