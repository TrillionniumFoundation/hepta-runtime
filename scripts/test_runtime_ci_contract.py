"""Fail-closed source contract for exact HEAD and PR-merge Rust qualification.

This test checks YAML source shape only; a passing result is not a Cargo or
GitHub runner execution receipt.
"""

from pathlib import Path
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml"


class RuntimeCiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_default_branch_pull_requests_trigger_ci(self):
        self.assertIn("  pull_request:\n    branches:\n      - hepta-runtime-base", self.source)
        self.assertIn("runs-on: ubuntu-24.04", self.source)
        self.assertNotIn("continue-on-error: true", self.source)

    def test_source_is_checkout_bound_before_rust(self):
        self.assertIn("ref: ${{ github.event.pull_request.head.sha || github.sha }}", self.source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_SOURCE_SHA"', self.source)
        self.assertLess(
            self.source.index("- name: Verify exact source commit"),
            self.source.index("- name: Install pinned Rust toolchain"),
        )
        self.assertLess(
            self.source.index("- name: Install pinned Rust toolchain"),
            self.source.index("- name: Format"),
        )

    def test_source_checks_include_native_toolchain_and_locked_cargo(self):
        for required in (
            "rustup toolchain install 1.95.0 --profile minimal",
            "rustup component add rustfmt clippy --toolchain 1.95.0",
            "cargo fmt --all -- --check",
            "cargo check --locked --all-targets",
            "cargo clippy --locked --all-targets -- -D warnings",
            "cargo test --locked --all-targets",
            "cargo build --locked --release",
        ):
            self.assertIn(required, self.source)

    def test_merge_is_independently_checked(self):
        self.assertIn("- name: Checkout exact pull request merge", self.source)
        self.assertIn("ref: ${{ github.sha }}", self.source)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_MERGE_SHA"', self.source)
        merge_section = self.source.split("- name: Verify and validate integration merge", 1)[1]
        self.assertIn("if: github.event_name == 'pull_request'", merge_section)
        self.assertLess(
            merge_section.index('test "$(git rev-parse HEAD)" = "$EXPECTED_MERGE_SHA"'),
            merge_section.index("cargo fmt --all -- --check"),
        )
        for required in (
            "cargo fmt --all -- --check",
            "cargo check --locked --all-targets",
            "cargo clippy --locked --all-targets -- -D warnings",
            "cargo test --locked --all-targets",
            "cargo build --locked --release",
        ):
            self.assertIn(required, merge_section)

    def test_contract_checks_run_on_source_and_merge(self):
        self.assertEqual(
            self.source.count("python3 -m unittest discover -s scripts -p 'test_runtime_ci_contract.py' -v"),
            2,
        )


if __name__ == "__main__":
    unittest.main()
