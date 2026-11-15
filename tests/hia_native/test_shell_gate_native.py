#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA shell preflight and helpers; no command execution is claimed."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "shell_oracle"))
from native_runner import run_native


class ShellGateNativeTests(unittest.TestCase):
    def test_actual_native_gate_and_transport(self):
        result = run_native("gate")
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
