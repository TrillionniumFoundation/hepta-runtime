#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual HIA terminal cleaning and complete corpus for fresh original replay."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "shell_oracle"))
from native_runner import run_native


class TerminalNativeTests(unittest.TestCase):
    def test_actual_native_terminal_and_transport(self):
        result = run_native("terminal")
        self.assertEqual(result["status"], "PASS")


if __name__ == "__main__":
    unittest.main()
