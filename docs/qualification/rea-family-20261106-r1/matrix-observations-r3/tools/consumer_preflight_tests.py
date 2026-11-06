#!/usr/bin/env python3
"""Pure-log negative checks; does not read a build output or launch any process."""
import unittest
from consume_matrix import parse_nextest


def fixture():
    return (b"Starting 2 tests across 1 binary (3 tests skipped)\n"
            b"PASS [ 0.1s] (1/2) package alpha\n"
            b"PASS [ 0.1s] (2/2) package beta\n"
            b"Summary [ 0.2s] 2 tests run: 2 passed, 3 skipped\n")


class ParserTests(unittest.TestCase):
    def test_complete_rows_and_separate_skip_count(self):
        value = parse_nextest(b"", fixture())
        self.assertEqual((value["tests_run"], value["passed"], value["reported_skipped"]), (2, 2, 3))
        self.assertEqual(len(value["pass_rows"]), 2)

    def test_slow_summary_and_informational_line(self):
        raw = fixture().replace(b"2 passed,", b"2 passed (1 slow),")
        value = parse_nextest(b"", b"SLOW [ 0.1s] package beta\n" + raw)
        self.assertEqual(value["reported_slow"], 1)

    def test_missing_or_duplicate_row_refused(self):
        for raw in (fixture().replace(b"PASS [ 0.1s] (2/2) package beta\n", b""),
                    fixture().replace(b"package beta", b"package alpha")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_nextest(b"", raw)

    def test_swapped_counters_refused(self):
        with self.assertRaises(ValueError):
            parse_nextest(b"", fixture().replace(b"(1/2)", b"(9/2)"))

    def test_start_skip_or_denominator_mismatch_refused(self):
        for raw in (fixture().replace(b"(3 tests skipped)", b"(4 tests skipped)"),
                    fixture().replace(b"(2/2)", b"(2/3)"),
                    fixture().replace(b"Starting 2", b"Starting 1")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_nextest(b"", raw)

    def test_duplicate_summary_and_failed_terminal_refused(self):
        for raw in (fixture() + b"Summary [ 0.2s] 2 tests run: 2 passed, 3 skipped\n",
                    fixture() + b"FAIL [ 0.1s] extra\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_nextest(b"", raw)

    def test_zero_or_incomplete_run_refused(self):
        for raw in (b"Starting 0 tests across 1 binary\nSummary [ 0s] 0 tests run: 0 passed\n",
                    fixture().split(b"Summary")[0]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_nextest(b"", raw)


if __name__ == "__main__":
    unittest.main()
