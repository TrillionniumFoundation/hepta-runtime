"""Strict completion accounting for the four current entropy qualification suites."""


def completion_counts(result, expected):
    counts = {
        "tests_run": result.testsRun,
        "expected_tests": expected,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    complete = type(expected) is int and expected > 0 and result.testsRun == expected
    clean = all(counts[name] == 0 for name in (
        "failures", "errors", "skipped", "expected_failures", "unexpected_successes"))
    return {"status": "PASS" if complete and clean and result.wasSuccessful() else "FAIL", **counts}
