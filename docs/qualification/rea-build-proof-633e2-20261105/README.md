# Build receipt validator regression evidence

The final check is `checks-v2.json`, with unchanged original stdout and stderr
in `unittest-v2.*.log`. It executed all 113 REA Python regression tests on the
selected worktree and returned exit code 0. `checks.json` and `unittest.*.log`
retain the earlier 112-test run before the final runner integration regression.

The added integration regression runs the real Python matrix producer and Linux
source monitor using a deliberately synthetic Cargo executable. The explicit
binary build failure (exit 23) makes the producer return exit 1,
`status=failed`, and `qualified=false`, even when all five original gates
return 0. Its synthetic successful output is independently accepted for format
and binding checks. No Rust compiler or native MCP is executed by that test.

Both original external receipts listed in each check were read without
modification. The selected-checks custom receipt is refused for unsupported
schema; the historical full matrix is refused for its missing explicit binary
build stage. Neither is upgraded or relabeled.

These files establish validator regression results and real unsupported-receipt
refusal. They do not qualify a Rust build, REA operation, or the whole REA
integration. A new complete matrix on the final integrated source and the
corresponding original/native operation run remain necessary.
