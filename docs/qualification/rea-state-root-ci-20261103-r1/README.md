# First state-root focused gate: one test-fixture failure

This source-bound run used explicit child launch umask `0022` and is retained
as a failed overall qualification: 45 tests ran, 44 passed, and one failed.
The pipeline job `1a1a18da495-96a-6fb4` terminated with authoritative state
`failed`, exit 1. The planned full r3 run did not start from this attempt.

The production bootstrap regression under `000`, `022`, and `077`, the two
original failing shipped-MCP cases, and the application, model-session HTTP,
and saved-web MCP checks passed. The only failure was the new UID-validation
unit fixture: it assumed that the installed tempfile crate's default directory
would be `0700`; under `0022` the observed mode was `0755`.

The correction creates an explicitly `0700` child directory for that metadata
identity test. It changes only test setup, not the production initializer or
its rejection rules. The original executable remains SHA-256
`290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`.

The subsequent expanded focused gate is recorded separately in
[rea-state-root-ci-20261103-r2](../rea-state-root-ci-20261103-r2/summary.json).
All original results in this directory remain unchanged.
