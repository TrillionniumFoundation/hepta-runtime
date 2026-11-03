# Ext4 focused run: query-budget failure retained

This run is **not qualified**. Job `1a1a1c5a709-96a-713c` ended as `failed`, exit 1. Formatting and strict all-target Clippy passed in both feature configurations. All-feature nextest ran **264 tests: 263 passed, one failed, 1,619 skipped**. The no-default focused stage did not run after that failure.

The source inventory remained `eff016991ae56572d55f6ba487550c8ded550a68028a0c24184ec75aa52e64d7`. Before/after inventories are identical, and the Linux source monitor completed with zero events/errors. The production all-feature binary remained SHA-256 `290fa949b7744c85018f9f26b32fbdd1884cce1c31ff202a9f076bc3d6a89c63`.

## Failure and source scope

The continuous-publication test ran for 11.966 seconds. Its corrected progress assertions passed: the writer joined successfully, all 64 completion events arrived in order, and individual gaps stayed below the unchanged ten-second no-progress limit. Observation validation then failed on `archive metadata query total deadline exceeded; repeat only the metadata query`. The production query budget remains three seconds; the error is not suppressed.

All selected REA model/session/application/web/worker cases passed, including actual shipped-MCP tests. This does not make the whole run successful.

`watchdog-test.diff` and `source-comparison.json` bind the test-only correction. Before that change, the complete test file matched base f9756508462ebc72e814a12f5dbba1b067edabe4 byte-for-byte. All original content/cache/count/flush assertions remain. Related production audit/archive paths are unchanged.

## Diagnostic limits

This synchronous helper bypasses the asynchronous blocking-worker queue. Its 64 pending identities fit the 128-entry readonly pending path. The final original-validation/projection phase holds the shared store/state view, excluding advancing writers. Normal generation growth alone was not found to cause repeated retries here.

A distinct candidate remains: publication-side index-maintenance failure or a watch mismatch can invalidate the index without changing the original write's successful result. The fixture's artificial worker marker could then leave readiness waiting until the query budget expires. No failing-state snapshot was captured, so successful original writes do not exclude that branch.

The error identifies the total deadline, not its exact phase. Earlier lock waits, hot-directory reads, complete original validation, invalidated-index readiness and scheduling remain possible. These logs do not prove pure disk I/O caused the failure. Optional tracing was not enabled in this run.

## Separate environments

This run used the host's default ext4 temporary storage. Later tmpfs attempts use separately declared roots with identical source, budgets and assertions. Their functional results do not erase this ext4 failure or prove physical-disk latency/power-loss durability. Different storage and execution times are not a controlled causal performance experiment.

Actual operator-engine and retained-session disk receipts remain separate. Committed-tree validation also requires #84's GitHub exact-head and prospective-merge checks. Any subsequent single traced/backtrace diagnostic invocation has its own instrumentation and actual outcome; it cannot retroactively qualify this run.
