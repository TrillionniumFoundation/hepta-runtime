# Initial full integration gate: failed, then deliberately stopped

This directory preserves the original unsuccessful qualification attempt.
It is not a passing qualification or a complete test-suite result.

- Runtime job: `1a1a1560b54-96a-6e58`.
- Authoritative terminal state: `cancelled`, exit `-15`, output complete.
- The runner retained `status: failed` and `qualified: false` in `summary.json`.
- Formatting and both strict Clippy feature configurations passed.
- The all-feature nextest stage encountered the real AAPT2 fixture failure
  `actual_aapt_and_aapt2_manifest_declarations_match_the_owned_sources`:
  `real aapt manifest: truncated ZIP u16`.
- The original job was stopped after diagnosis so the source could be repaired
  and a new complete qualification run could use a distinct evidence directory.
  Its nextest exit code 100 also reflects this interruption; the no-default
  nextest stage did not run.
- Source before and after were identical, tree SHA-256
  `609c3a532d3994575a9f5b551be9fecaec4fda0a3751188f584bf34dead8421b`.
  No source mutation or source-monitor coverage loss was used to explain away
  the failing test.

The unchanged, independently produced AAPT2 fixture contains a stored
`resources.arsc` entry with a one-byte, zero-filled local extra field that
aligns its payload to four bytes. The old shared ZIP parser attempted to read
this as a four-byte TLV header. The correction admits only the proved bounded
local-alignment case; the real fixture and original test remain in the suite.
See the application scope document and the separate subsequent qualification
for the final rule, regression tests, and outcome.

All original summaries, logs, source inventories, and event observations in
this directory remain unchanged.
