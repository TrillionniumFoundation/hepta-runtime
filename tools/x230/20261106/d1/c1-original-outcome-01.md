# D1 C1 original outcome and separate first offline audit

## Decision

The original C1 campaign is **failed**. The accepted runtime remains R24
(`baab4def80be7af015b2e7a594cb302f66c4130e`).
D1 is non-default diagnostic instrumentation, not an adopted performance version.
No workload was replayed and no threshold or original report was changed.

The original workload itself completed all **936 calls successfully**:
768 measured, 96 warmup, 24 preflight and 48 restart. All eight original
controllers closed by stdin EOF with exit 0, no observed surviving descendants,
no unmatched responses, no reader error and no sampler error. After the workload,
the adapter rejected an incorrect assumption about a public request identifier.
The failed adapter stopped the parent before its original native-audit stage.

## Original terminal and failure

- Holder job: `1a1b0849a11-fc05-7119`; failed, exit 1; all 288 stdout bytes
  and zero stderr bytes complete, durable and confirmed.
- Parent and adapter remain `passed=false` / `analysis_complete=false`.
  The adapter error is `unique original native request identity missing`.
- The original native workload wrapper returned 0 and its report has
  `passed=true`. These facts do not retroactively pass its enclosing stage.
- Original `c1-campaign-01/summary.json` and
  `c1-observation-01/independent-summary.json` remain absent.
- The parent waited and reaped its stage; process and process-group absence
  were observed. Its generic independent-controller-cleanup field remains
  `unknown`; the eight normal closes are separate original native evidence.
- Quiet interval: 90.049477269 seconds. The original compiler monitor and
  monitor audit passed with 222 samples. Source, fixture, topology, scripts
  and feature ELF remained bound to their original identities.

The frozen adapter required
`result._meta["io.hepta.runtime/request-v8"].request_id` in every
`process_status` and `process_read` response. The unchanged runtime exposes
this public identity only for its existing seven-tool whitelist, which excludes
these two tools. The D1 trace has an internal native request ID, but that does
not make it an on-wire field. The exact first original response frame is
preserved and has no `_meta` field. This is an adapter integration assumption
and review omission, not a broken runtime interface.

The failure precedes opening the first trace file and invoking the original
trace parser. `trace_interpretation_started=true` records only the attempted
postprocessing; the original completed trace count is zero.

## Complete original archive

The original collector job `1a1b098f953-fc05-719d` succeeded with exit 0.
Its archive outcome is `not_passed` and counts are null, preserving the original
campaign outcome.

- Archive: `c1-evidence-01/c1-evidence-01.tar.gz`
- Size: 2,220,914 bytes
- SHA-256: `522f79c7601612adfc093df876fb2962b201551e08016e9293d01424bbea36cb`
- Returned archive verified by the identical frozen collector: 1,641 files,
  25,702,724 selected bytes, eight raw traces, no receipt-binding errors,
  zero files extracted by that verification.

The archive includes raw transports/indexes, all eight traces, original native
and failed adapter/parent reports, monitor evidence and the 21 holder logs.
The holder log copy receipt explicitly records byte-identical SHA-deduplicated
copies; it does not claim independent refetches of identical log bodies.
Preparation, actual-only sealing, local verification and their original
receipts are published alongside the archive.

## Separate original auditor: first invocation

After preserving the failed campaign, the frozen original native auditor was
invoked for the **first time**, in a new output namespace. The original parent
never invoked it. This is offline audit of existing data, not a benchmark rerun.

- Auditor job: `1a1b09af362-fc05-71a6`; succeeded, exit 0.
- Complete stdout: 82 bytes; stderr: zero bytes.
- Result: verified true; 768 measured, 96 warmup, 936 total, zero failed calls.
- New output: `c1-offline-audit-originals-01/native-independent-summary.json`
- Size: 51,552 bytes
- SHA-256: `d7833ca3b5434de7ccc807ffa13be2ed66fab599ee31df45cd554f83ab83a6db`

Its raw start, terminal, full read and output bytes are included. The separate
audit result does not alter the original parent, holder or absent output paths.

## Calibration scope

The original sequence is OFF / ON / ON / OFF, C1 on six hosts, using the same
qualified feature ELF. OFF and ON each contain 384 measured requests.

| Metric | OFF | ON |
| --- | ---: | ---: |
| RPC/s, calls divided by total measured seconds | 8.5861376659 | 8.8707820941 |
| Controller CPU ms/call | 29.2447916667 | 22.9427083333 |
| p50 end-to-end ms | 112.226388 | 109.598532 |
| p95 end-to-end ms | 178.619423 | 175.360153 |
| p99 end-to-end ms | 193.837920 | 194.312417 |
| Within-arm round RPC/s spread | 23.462632% | 26.553594% |

These are instrumentation calibration observations, **not optimization gains**
and not a claim of statistical significance. The large round-to-round variation
requires keeping both ON rounds visible in the phase-cost interpretation.

A separately named offline interpreter is being reviewed against the preserved
original data. It must bind whole trace spans to unique original RPC intervals
within the same controller PID, birth identity and boot, with host/operation and
raw frame/index provenance. It must reject unmatched or ambiguous bindings,
leave the absent public native ID null, use only measured request slots for
phase-cost denominators and avoid double-counting nested synchronous spans.
No phase CPU conclusion or next candidate is claimed by this checkpoint.

## Source identity

Published source tree remains
`20648a0cd06f44b2a3eb91dca9f41f623c3ac5bd`, qualified by the original
feature suite (1,651 passed, 34 ignored), exact CI-equivalent path
(1,651 passed, 34 ignored) and ordinary feature-off suite
(1,645 passed, 34 ignored). No source is changed by this evidence commit.
