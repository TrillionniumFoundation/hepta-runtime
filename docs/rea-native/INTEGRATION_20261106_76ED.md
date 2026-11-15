# REA integration reconciliation — 2026-11-06

This source combines the bounded JSON/model/recorded-core work at
`1096174123561e0263a20e5f9080da5492b42410` with the independently published
`c25e4cef0610816bfd1263b69d3dd63e4114aa49` changes. Both descend from
`c759624715f24d5c7f09d66df34a77043a6950b2`. The merge preserves both histories
and their raw observations. It does not promote either parent's observations
to the new binary.

## JSON merge decision

The published tracker adds complete Unicode-scalar handling and bounded
20/10/20 UTF-16 diagnostic context. The local work adds a typed proof for a
complete root string that Rust cannot represent, and preserves the owned
reader's physical-EOF, UTF-8, token, cancellation, I/O and complete-read digest
checks. The merged tracker retains both behaviors. A root type proof never
fabricates a decoded value; nested unpaired surrogates remain unsupported.
The separate local context helper is removed only because the merged tracker
fully replaces its sole use.

An independent fixed Node 22.23.4 observation covered 6,575 distinct inputs
and 118,487 byte-split checks per tracker variant. The merged tracker produced
6,044 exact diagnostic/no-diagnostic results, 531 explicit unrepresentable
UTF-16 diagnostic windows, and no unexpected message or root-type differences.
The old local tracker had 729 differences on this expanded Unicode corpus.
These are standalone observer measurements, not complete public MCP,
Evidence-schema, large-file, cancellation or Provider qualification.

Both committed fixture families remain unchanged. The remote 77-case and
14-public-case test retains its historical raw gap flag for
`node-syntax-34`; the merged test separately asserts the improved typed
root rejection (86 exact, four remaining gaps, one typed root rejection).
The independent 150-syntax/15-public fixture and owned-reader regressions
remain in the test suite.

## JavaScript and browser changes

The seven-file JavaScript slice is retained. Transparent parentheses and
TypeScript syntax around a `BrowserWindow` options expression no longer
hide its preload declaration. Lexical callee resolution, shadowing, spread
exclusion and unknown dynamic values keep their existing boundaries.
Graph identity profile is `hepta.javascript-selected-source-graph.v4`;
v1, v2 and v3 continuation identities are rejected even for unchanged bytes.
The seven authored preload cases compare only two declared preload fields;
they do not establish a complete application or runtime graph.

The published C/Python browser environment observer is retained as a separate
instrumented observation. Its before-main constructor observes four variables
for the same Chrome PID under `LD_PRELOAD`. An unchanged-environment exec
trace has a different scope. Historical late-`/proc/PID/environ` failures
remain failures of that observation contract; no old RED record is rewritten.
The helper alone does not establish complete negative-control process-group
cleanup, browser isolation, arbitrary-page DOM or runtime equivalence.

## Model persistence compatibility

The model parser/index profile remains
`hepta.rea.model-directory-index.v2`. Eighteen pinned invariant GGML layouts
have bounded extent validation; historical ambiguous layouts retain explicit
limits. No quantized payload decoding or model inference is claimed.

Retained v1 indexes, including safetensors indexes, are not relabeled or
silently upgraded. Reopening an available original source creates a v2 session.
The original source is required for that reopening. Retained v1 directories
continue to consume quota and keep global session listing fail-closed.
Already opened v2 sessions still support direct query/read alongside them.

## Qualification at this source freeze

The pinned npm baseline remains `rea-agents@6.8.0`, 229 tools in 18 families.
The complete replacement ledger remains **0/229 qualified**:
187 absent, 22 partial-operation and 20 related-facility mappings.
The separate Git-source inventory must not replace the npm denominator.

Parent `10961741` has separately retained diagnostic observations for
116 public JSON inputs, 160 model cases and 812 recorded-core payload cases.
Their exact comparison layers and declared differences remain in their
original reports. Their runtime SHA is
`0e0020278558649660adf508e976de58f9e3586b7b12d41be5443ea0d98c3188`.
These observations are not qualifications of a different binary.

The reconciled source requires its own compilation/test and exact binary
bindings. Fresh native comparisons and external-engine/browser observations
must record their actual runtime, source, reference and lifecycle identities.
Original Ghidra/JADX availability, real provider execution, full platform
isolation, cross-host recovery and release/deployment qualification remain
separate gates. This document records merge decisions rather than future
test outcomes.
