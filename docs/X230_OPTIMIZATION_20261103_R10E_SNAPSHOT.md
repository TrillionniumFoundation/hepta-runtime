# X230 R10e qualified snapshot — 2026-11-03

This document preserves the previously completed R10e work as an independently
qualified baseline before R11, using its existing source and qualification evidence.

## Provenance

- R9 parent baseline: `94d7fecdb02f5a7ef3d5ff072665360eb0115e0f`.
- R10e source: `/home/qian/hepta-runtime-optimization-20261103-r10/source-r10e`.
- Qualification: `/home/qian/hepta-runtime-optimization-20261103-r10/qualification-r10e-01`.
- Qualification completed at **2026-11-03T10:21:00.225223+00:00**.

## Source changes relative to R9

There are **6 modified files, 7 added files, and no deleted files**.
The production changes occupy four modified files and one added module;
the remaining files supply regression coverage and deterministic test hooks.

| Status | Path | Role |
| --- | --- | --- |
| Modified | `src/mcp/runtime/binary.rs` | Closed file observation source |
| Modified | `src/mcp/runtime/jobs.rs` | Registry, publication, and inventory behavior |
| Modified | `src/mcp/runtime/jobs_registry_coalescing_tests.rs` | Cohort hooks and regression adaptations |
| Modified | `src/mcp/runtime/operation_async.rs` | Async process-list dispatch |
| Modified | `src/mcp/runtime/ssh_file_observation_tests.rs` | Fixed helper and wire-protocol checks |
| Modified | `src/mcp/server.rs` | Async list/page MCP entry points |
| Added | `src/mcp/runtime/jobs_cohort_admission_tests.rs` | Cohort interleaving regressions |
| Added | `src/mcp/runtime/binary_observation_source_tests.rs` | Real Python helper equivalence |
| Added | `src/mcp/runtime/jobs_pending_admission_tests.rs` | Pending publication ownership |
| Added | `src/mcp/runtime/jobs_record_projection.rs` | Validated borrowed strings |
| Added | `src/mcp/runtime/jobs_inventory_async_tests.rs` | Physical inventory capacity |
| Added | `src/mcp/runtime/jobs_inventory_digest_tests.rs` | Snapshot and cursor compatibility |
| Added | `src/mcp/runtime/jobs_registry_decode_tests.rs` | Full-schema decoder equivalence |

## Preserved R10e functionality

### 1. Borrow command fields during cold reuse scans

Content-watched registry scans decode the complete receipt schema while borrowing
plain command strings from descriptor-validated bytes. Only the requested or
cohort-selected originals become owned records, without rereading or reparsing.
Unrelated receipts still undergo type, required-field, duplicate-field, default,
and identity validation. The concrete owned decoder remains available.

### 2. Make cold-cohort ownership transitions atomic

Admission observes the leader gate and freezes membership under the same state
lock. Publication clears membership and releases the gate under that lock before
notifying waiters. Followers bind to the original epoch and an exact `Arc`
completion through a condition variable, preventing lost completion and waiting
for a later cohort. Changed epochs and panic/poison refusal remain explicit.

### 3. Transfer the original pending receipt to its publisher

Pending publication moves the original `JobRecord` into its physical writer and
returns it after the intent and persistence barriers, avoiding a full clone.
The intent is frozen before waiting for capacity. Intent, pending persistence,
and remote launch retain their order; submitted work keeps its original lane,
flock, owner admission, and permit even if the awaiting caller is cancelled.

### 4. Bound submitted asynchronous inventory reads

MCP list/page and the async operation's process-list dispatch use one shared pool
of four permits before `spawn_blocking`. A submitted closure retains its permit
until it exits, including time queued in the blocking pool and after caller
cancellation. Synchronous list/page implementations remain available underneath.

### 5. Stream the existing inventory snapshot digest

The snapshot serializer borrows rows and hashes through a fixed 8 KiB buffer,
avoiding a cloned `Value` tree and a second complete serialized binding.
The existing key order, escaping, null handling, SHA-256 binding, old cursors,
and page response bytes are preserved, including wire-budget page reduction.

### 6. Shorten the closed file observation helper

The fixed info/read helper omits unused `inode_patch.py` while retaining the
original metadata, descriptor, and binary-read helpers. The general RPC source
still includes all writers. Isolated Python executions compare actual successful
outputs and version, cursor, and path refusals against that complete source.

## Existing qualification and test evidence

The retained qualification reports `qualified: true`, using Rust **1.95.0**.
All eight stages exited zero: format, format check, Python harness tests,
all-targets/all-features Clippy with warnings denied, test build, isolated tests,
independent isolated-test audit, and all-features release bins/examples.

| Audit result | Count |
| --- | ---: |
| Selected | 1,644 |
| Executed / passed | 1,614 |
| Failed | 0 |
| Ignored | 30 |

The six added test modules contribute 31 entries: cohort admission 7, pending
publication 3, inventory async 6, inventory digest 3, registry decode 9, and
binary observation source 3. One decode diagnostic is ignored; 30 are ordinary
tests. Coverage includes cancellation, panic, closure queueing, original-owner
identity, escaped strings, descriptor guards, cursor compatibility, and helper
output equivalence.

The input, tested, and after source maps contain **210 paths with identical
SHA-256 mappings**. The imported R10e baseline was checked against all 210.
Harness hashes also match before and after qualification. The report records
zero automatic test retries and no service changes.

Qualified `hepta-runtime` release SHA-256:

```text
b4e9022de0c764f84450cb7ade4947de0858460f09a898d3c830270006cc1504
```

Evidence retained in the shared validation bundle:

- [R10e qualification](../tests/evidence/20261103-x230-r11/r10e-qualification.json.gz)
- [R10e isolated-test audit](../tests/evidence/20261103-x230-r11/r10e-isolated-tests.audit.json.gz)
- [R10e source map](../tests/evidence/20261103-x230-r11/r10e-source-map.json)

## Limits

- R10e borrows during cold reuse scans; inventory list/page still use owned decode.
  Borrowed inventory and moving `check_ref` observation off async workers belong to R11.
- Escaped JSON strings allocate decoded storage; borrowing is not zero allocation.
  The no-content-watch fingerprint fallback keeps its owned canonical decode.
- Four permits bound submitted physical inventory reads, not all waiting requests.
- The persistence protocol is unchanged. These tests do not establish a new WAL,
  distributed-consensus protocol, power-loss guarantee, or remote reboot guarantee.
- Qualification establishes the recorded build and correctness results. It does
  not establish a six-host throughput gain or a long-duration resource bound.
