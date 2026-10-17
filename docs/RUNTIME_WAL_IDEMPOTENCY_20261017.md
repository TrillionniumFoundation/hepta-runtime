# Durable WAL idempotency ledger — isolated runtime prototype

Status: **test-only implementation** (the `wal_idempotency` module is behind `#[cfg(test)]`).
Not a production migration, deployment, new effect owner, or replacement for V4/V11.

## Motivation

R22 had more than 23,000 JSON job records. A full history scan and directory
generation check for every new `(host, idempotency_key)` can conflict with
host-scoped launch locks and unrelated cross-host jobs.

## Proposed admission contract

- Private current-UID `0700` roots; SQLite DB current-UID `0600`.
- SQLite WAL + FULL synchronous durability + bounded busy timeout.
- v3 index schema retains the v2 global-ID fix:  `PRIMARY KEY(host, idem_key)` plus a separate `original_job_ids` table reserves every original ID, **including historical records with no idempotency key**. New batch reservations atomically populate both tables; a collision rolls back the whole transaction.
- Creation of an identity commits **before** a prospective remote submission.
- Crash after reservation, before JSON save, remains `reserved`: never infer
  failure or automatically allocate a new ID.
- Existing legacy keys with missing complete request digest remain bound
  but cannot be silently replayed.
- `mark_saved` checks the original current-owner 0600 single-linked file, its `pending` launch state, exact ID/host/key/digest and global original-ID binding before advancing the persisted phase.
- Test-only `begin_remote_submission` requires the exact durable `record_saved` identity, then atomically commits `submission_unknown` **before** yielding a single-use remote-submit ticket. An interrupted/unknown attempt cannot obtain a second ticket or a new job ID on controller restart.
- Import of existing JSON runs only against an isolated frozen-writer
  directory. Duplicate, malformed, wide-permission or linked files abort
  the entire transaction; no partially imported index is sealed.
- Reopen requires the same canonical root and job-dir device/inode and
  a sealed schema. DB corruption fails closed; do not auto-rebuild.
- Unkeyed original jobs are counted but **not assigned fictitious keys**.

## Adversarial regression: original unkeyed ID collision

The initial v1 prototype allowed a new keyed reservation to reuse an existing **unkeyed** legacy job ID. A new test reproduced that failure before any patch. The private v2 schema imports all original job IDs and verifies every keyed reservation's global ownership inside the same short SQLite transaction. Tests now prove a collision with an unkeyed original refuses both a single reservation and an entire batch without persisting partial new identities. Old unkeyed jobs are not assigned invented keys.

## Test-only WAL writer epoch model (v3)

A `writer_authority` row binds exactly one `v4`/`v11` writer, monotonically increasing epoch and `admitting`/`frozen` phase. Every indexed reservation, original-record save and `submission_unknown` transition rechecks this row **inside the same SQLite transaction**. A newly reserved original ID also persists its creating owner/epoch, so the successor cannot submit the predecessor's staged command. Frozen or stale-epoch connections refuse new indexed writes; reversal is modeled only from an exact frozen epoch and retains all historical task identities.

This is a database-only **cooperating-controller** model. The test-only initial-owner and transfer methods are **not** authenticated administrative operations. They do not establish that production V4/V11 or any other ingress uses the WAL ledger, do not drain already issued remote effects, and do not hold the real owner flock through a network submission. Until an independently authenticated shared effect fence encloses every production write ingress, this model must not be wired to live dispatch.

## Boundaries — do not confuse with production readiness

Tests model short SQLite transactions and 1/4/8/16/32 concurrent callers.
SQLite still has one WAL writer; this may be sufficient for short admissions
but is **not** parallel durable writes without contention.
Current `jobs.rs::start_job` is unchanged by this prototype. The WAL module remains compiled only for Rust tests, and its submit ticket is a **state machine model**, not permission to issue production remote effects. V4/V11 cross-controller owner admission must be implemented and retained through any actual network submission.
No remote SSH commands, trade orders, model tasks, systemd restarts or
new tunnel endpoints are initiated by these test-only functions.

Before effectful integration: authoritative single-effect-owner fence,
exact original idempotency reconciliation across V4/V11, gap-free import
while writers are frozen, crash-before/after-remote-write reconciliation,
owner epoch binding, and rollback that never issues a second job ID.

## Evidence

Exact source branch: `codex/runtime-wal-idempotency-20261017`,
stacked on PR #14 commit `9bf3e40cb38b1dc43720d26639df989b36d922e1`.
Current WAL v3 **focused** regression: **21 passed, 0 failed, 1 ignored**. The additions cover remote-submission single-use intent, crash/reopen recovery, six-host batch staging, the formerly failing unkeyed-legacy-ID collision, atomic batch rollback, frozen-owner rejection, V4→V11→V4 epoch transfer, and prevention of cross-epoch remote-intent submission. The ignored case is the independently invokable 23,347-row synthetic benchmark.
**WAL v3 actual-scale isolated replay:** the explicitly invoked 23,347-row
synthetic import completed PASS with **1,889.296 ms** to seal the
all-original-ID SQLite index, exact-key lookup **P50 0.0823 ms** and
**P95 0.1390 ms**. The full test took **175.27 s** mainly because it
created/fsynced 23,347 disposable JSON fixtures first; that preparation
is excluded from the 1,889.296 ms bootstrap measurement.
No production jobs, SSH, original state directories or owner services were used.

**Historical v1 benchmark (retained separately, not directly comparable):** the previously invoked synthetic 23,347-row test completed successfully:
private JSON -> WAL index bootstrap **1,577.497 ms**, 100 exact-key lookups
P50 **0.0874 ms**, P95 **0.1032 ms**. Total test wall was **177.40 s**
because fixture creation synchronously wrote 23,347 individual test files;
that fixture preparation is excluded from the stated bootstrap figure.
The current isolated replay of **32 separate FULL-sync transactions** returned
**2,641.86 ms** after connection initialization, while 32 entries committed
in one FULL-sync atomic `reserve_batch` call took **8.099 ms** on the same host.
Batch 4/8/16/32 returned **8.490 / 14.356 / 9.777 / 8.099 ms**, respectively,
with exact ID reuse on repeated input. All-or-nothing rollback tests for
conflicting keys and duplicate job IDs passed, as did crash/reopen recovery.
On the current WAL **v3** source, the complete locked offline Cargo suite passed:
**682 Runtime tests, 0 failed, 14 ignored; 8 Jobctl tests, 0 failed**.
Strict `cargo clippy --offline --locked --all-targets -- -D warnings` also
passed (exit 0) on WAL v3 after resolving a missing Cargo cache package (`adler2`) with a locked `cargo fetch`. The initial offline Clippy invocation failed before any source check due to that missing package; the final strict check passed. `cargo fmt --all -- --check` and `git diff --check` passed.
A normal-only Cargo dependency-tree check reports no `rusqlite` dependency:
SQLite code and its dependency are test-only, never invoked by production
`process_start`. Neither local tests nor benchmark establish hosted CI success.
The per-test ratio for 32 was approximately 326x, but this is a comparison
of durable DB write strategies, not six-host job launch TPS or production
speedup. Actual live request batching would require an owner-fenced,
resource-bounded admission collector that is NOT implemented by this PR.
