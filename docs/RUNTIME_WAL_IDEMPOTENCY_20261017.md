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
- `PRIMARY KEY(host, idem_key)` and `UNIQUE(job_id)` give atomic reservations.
- Creation of an identity commits **before** a prospective remote submission.
- Crash after reservation, before JSON save, remains `reserved`: never infer
  failure or automatically allocate a new ID.
- Existing legacy keys with missing complete request digest remain bound
  but cannot be silently replayed.
- `mark_saved` checks the original current-owner 0600 single-linked file
  and exact ID/host/key/digest before advancing the persisted phase.
- Import of existing JSON runs only against an isolated frozen-writer
  directory. Duplicate, malformed, wide-permission or linked files abort
  the entire transaction; no partially imported index is sealed.
- Reopen requires the same canonical root and job-dir device/inode and
  a sealed schema. DB corruption fails closed; do not auto-rebuild.
- Unkeyed original jobs are counted but **not assigned fictitious keys**.

## Boundaries — do not confuse with production readiness

Tests model short SQLite transactions and 1/4/8/16/32 concurrent callers.
SQLite still has one WAL writer; this may be sufficient for short admissions
but is **not** parallel durable writes without contention.
Current `jobs.rs::start_job` is unchanged by this prototype.
No remote SSH commands, trade orders, model tasks, systemd restarts or
new tunnel endpoints are initiated by these test-only functions.

Before effectful integration: authoritative single-effect-owner fence,
exact original idempotency reconciliation across V4/V11, gap-free import
while writers are frozen, crash-before/after-remote-write reconciliation,
owner epoch binding, and rollback that never issues a second job ID.

## Evidence

Exact source branch: `codex/runtime-wal-idempotency-20261017`,
stacked on PR #14 commit `9bf3e40cb38b1dc43720d26639df989b36d922e1`.
Initial isolated Rust WAL regression: **10 passed, 0 failed, 1 ignored**.
The explicitly invoked synthetic 23,347-row test completed successfully:
private JSON -> WAL index bootstrap **1,577.497 ms**, 100 exact-key lookups
P50 **0.0874 ms**, P95 **0.1032 ms**. Total test wall was **177.40 s**
because fixture creation synchronously wrote 23,347 individual test files;
that fixture preparation is excluded from the stated bootstrap figure.
A 32-thread independent-connection test preserved 32/32 unique identities,
but **32 FULL-sync individual transactions took 2,944.42 ms** even after
separating connection setup. That revealed real serialized WAL write cost.
The subsequent implementation adds a bounded `reserve_batch` method that
commits up to 128 reservations in one atomic FULL-sync WAL transaction,
with abort-and-rollback on any key/digest/job-ID conflict. Its updated
1/4/8/16/32 tests must pass before the batched path is qualified.
No six-host SSH TPS or production speedup is claimed from these DB tests.
