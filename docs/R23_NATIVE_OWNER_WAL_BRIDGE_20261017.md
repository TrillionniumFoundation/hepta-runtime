# R23 native owner fence + SQLite WAL index: integration candidate

**Scope:** isolated Git source and deterministic Rust tests only. This is NOT the live R22 production binary, effectful `process_start` WAL wiring, an owner transfer, or approval to stop Desktop Commander.

## Frozen inputs

- Base branch: PR #17 `bcd0a99df19c5b651c35c90e5a477cd9717cb47c` (integrated R22 native source, V4/V11 replay and PTY guard).
- WAL source: PR #16 `b153ae8aacf61bdbfc56b221447dee3489c4644f`, copied byte-for-byte from the isolated branch initially (SHA256 `97067c1e197234764c6b6482aa96bb961e03e4ab03d554a6908c56aab3b03cde`).
- Ledger remains **test-only** (`#[cfg(test)]`) and `rusqlite = 0.40.2` is a dev dependency; default shipping binary has no WAL executor.

## New combined owner proof

- Native `effect_owner_fence::AdmissionPermit` keeps a pinned owner identity and epoch only after obtaining its existing shared owner `flock` and validating the signed-in controller state path.
- The test-only `wal_writer_proof` refuses an unenrolled / ownerless / unlocked permit and returns the pinned `(v4|v11, epoch)` to the WAL state machine; it is not a standalone new authorization source.
- The disposable local fixture acquires a native V4 permit, creates a unique WAL reservation, saves the exact original JSON record, and persists the single-use `submission_unknown` remote intent.
- Under explicit fixture-only frozen transitions, V11 acquires the new native permit and binds its WAL writer to the same epoch. The V4 historical key remains owned by its original job ID and cannot yield a second remote-submit ticket.
- Rollback to V4 with a later monotonic epoch must preserve the original ID, not recreate the old remote effect.

## Remaining true production blockers

- Current WAL schema pins **one** original JSON jobs directory. The full effect-owner cutover has different V4/V11 controller state roots; this test does not solve multi-root original-record reconciliation.
- SQLite owner-epoch transitions model cooperating processes, but have not been linked to an authenticated administrative transfer that freezes/drains every ingress and holds native `flock` during the remote operation.
- Existing live R22 binary still lacks a verified source-commit reconstruction. New source commit and binary hash will not be interpreted as R22 bit-identity.
- No production use of the WAL ledger is enabled. Deployment must follow independent 1/4/8/16/32-way six-host end-to-end benchmarks and original-ID recovery and rollback verification.

## Evidence

On the combined source, native WAL tests **24/24 passed** (one explicit large synthetic benchmark ignored), native effect-owner fence tests **27/27 passed**, including two new combined/proof-negative regressions. The integrated test performs one bound remote-intent transition and a fixture-only V4→V11→V4 ownership round trip under the same EX-flock handoff. It does not launch SSH or route actual effects. The full locked offline Cargo suite is separately required; no full-suite or production speedup claim is made from focused regressions.
