# R36 source scope review

Date: 2026-11-06. Status: static source review passed; X230 qualification and performance acceptance pending.

## Source identity and scope

- Git parent: `86155fbf3b89e5a77e2a4aadebd2128c663fe50b`.
- Accepted R24 source baseline: commit `baab4def80be7af015b2e7a594cb302f66c4130e`, `src` tree `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`.
- Development branch: `perf/x230-r36-20261106`.
- Prepared patch SHA-256: `c693664d88e1bbed7e1257ad292d9d7b54eb3521db039cc1b8468f1e7b13caf1`.
- Prepared compile-input maps each contain 220 paths with identical path sets. Content changes are limited to `src/mcp/runtime/request_audit.rs`, `src/mcp/runtime/request_audit_lookup_tests.rs`, and `src/mcp/runtime/request_audit_tests.rs`.
- Current patch: 3 files, 45 insertions and 2 deletions. Production code has exactly two line replacements; no dependencies, runtime flags, limits, transport code, router, cancellation policy, or qualification thresholds change.

## Production review

Both `begin_with_read_at()` and `begin_reserved_record_at()` now publish their final, no-longer-used records with `cache_hot_owned(&directory, records)` instead of `cache_hot(&directory, &records)`. This removes the successful admission's final deep copy. Both paths retain the original `hot_snapshot(root, &directory)` read and its initial clone.

Exclusive `STORE_LOCK` custody, authority and read-pin checks, retention, archive and hot writes, file and directory fsync, cache publication, and active-marker publication retain their original ordering. The read-only snapshot paths are unchanged. Rejected lookup and archived-identity admissions do not consume the original cache. Archive-only admission continues to preserve the existing hot records. Unknown outcomes and the prohibition on redispatching an existing identity are unchanged.

The earlier proposal to take the hot snapshot before validation is excluded from this candidate. Its separate static-proposal patch is not a qualification input.

## Regression coverage and static checks

Two existing tests were extended; the test count is unchanged:

- `unowned_missing_malformed_or_nonlookup_pin_is_refused_before_eviction`: retained records, owner isolation, no erroneous read pin, reusable snapshots, and a subsequent valid lookup at the owner quota.
- `reserved_archived_identity_cannot_redispatch_after_hot_eviction`: retained records after rejection, subsequent distinct identity admission, no redispatch, and unchanged original archive bytes.

Cache availability is checked after reading the snapshot while retaining the same exclusive lock; no assertion assumes a global cache entry survives eviction by other roots between lock acquisitions. The additions do not call a locking admission/observation/completion entry point while holding `STORE_LOCK`. Record comparisons borrow their operands and do not require a new `Debug` implementation.

The author and an independent reviewer inspected the final source and tests. `git diff --check` passed. No Rust compilation, tests, formatter, or performance load was run locally. No throughput or resource improvement has yet been established.

## Qualification identity policy

The original pinned qualifier runs `cargo fmt --all` before its build and test stages. The prepared map therefore identifies **pre-format input**, not necessarily the bytes later compiled.

Before accepting qualification evidence, require:

1. `source_input` equals the prepared 220-entry candidate map.
2. `source_tested` equals `source_after`; both retain the exact 220-path set.
3. Relative to R24, post-format content differences remain within the three declared changed paths.
4. The complete 19-file harness map is identical before and after qualification and equals the pinned input map.
5. `formatted_source_matches_preparation` explicitly records whether formatting changed bytes. Read back and review the actual post-format diff before accepting the candidate; never present the prepared map as the build identity unless equality has been verified.

The launch uses a new R36 root and target directory. Preparation and qualification results, original logs, and the actual tested-source map must remain separate evidence. Static review does not substitute for the X230 qualification or the unchanged observation/lifecycle acceptance gates.
