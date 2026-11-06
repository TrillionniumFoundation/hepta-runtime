# R36 initial draft 01 — preserved eager scratch draft

This is an unformatted, uncompiled, unexecuted source draft on accepted R24 `baab4def80be7af015b2e7a594cb302f66c4130e`. It is not deployed or adopted. It contains neither D1/D2 instrumentation nor R31/R33/R34/R35 changes.

Only `ssh_observation_profile.rs` and its existing sibling `ssh_observation_reference_tests.rs` change. The full compile-input inventory remains 220 paths; the other 218 hashes remain those of accepted R24. The map was taken from the exact `baseline_compile_inputs` field of existing Git blob `86c91524ab994accb647e900220361b2505e31ba`; that R33 input is only a carrier of the R24 map, not this candidate's source baseline. Both changed source originals were independently fetched at the accepted commit and matched that map.

## Two mechanisms

1. Construct `ring::digest::Context` only when the immutable `self.reference` is None. Reference comparison still uses the original non-short-circuit `&=`; all reads and cancellation checks continue after a content mismatch. The Some/None pairing is determined once by immutable self, and no unwrap, expect, unsafe code, new panic, or reachable early-return branch is introduced. SHA fallback still includes an empty stream and finishes after the original final descriptor/path check.
2. Add an internal fixed-length mutable-buffer verifier. A checked Profile sweep owns one initialized 16 KiB array and lends it to the five files plus shell target sequentially. Standalone verification allocates its own local array. No buffer, FD, content result, permit, or authority is shared across requests, awaits, threads, worker/owner passes, or global state.

## Why this draft is preserved rather than chosen

The eager array initialization is at the wrapper/sweep entry. Every original `check_current` statement and its order relative to all fallible open/read/content/final checks are preserved, but an already-expired call can now pay the pure local memset before its first check. Root requested a separate lazy-scratch revision to preserve that earlier rejection position too. This draft is retained without overwriting it; its hashes must not be used as the lazy revision's identities.

No claim is made that removing Context initialization saves a heap allocation. No claim is made that five fewer source-level array initializations necessarily remove 80 KiB of actual machine writes, improve throughput, or reduce RSS. LLVM may already eliminate redundant work; Option discriminants, branches, stack layout or copies could offset any benefit. D2 actual cost attribution and the unchanged original full gates remain necessary before any performance decision.

## Safety scope

The patch keeps fresh per-component no-follow opens, all inode/permission/capability fences, fixed reference budget, `Read::take(maximum+1)`, read capacity, returned-count-only byte consumption, Interrupted/EOF handling, all original check_current statements, content error strings, final verify_read order, shell resolution, policy and owner boundary checks. The observation pool, validation permits, stop/deadline code, registry, child cleanup and cancellation helpers are untouched.

The author static check precisely reverses the eight explicit production edits back to the entire accepted original source. Removing the added test block precisely reconstructs the accepted sibling test file. This is a source-byte consistency result, not a Rust compile/test result or a performance result.

## Necessary regression drafts

Two new tests reuse the original private regular-file fixture:

- `shared_verification_buffer_ignores_stale_tail_across_modes_and_lengths`: one dirty shared scratch processes long, short and empty files in alternating reference/SHA modes and both starting orders; compares successful outcome and original callback count with fresh verification.
- `shared_verification_buffer_keeps_mismatch_cancellation_precedence`: a prior long file contaminates scratch; a later first-byte mismatch must still reach all original read/final boundaries, with cancellation at each original callback retaining precedence and count.

All existing reference/SHA differential tests remain byte-for-byte unchanged: multi-block/tail/empty data, original pin/budget, mismatch-then-cancel, metadata/path/length error precedence and owner rejection after worker acceptance remain available. They were not executed here. No tests claiming that a particular machine instruction disappeared were added.

## Reproducible identities and limitations

`input.json` contains the full before/after 220 maps, two source identities, new test names, patch SHA, and null qualification/CI/performance results. `candidate.patch` is the exact unified diff; `source/` contains complete changed files and `baseline/` the exact original two files. `static-review.json` records the source-only comparison and the initialization-order limitation. The reviewed design reference is Git `ff2b6e0ea76447d2b93ec5e5449f26c51379679f`.

No Cargo, rustfmt, Rust tests, benchmark, host API, workload or auditor was invoked. A first oversized local metadata writer was rejected before process creation (E2BIG); subsequent small create-only writes saved the exact draft and generated its diff. This was not a runtime/build/test failure.
