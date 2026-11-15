# Preserved Rust branch variant

Original branch: `fix/runtime-duplicate-idempotency-owners-20261023-gpt6`. Original commit: `a26c01a16833b1cf80a9d468ae101af72f30fbbe`.

Current full registry validates duplicate physical owners and idempotency key binding before reuse. Preserve the earlier parallel fix and tests without reverting later nofollow persistence and recovery logic.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.
