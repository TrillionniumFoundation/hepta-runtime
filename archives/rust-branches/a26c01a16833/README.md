# Preserved Rust branch variant

Original branch: `fix/runtime-duplicate-idempotency-owners-20261023-gpt6`. Original commit: `a26c01a16833b1cf80a9d468ae101af72f30fbbe`.

Current full registry validates duplicate physical owners and idempotency key binding before reuse. Preserve the earlier parallel fix and tests without reverting later nofollow persistence and recovery logic.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree a26c01a16833b1cf80a9d468ae101af72f30fbbe
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
