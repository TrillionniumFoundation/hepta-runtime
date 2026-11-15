# Preserved Rust branch variant

Original branch: `codex/r23-wal-owner-bridge-20261017`. Original commit: `2fad43726075d9f980aea007fd93138ef6e1fa73`.

Historical cfg(test) WAL/effect-owner bridge prototype, not a production adoption. Preserve exact owner/ledger source and tests outside the active build; the current durable native owner remains authoritative.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 2fad43726075d9f980aea007fd93138ef6e1fa73
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
