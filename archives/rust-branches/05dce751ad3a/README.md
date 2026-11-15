# Preserved Rust branch variant

Original branch: `fix/x230-r34-exact-rustfmt-20261106-gpt6`. Original commit: `05dce751ad3a71ff58cf289eec3669df3013b148`.

Earlier exact-format checkpoint for the rejected R34 lineage. Retain original source and formatting evidence without activating its fixed admission reserve.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 05dce751ad3a71ff58cf289eec3669df3013b148
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
