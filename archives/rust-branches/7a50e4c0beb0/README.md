# Preserved Rust branch variant

Original branch: `experiment/x230-compiler-20261105`. Original commit: `7a50e4c0beb0b23a61b7372c24966cf80fc65b99`.

R25 passed qualification but failed observation performance and was not adopted; tools/x230/20261105/r25/README.md retains both failed and passed attempts. Preserve its exact source and evidence without activating rejected compiler/runtime changes.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 7a50e4c0beb0b23a61b7372c24966cf80fc65b99
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
