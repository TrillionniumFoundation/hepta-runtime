# Preserved Rust branch variant

Original branch: `experiment/x230-r30-router-20261105`. Original commit: `7e3a08d549c60a66673b07c1d47e77fbe5c9df1c`.

R30 original six-host observation failed and the candidate was not adopted; tools/x230/20261105/r30/README.md. Preserve original rejection and source without enabling this historical router.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 7e3a08d549c60a66673b07c1d47e77fbe5c9df1c
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
