# Preserved Rust branch variant

Original branch: `experiment/x230-r31-pidfd-20261105`. Original commit: `6757eff310932654389184d88ecd7edef90696bd`.

R31 original observation rejected performance adoption; tools/x230/20261105/r31/OBSERVATION_REJECTED.md. Keep later accepted process ownership and preserve the unadopted variant.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 6757eff310932654389184d88ecd7edef90696bd
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
