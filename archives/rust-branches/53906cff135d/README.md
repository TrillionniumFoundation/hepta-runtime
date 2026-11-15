# Preserved Rust branch variant

Original branch: `experiment/x230-router-cache-20261105`. Original commit: `53906cff135dcf8a29c73782df4bb6761b646a7e`.

This router-cache proposal is explicitly prepared, unselected, unformatted, uncompiled and untested in tools/x230/20261105/router-cache-experiment/README.md. Preserve it as research, not active runtime.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 53906cff135dcf8a29c73782df4bb6761b646a7e
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
