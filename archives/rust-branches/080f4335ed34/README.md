# Preserved Rust branch variant

Original branch: `experiment/x230-r33-path-components-20261106`. Original commit: `080f4335ed34bff5d2fd607dcf048f79774e6f48`.

R33 failed the original C8 throughput gate and was not adopted; tools/x230/20261106/r33/README.md. Preserve original source and failed evidence.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 080f4335ed34bff5d2fd607dcf048f79774e6f48
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
