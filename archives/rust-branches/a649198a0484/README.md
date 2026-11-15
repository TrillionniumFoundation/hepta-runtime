# Preserved Rust branch variant

Original branch: `experiment/x230-r34-cancel-reserve-20261106`. Original commit: `a649198a048475b1d1bbaf1656b7c9a33eb869d7`.

R34 failed the original C8 throughput gate and was not adopted; tools/x230/20261106/r34/README.md. Its fixed cancellation admission reserve must not override the later explicit unbounded concurrency policy.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree a649198a048475b1d1bbaf1656b7c9a33eb869d7
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
