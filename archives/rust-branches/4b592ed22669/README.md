# Preserved Rust branch variant

Original branch: `experiment/x230-capacity12-20261105`. Original commit: `4b592ed22669d9facd46aadc3aba4e2f91c5fe8b`.

R26 was rejected and not adopted by its original observation and p95 gates; tools/x230/20261105/r26/README.md retains the original decision. Keep the later unbounded runtime and preserve the candidate exactly.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 4b592ed22669d9facd46aadc3aba4e2f91c5fe8b
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
