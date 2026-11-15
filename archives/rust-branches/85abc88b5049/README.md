# Preserved Rust branch variant

Original branch: `fix/runtime-host-start-guards-20261023`. Original commit: `85abc88b5049cfc1ab8f3b547687cc17614f56e8`.

Current host-scoped and full-registry duplicate-owner validation implements this historical intent. Preserve exact earlier guard/tests rather than replacing the newer retained native launch owner.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 85abc88b5049cfc1ab8f3b547687cc17614f56e8
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
