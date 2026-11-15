# Preserved Rust branch variant

Original branch: `recovery/weight-runtime-worktree-20261103`. Original commit: `4b1605065e53ff70d7214f47e76124f735b435d6`.

Original recovered weight-worktree snapshot predates current resident weight owner and the now-integrated WSP cohort/semantic features. Preserve exact recovered bytes without reverting newer config/MCP registration or active tests.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 4b1605065e53ff70d7214f47e76124f735b435d6
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
