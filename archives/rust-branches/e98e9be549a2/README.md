# Preserved Rust branch variant

Original branch: `fix/runtime-dual-source-merge-ci-proof-20261022`. Original commit: `e98e9be549a26cec3d10be19df769d6cf3f4ec82`.

Current CI supersedes this earlier exact-head/merge proof workflow. Preserve original contents and ancestry while retaining current source-identity checks and all-target validation.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree e98e9be549a26cec3d10be19df769d6cf3f4ec82
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
