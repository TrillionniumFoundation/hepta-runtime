# Preserved Rust branch variant

Original branch: `fix/runtime-ci-stacked-head-merge-20261023-gpt6`. Original commit: `4d32ba361452b0040c530ab6c0596672716d48d0`.

Current stacked-branch and main CI contains the intended exact-head/prospective-merge coverage. Keep current workflow and archive original proof proposal.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 4d32ba361452b0040c530ab6c0596672716d48d0
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
