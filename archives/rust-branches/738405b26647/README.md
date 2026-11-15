# Preserved Rust branch variant

Original branch: `dot/runtime-p3-full-source-qualification-20261022`. Original commit: `738405b266477d3127ba7d457ca5981f09983abb`.

Historical native-library and qualification stack. Current library, remote descriptor owner and isolated CI supersede its compiled files. Missing physical remote cwd guards are restored by the consolidation security patch; useful qualification Python guards are integrated separately.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 738405b266477d3127ba7d457ca5981f09983abb
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
