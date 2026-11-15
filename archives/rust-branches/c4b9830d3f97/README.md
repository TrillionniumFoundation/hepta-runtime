# Preserved Rust branch variant

Original branch: `fix/rea-unified-pr-ci-admission-20261103-gpt6`. Original commit: `c4b9830d3f9744177ed509b280ee662a61de83ae`.

Current CI already covers the unified stack and now main, with locked head/merge checks, both feature modes and isolated nextest. Preserve older branch-filter proposal without overwriting current qualification commands.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree c4b9830d3f9744177ed509b280ee662a61de83ae
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
