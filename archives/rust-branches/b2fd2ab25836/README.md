# Preserved Rust branch variant

Original branch: `feature/execution-shadow-abi-20261023`. Original commit: `b2fd2ab2583601c056c6244fb1d6282f1e8be67e`.

Current execution.rs retains the read-only canonical shadow ABI and adds deny_unknown_fields for both record and FinalUse envelopes. Preserve original API source without dropping current stricter wire validation or registering duplicate tools.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree b2fd2ab2583601c056c6244fb1d6282f1e8be67e
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
