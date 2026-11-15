# Preserved Rust branch variant

Original branch: `fix/runtime-audit-data-minimization-20261023-gpt6`. Original commit: `51cba75c0098dc01a5c1d19c431af7fbed68484f`.

Current callers retain typed minimal audit outcomes, numeric privileged exit validation and constant launch-error categories; strict shadow ABI is also present. Preserve original generic redaction source/tests rather than replacing later typed execution paths.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 51cba75c0098dc01a5c1d19c431af7fbed68484f
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
