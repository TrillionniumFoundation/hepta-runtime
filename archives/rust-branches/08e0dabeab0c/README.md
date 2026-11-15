# Preserved Rust branch variant

Original branch: `experiment/x230-r27-serializer-20261105`. Original commit: `08e0dabeab0c46bea91313e9e197bdb8d55d9d28`.

R27 was not adopted and its full gates were not run; tools/x230/20261105/r27/README.md. Keep the later runtime while preserving this unfinished serializer experiment.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 08e0dabeab0c46bea91313e9e197bdb8d55d9d28
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
