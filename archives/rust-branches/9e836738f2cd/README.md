# Preserved Rust branch variant

Original branch: `experiment/x230-r36-validation-scratch-20261106`. Original commit: `9e836738f2cd160cbe67a43daa917a9f29c7059c`.

The R36 candidate lineage remains unadopted; final original rejection is retained by perf/x230-r36-20261106 in tools/x230/20261106/r36/README.md. Preserve this earlier candidate and all evidence without reverting the later runtime.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 9e836738f2cd160cbe67a43daa917a9f29c7059c
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
