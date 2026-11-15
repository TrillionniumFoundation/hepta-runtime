# Preserved Rust branch variant

Original branch: `experiment/x230-r24-validation-cost-20261106`. Original commit: `092cc578faecace3f2f1fc7e8df12fbd3fb6a456`.

Historical accepted R24 and subsequent cost/evidence lineage precedes the current Rust source with native artifact/HIA adapters, strengthened owners and explicit unbounded policy. Preserve original accepted and failed campaign records without rolling current runtime back to an earlier snapshot.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 092cc578faecace3f2f1fc7e8df12fbd3fb6a456
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
