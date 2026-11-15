# Preserved Rust branch variant

Original branch: `experiment/x230-a43-owner-barrier-20261025`. Original commit: `ba46ac727d0169e23238740d1a1d1a30be370510`.

Finite original A43 qualification is preserved, but branch documents do not establish production adoption. Retain current later durable owner/barrier implementation and preserve original alternative source and all historical results.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree ba46ac727d0169e23238740d1a1d1a30be370510
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
