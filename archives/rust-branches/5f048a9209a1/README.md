# Preserved Rust branch variant

Original branch: `perf/x230-r36-20261106`. Original commit: `5f048a9209a128fa7d68564dd659f0589d961b0a`.

R36 required normal C6 lifecycle failed; original report records adoption_passed=false and rejected launch/cancel cost gates. tools/x230/20261106/r36/README.md and docs/X230_OPTIMIZATION_20261106_R36.md remain authoritative historical evidence.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 5f048a9209a128fa7d68564dd659f0589d961b0a
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
