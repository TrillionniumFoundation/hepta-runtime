# Preserved Rust branch variant

Original branch: `dot/runtime-http-auth-token-fence-20261021`. Original commit: `7d8c0c3f3c56540847d4c00132f54ae8b684b16c`.

Current token loader preserves private-file/no-follow/size validation. Consolidation additionally applies universal HTTP token and loopback enforcement with real middleware regressions; retain the older exact implementation as provenance.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 7d8c0c3f3c56540847d4c00132f54ae8b684b16c
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
