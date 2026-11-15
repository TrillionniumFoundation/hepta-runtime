# Preserved Rust branch variant

Original branch: `codex/native-runtime-remote-fs-feature-20261028`. Original commit: `bef3935e4751fae62f5139fda94409a571c5af6f`.

Current optional remote-fs library and native entry retain exact request identity, no-relaunch reuse and bounded terminal proofs. The newer independent SSH worker owns the static callback/guard through physical spawn, child reaping and uncertain-child quarantine, with cancellation regressions. Preserve old native variant without weakening the later owner lifetime.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree bef3935e4751fae62f5139fda94409a571c5af6f
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
