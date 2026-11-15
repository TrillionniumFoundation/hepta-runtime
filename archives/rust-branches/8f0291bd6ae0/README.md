# Preserved Rust branch variant

Original branch: `dot/runtime-idempotency-host-lanes-20261023-gpt6`. Original commit: `8f0291bd6ae0db6b06f133f185d88b303ce20367`.

Current registry and host-scoped native owners include newer duplicate-key, nofollow and durability validation. Preserve this earlier stack and its tests without replacing those later owners; separately reconcile missing physical-CWD checks in current code.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 8f0291bd6ae0db6b06f133f185d88b303ce20367
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
