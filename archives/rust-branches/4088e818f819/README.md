# Preserved Rust branch variant

Original branch: `codex/runtime-inventory-background-20261109`. Original commit: `4088e818f8194c62dffd6895f9316762b4b2d2d3`.

Superseded by the adopted #116 unbounded-baseline inventory implementation at 8d9f03692359176945c8628215e70f4524c3b86c. Preserve #115 original bounded-worker/four-entry variant but do not reintroduce those execution admission ceilings.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 4088e818f8194c62dffd6895f9316762b4b2d2d3
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
