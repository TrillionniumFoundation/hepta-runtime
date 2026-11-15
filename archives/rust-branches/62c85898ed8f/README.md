# Preserved Rust branch variant

Original branch: `fix/http-mcp-security-standalone-base-20261022`. Original commit: `62c85898ed8fbcd9d9b9776bcc5f55aad9a48f76`.

Actual standalone-HTTP auth gap is reconciled in current main.rs/cli.rs by universal token and loopback validation plus eight regressions. Archive the old whole-file patch so current credential scopes and unrelated startup paths remain intact.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 62c85898ed8fbcd9d9b9776bcc5f55aad9a48f76
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
