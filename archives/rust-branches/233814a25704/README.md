# Preserved Rust branch variant

Original branch: `fix/rea-request-audit-private-root-20261103`. Original commit: `233814a257044a5a42683d3dc6388b0906986858`.

Superseded by prepare_controller_state_dir with private recursive creation, exact 0700 mode and current UID checks, plus permissive-umask subprocess regressions. Preserve the older implementation and test without weakening the later owner validation or private startup receipt.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 233814a257044a5a42683d3dc6388b0906986858
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
