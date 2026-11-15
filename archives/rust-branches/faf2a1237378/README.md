# Preserved Rust branch variant

Original branch: `fix/runtime-sftp-runtime-mode-quarantine-20261023`. Original commit: `faf2a12373788560979f525b40a0588f1620b1e9`.

Current runtime remote effects use the descriptor-relative file owner; raw runtime-mode SFTP remains restricted. Preserve the old blanket quarantine patch without removing the later guarded supported route; root-ancestor trust remains an explicitly documented limit.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree faf2a12373788560979f525b40a0588f1620b1e9
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
