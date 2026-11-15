# Preserved Rust branch variant

Original branch: `fix/rea-preview-linux-atomic-publish-20261103-gpt6`. Original commit: `d875438db6d20f2c0218fde7a47f79a42d66b088`.

Linux RENAME_NOREPLACE publication is already present in current rea_store.rs, with later macOS exclusive-rename and durability handling. Preserve original source/tests without regressing those platform and owner safeguards.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree d875438db6d20f2c0218fde7a47f79a42d66b088
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
