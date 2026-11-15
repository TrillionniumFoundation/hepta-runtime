# Preserved Rust branch variant

Original branch: `fix/runtime-ssh-bounded-duplex-20261022`. Original commit: `103cae318756e780492c2c22980e07b244740f06`.

Current ssh_direct owner retains bounded stream capture, duplex IO and caller-cancellation cleanup. Preserve the old bounded SSH implementation/tests without replacing later original-child custody and direct transport.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 103cae318756e780492c2c22980e07b244740f06
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
