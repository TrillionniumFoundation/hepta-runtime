# Preserved Rust branch variant

Original branch: `fix/runtime-remote-receipt-fsync-20261023`. Original commit: `e4430da68028d6e300682be7923926b98c0728db`.

Current private_read_json and bound_remote_code strengthen corrupt/symlinked status/cancel receipt refusal with nofollow/nonblock, owner/link/size/stamp validation and pinned directories. Existing stage_file, request, owner and terminal publication retain the original fsync ordering. Preserve earlier receipt implementation/tests without reverting later owners.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree e4430da68028d6e300682be7923926b98c0728db
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
