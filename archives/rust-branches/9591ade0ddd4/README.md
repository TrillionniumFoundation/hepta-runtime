# Preserved Rust branch variant

Original branch: `fix/runtime-ci-dual-source-qualification-20261023-gpt6`. Original commit: `9591ade0ddd4a96891a4dcdb1001467552d5e63b`.

Retain current separate exact-head and prospective-merge gates with both feature configurations and nextest isolation. Archive this superseded earlier workflow without weakening or duplicating active gates.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 9591ade0ddd4a96891a4dcdb1001467552d5e63b
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
