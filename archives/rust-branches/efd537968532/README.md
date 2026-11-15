# Preserved Rust branch variant

Original branch: `dot/runtime-qualification-path-fence-20261023`. Original commit: `efd53796853209e373fd54402a97aa3ae24f1536`.

Historical native stack is superseded. Its PATH, source-byte and descendant qualification protections are retained and reconciled into current active Python helpers; preserve every original input without restoring obsolete CI or process owners.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree efd53796853209e373fd54402a97aa3ae24f1536
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
