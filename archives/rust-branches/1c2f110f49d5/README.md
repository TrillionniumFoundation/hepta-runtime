# Preserved Rust branch variant

Original branch: `fix/r34-format-on-current-evidence-20261106-gpt6`. Original commit: `1c2f110f49d568da6beb84456b3fd815b2336de4`.

Formatting and evidence checkpoint for the rejected R34 lineage; preserve all exact original inputs. Formatting success does not supersede the failed original performance adoption gate.

The original commit remains reachable from `main`. Manifest v2 binds every
original path to that commit, its tree, Git blob and file mode. Entries marked
`retained_in_reachable_git_history` use the original Git object instead of a
second working-tree copy; `previous_retained_path` and `previous_disposition`
record the former storage location and classification. Any remaining
`retained_path` is still checked against its exact original blob.

Restore the complete original source and evidence in an isolated worktree:

```sh
git worktree add --detach /your/isolated/worktree 1c2f110f49d568da6beb84456b3fd815b2336de4
```

The old candidate retains its original failed, incomplete or successful
observations. This archive does not adopt its implementation or qualify the
current runtime. See `manifest.json` for the exact source identities.
