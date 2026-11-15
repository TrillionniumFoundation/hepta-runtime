# Preserved Rust branch variants

This directory indexes the exact historical inputs retained while Rust development
converged on `main`. Failed and incomplete experiments retain their original
disposition.

Each commit-named directory contains a manifest with the original branch, commit,
tree, merge base, every changed path, original Git blob and file mode, and the
reason a later active implementation was kept. The original commit is a merge
ancestor and remains reachable. Restore its complete tree with:

```sh
git worktree add --detach /your/isolated/path ORIGINAL_COMMIT
```

Manifest v2 removes duplicate `files/` source copies and the retired experiment
records from the current checkout. An entry with disposition
`retained_in_reachable_git_history` is verified at `source_commit:path` against
its recorded original blob and mode. `previous_retained_path` and
`previous_disposition` preserve its former location and classification. Entries
that still have a `retained_path` remain materialized and are checked byte for byte
through their Git blob identities. Earlier v1 manifests remain supported by the
verifier.

The separate [repository history index](../repository-history/README.md) records
complete directory inventories retired during the repository cleanup. Both
indexes use existing reachable Git objects; no failed observation is rewritten,
no branch history is erased, and no archived source is newly adopted by the
current runtime.

Run `python3 scripts/verify_rust_consolidation.py` to verify all original Rust
branch heads, original commit trees, retained blob identities and complete retired
directory inventories. A shallow checkout or unavailable object fails with explicit
fetch guidance; the verifier never fetches implicitly. The complete original audit and protected HIA
reference inventory are under
[`docs/audits/rust-main-20261115`](../../docs/audits/rust-main-20261115/README.md).
