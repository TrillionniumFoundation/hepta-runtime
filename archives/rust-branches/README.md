# Preserved Rust branch variants

This directory keeps exact historical inputs while Rust development converges on
`main`. An archive is not a Cargo workspace member, an enabled GitHub workflow,
or a production adoption. Failed and incomplete experiments retain their original
disposition.

Each commit-named directory contains a manifest with the original branch, commit,
tree, merge base, every changed path, original Git blob, retained path and the
reason a later active implementation was kept. The original commit is also a
merge parent and remains reachable, so its complete tree can be restored with
`git worktree add --detach /your/isolated/path ORIGINAL_COMMIT`.

New historical experiment records are kept at their original evidence paths.
Conflicting source, tests, compiler settings and workflows live under `files/`.
Active security gaps found while comparing older fixes were repaired in current
code before their older whole-file implementations were archived.

Run `python3 scripts/verify_rust_consolidation.py` to verify all original Rust
branch heads and retained blob identities. The complete audit and protected HIA
reference inventory are under
[`docs/audits/rust-main-20261115`](../../docs/audits/rust-main-20261115/README.md).
