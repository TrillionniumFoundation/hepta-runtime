# Historical repository records

The working tree contains the current runtime, its operational tools, tests and
selected reference evidence. Historical source-custody copies and completed or
incomplete experiment campaigns are indexed here and retained in Git history.

The exact pre-cleanup snapshot is
[`a404d4f1bf540fb94f65ef3707145eed07eef183`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/a404d4f1bf540fb94f65ef3707145eed07eef183).
It remains an ancestor of the cleanup. The [2026-11-15 manifest](20261115.json)
records **9,708 historical files and 1,521,911,966 bytes**, including each original
path, Git blob, mode and byte count. The separate [Rust branch index](../rust-branches/README.md)
retains the identities of another 215 duplicate source copies.

The [October 28 X230 follow-up manifest](x230-20261028-20261115.json) records
**80 additional historical files and 54,051,755 bytes** from the exact
[`136ff99783d48d67a6bb1babfba4ad1631310257` snapshot](https://github.com/TrillionniumFoundation/hepta-runtime/tree/136ff99783d48d67a6bb1babfba4ad1631310257).
These are complete original-evidence collections, including their raw archives,
diagnostics and refused attempts. Both manifests together retain **9,788 historical
files and 1,575,963,721 bytes** outside the current checkout. Active harnesses and
the generic evidence packer/analyzer remain available.

## What moved out of the current checkout

| Historical group | Retained snapshot path |
| --- | --- |
| Recovered historical source copies | `library-recovery/` |
| Earlier HIA integration and source-admission evidence | `review-evidence/` |
| X230 November 3–6 campaigns and their authoring snapshots | `tools/x230/20261103/` through `tools/x230/20261106/` |
| Earlier X230 A-series campaigns | `tools/x230/a26/`, `a38/`, `a40/`, `a43/`, and `a46/` through `a55/` |
| Earlier REA qualification campaigns | `docs/qualification/rea-p0p5-679ccf-20261106/`, `rea-family-20261106-r1/`, and `rea-audit-ext4-20261103-r1/` |
| Earlier DC replacement and rollback campaigns | `docs/qualification/dc-functional-v7-integrated-evidence-20261013/`, `dc-functional-v7-six-rollback-20261013-r1/`, `dc-functional-v8-integrated-evidence-20261013/`, and `dc-functional-v9-integrated-evidence-20261013/` |
| October 28 X230 original evidence collections (follow-up snapshot) | `tests/evidence/20261028-x230/` and `tools/x230/20261028/evidence/` |

The October 28–30 X230 regression harnesses remain in the current checkout.
`tools/x230/a27/` also remains because the October 28 throughput harness defaults
to its resource sampler. Active DC ledgers, the pinned `v9-harness-drafts` input,
runtime helpers, cloud-compute tools, model workers, HIA branches and their frozen
original-source baseline remain available at their current paths or refs.

## Read or reproduce the original work

Append a path from either manifest to that manifest's pinned snapshot URL above
to inspect it on GitHub. To restore the first retirement's original relative paths
together in an isolated checkout:

```sh
git worktree add --detach ../hepta-runtime-history a404d4f1bf540fb94f65ef3707145eed07eef183
```

For the October 28 X230 evidence and its corresponding current harness paths,
use the follow-up manifest's source revision:

```sh
git worktree add --detach ../hepta-runtime-x230-history 136ff99783d48d67a6bb1babfba4ad1631310257
```

If the checkout is shallow and lacks the snapshot, fetch its history explicitly
first. For example, `git fetch --unshallow origin` obtains the complete ancestry
needed by the verifier. Restoring the full historical worktree requires space for
the original source and evidence; Git can also read one file directly:

```sh
git show a404d4f1bf540fb94f65ef3707145eed07eef183:tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh
```

Historical logs, failed attempts, source seals and result classifications retain
their exact bytes. Their existing limits still apply when read or replayed from
the snapshot. Storage retirement does not turn an incomplete campaign into a
passed qualification and does not qualify the current runtime.

## Verify retention

```sh
python3 -B scripts/verify_rust_consolidation.py
```

The verifier checks ancestor reachability, the original source tree, every retired
path's blob and mode, local blob availability and byte counts. It reconstructs the
complete original file set beneath each declared retired root and rejects omitted,
extra or duplicate entries. It also requires those retired paths to be absent from
the reviewed current tree. Missing history or objects are errors; the check never
fetches, rewrites history or executes archived code.

This cleanup reduces current and shallow checkouts. Full Git history deliberately
retains the original objects and their original storage cost.
