# Historical repository records

The current checkout contains the runtime, operational tools, tests and their
required reference inputs. Completed, failed and incomplete historical campaigns
are preserved at their exact Git revisions and indexed here.

| Complete original inventory | Source commit | Files | Original bytes |
| --- | --- | ---: | ---: |
| [20261115.json](20261115.json) | `a404d4f1bf54` | 9,708 | 1,521,911,966 |
| [historical-sources-20261115.json](historical-sources-20261115.json) | `151d74efcf25` | 2,039 | 114,186,765 |
| [obsolete-entrypoints-20261115.json](obsolete-entrypoints-20261115.json) | `151d74efcf25` | 6 | 62,797 |
| [x230-20261028-20261115.json](x230-20261028-20261115.json) | `136ff99783d4` | 80 | 54,051,755 |
| Total | | 11,833 | 1,690,213,283 |

Every row records the original path, Git blob, file mode and byte count. The
separate [Rust branch index](../rust-branches/README.md) also retains the original
identities of 215 duplicate branch-source copies removed in the first cleanup.
Some original evidence is described by both indexes; their row counts must not
be added together to infer unique files.

## What moved

The initial inventories cover copied recovery trees, HIA review artifacts,
November 3–6 and A-series X230 campaigns, older REA/DC collections, and the two
October 28 X230 raw-evidence collections. The continued review adds forty complete
historical directories: remaining X230 experiment/results copies, R11–R15 raw
evidence, old operator and REA/DC authoring snapshots, the withdrawn checkpoint
prototype and the source-only recovery bundle.

The single-file inventory retires two branch-specific diagnostic workflows,
their old ROG experiment script and three superseded search-effects harness
snapshots. Only those exact paths are retired; the general `ops/` namespace
remains available for future work.

The original successes, failures, refusals, partial attempts, manifests and raw
outputs remain byte-identical in Git history. Current REA mappings and reference
bundles, DC receipts, `v9-harness-drafts`, X230 harnesses and the A27 sampler,
model workers, Colab/Kaggle tools and the standalone weightspace study stay in
the current tree. Active HIA development refs retain their own source history.

## Read or reproduce originals

Use the `source_commit` from the manifest that covers the desired path. The
initial snapshot is
[`a404d4f1`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/a404d4f1bf540fb94f65ef3707145eed07eef183);
the October 28 follow-up uses
[`136ff997`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/136ff99783d48d67a6bb1babfba4ad1631310257);
the continued cleanup uses
[`151d74ef`](https://github.com/TrillionniumFoundation/hepta-runtime/tree/151d74efcf252314e57cb6e1a5542401ff68f362).

```sh
git worktree add --detach ../hepta-runtime-history SOURCE_COMMIT
git show SOURCE_COMMIT:ORIGINAL_PATH
```

Restoring the complete snapshot keeps original relative paths together for
historical reproduction. A shallow checkout must explicitly fetch the required
history first, for example with `git fetch --unshallow origin`.

## Verify original retention

```sh
python3 -B scripts/verify_rust_consolidation.py
```

The verifier checks ancestry, original trees, every blob/mode/size and complete
directory or exact-file selections. Missing rows, duplicate records, changed
originals and retired files still in the reviewed tree are errors. Immutable
inventory continuity also rejects deleting an entire manifest or shrinking its
required source inventory. Missing history/objects fail explicitly; verification
does not fetch or execute historical code.

Keep the inventory checkpoints in ancestry with merge commits or fast-forwards.
Source retirement reduces the current checkout and new shallow clones. Full Git
history deliberately retains the original objects and their storage cost.
