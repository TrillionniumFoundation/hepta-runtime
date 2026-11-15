# Repository cleanup audit — 2026-11-15

## Result and scope

The audit started from `a404d4f1bf540fb94f65ef3707145eed07eef183` (tree
`0984578f72d2a4291b5954d1fd93914dc116e3e6`) and continued from
`151d74efcf252314e57cb6e1a5542401ff68f362`. It covers every tracked path, source-language roles, the Rust module
graph, Cargo declarations, embedded helpers, CI/deployment callers, actual
evidence-reader paths and original-source retention.

| Metric | Original baseline | Current tree |
| --- | ---: | ---: |
| Tracked files | 17,673 | 5,636 |
| Tracked-file bytes | 1,864,002,891 | 170,882,966 |
| Python files | 1,986 | 609 |

**12,048 historical files / 1,696,849,279 original bytes** have
left the current tree, including **1,378 Python
files**. New audit/verification files account for the difference between gross
retirements and net file counts. These are tracked-file measurements, not Git
compressed-pack sizes or GitHub Linguist percentages.

The current Rust runtime, model workers and cloud-compute inputs keep their
original bytes. No additional safely removable active implementation was found
after the final dependency and source-role review. That conclusion does not
classify required non-Rust interfaces or independent reference programs as dead
code.

## Why the repository contains other languages

| Retained Python scope | Files | Purpose |
| --- | ---: | --- |
| `src/` | 17 | Rust-embedded runtime helpers |
| `workers/` | 25 | Model computation workers and worker tests |
| `tools/cloud-compute/` | 24 | Colab/Kaggle routing, recovery and offline tests |
| `tools/x230/` | 66 | Maintained qualification harnesses and frozen sampler inputs |
| `deploy/` | 74 | Operator, gateway, installation and recovery interfaces |
| `tests/` | 248 | Regression tests, independent references and fixtures |
| `scripts/` | 45 | Qualification, evidence admission and independent differential oracles |
| `experiments/` | 58 | Independent model studies and reproducible evaluation |
| `qualification/` | 1 | Frozen standalone Rust study verifier |
| `docs/` | 49 | Currently bound reference bundles and reproducible audit evidence |
| `.github/` | 2 | Current browser qualification bootstrap and tests |
| Total | 609 | |

All **17** Python helpers under `src/mcp/runtime` are actual Rust embedded inputs.
They implement configured document, worksheet, binary-file, metadata, process,
service, terminal, stream and checkpoint operations. The Python model worker
performs model computation; the native Rust client supplies transport and
ownership. The **24** Colab/Kaggle files remain active dispatch/recovery tools and
offline tests. Nine Java sources serve revision-specific Ghidra/JADX bridges.
JavaScript/TypeScript/C fixtures and Node reference implementations provide
independent parser, provider and differential checks.

All **429 `src/*.rs` files** are reachable from Cargo roots and explicit module
paths. All **37 dependency declarations**, including target/development entries,
have actual source uses. There are no unresolved module paths or unused whole
Rust source files in that graph. `Cargo.toml`, `Cargo.lock` and `vendor/ruzstd`
remain unchanged; the manifest participates in persistent request identity.

The remaining 49 Python files under docs are individually accounted for:
39 belong to currently bound REA reference bundles, four to A27 public
recalculation/publication evidence and six to the current Rust integration audit.
The 58 model-study scripts and the frozen standalone study verifier remain
reproducible research inputs. [inventory.json](inventory.json) contains their
per-root paths and binding/reader reasons.

## Changes made

| Retirement wave | Files removed | Original bytes |
| --- | ---: | ---: |
| Initial historical collections and branch-source copies | 9,923 | 1,528,547,962 |
| Remaining October 28 X230 evidence | 80 | 54,051,755 |
| Continued historical directory review | 2,039 | 114,186,765 |
| Expired workflows/script and standalone harness snapshots | 6 | 62,797 |
| Total | 12,048 | 1,696,849,279 |

The continued directory review removes forty complete X230, DC and REA history
roots, the withdrawn native checkpoint prototype and an obsolete source recovery
bundle. The checkpoint prototype was never compiled into the current runtime;
its failed automatic-continuation result remains a failure in the original.
The two expired workflows only targeted branches already retired in the earlier
Rust consolidation. Their observed historical runs were terminal; source cleanup
does not operate any hardware or service.

The first cleanup replaced one of two identical 467-line read-only MCP bridges
with a fixed-path loader while retaining the standalone implementation unchanged.
Its import/global-patching and standalone deployment behavior has focused tests.
The continued review changes no active runtime implementation.

The three remaining byte-identical active Python pairs have specific contracts:
the DC V10 acceptance aliases must match under an existing test; the October 31
RSS helper is opened adjacent to its caller with `O_NOFOLLOW` and a fixed hash;
the October 28 and A27 samplers have separate pinned caller paths. Replacing them
with wrappers would alter those source/admission contracts. The independent Rust
weightspace study also retains its exact frozen compilation inputs.

## Original-source retention

[Four repository history manifests](../../../archives/repository-history/README.md)
and [42 Rust variant manifests](../../../archives/rust-branches/README.md) preserve
every original source identity. The continued review retains all previous
**15,065 original rows**, adds **2,045 exact original file rows**, and changes only
the allowed storage disposition of 119 historical source/documentation rows.
Its 70 Markdown links and three directory references point to exact original
commits. Historical JSON provenance, failure status and evidence pins are unchanged.

Inventory continuity is bound to an immutable cleanup checkpoint in the verifier.
It must survive as an ancestor: use a merge commit or fast-forward, without
squashing/rebasing the checkpoint history. The v2 schema additionally supports
precisely named individual files. Removing a required manifest, shrinking its
file list, changing an original blob or reintroducing a retired file must fail.
The package check covers both retired directories and exact file names.

## Validation

Independent comparison confirms **608 unchanged core inputs**, including all
474 current runtime source inputs, Cargo, config, model workers, cloud-compute
tools and the patched decoder. All **214 Rust include references / 141 unique
embedded inputs** remain present and unchanged. Each of this continuation's
2,045 deletions matches its original path/blob/mode/size, with no unlisted deletion.

The actual local checks include **34 real-Git custody tests** (23 previous and 11
new v2 cases), **23 DC receipt/ledger regression tests**, REA mapping verification
and the independent deletion/source comparison. Four existing evidence consumers
were traced while executing; none opened any retired path. Their original
qualification results remain unchanged: REA mapping integrity passes while its
parity gate stays OPEN, and DC receipt integrity passes while full replacement
qualification stays false.

Repository Hygiene now also runs the three retained DC receipt suites and checks
their input paths. The full runtime workflow still covers pinned Rust 1.95.0,
both feature configurations, Clippy, process-isolated nextest and release builds.
Read the GitHub run attached to the exact published commit for its terminal result;
an ancestor's successful run does not qualify a new commit.

[validation.json](validation.json) retains previous failed local checks, hosted
observations, exact source identities and the current review. Prior AF_UNIX,
process-observation and disk-space failures remain recorded. Cleanup alone does
not establish a new runtime, HIA, model-quality or deployment qualification.

## Recovery

```sh
git worktree add --detach ../hepta-runtime-history SOURCE_COMMIT
git show SOURCE_COMMIT:ORIGINAL_PATH
python3 -B scripts/verify_rust_consolidation.py
```

Select `SOURCE_COMMIT` from the manifest containing the path. Use the separate
historical tree to reproduce original relative paths and the current verifier to
check retention. Missing history requires explicit fetching. Full Git clones keep
the historical object storage; this cleanup reduces the current tree and shallow
checkouts without rewriting history.
