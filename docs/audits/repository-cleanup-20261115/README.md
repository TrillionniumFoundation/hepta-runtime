# Repository cleanup audit — 2026-11-15

## Result and scope

The audit started from `a404d4f1bf540fb94f65ef3707145eed07eef183` (tree
`0984578f72d2a4291b5954d1fd93914dc116e3e6`) and continued from
`151d74efcf252314e57cb6e1a5542401ff68f362` and
`ad7cabe9ccd3a56f19bbf9d26c2df9de48099f97`. It covers every tracked path, source-language roles, the Rust module
graph, Cargo declarations, embedded helpers, CI/deployment callers, actual
evidence-reader paths and original-source retention.

| Metric | Original baseline | Current tree |
| --- | ---: | ---: |
| Tracked files | 17,673 | 5,306 |
| Tracked-file bytes | 1,864,002,891 | 161,913,642 |
| Python files | 1,986 | 590 |

**12,380 historical files / 1,705,926,359 original bytes** have
left the current tree, including **1,397 Python
files**. New audit/verification files account for the difference between gross
retirements and net file counts. These are tracked-file measurements, not Git
compressed-pack sizes or GitHub Linguist percentages.

The internal review removes eleven superseded entrypoint/registry files and
consolidates two identical Rust rules: safetensors dtype widths and ECMAScript
whitespace. Four Rust files change; the retained function bodies are byte-identical
to their originals. The other 604 core inputs, Cargo, model workers, cloud-compute
helpers and all embedded reference inputs remain unchanged. Required non-Rust
interfaces, independent references and frozen source contracts remain in use.
A final reader-based pass also retires 321 completed audit/evidence files while
preserving all maintained runtime and test inputs from `93d43067`.

## Why the repository contains other languages

| Retained Python scope | Files | Purpose |
| --- | ---: | --- |
| `src/` | 17 | Rust-embedded runtime helpers |
| `workers/` | 25 | Model computation workers and worker tests |
| `tools/cloud-compute/` | 24 | Colab/Kaggle routing, recovery and offline tests |
| `tools/x230/` | 62 | Maintained qualification harnesses and frozen sampler inputs |
| `deploy/` | 74 | Operator, gateway, installation and recovery interfaces |
| `tests/` | 243 | Regression tests, independent references and fixtures |
| `scripts/` | 45 | Qualification, evidence admission and independent differential oracles |
| `experiments/` | 58 | Independent model studies and reproducible evaluation |
| `qualification/` | 1 | Frozen standalone Rust study verifier |
| `docs/` | 39 | REA reference bundles and original qualification fixtures |
| `.github/` | 2 | Current browser qualification bootstrap and tests |
| Total | 590 | |

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

The remaining 39 Python files under docs preserve REA reference and qualification
inputs: 37 have direct manifest/hash bindings, and two are original umask022
launch fixtures whose commands, binary pins and environment remain documented
in their qualification packages. The final pass retires six completed audit
snapshots and four historical publisher copies; current public recomputation
uses the maintained `tools/` code.
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
| Superseded acceptance and X230 publisher entrypoints/registries | 11 | 191,032 |
| Completed Rust audit validation and A27 publisher copies | 321 | 8,886,048 |
| Total | 12,380 | 1,705,926,359 |

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
That directory review changed no active runtime implementation. The subsequent
internal review shares two identical pure rules across their existing Rust callers,
removing 38 lines and adding seven without changing parser budgets or interfaces.

The three remaining byte-identical active Python pairs have specific contracts:
the DC V10 acceptance aliases must match under an existing test; the October 31
RSS helper is opened adjacent to its caller with `O_NOFOLLOW` and a fixed hash;
the October 28 and A27 samplers have separate pinned caller paths. Replacing them
with wrappers would alter those source/admission contracts. The independent Rust
weightspace study also retains its exact frozen compilation inputs.

## Original-source retention

[Six repository history manifests](../../../archives/repository-history/README.md)
and [42 Rust variant manifests](../../../archives/rust-branches/README.md) preserve
every original source identity. The continued review retains all previous
**15,065 original rows**, adds **2,045 exact original file rows**, and changes only
the allowed storage disposition of 119 historical source/documentation rows.
Its 70 Markdown links and three directory references point to exact original
commits. Historical JSON provenance, failure status and evidence pins are unchanged.

Inventory continuity now binds all **48 manifests / 17,442 original source rows**
to the immutable [b81d1b37 checkpoint](https://github.com/TrillionniumFoundation/hepta-runtime/commit/b81d1b3780eb4a01f0ba0f67b63d52140285538b).
It must survive as an ancestor: use a merge commit or fast-forward, without
squashing/rebasing the checkpoint history. The v2 schema additionally supports
precisely named individual files. Removing a required manifest, shrinking its
file list, changing an original blob or reintroducing a retired file must fail.
The package check covers both retired directories and exact file names.

## Validation

The previous directory review confirmed 608 unchanged core inputs. The internal
review permits only the four listed Rust helper edits: **604 core inputs remain
unchanged**, including Cargo, config, model workers, cloud-compute tools and the
patched decoder. All 474 runtime source paths remain present. All **214 Rust include references / 141 unique
embedded inputs** remain present and unchanged. Each of the previous directory continuation's
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

## Internal review and current qualification

The final pass inspected 2,853 Rust function bodies and 232 maintained Python
files containing 3,798 function definitions. Repeated state machines with
different durable namespaces, externally visible library APIs and immutable
oracle inputs are retained. The two shared Rust predicates preserve the original
22 dtype mappings and all 25 ECMAScript whitespace scalars. An independent Node
trim comparison checked all 1,112,064 Unicode scalars, including BOM, NEL and MVS.

Five obsolete test entrypoints have no live code/workflow/Markdown callers.
The retained owner-fence replay harness keeps all 22 original checks and four
additional replay checks. Three prior fairness publishers and two registries
have current successors; the fixed-path A25 publisher only rebuilt its historical
failed campaign. Historical instructions point to exact Git originals because
newer output schemas cannot stand in for original publication bytes.

After deletion, 55 existing V9/V10 safety and contract tests pass without any
attempt to open a retired file. Repository Hygiene now runs those exact pinned
successor suites in addition to its existing gates. The 34 custody regressions
also pass. The REA source projection initially failed after the Rust edits;
canonical regeneration changed exactly nine identity scalars, followed by 29
passing ledger tests and a passing mapping check. All 229 tool rows stay OPEN,
with zero qualified tools; strict parity still refuses as expected.

The internal-review manifest adds eleven exact original rows while preserving every one
of the earlier 46 manifests and 17,110 original rows. Original failures, receipts,
qualification input lists and publication manifests keep their original bytes.
Full exact-source Rust validation is required for the helper consolidation.
See the attached GitHub workflow, not an ancestor run, for its terminal outcome.

## Completed audit and publisher follow-up

A further exact-reader review corrected the previous retention classification
for ten documentation Python files. Six were one-shot Rust audit snapshots;
four were A27 private-archive publishers, including one exact copy of a retained
tools implementation. They are not inputs to the current public recalculator.

The complete Rust `validation/` subtree (317 files / 8,759,153 bytes) now lives at
its exact original Git revision, together with all original failed, interrupted,
partial and successful attempts. Four publisher source files add 126,895 bytes
of retirement. The actual public A27 recomputation still passes 2,176 operation
rows and 32 cells. Its original overall adoption decision remains false, and
every individual gate outcome is unchanged. There is no new workload or renewed
qualification. All public data, receipts and manifests remain intact;
six current Markdown explanations link back to the original source packages.

This follow-up preserves every one of the preceding 47 manifests and 17,121
original rows. It adds 321 complete original file identities. All 608 core inputs,
all 214 embedded references / 141 unique inputs, and maintained test/fixture inputs
are unchanged from the Rust-validation reference commit `93d43067`. Only the
custody verifier's immutable checkpoint literal changes among maintained scripts.
The current branch and HIA custody inventories outside `validation/` remain
byte-identical. After real deletion, REA mapping and 29 ledger regressions pass,
with zero reads of retired paths. Original REA parity remains 229 OPEN / 0 qualified.

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
