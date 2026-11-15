# Repository cleanup audit — 2026-11-15

## Scope and result

Baseline: `a404d4f1bf540fb94f65ef3707145eed07eef183`, tree
`0984578f72d2a4291b5954d1fd93914dc116e3e6` on main. The complete tracked inventory
contained **17,673 files / 1,864,002,891 bytes**, including **1,986 Python files**.
The audit combines complete path/blob/mode accounting, Cargo/module reachability,
embedded-helper callers, CI/deployment dependencies and historical source custody.
It is a repository cleanup audit, not a complete security or runtime qualification.

Hepta Runtime is a Rust application with active Python and Java engine boundaries.
Historical experiments and repeated source snapshots inflated the checkout and
language counts. The cleanup removes **9,923 historical files / 1,528,547,962 bytes**
from the current tree, including **1,247 Python files**, with every original
preserved in reachable Git history. It also consolidates a genuinely duplicated
bridge implementation. [inventory.json](inventory.json) records exact metrics.

## Language and dependency findings

| Baseline Python area | Files | Bytes | Role |
| --- | ---: | ---: | --- |
| Whole repository | 1,986 | 41,557,159 | Production, tests and historical copies combined |
| tools/x230 | 1,200 | 27,249,379 | Hardware experiments, source snapshots and active qualification harnesses |
| docs/qualification | 213 | 5,065,948 | Frozen producer/reference code and evidence |
| tests | 249 | 4,343,496 | Maintained regressions and independent references |
| deploy | 74 | 1,368,109 | Operator/gateway/install interfaces |
| scripts | 44 | 1,041,296 | Qualification, evidence admission and differential oracles |
| experiments/weight | 58 | 717,267 | Separately scoped model research |
| tools/cloud-compute | 24 | 476,134 | Colab/Kaggle dispatch, recovery and offline CI |
| workers/weight | 25 | 259,206 | Actual model computation and tests |
| src/mcp/runtime | 17 | 237,180 | All seventeen are live Rust include inputs |

The static module graph reaches **all 429 src Rust files** from the library and
three binary roots, with no unresolved external modules or orphan paths; 208 are
named `*_tests.rs`. Cargo resolves two examples and fourteen integration tests.
All **474 src files** remain unchanged.

The 17 Python helpers implement document parsing/calculation/security,
descriptor-relative and binary file operations, metadata preservation, remote
search, services, operator processes, persistent streams, PTYs and checkpoints.
See [documents.rs](../../../src/mcp/runtime/documents.rs),
[binary.rs](../../../src/mcp/runtime/binary.rs),
[search_jobs.rs](../../../src/mcp/runtime/search_jobs.rs) and
[terminal.rs](../../../src/mcp/runtime/terminal.rs). Removing them breaks Rust
`include_str!` inputs or the corresponding routes. Roughly 70 KB of Python also
remains inside jobs.rs for macOS/operator paths; Linux isolated system_jobctl
serves a different boundary.

Rust's native weight client supplies transport, not model computation, so the
Python worker remains necessary. Nine Java sources remain active revision-specific
Ghidra/JADX bridges. JavaScript/TypeScript, C, APK and JAR fixtures support native
parsers/provider/observer regressions. The 134-file fixture directory (7,241,333
bytes) and pinned independent Node REA reference scripts remain unchanged.

## Concrete cleanup

| Current-tree retirement | Files | Original bytes |
| --- | ---: | ---: |
| Historical material in 27 complete roots | 9,708 | 1,521,911,966 |
| Duplicate branch source files under archives/rust-branches/*/files | 215 | 6,635,996 |
| Total | 9,923 | 1,528,547,962 |

The [complete history manifest](../../../archives/repository-history/20261115.json)
records every original path, blob, mode and length. Its roots cover historical
source recovery, older HIA review artifacts, November 3–6 and selected A-series
X230 campaigns, and seven self-contained old REA/DC evidence collections. Original
successes, failures, partial attempts and raw outputs retain their exact bytes and
classifications. No Git history or protected HIA branch was rewritten.

Forty-two [Rust variant manifests](../../../archives/rust-branches/README.md)
preserve their original inventories and previous dispositions. They retain 5,107
pure history-only rows and 118 exact original files in the current tree. Nineteen
additional Markdown originals remain in history while explicitly pinned live
versions update only evidence links;
33 historical already_identical rows also require original blob availability.
The verifier checks 5,277 original branch-source rows in total.

The October 28–30 X230 suites remain in CI. The complete A27 subtree remains:
run_reuse_throughput.py loads its resource sampler by a relative path and pinned
hash. The v9-harness-drafts baseline remains because current workflows/tests pin
and read it. Current REA mapping inputs and independent fixtures remain.

### One bridge source

The two 467-line bridge implementations were byte-identical. The standalone
`deploy/readonly-bridge/bridge.py` stays unchanged, SHA-256
`69efe77eb0620648fcd3c6fd545ae162c9b9e62e99bd2acf249f03e12443918b`.
`deploy/chatgpt_mcp_bridge.py` becomes a short fixed-path loader in the original
module namespace. This preserves CLI/import/global-patching behavior without a
symlink or duplicate maintained implementation. Two focused regressions cover
patched module globals and an independently copied standalone deployment file.

### Documentation and ongoing checks

README now presents actual Hepta ownership and current directory roles. Repeated
Octofs installation/marketing content is replaced by a link to the imported
upstream revision; attribution and source copyright remain. CONTRIBUTING uses
the pinned Rust/nextest process-isolated workflow.

**345 existing Markdown links** now point to exact original GitHub evidence paths;
two additional plain v9 paths became pinned links. Historical provenance JSONs
remain unchanged. The new Repository Hygiene workflow checks archive custody,
refusal regressions, both bridge entries, retained X230/REA consumers and Cargo's
source-file closure. Existing workflows remain unchanged.

## Production identity preserved

Independent byte/mode comparison covers **608 inputs** across src, vendor,
Cargo.toml, Cargo.lock, config, workers and tools/cloud-compute. There are no
changes or extra files in those scopes. Other deployment code and service files
remain unchanged except for the bridge entry. The standalone weightspace study
and existing HIA refs remain preserved.

Cargo originally listed 6,728 package paths /846,236,238 existing-file bytes.
Historical retirement reduces the list without changing Cargo metadata; current
values are recorded in inventory.json. The list is not a supported release
contract: ordinary registry packaging omits the local ruzstd patch and nested
crate. The private Git-checkout release remains the documented build path.

A packaging-only Cargo edit was considered, then reverted during review:
weight_guard_journal.rs embeds the complete manifest in persistent request
identity. Even changing exclude/publish metadata changes journal selection after
rebuilding. **Cargo.toml and Cargo.lock stay byte-identical.** A future packaging
redesign requires a separate identity-compatibility assessment.

REA qualification intentionally hashes a broader source selection including
tools paths. The smaller tree has a new qualification source identity. No old
source pin was changed and no old receipt was represented as a current pass.

## Validation and limits

[validation.json](validation.json) records actual observations. Sixteen real-Git
tests cover exact recovery, invalid tree/blob/mode/path, unknown/non-ancestor
source, shallow history, missing original objects, incomplete/duplicate inventories
and old-schema compatibility. The complete candidate verifier checks 149 merged
Rust refs,42 branch manifests,5,277 original paths and all9,708 historical paths.
Independent diff verification accounts for exactly9,923 deletions with no extras.

Both all-feature and no-default-feature target checks and formatting passed on
the unchanged production inputs before a local environment reset. Clippy then
failed because the shared disk was full; that failure is not a code-quality pass.
The candidate was reconstructed from the exact original commit and rechecked;
no unverifiable temporary commit identity is used as the published source.

Fresh reconstructed bridge checks pass9 unit,16 stdio and1 legacy-import test.
The4 HTTP tests fail both before and after because local AF_UNIX creation is
denied. Unchanged X230 suites previously yielded88 passes and10 AF_UNIX setup
errors. REA mapping passed;362 regression tests yielded361 passes and1 missing
/proc child-observation error. These are failed local suites, not complete passes.
GitHub's exact-commit Repository Hygiene workflow runs those host-dependent paths
independently; consult the run attached to the published commit for its result.

No full runtime-suite pass, deployment, HIA activation, model improvement or
performance improvement is inferred from cleanup/source custody alone.

## Recovery

```bash
git worktree add --detach /your/isolated/hepta-runtime-history \
  a404d4f1bf540fb94f65ef3707145eed07eef183
python3 scripts/verify_rust_consolidation.py
```

Use the cleanup checkout's verifier and the separate historical tree for original
reproduction. Missing history/objects require explicit fetching; the verifier
never fetches or executes archived code. The change reduces the current tree and
new shallow checkouts. Full Git clones retain the original objects and storage
cost; Git history was deliberately preserved.
