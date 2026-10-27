# A52: owned metadata cohorts and durable owner recovery

**Candidate status: Draft. `performance_adopted: false`.** This evidence checkpoint is dated 2026-10-26. A52 combines the owned archive-cohort lifecycle, complete serial page verification and durable-owner changes in one 173-input source tree. That combined tree and its release ELF passed fresh X230 qualification. The same release then passed the three native X230-to-AI395 recovery cases, and an isolated copy of the qualified source passed the original fifteen Python CI test commands. Throughput, CPU and memory adoption remain pending the fixed new comparisons.

The [evidence index](evidence-index.json) lists the exact retained file sizes and SHA-256 values, completed observations and remaining gates.

## Acceptance status at this checkpoint

| Gate | Recorded result | Evidence |
|---|---|---|
| Combined Rust qualification | All six stages exited 0; 1,305 top-level tests passed, 23 ignored, no failures | [Qualification](qualification.original.json), [entry](entry.original.json), [worker](worker.original.json) |
| New lifecycle and owner regressions | All 31 named new tests have an original `... ok` line | [New-test coverage](new-test-coverage.json) |
| Native owner recovery through the real Rust MCP/SSH/systemd path | Three cases passed; original job reused without another launch in each case | [Native recovery summary](native-owner-summary.original.json) |
| Original Python CI gates on X230 | Fifteen test commands exited 0; 284 reported tests, 0 reported skips; separate dependency precheck also passed | [r02 entry](control-gates-r02.entry.original.json), [r02 worker](control-gates-r02.worker.original.json) |
| Qualified source publication mapping | Complete 173-path expected Git blob map prepared; actual changed source bodies match the tested map | [Publication manifest](compiler-publication.original.json), [expected Git map](a52-expected-git-blob-map.json) |
| Fixed small comparison | Running; result and adoption decision remain pending | [Frozen protocol](../../../../tools/x230/a52/small-archive-a52-r01.protocol.json) |
| Fixed large C1/C4 archive comparison | Not executed at this checkpoint | No A52 performance result claimed |
| New eight-job native concurrency acceptance | r01 executed and failed; diagnosis remains open | [Actual operator outcome](native-concurrency-r01.operator-outcome.json); the [9/9 local implementation selfcheck](native-concurrency-selfcheck.original.json) remains a separate layer |
| Earlier full r07 native acceptance: eight stages and six-host pool | Remains separately open | The explicit two-host recovery profile has its own narrower admission and result |
| GitHub CI on the exact published combined source head | Pending publication and that head's actual CI result | X230 qualification and Python results retain their own identities |

The original test log contains top-level results of 18, 1,279 and 8 passes, totaling 1,305. Its two nested one-test subprocess results are already exercised by the main suite and are not added again. The 23 ignored tests remain reported as ignored. The test-log SHA and all original result lines are retained in the qualification and coverage records.

## Product changes in the qualified combination

### Owned leader work and asynchronous followers

For a hinted large archive, an admitted page query registers its cohort and transfers its owned semaphore permit before the member becomes visible. A unique `Completion` guard exists before registry exposure and before submission of the blocking work. The leader submits the shared observation; followers await their private results asynchronously and do not submit another blocking observation. An unhinted singleton keeps the existing independent observation path.

The original work owns every admitted group permit. Cancelling or timing out a caller drops its waiter while the original queued or running work retains custody. The finalizer releases permits after observation scopes, locks and original-reader joins have ended, then publishes completion and wakes waiters. An unsubmitted or cancelled queued closure destroys its captures before finalization. Completion removes only its own registry identity, so an older group cannot erase a newer group for the same root.

Each reply has persistent terminal state. A waiter enables its notification before inspecting that state, covering completion before its first poll and completion between checking and waiting. The group's minimum original deadline stays fixed even when its earliest caller cancels. Expired work cannot begin a new observation or publish a late success. The existing eight-query admission bound, one-millisecond collection window and absolute product deadline remain in force. These lifecycle properties are covered by 17 new regressions, including cancellation, queued-work cleanup, unwind, poison, reply coverage and notification ordering. Source: [archive batching](../../../../src/mcp/runtime/request_archive_batch.rs), [owned lifecycle tests](../../../../src/mcp/runtime/request_archive_owned_tests.rs), [actual test coverage](new-test-coverage.json).

### Complete serial page verification

`verify_page_members` uses the existing `verify_members` serial kernel. A fresh page cohort still verifies the complete original namespace and every bounded original record, including records outside the requested page. It retains private-file checks, descriptor and pathname stamps, identity/coverage checks, deadline checks and final namespace fences. The caller's store guard remains held for the original observation.

The bounded parallel kernel for online usage snapshots remains available through `verify_usage_members`. A52 does not introduce a content lease, skip untouched-looking records, accept an old metadata snapshot as current, change page selection, or extend a deadline. The serial choice is a candidate CPU-cost improvement whose effect must be measured in the new comparisons. Source: [archive content verification](../../../../src/mcp/runtime/request_archive_content.rs).

### Two durable owner files and one directory barrier

The production supervisor holds the original lifetime lock and refuses surviving owner/terminal publication names before launching work. It creates `owner-intent.json` and `started.json` separately with exclusive, no-follow creation. Each file is written, flushed, file-fsynced and closed. One fsync of the already pinned job directory follows both completed files. The business child can be submitted only after that directory barrier succeeds.

A write, flush, file-fsync, close, create or directory-fsync failure stops before business submission. A surviving empty or partial owner name remains a no-replay tombstone. Existing request identity, launch nonce, exclusive ownership and terminal publication/witness rules remain in force. Seven owner-publication regressions cover the order, each failure boundary, existing names/lock, interruption and fresh-interpreter same-key reconciliation. Source: [production jobs and supervisor](../../../../src/mcp/runtime/jobs.rs), [publication tests](../../../../src/mcp/runtime/jobs_owner_publication_tests.rs).

### Stable malformed owner metadata stays unknown

Status reading first obtains a bounded, stable snapshot from the pinned private job directory. Missing, empty, partial or non-object `started.json` content cannot establish a live original owner. Reconciliation retains the original job identity, reports an unknown/unconfirmed owner outcome as appropriate, and sets `automatic_retry: false`; the surviving request/owner tombstones prevent a second launch.

This classification is limited to safely observed absent or malformed binding content. Unsafe paths, symlinks, nonprivate files, changed metadata and read failures still fail closed. A mismatched PID/birth/UID or systemd invocation cannot be promoted to a running original owner. A valid original terminal receipt and matching witness retain precedence over torn owner metadata, while the existing legacy terminal-receipt contract is preserved. Seven new tests exercise the production status code and same-key behavior. Source: [owner metadata tests](../../../../src/mcp/runtime/jobs_owner_metadata_tests.rs), [production status implementation](../../../../src/mcp/runtime/jobs.rs).

## Fresh combined qualification

The qualification started from the actual A51 tested source and overlaid the ten A52 product/test files. It ran Rust 1.95.0 with offline/locked dependencies, two Cargo jobs, two Tokio workers, two Rust test threads and explicit stage umask `022`. Metadata tracing was disabled. The six original stages were `format`, `fmt-check`, `clean-package`, `clippy`, `test` and `release`; Clippy included all features and targets with `-D warnings`.

Every stage executed once after its own clear host admission snapshot. The original worker received its GO permit, retained its pidfd and original birth/session identity, and was reaped with raw wait status 0 after its process group was quiet. No cleanup signal was required. The prepared source map is retained separately from the formatted tested map; `source_tested` equals `source_after`. Both test and release ELFs have original fresh compiler-artifact evidence. Sources: [qualification protocol](../../../../tools/x230/a52/qualification.protocol.json), [entry](entry.original.json), [worker](worker.original.json), and the six original [stage-gate receipts](qualification-stages/).

| Fixed identity | SHA-256 |
|---|---|
| A52 qualification report | `a332bf0dacae308f6a13fbe5f2037c81e8dac10765dc6c13c65a4ad8e69ea533` |
| A52 entry report | `d7139b6625ddf730d76ad1c2beec535538407c09075b76adf70099d5738aae3b` |
| A52 worker report | `b2228ec33b2ce52703c2734645ab6179716424f347c6bcbe60eeeb95e1a5ecd1` |
| Release ELF | `96f8d2efed08442b5c22e85f7dfdd0043a14364d9d364432edfdf4df3f62f268` |
| Main test ELF | `d452742553be55455c1807d0332e3a40fb655816dfcfd6a94782445c4f9cf988` |
| Prepared source map, sorted compact JSON without newline | `dc87085073c0501cdb29b296bc78975aca8475b6894058b1a32328252adeee69` |
| Tested source map, sorted compact JSON without newline | `93c0c3567734d9d326d88b20b2a94be684a12b17449756e8e37495db9dc36624` |
| Original full test log | `136fcc8935a500ed762906612affd611b4342c2a88cfa766d8682c4754ac3ba3` |

## Actual native recovery across X230 and AI395

The qualified Rust release on X230 called the real native `process_start` path over an explicitly admitted direct SSH profile to the production Python supervisor under AI395's user systemd. Detached fallback was disabled. An independent operator observation bound the remote UID, machine, boot, home and Python identity; the fresh profile and each helper session had to match that binding.

All three fixed cases passed on one new fixture each, with no replacement key or automatic retry:

| Case | Injected boundary and observed recovery |
|---|---|
| `controller-loss` | The original Rust MCP controller was killed after launch. A new controller observed the original job still running and reconciled the same key to that job. The original owner subsequently published confirmed success with complete durable stdout/stderr. |
| `reply-loss` | The original launch reply was deliberately left unconsumed before controller loss. Reconciliation recovered the original running job without another launch. The original owner subsequently published confirmed success with complete durable stdout/stderr. |
| `owner-loss` | The bound original remote owner received one pidfd-bound SIGKILL while its business child was live. The recovered status remained `finalizing`, `outcome: unknown`, nonauthoritative and without a confirmed terminal publication; automatic retry was false. |

Each case recorded one durable synthetic business append, `same_key_reused: true`, `same_key_retried_launch: false` and complete bounded remote cleanup. Original local controller and custody-SSH children have their own actual wait4 receipts. Remote owner/business completion uses held pidfds and original durable metadata/output evidence; the remote observer does not claim to wait4 processes it did not create. The observer has no business-launch operation. Original input, owner metadata and same-key identity fences were checked around reconciliation. [Original native recovery summary](native-owner-summary.original.json).

The [full recovery report](native-owner-report.original.json) is 567,710 bytes at SHA-256 `8884100c857cdea4da68f25bb9a399414e36873b72d94b8a876f76c592d95e51`. The summary is 14,420 bytes at `1803b61e9cd6495f30c6533508af3fa6f8e27bcaebbf3555416a140da3820f71`. Its frozen plan is `827bd77b4787a9cb9c9815084a64c747e32a5659edb1db19cd7ba8f35b4a2682`. The retained [complete 88-file evidence export](native-owner-evidence.original.json.gz) is 488,046 bytes at `866c49e8791d7c65fb424f37818082e2f03d2a7ecb6297959f5580306d477bde`; every contained file's bytes and SHA were rechecked after export. The summary binds that export, its original report, the release ELF and each case's results.

These are process-loss and same-key recovery observations for the bounded synthetic fixture on these two machines. They establish no physical power-loss result or general exactly-once guarantee for arbitrary external effects. The older six-host pool/eight-stage native acceptance and the new eight-job concurrency acceptance remain separate gates.

## Original Python CI gates on the qualified source

The r02 run copied the actual 173 qualified compiler inputs into a new private test directory and added the 43 reviewed original Python-gate dependencies. Two paths overlapped identically, producing 214 files. It executed the fifteen original commands through `/usr/bin/python3`, plus one separately counted dependency precheck. Original test timeouts and assertions were preserved; no Rust rebuild, remote call or service change was part of this gate run.

All fifteen test commands passed: **284 reported tests and 0 reported skips**. The worker had no unexecuted commands. Its parent retained original custody through raw waitpid and a quiet group; every final stdout/stderr receipt matched the corresponding passed command, and qualified-source, copy and original-input fences passed. [r02 entry](control-gates-r02.entry.original.json), [r02 worker](control-gates-r02.worker.original.json).

The earlier r01 attempt remains a failure with zero tests executed: its pre-worker fence compared a plain file receipt to an enriched artifact dictionary containing compiler evidence. r02 corrected only that comparison to exact `path`, `bytes`, `sha256` and complete stat9 fields, and used a fresh output directory. Compiler qualification checks, test commands and custody stayed unchanged. The original [r01 failure receipt](control-gates-r01.entry.original.json) is retained; it is not counted among the successful tests.

| Python gate record | SHA-256 |
|---|---|
| r02 entry | `5a491b35fc09ea60fa354279c817efa2aef5db751a07c4c9e38fa3b1c1ede50c` |
| r02 worker | `000df45159cc3b677aa9050a08098ef4b5b29798b7dcb3d1c7a14abbd3275873` |
| Frozen r02 runner | `df6f52f06d90fec89c57eda730d9429352493fa26368cccacd3ef3aefd557b14` |

## Exact source publication

The [publication manifest](compiler-publication.original.json) composes A50 commit `17d01dda7bd75b9bb9c0c5f1f90f84bddbfb54cb`, the actual A51 tested map and the actual A52 tested map. It records 15 A50-to-A51 changes, ten A51-to-A52 changes and 20 final changed compiler inputs relative to A50. Relative to the expected parent containing only the nine CI fixture fixes, the combined candidate needs twelve source updates: the ten A52 files plus A51's `request_archive_index.rs` and `request_metadata_trace_tests.rs`.

Each final changed body was checked against its tested SHA-256 and used to calculate its actual Git blob SHA-1. A51 trace files came from the qualified A51 export; A52 files came from the qualified post-format A52 export. The six A52 files changed by rustfmt must never be replaced with the prepared overlay. The [qualified source export](qualified-source-export.original.json.gz) preserves the ten A52 bodies, stage evidence and named test coverage. The [tested source map](a52-tested-source-map.json) retains all 173 compiler-input SHA-256 values.

The [expected Git blob map](a52-expected-git-blob-map.json) covers all 173 compiler inputs: 20 changed bodies were rehashed for this composition, and 153 unchanged blob IDs were inherited from the pinned complete A50 map. This composition does not claim a new read of all 153 unchanged bodies. A captured complete GitHub commit/tree must match the full expected path set and blob map before the published tree is marked verified. The retained preparation manifest correctly has `final_a52_github_tree_verified: false` until that separate check is performed.

## Diagnostic context and remaining adoption gates

[A51](../a51/README.md) captured all 20 measured diagnostic calls successfully, including four full C4 cohorts. Its initial index kickoff still returned the original deadline error, so that diagnostic retains `product_passed: false`. It did not reproduce the earlier C4 failure and provides no causal proof that blocking-pool scheduling caused it. The trace motivates further measurement of complete original-verification cost; it is not an A52 speedup result.

The fixed small A52 comparison still requires all 8,192 measured and 8,848 total calls across both opposite-order ABBA blocks. Its original two workers, 300-second block budgets, product/client deadlines, full call coverage, CPU quantization and preregistered wall/CPU/RSS thresholds remain unchanged. The fixed large C1/C4 comparison, successful real eight-job concurrency acceptance, older full native/pool acceptance and exact-head GitHub CI also remain outstanding at this checkpoint. Failed or partial runs retain their full original costs and cannot be turned into a successful subset.

The first eight-job native concurrency attempt did execute. Operator job `1a177f5cf94-96a-1174` exited 1 after 4.662806507898495 seconds. Its reported native RPC 33 failure was SSH exit 255 with `Connection closed by 192.168.0.11 port 22`. The [actual operator outcome](native-concurrency-r01.operator-outcome.json) retains the returned status/stdout/stderr and binds the now-retained [complete original report](native-concurrency-r01.report.original.json): 237,036 bytes at SHA-256 `5fe38092e3cd49f8ad7171fb8649dc090bd94495be3bcbf1af90d3bfae2f2080`. No `MaxStartups`, request-wave or other cause is established here. The nine passing local implementation selfchecks do not change this real run's failed outcome. Diagnosis and any subsequent candidate require their own source identity, evidence and acceptance; the failed attempt will remain retained.

The combined candidate is published for exact-source CI and the remaining acceptance work while the PR stays Draft. Later performance evidence must name its actual source map and ELF and be committed separately. No throughput increase, resource reduction or performance adoption is asserted here.
