# A53 — bounded direct SSH, X230 qualification checkpoint

**Status: full X230 qualification passed; final native and performance acceptance
is in progress. This checkpoint does not authorize performance adoption, merge
or deployment.**

A53 starts from the published A52 commit
`06c18da77a3433a34773c0ed690833cd44db5715` and adds bounded admission and original-child
ownership to the default direct SSH path. Its source and release executable are
qualified on X230. The pending acceptance rows below must be replaced by actual
results from that executable; earlier A52 passes are not A53 results.

## Why this change is needed

The failed A52 native concurrency run acknowledged eight durable jobs and reused
the same eight identities on the first repeated-key batch. Its first terminal
observations had the expected outputs and exit codes. Two requests in the next
sixteen-pending mixed status/read batch failed with SSH exit 255. The other
fourteen replies were consumed; the final repeated-key batch was not executed.
The complete attempt remains failed.

Source inspection found that the default direct path spawned SSH without the
admission limits of the optional observation pool. A53 limits direct transport to
two SSH children per exact configured target, eight globally and sixteen admitted
requests including queuing and cleanup. Admission uses the original absolute
deadline. Cancellation cannot release a submitted child's permits before actual
reaping; uncertain cleanup freezes the transport and retains original custody.
There is no automatic business relaunch.

The change also joins the direct owner and observation pool at normal transport
shutdown. It retains A52's archive validation cohort, serial page verification,
owner publication barriers and fail-closed unknown-owner recovery. See
[DESIGN.md](DESIGN.md) for the contracts and their limits, including the unchanged
release `panic=abort` profile and the absence of physical power-loss acceptance.

## Actual X230 qualification

The successful attempt used fresh `source-a53-bounded-direct-ssh-r02`,
`qualification-a53-bounded-direct-ssh-r02` and `a53-bounded-direct-ssh-entry-r02`
directories under the existing X230 experiment workspace. The root operator job
was `1a1781a666f-96a-11da`, with exit code 0 and complete, untruncated operator output.

Rust 1.95.0, the original offline/locked commands, two Cargo jobs, two test threads,
two Tokio workers, incremental compilation disabled, stage umask 022 and the
original stage budgets were retained. No Rust build or test was performed on the
local review machine.

| Original stage | Exit code | Measured stage duration |
| --- | ---: | ---: |
| format | 0 | 2.103 s |
| fmt-check | 0 | 2.073 s |
| clean-package | 0 | 0.427 s |
| all-feature/all-target Clippy with warnings denied | 0 | 43.970 s |
| full test | 0 | 532.592 s |
| release | 0 | 325.414 s |

The original test log contains **1,325 top-level passed tests and 23 existing
ignored tests**. All twenty new direct-transport regression tests appear exactly
once with `ok`. Two nested, filtered subprocess test summaries are retained in
the coverage evidence and are not added to the top-level total.

All six original stage host gates passed. The guarded worker retained its
original process identity, pidfd, GO decision and wait custody; its original
child was reaped with raw wait status 0, the group was quiet and no signal was
needed. No service or authentication configuration was changed.

| Qualified object | SHA256 |
| --- | --- |
| [Original qualification](qualification-r02.original.json) | `ab3a37ceb97667694c201d9b62556398e04e805010c8492af6a8f6f51486a72b` |
| [Original guarded entry](entry-r02.original.json) | `9f888ba1399bb23453e40ee6f8544b11584b8bfcc5c97245dedec40ece1fcc78` |
| [Original worker](worker-r02.original.json) | `9cf2c2e61b8257061954ddc410c71e61516b74081f16c4f68eb04d0fdbc5ebbc` |
| Release ELF | `5855f6fb044745eba0bf0885b0430bc5a5bb03f68310cce50d961947925c03c6` |
| Test ELF | `6cd39d3071b8fe6226f47e73d2d41aef81693139a32a2b5e2c276c00ae302b25` |
| Complete tested/after map, 175 entries, compact JSON | `91962e89b203621686cfa0d77567b13bd246092a99345681674bbafd46388c35` |
| Original full test log | `6e0905516ea78963f80f2e5c79cf7d10ccf92ec305b52b02e4ae700256fe9f4f` |
| [Qualified source export](qualified-source-export.original.json.gz) | `4051d374929eb798dc92923bd953858f7291f9bc944e42ec3eafaee6d5e914bc` |

The export is 83,674 compressed bytes and 569,482 expanded bytes. It contains the
four actual formatted source bodies, the six original stage gate bodies, the
complete input receipts, unchanged-source checks and the original-test-log
coverage analysis. Its expanded SHA256 is
`2957367dd88e475e4820d2a73ab5b6c63466d6157694d490ace29e31d620ca0d`.

The first qualification attempt is preserved separately in
[qualification-r01-failed.original-files.json.gz](qualification-r01-failed.original-files.json.gz).
It failed Clippy with `async_yields_async` in the new caller-runtime-drop test;
test and release were not executed. The second attempt only restructures that
test's runtime registration and readiness wait. Production source, handle
lifetime, assertions and lint policy are unchanged. The failed worker was also
authoritatively reaped, with no group left running.

## Publication identity

Publication uses the actual formatted export, not the pre-format candidate.
Four files are prepared for publication, and the other 171 compiler inputs
inherit the already verified A52 Git objects. The complete 175-path SHA256 map,
expected Git blob map and mode map have passed local composition checks. The
[prepublication receipt](compiler-publication.original.json) explicitly records
`final_a53_github_tree_verified: false`; the newly created GitHub commit and tree
still require a captured full-tree check. Every compiler input must have the
expected path, regular-file mode and blob identity; a four-file diff alone is not
the complete source-tree check.

| Actual formatted file | Bytes | SHA256 |
| --- | ---: | --- |
| `src/main.rs` | 11,309 | `d71918759947bd07d531f486e22b39d2d051cd128966fe3b55e670ccd310a8f6` |
| `src/mcp/runtime/ssh.rs` | 15,676 | `83b7c3893adeddaaaecd68b20a60d6c0e68581ec12d387e91ac1e70517c9ebac` |
| `src/mcp/runtime/ssh_direct.rs` | 19,140 | `e0c9e90d492d8f05b42002eb463d5e144780507fe68c6107f6bf61ebbba9862d` |
| `src/mcp/runtime/ssh_direct_tests.rs` | 23,026 | `9cf3ad7eba20e9256f5053f8d51338108037ca5f5f70e26c8bc78e5d98eb2838` |

## Acceptance ledger at this qualification checkpoint

| Gate | Actual state at this checkpoint | Remaining requirement |
| --- | --- | --- |
| X230 full qualification | Passed, original r02 evidence retained | Bind every following run to its actual source map and ELF |
| Original fifteen Python commands and dependency precheck | Passed: 284 reported tests, 0 reported skips; all sixteen commands exited 0 | Original entry/worker, input/output fences and original-worker custody retained |
| Native concurrency implementation checks | All nine same-source X230 checks passed, including three original-child custody checks | This implementation check does not replace native business acceptance |
| Eight-job native concurrency | Actual operator summary reports `passed: true`, exit 0, wall 10.7337867 s for `1a1783541ed-96a-120e`; independent report-field cross-check passed | Independent reconciliation against six original remote evidence files remains pending |
| Native controller/reply/owner-loss cases | Actual plan prepared and independently checked; native run pending | Three fresh cases against qualified A53, with original effects and exit witnesses |
| Small archive | Actual protocol frozen; run pending | 8,192 measured / 8,848 total calls and all six gates |
| Large archive | Actual protocol frozen; run pending | 80 calls / 32 waves, full fixed inventory and all sixteen gates |
| Six-host access | Passed read-only readiness | Establish a fresh owned forwarding session for the complete native suite |
| Original six-host native suite | Actual candidate adapter frozen; run pending | All eight original stages passed once, including the 600-second trace-off soak |
| GitHub CI | The preceding A52 PR71 run and PR72 run were still queued without runners at the last read | Observe the actual CI result for the newly published A53 commit |

The Python run was `1a1782d9526-96a-1202`. Its
[original entry](control-gates.entry.original.json) is 56,019 bytes at SHA256
`4be56319acb630933eb17f6255de2916acfc55e1e30d2c9e1180b21a5a72f857`, and its
[original worker](control-gates.worker.original.json) is 35,661 bytes at
`96cedc8d6ed1f2b2999190bbb2b694813584adf89f979161fa75d33d65ba4950`.
All fifteen original Python test commands and the dependency precheck executed
once. The qualified 175-file source plus 43 supplemental files, with two shared
paths, formed the unchanged 216-file test copy. Original input/output receipts
were retained and the output writers settled. The original worker was reaped
with raw wait status 0, a quiet group and no cleanup signal. The dependency
precheck is excluded from the 284-test total; zero skips means zero reported
skips in these original command summaries.

The [native concurrency implementation receipt](native-concurrency-selfcheck.original.json)
contains all nine checks and no unexecuted check. It is distinct from the
[frozen native execution plan](native-concurrency-plan.original.json) and the
subsequent eight-job run. That run's observed operator summary is recorded above.
The [complete original report](native-concurrency.report.original.json.gz)
contains 340,718 uncompressed bytes at SHA256
`bc42fcacd21679de459a70e077cd5369d2412a681bc8b47ee8e7cf33a2e7c08a`;
its top-level `passed: true`, empty errors and wall time agree with the operator
summary. The [independent report-field cross-check](native-concurrency.report-field-audit.json)
passed: it checks all 49 RPC identities and complete packet writes, the fixed
8/8/8/16/8 batches, eight distinct starts, both repeated-key batches, mixed output
reads, expected terminal exit codes, original controller/SSH custody and the
175-file source binding. The separate reconciliation against six original remote
evidence files remains pending; this checkpoint does not close that evidence
requirement from the report fields alone.

The three-case recovery [actual plan](native-owner-plan.original.json) and
[38-check independent plan audit](native-owner-plan.independent-audit.json) bind the
qualified A53 executable, fresh fixture names and the existing direct AI395
profile. The audit explicitly records `native_acceptance_result_claimed: false`;
plan preparation does not establish any of the three fault-injection results.

The [main-to-X230 forwarding probe](main-to-x230-forward-readiness.original.json)
and [six-host readiness probe](six-host-forwarded-readiness.original.json) used
existing main-agent identities and existing pinned host keys. AI395, Mac, main,
Pocket4, ROG and X230 all returned the expected
account/platform identities. All seven original SSH children exited with 0, had
both output streams completed and were reaped without signals or discarded
bytes. The probe took 7.479 seconds. It made no business launches, key additions,
private-key reads or authentication changes. This establishes access readiness,
not the later eight-stage native acceptance.

The short forwarding sockets have already expired and are not reusable. The
complete native suite must retain one new owned SSH session and its current
agent through original-driver completion and cleanup. Its original stage budgets
and fixed six-host membership remain unchanged.

## Newly completed A52 evidence retained with this checkpoint

The A52 small-archive comparison completed all 8,192 measured / 8,848 total calls
correctly, with two opposite ABBA blocks and all six numeric gates passed. Its
[full original report](../a52/small-report.original.json) and
[independent analysis](../a52/small-analysis.original.json) are retained separately.

| Measurement, 4,096 measured calls per arm | r07 | A52 |
| --- | ---: | ---: |
| Measured wall time | 32.4622 s | 34.3333 s |
| Observed controller CPU | 28.40 s | 30.12 s |
| Successful measured calls/s | 126.178 | 119.301 |
| Whole-life peak RSS | 34,780 KiB | 35,200 KiB |

Wall time increased 5.76%, observed CPU increased 6.06%, and RSS increased 420 KiB.
The conservative candidate CPU upper bound divided by the baseline lower bound
was 1.07224, within the fixed 1.10 limit. These are regression-limit passes, not
evidence of a small-archive speedup. They are not pooled into A53 measurements.

The [complete A52 failed eight-job raw evidence](../a52/native-concurrency-r01-detail-evidence.original.json.gz),
[independent failure review](../a52/native-concurrency-r01-failure-review.json)
and [remote reconciliation](../a52/native-concurrency-r01-remote-reconciliation.json)
are also retained. All eight distinct effects and their original exit witnesses
reconcile, but the two failed observation replies and the unexecuted final batch
remain failures. The fresh A53 run's operator summary does not rewrite that A52
attempt or replace A53's pending independent evidence audit.

Performance adoption remains false until the final candidate's complete native,
correctness, resource and numeric gates have actually passed. There is no claim
that the global optimization limit, host reboot recovery or physical power-loss
recovery has been established.
