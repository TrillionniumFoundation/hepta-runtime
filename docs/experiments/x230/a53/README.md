# A53 — bounded direct SSH, qualification and native evidence

**Status: full X230 qualification, the original Python gates, eight-job native
concurrency, three recovery cases and the small-archive regression gates passed.
The complete small and large original-evidence audits and exact-head GitHub CI
also passed. Large archive completed but failed one gate (candidate C4: 30/32).
The complete six-host suite remains unexecuted for this candidate.
Performance adoption remains false.**

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

Publication uses the actual formatted export. Commit
`b20bcf02cfe72b3873c5c03180e4028ea673067f`, tree
`84d5caea62cceaf41b59a354185c85439a6fa0e8`, directly extends A52 commit
`06c18da77a3433a34773c0ed690833cd44db5715`.

The [final compiler publication receipt](compiler-publication.final-b20bcf02.json)
verifies all 175 compiler paths, modes and Git blob identities against the actual
qualification. It rehashes the four actual formatted bodies and inherits the
other 171 already verified A52 objects. It does not claim a fresh local read of
all 175 source bodies. The [complete checkpoint tree audit](checkpoint-full-tree.final-b20bcf02.json)
also verifies all 53 checkpoint assets, all 6,894 leaf entries and the complete
7,573-entry captured tree. All other parent leaf identities remain unchanged;
there are no missing, extra or mismatched entries.

The captures are serialized GitHub API objects, not original HTTP wire bytes.
This local audit verifies the commit/tree objects; the root operator separately
performed the successful branch update and ref readback. The earlier
[prepublication receipt](compiler-publication.original.json) remains byte-for-byte
unchanged with its original `final_a53_github_tree_verified: false` preparation
state. The new final receipts establish the completed check without rewriting
that earlier evidence.

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
| Eight-job native concurrency | Actual run passed; report-field and six-file original-evidence reconciliation passed | Scope is this fixed native run, without a performance or observation-pool claim |
| Native controller/reply/owner-loss cases | Three actual cases passed; 88 original files and 799 independent checks passed | Physical power loss, host reboot and arbitrary external-effect exactly-once remain outside this test |
| Small archive | 8,192 measured / 8,848 total calls completed; six numeric gates, report-field cross-check and complete raw semantic audit passed | One independent audit implementation agrees on X230 and the complete local original; no CPU improvement beyond quantization is claimed |
| Large archive | All 80 calls / 32 waves completed; 15/16 gates passed and candidate C4 correctness failed at 30/32 | Complete failed attempt and costs retained; all original bytes captured and independently audited in full on X230 |
| Six-host access and lease admission | Read-only readiness and actual X230 same-source implementation/plan admission passed | Keep the fresh owned forwarding session through complete native execution and cleanup |
| Original six-host native suite | Actual candidate adapter frozen; run pending | All eight original stages passed once, including the 600-second trace-off soak |
| GitHub CI | Exact A53 commit `b20bcf02cfe72b3873c5c03180e4028ea673067f` passed run 40332089549, attempt 1, all 13 steps | A subsequent candidate still requires its own exact-head CI result |

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
175-file source binding.

The subsequent [independent raw reconciliation](native-concurrency.purpose-download-audit.json)
also passed. Its [download manifest](native-concurrency.purpose-download-manifest.json)
and [six-file evidence archive](native-concurrency.purpose-captured-evidence.json.gz)
retain version-bound purpose downloads of the original files. This gzip was
assembled locally from those downloads; it is not a remote packer's output.
The audit checks 178 nested remote file receipts, 56 unchanged immutable records,
eight original terminal witnesses, exact stdout/stderr/cursors, eight single
effects, both repeated-key batches and the sixteen mixed status/read replies.
Expected exits `[0, 3, 0, 7, 0, 2, 0, 5]` all match. The original controller and
four custody SSH children have actual local wait4 receipts; remote owner/business
observations are not represented as local wait4. This establishes the fixed
native concurrency acceptance and makes no observation-pool or speedup claim.

The three-case recovery [actual plan](native-owner-plan.original.json) and
[38-check independent plan audit](native-owner-plan.independent-audit.json) bind the
qualified A53 executable, fresh fixture names and the existing direct AI395
profile. That preparation audit retains its original
`native_acceptance_result_claimed: false` field. The later actual run,
`1a1786a27b7-96a-1234`, exited 0 with all three cases passed and no errors.

The [original 88-file evidence archive](native-owner-evidence.original.json.gz),
[original summary](native-owner-summary.original.json) and
[independent result audit](native-owner-independent-audit.json) establish the
actual outcomes. All 799 checks passed, including 304 nested byte receipts and
the actual qualification/source/ELF/plan bindings.

| Recovery case | Original attempt and actual result |
| --- | --- |
| Controller loss | Kill the original local controller through its bound pidfd; the original AI395 owner and business survive, then publish the confirmed durable terminal result |
| Launch reply loss | Keep 2,507 reply bytes unconsumed, kill the original controller, and reconcile the same original remote job to its confirmed durable terminal result |
| Original owner loss | Kill only the original remote owner through its bound pidfd while the business is live; preserve `finalizing` / `unknown`, nonauthoritative status, no terminal witness and no automatic retry |

Every case retains exactly one local job record and one original remote effect.
The same request key resolves to the same job without another launch. Successful
terminal cases preserve exact stdout, stderr, offsets and the original 4,096
stdin bytes. Original local controller and SSH children are actually reaped;
remote owner/business cleanup uses their original identity observations and
pidfds, without a remote wait4 claim. The 75-second business release deadline,
90-second native job timeout and all other original budgets remain unchanged.

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

The new lease's [actual X230 implementation selfcheck](six-host-lease-selfcheck.original.json),
[frozen plan](six-host-lease-plan.original.json),
[independent admission audit](six-host-lease-admission.independent-audit.json) and
[original read provenance](six-host-lease-admission.read-receipts.json) are retained.
All ten checks completed under X230's UID 1000, with nine original local child
receipts. The deliberate selector-I/O failure remains `cleanup_complete: false`
while still proving original-child reaping; the selfcheck does not turn that
negative case into successful cleanup. These implementation and admission checks
perform no SSH connection, agent query or business launch. The complete eight-stage
six-host workload is still pending, including its original 600-second trace-off
soak. There is not yet a six-host result packer or an actual long-suite result.

## A53 small-archive comparison

The [full original report](small-report.original.json) and
[original evaluator result](small-analysis.original.json) report all 8,192
measured calls and 8,848 total calls complete, with both opposite-order ABBA
blocks and all six fixed regression gates passed. Each arm contributes 4,096
measured calls; historical A52 observations are kept separate.

| Measurement | r07 | A53 |
| --- | ---: | ---: |
| Measured wall time | 32.6007 s | 32.2568 s |
| Observed controller CPU | 28.40 s | 28.13 s |
| Successful measured calls/s | 125.642 | 126.981 |
| Whole-life peak RSS | 35,016 KiB | 35,004 KiB |
| Controller FD endpoints in each round | 20 → 20 | 24 → 24 |

Within this comparison, wall time decreased 1.05%, observed CPU decreased 0.95%,
and peak RSS decreased 12 KiB. The conservative candidate CPU upper bound divided
by the baseline lower bound is 1.00177, within the original 1.10 limit. These are
descriptive results from one fixed comparison and regression-limit passes; they
do not establish a general speedup or attribute the difference to direct SSH.
The CPU upper/lower ratio remains above 1, so this observation is not separated
from endpoint quantization. A53 has four more observed controller FDs at the
round endpoints; neither arm increases within a round. These endpoint readings
do not establish a continuous FD or memory soak result.
The [independent report-field audit](small-report-field-audit.json) passed all 146
checks of the original report, evaluator, qualification and protocol, including
independent decimal sums of all eight rounds. It confirms the reported coverage
and numerical calculation. The original evaluator explicitly
does not claim an independent re-audit of all raw wire and fixture originals.
The later complete original package, preserved as
[56 consecutive unchanged byte parts](small-original-evidence.parts/manifest.json),
contains 2,023 members: all 1,678 fixed experiment originals, three producer
references, 340 source bodies and two release ELFs. Its 29,004,490 compressed
bytes have SHA256
`94adcdbfed0ce4e55e60cad6a2bbe5c0166072b9806c24f1b7cacd3c5c93951e`.
All 443 purpose-read chunks and the complete gzip were verified. The Git parts
are at most 512 KiB each. Concatenating their `file` entries in manifest order
reconstructs the original gzip exactly; the manifest also binds each part
offset, length and SHA256. This transport does not recompress or alter evidence.

The [X230 raw audit](small-raw-audit.x230.original.json) and
[local raw audit](small-raw-audit.local.original.json) both passed. They verify
all 8,848 raw calls, 1,024 records, 32 snapshots, eight original controllers,
original custody, source/ELF bindings and complete numeric recomputation.
The [reconciliation](small-raw-audit.reconciliation.json) confirms identical
semantic results; only the archive location and local file identity differ.
This is one independent implementation run in two places, not two independent
implementations. The earlier field-audit limitation remains unchanged in its
original file; these later receipts close the full small raw-evidence gate.
Performance adoption remains false.

## A53 large archive: complete failed attempt

The [complete original report](large-report.original.json) retains four original
A/B/B/A controllers, each with 65,536 archive and 512 hot records. All 80 measured
calls and 32 waves executed, all original fixtures remained unchanged and no
measured slot was omitted. The [independent field/numeric audit](large-report-field-audit.json)
passed 706 checks and independently recomputed the original sixteen gates.
That audit pass does not turn the failed performance attempt into a pass.

Baseline A completed C1 at 8/8 and C4 at 8/32. A53 completed C1 at 8/8 and C4
at **30/32**. The only failed gate was `candidate_c4_32_correct`. Both candidate
failures occurred in controller 2, wave 6: slots 53 and 54, RPC IDs 18 and 19,
with the tail-32 and first-1 query shapes. Complete product failures arrived at
3,003.206 ms and 3,003.634 ms. They exhausted the original three-second metadata
budget; they were not ten-second client timeouts, unknown transport outcomes
or replayed requests.

C4 inclusive CPU, including failures and shutdown, was 24.086397 seconds for
baseline A and 18.488519 seconds for A53. Whole-life maximum RSS was 96,492 and
80,580 KiB. Successful-call rate ratio was 4.88123. These figures retain failed
costs, but **30/32 is below the required 32/32**, so they do not establish an
adopted performance result. All four initial index-kickoff failures are also
retained; they are not relabelled as successful setup.

The original collector job `1a178a08c15-96a-124b` completed with exit 0 in
219.082 seconds. It captured 264,292 members, including all 264,192 original
record bodies, and checked complete original-byte and namespace fences again.
The gzip has 49,267,466 bytes and SHA256
`55ab40111d71f1cf3781682147fc1cabf98989f0988e70d250df2762a62302f4`.
The 340 shared source bodies and two ELFs are bound to the complete small
package and were independently rechecked at their original positions. The
capture launches no business or child, changes no original, and explicitly
keeps `original_performance_passed: false`.

The [complete independent raw audit](large-raw-independent-audit.original.json)
subsequently passed on X230, job `1a17984d93f-96a-1279`, exit 0. The 98,351-byte
original audit has SHA256
`ca6b196a5f981b6a3e1916b8d035c2afbf5791aebf5ab4c1fe9377b2777c6e57`.
It validates all 264,192 record bodies, the complete gzip/frame inventory, 96
RPCs, 92 journal entries and all 80 measured slots/32 waves. Original custody,
full namespace and source/ELF fences and the numerical gate recomputation are
retained. The audit preserves the failed 15/16 result; evidence completeness
does not certify performance. Its disclosed limits remain: the cached seal
digest is not independently recomputed, and test-ELF bodies are not exported.

The full large gzip remains at the immutable X230 path recorded by the
[capture receipt](large-raw-capture-receipt.original.json); its independent audit
read the complete original there. Its local transfer was incomplete at this
checkpoint, so no complete local-package audit or Git package publication is
claimed for that large gzip.

## Same-executable metadata diagnostic

The [original diagnostic report](metadata-diagnostic-report.original.json) and
[independent raw trace audit](metadata-diagnostic.independent-audit.json) retain
20 measured calls: 19 successes and one product deadline. All 3,173 trace events
were parsed without drops or parse errors and reconciled with the complete
closed original stderr. The source map and executable equal the qualified A53
ones. The instrumented run is separate from performance acceptance.

In its wave 6, three calls froze into one cohort. A later first-1 call entered
282 microseconds after that freeze and formed a new one-member cohort. It
waited 2,159,223 microseconds for the original store lock, then began complete
verification with about 839,130 microseconds remaining. That unfinished scan
reached the original deadline. The preceding three-member cohort completed
its full scan in 2,156,541 microseconds and returned three successes.

This directly identifies the lock-wait/full-validation sequence in the
instrumented diagnostic. Tracing can affect scheduling, so it does not prove
the exact cohort split of the earlier two untraced large-run failures. It also
does not authorize wider cohorts, renewed deadlines, proof reuse, discarded
failure slots or automatic retries.

## Exact A53 GitHub CI result

The [captured API result](pr71-b20-ci-success-api-capture.original.json) identifies
commit `b20bcf02cfe72b3873c5c03180e4028ea673067f`, run `40332089549`, job
`121603847254`, attempt 1. The job ran from 15:45:30 to 15:59:11 UTC on
2026-10-26 and completed with `success`. All thirteen steps succeeded,
including format, all-target check, Clippy, tests, descriptor-relative file
safety, control-plane regression and release. The earlier queued snapshot
remains unchanged as historical evidence. This closes A53 CI, not a later
candidate's CI or the original six-host runtime suite.

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
attempt. A53's independent raw reconciliation is a separate successful run.

Performance adoption remains false until the final candidate's complete native,
correctness, resource and numeric gates have actually passed. There is no claim
that the global optimization limit, host reboot recovery or physical power-loss
recovery has been established.
