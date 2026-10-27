# A54 — borrowed compact rows, X230 qualification checkpoint

**Status: X230 qualification, all original Python gates, native eight-job
concurrency, all three owner-recovery cases and the fixed small comparison
passed. Their original-evidence audits passed. The large comparison stopped
at the candidate warmup deadline; 60 planned calls were unexecuted. A separate
same-executable diagnostic completed 20 calls with four failures. The complete
six-host suite remains unexecuted for this candidate. Exact-head GitHub CI
passed all 13 steps. Performance adoption is false.**

A54 extends the published A53 commit
`b20bcf02cfe72b3873c5c03180e4028ea673067f` / tree
`84d5caea62cceaf41b59a354185c85439a6fa0e8`. Three existing source files change; the
other 172 compiler inputs retain their qualified A53 identities. The release
still includes A53's bounded direct SSH and original-child cleanup ownership,
the owner publication barriers and conservative unknown-owner recovery.

## What changed and why

The serial archive verifier previously decoded each compact derived ROW into
three owned strings, expanded binary IDs to hex, then parsed those IDs again to
validate its ROW/ORDER join. A54 keeps the original redb access guard alive for
one member and borrows the compact row's already validated fields. It constructs
the same 80-byte ORDER key and checks the same 32-byte ORDER value directly.

`view_if_compact` uses the complete existing compact parser. A malformed `HAR1`
row remains an error; it cannot fall back to the legacy JSON path. Legacy rows
continue through the existing decoder. Base-row encoding, identity and ORDER
checks precede pending replacements, so a valid pending completion cannot hide
a damaged base row.

The actual original JSON is still read completely and parsed by the original
record deserializer. A54 compares every record field and the complete file
stamp. The exhaustive record destructure makes future record fields require an
explicit comparison. Canonical identifier checks, escaped but valid JSON,
strict compact framing, legacy behavior, pending updates, off-owner membership
and corrupted ORDER bindings have regression coverage in the existing sibling
test file.

This change removes expected-row allocations and repeated encoding work. It
does not reuse a completed observation. The full namespace walk, all original
record reads, descriptor/path checks, pre/post layout fences, ROW/ORDER
transaction, pending accounting and final fences remain required. The serial
page path, original usage-reader path, eight metadata permits, one-millisecond
cohort cutoff and original three-second absolute request budget are unchanged.

## Actual X230 qualification

The original root job was `1a17893f8e9-96a-1245`, started on
2026-10-26 at 14:18:45 UTC and completed at 14:33:39 UTC with exit code 0 and
complete, untruncated operator output. Fresh source, entry and qualification
directories use the `a54-compact-view-r01` identity.

Rust 1.95.0, the original offline/locked commands, two Cargo jobs, two test
threads, two Tokio workers, disabled incremental compilation, stage umask 022
and the original stage timeouts were retained. No Rust build or test was run
on the local review machine.

| Original stage | Exit code | Recorded duration |
| --- | ---: | ---: |
| format | 0 | 2.504 s |
| fmt-check | 0 | 2.060 s |
| clean-package | 0 | 0.429 s |
| all-feature/all-target Clippy, warnings denied | 0 | 42.642 s |
| full test | 0 | 523.940 s |
| release | 0 | 316.523 s |

The original test summaries contain **1,332 top-level passed tests and 23
existing ignored tests**: 18 + 1,306 + 8. Two nested, filtered subprocess
summaries are retained and excluded from that total. The [complete original test log](qualification-test.original.log.gz) was
separately purpose-read in full: 429,389 bytes at the qualification-pinned SHA256
`9c4754e96493e65732ccb2a7d3ed59d0ee6a7026b41270623330841c4a39ad6e`.
The [download and parser receipt](qualification-test-log.purpose-verification.original.json)
and [seven-test coverage record](new-test-coverage.direct-log.json) verify that
each new fully qualified test name appears exactly once with `ok`, and that
all twelve original test declarations remain present. The subsequent full-source export also passed and independently agrees with
these direct source and original-log observations.

All six stage host gates passed. The guarded original worker retained its
identity, pidfd, GO decision and wait custody until reaping. Raw wait status
was 0, its process group was quiet and no cleanup signal was needed. The parent
source/input fences and the actual retained parent Git identities remained
unchanged. No service or authentication configuration changed.

| Object | SHA256 |
| --- | --- |
| [Original qualification](qualification-r01.original.json) | `49b0019ece7405d455ace8cb638080a203a24fca01c6985a6cdda6d51180a51c` |
| [Original guarded entry](entry-r01.original.json) | `a98b564f5db07c64b497b68098902192f71f7be6884e687e68b38e9e41f3e6c3` |
| [Original worker](worker-r01.original.json) | `b7ee93502f5ba0a3861e4578da8301ebac9af8ceb9e1b535ad2e5a8c6af73a90` |
| Release ELF | `d2134c1b2b1999f46f0808b0d523ae51f54821c09afa6ecbf8188c883bbf3d70` |
| Test ELF | `9ae6a1ca692bea236a09771e6b5ca58d7c99454f7f4d51ccf11f1d5f1cd161eb` |
| Complete tested/after map, 175 entries, compact JSON | `7d4143971feeb9b1fcbf1f3e567ba367c36770cdf050fe496b1e2778a1025176` |
| Original full test log | `9c4754e96493e65732ccb2a7d3ed59d0ee6a7026b41270623330841c4a39ad6e` |

Publication uses only the three actual formatted bodies read from their exact
qualified X230 paths and checked against the complete qualification map. The
[complete original source export](qualified-source-export.original.json.gz) is
79,175 compressed bytes at SHA256
`91d34de8a51d77121ac036a9044d393c40c5fe2c7614d9a92fe72dc19eea6274`.
Its actual job `1a179848f46-96a-1278` completed with exit 0 and complete output.
The export rehashed all 175 source inputs, retained their final fences, exported
the three changed bodies and six original host-gate bodies, and checked all
seven new test names against the original full log. Its 551,116 expanded bytes
have SHA256
`8e8b667afa9f58f392e4a753c32c9a110be3379a3aad34e741cc23a0a3c6c77c`.

The [download verification](qualified-source-export.download-verification.json),
[direct-read reconciliation](qualified-source-export.direct-reconciliation.json)
and [independent review](qualified-source-export.independent-review.json)
verify complete bytes, the exact 186 input-receipt membership, all 175 source
identities, the six embedded gate bodies and all seven unique successful test
names. The three exported source bodies are byte-identical to the earlier
direct capture. The export records ELF identities from the qualification; it
accurately makes no new ELF-body rehash claim. Each native/performance admission
still checks its exact executable under the original protocol.

Rustfmt changed the prepared content-verifier and test-file bytes. The three
qualified identities are:

| Source | Actual formatted SHA256 |
| --- | --- |
| `src/mcp/runtime/request_archive_codec.rs` | `8201e82a69debf0243f9145f2b6fac8dfac5ec417cbe4f3f14b35f1a8c3a6e94` |
| `src/mcp/runtime/request_archive_content.rs` | `d5be2c37d5544a870a7f64af210bfd9f512f7c7771f5501d13a6cd037071b768` |
| `src/mcp/runtime/request_archive_content_tests.rs` | `a5053ec2721dacff50ba965f0bfa49534dffce668acd23e6c292c3e94f8e9d3d` |

## Acceptance ledger for A54

| Gate | Actual result | Evidence and remaining limitation |
| --- | --- | --- |
| Full X230 qualification | Passed | Six original stages; 1,332 top-level tests, 23 existing ignored; exact source/ELF and original-worker custody |
| Fifteen Python commands plus dependency precheck | Passed | 284 reported tests, zero skips; all original sixteen commands and the 216-file combined source map |
| Native eight-job concurrency | Passed | Nine same-source selfchecks; original 8 jobs, 8 early reuses, 16 mixed reads/status requests and 8 final reuses; full raw audit |
| Controller/reply/owner loss | Passed | All three original cases; complete 88-file package and 304 nested receipts; explicit unknown on owner loss |
| Small archive | Passed all six fixed numerical gates | 8,192 measured / 8,848 total calls, two opposite blocks; complete original-evidence audit passed on X230 |
| Large archive | Failed, incomplete | Baseline controller completed 20 calls; candidate warmup failed at the original deadline; 60 calls unexecuted, all sixteen gates false |
| Same-ELF diagnostic | Complete capture, four measured failures | 20 attempted / 16 successful / 4 failed; full trace establishes two late two-member cohorts waiting on the store lock |
| Original six-host suite | Not executed for this candidate | Ten same-source lease selfchecks and 87 admission checks passed; those do not execute the eight-stage suite or its 600-second trace-off soak |
| GitHub CI | Passed on the exact published head | `34b961941a211025f2083b9fd24470de32cb5b2f`, run 40381563393 / job 121778869380; all 13 steps completed successfully |

The [published whole-tree verification](published-checkpoint-whole-tree.independent-summary.json)
checks all 175 actual compiler inputs, the three changed source blobs and the
44 checkpoint assets against the full Git tree. All 6,891 other parent leaves
are unchanged. The later [compiler publication manifest](compiler-publication.final.json)
records the actual published checkpoint. No source from a different executable
is used to close the rows above.

The [exact-head CI verification](github-ci-34b96194.independent-verification.json)
checks the complete [run capture](github-ci-34b96194.run.captured.json) and
[job capture](github-ci-34b96194.jobs.captured.json). The original job ran
from 19:45:45 to 19:59:19 UTC on 2026-10-26 and all 13 steps completed
successfully. Both API head identities match the exact A54 commit; this
CI result does not replace the failed large comparison.

## Actual control, native concurrency and recovery results

The [control-gate audit](control-gates.independent-audit.json) passed 171 checks
of the actual sixteen commands, 284 reported tests, original worker custody and
output receipts. The original job `1a17984e450-96a-127a` completed with exit 0.
Its 216-file inventory is the original 175 compiler inputs plus 43 supplemental
files with two shared paths; all original argv and timeouts are retained.

The native concurrency job `1a1798b15f1-96a-12ae` completed in 10.216547 seconds.
The [complete six-file package](native-concurrency-detail-evidence.original.json.gz)
and [independent raw audit](native-concurrency-raw.independent-audit.json) retain
178 remote receipts, five local original wait4 receipts, unique job identities,
exact source/ELF fences and one effect per job. The eight expected job exit codes
are 0, 3, 0, 7, 0, 2, 0 and 5; success here means the original case expectations
were met. Its elapsed time is not an independently controlled speedup claim.

The owner-recovery job `1a179885ee8-96a-1299` also completed with exit 0. Its
[complete 88-file original package](native-owner-evidence.original.json.gz),
[independent audit](native-owner-evidence.independent-audit.json) and
[acceptance receipt](native-owner-evidence.acceptance.json) verify 799 checks
and 304 nested receipts. Controller loss and reply loss retain the durable
terminal result and original exit witness, with one effect for the same key.
Owner loss remains explicitly unknown/finalizing and non-authoritative. There
is no fabricated exit witness or retry of an unknown effect. All original
SSH/control waits and remote pidfd cleanup are accounted for.

## Small archive: complete passing comparison

The [original report](small-report.original.json),
[original evaluator output](small-analysis.original.json) and
[independent 160-check field/decimal audit](small-report-field-audit.json)
retain all eight original controllers and all 8,848 calls. Each arm has 4,096
measured calls. Baseline r07 used 33.902275211 seconds wall and 29.65 seconds
observed CPU; A54 used 31.405333296 seconds wall and 27.31 seconds observed CPU.
These are decreases of approximately 7.365% and 7.892% respectively. The
conservative candidate-upper/baseline-lower CPU ratio is 0.9315022, so this
sample's CPU reduction exceeds the stated endpoint quantization allowance.
Whole-life RSS changed from 35,052 to 35,196 KiB, within the original guard;
observed FD endpoints changed from 20 to 24 without within-round growth.
This is the fixed small C1 comparison, not a saturated concurrency or soak test.

The complete original gzip on X230 contains 2,023 members and 101,669,953 raw
bytes. Its compressed size is 28,981,357 bytes and SHA256 is
`cad4bc1ccee3e3433b0cac38c133cdca9615214c0084ae81e8a28cb8015960a1`.
The [actual corrected independent raw audit](small-raw-audit.r02.original.json)
and [reconciliation](small-raw-audit.r02-reconciliation.json) passed against
that complete original: all 8,848 calls, 1,024 records, 32 snapshots, 340 shared
source bodies and two release ELFs are covered. This package has not been
fully downloaded locally or published as a complete Git payload here; the
original collector receipt identifies its immutable X230 path and full hash.

The [first failed audit](small-raw-audit.r01-failed.original.json) is retained.
It rejected a stale protocol byte-length binding (8,572 instead of the actual
8,542). The corrected auditor changed only that literal, then inspected the
same original package under the original 300-second outer budget. It did not
rerun the benchmark or change any runtime result.

## Large archive: failed warmup and retained partial evidence

The original large job `1a1798fe32b-96a-12d0` completed with exit 1, without an
outer timeout or cancellation. The [original report](large-report.original.json)
and [independent 475-check partial field audit](large-partial-report-field-audit.json)
retain the exact planned 80 calls/32 waves and actual early stop. Baseline
controller 0 attempted 20 measured calls: 8 succeeded and 12 failed. Candidate
controller 1 completed no measured call: after the unchanged 60-second idle,
its sole fixed warmup returned the product deadline error at 3,001.595 ms.
The original ten-second client deadline did not expire. Both original
controllers were reaped with exit 0 and their fixtures were unchanged.

Consequently 60 planned calls are unexecuted, all sixteen acceptance gates
are false and comparative ratios are undefined. The zero candidate measured
failures in this partial report must not be interpreted as C1 or C4 success.
All three setup failures are retained. There is no readiness retry, shortened
inventory or substitution of a different diagnostic for this failed attempt.

The [partial capture receipt](large-partial-original-evidence.receipt.original.json)
contains exactly the two actual controllers: 132,096 original record bodies,
65 required control originals, two actual optional seals and two collector
inputs, for 132,165 members. It does not invent evidence for unexecuted
controllers. The immutable gzip is 25,012,867 bytes, SHA256
`bec5c4af192bd5957e4e201dc0f6557a2cc2b0764c650921407d6fc7a44f11f7`.
The [complete independent raw audit](large-partial-raw-audit.original.json)
subsequently passed on X230, job `1a179b195e3-96a-1388`, in 45.997 seconds.
It checks all original bodies, complete gzip framing/CRC, source/ELF and final
namespace fences, all 28 RPCs/26 tool calls and both original EOF/wait4 exits.
The 67,442,623 raw bytes and all 512 result-shard records are covered. Its
66,895-byte audit SHA256 is
`1e0c2d2d010d6d34fad0bd36e426318ca0c2e5cfebf6879119e87f0e5dd00e55`.
The raw gzip remains on X230 at the receipt's path; no complete local transfer
or Git publication of that payload is claimed. Raw-evidence audit success
preserves the incomplete and failed performance result.

## Same-executable diagnostic: two independent late cohorts

One new diagnostic used the same release ELF and the original fixed workload:
65,536 archived records, 512 hot records, one kickoff, 60-second idle, one
warmup and 20 measured calls in eight C1/C4 waves. Only the existing opt-in
trace flags changed. The [complete original report](metadata-diagnostic-report.original.json),
[original trace](metadata-trace.original.json.gz),
[original stderr](metadata-diagnostic-stderr.original.log.gz) and
[independent audit](metadata-diagnostic.independent-audit.json) retain all
3,206 events, 22 server calls and ten cohorts, with no drops, parse errors or
sequence gaps. All 20 measured calls were attempted; 16 succeeded and 4 failed.
Warmup succeeded in this diagnostic, which does not erase the earlier failed
warmup or establish a performance pass with tracing disabled.

| Diagnostic wave | Failed slots / RPC IDs | Late server calls / cohort | Store-lock wait | Remaining verification budget | Earlier complete scan |
| --- | --- | --- | ---: | ---: | ---: |
| 6 | 13,14 / 18,19 | 17,18 / 16 | 2,153,089 us | 845,151 us | 2,150,402 us |
| 7 | 17,18 / 22,23 | 21,22 / 19 | 2,118,530 us | 879,569 us | 2,117,846 us |

Each wave formed two independently frozen two-member cohorts. The later API
entries arrived 128 and 112 microseconds after the earlier cohort froze. Their
partial fresh scans used 845,165 and 879,585 microseconds and crossed the
original deadline. Permit waits were 0–1 microseconds and the late blocking
queue waits were 22 and 28 microseconds. The raw trace establishes store-lock
waiting in this diagnostic. It does not explain the arrival delay or separate
ROW/ORDER, namespace calls, file reads, JSON parsing or allocation cost inside
the scan; instrumentation can itself affect scheduling.

The follow-up A55 design therefore measures bounded internal phase totals
and reduces repeated filename construction. No speedup or blocker closure
is attributed to that proposed change before fresh qualification and acceptance.

## Earlier A53 results retained

The A53 eight-job native run and all three native owner-recovery cases completed
and passed independent raw-evidence audits. The small-archive comparison passed
all six fixed gates. Its complete 29,004,490-byte original archive is retained;
one independent audit implementation passed on both X230 and the fully
downloaded local original, with identical semantic results. These are A53
results and do not close the A54 rows above.

The A53 large attempt completed all four original controllers and all 80
measured calls. It passed 15 of 16 gates; candidate C4 correctness was **30/32**,
so the attempt remains failed. Both errors consumed the original three-second
metadata budget. All failure costs are retained. The comparison's successful
call-rate ratio is not a complete-acceptance speedup.

An independent same-ELF diagnostic reproduced one failure among 20 measured
calls. In that diagnostic, a late caller formed a new one-member cohort after
the original cutoff, waited 2.159 seconds on the store lock, then entered full
verification with about 0.839 seconds remaining and reached its original
deadline. The earlier three-member cohort's complete scan took 2.157 seconds.
Trace instrumentation can affect scheduling; this is direct evidence about
the diagnostic, not proof of the exact split in the preceding untraced run.

The complete A53 large-original collector subsequently retained 264,292 members,
including every one of the 264,192 original record bodies, in a 49,267,466-byte
gzip at SHA256
`55ab40111d71f1cf3781682147fc1cabf98989f0988e70d250df2762a62302f4`.
It checked complete before/after byte and namespace fences and preserved the
failed performance result. The subsequent complete independent raw semantic
audit passed on X230 and retains the failed 15/16 outcome; see the
[A53 evidence ledger](../a53/README.md).

A54 must demonstrate its effect under the original acceptance protocol. No
success from another executable, widened window, renewed deadline, successful
subset or automatic business retry can close a remaining gate.
