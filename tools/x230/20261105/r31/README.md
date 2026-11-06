# R31: pidfd readiness wait on accepted R24

**Status: qualification and exact Rust CI passed; completed observation 02 failed
the original C1 throughput gate. R31 is rejected and not adopted; R24 remains accepted.**

R31 reduces the delay in observing an already-exiting supervisor during the
Linux cancellation helper. The source baseline is accepted R24
`baab4def80be7af015b2e7a594cb302f66c4130e`. The router experiment and the
R25/R26/R28 cumulative changes are absent.

## Behavior and source scope

The helper registers the existing identity-bound pidfd with `select.poll`
before sending SIGTERM. It waits for readiness within the original monotonic
grace deadline, with a bounded poll slice. A readiness event still triggers
the original metadata and identity recheck, including at the deadline boundary.
Unexpected descriptors, masks, or polling errors retain the existing unknown
outcome; they do not trigger another signal or an automatic retry.

Readiness does not establish an authoritative job terminal result. The
acknowledgment still carries `termination_confirmed=false` and reconciliation
through `process_status`. The original non-Linux wait path is preserved. The
change shortens cancellation acknowledgment delay; it does not claim to make
the target process handle SIGTERM faster.

The only changed compilation inputs are:

- `src/mcp/runtime/jobs.rs`
- `src/mcp/runtime/jobs_cancel_wait_tests.rs` (new)
- `src/mcp/runtime/jobs_cancel_wait_fixture.py` (new)

Eight Rust regression tests cover 25 controlled wait-boundary cases. The Python
fixture covers readiness at the deadline, interrupted polling, unexpected
readiness, metadata/identity changes, descriptor cleanup, and preserved outcome
semantics. The complete existing regression inventory ran through the same
qualifier used for R24.

## Complete x230 qualification

The eight original stages passed: format, format check, harness tests, Clippy,
test build, isolated tests, independent isolated-test audit, and release build.

| Result | Value |
|---|---:|
| Passed tests | 1653 |
| Failed tests | 0 |
| Ignored tests | 34 |
| Selected tests | 1687 |
| Test retries | 0 |
| Unchanged qualification harness files | 19 |
| Compilation inputs matched to this checkout | 222 |

The successful native job is `1a1ae1c32b8-fc05-5d7a`. It completed with exit 0
and complete, durable, synchronized, untruncated logs. The tested runtime SHA256
is `70767e3ef78ec8519b81d7f600b37d012965b3c1b96abaf6c47c8273c73ee450`;
the unchanged jobctl SHA256 is
`61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62`.

There was **one earlier preparation failure**, job `1a1ae1597f5-fc05-5d3e`,
before cache transfer, source copying, or any qualification stage. Linux denied
reading a known system helper's proc links. Preparation v2 preserves that
failure and records the specific nondumpable helper identities and inaccessible
fields. Unknown opaque processes, visible cache references, and any compiler
still block cache reuse. The completed R30 cache was renamed, with no cache
deletion or second full cache copy. The original failed preparation remains in
the raw archive; the eight test stages were subsequently executed once.

[qualification-native.json](qualification-native.json) is the original successful
terminal. [qualification-summary.json](qualification-summary.json) binds both
preparation attempts, reports, raw logs, test audit, binaries, and source maps.
[qualified-source-match.json](qualified-source-match.json) records the full
222-input comparison with this publication checkout.

The original [candidate.patch](candidate.patch) and [input.json](input.json)
remain the pre-format inputs. [qualified-source-map.json](qualified-source-map.json)
records the final tested bytes. The transfer receipt explicitly records that
files were first fetched while qualification was running; the subsequent full
source match and successful terminal close that earlier provisional status.

## Real pidfd component on x230

The existing full cancellation helper was assembled from each side's actual
source and exercised against owned synthetic supervisor processes on x230.
The fixed experiment completed **62/62 samples**, including 48 measured samples,
12 warmups, and two lost-acknowledgment cases. Two additional already-exited
controls passed. All owned children were reaped, with zero cleanup kills.

Each measured arm/delay has eight samples. Full helper wall-time medians were:

| Fixture exit delay | R24 A | R31 B | Median reduction |
|---|---:|---:|---:|
| 5 ms | 152.923 ms | 66.192 ms | 56.7% |
| 25 ms | 151.701 ms | 88.222 ms | 41.8% |
| 65 ms | 153.674 ms | 137.186 ms | 10.7% |

This measures the Python cancellation helper with controlled supervisor delays,
including real pidfd signaling and readiness. It is not a measurement of the
whole runtime, SSH transport, six-host throughput, or saturated cancellation.
Small-sample p95/p99 values are maxima and are descriptive only. The original
summary's generic scope string is preserved; the component compact and native
receipt identify the actual execution host as x230 and clarify that scope.

[component-compact.json](component-compact.json),
[component-summary-original.json](component-summary-original.json), and
[component-evidence-01.tar.gz](component-evidence-01.tar.gz) retain the exact
results, fixture receipts, helper source, freeze, and native terminal.

## Formal performance gates

The first Mac holder job `1a1ae37dda9-fc05-5e42` closed with exit 1 before
quiescence or any measurement: the old parent retained the R30 socket prefix.
The owned temporary agent was reaped. [The original failure](preflight-failures/README.md)
and its complete logs remain preserved.

The separately frozen [campaign 02 tools](parent-runner-02/README.md) use fresh
R31 namespaces and bind that earlier failed attempt. Original Mac holder
`1a1ae66710c-fc05-5f6e` completed with exit 0 and complete durable output.
All seven parent stages completed; all 2,304 measured calls succeeded. The
parent's `passed=true` records execution/evidence completion. Its separate
`observation_gate_passed=false` and independent summary reject adoption.

C1 throughput was 7.974917871 → 7.574879420 calls/s: B/A
**0.9498379221405816**, below the unchanged **0.95** floor. C8 and C16 throughput,
all p95/CPU gates and the sampled controller RSS bound passed. No threshold was
changed and no workload was replayed. [The complete rejection](OBSERVATION_REJECTED.md)
records the matrix, cleanup, boundary and recovery results.

The original normal lifecycle materializer `1a1ae6ce842-fc05-5f8b` correctly
refused to proceed because the observation performance prerequisite failed.
It created no lifecycle inputs, parent output or ABBA output. No normal
lifecycle performance or saturated cancellation capacity result is established.
The favorable helper component remains a separate result.

[Static path review](OBSERVATION_PATH_REVIEW.md) found no direct mechanism by
which the changed cancellation code enters the timed status/read payload or
adds full-file verification work. That finding does not explain away the C1
result or attribute it to code, network or machine conditions.

[The complete original observation archive](observation-evidence-01.tar.gz)
retains both observation attempts, every measured call, resource and compiler
samples, boundary/recovery outputs, original tools, holder receipts, and the
downstream lifecycle refusal. Its manifest and compact sidecars preserve the
failed gate separately from successful execution. R24 remains accepted.

## Supplemental exact CI and historical Python evidence

[Exact Rust CI attempt 02](exact-ci/README.md) executes the published workflow's
`cargo check --locked --all-targets --all-features`, complete nextest inventory,
and nextest run with version 0.9.137, one test thread and zero retries. Its final
outcome is recorded separately from the original eight-stage qualification.

The original native job `1a1ae572e9e-fc05-5f26` passed, finishing at
`2026-11-06T00:57:21.474789+00:00`. All six version/check/list/run stages returned
zero. The exact inventory and raw nextest output reconcile to **1653 passed,
0 failed, 34 ignored, 1687 selected, 0 retries**, with 1653 ordinary `PASS`
statuses and no nonplain successes. Every owned process/group closed; the
qualified compiler inputs remained unchanged. The original report, terminal and
read response are under [exact-ci/results-02](exact-ci/results-02/).

[exact-ci-evidence-01.tar.gz](exact-ci-evidence-01.tar.gz) retains the original
plan, both tool versions, all stage logs and the preserved preflight failure.
The archive's launch response timed out at the MCP transport layer; a read-only
inventory/status/log reconciliation identified the original archive job
`1a1ae627343-fc05-5f57` as succeeded. The start request was not replayed.

The first CI planning attempt stopped before Cargo because the private source
snapshot's workflow differs from the published workflow: it lacks the two later
Python discovery commands. Attempt 02 preserves that original file, binds the
published workflow by SHA256 and Git blob, and changes no qualified compiler
input. The full preflight failure is retained with the observation failure.

[The Python reuse proof](python-closure-reuse/README.md) checks all 85 historical
Python dependency inputs and modes against fixed published R31 commit
`c039688312ceb09b3d26d1cdd50f9118eb11129f`, together with the original successful
18-command execution and complete raw logs. It is a same-input historical proof,
not a new R31 Python execution or a claim about the whole private source tree.
Neither this proof nor native exact-command execution marks hosted GitHub Actions
or the prospective merge as passed.

The [native originals companion](r31-native-originals-companion-01.tar.gz)
adds the exact outer qualification, component and failed-preparation streams.
Its [independent verification](native-originals-companion-verification-01.json)
checks all 20 members, stream offsets and terminal byte counters, all eight
qualification stages, and the complete 222-input source map.

## Verified raw evidence

| Archive | Bytes | SHA256 |
|---|---:|---|
| [qualification-evidence-01.tar.gz](qualification-evidence-01.tar.gz) | 1251141 | `f802c5fed5e3b79773825a12cbe9c888570e3ea19f954009857350e93c8071d2` |
| [component-evidence-01.tar.gz](component-evidence-01.tar.gz) | 262385 | `bf5446e7cda85580b6f32c8caaf7217dc56c7864dafbcb5ee0cddef16d093f74` |
| [exact-ci-evidence-01.tar.gz](exact-ci-evidence-01.tar.gz) | 326815 | `2d2fd850b04e3e31374c0336f48f7e9d66f0589e4d04764e88a5b913444d6c91` |
| [r31-native-originals-companion-01.tar.gz](r31-native-originals-companion-01.tar.gz) | 18855 | `451ad971ab9d1d05db6c0ee6a201edf8d6383134a2730b35f694ce239f1e379e` |
| [observation-evidence-01.tar.gz](observation-evidence-01.tar.gz) | 3150234 | `b3e443d4a871b7d77f809d55b161be0e29ced8c722382a7a68bba66668a610d5` |

The generated archives were read back with fixed file versions, checked chunk by chunk, and then
verified against full archive and member hashes without extracting or executing
archived programs. Credentials and executables are excluded from the qualification
archive. The `parent-runner` directory preserves the exact five measurement
scripts and sealed bundle manifest. Archiving did not rerun any test or benchmark.
