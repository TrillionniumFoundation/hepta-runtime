# R07 recovery parent: require actual original-child exit evidence

**Validation checkpoint: 2026-10-25 21:55 EDT (2026-10-26 01:55 UTC).**
Later experiment results require a new recorded update; this document does not
predict their outcome.

This source is the shared recovery parent for separate experimental branches
in this private repository. It corrects an observed false-success path. Its
Rust qualification is complete; final multi-host acceptance and performance
adoption remain separate decisions. The branch is not a deployment or merge.

## Problem and behavior

An original child can really exit with status 7 while another collection path
reaps its status. A later Python `Popen.wait()` can handle the resulting
`ECHILD` as a compatibility return of 0. The old normal completion path could
then publish a successful result without the child's actual successful exit.

R07 accepts only a matching raw wait result for the original child on the four
explicit post-spawn wait paths. Missing or inconsistent exit evidence retains
Unknown, a non-authoritative status and no automatic retry. It does not invent
exit 0 from a compatibility return value. Existing custody requirements,
signal-before-reap behavior and absolute output-drain budgets remain intact.
An output or terminal publication witness cannot upgrade Unknown into an
authoritative business success.

The no-further-wait statements in the fault fixtures describe explicit product
error paths. Python's `Popen` destructor may make an implicit nonblocking poll;
the experiments did not trace all interpreter teardown syscalls.

## Exact source

The parent is the published A40 commit
[`5f558594cc2a69154eb8b34c70559aa80307d0eb`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/5f558594cc2a69154eb8b34c70559aa80307d0eb),
with Git root tree `1a263824b6df67d1d8de9476a929153f67200cb3`.
Fresh read-only GitHub inspection matched the complete A40 source set to the
preserved baseline: all 165 file paths, byte lengths, modes and Git blob hashes.

R07 changes only these two source files; the other 163 compiler-input files
remain byte-identical to A40:

- `src/mcp/runtime/jobs.rs`
- `src/mcp/runtime/jobs_output_durability_tests.rs`

| Identity | SHA-256 |
| --- | --- |
| Complete 165-file source map | `4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d` |
| `jobs.rs` | `643505d2ab9468bfff8c0d62cbc679471a9bbc17a83310a5881ada6056311f44` |
| `jobs_output_durability_tests.rs` | `3ed77dbc4b4ba3480e288fe6f8c38603cbe4b65eec501069bb1163a2e93a963a` |
| Qualified release executable | `7ab8d93d00f964e7e479ee7df7d25f40ede8e364f3914d30b9fa4b7b2ff867eb` |
| Qualified test executable | `a9e4dda33eff8836a177198a428c058c4724273bda2538d088a96583152b155f` |
| Qualification report, 58,411 bytes | `ab3481a57c69177d20f4d4feff31543dbc0a32b6f07892a0553879035b928cc9` |

The source-map digest hashes UTF-8 JSON mapping source-relative file paths to
each file's SHA-256, with sorted keys and compact separators `,` and `:`. The
map includes `Cargo.toml`, `Cargo.lock`, `rustfmt.toml` and all files under
`src`. It is not a hash of the whole documentation and evidence tree.

## Completed validation on X230

Rust 1.95.0 format, format check, package-cache clean, strict
all-feature/all-target Clippy, all-feature tests and a fresh release build all
passed. The top-level tests were **1,234 passed, 0 failed, 23 ignored**:
18 owner-control tests, 1,208 main tests and 8 job-control tests. Nested child
test summaries are not counted again. The top-level suite reports 23 ignored
entries; some are subprocess-only helpers invoked by passing parent tests.
These totals do not claim execution of the ignored remote integration or manual
benchmark suites.

The full source maps matched from test input through completion. Both recorded
test and release compiler artifacts were fresh builds. Executable bodies are
not included in this documentation; their qualification receipts and compiler
events provide the retained historical identity evidence.

Separate Linux/Mac fixtures directly executed the source-derived Python
supervisor paths and established the lost-exit-status counterexample and
candidate behavior. Their scope does not qualify the final release's complete
multi-host native experiment. The latest recorded final-native attempt failed
the current-agent preflight before handoff: no native stage started. The new A44
check-only attempt at **2026-10-25 21:51:49 EDT** (2026-10-26 01:51:49 UTC)
also failed its bounded current-agent check. It requested no native handoff and
started **zero native stages**. Its exact agent identity count was not captured
and is not reported as a zero-key result. The retained report is 15,253 bytes,
with SHA-256
`06cde9a73d0e1a7013f802c8cbb37981b153198630f1dc76f206a5eb98328295`.
The check made no authentication changes, searched for no other keys and did
not rewrite the previous attempt.

At this checkpoint, A45 is a separate scheduling observation for the A42
release. It is still in progress and supplies no new native acceptance,
release build or performance result for this recovery parent.

## Measured resource tradeoff retained

Two fixed, opposite-order native small-archive blocks completed 8,848 tool
calls, including 8,192 measured calls, with all correctness checks passing.
Each source had four fresh controllers and 4,096 measured calls. This is a
64-record, C1 client verification loop, including RPC, complete oracle checks
and journal flushing; it is not saturated server throughput.

| Metric | A40 | R07 | R07 change |
| --- | ---: | ---: | ---: |
| Measured loop wall time | 31.700708 s | 33.044128 s | +4.237824% |
| Successful measured calls/s | 129.208471 | 123.955456 | −4.065534% |
| Measured controller CPU | 27.66 s | 28.93 s | +4.591468% |
| Whole-round waited CPU, a separate scope | 29.742236 s | 30.812391 s | Not used as measured-loop CPU |
| Whole-round maximum RSS | 34,796 KiB | 34,984 KiB | No memory improvement established |

Both blocks had the adverse rate/CPU direction. The experiment does not
establish a causal attribution to these two recovery files. The proposed
same-binary control stopped at its busy-host gate with zero queries; it cannot
provide a noise correction or remove these observations.

The complete outer comparison report is 117,606 bytes with SHA-256
`14ee8ddbbca4fbe31b79052e8d9f8b7c19c7bf0b2f13d1b00bcfed6e0f813a29`.
Its complete independent review is 41,438 bytes with SHA-256
`a0dfec9687ff68cfa4e4e355bc252bedac5d415fe292ea99a6b514b3248e3333`.
All failures and unexecuted acceptance stages remain part of the retained
evidence. This parent is retained for correctness review, without a new
throughput, CPU or RSS improvement claim.

## Child experiment boundaries

An archive-cohort child and an owner-publication child each have their own
source identity and validation record. A child must not inherit qualification
for its changed source merely because this recovery parent passed. Combining
the two children creates another source tree and needs separate qualification.
Neither controller restart nor controlled exception fixtures prove host reboot,
power-loss recovery or exactly-once external business effects.
