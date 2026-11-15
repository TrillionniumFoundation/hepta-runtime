# R35: isolate legacy read JSON deferral and move the observation command

R35 is a **prepared, statically reviewed candidate**, based directly on accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`. This package has not been formatted, compiled, tested, benchmarked, or adopted. It contains two production changes and the required mutable-borrow adaptation in two existing test fixtures. No runtime capacity or security policy changes.

The first change deliberately reuses an existing R26 idea in isolation on R24. The second transfers an owned command string at its sole production consumption point. The static rationale is less unnecessary allocation and copying. Neither change yet establishes better end-to-end throughput, CPU time, latency, or RSS.

## Exact scope and package

The baseline and candidate maps each contain the same 220 compile-input paths. Exactly three SHA256 entries change:

| Path | Change |
| --- | --- |
| `src/mcp/runtime/jobs.rs` | Move the existing seven-field legacy read request into the final legacy Python branch of `read_job`. |
| `src/mcp/runtime/ssh_observation_pool.rs` | Let `execute_inner` borrow the owned request mutably and transfer its command with `std::mem::take`. |
| `src/mcp/runtime/ssh_observation_pool_tests.rs` | Add `mut` and `&mut` at the two existing direct callers of `execute_inner`; no assertion or test case changes. |

`source/` contains the complete candidate versions of those three files. `baseline/` contains their exact R24 originals, the unchanged jobs tests, Cargo manifest/lockfile, and formatter configuration. The remaining 217 inputs retain their exact hashes in `baseline-compile-inputs.json` and `candidate-compile-inputs.json`; they are obtained from the accepted source when the isolated qualification directory is prepared. This package is a source overlay on that pinned baseline, not a separate fork of all runtime files.

`candidate.patch` applies directly to R24. `input.json` includes both full maps, the patch identity, original Git blob identities, and the scope of static validation. `reference-r33-input.json` is preserved only as the published carrier of the accepted R24 map. R33 is not a source baseline here. The accepted Git root tree is `b74e40052e275abe99c51df460e94622d516af34`; its `src` subtree is `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`.

No R25/R34 cancellation reserve, R28 command cache, R30 router, R31 pidfd wait, R32/R33 path change, capacity-12 experiment, dependency update, or compiler-profile change is included. Any later combination requires a new explicit freeze and qualification.

## 1. Construct legacy read JSON only where it is consumed

R24's `read_job` creates a seven-field `serde_json::Value` before choosing a transport branch. The pooled observation branch builds a `JobObservation` directly; the system-jobctl branch creates its own request. Those branches never use the first JSON value. R35 moves the original construction, with precisely the same field expressions, into the final legacy `run_python_json` branch.

The following ordering and behavior remain:

- `check_ref_async` establishes the existing job identity before the transport choice, and host lookup occurs in its original position.
- Pooled Python observations still require the complete request digest. Pooled and direct system reads retain their original 16,384-byte default; legacy Python reads retain the original 65,536-byte default and `MAX_LOG_READ_BYTES` clamp. Offsets and explicit limit handling remain unchanged in all branches.
- In the legacy branch the same JSON fields are constructed before `bound_remote_code(READ_CODE)` and `run_python_json`, with the same 15-second transport timeout.
- The completion audit, preservation of observations after audit errors, warning/redaction rules, and pretty serialization remain byte-identical after the branch.
- The six embedded job helper constants, including `READ_CODE`, `CANCEL_CODE`, and all start/status/ownership helpers, remain byte-identical. There is no Python change.

The removed work is only construction of an unused JSON value on the other branches. Its expressions read already-owned strings/options and integer parameters; no validation, authority decision, I/O, callback, deadline, or owner-cleanup action is deferred or removed.

### Historical overlap

The jobs-only part of this patch is **byte-for-byte identical** to the published R26 selected delta, Git blob `aca7b72bab2d2241ac9ecfa86c4f71395590abcf`. It also appeared in cumulative R28. Earlier R26/R28 candidates combined this with other changes; their recorded acceptance/rejection does not isolate this JSON adjustment's performance effect. R35 must be described as an isolated reuse on R24, not a newly discovered optimization or a previously proven standalone regression.

The preserved [historical review](history/historical-overlap-review-01.json) identifies the exact original patches and branch snapshots checked. The command ownership change is absent from that checked history; this is a bounded statement about retrieved evidence, not a claim about every unpublished experiment.

## 2. Transfer the observation command at its unique consumption point

`execute` already owns a `Request`. R24 passes `&Request` to `execute_inner`, then clones `request.command` when appending it to the argument vector. This is the only production read of that field. Once that inner future returns, `execute` sends the result through `request.reply` and does not retry the command.

R35 makes the owned binding mutable, passes `&mut Request`, and uses `args.push(std::mem::take(&mut request.command))` at exactly the original push site. `take` leaves an empty String in the request and moves the original string buffer into the argument vector. There is no custom `Drop` implementation that reads the request's command, and no later production read of the emptied field. The moved vector is owned by the original `captured` call; its argument values are unchanged. This removes this particular nonempty String clone/copy. It does not imply that process construction or the whole request path becomes allocation-free.

The mutable borrow is confined to the inner future. It ends before `request.reply.send(result)` consumes the sender. Shared reborrows for admission/profile/budget checks finish before the command is taken. The renewal loop remains before the take, so no repeat of that loop can observe an emptied command. There is no new retry or dispatch path after transfer.

All admission, host/global permit acquisition, stop/cancel/deadline checks, master generation/renewal rules, full profile validations, root and socket checks, peer ownership checks, child registration, actual waits/reaping, uncertain-cleanup handling, and post-response authority checks retain their original code. The original `Captured` value still retains the global and admission leases until the caller releases it. Owner queue capacities, per-host/global bounds, and Python cancellation semantics are unchanged.

## Tests and static validation

No new runtime tests are added for a branch-local allocation or a standard String move. The only test-source changes adapt the two actual internal call sites to the new mutable-reference type:

- `renewal_fixture`, the `renew-deadline` / `renew-terminal` case, keeps its real master/renewal/deadline checks.
- `isolated_helper`, the `admission-cancel` case, keeps its bounded real fixture and verifies cancellation before any `NEVER_DISPATCH` command can be submitted.

The other `NEVER_DISPATCH` declaration belongs to a different queued fixture and remains unchanged. Test-only command clones used by controlled dispatch helpers also remain unchanged.

Existing coverage to run during normal qualification includes the queue identity/cancel/deadline/stop tests, the completed-output budget retention tests, and `isolated_actual_ssh_guard_cancellation_and_ownership_fixtures`. That isolated suite already covers renewal, actual SSH ownership/cancellation, preflight and post-response authority checks, agent timeouts, cleanup failures, and fairness/budget cases. Existing jobs tests cover retained output/cursors after audit failure, controlled unknown observations, and the real audit sync barrier. These tests have been read here; **none was executed for R35 in this preparation**. They do not constitute a standalone allocation benchmark or a new branch-by-branch performance proof.

`verify_candidate.py` is an artifact verifier, separate from the runtime compile map. It reads bytes, parses JSON, reconstructs/applies the exact unified hunks, and checks that the complete files equal only the stated edits. It also verifies all local baseline files against the accepted map, exact preservation of the six embedded helper constants, all pool test function names/assertion lines, and the historical R26 delta equality. It never imports runtime modules, invokes Rust, runs fixture code, contacts hosts, or changes source files. The original local result is `static-checks.json`. The independent review is retained under `review/`.

The source retains the existing indentation conventions. Rustfmt has deliberately not been run. A future qualification must record its actual formatted source map, compile/test results and native terminal/log receipts rather than treating this input map as a post-format map or pre-filling success/counts. The usual complete qualification, exact Rust CI, and original multi-host performance/resource gates remain required before any adoption. R34's capacity preparation is unrelated and supplies no R35 performance evidence.

## Publication state

The freeze manifest and Git blob catalog identify source-preparation artifacts only. Publishing this candidate does not make it the accepted runtime. Qualification, CI, performance results and adoption are `null`/false in the candidate input until separately recorded from actual execution. No new remote process, benchmark, compilation, fixture or permission change was performed to create this package.
