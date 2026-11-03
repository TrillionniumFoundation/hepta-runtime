# Current100k future-window readback: 2026-11-03

The independently registered eleven-head family is running on Pocket4. A natural
eligible request has now produced its first shared-feature publication with fresh
head and durability timestamps. The latest retained new-family strict readback,
as of **12:07:46.088 EST**, records **two original opening commands and two
observed results**. The earlier **11:26:51.575 EST** readback recorded its first
command and observed result. The source-study readback at **11:27:37.798 EST** records ten
commands and six observed results, retaining its three previously proven
permanent misses. This closes the earlier
uncertainty about service activation and first live cross-plan publication, and
the new trade population is no longer empty. Two observed results do not
establish future predictive benefit, completed coverage, or final eligibility.

## Fixed registration and service state

The readback used the existing research services and pinned files. No service was
restarted, no registered candidate was replaced, and neither the trading owner
nor an existing study was modified.

| Event | UTC | America/New_York (EST, UTC-05:00) |
| --- | --- | --- |
| Registration | 2026-11-03 15:44:25.673 | 2026-11-03 10:44:25.673 |
| Input start | 2026-11-03 15:49:25.673 | 2026-11-03 10:49:25.673 |
| Input end | 2026-11-17 15:49:25.673 | 2026-11-17 10:49:25.673 |
| Settlement deadline | 2026-11-18 15:49:25.673 | 2026-11-18 10:49:25.673 |

The new input window is fixed at fourteen days, followed by twenty-four hours
for settlement. These dates are the registered boundaries, not dates rescheduled
by this readback.

New plan ID:
`3a365ad12cab17e3864d26501dcef0e1bb8ffdb72c2b30503cdc402ffdc219cc`.

Both new workbench services and both original source-study services were
`enabled`, `active`, and `running`, with zero reported systemd restarts. The
eleven CPU heads were ready at 15:44:28.376 UTC, before the new input start. Their
receipt records zero encoder loads and zero guard acquisitions for this shared
phase.

The snapshot beginning at 16:16:25.103 UTC and finishing at 16:16:25.756 UTC
verified unchanged before/after hashes for both studies' plan, registration,
activation, and predictor configuration. The independently read status files are
time-stamped observations, not a claim of an atomic snapshot across live files.

| Artifact | SHA-256 |
| --- | --- |
| New plan file | `66d6c95296c9bc9adb2b764d6c8366d48d528e586f5d6070c854d5926ed5402c` |
| Activated predictor configuration | `385bd3dd8dc7a968b29e5057b62aa50600f66df43df23173b5320b6ea9d3ad3a` |
| New activation | `b1250a33ad76235456934e46769c9b18bd1f51f9f8442339949029d050f09f66` |
| Eleven-head readiness receipt | `ad4bdde8de33fb5e398a5630196aa313852168bfd237ea32702cc5d5a49d9eb4` |
| Private live-readback snapshot, r2 | `d6dc82ca944bdc6707a9306ea69f7eddd3c4e4662e77a17533075425c1472a1f` |
| Private first-publication snapshot | `ca45cc37f75888aefa11a7e35f5f4323beb3a4e5fac4d34ad0bb1c6ab6a690ab` |
| Private first-publication verification | `a6118c9ffe40b0b192a32c329d69e8bdb842746a5e24e2e67f7a50c2f57d58db` |

The earlier r1 audit retains an inspector-side tuple-unpacking error. The
corrected r2 audit consumes the documented four-field ingress result. That
inspection error was not a collector incident and did not alter either study.

## First natural shared publication

The earlier 16:00:14.785 UTC ingress audit had five post-start requests, all
non-flat, and zero eligible requests. That was an accurate empty-window snapshot;
it is superseded by the later observations below, not rewritten into a success.

The bounded verified ingress capture contained 209 original requests in total.
Thirteen were after the new input start: twelve had nonzero positions and one
was eligible under the frozen flat-position rule. The capture reported zero
source issues, snapshot conflicts, retries, or busy returns. The new collector
had one request input, one terminal, one prediction directory, and zero
incidents.

At the first-publication readback, the eligible request had produced all eleven
head predictions. Its terminal was `SEALED_AWAITING_ORIGINAL_COMMAND`, with
`before_command_confirmed=false`. The snapshot found no original-command record
for that request. That snapshot establishes live shared publication; the later
strict evaluator status below supplies the separately timed trade-level result.

| Clock | UTC on 2026-11-03 |
| --- | --- |
| Original request started | 16:16:04.070 |
| Source encoder features computed | 16:16:06.509 |
| Source publication durability observed | 16:16:06.553 |
| New head attempt started | 16:16:06.719 |
| New collector consumed source features | 16:16:06.739 |
| New prediction computed | 16:16:06.768 |
| New publication durability completed | 16:16:06.775 |
| New publication durability observed | 16:16:06.776 |
| New successful terminal observed | 16:16:06.779 |
| Original nonrenewable request deadline | 16:17:04.070 |

The new feature document correctly retains the source encoder's computation
time as provenance. The new prediction and publication use later clocks from the
new collector. They do not inherit the encoder's earlier time. The source feature
proof includes the original request, attempt, successful terminal, publication,
observation, and feature hashes.

A separate read-only verification at 16:19:16.110 UTC passed all twelve recorded
identity, hash-chain, family-membership, and timing checks. The source and target
request contents are equal. The feature document, including numerical vectors
and encoding provenance, is equal after removing the new shared-consumption
metadata. All eleven heads match the frozen plan. Both successful terminals
retain the original deadline. The source observation file's timestamp is
16:16:06.553 UTC; its terminal's later durability confirmation is
16:16:06.555 UTC. Neither is used as the new head's computation time.

The source reports 2.287548061 seconds of encoder work. The new ledger's attempt
reports 59.453128 milliseconds, including its own checks and publication. These
are different nested operations; they are not an end-to-end comparison of
training against direct editing. The source work remains part of shared feature
cost, and no additional encoder execution is declared by the new consumption
receipt.

## Strict population at each readback

| Population | Original opening commands | Observed | Pending | Censored |
| --- | ---: | ---: | ---: | ---: |
| Original source study, as of 16:16:07.271 UTC | 9 | 5 | 1 | 3 |
| New family, as of 16:16:21.189 UTC | 0 | 0 | 0 | 0 |

One later settlement increased the original study's observed count from four to
five. The three permanent missing pre-opening predictions remain. The previous
`IRRECOVERABLY_INELIGIBLE` finding under the zero-unresolved rule is unchanged;
settlement does not backfill a past prediction. The old service remains in its
ordinary `PENDING` source lifecycle until its fixed deadline. That lifecycle
state is distinct from the already established irreversible comparison failure.

The new strict evaluator reports `PENDING`, complete current replay, no verified
irreversible blocker, and comparison eligibility `UNKNOWN`, with
`formal_success_possible_under_frozen_rule=null`. It records one nontrade
request and zero original opening commands at that 16:16:21.189 UTC snapshot.

### Later bounded status refresh

One final native read of the four small status/readiness files found:

| Record | As-of UTC | Original commands | Observed |
| --- | --- | ---: | ---: |
| New independent strict evaluator | 16:26:51.575 | 1 | 1 |
| Original source strict evaluator | 16:27:37.798 | 10 | 6 |

The new reviewer still reports `PENDING`, `UNKNOWN` comparison eligibility,
`formal_success_possible_under_frozen_rule=null`, and `replay_skipped=false`.
Its remaining reasons are the unfinished fixed window, incomplete time halves,
insufficient prospective trades, sign coverage, and time-block support. The
earlier zero-command state is therefore historical. The first publication's
separate snapshot still says what it observed; this later status is not used to
backfill its `before_command_confirmed` field.

At 16:27:37.406 UTC, the supervisor still reported
`COLLECTING_FIXED_INPUT_WINDOW`, both predictor and evaluator children running,
no child exits, no native stop, no selection, and zero broker orders sent by the
research service. The immutable eleven-head readiness hash remained unchanged.
The existing source study's additional command and settlement cannot erase its
three previously proven permanent prediction gaps.

| Refreshed status file | SHA-256 at readback |
| --- | --- |
| New supervisor | `6399ba2a2499c3bd41b00793475913e0295bbd65edfffe5803b7a1b13b552766` |
| New independent evaluator | `278b0c2223edf1f014a3053804f040b7aeb7a23e96436332396e565547151383` |
| Original source evaluator | `ddaad3270652eeb8e7236ab7688770448bfd187e35a8c98dd348d2c5ea13052b` |

### Final bounded refresh during the diagnostic run

An additional read of the two small live status files found **two original
commands and two OBSERVED results** at **17:07:46.088 UTC / 12:07:46.088 EST**.
The strict reviewer still reported `PENDING`, comparison eligibility `UNKNOWN`,
`formal_success_possible_under_frozen_rule=null`, and `replay_skipped=false`.
Its stated open requirements were the unfinished fixed window, incomplete time
halves, prospective sample size, sign coverage and time-block support.

At **17:08:09.072 UTC / 12:08:09.072 EST**, the supervisor reported
`COLLECTING_FIXED_INPUT_WINDOW`, with predictor and evaluator running, no child
exits, no stop, no selection and zero research-service broker orders. This later
status refresh does not replace the separately captured first-publication clocks.
No new original-source readback was made in this two-file refresh.

| Final refreshed file | SHA-256 |
| --- | --- |
| New independent evaluator | `1be680b12cba6eb23ec9dc398dadf253098dea7f5eafbc65da0cf44efa9aa60a` |
| New supervisor | `52abad1cff2b03178fd27f4429cddf64a167526dbfde8afa4f9295258104b0d8` |

The existing family still requires its fixed future window, at least twenty
observed trades, sufficient signs and time blocks, both time halves, original
coverage rules, fee-stress checks, and its declared multiple-comparison rules.
The same-producer formal-adoption restriction also remains. Neither a ready head
nor a successful shared publication removes those requirements.

## Remaining operational observations

1. The original-request, durable-publication, and original-command relationship
   must keep satisfying the strict evaluator throughout the window. One observed
   trade is initial evidence of that route, not evidence of continuous coverage.
2. The complete fixed future population and later outcomes must remain eligible
   under their original rules. Missing and late cases stay in the denominator.
3. The live source-window-end handoff must reach the existing guarded encoder
   path. The source plan's own fixed input end remained in the future at the
   latest readback; no live handoff was observed. It is distinct from the new
   family's settlement deadline. Passing hook tests do not substitute for this
   operational observation.
4. Additional mechanism controls or different pooling representations belong to
   another separately frozen comparison. They cannot be added retrospectively
   to the currently registered eleven-head family.

Private snapshots retain the complete identities and receipts. This document
publishes only the operational counts, clocks, and hashes needed to review the
conclusion. It introduces no candidate selection, actor update, trade authority,
or prediction-quality claim.

## Development label-availability audit

The retained 54-row development dataset does not contain per-row
`outcome_first_fully_known_ms`. The existing `value343_oos.settled_time()` takes
the latest first-recorded execution or commission event. That establishes an
economic-evidence lower bound; it does not by itself establish the native
accounting owner's `settlement_complete` condition, which also depends on valid
terminal, cancellation, or reconciliation evidence for all episode commands.

A time split must therefore reuse the original accounting replay. When an
original replay proves the complete bound reward at an as-of time, that time is
a conservative availability upper bound, unless an earlier fully valid replay
has also been established. Closing time, inspection time, and a global
`max_label_resolved_at_ms` value are not interchangeable with per-row first-known
time. The audit changes no accounting owner or live training rule.

## Related implementation evidence

- [Shared-feature contract and deployment](https://github.com/TrillionniumFoundation/heptatrader/blob/2be59f99272fd8c24f5cd2033817c87ce3de924a/docs/technical/current100k-shared-features-20261103.md)
- [Strict original-source review](https://github.com/TrillionniumFoundation/heptatrader/blob/2be59f99272fd8c24f5cd2033817c87ce3de924a/docs/technical/current100k-weight-strict-review-20261103.md)
- [Earlier engineering closure and preserved limits](BLOCKER_CLOSURE_20261103.md)
