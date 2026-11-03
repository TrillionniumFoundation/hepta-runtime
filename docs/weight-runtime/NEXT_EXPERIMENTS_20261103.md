# Current100k: next experiments and training-avoidance evidence

This update implements the signal/pooling/readout comparison, adds output-matched
mechanism controls, and makes evaluation overlap and inclusive cost scopes
explicit. It also verifies the first natural publication and first observed
command in the independently registered future family.

The supported conclusion remains bounded: a frozen encoder can serve many small
heads, and closed-form fitting can avoid gradient updates. These engineering
facts do not establish that fitting is unnecessary, that the proposed patch
improves predictions, or that an alternative is cheaper end to end.

The actual development comparison found no RMSE improvement over the parent in
either time fold. Ridge and same-objective short SGD had nearly identical RMSE;
the existing directed edit mostly shifted the common mean. These findings favor
simpler readout solving and stronger prospective controls, not new internal
encoder patches. The new future family has two observed original commands at
the retained final readback and remains pending.

## P0: independent future evidence has started

The retained strict readback at **2026-11-03 12:07:46.088 EST** has **two original
commands and two OBSERVED results** for the new eleven-head family. Its input window
ends **November 17 at 10:49:25.673 EST**; its settlement deadline is **November 18
at 10:49:25.673 EST**. Both services were active. The new head's compute and
durability times are its own, later than the shared source feature publication.

The original source remains irreversibly ineligible under its zero-missing rule.
Its later **11:27:37.798 EST** snapshot has ten original commands and six observed
results; the three permanent missed pre-opening predictions remain. A settlement
cannot supply a missing earlier prediction.

The first observed commands verify an initial operational route. Fixed-window
coverage, signs, time blocks, both halves, multiplicity, same-producer adoption
restrictions and the live source-end guarded handoff remain open requirements.
See [the complete operational readback](FUTURE_WINDOW_READBACK_20261103.md).

## P1A: an actual, label-free mechanism control screen

The Pocket4 run used the original 54 frozen FP32 feature rows and the already
saved full-dose head. It did not read labels, run an encoder, optimize a head, or
alter the registered family. Its fixed recipes retained all nine conditions.
Every resulting head was saved and reloaded before scoring.
The full recipe is in [the output-control contract](CURRENT100K_OUTPUT_CONTROLS.md).

The following are raw, unclipped USD **changes from the parent output**, not
prediction errors or future gains.
The table omits the separately retained parent reference, whose displacement is
zero; `parent` and `dose-0` are separate retained conditions.

| Condition | Mean shift, USD | Total shift RMS, USD | Centered shift RMS, USD | Actual parameter delta L2 | Norm match | Output RMS match |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `dose-0` | 0.0000000 | 0.0000000 | 0.0000000 | 0.0000000 | fail | fail |
| `dose-0.5` | 1.2724947 | 1.2724951 | 0.0010429307 | 0.012747581 | fail | fail |
| `dose-1` | 2.5449896 | 2.5449905 | 0.0020858348 | 0.025495161 | pass | pass |
| `bias-mean-match` | 2.5449895 | 2.5449895 | 3.6322565e-7 | 0.025449896 | pass | pass |
| `random-norm-0` | 3.5321271e-8 | 0.0058898893 | 0.0058898893 | 0.025495161 | pass | fail |
| `random-rms-0` | -0.0000027418137 | 2.5449910 | 2.5449910 | 11.016576 | fail | pass |
| `random-norm-1` | -3.5321271e-8 | 0.0050492573 | 0.0050492573 | 0.025495161 | pass | fail |
| `random-rms-1` | 0.0000016247785 | 2.5449899 | 2.5449899 | 12.849962 | fail | pass |

The full-dose mean-shift energy fraction is **0.9999993282812015**. Approximately
**99.9999328%** of its squared output displacement is a common offset on these
frozen inputs. The bias-only control matches that offset after FP32 storage.
Zero dose exactly preserves the parent; the half dose has approximately half the
displacement.

The output-RMS random controls require parameter-delta norms **432.1046** and
**504.0157** times the full-dose norm. They qualify as output-scale controls,
not simultaneous parameter-norm controls. All joint random matches fail. Within
the full-dose edit's **768 weight-coordinate support, with bias fixed**, and the
fixed norm and cosine tolerances, the FP64 numerical upper
bound is **0.1440442233 USD**, below the required RMS lower edge
**2.4940806837 USD**. This conservative SVD/triangle bound is not an
interval-certified impossibility proof. The constraints were not relaxed.
The bias-only control lies outside that support; it has zero cosine with the
full-dose weight edit and passes both matching tolerances. The bound does not
assert infeasibility in the complete 769-parameter head space.

The initial “directed edit changes outputs, orthogonal random edit barely does”
observation is therefore explained mainly by common-mean alignment in this
sample. It does not identify predictive information or a useful internal encoder
intervention. Smooth dose response confirms output control; usefulness still
requires original outcomes in an independent window.

The final parent head recomputation recovered exact output bytes, and the
source-integrity receipt passed for all four inputs. This is head recomputation
on frozen features, not an uncached encoder restoration.

This existing full-dose head has delta norm **0.0254951614**, about **3.5315**
times the later signal diagnostic's **0.00721934184** parent-delta radius. They
are separate experiments, not a common-norm competition. The mechanism head is
not among the sixteen label-scored signal conditions below; the label-free
screen cannot establish that its predictive loss is better or worse.

| Evidence | SHA-256 |
| --- | --- |
| Mechanism numerical report | `e0f73c3f29da9795436a8254d28ba03610d2a09ae6657b6b3f517f58de2e4d09` |
| Final mechanism source-integrity receipt | `1860bd8d521d99ae9e337f859cfc359688beb93efa213111616556c7fac395e4` |
| Scope-aware mechanism cost summary | `2091b6473e2f0539dc10c9ed7f670d2161d5302adf9889401fa4de3be7947f07` |
| Mechanism test log | `56c76448130c28317f376b31803524db6eb13d8a7a257b18cead00842d15bd3f` |
| Evaluation test log | `af29e0f4f2daa7208f689c0624866999742a2c2996b9f680af70d46c91a1c85f` |

## P1B: fixed signal, pooling and constraint comparisons

The new numerical runner retains sixteen arms per chronological fold:

- Parent, fit-segment mean, fit-segment median and bias calibration.
- Ridge and short SGD for original mean pooling, action pooling, equal-group
  pooling and eight input-only structured scalars.
- Ridge and SGD in an absolute parameter ball and a parent-relative delta ball,
  both on unchanged original raw features.

The encoder representations each have 768 features and 769 head parameters.
Grouped pooling equally weights normalized quotes, template and action pools,
then renormalizes. Template includes action; this is declared reweighting, not a
disjoint partition. The structured baseline has nine parameters. Standardization
uses only the fitting rows.

Both raw constraint groups share a zero-centered ridge prior. Their constraint
centers and radii differ explicitly. Feature rescaling with an unchanged
numerical cap is not treated as an equivalent function class. Constrained ridge
solves the trust-region problem, rather than clipping an unconstrained solution.

Each SGD construction has a two-second soft wall-time budget and a hard cap of
8,192 steps. Input-based step-size capping, allocation and optimizer setup count
inside the actual elapsed time. A data-free lazy optimizer initialization is
shared and measured before the loop. Setup, an operation already executing and
final cloning may overrun the wall budget; every overrun remains reported.

The fixed primary diagnostic metric is raw, unclipped USD RMSE, accompanied by
MAE, dispersion, saved norms and costs. Every head and failure is retained; no
winner is automatically selected. Previously viewed labels remain development
data even after a chronological split.

### Original-accounting label availability

The original 54-row dataset lacks exact per-row first-known settlement times.
The preparer captures a complete immutable OMS byte prefix and replays the
original pinned accounting module before both fit boundaries and at the original
information cutoff. It checks complete executions, quantities, prices, fees,
native terminal witnesses and original request/command identities.

A matching replay supplies a **conservative availability upper bound**, never an
invented exact settlement time. Every row must also match at the final cutoff;
later corrections cannot be hidden behind earlier matches. The original journal
prefix is verified unchanged at the end; later appends are allowed.

Feature text is reconstructed from the original request and action using the
existing Current100k helper. Rehashed but unrelated text is rejected. All 54
final-layer cached rows must match their original row/text identities and mean
feature cache. No encoder is reloaded.

The fixed zero-based split indices are `[18, 36]`; scoring intervals are
`[1793113836655, 1793137465959)` and
`[1793137465959, 1793165410709)`. Labels unavailable before fitting are purged.
See [the detailed numerical contract](CURRENT100K_SIGNAL_DIAGNOSTICS.md).

Standardized heads remain diagnostic `readout.*` artifacts bound to their saved
mean/scale transforms. An equivalent raw parameter norm does not qualify a
converted FP32 deployment head or permit registering these files in the existing
`value.*` family.

## P1B actual Pocket4 results

The complete run qualified all **54** original rows through three original
accounting replays. The two folds had **18 fit / 18 score** and
**36 fit / 18 score** rows, with zero labels purged after actual availability
verification. Zero purges are an observed result, not an assumed relaxation.
The original mean cache matched every value exactly (maximum error **0**).
The final audit checked **53 source files**, **127 input/output pins**, and the
unchanged **52,720,481-byte** original OMS prefix. Data preparation and fitting
loaded no Current100k encoder.

All sixteen conditions were retained in each fold. The table contains the full
declared diagnostic family; smaller RMSE is better. These are previously viewed
development labels, not the separate prospective window.

| Condition | Fold 1 RMSE, USD | Fold 2 RMSE, USD | Fold 1 prediction SD, USD | Fold 2 prediction SD, USD |
| --- | ---: | ---: | ---: | ---: |
| `parent` | 16.988234 | 13.972075 | 0.002866 | 0.007338 |
| `constant_mean` | 27.468021 | 15.485536 | 0.000000 | 0.000000 |
| `constant_median` | 30.708451 | 16.082426 | 0.000000 | 0.000000 |
| `bias_calibration` | 27.467661 | 15.483390 | 0.002866 | 0.007338 |
| `masked_mean:standardized:ridge` | 35.123035 | 22.701000 | 26.000353 | 20.142031 |
| `masked_mean:standardized:sgd` | 35.122818 | 22.700969 | 26.000353 | 20.142021 |
| `action:standardized:ridge` | 25.814226 | 37.047646 | 16.318580 | 21.976535 |
| `action:standardized:sgd` | 25.813822 | 37.047311 | 16.318572 | 21.976454 |
| `grouped:standardized:ridge` | 24.067549 | 25.600216 | 17.001818 | 19.625228 |
| `grouped:standardized:sgd` | 24.067210 | 25.600039 | 17.001821 | 19.625176 |
| `structured:standardized:ridge` | 23.294387 | 50.103231 | 20.126385 | 48.193904 |
| `structured:standardized:sgd` | 23.294384 | 50.103191 | 20.126382 | 48.193866 |
| `masked_mean:absolute:ridge` | 18.863403 | 15.046492 | 0.004100 | 0.026907 |
| `masked_mean:absolute:sgd` | 18.863403 | 15.046493 | 0.004100 | 0.026907 |
| `masked_mean:parent_delta:ridge` | 17.409445 | 14.182414 | 0.003119 | 0.008375 |
| `masked_mean:parent_delta:sgd` | 17.409445 | 14.182414 | 0.003119 | 0.008375 |

Every newly fitted arm has higher RMSE than the parent in both folds. This is
specific to the fixed primary diagnostic metric: some second-fold arms have
lower MAE, so the result must not be generalized to every loss or metric.
The parent predictions themselves have very small dispersion; beating these
particular fitted candidates does not establish that the parent has useful
input-dependent signal or adequate absolute performance.

Action and grouped pooling improve on standardized mean pooling in the first
fold, but worsen it in the second. The structured baseline has the same
instability, with second-fold RMSE about **50.10 USD**. There is no stable gain
here that justifies an internal encoder intervention. This small, previously
viewed sample also cannot establish absence of signal in the representation.

For the twelve same-objective ridge/SGD pairs, the largest absolute difference
in scoring RMSE is **0.000403890041 USD**. Every SGD construction completed
**8,192** steps within its declared budget; twelve constructions used
**98,304** total gradient steps. Ridge used zero gradient steps. This supports
using the closed-form solution for these fixed quadratic readout problems,
without claiming byte-identical predictions, a general replacement for
nonlinear training, or predictive improvement.

The original raw constraint arms remain almost constant, while standardized
unconstrained heads produce much larger dispersion and equivalent raw norms.
A looser function class did not yield a stable scoring benefit. Constraint
geometry and useful signal are separate questions; “allow larger changes” is
not a demonstrated remedy.

The complete measured orchestration scope took **25.140706758 seconds wall**
and **24.523198 CPU seconds**, including input capture/qualification, all five
regression suites, preparation, numerical comparison and final audit. The
mechanism/evaluation run, historical computation, Astra, source editing/transfer,
interpreter startup and final cost-summary publication are outside this scope.
Nested phases are not added again. End-to-end cost and speedup remain unknown.

| Evidence | SHA-256 |
| --- | --- |
| Complete signal report | `2db7b11fe45084a0c48a3f0a3398e8d9226c20e82c5f949aabda3c294fa51451` |
| Aggregate signal summary | `f3ce66386fbba2d63a3a6ca7df664c79fb99bb25f56f1af67c46bfd3cd331504` |
| Qualified input receipt | `90f4714cffcd8f48607a1bfd2ff2fd9bb18d14039da8d1da3d4351c5c6a9e936` |
| Final signal source integrity | `0d71ec0d9bcc2c5cc847d007e16fc33b5b6e5b95204ef62f0f4fce1bf34a261a` |
| Complete invocation audit | `d50d869bae1ac39af4ec3803b486b8349b782a1ceb73c5103670566871f582dd` |
| Inclusive cost summary | `ecb67b1cd8d2e30975eda04fbcdc93f83f4fc449552edb13a79b97afb86c984e` |
| Final source inventory | `2085a53b95e41df6038aa9566449d08b0f115873b2a0866ceb7d51ed86a8bec3` |

## P2: original denominators, overlap and actual cost

The independent handoff exposes transitive overlap components on original whole
UTC-day intervals, original blocks/halves, and the full directed comparison
family. Eleven heads plus two benchmarks imply **132** directed comparisons.
Existing alpha allocation and mixture thresholds are checked against original
metadata; missing legacy metadata stays unknown. This inventory supplements the
source evaluator without replacing its decision or changing its score.

Cost input v2 binds receipts to operation identities, parent scopes and inclusive
metrics. Per metric, aggregation chooses the outermost measured scope and
suppresses included descendants. Failures remain operations. Unknown parent
measurements expose only measured subscope lower bounds. Invalid cycles,
inconsistent ancestry and ambiguous scope claims are rejected.

Actual mechanism measurements:

| Scope | Wall time |
| --- | ---: |
| Inner numerical screen after validation | 0.041043933 seconds |
| Screen subprocess, including imports/input handling | 1.285451424 seconds |
| Declared wrapper, including 14 mechanism and 72 evaluation tests | 5.419783999 seconds |

These nested times must not be added. The inner screen reports 594 completed
head examples, zero encoder examples and zero gradient steps. Wrapper CPU time
is 5.361362282 seconds. Its timer starts after initial input validation and plan
preparation, so even this outer measurement is not complete task elapsed time.

Astra inference, earlier extraction/model loading/candidate construction,
external dispatch waits and the complete failure inventory are not fully
measured. End-to-end wall time and speedup therefore remain **null**. A 41 ms
screen is not a 41 ms end-to-end alternative to training.

See [the handoff/accounting contract](../../experiments/weight/evaluation/CURRENT100K_HANDOFF.md).

## Verification and retained boundaries

Latest-version Pocket4 suites used actual PyTorch and safetensors with zero
skips:

| Suite | Tests passed |
| --- | ---: |
| Worker and parity tools | 83 |
| Candidate bundling | 22 |
| Original baselines | 10 |
| Output-matched mechanism controls | 14 |
| Signal/pooling/constraint comparisons | 18 |
| Original-accounting input preparation | 8 |
| Independent evaluation and cost scopes | 72 |
| **Distinct total across separate invocations** | **227** |

The local environment passed the focused suites; its worker suite skipped one
AF_UNIX test because that socket capability was unavailable. The actual Pocket4
worker invocation passed all 83, including the socket checks. These are distinct
latest-version tests, not sums of repeated runs or additions to the previous
214-test cross-repository release count.

The final eight changed Python files match their staged source SHA-256 values.
No registered candidate, existing scoring rule or live trading weight is changed
by these research runs. Transport timeouts were reconciled through stable job
identities when launching actual experiments; they are not counted as successful
numerical runs or as zero-cost attempts. A superseded source-only staging request
had no confirmed result and remains outside the measured scopes. Complete
earlier-failure inventory is still unverified.

## What would answer the training question

| Claim | Required evidence |
| --- | --- |
| Avoid duplicate encoder work for multiple heads | Shared feature identity plus every head's own compute/publication clocks |
| Avoid gradient optimization of this readout | A fixed closed-form/calibrated readout with acceptable independent future loss |
| Avoid all label fitting | Construction that did not fit these labels, plus the same future comparison |
| Prefer direct editing economically | Comparable future usefulness and complete cost, including Astra and failures |

Ridge and bias calibration both fit labels. Mechanistic explanation does not
replace statistical comparison or cost measurement.

The current family continues under its existing rules. Added pooling
representations and output controls require separately frozen artifacts,
transforms and future registration; they cannot be appended to that family.

A next decision comparison must retain the original model, constant/bias
calibration, closed-form fitting, equal-budget short SGD and the grounded edit.
It must use the same original requests/commands, retain missing/late cases,
handle overlap, and fix the primary loss, multiplicity rule and any practical
noninferiority margin before new outcomes. “No statistically significant
difference” alone does not establish equivalence. Equally poor arms do not
establish a useful no-training solution.
