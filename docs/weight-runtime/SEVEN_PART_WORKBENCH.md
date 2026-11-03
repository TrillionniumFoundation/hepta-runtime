# Seven-part weight workbench

The later [blocker closure record](BLOCKER_CLOSURE_20261103.md) contains the
214-test qualification, complete eleven-head bundle, strict original-window
ineligibility and separately registered live research family. Earlier execution
snapshots below remain historical evidence.

This extension connects task-specific model observation, mechanism diagnosis,
controlled edits, independent assessment and cost comparison through the existing
resident weight worker. It adds Python providers and experiment clients. Rust
ownership, durable request identity, worker admission and the existing MCP tools
continue to own managed sessions.

## Responsibilities

| Responsibility | Implementation | Evidence boundary |
| --- | --- | --- |
| Task adaptation | `laya` classification and `current100k_value` USD regression | Separate text, outputs, units, pooling and task identities; regression rejects softmax. |
| Model/input observation | Pinned source/base/head, actual token hashes and resident cache | Same encoded inputs; logical forwards and encoder work are counted separately. |
| Astra diagnosis | Structured hypothesis and diagnostic digests | Statement, expected observation and falsifier are retained; declarations are not verified causal conclusions. |
| Controlled experiment | `weight_runtime/mechanism.py` | Fixed doses, seeded controls, post-storage norm checks and uncached parent recomputation. |
| Candidate construction | Existing typed patch, safetensors reload, scope/norm measurements and seal | Actual dtype, physical/effective changes; research sealing grants no adoption authority. |
| Independent evaluation | Current100k ordered-outcome handoff; existing Laya Brier path | Original registration, request/command/timing lineage, population and statistical rules. |
| Adoption and costs | Shared-feature baselines, receipt-backed cost import, existing HeptaTrader owner | No automatic selection; unmeasured cost and future usefulness remain unknown. |

## Research sequence

1. Choose the task adapter and freeze the model, output semantics and input-only
   development rows. Open a bounded resident session. Reward-bearing rows are not
   model inputs.
2. Inspect a bounded weight block and necessary activation summaries. Record a
   hypothesis, predicted effect, falsifying observation and diagnostic digests.
3. Predeclare input cases, doses, random controls, outputs and total budgets. All
   delta payloads are fixed before the first forward. Each candidate is compiled
   and reloaded before its child forward; results do not choose later doses.
4. Compare exact `model_input_id` values. Check effective and physical norm
   matching after dtype rounding. Report failed controls without adaptive retries.
5. Restore the parent, recompute its encoder without cached features, and verify
   touched parameter hashes and output bytes. Preserve the original receipts.
6. Seal against the intended evaluation protocol and actual information cutoff.
   New edits cannot enter an already frozen candidate family or inherit a prior
   seal time. Future evidence belongs to its separately registered evaluation.
7. Compare alternatives and measured costs; pass verified evidence to the existing
   HeptaTrader adoption path. The workbench cannot issue acceptance or trade
   authority.

## Current100k contract

Each original text is tokenized and encoded separately without truncation, up to
2,048 tokens. Attention-mask mean pooling is followed by FP32 L2 normalization.
Vectors are then concatenated before one batch 768-to-1 Linear head call:

```text
features = normalize(masked_mean(encoder(single_row_tokens)))
value_scaled = linear(concatenated_features, value.weight, value.bias)
value_usd = 100 * value_scaled
```

The worker reports raw USD values. The original prospective collector retains its
separate 15 USD output bound; the handoff checks that frozen transformation.

The cache is per resident session, capped at 128 vectors / 393,216 payload bytes.
Head-only changes reuse the unmodified encoder result. Captures, interventions,
encoder changes and `bypass_feature_cache:true` bypass both cache reads and writes.
Cache hits still consume the logical forward budget. Recovery discards the cache.

## Entry points

See [CURRENT100K.md](CURRENT100K.md) for provider configuration,
[MECHANISM_EXPERIMENTS.md](MECHANISM_EXPERIMENTS.md) for fixed experiment plans, and
[CURRENT100K_HANDOFF.md](../../experiments/weight/evaluation/CURRENT100K_HANDOFF.md)
for independent evaluation and cost-receipt import.

```sh
python experiments/weight/mechanism_experiment.py \
  --config /private/open.json --config-sha256 CONFIG_SHA256 \
  --plan /private/mechanism.json --plan-sha256 PLAN_SHA256 \
  --out /private/new-mechanism-run

python experiments/weight/qualify_current100k.py \
  --model-config /private/model.json --model-config-sha256 MODEL_CONFIG_SHA256 \
  --input-rows /private/input-only.json --input-rows-sha256 INPUT_SHA256 \
  --reference-features /private/features.safetensors --reference-features-sha256 FEATURE_SHA256 \
  --reference-indices 0 1 --cpu-threads 2 --output-dir /private/new-parity-run

python experiments/weight/current100k_baselines.py \
  --features /private/features.safetensors --features-sha256 FEATURE_SHA256 \
  --labels /private/labels.safetensors --labels-sha256 LABEL_SHA256 \
  --head /private/parent.safetensors --head-sha256 HEAD_SHA256 \
  --plan /private/baselines.json --plan-sha256 PLAN_SHA256 \
  --output /private/new-baseline-run
```

The explicit baseline experiment is outside the no-training worker. Its SGD arm
performs real backward/optimizer steps and reports their count. Constants and bias
calibration are diagnostic comparators without the capped-head constraint. Ridge
and SGD share the declared absolute delta bound on concatenated weight and bias.
Fitted development scores are not independent evaluation results.

The companion HeptaTrader exporter publishes the original ordered outcome list
before assessment or terminal publication and pins its code in review provenance.
Old reviews without this export remain explicitly unverified; directory sorting
cannot recover the original order by assumption.

## Qualification on 2026-11-03

The code ran on the existing Pocket4 environment with Python 3.14.4,
PyTorch 2.13.0+rocm7.14.0, safetensors 0.8.0 and NumPy 2.4.1. Model tensors and
forwards used CPU FP32. GPU numerical parity is not claimed.

The final core snapshot passed 65 worker tests, 53 independent-evaluation tests
and 19 experiment tests. Six parity-tool tests passed after that tool was added:
**143 distinct tests** in total. The actual frozen Current100k model was also
executed separately. No Rust source changed; these results do not claim a fresh
Rust build or qualification of unrelated native-runtime changes.

### Actual model parity and edit

Two preselected original development rows, with 1,332 and 1,334 tokens, were
recomputed from the pinned source and original head. Their features were
**bitwise equal** to the frozen reference, with maximum absolute difference **0**.
Tolerances `atol=2e-6`, `rtol=2e-5` were fixed before execution.

A real FP32 bias edit of 0.01 produced the expected approximately 1 USD change;
the realized scaled delta was 0.010000001639127731. The child reused features.
The final parent recomputed both encoder rows and restored original parameter
hashes, features, USD values and output bytes. Source files and the source head
were unchanged. The complete parity run took 13.642 seconds including admission,
load, probes, persistence and cleanup.

### Fixed mechanism screen

Three predeclared doses and two seeded random controls targeted the 768 head
weight coordinates. The full dose removed half the head projection along the
normalized mean direction of the frozen development features.

| Condition | Changed coordinates | RMS USD output change |
| --- | ---: | ---: |
| Zero dose | 0 | 0 |
| Half dose | 768 | 1.27212231 |
| Full dose | 768 | 2.54424558 |
| Random control 0 | 768 | 0.00447607 |
| Random control 1 | 768 | 0.00527021 |

Both controls matched effective and physical post-storage delta norms, with
relative discrepancies below 5e-10 under the predeclared 1% tolerance. The
reference delta L2 was 0.025495161437170014. The run used **14 logical forward
examples, 4 actual encoder examples and 10 cache hits**, with no backward or
optimizer steps. It took 8.966 seconds after open, including 8.804 seconds of
measured model forwards. The uncached parent restoration passed.

Larger output movement does not mean smaller prediction error. The controls are
explicitly orthogonal to the proposed delta; that construction partly explains
their response difference. This run had one batch case containing two rows, so
`case_variation_rms` is zero by definition along the case axis. It does not measure
within-batch prediction dispersion.

### Shared-feature baselines

All 54 labels were previously viewed and remain development data. Scores below
use saved/reloaded FP32 heads and raw USD outputs. Capped methods used an absolute
concatenated weight/bias delta limit of approximately **0.00721934**, equal to 10%
of this parent head's norm. The earlier study used an absolute 0.1 bound; these
two experiments must not be pooled or labelled with the same cap.

| Method | MAE USD | RMSE USD | Prediction std USD | Gradient steps |
| --- | ---: | ---: | ---: | ---: |
| Parent | 16.786469 | 23.379921 | 0.005976 | 0 |
| Constant mean | 16.335332 | 23.265109 | 0 | 0 |
| Constant median | 16.167994 | 23.373604 | 0 | 0 |
| Bias calibration | 16.334965 | 23.263678 | 0.005976 | 0 |
| Capped ridge delta | 16.783405 | 23.375605 | 0.009051 | 0 |
| Capped short SGD | 16.562240 | 23.300100 | 0.007488 | 8,192 |

The complete six-head comparison took 0.801 seconds using existing features. It
excludes shared encoder extraction and Astra diagnosis/implementation effort.
This does not establish an end-to-end speed advantage for direct editing. Ridge
projects its unconstrained solution onto the declared norm ball; it is not claimed
to solve the optimal constrained problem. Simple constants remain strong controls.

## Adoption boundary

The existing Current100k candidate family and original future window are
preserved. These new mechanism candidates and head baselines are development
artifacts, not new members of that frozen family. The source evaluator keeps its
timing, completeness, coverage, support, fee-stress and statistical requirements.
Pending or incomplete future evidence cannot become an improvement/adoption claim.

The companion exporter was executed once in a separately pinned research release.
The complete current replay contained three original commands, all CENSORED, and
zero observed trades. Its state remained PENDING. Export and independent runtime
import succeeded while original plan/configuration/head hashes stayed unchanged.
A second, cost-aware import attached 16 deduplicated operation records, including
one explicitly unresolved cost-aggregation request with unknown consumption.
Shared historical encoding was counted once. End-to-end wall time and Astra
tokens remain unknown; no speedup is inferred from missing measurements.

Generic code and tests belong in Git. Original prompts, labels, request/command
IDs, weights and full host receipts remain in the private experiment directory.
