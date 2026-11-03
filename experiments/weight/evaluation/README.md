# Frozen paired research evaluation

This module compares a fixed parent and direct weight edit using matched inputs,
inference profiles and calibration identities. It uses only the Python standard
library and does not load a model.

## Run

~~~sh
python3 -m unittest discover -s experiments/weight/evaluation -v
python3 experiments/weight/evaluation/paired_eval.py freeze --spec SPEC.json --out PLAN.json
python3 experiments/weight/evaluation/paired_eval.py evaluate \
  --plan PLAN.json --parent PARENT.json --candidate CANDIDATE.json \
  --outcomes OUTCOMES.json --out EVALUATION.json
~~~

Freeze creates a plan once. Retrying the same specification returns the same seal
and time; changed specifications never overwrite the original. Publications use
create-only atomic linking and directory synchronization.

## Plan

The plan binds:

- Parent, candidate, inference profile, and both calibration digests. Distinct
  calibrations are permitted only when explicitly frozen.
- Dataset descriptor and outcome-source identity. Prospective plans cannot
  predeclare hashes of unknown future labels. Retrospective replay may also
  bind the exact outcome document.
- Discovery, development and confirmation unit IDs. Confirmation cannot overlap
  recorded search inputs. Known replay remains retrospective.
- Frozen dependence clusters. Repeated inputs cannot be split into independent
  clusters to inflate support.
- Information and calibration cutoff times. Prospective inputs follow the seal,
  predictions precede deadlines, and observed outcomes follow those deadlines.
- Class count, minimum sample/cluster support, minimum useful Brier gain, fixed
  confidence/bootstrap settings and optional action-output regression limit.

The function test_paired_eval.fixture() is an executable synthetic schema example.
Its digests are deliberately synthetic; the fixture is not market evidence.

## Artifacts

A prediction document has model_digest, calibration_digest,
execution_profile_digest, dataset_digest and rows. Each row contains unit_id,
input_digest, seed, created_at_ms and probabilities. If required, it also contains
two action_probabilities.

An outcome document has dataset_digest, source_digest and rows. Each row contains
the same unit/input identity, the frozen cluster_id, and status:
observed, pending or censored. Only observed rows have a label. Prospective rows
also bind input_at_ms, prediction_deadline_ms and observed_at_ms when observed.

Duplicate JSON keys, nonfinite values, invalid simplexes, changed identities,
duplicate units, missing rows and post-seal cluster changes are errors.

## Estimator and outcomes

The primary effect is parent summed multiclass Brier minus candidate Brier.
Bootstrap sampling resamples whole declared clusters and retains all their rows.
Positive gain means improvement. Bootstrap work has an explicit upper bound.
Clusters must be defensible for the task; this module cannot infer independence.

A lower interval bound above the frozen minimum useful gain produces
ResearchGainConfirmed. Clearly inadequate gain or action regression produces
NoUsefulPatch. Insufficient support or an interval crossing the required gain
produces InsufficientEvidence. Pending/censored outcomes are counted separately.
Any pending row in the frozen confirmation set prevents a positive final claim,
even if the observed subset already meets minimum support. V1 also reports
censored subsets descriptively: without a predeclared missing-outcome estimator,
removing unfavorable or late rows must not turn an interim gain into confirmation.

Every result has production_eligibility=false and activation_authorized=false.
The deployed Hepta evaluator/selector retains its existing responsibility.
This module does not mint production receipts.

## Host-enforced separation

Run confirmation evaluation outside the editing worker. Outcome files must be
absent from the worker's allowed input roots. Freeze before release. The host
authenticates the outcome source and supplies genuine timestamps. Digests and
internally consistent timestamps cannot prove that an editor did not already
know a label. Results retain that limitation.

## Existing Laya negative control

~~~sh
python3 experiments/weight/evaluation/replay_laya.py \
  --bundle /private/path/to/astra_weight_edit_bundle \
  --out /private/path/to/replay-result
~~~

The importer verifies original input/outcome/prediction hashes and recomputes the
same-CPU calibrated Brier scores. It performs no new model forward passes and
creates no new prospective observations. Ten legacy rows are grouped conservatively
and cannot support a new efficacy claim. Original search eligibility is preserved
separately from the replay evidence verdict.

Real inputs, predictions, model weights and outcomes stay in private experiment
directories. The public repository contains code and synthetic tests only.

