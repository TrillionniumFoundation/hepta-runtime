# Current100k signal, pooling and readout constraints

`experiments/weight/current100k_signal_diagnostics.py` compares sixteen fixed
development readouts per chronological fold. It fits only the declared earlier
rows and scores the same later rows for every arm. These labels have already
been viewed; chronological splitting does not make them an independent future
test. Every arm is retained and no winner is selected or deployed.

The implementation addresses three different questions: whether a frozen
representation contains a useful readout signal; whether the pooling contract
changes that signal; and whether the allowed parameter set limits the readout.
It does not infer a damaged encoder layer from a nearly constant output.

## Fixed comparisons

| Family | Comparators | Role |
| --- | --- | --- |
| Reference and calibration | Frozen parent, fit-segment mean, fit-segment median, fit-segment bias calibration | Check whether a complex candidate improves on simple offsets |
| Signal and pooling | Closed-form ridge and short SGD for each of four representations | Same input identities and time cuts; fit-only preprocessing |
| Raw-coordinate constraints | Ridge and SGD in the absolute parameter ball; ridge and SGD in the parent-delta ball | Same raw features and objective, separately defined admissible sets |

The four representations are original masked-mean/L2 pooling, the original
action-token pool, a fixed equal-group pool, and eight input-only market scalars.
The equal-group pool is

\[
\operatorname{normalize}\left[
 (u_{quotes}+u_{template}+u_{action})/3
\right].

Each `u` is the original final-stage group pool after L2 normalization. The
template group includes the action, so this is a declared reweighting, not a
partition into three disjoint groups. It keeps the same 768-dimensional output
and 769-parameter head as the original and action-only representations. It
does not silently triple readout capacity by concatenating three pools.

The structured baseline has nine readout parameters. Its eight columns are the
action sign, current quoted spread, signed whole-history return, signed last-five
interval return, signed last-interval return, RMS interval return, quoted range,
and quote age. It reads the original prompt's quote history and refuses crossed,
nonfinite, unordered or future-known quotes. Execution prices, future closes,
fees and realized labels are not inputs.

## Chronology and label availability

Each fold declares `fit_before_ms`, `score_start_ms`, `score_end_ms` and
`embargo_ms`. Score intervals are disjoint. Fitting requires both the original
request and the availability evidence for its label to precede `fit_before_ms`.
Unresolved or later-known fit-period labels are purged and listed, not silently
moved to an earlier time. The same original request cannot occur in both sides.

The runtime accepts an exact declared label-resolution time, or an explicitly
labelled conservative upper bound from original accounting replay:

```json
{
  "row_id": "ORIGINAL_ROW_ID",
  "request_id": "ORIGINAL_REQUEST_ID",
  "input_started_at_ms": 100,
  "label_available_by_ms": 200,
  "label_time_basis": "VERIFIED_ORIGINAL_ACCOUNTING_ASOF_UPPER_BOUND"
}
```

The second form never creates `label_resolved_at_ms` or claims first-known time.
An upper bound equal to the fit cutoff is still purged. The report preserves the
original metadata and marks this basis as non-exact. Source replay is the input
preparer's responsibility; the numerical runner does not authenticate a clock
by inspecting a feature tensor.

For the current 54-row source, the original dataset has no per-row settlement
timestamps. First execution and commission timestamps alone are insufficient:
the original accounting owner also requires a valid terminal witness for each
command. A chronological replay must therefore use its existing settlement
logic, including original correlation/epoch bindings, and match the complete
execution and fee contents to the frozen row. A close time or the current
inspection time is not substituted for missing historical proof.

`prepare_current100k_signal_inputs.py` implements that qualification. A pinned
request names the original dataset, features, labels, head, final-layer binding
and report, all per-row layer receipts/tensors, period configuration, immutable
OMS capture, original accounting module and numerical runner. Its original
feature text must be reproduced exactly from the corresponding original request
and action. Self-consistent replacement text and hashes are insufficient.

```sh
python -B experiments/weight/prepare_current100k_signal_inputs.py \
  --request REQUEST.json --request-sha256 REQUEST_SHA256 --output NEW_DIRECTORY
```

The output `ready.json` binds `features`, `labels`, `head` and `rows` artifacts,
the fixed chronological folds, available fit counts, cache parity and final
source-integrity checks. Only qualified outputs proceed to the numerical runner.
The preparation retains failed replay and source checks, and never overwrites a
prior output directory. The exact CLI request and source files are rehashed at
the end.

## Preprocessing and constraints

Signal/pooling ridge and SGD use the same means and standard deviations fitted
only on the fitting rows. Scoring rows never affect preprocessing. Constant
columns use scale one. Stored transform tensors are part of each fold's output.
The ridge objective in standardized coordinates is a particular model class;
it is not claimed to be the same as ridge in raw coordinates.

For the constraint comparison, both methods use the unchanged raw original
features, include the intercept in the parameter norm, and share the objective

\[
\frac1n\sum_i(a_i^T\theta-y_i/100)^2+
\lambda\|\theta-p\|_2^2,
\qquad \|\theta-c\|_2\le r.
\]

The regularization center `p` is zero for **both** raw constraint groups.
The absolute ball has `c=0`; the parent-delta ball has `c=theta_parent`.
Their radii are separately declared. This avoids accidentally changing the
regularization prior while attributing the result entirely to a constraint.

Closed-form ridge uses thin SVD and a scalar Lagrange multiplier to solve the
constrained objective. It does not radially clip the unconstrained fit and call
that the optimum. The solver includes the nullspace term when the constraint
center differs from the regularization center. SGD uses the same objective and
projects around the same constraint center after each update.

Changing feature scale while leaving a numerical weight cap fixed generally
changes the admissible functions. Reports therefore state parameter coordinates,
both centers, radius, stored norm and equivalent raw-coordinate parameter norm.
The standardized signal arms have no asserted equivalence to the raw norm balls.

## Fair short-SGD cost

The plan gives each SGD construction a two-second soft wall-time budget and a
hard cap of 8,192 steps.
A fixed input-only Lipschitz rule caps the declared learning rate to avoid
making a wider or more correlated representation unstable by construction.
Its calculation, parameter allocation and optimizer creation count in that
candidate's elapsed time. Setup, an operation already running at the deadline,
and final cloning may finish after that deadline; an over-budget construction is
reported rather than erased.

One data-free optimizer-runtime initialization occurs before any candidate is
fitted. Its time is reported as shared initialization and included in the complete
experiment timer. It performs no backward or optimizer step. This prevents the
first representation from paying a one-time lazy-import cost that later
representations avoid. This is a resident-runtime comparison; it is not a claim
that cold startup is free.

Each FP32 head is saved and reloaded before scoring. The stored parameter norm
is checked against the declared ball and the explicit rounding tolerance.
At the end, the parent is recomputed on the frozen features and parameter/output
hashes are checked. This is a head-only recomputation, not a new encoder run.
The CLI also rereads all five pinned source files and retains a separate
`source-integrity.json`. Source qualification requires its passing receipt as
well as the completed numerical report.

Failures retain `started.json`, completed candidate references, wall/CPU costs,
and started/completed backward and optimizer-call counts. Interrupted calls do
not become completed steps. Output directories are never overwritten or resumed
under the same identity. Historical feature extraction, previous failed work,
model loading and Astra usage remain separate cost inputs; absent measurements
stay unknown. Use the scope-aware accounting in
[CURRENT100K_HANDOFF.md](../../experiments/weight/evaluation/CURRENT100K_HANDOFF.md).

## Interpretation and next independent comparison

The fixed diagnostic metric is raw, unclipped USD RMSE, with MAE and prediction
dispersion also reported. The prospective collector's existing +/-15 USD bound
is a different, frozen transformation. Neither transformation is silently
changed to improve a result.

Consistent later-development gains over constants can justify a new fixed
candidate family; they cannot establish future usefulness. A difference between
the original and action/grouped pools remains a representation comparison,
not proof that an internal weight tensor is defective. If simple calibration
matches a mechanism edit, the edit has not earned credit for an additional
predictive mechanism.

The active eleven-head family remains independently registered with its original
head identities and clocks. These new diagnostic outputs cannot be appended to
that family. Any prospective extension needs a separate freeze and the original
request/command, timing, completeness, overlap, multiplicity and adoption rules.
Closed-form label fitting removes gradient steps; it does not remove data fitting
or demonstrate that learning is unnecessary.
