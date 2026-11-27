# Source-bound sender-drive editing

This increment adds a narrow hidden-parameter plan and an independent complete-model
evaluation interface. The existing readout-only SmallHCSN profile, equations,
qualification inputs and experiment budgets remain unchanged. No real checkpoint
is included in this public source. The supplied profile manifest and its complete
SHA continue to bind private experimental inputs separately.

## Scope and owner

`weight_hidden_scope::prepare` accepts only `SenderDriveAndBias` for the existing
eight-unit, nine-input mathematical profile. Its writable coordinates are exactly
`body.input_drive.weight` (4×9 F32) and `body.input_drive.bias` (4 F32).
It does not accept raw boundary, cost, recurrent, readout, reset or architecture
changes. An allowed-coordinate list may narrow those 40 coordinates. Duplicate
coordinates, unsupported variants, nonfinite values, malformed bytes and edits
outside that list reject before owner publication.

The prepared plan checks the complete parent SHA, complete canonical header SHA,
all twelve tensor shapes/dtypes/extents, the two head aliases and contiguous,
nonoverlapping payload coverage. Every edited F32 value has exact little-endian
before/after bytes. The predicted candidate complete SHA must equal the request's
commitment. Actual admission compares the complete returned candidate with those
exact bytes; any undeclared payload, header, metadata or padding change rejects.
Actual values for the two writable tensors are decoded from the candidate.

The shared `weight_norm` implementation compares the sum of squared actual F32
differences with the exact F64 radius square. This is one combined budget over
both tensors. No continuous-proposal tolerance, dtype slack or implicit scaling
is used. Each member of the original cohort owner also receives that radius; the
global owner budget remains authoritative over the combined update.

`PreparedPlan::cohort_request` returns the existing
`weight_artifact::cohort::PatchParams`. Both tensor members are mandatory; a member
whose value should remain unchanged uses an explicit exact no-op element, which
still counts against the element limit. KEEP can normally skip publication.
The existing owner remains responsible for path confinement, quotas, its
retained concurrency owner, atomic publication, immutable inverse and restore
receipt. This module creates no alternate store or live activation pointer.

The cohort dependency commitment is the SHA of the complete typed hidden plan;
its objective commitment is the SHA of the target-source declaration. The original
caller identity fields are retained inside that plan. This makes the binding
explicit without claiming those declarations are independently proven. Source,
target or identity digests do not themselves prove training provenance, objective
validity or an execution closure.

## Closed-form drift target compilation

`weight_hidden_scope::drift::compile` takes a parent/input identity, a required
target-source declaration and at most 1,920 explicit `(query, choice, slow tick,
sender)` targets. Queries are bounded to 80; choices to two; senders to four; slow
ticks to 0, 2 and 4. Repeated locations reject. No sample, label or target is
inferred from an undeclared file.

The compiled real inverse is

\[
z^*=\operatorname{atanh}\left((\mu^*-\mu_0)/s\right),
\]

where the fixed native model's F32 constants `-0.2f32` and `0.15f32` are widened
exactly to F64 for this calculation. The target must be finite and strictly inside
that real interval. Endpoints and out-of-domain values reject; there is no silent
clipping. This is the supported *interior real law*, not a proof that every rejected
endpoint is unreachable in all F32 saturation cells.

Each result reports the F64 inverse, its F32 bytes, the scalar F32 law's realized
drift, residual and bit equality separately. `ReportResidual` permits a reported
F32 residual. `RequireBitExact` rejects if this compiled F32 scalar does not realize
the exact requested F32 value. It does not search adjacent floats and does not
claim the target is globally impossible merely because this candidate fails.

This compiler does not solve the shared multirow weight system, estimate a
gradient, or prove that future recurrent offsets remain fixed. It does not hold
cost unchanged: the existing cost law reads the same preactivation. Its output
is a local target for a later source-bound parameter solver. Allowed source kinds
are `CallerSpecified` and `PinnedExternalReference`; both remain declarations.
There is no wire variant for a proven NDU optimum. The output explicitly reports
that target truth and NDU validity have not been verified.

## Complete candidate evaluation

The independent example `weight-smallhcsn-hidden-research` accepts an absolute
request JSON path and its full SHA. Its wire operations are:

- `compile_drift`: run only the bounded scalar inverse compiler.
- `prepare_cohort`: capture the original profile, exact parent and raw input;
  admit the old profile and raw layout; return the original owner's two-member
  request and the preparation evidence. No model forward or artifact is published.
- `evaluate_candidate`: perform the same parent admission, reopen the actual
  candidate bytes, enforce the hidden plan, replace only the two decoded tensors
  in the bound model and execute the original complete six-tick kernel on raw
  input. Reopen parent/profile/input/candidate identities before publishing output.

For the latter two operations, `sources` contains `profile_path`,
`profile_sha256`, `parent_path` and `raw_input_path`. `params` is the strict
`PlanParams` structure. The preparation operation also takes `request_id`.
Candidate evaluation also takes `candidate_path` and a fresh `output_path`.
Paths are explicit research CLI inputs. They are not a substitute for MCP
workspace admission, and the evaluator does not independently prove that the
path came from a canonical owner receipt. The external experiment must bind the
actual returned owner ID/path and complete SHA before evaluation.

The example imports the existing `native_smallhcsn_profile` math and input modules
by path. It does not copy or relax the old candidate binder. That binder validates
the exact canonical parent first. The new plan then proves that candidate bytes
outside its two tensors are identical to that parent. The actual candidate values
are inserted only after that proof. Raw normalization and every physical/model
operation execute anew; a cached hidden-feature file is never admitted as input.

The result binary keeps `HCSNOUT1` and its existing features/raw-head/scores,
physical diagnostics, margin MSE and correct-count layout. The overall deadline
is 60 seconds, shared across admission, file reads, model ticks and output writes.
Pure preparation and scalar compilation additionally have a five-second bound.
All files are bounded and read with Tokio. Output is created only after complete
evaluation and source rereads; a failed partial output write removes its own file.

## Required transaction and experiment sequence

The standalone evaluator neither selects a candidate nor performs restoration.
The caller prepares the exact cohort request, asks the original owner to publish
it atomically, binds the actual owner receipt, evaluates that returned artifact,
and requests the original cohort inverse on failure or on completion of the
engineering experiment. It then reopens the actual restored artifact, verifies
the original complete SHA, and runs the original readout-only complete-model
example to compare the restored output with the original canonical output.
It must not fabricate a restored copy by subtracting an ideal delta in memory.

A later fixed train-only protocol will declare the exact hidden candidate,
allowable data, action/quality gates and transaction/forward budget before any
real model run. This is a research-record requirement within the user's existing
authorization, not a request for renewed user permission. Historical test data do
not become a new independent confirmation partition. The current readout
qualification records and their failure outcomes remain immutable.

## Authored controls and qualification status

Eight synthetic Rust controls cover actual-byte admission of both members,
cohort identity binding, extra readout edits, false expected bytes or parent SHA,
duplicate/foreign coordinates, missing members, exact F32 radius boundaries and
explicit no-ops, nonfinite/invalid bytes, expired deadlines, changed shapes or
aliases, interior inverse recovery, separate F32 residuals, exact-mode rejection,
out-of-domain targets, duplicate/invalid target clocks and unsupported NDU claims.
They do not load a checkpoint or run a model.

At source authoring, these controls and the new example have not been compiled or
executed. Local Rust 1.96 formatting is preparation only. Normal Rust 1.95
check/Clippy/nextest gates in both feature configurations remain required, followed
by a separately frozen actual-model hidden-scope qualification. No task-quality
gain, rollback execution, production eligibility or new model-call result is
claimed by source review alone.
