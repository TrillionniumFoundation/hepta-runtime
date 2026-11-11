# Native planning and guarded evaluation for small weight edits

This extension adds two bounded research operations to the existing native
weight workbench. `weight_linear_ridge_plan` computes a supervised, proximal
weighted least-squares proposal in Rust. `weight_guarded_linear_patch` evaluates
one exact edit of an F32 linear tensor, checks its declared constraints, and
attempts exact reverse publication when the candidate fails. Neither operation
activates a model or qualifies a production policy.

The existing workbench already supplied safetensors inspection, exact element
patches, immutable artifacts, reverse patches, native linear inference and
resident Python workers. Those capabilities are dependencies, not new results
of this change. This extension makes a small planning/evaluation loop executable;
it does not add a complete Rust transformer or Hepta Neuron graph interpreter.

## Separate the mathematical claims

For fixed features X, initial head theta0, targets y and nonnegative sample
weights D, the planner solves each output head independently:

\[
\min_\theta (X\theta-y)^T D(X\theta-y)
              +\lambda\|\theta-\theta_0\|_2^2,\qquad\lambda>0.
\]

\[
\theta=\theta_0+(X^TDX+\lambda I)^{-1}X^TD(y-X\theta_0).
\]

Positive regularization makes this fixed quadratic strictly convex. Cholesky
solves its normal equations without gradient steps. A residual check and a
finite F32 conversion check bound what the tool claims numerically. This is
**closed-form supervised fitting**: it consumes training targets and does not
establish that an agent understands an arbitrary network's internal circuit.
The unique minimum of this quadratic is not a global minimum of task loss or a
globally optimal NDU policy.

The planner accepts caller-supplied numeric matrices. Its exact-edit bytes use
the F32 conversion of the supplied initial weights. It does not authenticate
those initial weights against a checkpoint. The subsequent guarded patch
requires the complete file SHA-256 and exact expected bytes, and performs that
source check before any candidate can be admitted. A caller must preserve this
boundary rather than treat a mathematical plan as an authenticated model edit.

## Planner interface

`weight_linear_ridge_plan` accepts:

- `features`: n rows by p frozen features; append an explicit constant feature
  if a bias is to be edited.
- `targets` and `sample_weights`: n by o matrices. Weights are per output, so
  illegal or unavailable actions can have zero weight without changing other
  action heads. There is no implicit normalization.
- `base_weights`: o by p initial parameters.
- `lambda`: the positive proximal regularizer.

The operator bounds dimensions and arithmetic work, validates finite inputs and
nonnegative sample weights, and uses a bounded blocking-worker admission. Its
receipt distinguishes F64 solutions from rounded F32 parameters, includes
normal-equation residuals and objective values, and identifies supervised target
use. It returns a proposal; no source file, model artifact or active pointer is
written by this operation. A bias constant and its regularization are part of
the caller's declared objective.

## Guard interface and score semantics

`weight_guarded_linear_patch` accepts the existing `PatchTensorParams` under
`patch`, fixed `inputs`, optional explicit `bias`, an `objective`, nonnegative
`minimum_gain`, and up to 32 `constraints`.

The `squared_error` objective uses a `targets` matrix matching the supplied rows
and all output columns. Its score is negative mean squared error, averaged over
both rows and columns. The `action_value` objective takes distinct
`action_columns` and a `values` matrix with one realized payoff per listed
action. Argmax of the model outputs selects an action; ties select the first
listed action. The score is the mean of its supplied payoffs. The payoff matrix
is used only by the evaluator, never passed to linear inference. Payoffs must
already account for the task's relevant costs.

The action-value mode evaluates decisions on a fixed supplied set of states and
payoffs. It is not a rollout engine: editing a policy can change its future state
distribution and continuation values. A whole-task NDU evaluation must recompute
those dependencies outside this bounded operator. Caller-provided action values
do not automatically become counterfactual ground truth.

Acceptance requires all of:

1. The exact source and declared tensor pass the existing native checks.
2. Baseline labels, shapes and constraint definitions are valid.
3. The candidate forward operation succeeds and every result is finite.
4. Every declared candidate constraint holds on every supplied row.
5. Candidate score minus baseline score is **strictly greater** than
   `minimum_gain`. A no-op or a tie is not an improvement.

For sequential edits, the authenticated source must be the current incumbent.
The baseline forward is evaluated from that same source. An agent must not keep
comparing a composite edit against an older, weaker checkpoint and attribute the
older improvement to a newly added component. This tool binds a request to its
declared source; it does not maintain an authoritative production incumbent.

Source constraint violations are returned for diagnosis. A baseline violation
does not prevent a candidate from repairing it; the candidate must satisfy all
declared constraints. No constraint is silently weakened to obtain acceptance.

## Mathematical constraints and their limits

| Constraint | Checked relationship | What it does not establish |
| --- | --- | --- |
| `range` | A selected output lies in the closed interval | Calibration, causality or behavior outside the supplied rows |
| `complement` | Two selected outputs are in [0,1] and sum to one within tolerance | Monetary put-call parity; competing first-exit probabilities when surviving mass remains |
| `terminal_q` | Belief is in [0,1], STOP=0, SUBMIT0=1−2p, SUBMIT1=2p−1 | Correct belief, correct terminal reward definition or optimal continuation values |
| `preserve` | Selected output changes by at most the stated amount | Preservation on unobserved feature directions or whole-model capability |

The `complement` DTO retains field names `call` and `put`; those names do not
change its mathematical premise of mutually exclusive, exhaustive probability
events. For an absorbing process, survival + first-up-exit + first-down-exit is
one; the two exit probabilities alone generally do not sum to one. Expected
monetary option payoffs require the appropriate put-call parity, not this check.

All checks in this tool are finite-row checks. Analytic parameterization of a
valid CTMC generator, reset kernel or probability distribution can guarantee
properties over a broader domain, but no such graph-level compiler is added
here. Constraints must match the actual model semantics and units.
The guard does not have a parameter-norm or trust-region constraint. An
experiment requiring either must independently verify it on the exact candidate
bytes before using this tool; output constraints are not a substitute.

## Artifacts, recovery and interruption

The guard reads the original model through the existing confined descriptor and
pins its complete content identity. It publishes a separate immutable candidate
using `weight_artifact`, then evaluates that artifact. The original file and any
live model pointer remain untouched.

If the candidate score or constraints fail, or if candidate inference fails,
the guard attempts a reverse artifact. It verifies both its full SHA-256 against
the original and its outputs against the already evaluated baseline. Outcomes
are explicit:

| Outcome | Meaning |
| --- | --- |
| `accepted_on_supplied_rows` | Score and declared constraints passed on these rows only |
| `rejected_and_restored` | Candidate rejected; a reverse artifact was created and original hash and outputs were verified |
| `rejected_recovery_unverified` | Candidate rejected; recovery did not complete or could not be verified |

The last state is a real failure state, not a successful rollback. For example,
retained interrupted stages can leave room for a candidate but no room for its
reverse artifact. Tests exercise this exact quota boundary.

These artifacts are isolated replicas. The term recovery does not mean a live
model was changed and subsequently rolled back. The evaluator also has **no
durable evaluation journal**. Request cancellation, process death or timeout
after publication can leave a candidate without a final evaluation receipt.
The source is still untouched, but the evaluation outcome is unknown. Reconcile
the identical source, exact patch and complete evaluation request; never infer
acceptance from an artifact's existence. Existing artifact idempotency supports
that reconciliation, but restart/cancellation recovery is not qualified here.

The deterministic evaluation ID hashes the complete serialized request,
including labels and constraints. It does not certify independent data origin,
prevent an adaptive agent from reusing validation labels, or prove that a
claimed holdout was unseen. The receipt explicitly reports
`independent_holdout_verified=false`, `production_eligible=false`,
`end_to_end_cost_known=false`, `interruption_recovery_verified=false` and
`durable_evaluation_receipt=false`.

## Resource and numerical boundaries

Native guard inference retains the existing linear limits: 1–64 rows,
dimensions at most 4096, at most 1,048,576 weights, 16,777,216 multiply-add pairs
and 16,384 output values. The exact patch touches at most 1024 elements. The
guard caps its additional canonical serialization at 1 MiB before that buffer
grows further; transport deserialization has already occurred. It does not
claim the same cap for every transport allocation.

Inference uses sequential F32 accumulation. The planner uses F64 arithmetic and
then exposes F32 rounding explicitly. F64 model checkpoints require a declared
lowering step and numerical qualification; they cannot be described as bitwise
equivalent to the F32 operator. Full-file hashing, artifact publication and
reverse verification are included in `native_operation_wall_seconds`.
Checkpoint acquisition, feature extraction, solver search, held-out rollouts,
LLM usage, compilation and energy are separate costs.

## Verification

Verify the declared source and public evidence files without running inference:

```sh
python3 experiments/weight/native_guard_20261104/verify_publication.py
```

Use the toolchain versions recorded in the
[software qualification](../experiments/weight/native_guard_20261104/qualification.json)
and the unchanged `Cargo.lock`. The following commands assume the locked
dependencies are already cached. The recorded complete-suite configuration uses
one test worker and a short private temporary directory outside the source checkout;
the shell tests intentionally distinguish external scratch space from the
worktree. On the qualified Linux host:

```sh
cargo fmt --all -- --check
wsp_test_tmp=$(mktemp -d /tmp/hw-XXXXXXXX)
TMPDIR="$wsp_test_tmp" cargo test --locked --offline --all-features -- --test-threads=1
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
```

The qualification retains the initial default-parallel failure and every later
partial or cancelled run. Serial qualification does not establish that the
repository's shared-state tests are safe under arbitrary concurrency. A fixture
fix gives the publication-order test its own audit subdirectory; it preserves
the production parent-directory identity check and all original assertions.
The short temporary prefix also leaves room for OpenSSH's temporary control
socket name; the production path-length check remains enforced. A maintenance
test that initializes the process-global runtime configuration is isolated in
the existing bounded child-test helper so it cannot change later legacy-server
tests' mode. Its original asynchronous checks are retained.

The existing shipped-MCP CPU integration test is extended with positive and
negative guard cases, including independent PyTorch loading of the resulting
artifacts and full-byte recovery. It is intentionally explicit about its
external environment:

```sh
HEPTA_WEIGHT_TEST_PYTHON=/absolute/path/to/existing/venv/bin/python \
  TMPDIR="$wsp_test_tmp" \
  cargo test --locked --offline --all-features --test weight_forward_external \
  -- --ignored --test-threads=1
```

No package installation occurs in that test. Unit cases cover true improvement,
no-op rejection, harmful edits, F32 overflow, invalid labels and indices,
unpinned sources, request size, preservation/terminal constraints, action-value
label isolation and exhausted recovery quota. Tests of synthetic examples are
software qualification, not evidence of a new task capability.

## Relationship to weight-space programming research

The separately pinned [MIT replay](../experiments/weight/mit_wsp_replay_20261104/README.md)
reconstructs and evaluates published MinAtar weight programs and audits the
original editor's token usage. It does not reproduce the original LLM's search,
establish a general ability to read arbitrary networks, or show superior total
cost to training. Research candidates need independent generated-output/task
evaluation and matched baselines before making those claims.

A future full system needs a graph-to-mechanism map, causal interventions,
identifiable parameterization, feature/label provenance, independent evaluation
budgets, durable request reconciliation and complete task-cost accounting.
This extension supplies a narrow executable component of that system while
keeping those unimplemented capabilities explicit.
