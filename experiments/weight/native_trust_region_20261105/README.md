# Native joint update budgets

This increment adds an optional **single-patch joint L2 update budget** to
`weight_linear_ridge_plan` and `weight_guarded_linear_patch`. The planner solves a
bounded, proximal, weighted least-squares problem in F64 without gradient steps.
The guard independently verifies the numeric change represented by the actual
F32 edit bytes. A planner declaration cannot substitute for this verification.

The baseline is Runtime PR #91, public commit
`d85852b3c1708d9b2e8162badc07116999eff15e`, tree
`84f79718dda7ce1f976e6d21ad041031f4fd5c7f`. The isolated local checkout began at
`2809dc57a6ec393e4ab8e9935a047c79e66c679b`, which has the identical tree. No
production checkpoint, model pointer, runtime service, or training run is changed
by this experiment.

## Contract and mathematical scope

Both tools accept `max_update_l2_norm: number | null`. Omission and `null` retain
the preceding request commitment and unconstrained behavior; a supplied radius
participates in the request commitment. A supplied radius must be finite and
nonnegative. A constrained planner additionally requires every anchor to be
exactly representable as finite F32, so planning and the declared edit have the
same center.

The objective is the sum, over output heads, of weighted squared prediction
error plus `lambda * ||candidate - anchor||^2`, with positive `lambda`. Sample
weights may differ across heads. The constraint is one shared ball across all
heads, not a separate radius for each head. For head `j`, the centered equations
are

```text
H_j = X^T diag(sample_weights_j) X + lambda I
c_j = X^T diag(sample_weights_j) (target_j - X anchor_j)
(H_j + mu I) delta_j = c_j
sum_j ||delta_j||^2 <= radius^2
```

A common nonnegative multiplier `mu` is found by bounded bracket search and
bisection. Each solve uses Cholesky. Radius zero is a singleton feasible set;
the answer is the anchor and no finite KKT multiplier is claimed. The real
arithmetic problem is strictly convex, but the implementation reports numerical
F64 residuals, not an interval arithmetic proof of optimality.

The F64 result is lowered coefficient by coefficient toward its F32 anchor.
That operation may sacrifice objective quality. The result is independently
checked against the exact represented-number budget before it is returned.
Neither F32 optimality nor exact F64 global optimality is certified.

The guard computes the squared sum of actual `expected_hex` to
`replacement_hex` F32 numeric differences. A fixed 576-bit integer represents
that sum exactly in units of `2^-298`. The exact binary F64 radius is decomposed
and compared without floating-point squaring or an acceptance tolerance. The
width proof and arithmetic implementation are in `src/mcp/weight_norm.rs`.
The existing artifact path still authenticates the whole source SHA and old
bytes and rejects duplicate element addresses. An oversized budget proposal
fails before candidate publication.

This budget covers only the declared patch. It does not cover cumulative drift
across successive calls, a caller's separately supplied bias, or changes to a
task environment. Positive and negative zero have zero numeric difference even
though their bytes differ. The guard retains the strict primary gate
`gain > minimum_gain` and all independently declared constraints.

The existing dimensional limits, two planner workers, 30-second deadline, and
80-million-unit arithmetic admission ceiling remain. The constrained admission
model reserves bracket search, shifted factorization, triangular solves,
residual checks, lowering, exact norm checking, and final objective/KKT
recomputation. Some Cartesian combinations of dimensional maxima are therefore
refused before computation. This is an operation model, not a measured FLOP or
energy count.

## Evidence and precision boundaries

`PROTOCOL.json` freezes the local qualification scope. `RPC_PROTOCOL.json`
freezes the actual MCP cases and tolerances before running the native binary.
The independent reference uses NumPy eigendecompositions and SciPy Brent root
solving; it does not reproduce the Rust Cholesky/bisection implementation.

The public Hepta fixture originates from research commit
`2d0120e208ed81515837a7530c9f6943af03e87f`, path
`tools/hcsn/wsp_20261104/joint/fixtures/rust_fixture.json`, SHA256
`6230881d25b9511d176fefd31778a6552444e22d2c0d8a8afaa7ad40eb3975c1`.
It contains 64 original TRAIN rows, 49 features, three continuation heads, and
a frozen Belief row. The original base weights are F64. The derived fixture
explicitly serializes a new F32 source and lifts those exact F32 values back to
F64 as the common planner/reference anchor. This is not a claim that an original
F64 checkpoint is byte-identical to the derived F32 source.

The MCP qualification checks seven planner cases, absent/null/supplied request
commitments, 60 exact norm decisions, malformed-source controls, and two public
head radii. For each public radius it checks the primary TRAIN MSE gate and an
additional deliberately conflicting preservation constraint. The conflicting
constraint is an engineering rejection case, not a naturally occurring model
failure. Successful TRAIN MSE improvement is not held-out task value or new
end-to-end efficacy evidence.

The norm cases include exact boundaries and adjacent F64 radii, subnormals,
large exponent differences, signed zero, extreme finite values, and up to 1,024
edited elements. Python `Fraction` independently checks the exact binary F32
differences and F64 radius for the actual MCP calls. Failure and compile costs
must remain in the qualification records; no retry may replace its predecessor.

## Reproduction

Use Rust 1.95 and the committed lockfile. The local gates are:

```sh
cargo fmt --all --check
cargo test --locked --offline --all-features --lib weight_ -- --test-threads=1
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
cargo test --locked --offline --no-default-features --lib weight_ -- --test-threads=1
cargo build --locked --offline --all-features --bin hepta-runtime
```

The historical ignored actual-head test requires a separate fixture variable.
This increment exercises the shipped MCP interface using the included public
derived fixture and synthetic cases. The focused test filter does not imply a
pass for the complete repository test suite.

`run_local_qualification.py` runs and records the requested gates with two Cargo
jobs, one test thread, a private temporary directory, per-command timeouts, an
8-GiB address-space ceiling, and source hashes before and after compilation.
Read its `--help` before choosing an isolated target and receipt location.

The committed reference and norm fixtures can be replayed without SciPy:

```sh
python3 experiments/weight/native_trust_region_20261105/run_native_qualification.py \
  --binary target/debug/hepta-runtime \
  --fixtures experiments/weight/native_trust_region_20261105/fixtures \
  --work-dir /absolute/path/to/new-private-replay-directory \
  --output /absolute/path/to/new-replay-receipt.json
```

The binary is pinned to a private copy before use and reverified afterwards.
The runtime configuration disables host execution. All edited artifacts are
derived disposable fixtures. The output directory and raw receipts contain
local paths; publish the explicitly sanitized evidence, not the private replay
directory. `prepare_reference.py` regenerates the independent references from
the pinned original fixture and requires NumPy and SciPy.

## Remaining boundaries

This increment does not authenticate a complete neural-network graph, infer
circuits from weights, establish independent holdout improvement, select the
right environment law, qualify interruption recovery, or replace production
state. Normal-return rejected artifacts are restored and verified byte for
byte. Durable evaluation journaling and recovery from interruption require a
separate implementation and qualification. Subsequent Bellman planning is also
a separate increment and cannot inherit the evidence recorded here.
