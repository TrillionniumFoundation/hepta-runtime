# Native SmallHCSN time-path diagnostic

This read-only research executable compiles the production `bound_io`, `model`,
`physics`, `matrix`, `deadline` and trace source files directly. It does not copy
the model into a second evaluator. The complete six-tick rollout remains the
source of scores and physical residuals.

The diagnostic records every query, choice, tick and neuron: normalized input,
prior centered-boundary messages, recurrent offset, drive, mark, effective drift
and cost, boundary before/after, five physical features, and receiver scores.
Effective drift/cost are held between the original QVI refreshes. Intermediate
receiver heads are observations only; they do not feed back into the model.

## Build and run

Use Rust 1.95.0:

```sh
cargo build --locked --release --manifest-path qualification/weight_trace_runtime_20261128/Cargo.toml
cargo test --locked --release --manifest-path qualification/weight_trace_runtime_20261128/Cargo.toml
```

The executable arguments are:

```text
hepta-smallhcsn-trace-research MODE ABS_PROFILE PROFILE_SHA ABS_PARENT PARENT_SHA ABS_CANDIDATE CANDIDATE_SHA ABS_INPUT INPUT_SHA ABS_NEW_OUTPUT
```

All inputs have explicit complete SHA-256 commitments. The canonical parent is
revalidated through the original profile. Output is create-only. No model,
artifact journal, runtime configuration or active service is written.

| Mode | Graph | Candidate scope | Full-model forwards |
| --- | --- | --- | --- |
| `trace` | Original | Original 40 sender drive coordinates | 1 |
| `check` | Original | Original 40 sender drive coordinates | 2, including an untraced byte-for-byte output comparison |
| `mark-control` | Original | Four input-mark weight words at indices 7, 16, 25, 34 | 1 |
| `mark-control-check` | Original | Same four words | 2, including an untraced comparison |
| `late-bridge` | Explicit modified graph | Same four words | 1 |

The parent can be supplied as the candidate. Mark-control modes verify that
every other byte is identical to that parent; the research program reconstructs
those four actual F32 words in memory. This is a scientific input contract, not
an expansion of production weight-owner admission. Normal evaluation and MCP
operations retain their original graph and edit scopes.

## Opt-in late-input graph

`late-bridge` reuses sender mark row `i-4` for receiver `i` at tick 5 only:

```text
receiver_raw_mark = dot(normalized_input, input_mark.weight[i-4])
                    + input_mark.bias[i-4] + recurrent_offset
```

It adds no parameter and does not change the QVI refresh schedule, probability
generator, reset rule or readout. It changes effective connectivity and is
reported as a modified graph. A result under this mode is not a pure weight
repair of the original graph. The original profile supplies the frozen model
parameters; it does not identify this modified program as the original model.

The trace also reports the local F64 affine expression for signed event rate,
`offset + slope * tanh(raw_mark)`, holding the pre-flow state and physical
operator fixed. Final features are rounded to F32, so this is not a bitwise
identity after arbitrary reassociation. These local coefficients are not
derivatives of the full recurrent rollout or evidence of global optimality.

## Validation scope

The sibling production-source tests verify untraced output equality, local
affine consistency, deadline rejection, and that the opt-in final mark path
changes scores while preserving probability-derived features. The standalone
suite is a scoped numerical check. The repository's full two-feature-mode
nextest, typecheck, Clippy and release gates remain separate requirements.

Scientific task protocols, holdout identities, random-edit and gradient
baselines, complete costs, and actual checkpoint receipts belong to the
experiment which invokes this executable. A trace alone does not establish
causal attribution, task quality, retention or trading utility.

## Closed semantic program and graph-aware inverse

The second executable, `hepta-smallhcsn-late-program`, invokes the reusable
`weight_smallhcsn::compile_late_quote` pure Rust module. Its `LateQuoteMinV1`
input view contains normalized inputs and baselines only. It checks that the
two choices have identical histories, equal final non-price inputs and
baselines, and distinct final prices in column 7. The original raw-input binder
checks the six-tick layout and positive normalization scales. Compilation does
not read labels, observations, objective values or gradients.

For each receiver's signed-feature head contrast `v`, the program makes the
existing price coefficient `-sign(v) * abs(parent coefficient)`, using `1/16`
only when a nonzero contrast has a zero coefficient. It leaves zero-contrast
channels unchanged, abstains when all four contrasts vanish, and changes at
most four exact F32 words. It reparses each checkpoint and records old/new bits
and file offsets; no delta is transferred between parents. Mathematical
monotonicity does not remove the need for complete F32 validation, since
saturation or cancellation can still produce ties.

Every function identity includes the complete parameter SHA-256, graph enum
and evaluator source SHA-256. Observations additionally bind the input and
phase. `PreparedLateQuote::restore` verifies the candidate identity, reverses
its exact words and restores `Original` graph. Equal parent/candidate weight
hashes alone cannot pass that inverse: a graph change can alter outputs with
zero changed weights.

The engineering executable accepts:

```text
hepta-smallhcsn-late-program ABS_REQUEST REQUEST_SHA ABS_NEW_OUTPUT_DIRECTORY
```

The request schema is `hepta.late-quote-qualification.v1`. It has five objects,
`parent`, `late_profile`, `late_input`, `retention_profile`, and
`retention_input`, each containing an absolute `path` and full `sha256`, plus
`minimum_accuracy_percent` in 1 through 100. Its output directory must be new.

The candidate program is sealed before validation targets are checked. The
executable measures the bridge with unchanged weights first. If it meets the
declared accuracy goal, it keeps those weights. Otherwise it evaluates the
fixed sign program. This is a finite measured goal policy; it does not claim
global weight optimality or an empirically calibrated NDU utility law.
Independent training and held-out experiments must remain separate from this
engineering replay.

Both unconditional bridge retention and request-scoped retention using the
original graph are measured. Unconditional acceptance requires no previously
correct decision to be lost and mean CE no larger than parent plus `1e-6`.
Request-scoped retention requires complete output bytes to match the original.
The inverse artifacts are retained before later validation can fail, and the
executable separately evaluates the weights-only negative control and complete
graph-plus-weights restoration. Normal and late-task outputs must both return
byte-for-byte. Reports count every complete model forward and artifact write.

These are create-only, isolated research artifacts. No active model, runtime
configuration or task router is modified. Persistent production transactions,
crash recovery for graph changes, and session-owner/MCP admission of this new
program remain distinct integration gates. The existing production editor's
parameter scope and default graph are unchanged.
