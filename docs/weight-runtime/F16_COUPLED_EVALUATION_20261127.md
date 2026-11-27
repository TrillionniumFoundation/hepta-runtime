# Read-only coupled F16 head evaluation

This is a **source candidate, with 13 authored control groups not executed**.
It is based on Runtime `84c7f9f1c6a32cfaeab1e56688be9fa0e32eef73` plus the
unchanged `548a0f94...` exact-byte proposal candidate. The separately reviewed
`a64010ea...` affine compiler is unchanged and is not composed into this source.
Rust 1.96 formatting is preparation only. Pinned Rust 1.95 build, check, Clippy
and tests on the authorized `ssh dev` host remain unexecuted; the host mapping
has not been established. There has been no model, worker, new native control,
owner invocation or checkpoint publication during preparation.

## Library contract and the exact gap it covers

The new entry is
`weight_guard::f16::evaluate_from_admitted(&CoupledF16EvaluationParams, &mut tokio::fs::File)`.
It borrows an already-admitted descriptor. It does not open the proposal path,
find roots, register an MCP route, read an environment variable, fetch data,
write a model, create an artifact, call a transaction owner or activate a
candidate. The descriptor's position can advance. Its contents are not changed.

It compares one W/b pair using **original W and original b** for the baseline,
and **candidate W and candidate b** for the proposed head. Both tensors are
captured from the same source checkpoint. This closes a narrower interface gap
than the existing mutating single-tensor guard, which uses a common external
bias for both forwards. The existing guard and owner functions retain their
original bodies and behavior.

The selected F16 coefficients decode exactly into F32. The evaluator reuses
the existing sequential F32 multiply/add kernel, including its row-major
order, bias addition, finite-result checks and deadline checks. Those F32
operations are rounded arithmetic, not real-number affine equivalence or a
claim about a model's hardware F16 accumulation. There is no replacement
encoder, implicit F64/F32-to-F16 rounding, fused reduction, activation or
normalization added here. Replacements remain the caller's exact two bytes.

The current application's `load_verified_laya` path loads base weights into a
model and uses FP32 with its effective LoRA adapters. Evaluating selected base
F16 coefficients in this interface does not reproduce that complete loaded
adapter model. Tensor shapes alone do not establish head semantics. Neither
this candidate nor an eventual successful call establishes that the real
checkpoint has a weight bug or should replace the current KEEP decision.

## Types and source binding

`CoupledF16EvaluationParams` contains the unchanged `F16ProposalParams`,
`HeadSelection`, `FeatureBatch`, the existing `Objective` and `Constraint`
types, and a finite nonnegative `minimum_gain`. It accepts one shared feature
matrix. There is no separate before/after feature matrix or dense affine A.
All request structs reject unknown fields. The public result has private
fields and implements serialization only.

`HeadSelection` names a distinct existing F16 W `[out,in]` and F16 b `[out]`
in the proposal read set. Both complete payload hashes are mandatory. A missing
bias is an error; no implicit zero tensor is constructed. Only these two
tensors may be edit targets. Other read-set members can be unchanged
dependencies; the original proposal compiler still authenticates all of them.

The evaluator first obtains a typed `F16Proposal` by calling the unchanged
compiler. It never deserializes a supplied receipt into authority. It borrows
the typed `cohort_proposal()` only to apply validated nonidentity edits to
bounded in-memory coefficient bytes. It verifies each expected two-byte value
and range again. A typed KEEP applies no edits, but still reaches all source,
feature, finite-value and comparison checks.

The second source capture deliberately retains the already-reviewed compiler
unchanged. It performs another directory inspection and full SHA-256 pass
on the same borrowed descriptor, collecting W and b from that stream. It
checks metadata before/after, whole source SHA, the raw prefix and both full
payload hashes. The raw prefix includes the 8-byte length field; the separate
JSON-header hash excludes that length field. It does not reread selected
ranges after hashing. Parser descriptor work has returned before the next
seek. Equal full commitments bind the two passes to ordinary byte identity;
this is not a lease against a malicious concurrent writer or namespace swap.

Every selected original and candidate coefficient must be finite, including
unedited coordinates. The proposal compiler alone only requires finite
expected/replacement edit values and does not imply this stronger selected
head condition. Unselected checkpoint values are not certified finite.

## Feature provenance is explicit and remains unverified

`FeatureBatch` requires these identities:

- Source checkpoint, source domain, producer code and producer configuration.
- Declared producer receipt, data manifest and ordered distinct sample IDs.
- The expected exact feature-row commitment and the shared finite F32 rows.

Each digest is a complete lowercase SHA-256. Source and data identities must
equal the proposal's corresponding identities. The row hash is SHA-256 of
`hepta.weight.coupled-f16-feature-rows.v1` followed by a NUL byte, then the
row/column counts as little-endian u64, then each sample's decoded 32 digest
bytes followed by that row's little-endian F32 bit patterns. Sample order and
negative zero therefore affect the commitment.

The two origins are `SyntheticControl` and `DeclaredEncoderOutput`. Both
hardcode `producer_execution_verified=false` and
`feature_provenance_verified=false`. Declaring an encoder receipt does not
verify it, and a digest does not certify that an encoder ran. The result also
hardcodes `head_semantics_verified=false` and
`independent_holdout_verified=false`.

The canonical bounded request hash binds the actual inline objective,
constraints, selected tensors, threshold and all declared provenance. A
separate inline-specification hash identifies the head/objective/constraints/
threshold tuple. The proposal's external objective/dependency hashes remain
separate caller commitments; they are not silently redefined to match this
inline specification. The selected-source hash identifies named source files,
not a compiled binary, dependency closure, toolchain or actual invocation.

## Comparisons and result qualification

The baseline and candidate predictions must both have the complete expected
row/column dimensions and finite values before either reaches the existing
constraint function, whose iteration uses zip. Prediction bit hashes preserve
the exact F32 outputs in addition to their lossless F64 representation in the
report. There is no opportunity to supply predictions directly.

The unchanged score functions calculate negative MSE or the stated realized
action values, including the original first-listed action tie rule. Original
and candidate constraint failures are reported independently. The sole
comparison condition is named `supplied_row_condition_satisfied`: finite
`gain > minimum_gain` and no candidate constraint failures. Equality is not an
improvement. A -0-to-+0 byte edit can be non-KEEP with zero numeric norm and
zero gain; it does not pass this strict condition.

Even when that condition is true, the result sets owner invocation, artifact
creation, live activation, rollback execution, full-model execution and
production eligibility to false. `linear_kernel_evaluated=true` describes
only the two head calculations that a successful future call actually runs.
The embedded proposal's own `behavior_evaluated=false` remains unchanged: it
describes that inner compile stage, not a denial that the outer wrapper has
computed these supplied-row results. No acceptance or adoption gate is added.

A durable consumer linking verified features, this comparison, a particular
published cohort and final use remains separate work. Existing cohort
publication/reconciliation/restore contracts are neither bypassed nor claimed
tested. The current global retention/NDU and actual-model evidence gaps remain.

## Combined limits and costs

| Resource | This candidate |
|---|---|
| Complete checkpoint | At most 2 GiB; no complete-file allocation |
| Header/directory | At most 256 KiB JSON header, 256 tensors and 64 bounded metadata rows |
| Read set and edit count | Original 32 members and 1,024 requested edits, before identity filtering |
| W and b | Dimensions 1..=4,096; W at most 1,048,576 values; b exactly one per output |
| Features | 1..=64 finite rows at the selected input width |
| Two kernels together | At most 16,777,216 multiply-adds and 16,384 output values |
| Constraints | Original maximum 32 and unchanged predicate implementations |
| Extra request copy and serialized report | Each at most 1 MiB; not a transport-deserialization bound |
| Deadline | One 60-second operation budget covering compile, captures, both forwards and comparisons |

The maximum selected F16 byte buffers total 2,105,344 bytes. Each set of F32
coefficient vectors needs at most 4,210,688 bytes. Original coefficients are
decoded before the raw bytes are changed in place for the candidate. Those
raw buffers are released after candidate decoding and payload hashing. One
1 MiB streaming buffer is used for the second pass. Directory, features,
results and serializer overhead are additional; these are not measured RSS.

The successful result reports two full passes and `2 * source_size_bytes`
hashed. Two directory inspections and extra parser/header reads are not
included in that byte number. Their exact I/O total remains unknown. For the
historical 643,835,514-byte base this would be 1,287,671,028 full-pass bytes,
plus the extra reads; no claim says it will complete within 60 seconds.

Monotonic phase durations are wall intervals, not CPU use. The operation
interval is explicitly named `operation_wall_ms_before_final_response_check`;
the final bounded serialization and final deadline check occur afterward.
One outer asynchronous timeout and cooperative checks share the same deadline,
including both full passes and both kernels. They do not prove hard real-time
termination of arbitrary OS or inherited-worker blocking. Producer work and
total end-to-end cost remain unverified. No timeout, retry or warmup is added
to make a qualification result pass.

## Actual sizes and remaining inputs

The retained historical base metadata admits a complete ACT last pair
`act_head.2.weight[2,256]` plus `.bias[2]`: 514 F16 coefficients. PRICE
`scorer.3.weight[1,768]` plus `.bias[1]` has 769. Each full pair is within this
profile individually; the width-32 restriction of a640 is not inherited.

Both full pairs have 1,283 coefficients, above the unchanged 1,024 requested
edit cap. A sparse joint proposal might fit that compiler cap, but this first
evaluator rejects editing a second head. Two separate evaluations are not one
joint evaluation or transaction. Actual changed bytes can be fewer than the
complete coefficient count, but requested edits still count before filtering.

Historical header metadata does not provide the required four complete tensor
payload hashes, genuine feature rows or their authenticated producer evidence.
Source preparation therefore does not make a call on the actual Pocket model
ready. Any later retained commitments do not automatically establish encoder
provenance, effective LoRA identity or final model semantics. The separate
F64 research readout `85 -> 48 -> 4` is a different model and representation.

## Authored controls and preparation boundary

Thirteen sibling control groups exercise the actual descriptor entry:

1. Independently computed dyadic W/b before/after values, exposing old-bias reuse.
2. Bias-only and W-only edits with the other full payload as a dependency.
3. Complete synthetic 514/769 ACT/PRICE pairs, explicitly synthetic features.
4. The compiler's 1,283 rejection and a legal sparse compiler proposal rejected
   only by this evaluator's one-head profile.
5. Source, payload, bias shape, duplicate-name and dtype rejection.
6. Unedited selected NaN/Inf rejection and fixed subnormal/signed-zero bit vectors.
7. KEEP source checks and non-KEEP signed-zero edits without strict gain.
8. Feature/sample/source/data commitments and both unverified origin variants.
9. Unknown before/after feature-space fields and forged verification fields.
10. Combined MAC/output limits and bounded request serialization.
11. Real score/constraint comparisons, strict threshold, F32 overflow and
    explicit prevention of unequal matrix zip truncation.
12. Two-byte cross-chunk capture, bias-first layout, truncation and a controlled
    source change between the original compiler and the second capture helper.
13. Two-pass/two-forward accounting and no artifact side effects in owned fixtures.

These are authored, not executed. The controlled file mutation is performed
only by a test on its own temporary source; no production injection hook is
introduced. No timing assertion treats a small synthetic fixture as a real
checkpoint performance qualification.

Exactly six paths change. Four forward items gain `pub(super)` visibility,
the old guard gains one child declaration, and the three new sibling Rust
files plus this document implement the proposed interface. All old function
bodies, 548a files and a640 files are retained. There is no Cargo, lock, route,
owner, training contract or workflow change. The source remains unstaged and
uncommitted under AGENTS; preparation is not the pinned dev gate.
