# Bounded affine-coordinate proposals

Status: source candidate only. The compiler, its Rust controls, and the complete
repository gates have not been executed. The base is the fresh-read Runtime
PR 157 head `84c7f9f1c6a32cfaeab1e56688be9fa0e32eef73`; old results for that
head do not qualify this addition. The source export is partial and is not a
substitute Cargo checkout. No Git staging, commit, public reference update,
model execution, training, or existing experiment rerun accompanies this work.

## Purpose and existing owner

`weight_affine::compile(&params, checkpoint_bytes)` is a synchronous, pure
proposal compiler. It borrows an immutable complete safetensors file and
explicit external coordinate claims. It returns either no byte change (KEEP)
or the existing `weight_artifact::cohort::PatchParams` with coupled weight and
bias edits. It performs no file, process, network, artifact-owner, guard,
evaluation, recovery, selection, or activation operation. It registers no MCP
tool and adds no dependency or persistent owner.

A caller must still explicitly hand a proposal to the existing cohort owner.
That owner reopens the source under its existing path, full-file hash,
old-element byte, budget, transaction and confinement rules. A private-field,
serialize-only result is not an authorization token. Copying or modifying its
public cohort request does not create authorization. No existing owner or
final-use admission rule is weakened.

The current single-tensor guard uses one shared external bias for its baseline
and candidate. It cannot validate this coupled W/b coordinate change. A future
evaluator adapter must be separately designed and qualified. This compiler
does not route around that gap or relax strict gain, retention, preservation,
selection, or NDU evidence. Zero-gain equivalence is not capability improvement
or a reason to adopt a checkpoint.

## Conditional linear identity

Let the caller assert the relation `u_old = A u_new + c`, and define
`z_old = D_old^-1 (u_old - mu_old)` and
`z_new = D_new^-1 (u_new - mu_new)`. The proposed real-arithmetic coefficients are

```text
W_new = W_old D_old^-1 A D_new
b_new = b_old + W_old D_old^-1 (A mu_new + c - mu_old)
```

W is a row-major `[outputs, inputs]` matrix. A's row indexes the old coordinate
and its column indexes the new coordinate. D is a vector of positive diagonal
scales. W and b must already exist in the same source; b has shape `[outputs]`.
Old and new input/output widths are equal. No tensor, missing bias, graph or
shape is created. A need not be invertible for this conditional head identity.
This does not prove invertible state, Markov sufficiency, or a complete repair
of a FirstPassage or Belief model.

The names, shapes, dtypes and hashes authenticate the selected bytes. They do
not establish that a named F32 tensor is a linear head or a bias in the actual
model. These roles, the coordinate relation, the data/objective/dependency
commitments and the relevance to an evaluation are external caller claims.
The result keeps `external_relation_verified`,
`encoded_forward_equivalence_verified`, `behavior_evaluated` and
`production_eligible` false.

## Source authentication and bounded profile

| Item | Admitted input |
| --- | --- |
| Complete borrowed checkpoint | 9 bytes through 32 MiB |
| JSON header | 1 through 256 KiB, object beginning with `{` |
| Tensor directory | 2 through 256 declarations; names 1 through 1,024 bytes |
| Metadata | At most 64 string entries; keys 1 through 1,024 bytes and values at most 4,096 bytes |
| Each descriptor | Only dtype, shape and two data offsets; rank at most 32 and dtype name at most 16 bytes |
| Selected pair | Finite little-endian F32 W and b, distinct names |
| Widths | Each from 1 through 32; combined W and b elements at most 1,024 |
| External transform | Exact dimensions, finite scalars, both scale vectors strictly positive |
| Budgets | Explicit finite nonnegative member and combined L2 limits |

The compiler uses the actual header rather than accepting caller offsets. It
reuses the existing strict duplicate-key JSON parser and the existing pure
`rea::inspect_bytes` directory inspection. Complete storage extents, lengths,
gaps, overlaps and unindexed trailing bytes must pass; unknown storage dtypes
are rejected in this profile. Selected payload hashes, shapes and dtypes must
match their independent bindings in addition to the complete file SHA-256.
No REA preview identifier is promoted to behavioral or compatibility evidence.

The profile is deliberately narrower than the existing owners. F16, BF16, F64,
packed and quantized selected tensors are rejected. Other tensors are untouched.
There is no optimizer-state interpretation or migration, and a tensor's role
cannot be inferred merely from its name. The output training policy is always
`InferenceOnly`.

The present Pocket checkpoint is 643,835,514 bytes and primarily F16. It is
outside both this dtype profile and this complete-file size limit. This source
candidate therefore is not its weight repair, an executed transfer, or new
evidence of a checkpoint defect.

The compiler validates an absolute path using the current host's native path
syntax, rejecting NUL and parent-directory components. It neither opens nor
canonicalizes that path and does not prove its namespace identity. A future
caller still needs the normal owner checks. These bounds apply after a caller
has constructed the typed request; no bounded wire-input API is added here.

## Numerical and byte contract

1. Validate the request, every external finite value, all positive scales and
   all declared budgets. Authenticate the complete source and both payloads;
   validate all selected source coefficients as finite F32.
2. Detect an explicit identity: A is the identity matrix, c is zero, and the
   old/new means and positive scales compare equal. This path retains every
   original F32 bit, including negative zero and subnormals. It does not divide
   and multiply coefficients. The exact member and combined norm checks still
   run, so KEEP is not a shortcut around source or budget validation.
3. Otherwise, compute each shift component by ascending input column, then
   each output row's original W divided by old scales. Compute new W columns
   in order and multiply each completed sum by its new scale. Compute b from
   the original b and original scaled W, never from the already changed W.
   Every binary64 arithmetic result must be finite.
4. Cast each final coefficient once to F32 and reject nonfinite encoded output.
   Record final-cast differences, rounded coefficient count and nonzero
   underflow-to-zero count. These fields describe the binary64-to-F32 cast;
   they do not bound errors from earlier binary64 operations, cancellation,
   underflow, or a later model forward. In particular, finite intermediates
   and small updates do not prove exact real or rounded forward equivalence.
5. Check the existing exact represented-F32 member and combined L2 budgets.
   This reuses integer-based `weight_norm::check_pairs`; no approximate norm
   or tolerance is substituted. A failed budget returns an error and no
   proposal. The compiler does not choose a budget to make its own output pass.
6. Emit `ExactElementEdit` entries only where four encoded bytes differ. Both
   W and b bindings remain in the result even if one member has no edits.
   No edits means KEEP with no empty cohort request. Changed signed-zero bits
   are still byte edits even when their numerical norm contribution is zero.

The complete candidate hash is streamed from immutable source slices and
sorted four-byte replacements. It does not allocate another complete checkpoint
buffer. Header bytes, metadata, other tensors, file length and all untouched
payload bytes contribute unchanged. Only the small synthetic test helper
materializes its fixture to check that digest and an inverse.

## Provenance and limits of evidence

The result binds the complete source SHA, actual raw-header SHA, both target
payload bindings, the typed request, the transform and a selected-source hash.
The cohort dependency identity includes the caller's dependency commitment and
the request, transform and selected-source hashes. The tensor-map identity
includes the complete source, raw header, both bindings and both actual offsets.

`compiler_source_sha256` length-frames nine named source inputs: this compiler,
its source authenticator, `rea.rs`, `rea_evidence.rs`, `weight_norm.rs`,
`weight_tensor.rs`, `weight_artifact_cohort.rs`, `weight_config.rs` and
`Cargo.toml`. It is a selected-source identity, not a compiled-binary digest,
complete transitive build closure, lockfile attestation or execution record.
JSON hashes use the existing pinned crate's typed serialization. External
commitments are hashed claims and are not independently authenticated by hashing.

The sibling Rust controls are written but unexecuted. They exercise the real
compiler with small synthetic safetensors inputs: identity bits and extreme
scales, independent dyadic W/b bits, reversed payload order, exact candidate
hash and inverse, singular A, an unchanged member's read set, known cast
rounding/underflow, independent member/global norm rejection, malformed or
stale source bindings, duplicate keys, invalid extents, nonfinite values and
dimension/profile limits. They do not invoke an artifact owner or model.

The existing shared Rust 1.96 formatter has parsed and formatted the source as
preparation. This is not the repository's pinned Rust 1.95 format gate. A first
pre-format snapshot was not retained; raw formatter output and the final
source are retained, without claiming a recovered pre-format artifact. Real
Rust compilation, strict Clippy, all-target tests in both feature configurations
and required release gates remain unexecuted. Those require the authorized dev
environment and its pinned toolchain, after independent source review. The
old 5243 worker replay, 229-operation ledger and earlier native model outcomes
are unchanged and do not qualify this new code.
