# From a behavioral observation to a bounded weight edit

This workflow uses the registered worker operations over the resident model.
Each operation is submitted with `weight_call`; its completed JSON response is
read through the original durable job with `weight_read`. It does not require a
caller-supplied Python program or repeated model loading.

## Retain a parameter or a selected block

An inspect request can export a parameter into the session artifact store:

```json
{"export_tensor":true,"tensor":"2.weight","columns":[0,2]}
```

The result contains `array`, the selected shape/dtype, and the hash of the complete
parent tensor. Optional `rows` and `columns` select a matrix block without changing
its values. The exported element count is bounded by `max_capture_elements`.
Exports remain read-only evidence; editing still requires `patch` and the complete
parent tensor hash. Querying a retained tensor pages at most 1024 scalar values.

Use `{artifact_id, tensor}` wherever an analysis operation accepts a tensor value.
`artifact_id` is the returned artifact identity, not its raw content SHA256. The
exported tensor is named `value`; captured tensors use `capture_name.0`, then
increasing ordinals if the same module is called repeatedly.

## Compose probes into a direction estimate

First probe several **development** inputs and their semantically equivalent
permutations. Capture only the needed positions. The provider must align the
semantic option axis; raw token positions from different permutations are not
interchangeable.

The numerical operations are:

| Operation | Input | Result |
| --- | --- | --- |
| `concatenate` | `values`: 1–64 tensors; optional `axis` | `value` tensor with compatible dimensions |
| `reshape` | `value`, `shape` | `value` tensor with unchanged element count |
| `pair_differences` | `[states, permutations, ...features]`; optional `reference_permutation` | `difference` from the reference, normally flattened to rows |
| `svd` | Matrix, rank 1–64, optional `center_columns` | `basis` and `singular_values` |
| `difference` | Two equal-shape tensors | Difference tensor and magnitude summary |
| `statistics` | A tensor | Shape, mean, RMS, minimum and maximum |
| `permutation_metrics` | `[states, permutations, semantic_classes]` logits | Centered permutation variation, amplitude and state contrast |

Every operation checks shapes, finite values and the session's element budget.
Large arrays are written once and referred to by identity. Singular vectors are
descriptive directions; they are not proof of a causal failure or preserved task
information.

Use `intervene` to subtract a direction temporarily at the selected hook. Compare
its effect with the unedited parent, multiple doses, a simple input control and
a matched random direction. Hooks and temporary parameters are restored after
each forward, including failure paths. Captures at a hook precede an intervention
at that same hook.

## Rank an MLP's output columns

`writer_ranking` accepts:

```json
{
  "operation":"writer_ranking",
  "value":{"artifact_id":"CONTRAST_ARTIFACT","tensor":"difference"},
  "weight":{"artifact_id":"PARAMETER_ARTIFACT","tensor":"value"},
  "direction":{"artifact_id":"SVD_ARTIFACT","tensor":"basis"},
  "top_k":64,
  "positive_only":true
}
```

The differences have shape `[observations, input_width]`; the weight has shape
`[output_width, input_width]`; a rank-one basis supplies the output-space direction.
With a unit direction `u`, columns are ranked by:

```text
projection = u.T @ W
projected_difference = input_difference @ projection
score[j] = mean(input_difference[:,j] * projected_difference) * projection[j]
```

This covariance score is invariant to reversing `u`'s sign. It ranks contributions
to the observed direction under the supplied contrasts. It does not estimate a
label-based loss or guarantee that removing a column improves a task. Column
selection must use discovery/development data only. The operator records the exact
ranking basis, retained scores and chosen columns.

## Materialize, evaluate and stop

A writer patch changes selected columns with
`W[:,J] -= alpha * u @ (u.T @ W[:,J])`. Supply the expected model and parent tensor
identities. Realized dtype, coordinate count, norms and serialized tensor hashes
are measured after casting and reloading. A frozen base is restored after each
candidate probe.

The standalone evaluator in `experiments/weight/evaluation` consumes a separately
frozen paired protocol and prediction/outcome artifacts. It cannot read outcomes
on the editor's behalf or authenticate a caller merely from a hash. The host must
keep confirmation outcomes outside the editing worker's input roots and verify
their source. Pending or censored confirmation rows cannot produce a positive
final claim in this version.

`NoUsefulPatch` and `InsufficientEvidence` are complete research outcomes. Reduced
permutation variation accompanied by a nearly constant prediction is not a useful
repair. Sealing a `DirectWeightEdit` never grants production eligibility; existing
evaluation, selection and model-loading owners retain that responsibility.

## Examples and evidence

- `workers/weight/tests/test_analysis_workflow.py` executes export, concatenation,
  differences, SVD and writer ranking on real synthetic tensors.
- `experiments/weight/laya_localize.py` and `laya_session_experiment.py` accept
  explicitly pinned private inputs and produce retained development evidence.
  Private financial inputs and results do not belong in this public repository.
- `experiments/weight/mit_replay` reconstructs the public MIT BF16 patch and records
  a bounded teacher-forced mechanism replay. It does not rerun the full benchmark
  or independently discover the published patch.
