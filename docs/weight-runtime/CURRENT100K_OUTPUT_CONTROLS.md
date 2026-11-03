# Current100k output-matched mechanism controls

`experiments/weight/current100k_mechanism_controls.py` adds a label-free screen
for a previously frozen Current100k FP32 value head. It addresses the ambiguity
between a direction that changes average outputs and a direction with useful
input-dependent effects. This screen cannot determine whether either predicts
future outcomes well.

The existing generic mechanism runner and registered eleven-head family are
unchanged. This module creates a new output directory and retains every planned
condition. It does not add arms to an existing registration, change active
weights, or backdate predictions. A new prospective family would require its own
registration and outcome rules after these heads have been frozen.

## Inputs and fixed recipes

The CLI requires SHA-256 pins for four files:

| Input | Required content |
| --- | --- |
| `--features` | Safetensors with exactly `features`: 2..4096 CPU FP32 rows of width 768, L2 normalized |
| `--parent` | The complete frozen FP32 `value.weight` and `value.bias` head |
| `--full` | The complete saved full-dose FP32 head from the prior mechanism experiment |
| `--plan` | The exact plan schema below |

No labels are read. `information_cutoff_ms` declares the development information
boundary; the script does not infer observation timestamps from tensor values.
The caller must independently verify the frozen feature matrix's row order,
encoding identity and information lineage before interpreting the screen.

```json
{
  "schema": "hepta.weight.current100k.output-controls-plan.v1",
  "partition": "development",
  "information_cutoff_ms": 2000,
  "doses": [0, 0.5, 1],
  "random_seed": 37,
  "random_controls": 2,
  "norm_relative_tolerance": 0.02,
  "output_relative_tolerance": 0.02,
  "output_absolute_tolerance_usd": 0.00001,
  "orthogonality_max_abs_cosine": 0.02,
  "max_output_rms_scale": 1000000,
  "prediction_chunk_size": 2
}
```

These are example values, not a registered experiment. Use an actual cutoff and
freeze the complete plan before running. Matching tolerances, recipes, seeds and
the prediction chunk size are fixed before the first forward. The new bias and
RMS-control payloads are then calculated by those recipes from the frozen
development outputs, not fixed independently of those outputs. The report states
this distinction explicitly. No adaptive search or replacement seed is used.

The conditions are:

1. The original parent, retained as its own reference.
2. Zero, half and full doses interpolated in FP64 and saved in FP32. Zero and full
   endpoints copy their source tensors to preserve exact bytes, including signed
   zero. Zero must match the parent head and outputs exactly.
3. A pure bias offset equal to the full-dose mean USD displacement divided by 100.
   Its weight tensor is unchanged. Mean matching is checked after FP32 storage.
4. For each fixed seed, a random delta orthogonal to the realized full-dose delta
   with the same pre-storage joint weight/bias norm. Its support is the full-dose
   delta's actual nonzero coordinates. Post-storage norms and directions are
   checked independently.
5. A second control made by scaling each stored random delta once to match the
   full-dose output RMS under the frozen linear map. Its actual match is checked
   using fresh FP32 head forwards. Its parameter norm is reported independently.

The outputs use `100 * linear(features, weight, bias)`, with no clipping, in the
fixed chunk size. Mean displacement, total RMS displacement and centered RMS
displacement are all reported. This separates a common offset from variation
across the frozen requests.

## Norm and output matching are different constraints

Scaling a random direction to match the proposed patch's output RMS can change
its parameter norm substantially. An output-RMS match therefore does not imply a
parameter-norm match. A control has `joint_random_match_passed=true` only when its
post-storage parameter norm, actual output RMS and realized orthogonality all
pass their independently fixed tolerances.

The screen additionally calculates a numerical upper bound for simultaneous
matching under the same support, allowed norm and allowed cosine. Let `A` be the
frozen augmented feature matrix, including the USD factor and division by the
square root of the number of rows; let `q` be the normalized full-dose delta.
Decomposing each permitted direction along `q` and its orthogonal complement
gives the conservative bound

\[
\|\Delta\|_2(1+\epsilon_N)
\left(\|A(I-qq^T)\|_2+\epsilon_C\|Aq\|_2\right).
\]

If the minimum allowed RMS exceeds this bound, the plan's joint comparison is
numerically infeasible. This calculation uses FP64 SVD and a triangle-inequality
bound; it is not an interval-certified floating-point impossibility proof. Its
linear-map calculation also does not replace the actual FP32 match checks.
The report does not respond to infeasibility by relaxing the norm or cosine.

A one-coordinate support has no orthogonal direction. A zero realized output
effect cannot qualify an output-RMS control. Degenerate random draws, zero output
responses and scales beyond the fixed limit are retained as failed construction
records, with one attempt and no substitute seed. A completed diagnostic can
contain failed or unmatched controls; completion does not certify those controls.

## Storage, preservation and cost

Each candidate is written as a complete head, reloaded and checked for exact
tensor hashes before scoring. The report binds its actual saved head and output
artifacts. The final parent is reloaded and recomputed; the original parameter
hashes, frozen feature tensor and exact parent output bytes must remain unchanged.
This is a **parent head recomputation on frozen features**. It performs no encoder
forward and does not replace the generic runner's uncached final encoder check.

The CLI writes a separate `source-integrity.json` after checking all four source
files again. A completed source-qualified CLI run requires both the completed
development report and this passing source-integrity receipt. Incomplete output
directories are never overwritten or replayed in place. Computation failures
retain `failure.json`, observed forward counts and completed candidate records.

The diagnostic cost records head forward examples, wall and process CPU time,
zero encoder forwards, and zero optimizer/backward calls. Candidate phase times
are nested within total diagnostic wall time and must not be added to it. Python
imports, input loading, prior construction, prior encoding, Astra reasoning and
future evaluation are outside that total. Unknown costs stay null, and
`end_to_end_cost_complete=false`. This report cannot establish training savings.

```sh
python experiments/weight/current100k_mechanism_controls.py \
  --features FEATURES.safetensors --features-sha256 FEATURES_SHA256 \
  --parent PARENT.safetensors --parent-sha256 PARENT_SHA256 \
  --full FULL.safetensors --full-sha256 FULL_SHA256 \
  --plan PLAN.json --plan-sha256 PLAN_SHA256 --output NEW_OUTPUT
```

The placeholder arguments above must be replaced with real pinned files. Focused
verification uses real PyTorch and safetensors:

```sh
python -B -m unittest discover -s experiments/weight \
  -p test_current100k_mechanism_controls.py -v
```
