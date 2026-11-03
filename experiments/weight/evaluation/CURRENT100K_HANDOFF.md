# Current100k USD review handoff

`current100k_handoff.py` imports an **already registered** Current100k strict
review into the weight workbench. It does not load a model, register a window,
resubmit predictions, fit or select a head, or access a broker. Existing Laya
multiclass Brier evaluation in `paired_eval.py` remains unchanged.

The source contract was inspected at heptatrader PR #528,
`f9e12deb2c1ade7799352d5b31ec16b002128c32`. The original statistical evaluator
uses its registered support rules, time halves, fee stresses and family-adjusted
Huber mixture evidence. Its block-bootstrap intervals remain exploratory. This
importer does not replace that rule with the Brier evaluator's interval gate.

## What is checked

- The externally supplied original plan ID, source plan digest, original
  registration, head hashes, source review provenance and original dates.
- The complete ordered outcome-list digest from the same source assessment.
- Unique original commands and all OBSERVED/PENDING/CENSORED denominator entries.
- For observed rows: original request, reward, successful terminal/binding
  references and pre-open/first-fill/close time ordering.
- Shared head population and the prospective USD contract: scalar FP32 head
  scaled by 100, with predictions capped uniformly at +/-15 USD. Targets are not
  clipped. The source outcome rows contain capped predictions; the importer does
  not pretend raw values are present.
- Independently recomputed MAE, RMSE and paired error gains for all original arms
  and both benchmarks. Source statistical decisions are retained as source
  decisions; `statistical_rule_recomputed` stays false.
- Independently reconstructed UTC-day dependence blocks, distinct opening days,
  time-half counts and the complete directed comparison count. Present source
  metadata must match; missing legacy fields remain explicitly unverified.
  When the plan records `family_alpha`, its division across the full family and
  each present mixture threshold are checked without recomputing the test result.

The original strict evaluator owns the full original input/attempt/terminal/
publication/command and current ledger replay. This adapter checks that the
export is bound and internally consistent, not that hashes authenticate an
observer. The host supplies the trusted original plan ID and protects the source
review directory and outcome separation.

Source loss preserves `current_replay_complete=false`, the known-command lower
bound and any unenumerated retained count. All error metrics stay null when
current observed credit is withdrawn. A pending or incomplete report cannot
become an accepted comparison by importing it. A censored row may retain old
diagnostic values; those values never enter scoring.

### Overlap and the fixed comparison family

`comparison_design` mirrors the source's **whole UTC-day interval** grouping.
Episodes spanning a common day belong to one block; a chain of such overlaps
also belongs to one block. Two nonoverlapping clock-time episodes on the same
UTC day are not split into separate source blocks. This preserves the declared
source dependence rule, including its conservative day resolution. The block
sizes refer only to currently observed rows. Pending and censored commands stay
in the original denominator and do not become usable outcomes.

With eleven heads and two benchmarks, the frozen source evaluates
`11 * (13 - 1) = 132` directed comparisons. The importer verifies the whole set;
choosing the best observed head cannot reduce that comparison count or enlarge
its pair alpha. It checks source `time_blocks`, `distinct_utc_days`, `half_counts`,
`multiple_comparison_count`, `family_alpha` and `pair_alpha` when present.
Available Huber-mixture records must keep the plan's method, pair alpha and
`log(2 / pair_alpha)` threshold. Their observed log-e values and final decisions
remain source-owned rather than being silently reissued by this adapter.

The source's block-bootstrap interval remains exploratory; it is not the source
acceptance test. Recomputed groups do not prove exchangeability, independence,
generalization or error control across later experiment families. A new set of
heads or a new selection rule needs its own prospective freeze; this audit does
not amend an already registered window.

## Schedule state and irreversible comparison ineligibility

`source_state=PENDING` describes the original schedule. It does not assert that
the frozen comparison can still succeed. A missed original pre-command prediction
cannot be supplied by a later training run, inference retry, fill or fee receipt.
The original unresolved-command limit can therefore make formal success
impossible before the unchanged outcome deadline.

New source reviews can include `comparison_eligibility` using schema
`heptatrader.current100k-comparison-eligibility.v1`. This is separate derived
metadata. It never changes the original state, deadlines, candidates, row list,
outcome digest, statistical rule, observed error metrics or source comparisons.
The handoff exposes the metadata and a top-level
`formal_success_possible_under_frozen_rule` field:

| Evidence | Status | Formal success possible |
| --- | --- | --- |
| Verified permanent missing predictions exceed the original `maximum_unresolved_at_final` | `IRRECOVERABLY_INELIGIBLE` | `false` |
| No supported permanent proof, a count within the frozen limit, or unavailable current source | `UNKNOWN` | `null` |
| Old report without the field, or an unsupported metadata schema | `UNKNOWN` | `null` |

No path infers `true`. `CENSORED` alone is not an irreversible-failure proof:
settlement, current source availability and other evidence may still change.
Known-schema metadata with inconsistent hashes or bindings is rejected instead
of converted into a conclusion.

The currently supported proof is the original request ledger's immutable
`NO_PREDICTION_BEFORE_ORIGINAL_COMMAND` terminal. The source reads its original
private bytes and verifies the fixed activation/configuration/plan/registration,
protocol, request digest, exact original-command reference, full current command
binding and original clocks. It exports only the safe terminal/reference records,
their raw SHA-256 values, the other receipt hashes and a proof digest; input text
and private ledger content stay in the source.

The importer independently checks those two original safe records' canonical
bytes including their newline, request/command/producer/plan identity, command
membership in the captured CENSORED population, time ordering, unique proofs and
the unchanged unresolved limit. Full private input and ledger verification
remain the original strict evaluator's responsibility. Hash consistency is not
observer authentication. A negative conclusion requires that trusted source
review and its existing provenance binding.

Observed rows still supply descriptive MAE/RMSE and paired gains even when the
family is irrecoverably ineligible. They do not repair the missing original
prediction or authorize selection. Source loss changes the current metadata to
`UNKNOWN`, withdraws current observed credit under the existing rule and keeps
the prior completed assessment in the source's immutable history. An old blocked
assessment remains historical negative evidence; current unknown is never
reported as recovered eligibility. Finalization still happens only at the
original fixed deadline.

## Ordered source export

The original evaluator stores individual outcomes and a digest of its ordered
`results` list. Sorting the outcome directory cannot reconstruct that list in
general: unbound commands can be appended in ledger order. The importer therefore
requires an explicit ordered snapshot, and refuses older reports that lack it
with `ORDERED_OUTCOME_SNAPSHOT_REQUIRED`. It does not guess an ordering.

`write_outcome_snapshot(review_root, assessment, rows)` takes the exact list from
the current computation, checks its existing digest, publishes an immutable
`outcome-sets/<document-digest>.json`, and returns a small pointer. It does not
modify either argument. Publish the pointer in the assessment **after** the
snapshot succeeds. A crash before the assessment is published leaves an
unreferenced snapshot, not a new credited report.

### Heptatrader source integration

Apply the export hook only to a **new independent strict-review release and
output directory**. Preserve the existing registered plan, predictor, candidates,
dates and original reports. Do not deploy by changing the identity of a running
review whose provenance is already pinned.

In `laya_cell/current100k_weight_shadow_eval.py`, `Evaluator.evaluate_snapshot`,
after the existing outcome-file loop and immediately before
`W.atomic(self.root/self.assessment_name,result)`:

```python
if self.strict_review:
    result['outcome_set_snapshot'] = write_outcome_snapshot(self.root, result, results)
```

In `strict_source_unavailable`, after the outcome-file loop and **before** the
`if now>=plan['outcome_end_ms']:` branch that seals the terminal receipt:

```python
result['outcome_set_snapshot'] = write_outcome_snapshot(root, result, rows)
```

That placement makes the original unavailable-source terminal receipt retain the
same snapshot pointer on restart. Do not retrofit an old final terminal receipt
or rewrite its outcome dates. Use an explicit export pack if its ordered original
rows were separately captured; otherwise retain the missing-export diagnosis.

Heptatrader contains its own `laya_cell/current100k_outcome_export.py` helper and
both hooks. Its actual SHA is part of
`PreopenEvidence.provenance()['review_implementation_sha256']`; it does not import
runtime source files. The runtime `write_outcome_snapshot` helper preserves the
same wire format for isolated export packs and tests. The source evaluator owns
row computation and publication. Eligibility proofs are collected from
`PreopenEvidence.permanent_prediction_failure` before publishing the same
assessment; the source-loss hook emits explicit unknown metadata.

The source uses `json.dumps(sort_keys=True, separators=(',', ':'),
ensure_ascii=True, allow_nan=False)`. This is deliberately different from the
existing Brier helper's `ensure_ascii=False`. The handoff preserves the source
canonicalization, including non-ASCII strings; it never re-signs the original
plan under the runtime convention.

## Import an existing independent review

```sh
python3 experiments/weight/evaluation/current100k_handoff.py \
  --review-root /private/strict-review-with-export \
  --expected-plan-id ORIGINAL_REGISTERED_PLAN_ID \
  --out /private/weight-results/current100k-handoff.json
```

The importer reads only that independent review directory. It needs:

```text
assessment-strict.json
review-plan-snapshot.json
strict-review-provenance.json
outcome-sets/<digest>.json
```

Source-unavailable reports can omit unavailable provenance, but never retain
observed credit. A complete replay requires provenance and the report's matching
raw-byte provenance SHA. The assessment is re-read after capture to detect a
concurrent update; a changed report returns an explicit error rather than mixing
generations. An output path inside the source review is refused. Output is
create-once, and identical repeat imports are idempotent.

Every imported result includes `production_eligibility=false`,
`activation_authorized=false`, `trade_authority=false`, and
`model_forwards_performed=0`. It preserves the source assessment time instead of
giving an old report a new observation timestamp.

## Measured costs

`--cost-manifest /private/cost-inputs.json` optionally adds actual recorded costs.
The manifest selects fields from hash-checked JSON receipts; numeric cost values
are read from those receipts, not accepted as replacement values in the manifest.
For example (replace the placeholder hash with the receipt's actual byte hash):

```json
{
  "schema": "hepta.weight.cost-inputs.v1",
  "records": [
    {
      "operation_id": "candidate-edit-attempt-1",
      "stage": "candidate_construction",
      "arm_ids": ["edit"],
      "source_path": "/private/attempt.json",
      "source_sha256": "EXACT_64_HEX_SHA256",
      "source_record_path": [],
      "metric_paths": {
        "wall_seconds": ["wall_seconds"],
        "cpu_seconds": ["cpu_seconds"],
        "optimizer_steps": ["optimizer_steps"]
      },
      "status_path": ["status"]
    }
  ]
}
```

Paths are arrays of object keys or list indices relative to `source_record_path`.
Recorded statuses are `completed`, `failed`, `interrupted`, or `unknown`; omit
`status_path` when the receipt has no such field. Supported metrics are wall/CPU/
GPU seconds, forward examples, generated/editor tokens, optimizer steps and peak
RSS bytes. Units must already match; this module does not guess unit conversions.
Omit unknown metrics. They remain null and have explicit missing-operation counts.

Stages distinguish Astra inference, model load, shared feature extraction,
discovery, candidate construction, confirmation and cleanup. `arm_ids=[]` or multiple arm IDs marks
shared work. A shared encoder is counted once, not once per candidate. Identical
duplicate operations deduplicate; conflicting identities or a receipt relabeled
as a second operation are rejected. Failed attempts remain included. RSS uses a
maximum, not a sum. Wall values are labelled sums of measured operations; they do
not imply end-to-end elapsed time when operations overlap or use different hosts.
No speedup or equal-hardware claim is inferred from budgets or partial receipts.

### Nested timing receipts and complete-cost gaps

The version-one manifest remains readable. Its legacy `sum_of_operations` values
describe the submitted measurements and do not establish disjoint scopes. The
summary now explicitly reports `LEGACY_REPORTED_OPERATION_SUMS_SCOPE_UNKNOWN`.
An ancestor and child `source_record_path` from the same receipt are rejected
without an explicit containment contract; changing the path cannot make an
experiment total and its inner SGD timer independent work.

For new experiments, use `hepta.weight.cost-inputs.v2`. Each operation's actual
hashed receipt must contain an accounting object such as:

```json
{
  "accounting": {
    "schema": "hepta.weight.inclusive-cost-scope.v1",
    "operation_id": "baseline-run-1",
    "parent_operation_id": null,
    "metric_scope": "inclusive"
  },
  "wall_seconds": 8.5,
  "head_fit": {
    "accounting": {
      "schema": "hepta.weight.inclusive-cost-scope.v1",
      "operation_id": "head-fit-1",
      "parent_operation_id": "baseline-run-1",
      "metric_scope": "inclusive"
    },
    "wall_seconds": 1.5
  }
}
```

These numbers illustrate the wire format and are not experimental measurements.
The manifest selects the outer record with `source_record_path: []`, the inner
record with `source_record_path: ["head_fit"]`, and each accounting object with
`accounting_path: ["accounting"]`. Both select their own
`metric_paths: {"wall_seconds": ["wall_seconds"]}`. The receipt's operation ID
must match the manifest ID. Inclusion metadata cannot be supplied as replacement
values in the manifest. Unknown parents, cycles, excessive nesting, inconsistent
same-receipt ancestry and a known child quantity exceeding its inclusive parent
are refused. Scope hashes establish consistency, not observer authentication.

For each metric the summary selects its **outermost measured inclusive scopes**.
The example contributes 8.5 seconds, not 10 seconds. A failed or interrupted
inner attempt remains visible in the operation and status inventory even when
the outer timer already includes its consumption. If a parent CPU measurement
is unknown and only a child CPU measurement exists, the child contributes known
subscope consumption; the parent remains unknown, the metric is incomplete, and
the value is labelled a lower bound over the declared scopes. A parent's known
wall time does not fill its unknown CPU time. Peak RSS remains a maximum.

Per-stage summaries retain their measured operations for inspection and may
overlap. Do not add stage summaries together. The per-metric selected/suppressed
operation IDs make the whole-manifest accounting inspectable. Root wall values
can still overlap in real time or run on different hosts, so the result does not
invent end-to-end elapsed time.

`coverage` lists the required stages and those missing from the submitted
receipts: `astra_inference`, `model_load`, `feature_extraction`, `discovery`,
`candidate_construction`, `confirmation` and `cleanup`. An explicitly measured
zero is different from a missing stage. Having one receipt for each stage still
does not prove that every failed attempt or every Astra call was supplied:
`complete_experiment_inventory_verified` and
`failed_attempt_inventory_verified` remain false. Missing tokens, hardware time
or historical feature costs stay unknown. Neither cost schema issues a speedup
claim.

## Validation

```sh
python3 -m unittest discover -s experiments/weight/evaluation -v
```

The new synthetic regressions cover independently known USD errors, changed
original identities/dates, ordered snapshots, incomplete/censored and source-loss
denominators, late/failed terminals, raw-versus-capped predictions, atomic replay,
unchanged source bytes, nonfinite/duplicate input, and actual-cost deduplication
and missing values. Negative-evidence tests cover original bytes, request and
command identity, source-binding claims, clocks, duplicate proofs, unchanged
frozen limits, no positive inference, legacy/unsupported schemas and preservation
of observed diagnostics. They perform no model forward or market evaluation.
