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

### Minimal heptatrader insertion points

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

The exporter has no HeptaTrader imports. Expose this file through a pinned import
path or package it under an explicitly pinned local helper module; add its actual
SHA to `PreopenEvidence.provenance()['review_implementation_sha256']`. Do not use
an unpinned ambient module from PYTHONPATH. The module name of that installed
helper determines the import line; no source path is silently chosen by this
adapter. The actual original evaluator stays the owner of row computation and
publication.

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

Stages distinguish model load, shared feature extraction, discovery, candidate
construction, confirmation and cleanup. `arm_ids=[]` or multiple arm IDs marks
shared work. A shared encoder is counted once, not once per candidate. Identical
duplicate operations deduplicate; conflicting identities or a receipt relabeled
as a second operation are rejected. Failed attempts remain included. RSS uses a
maximum, not a sum. Wall values are labelled sums of measured operations; they do
not imply end-to-end elapsed time when operations overlap or use different hosts.
No speedup or equal-hardware claim is inferred from budgets or partial receipts.

## Validation

```sh
python3 -m unittest discover -s experiments/weight/evaluation -v
```

The new synthetic regressions cover independently known USD errors, changed
original identities/dates, ordered snapshots, incomplete/censored and source-loss
denominators, late/failed terminals, raw-versus-capped predictions, atomic replay,
unchanged source bytes, nonfinite/duplicate input, and actual-cost deduplication
and missing values. They perform no model forward or market evaluation.
