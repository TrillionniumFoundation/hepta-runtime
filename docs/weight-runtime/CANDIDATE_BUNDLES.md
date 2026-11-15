# Current100k candidate bundles and separate registration

`experiments/weight/current100k_candidate_bundle.py` connects completed
development experiments to the **inputs** of the existing HeptaTrader shadow
registrar. It does not register, activate a collector, load an encoder, select a
candidate, or trade. `PREPARED_NOT_REGISTERED` is an artifact state, not permission
to launch a future window.

The original mechanism screen and six-head baseline comparison remain development
evidence. A new frozen family needs its own registration, future input window,
original successful pre-open publications and independent outcome assessment.
An old missing, failed or late prediction remains part of its original command
denominator. A new candidate bundle cannot repair it retrospectively.

## Complete candidate family

The builder retains every source candidate, in a fixed order: the six baseline
report entries, followed by all entries of the mechanism summary. For the first
Current100k screen this is **11 arms**: six baseline entries and five mechanism
conditions. Parent and zero-dose copies remain distinct declared arms even when
their parameter payloads are identical. No development metric ranks, discards or
selects arms. The existing collector's limit is 16 arms.

Each exported head has exactly two finite CPU FP32 tensors:

| Tensor | Shape | Source |
| --- | --- | --- |
| `value.weight` | `[1,768]` | Original baseline head, or the stored mechanism replacement |
| `value.bias` | `[1]` | Original baseline head, or the unchanged pinned parent when the mechanism did not edit it |

The builder checks the original worker artifact descriptors, content digests,
model/backend identity, actual patch parent and stored parameter hashes, complete
condition inventory and successful parent-restoration report. Encoder patches
cannot be converted into scalar-head candidates. Full heads are serialized and
reloaded before their tensor hashes and arithmetic are retained.

Old evidence is not upgraded to a newer worker's qualification. For example, a
random control record without a newly added post-storage orthogonality field
remains without that field. Its source report, patch and actual stored head are
bound; new qualification is not inferred from a code update.

## Build a private bundle

All references below are objects with an absolute `path` and the SHA-256 of its
exact file bytes. Keep original inputs, labels, weights and host receipts outside
Git. The request schema is exact:

```json
{
  "schema": "hepta.weight.current100k.candidate-bundle-request.v1",
  "parent_head": {"path": "/private/original-head.safetensors", "sha256": "HEAD_SHA256"},
  "features": {"path": "/private/features.safetensors", "sha256": "FEATURE_SHA256"},
  "labels": {"path": "/private/labels.safetensors", "sha256": "LABEL_SHA256"},
  "development_dataset": {"path": "/private/development.json", "sha256": "DATASET_SHA256"},
  "ordered_development_row_ids": ["ALL_ORIGINAL_ROW_IDS_IN_FEATURE_ORDER"],
  "mechanism_summary": {"path": "/private/mechanism/summary.json", "sha256": "SUMMARY_SHA256"},
  "mechanism_plan": {"path": "/private/mechanism/plan.json", "sha256": "MECHANISM_PLAN_SHA256"},
  "mechanism_receipts": {"path": "/private/mechanism/receipts.json", "sha256": "RECEIPTS_SHA256"},
  "baseline_report": {"path": "/private/baselines/report.json", "sha256": "REPORT_SHA256"},
  "baseline_plan": {"path": "/private/baselines/plan.json", "sha256": "BASELINE_PLAN_SHA256"},
  "prior_plans": [{"path": "/private/original-study/plan.json", "sha256": "OLD_PLAN_SHA256"}],
  "information_cutoff_ms": 0
}
```

Replace placeholders and the zero timestamp with verified values. The information
cutoff cannot be in the future or precede a known patch construction, input,
observed dataset, or baseline label cutoff. It is still a caller declaration.
Because old baseline reports have no independently verified construction wall
clock, prospective registration conservatively uses the bundle's **actual new
creation time**, rather than reusing an earlier label cutoff as a seal time.

```sh
python experiments/weight/current100k_candidate_bundle.py build \
  --input /private/bundle-request.json --input-sha256 REQUEST_SHA256 \
  --output /private/new-candidate-bundle
```

The directory must be new. Incomplete output is retained and cannot be silently
replayed. Output cannot be placed inside an old study. Original sources are read
and rechecked; they are not rewritten.

The result includes `bundle.json`, full heads, `cost-fairness.json`,
`cpu-head-qualification.json` and the pinned request. All development dataset IDs
must be excluded by the new registration. Label values must match their complete
declared row order in FP32, and each mechanism input must match an excluded source
row. Feature order is explicitly a caller declaration; these checks do not
authenticate every original market record or independently recompute all features.

## Prepare a registration without starting its clock

The preparation request has these required fields:

```json
{
  "schema": "hepta.weight.current100k.prepare-registration.v1",
  "bundle": {"path": "/private/new-candidate-bundle/bundle.json", "sha256": "BUNDLE_SHA256"},
  "registration_template": {"path": "/private/new-study-template.json", "sha256": "TEMPLATE_SHA256"},
  "producer_manifest": {"path": "/private/new-producer-manifest.json", "sha256": "PRODUCER_SHA256"},
  "collector_implementation": {"path": "/private/release/current100k_weight_shadow.py", "sha256": "CODE_SHA256"},
  "new_study_root": "/private/new-future-study"
}
```

An optional `backend_qualification` reference can pin the existing backend
qualification. The template must be a
`heptatrader.current100k-weight-shadow-config.v1`, with all effect-authority flags
false. It must bind the same encoder base and complete development dataset,
original exclusions and training mean, plus the intended future producer, reward
configuration, period and execution profile. It must not contain an existing
`plan_id`, registration clock or window dates. CPU FP32 and the existing HIP FP32
encoder profiles can feed CPU FP32 heads.

```sh
python experiments/weight/current100k_candidate_bundle.py prepare \
  --input /private/prepare-request.json --input-sha256 PREPARE_SHA256 \
  --output /private/new-registration-inputs

python experiments/weight/current100k_candidate_bundle.py verify-ready \
  --input /private/new-registration-inputs/ready.json --input-sha256 READY_SHA256
```

Preparation writes `sourceproof.json`, `registration-config.json` and `ready.json`.
It does not create the future study root. Every head entry in the configuration
binds both the bundle SHA and source-proof SHA. The existing `freeze` function
preserves these head-entry fields when it computes the new plan ID. Arbitrary
top-level configuration notes would be dropped by that registrar, so they are
not used for this binding.

Immediately before an authorized registration, `verify-ready` rechecks input,
head, source-proof and historical qualification digests and refuses an existing
study root. The existing registration entry point can then consume the prepared
configuration:

```sh
python -m laya_cell.current100k_weight_shadow_eval \
  --register /private/new-registration-inputs/registration-config.json \
  --root /private/new-future-study
```

That last command performs registration and starts the registrar's real clock.
It is **not run** by the bundle tool. It should only be invoked after the existing
supervisor's source, backend, resource and deployment requirements are satisfied.
The existing registrar validates producer registration and period provenance,
then creates its new window five minutes after actual registration. Its original
14-day input window and 24-hour settlement grace are unchanged.

If the future producer manifest is the same as a prior plan, the source proof
explicitly records that fact and its limitation for formal adoption. A new
directory or plan ID alone does not establish a new producer scope or statistical
independence.

## Numeric evidence and resident-resource scope

There are three separate claims:

| Evidence | What is established | What remains outside its scope |
| --- | --- | --- |
| Existing historical HIP benchmark | Its exact backend, runtime manifest, loader, reference feature cache, finite sample errors, original limits and cleanup evidence match | A uniform error bound over unseen inputs, current admission or future pre-open timing |
| New CPU head qualification | Saved FP32 heads produce matching separate-head and shared-head Linear outputs within the predeclared 0.001 USD tolerance | New end-to-end HIP encoder executions or predictive improvement |
| Future original pre-open receipts | Actual successful publication before the original command under the registered plan | Any missing or failed historical attempt |

The builder evaluates retained CPU features in chunks of two rows. It sorts head
arms as `HeadEnsemble` does, compares each shared result with the corresponding
separate Linear operation, and reports both raw USD and the collector's clipped
USD values. FP32 scaled values are converted to double before the USD100 scale,
matching the collector's Python-float conversion. All files are reloaded before
these checks. The receipt counts actual Linear calls, elapsed time, CPU threads,
and zero encoder/backward/optimizer work.

The historical verifier checks the qualification's referenced benchmark; a
backend label alone is insufficient. A different loader/cache, missing original
evidence, failed sample or cleanup leaves the numeric qualification pending.
Previously measured results for an old nine-head bundle are never relabelled as
new eleven-head results. In particular, the largest error seen on four historical
requests is not a global bound on all future features.

The existing collector encodes each request once and shares its BUY/SELL features
across the heads in **one registered family**. This does not show that a second
registered collector can reuse the first collector's encoder or previously
published features. Both plans have frozen configuration and successful pre-open
timing requirements. Cross-plan sharing needs an implemented, pinned interface
and original timing evidence; this bridge does not provide or assume it.

Resource admission and activation remain pending in `ready.json`, even if numeric
qualification is adequate. Historical warm-inference timings do not prove that
the resident encoder will survive current guard yields, cooldowns or cold loads
before the next original OPEN. Do not start an irrevocable future window merely
because preparation succeeded.

## Cost fairness

The cost audit reads each retained baseline receipt and keeps measurements in
their original scopes. It deduplicates identical receipts and checks real
gradient/optimizer counts. It does not add worker/model time to wall time, SGD
training time to construction time, or per-head times to the complete comparison
time. These intervals overlap.

Historical shared encoding, Astra diagnosis time/tokens and complete end-to-end
preparation costs remain null where unmeasured. Unknown consumption is not zero,
and the report always leaves speedup unestablished. The new bundle's verification,
serialization and head-only qualification have a separately measured preparation
scope; they do not retrospectively fill missing construction costs.

Realized full-head delta norms are recomputed after reloading. Ridge and SGD use
their declared absolute bound on concatenated weight and bias. Constants and bias
calibration are uncapped diagnostics. The mechanism's target-relative bound is a
different constraint. The first new baseline cap was approximately 0.00721934;
the earlier study's absolute 0.1 bound and the new mechanism full-dose norm of
approximately 0.02549516 are not interchangeable. The audit does not claim an
equal-constraint comparison when the underlying experiments differ.

Development baseline scores use raw USD. Future shadow predictions retain the
existing `100 * FP32 Linear` transformation and clip USD to `[-15,15]` before the
original scoring rules. Future improvement, coverage, support, fee stress,
uncertainty and selection remain the independent evaluator's responsibility.
