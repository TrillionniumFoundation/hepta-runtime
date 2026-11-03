# Controlled mechanism experiments

`workers/weight/weight_runtime/mechanism.py` supplies
`run_experiment(call, opened, plan)`. `call(operation, parameters)` returns the
existing resident worker's result object. Transport, request identity and durable
operation receipts remain with that worker. No new execution owner or model
provider is introduced.

## What is bound before inference

A `hepta.weight.mechanism-plan.v1` identifies the exact model and backend, a pinned
target matrix, selected rows/columns, development inputs and their canonical JSON
hashes, output names, doses, random seeds and resource limits. The selected block
is at most 8,192 elements. The runner reads it through `inspect` and bounded
`query` pages. It accepts an explicit additive delta or a writer projection; it
does not infer a useful delta from outcome labels.

An optional structured `hypothesis` contains exactly `statement`,
`expected_observation`, `falsifying_observation`, `diagnostic_evidence` and
`author_model`. Evidence is a nonempty bounded list of `{ref, sha256}` records;
`ref` may identify an existing artifact or source file. The hypothesis is retained
unchanged, but the runner does not authenticate the external references or declare
the causal explanation proven. With no hypothesis, `diagnosis_present=false` and
`hypothesis_status=not_provided`; an unlabelled edit cannot count as a completed
mechanistic diagnosis.

Doses must include zero, one and an intermediate value. All candidate payloads
and random controls are fixed before the first forward. For C candidate/control
patches and E examples across the input cases, the total is `(C + 2) * E` forward
examples: one parent pass, all C conditions, and a repeated parent pass. The
candidate count includes the zero-dose patch. `required_limits(plan)` exposes
these counts before opening a disposable worker. Actual worker counters and batch
sizes must agree with the plan.

The runner checks the actual `model_input_id` for each case across every condition.
The input specification is copied to immutable canonical bytes, so changing the
caller's original dictionary cannot silently change a later comparison.

## Controls and precision

The additive control uses the same support, an isotropic random delta orthogonal
to the proposed delta, and the same pre-cast Frobenius norm. Its rank is not
matched. The writer control keeps a rank-one projection and the same support,
uses an orthogonal random output direction, and matches the proposed delta norm.
The seed is recorded. Degenerate controls are rejected without retries.

The existing `patch` operation compiles the target to physical parameters, casts
to the actual storage dtype, saves and reloads it. The experiment retains both
effective-coordinate measurements and physical storage measurements. A control
passes norm matching only if **both** realized effective and storage delta norms
are within the predeclared relative tolerance. A zero realized reference norm is
not a valid norm-matched control. A mismatch remains a completed, explicitly
failed control; the runner does not tune a replacement against observed results.

Zero dose uses multiplication by one to preserve signed-zero bits. It must leave
stored parameter bytes and all output artifact bytes identical. After all probes,
the runner verifies hashes of every touched physical parameter and the effective
target, and repeats all parent outputs with `bypass_feature_cache=true`. A provider
with encoder caching must report actual encoder recomputation and zero cache hits
for that final parent. It does not claim a hash audit of untouched model parameters.

## Evidence and limits

The result is `hepta.weight.mechanism-experiment.v1`; each condition has a
`hepta.weight.mechanism-candidate.v1` record. It contains worker artifact references,
encoded input identities, dose/control metadata, output changes and restoration
evidence. Probability outputs are explicitly named and validated as simplexes
before total variation is reported. A regression provider rejects probability
labels even when its USD outputs happen to form a numeric simplex.

Costs include actual forward examples, candidate count, public worker operations,
queried scalars, model forward time, available worker CPU/wall receipts and unique
retained artifact payload bytes. Payload accounting excludes descriptor and
request-ledger overhead; the worker's existing artifact limits still apply.
Each probe retains its computation receipt. When every probe reports encoder
counts, the result also totals actual encoder calls and feature-cache hits/misses;
otherwise these totals are explicitly unavailable, not reported as zero work.
Process CPU time includes worker CPU time when embedded, so those values must not
be added. The CLI additionally records model load time and peak process RSS.

Wall limits are checked before and after each call, including the final inspection;
an operation that returns too late produces a failure with its observed cost and
artifact references. Query/operation limits are checked between calls. The callable must honor
the supplied `timeout_ms`; the supplied CLI uses the resident transport's hard
request deadline and memory watcher. A hard interruption can leave an unresolved
durable request; it cannot produce a successful result.
An embedded direct `Session.dispatch` callable supplies only the runner's between-
call checks unless its owner adds a hard deadline; those checks cannot interrupt a
running tensor operation.

Every result is a **development mechanism screen**, with
`production_eligible=false` and `new_unseen_or_prospective_data=false`. A changed
output, more variation, a plausible dose response, or a passing random control
does not establish improved forecasting. Independent outcome evaluation and
promotion remain separate.

## CLI

`experiments/weight/mechanism_experiment.py` reads a SHA-pinned configuration and
plan. The configuration's output directory must be `OUT/artifacts` and the caller
must already supply its authorized input roots. It lowers worker hard limits to
the complete plan, retains the executed open-spec hash, and writes immutable plan,
request receipts and summary files. It reads back an identical completed run;
unfinished directories are never silently rerun.

```sh
python experiments/weight/mechanism_experiment.py \
  --config CONFIG.json --config-sha256 CONFIG_SHA256 \
  --plan PLAN.json --plan-sha256 PLAN_SHA256 --out OUT
```

The example arguments are placeholders for actual pinned files, hashes and an
absolute output directory. The runner does not edit source checkpoints, production
profiles or trading processes.

## Tests

`python -m unittest discover -s workers/weight/tests -p test_mechanism.py -v`
uses real CPU PyTorch modules and safetensors, including BF16 rounding, signed-zero
preservation, dose response, typed plan/identity failures, encoded-input drift,
actual batch accounting, physical/effective norm differences and CLI recovery.
Missing PyTorch is a missing test dependency, never a mocked passing result.
