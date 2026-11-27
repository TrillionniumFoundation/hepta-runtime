# Source-bound isolated weight research

This change connects actual parameter bytes to the existing Runtime artifact
owners. It adds an F16 cohort research path, a verifier that reopens real
coefficient bytes, and a small F32 adapter that authenticates a stored bias
before using the existing durable guarded-head implementation. It does not
claim full-model execution or authorize a production model replacement.

The underlying affine, exact-F16 and coupled-F16 candidates are composed on
`84c7f9f1c6a32cfaeab1e56688be9fa0e32eef73`. Their first integrated source commit
is `165a004b030e687db8139df8d0dfe82cc027d676`. Its pinned Rust 1.95 formatting
and both feature-mode type checks passed. Its first production Clippy run
reported three nonminimal boolean expressions in metadata validation; this
change applies the equivalent `is_none_or` expressions without lint overrides.
Those first-run results do not qualify the additions documented here.

## F16: typed plan, actual artifact, reverse publication

`weight_artifact::cohort::f16_research::run` accepts the existing
`CoupledF16EvaluationParams` in an explicitly configured Runtime process:

1. The original path is admitted under the configured workspace roots. The
   existing compiler authenticates the complete checkpoint, exact element
   bytes, tensor payloads and update budgets. The coupled evaluator computes
   the original and planned W/b results on its committed feature rows.
2. A typed handoff binds the complete inline evaluation request and the bridge
   source identity to the original cohort dependency commitment. Changing
   labels, features, thresholds or constraints cannot silently reuse the
   original owner request key.
3. The unchanged cohort publication body creates an immutable candidate in its
   original store. The new layer does not create another artifact store,
   publication algorithm or active-model pointer.
4. The candidate is reopened by the canonical owner. Its manifest hash must
   equal the compiler's complete candidate commitment. A new complete hash
   pass captures actual W and b and runs the existing sequential F32 kernel
   on their exactly decoded F16 values. Prediction bit commitments must match
   the typed plan; an externally supplied prediction is never accepted.
5. A normal candidate failure or supplied-row rejection attempts the canonical
   inverse publication. A passing candidate is also restored because this is
   an isolated research operation. The restored artifact is reopened, fully
   hashed and recomputed against the original prediction bits.

`keep_without_publication` means source authentication and the read-only
comparison completed but all requested parameter bytes were identical.
`supplied_row_pass_and_restored` and `supplied_row_reject_and_restored` require
actual restored bytes and prediction bits. Any restoration error is retained
as `recovery_unverified`; it is never reported as successful rollback.

The existing cohort semaphore and effect-owner permit cover the retained
research task. The original retained-task helper is generalized only in its
result type; its custody logic is unchanged. Dropping the caller's join does
not abort that admitted task. A process crash, panic or runtime shutdown is a
different event. This layer does not add a durable research-stage journal and
hardcodes `crash_recovery_verified=false`. If publication does not return a
valid receipt, its state is uncertain and only the identical original owner
request may be reconciled. A changed or unavailable original file can prevent
this research entry from reaching reconciliation. The existing explicit owner
restore remains the recovery mechanism; there is no background recovery claim.

The F16 readback entry is also independently usable:
`weight_guard::f16::reopen::verify_from_admitted` accepts a typed evaluation,
the exact same parameters and an already admitted descriptor. It rejects
stale plans, changed inline parameters, wrong source bytes and wrong prediction
bits. `read_original_from_admitted` performs a new request without accepting
any prior prediction. The public `f16_research::next_request` first obtains the
descriptor from the canonical artifact owner and requires the original whole
checkpoint identity.

## F32: bind the actual independent bias

The canonical SmallHCSN export retains `body.readout.weight [2,20]` and
`body.readout.bias [2]` as separate original F32 tensors. It also retains
physical F64 buffers. No augmented feature, dtype conversion or new parameter
layout is needed.

`weight_guard::source_bound_f32::authenticate_from_admitted` authenticates the
named F32 bias vector during a complete checkpoint hash pass and compares each
little-endian bit with the existing guard's explicit bias. Signed zero is
preserved. Its `BiasBinding` requires the full bias payload hash; the weight
and bias names must be distinct. Wrong bias values, dtype, shape, payload hash
or any unchanged checkpoint byte are rejected before the guarded operation.

`source_bound_f32::evaluate` delegates to the original durable F32 guard after
that authentication. The original full-source checks still occur before
publication, on the candidate forward and on rejected-candidate restoration.
The adapter does not modify the original guard or journal bodies. Passing
artifacts remain isolated for review according to that existing contract.
The `next_request` entry reopens an actual restored artifact, authenticates its
bias again and runs a new native forward. It does not reuse cached outputs.

This binds one fixed head and its stored bias. It does not authenticate the
feature producer, establish effective LoRA identity, prove the model's head
semantics, or execute a recurrent/physical network. Those remain separate
whole-model and provenance checks. All new reports preserve
`full_model_executed=false`, `feature_provenance_verified=false` and
`production_eligible=false`.

## Explicit-process driver

The example binary is built by the repository's existing
`cargo +1.95.0 build --locked --all-features --release --bins --examples` gate.
It changes no running service and uses no default Runtime configuration:

```text
weight-source-bound-research ABSOLUTE_RUNTIME_CONFIG_JSON ABSOLUTE_REQUEST_JSON
```

Both files must be regular JSON files of at most 2 MiB. The explicit config is
validated by the existing Runtime schema and fixes the workspace roots and
private owner state. Results are emitted as one JSON value on standard output.

The driver also delegates the exact private `rea-model-worker --request JSON`
entry to the existing Runtime parser before it creates asynchronous runtime
threads. The library re-executes its current binary for non-test descriptor
inspection. This delegation preserves the original read-only inherited
descriptor, request limit, process limits, parent-death behavior and seccomp
checks; it introduces no parser or alternate filesystem admission. Unit tests
alone use a different in-process parser path, so a real example invocation is
required to verify this boundary.

After the existing exact-head CI gates succeed, the accompanying packaging
step retains the already built `hepta-runtime` and
`examples/weight-source-bound-research` binaries. Its manifest binds the
source commit/tree, `Cargo.lock`, Rust/Cargo versions, and each binary's byte
length and SHA-256. The artifact is for a separate research process on an
explicitly selected host. Packaging does not install it into a running service
or qualify a new deployment. The existing CI gates and their limits remain
unchanged.

Request variants are:

| `kind` | Required fields | Operation |
| --- | --- | --- |
| `f16_research` | `params` | Compile, publish, reopen, evaluate and restore an F16 cohort |
| `f16_next_request` | `params`, `artifact_id` | Fresh original-identity read of a restored F16 artifact |
| `f32_roundtrip` | `params` | Source-bind bias, run the original guarded patch, restore any passing artifact, then perform a fresh restored read |
| `f32_next_request` | `params`, `artifact_id` | Fresh stored-bias authentication and native forward on a restored F32 artifact |
| `f32_restore` | `params`, `artifact_id` | Explicit canonical inverse publication and a fresh original-identity read |

F32 `params` contains `guard` (the existing `GuardedPatchParams`) and
`bias_binding` with `tensor_name` and `payload_sha256`. F16 `params` retains the
existing `CoupledF16EvaluationParams`. All request structs reject unknown
fields. The driver never loads optimizer state or starts training. A driver
process crash after a passing F32 guard may leave an isolated candidate; the
explicit restore variant does not turn this into an automatic crash-recovery
claim. Runtime's normal filesystem and artifact quotas still apply.

## Verification and costs

The six new Linux F16 test functions execute owned temporary safetensors
fixtures through the actual cohort owner: a positive candidate, wrong-direction
and preservation-failing candidates, authenticated KEEP, same-request reuse
and changed-objective rejection, typed-plan and protected-byte corruption, and
bad old-byte rejection before publication. They also read the restored
artifact in a separate request.

Four new Linux F32 tests check exact signed-zero bias bits, wrong values/dtype/
hashes, unchanged physical-byte authentication, and integration with actual
guard publication/restoration plus a fresh restored request. These fixtures
are synthetic. They are not a real SmallHCSN full-model experiment.

The focused filter is:

```text
cargo +1.95.0 nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast -E 'test(weight_artifact::cohort::f16_research) | test(weight_guard::source_bound_f32)'
```

The same filter can be run with `--no-default-features`. Qualification still
requires the repository's full exact-source CI, both feature configurations,
Clippy and release examples. Rustfmt preparation alone is not execution.

The F16 preflight performs two full checkpoint passes; each candidate/restored
head readback adds another complete pass, and the canonical owner performs its
own verification, copying and inverse work. The F32 adapter likewise adds a
complete bias-authentication pass before the original guard. These costs are
not estimated from edited element counts. No report claims lower total cost
than training, total end-to-end cost, independent holdout gain or global NDU
improvement without separate measurements.
