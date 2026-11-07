# Native weight cohort candidate qualification — 2026-11-07

## Result and ownership

This candidate extends the existing HeptaRuntime immutable weight artifact owner
at base `bc38fb82244b946907886704b3c677bf00761cb9`. It adds
`weight_cohort_patch` and `weight_cohort_restore` to the original MCP tool router.
The candidate branch is `codex/wsp-cohort-20261107` in the existing
`TrillionniumFoundation/hepta-runtime` repository.

The implementation creates one complete, immutable safetensors candidate for a
bounded group of exact tensor edits. The checkpoint, manifest and reverse edits
are read back through the existing artifact owner. Publication uses the existing
private store and its cross-process lock, with exclusive directory publication.
It does not own or change a live model pointer. An atomic candidate artifact is
not a live-model compare-and-swap adoption transaction.

Qualification used the original `Cargo.toml` and `Cargo.lock` on the configured
development host. No dependency, admission cap, budget or permission was relaxed.
The final related regressions passed: **103 weight tests and 31 effect-owner-fence
tests**, with zero failures. The weight run additionally has three documented
ignored entries. Formatting and `clippy --locked --all-features -- -D warnings`
passed. This is a bounded engineering candidate, not a production model release
or a claim of scientific efficacy.

## Contract and unchanged bounds

| Property | Contract |
| --- | --- |
| Base checkpoint | One opened source descriptor; complete expected SHA-256; exact prior element bytes; metadata and full-stream identity rechecked |
| Members | 1–32 unique tensor names; repeated tensor members rejected |
| Edited elements | At most **1024 total across the whole cohort**, including all members |
| Element formats | Existing finite F32/F16/BF16 byte representation and tensor-layout checks |
| Update budget | Each member has an exact L2 bound; one additional exact global L2 bound covers every member |
| Model size | Existing 2 GiB maximum |
| Manifest size | Existing 512 KiB maximum; serialized request additionally bounded before expansion |
| Store | Existing `weight-artifacts-v1`, existing exclusive store lock, shared 128-directory/8 GiB budget |
| Journal | Private `weight-cohort-journal-v1`, at most 128 admitted request directories; no automatic history eviction |
| Active transactions | At most four retained cohort workers in one runtime process |
| Response deadline | 300 seconds after owner admission; a timed-out response does not cancel an admitted mutation |

The 1024-element limit remains a real capacity restriction. The MIT case with
65536 parameters per layer cannot fit this interface. Splitting one tensor into
multiple members cannot bypass the cap. A 147-parameter Hepta candidate can fit
the count limit, subject to all other checks; count eligibility says nothing about
its measured quality or adoption eligibility.

Every request binds checkpoint identity plus SHA-256 commitments for code,
tensor map, data manifest, external objective and dependency manifest. The data
manifest is expected to bind splits, freshness, time and units; the dependency
manifest is expected to bind generator/table inputs. These are immutable caller
commitments. The runtime does not fetch those external contents or independently
verify their scientific meaning, freshness, coverage or split independence.

## Group transaction and recovery

All members are validated before publication. The implementation prepares exact
native tensor changes, refuses overlapping byte ranges, computes the original
exact integer norm checks, and streams one complete candidate checkpoint.
It reuses the original private-directory, streaming, quota and exclusive-rename
helpers. Single-tensor and cohort artifacts share the same store and quota.

The journal retains canonical `intent.json` and `outcome.json` records. The intent
binds the full request, roots, state directory, implementation fingerprint,
candidate identity and inverse-restore identity. Records are privately created,
fsynced, exclusively renamed and read back. Publication puts the checkpoint and
all reverse-edit metadata under one `wc1_...` artifact identity. No consumer is
given a partial member artifact as a successful group result.

Retry the **same request identity** after an uncertain response. The same key
cannot authorize changed request content or a changed source. Before publication,
an interrupted stage is validated under the original store lock and rebuilt.
After publication, recovery verifies the existing complete artifact before
recording or returning the outcome. A completed outcome whose candidate is
missing, and a corrupt retained model/manifest/outcome, fail closed instead of
silently recreating accepted history. Symlinked, multiply linked or nonprivate
stage files are refused. An interrupted request's own stage is removed before
rechecking shared quota, so recovery does not consume an additional artifact slot.

Restore reverses every member into a new immutable artifact. Its complete SHA-256
must equal the original checkpoint commitment. It does not overwrite either
input artifact. A restored cohort cannot be restored again through this API.

### Cancellation and effect-owner admission

The retained transaction worker owns both its capacity permit and the original
`effect_owner_fence::AdmissionPermit`. The worker's `apply` operation owns the
original artifact-store flock through publication, full readback and journal
outcome. A caller abort or response timeout drops only the join, leaving the
admitted worker and both ownership guards alive. No caller-facing abort handle
for that worker is exposed.

This closes the concrete late-rename race: an uncancellable blocking
`renameat2` cannot outlive an RPC's dropped locks and publish a newly recreated
stage from a same-key retry. It also prevents an effect-owner exclusive handoff
from passing the admission fence while that old-owner mutation remains active.
Both new RPCs are registered in the existing complete mutating-tool owner audit.

The cancellation test blocks the actual rename worker, aborts the caller, checks
that an actual `AdmissionPermit` still excludes `LOCK_EX` takeover, and checks
that same-key recovery waits on the original store lock. After releasing rename,
only one complete candidate exists and exclusive takeover can proceed.

These cancellation results cover RPC cancellation while the runtime process is
alive. Separate tests send real `SIGKILL` at four durable phases—intent, staged,
published and completed—and recover the same request in a fresh process. They
do not establish arbitrary machine-power-loss, storage-controller, filesystem
corruption or whole-runtime-shutdown behavior.

## Continued training and optimizer state

`training` is mandatory and rejects unknown fields. It accepts only:

- `inference_only`, which does not declare continued training;
- `stateless_fresh`, which names gradient descent or projected gradient descent
  and commits to trainer code and a training protocol. This declaration forbids
  loading an old stateful optimizer checkpoint.

There is no implicit policy to preserve stale momentum, and no default
continuation policy. Unsupported stateful reuse or an extra optimizer-checkpoint
field is refused by the schema. Restored artifacts carry `inference_only`.

The runtime is not a trainer and does not migrate optimizer buffers. A separate
training owner must verify and implement the declared fresh stateless protocol
before resuming a candidate. The receipt therefore explicitly returns
`optimizer_state_migrated: false` and
`training_owner_verification_required: true`.

Every cohort receipt also has `production_eligible: false`,
`incumbent_pointer_modified: false`, `source_modified: false` and
`behavior_evaluated: false`. Source-byte integrity, candidate publication and
declared training policy do not establish main-task performance, preservation,
OOD behavior, calibration, latency, energy use or complete operational cost.

## Validation and reproducible evidence

The isolated development directory was
`/home/qian-qi/work/hepta-runtime-wsp-cohort-20261107-candidate-r2` on the configured
`desktop` development host. Existing production/other-session source and model
state were not modified. Toolchain receipts identify Cargo 1.95.0 and rustc 1.95.0.

The original dependency lock remains byte-for-byte unchanged:

`Cargo.lock` SHA-256:
`91fd7a8a50e2cbd179b0f5bc3e6d6d9e71b95a94bce4e9eaa9fba67bbb877863`.

`Cargo.toml` SHA-256:
`fdb5f653f9c3d858dc5d1e20b285a0141e3cbc40106b2f5619ff315a9bfe59f4`.

The original lock resolved, among other dependencies, `num-bigint 0.5.1`,
`rmcp 3.4.1` and `serial_test 3.5.0`. No research-harness shims or substituted
versions were used.

| Run | Exact gate | Result |
| --- | --- | --- |
| R2, `1a1b491f683-fc05-8871` | `cargo test --locked --all-features weight_artifact -- --test-threads=1` | Exit 101: private source transfer omitted three original APK/JAR/ZIP fixture files, causing four `include_bytes!` errors. Preserved as a failed run. |
| R3, `1a1b495e75c-fc05-8894` | Same command after restoring original fixtures and repository formatting | 20 passed, 0 failed, 1 ignored subprocess helper |
| R4, `1a1b4a51cc8-fc05-88eb` | `cargo fmt --all --check` | Passed |
| R4 | `cargo clippy --locked --all-features -- -D warnings` | Passed |
| R4 | `cargo test --locked --all-features weight_ -- --test-threads=1` | 103 passed, 0 failed, 3 ignored |
| R4 | `cargo test --locked --all-features effect_owner_fence -- --test-threads=1` | 31 passed, 0 failed, 0 ignored |

R3 is a subset of R4 and must not be added to R4's independent test count. The
three ignored R4 weight entries are the cohort and existing guard-journal
subprocess helper entry points, which their parent crash tests invoke explicitly,
and the existing separately authorized actual-head NumPy ridge fixture test.
That external actual-head fixture was not supplied or claimed qualified here.
Unrelated repository tests were not run as part of this scoped candidate gate.

The new cohort tests cover joint bounds and admission limits, all supported
finite element formats, whole-group refusal on wrong bytes, source/request
conflicts, one-store coexistence, actual cancellation and takeover exclusion,
real process-death recovery, private-stage symlink refusal, missing/corrupt
retained outputs, temporary/damaged outcome handling, artifact count recovery,
simultaneous same-key requests, exact inverse restore and native artifact reader
descriptor readback. Existing weight and fence regressions also passed.

Evidence files:

- [Initial failed build](wsp-cohort-20261107-evidence/build-r2-missing-fixtures.json)
- [First successful owner run](wsp-cohort-20261107-evidence/weight-artifact-r3.json)
- [Final complete validation receipts](wsp-cohort-20261107-evidence/owner-validation-r4.json)
- [All 272 compiled source/configuration SHA-256 entries](wsp-cohort-20261107-evidence/tested-source-sha256.json)

Every source/configuration hash in that manifest was checked against the final
local deliverable. Repository-wide formatting additionally normalized whitespace
in four pre-existing files: `fs/core.rs`, `runtime/documents.rs`,
`runtime/request_results.rs` and `runtime/ssh_direct.rs`. Those formatter-only
changes are retained so the candidate exactly matches the tested source bytes.

## Publication state and remaining qualification

Local commits and a base-to-head review patch are available. An attempted normal
Git push to `https://github.com/TrillionniumFoundation/hepta-runtime.git`, branch
`codex/wsp-cohort-20261107`, was rejected by automatic approval review. The stated
reason was that the destination had not been established as trusted
organization-owned and the broad task authorization did not explicitly authorize
uploading this payload to that exact repository. No alternate push route or PR
was attempted after the rejection. Publishing needs explicit approval for the
exact repository, branch and reviewable payload.

Remaining qualification includes live model-owner adoption and its group CAS,
actual training-owner enforcement/optimizer behavior, external data/model identity
verification, large-model capacity beyond the preserved 1024-element cap,
scientific efficacy and complete quality/cost evaluation, and release/deployment
validation. This implementation neither claims nor performs those actions.
