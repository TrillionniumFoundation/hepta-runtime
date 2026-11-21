# Source-authenticated semantic adapter study

This isolated Rust qualification crate binds checkpoint bytes to exact tensor
descriptors and two distinct, reviewed source profiles. It has no Runtime route,
parameter-edit owner or model-execution capability. Source authentication does
not establish model quality, independent evaluation or production eligibility.

The implementation was reviewed against `TrillionniumFoundation/hepta-runtime`
PR #141 at `666257e87540207d93a6f4275d86d9eaed6f1aa4`. Its production baseline
was `d3d75c30719db966b004756f610007a7c723729e`. The native `rea_evidence.rs`
duplicate-key JSON parser was reused, with its source identity retained in
`reference/MANIFEST.json`. This directory does not register a production route.

## Complete descriptors and partial captures

`authenticate_safetensors` checks a reviewed source size and SHA256, then derives
actual ordered shape, dtype, checked element count, contiguous offsets, byte
length and tensor payload hashes. An actual `[49,3]` shape cannot be claimed as
`[147]`. Duplicate keys, overflow, gaps, overlaps, unindexed tails and nonfinite
floating values are rejected. The deliberately narrow format profile accepts
positive rank 1–8 F16/BF16/F32/F64 tensors; it is not a replacement format owner.

`authenticate_claims` compares every descriptor field with that complete byte
capture. `authenticate_subset` instead checks a header prefix and whole provided
tensors against linked path, version, source-size and chunk-receipt identities.
Its result is a separate type: `require_complete_source()` always fails. A
reported full-file hash and arbitrary chunks are not a membership proof for
the entire file. Full-source admission must not accept that partial result.

## Reviewed profiles

### Laya masked B@A

The supported source profile has the following layouts:

| Layer | F16 base | F32 A | F32 B | Mask |
|---|---|---|---|---|
| `scorer.1` | `[768,768]` | `[2,768]` | `[4,2]` | output rows 0–3 |
| `scorer.3` | `[1,768]` | `[1,768]` | `[1,1]` | output row 0 |
| `act_head.2` | `[2,256]` | `[1,64]` | `[2,1]` | input columns 0–63 |

There is no alpha/rank scaling. The materialized reference adds masked `B @ A`
to the F32-cast base. The adapter forward adds the base affine result to two
separately rounded `F.linear` operations. The prototype records these distinct
execution contracts without claiming bitwise equivalence or performing either
forward. Factor norms do not establish an effective-weight edit budget.

The action task is frozen-parent answer correctness versus ACT/ESCALATE.
Requesting Call/Put semantics is rejected. The parent profile explicitly lacks
an action adapter. Price scoring retains its own input, option-label and
calibration contract; this profile grants no trading interpretation.

Adapter source is pinned to
`TrillionniumFoundation/heptatrader@ffec655e69c610e0c4af41c00e3565e84edeb940`.
Official `laya==0.3.28` package metadata and three required source-file pins are
retained under `reference/`; their Git blob identities match upstream SDK
commit `a4a8921afebfd852bba0000475cfb6ab737a124c`. Third-party source and package
bytes are not vendored here. Repository/package identity is not deployed-code
identity.

### Neuron F64 JSON

The second profile binds original compressed JSON to a reviewed fetch receipt,
checks the compressed pin, independently decodes one gzip member, rejects CRC
or trailing-member failures, and verifies the derived raw-JSON pin. The four
network shapes are `[48,85]`, `[48]`, `[4,48]`, `[4]`, totaling 4,324 F64
coordinates. Interpreted F64 little-endian tensor hashes are distinct from
physical JSON byte offsets. The complete raw source hash binds the JSON bytes.

All non-network fields receive a separate canonical structural commitment.
`validate_neuron_network_only` rejects changes to those physical/task fields or
the reviewed profile sources. An F64 model cannot silently enter the native
F32 composition/cohort patch format.

The reviewed task is the renewal endpoint event `X_deadline6 > 0`, with early
submission. Scores are STOP, WAIT, READ, REPAIR, `1−2p`, `2p−1`; `p` is the
fourth affine output's clipped sigmoid. Sensor REPAIR does not reset latent
state; background CTMC recovery/reset is distinct. No first-passage solver or
new NDU optimizer is implemented. Source identities are pinned to
`TrillionniumFoundation/hepta-private-ci@5669aa349fde9eb0b6692dbfaa55a1b9897f6e69`.

## Authority and receipt boundary

A reviewing owner supplies `ProfilePin` and the expected fixture-manifest hash.
They must not originate from an untrusted candidate. Matching these anchors
proves byte consistency, not the reviewer's identity or program semantics.

Authenticated types and `VerifiedProfile` cannot be deserialized.
`SemanticReceipt` and `Scope` have private fields and read-only accessors.
Effect and quality qualifications are constructed as false. Serialized
receipts are evidence, not authorization tokens; the binding hash is unkeyed,
not a signature. A consumer must reauthenticate against its own authoritative
pins or retain an independently trusted receipt identity.

## Standalone validation

The 21 unit tests construct synthetic data entirely in memory. They require no
host access, checkpoint, transfer receipt, private fixture, model inference,
secret or additional Python package. The CLI is compiled by `--all-targets`;
`cargo test` does not execute its real-source driver.

```sh
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 check --locked --all-targets --all-features
cargo +1.95.0 test --locked --all-targets --all-features -- --test-threads=1
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 check --locked --all-targets --no-default-features
cargo +1.95.0 test --locked --all-targets --no-default-features -- --test-threads=1
cargo +1.95.0 clippy --locked --all-targets --no-default-features -- -D warnings
```

These standalone checks passed during local qualification with official Rust
1.95.0 and real dependencies. Each test configuration passed 21 tests with no
failures or ignored tests. All 34 registry dependency versions/checksums match
the referenced Runtime lockfile. The separate path-scoped workflow reruns only
these source gates. It neither retrieves real captures nor executes a model.
This does not report full Runtime dev-server CI, nextest, release-build or
production-integration results.

For separately authorized real-source replay, obtain the retained capture
bundle and its independently reviewed manifest hash. Then run:

```sh
cargo +1.95.0 run --locked -- /path/to/capture/fixtures/MANIFEST.json REVIEWER_PINNED_MANIFEST_SHA256
```

The raw qualification evidence, original source/capture pins, complete logs
and historical failed attempts are retained separately. They are not included
in this source publication. See `PUBLICATION.md` for the publication boundary.

## Incremental Runtime handoff

Existing owners remain responsible for confined admission, old bytes, exact
budgets, immutable publication and durable rollback. A complete-source
descriptor check can sit between admission and candidate planning; the owner
must reauthenticate the same source at use. This versioned descriptor-map
commitment is not interchangeable with a caller-declared composition-map hash
without an integrating adapter.

Laya still requires full-base, deployed-graph, actual-forward and effective
edit-budget qualification. Neuron still requires an F64 artifact-edit/restore
boundary and controlled execution. Both require independent evaluation before
accepting edits. `KEEP_ORIGINAL_AND_STOP` remains a valid terminal decision.
