# Fixed-anchor F32 edit-program composition

This research module composes several exact edit plans into one candidate measured
against the original checkpoint. It closes a narrow gap in the current native
workbench: independently bounded source-to-candidate edits can accumulate more
drift than the experiment's original radius permits.

The planner uses the existing `src/mcp/weight_norm.rs` exact integer arithmetic
and `weight_tensor::ExactElementEdit`. It adds no dependency, optimizer, model
worker, artifact store, journal or production route. The final edit list is meant
for one publication by the existing immutable cohort owner.

## Source and status

Reference: `TrillionniumFoundation/hepta-runtime` main at
`d3d75c30719db966b004756f610007a7c723729e`.

The implementation and sibling tests are new research source. Actual standalone
qualification with official Rust 1.95.0 passed **29 tests, with zero failures and
one deliberately ignored private-input runner**. This includes six unchanged
native norm tests and 23 composition tests. Strict Clippy with `-D warnings` and
format checking passed. The ignored runner was separately invoked on the explicit
synthetic schema example and passed; it did not load an actual checkpoint.

All 28 resolved standalone dependency versions and registry checksums match the
reference Runtime lockfile. The standalone crate uses the complete unchanged
native norm source and its tests, plus literal extractions of the original exact
edit declaration and hex decoder. It uses actual serde, schemars, anyhow and sha2
dependencies, without substitute macros or mock numerical implementations.
This exercises the research module without compiling Runtime's unrelated process,
transport and artifact owners. Full-runtime, MCP and production qualification
remain separate and were not executed by this study.

See `evidence/summary.json` and the complete logs. The initial installation failure
from exhausted workspace storage and an initial harness formatting failure remain
retained. Installation and compilation subsequently completed in separate scratch
storage. `SOURCE_BINDING.json` and `verify_sources.py` check source identity only;
that check is not itself a test pass. During qualification no checkpoint, training
job, live pointer or deployment was changed.

## Contract

The request binds the complete original checkpoint SHA-256, model graph, tensor
descriptor map, task semantics, row/evaluation protocol, objective and dependency
manifest. Every step repeats that same binding and has a unique step ID. Hashes
are caller commitments: this planner does not read files or authenticate their
origin, and a row-protocol hash does not establish independent holdout custody.

Tensor contracts include name, F32 dtype, little-endian row-major layout, full
shape, original tensor hash, a protected flag and an exact member radius. The
descriptor-map hash is recomputed from the sorted name-to-descriptor mapping.
Policies and radii are also included in the complete canonical program hash.

For each coordinate, the first `expected_hex` is its original anchor. Every later
`expected_hex` must equal the preceding `replacement_hex`. The final plan emits
the original bytes and final bytes once per touched coordinate. Complete history
retains every intermediate edit, including signed-zero changes, exact no-ops and
changes that are later cancelled. A cancelled coordinate still consumes the
touched-coordinate budget and still has its original bytes authenticated when
the existing artifact owner applies the resulting plan.

The exact radius is computed from the final stored F32 values relative to the
original anchor. It is a net displacement, not accumulated path length. For
example, 0 → 0.75 → 1.5 fails a radius of 1 even though each step is smaller than
1. The program 1 → 2 → 1 has zero final displacement and retains both operations
in its history. Intermediate programs are never executed or published here.

| Bound | Value |
| --- | --- |
| Declared tensor contracts | 1–32 |
| Program steps | 1–64 |
| Tensor rank | 1–8, positive dimensions |
| Elements in one declared tensor | At most 1,048,576 |
| Edited elements per step | At most 1,024 across its members |
| Touched-coordinate union | At most 1,024 across the entire program |
| Total edit operations, including repeated coordinates and no-ops | At most 4,096 |
| Canonical request serialization | At most 1 MiB |
| Canonical result serialization | At most 2 MiB |

The serialization limits bound this pure function's additional serialization,
not a preceding transport's deserialization allocation. Nonfinite intermediate
values, invalid byte widths, uppercase or malformed hex, ambiguous duplicate
members/coordinates, shape mismatches, discontinuities, protected tensors and
budget violations are rejected. No normalization, hidden cast or epsilon is used.

## Existing-owner handoff

1. Preserve the complete request and returned program hash with the experiment.
2. Copy the returned exact edits and member radii into the existing cohort input.
   Keep the original checkpoint as the source, rather than publishing each
   intermediate step.
3. Let the existing owner independently validate the full checkpoint hash,
   actual tensor name/dtype/storage extent, old bytes and global/member radii.
   The current cohort owner treats `tensor_map_sha256` as a caller commitment:
   it does not recompute this planner's complete shape/map/payload-hash contract
   or authenticate its graph, semantics and row protocol. An integrating adapter
   must compare those contracts with the actual checkpoint and experiment before
   claiming that stronger binding. That adapter is not implemented by this study.
4. Evaluate the actual candidate through the appropriate model executor and
   independently frozen experiment. The existing cohort operation creates an
   immutable artifact; it does not assess model quality or adopt a live model.

Results explicitly set `source_authenticated`, `independent_holdout_verified`,
`cross_request_budget_enforced`, `intermediate_models_executed`,
`weights_modified` and `production_eligible` to false. In particular, unrelated
calls can declare different anchors: enforcing a global experiment allowance
across agents, processes and restarts requires an authoritative experiment owner.
This module does not manufacture such authority from a supplied hash.

## Register and test in an isolated full checkout

The source imports the actual private native helpers as a sibling under `mcp`.
It is intentionally not a standalone crate and does not replace dependencies
with test shims. Copy this directory to the same relative path in an isolated
full checkout of the reference commit, then apply `register-tests.patch` there:

```sh
git apply --check qualification/weight_program_composition_20261120/register-tests.patch
git apply qualification/weight_program_composition_20261120/register-tests.patch
python3 qualification/weight_program_composition_20261120/verify_sources.py --repo .
cargo +1.95.0 fmt --all -- --check
cargo +1.95.0 test --locked --all-features --lib mcp::weight_program_composition -- --test-threads=1
cargo +1.95.0 test --locked --no-default-features --lib mcp::weight_program_composition -- --test-threads=1
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 clippy --locked --all-targets --no-default-features -- -D warnings
```

Run on the configured development host as required by the repository's
`AGENTS.md`. The patch only adds a `cfg(test)` module registration; no MCP tool,
production handler or effect-owner route is added. All repository integration
gates still apply if this study is integrated. Record the actual toolchain,
source/binary hashes, commands, exit codes, logs and complete test counts.

The sibling suite includes real malformed-input and boundary calls to `compose`:
discontinuous bytes, every binding substitution, map/shape/dtype drift, duplicate
IDs and coordinates, no-op/protected tensors, nonfinite intermediates, exact
decimal/subnormal/signed-zero radius cases, member/global drift, cancelled union
capacity, repeated-operation budget and bounded serialization. The fixtures are
synthetic software controls, not demonstrated improvements to HeptaTrader.

## Reproduce the qualified standalone scope

`prepare_standalone.py` verifies the original helper source pins, extracts the
unchanged input declarations, and creates a new crate with the delivered lockfile.
The target directory must not exist. No Runtime owner is replaced or simulated.

```sh
python3 qualification/weight_program_composition_20261120/prepare_standalone.py \
  --source-repo . --out /absolute/new-composition-study
cargo +1.95.0 test --manifest-path /absolute/new-composition-study/Cargo.toml \
  --locked -- --test-threads=1
cargo +1.95.0 clippy --manifest-path /absolute/new-composition-study/Cargo.toml \
  --locked --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path /absolute/new-composition-study/Cargo.toml \
  --all -- --check
```

The source extraction and all dependency identities are recorded in the new
crate's `SOURCE_EXTRACTION.json`. This is the scope actually executed for the
reported 29-test result; the full-checkout integration commands above remain a
separate gate. Build, dependency-download and compiler setup time are recorded
separately from the test harness's inner time, and no training-speed comparison is
inferred from these software measurements.

## Optional pinned private request

The ignored test can run a separately prepared request without loading a model.
It authenticates the request file's exact SHA-256, creates a new private result
file and refuses to overwrite an existing output:

```sh
HEPTA_COMPOSITION_REQUEST=/private/request.json \
HEPTA_COMPOSITION_REQUEST_SHA256=FULL_REQUEST_SHA256 \
HEPTA_COMPOSITION_OUTPUT=/private/new-result.json \
cargo +1.95.0 test --locked --all-features --lib \
  mcp::weight_program_composition::tests::external_private_program \
  -- --exact --ignored --nocapture --test-threads=1
```

`synthetic_request.json` is a schema example only. Its model/tensor identities are
explicit synthetic commitments. Running it does not inspect or modify an actual
checkpoint. Use complete private checkpoint and semantic identities for a real
experiment, and authenticate the resulting edits again at the existing artifact
owner before any candidate publication.

## Related documentation correction

The companion edit to `docs/native-weight-guard.md` corrects stale statements
that the native guard lacked a hard radius and durable journal. Both already
exist in the reference commit. The correction describes their actual public
receipt and explicit same-request recovery without changing historical tests,
model evidence or qualification records.
