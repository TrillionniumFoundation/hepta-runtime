# Native binary-choice contrast over frozen features

This read-only increment evaluates the complete paired task using actual F32
readout parameters reopened from the original checkpoint and an isolated native
candidate artifact. It follows the source-bound research bridge and reuses the
existing linear kernel, source parser, confined descriptor admission and artifact
owner. It does not publish or restore artifacts and does not change owner state.

## Source and computation contract

The request supplies two complete file SHA-256 values, the exact weight and bias
payload SHA-256 values, named F32 `[2, width]` and F32 `[2]` tensors, frozen feature
rows, one physical baseline per row, and ordered binary-choice pairs. Checkpoint
paths must pass the existing workspace policy. Native artifact IDs must resolve
through the canonical owner manifest and agree with the requested complete SHA.

Each source is opened once. The existing isolated parser reads both named tensor
descriptors from that admitted file descriptor. A subsequent complete streaming
hash captures both tensors, checks the descriptor header, checks metadata before
and after, and hashes all bytes outside the exact selected weight extent. All
forward batches then use the immutable coefficients captured in that same pass.
The evidence records the complete source SHA for every batch. The candidate must
have the same file size, weight extent and protected-byte commitment as the parent.
This protects the entire raw header, bias including signed zero, physical buffers,
and every other parameter. The profile therefore supports weight-only candidates.

Complete file hashing authenticates the actual evaluated parameters. Producer
code, cache, physical-source and evaluation-protocol hashes remain **declared
feature provenance**. This operation does not replay the model body to verify
those declarations. Reports explicitly keep `feature_provenance_verified=false`,
`full_model_executed=false` and `production_eligible=false`.

For each raw head row `z = W x + b`, the exact operation sequence is:

1. `contrast = F32(z[1] - z[0])`.
2. `score = F32(baseline + contrast)`.
3. For a complete query, `margin = F32(score_choice1 - score_choice0)`.
4. Convert that final F32 margin to F64 and accumulate squared error against the
   declared `-1` or `+1` target, in query order. Divide by the query count.

Accuracy selects choice 1 only when `margin > 0`; a zero margin selects choice 0.
The head uses the existing sequential F32 multiply/add kernel. This diagnostic
MSE is not the original training cross-entropy, a portfolio-return measure or an
NDU adoption certificate. Native kernel outputs may differ in low bits from a
BLAS implementation; the report retains actual raw output and query-margin bits.

## Pairing and data commitment

Rows must be in query-major order: choice 0, choice 1, then the next query. Every
pair must reference exactly `[2*i, 2*i+1]`. Odd row counts, missing pairs, duplicate
row or query identities, nonfinite values and targets other than `-1` or `+1` are
rejected. No tail can disappear through truncating iteration.

The versioned binary data hash covers the five source/provenance declarations,
row and column counts, every ordered row identity, every feature F32 bit pattern,
every baseline F32 bit pattern, ordered query identities, exact pair indices and
signed targets. SHA strings use fixed 64-byte lowercase ASCII encoding; dimensions
and indices use little-endian u64; values use little-endian F32; targets use i8.
The domain is `hepta.weight.binary-choice-data.v1` followed by a zero byte. A
different float JSON spelling cannot change the committed F32 value. A separate
bounded Rust JSON serialization binds the complete request, including artifact
IDs and paths, for the native report. It is not a raw request-file digest.

## One total budget

The existing per-kernel row limit remains 64. The complete 160-row, width-20 task
is evaluated in batches of 64, 64 and 32 for each source. Parent and candidate
share one total ceiling of 16,777,216 linear MACs and 16,384 output values. The
additional physical scores and margins also count against that output ceiling.
The actual task costs 12,800 combined MACs, 640 raw head output values and 480
aggregate values: 1,120 counted values altogether. No batch receives a fresh
whole-operation budget. A single 60-second deadline includes admission, parser
work, both complete source captures, both models and all aggregation. Each input
request is bounded to 1 MiB after Rust serialization; the example retains its
existing 2 MiB input-file ceiling. Checkpoints remain bounded to 2 GiB.

## Isolated research driver

The unchanged explicit-config example accepts a new request kind:

```json
{"kind":"binary_choice_contrast","params":{"parent":{},"candidate":{},"weight_tensor":"body.readout.weight","bias_tensor":"body.readout.bias","data":{},"expected_data_sha256":"..."}}
```

Use the complete typed schema in `weight_binary_choice.rs`; the illustration
omits required bindings and data. The worker entry remains the exact early
`rea-model-worker --request` delegation, before runtime thread creation.

For the sealed SmallHCSN cases, first run the existing 16-row engineering
`f32_roundtrip` requests. Their forced rejection verifies the native candidate
publication and restoration and does not measure task benefit. Then prepare
the complete-task requests with the actual candidate artifact IDs returned by
those successful roundtrips:

```sh
python qualification/weight_binary_choice_20261127/prepare_smallhcsn.py \
  --native-requests /absolute/sealed/native_requests_v1 \
  --receipt-map /absolute/seed_to_roundtrip_stdout.json \
  --model-root /absolute/isolated/models \
  --out /absolute/new/contrast_requests
```

The receipt map is a JSON object mapping `47`, `83` and `137` to absolute native
roundtrip stdout JSON paths. The preparer requires actual original/candidate
hashes and verified restored bytes; it does not fabricate candidate IDs or run
another model forward. `--check-source-only` validates the sealed full data and
computes its native binary commitment without requiring receipts.

After the native example returns each complete-task report, independently check
its aggregation and bindings using only its actual raw output bits:

```sh
python qualification/weight_binary_choice_20261127/verify_report.py \
  /absolute/request.json /absolute/native_report.json
```

This Python checker performs no model forward. It uses explicit binary32 rounds
between the three task operations, verifies every output-vector length and finite
value, checks each batch hash and cumulative work, and checks all scoped claims.
Its output pins the exact request/report/checker files. Full-model validation
requires the separately source-bound SmallHCSN body evaluator.

## Qualification status

The increment adds 12 Rust controls covering width 20, full 160-row execution,
64-row boundaries and an even tail; odd tails, total budget boundaries, bad
pairing and targets, duplicate identities, F32 signed-zero commitments, a rounding
counterexample and zero-margin tie rule, protected physics or bias changes even
under updated file hashes, stale source/payload/dtype/shape bindings, nonfinite
actual coefficients, expired deadlines, request-size overflow, an independent
binary data-hash fixture, actual canonical
artifact reopening and a fresh restored request.

At authoring these controls are **not native-executed**. Rustfmt 1.96 is only local
source preparation. Qualification must use the existing Rust 1.95 CI gates for
both feature sets and the release example. No gate, toolchain, resource limit or
active service is changed. Native evidence must identify the exact compiled
commit, tree, Cargo.lock, toolchain, binary SHA and runtime configuration.
