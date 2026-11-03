# Unified native artifact, analysis and weight runtime

This source integration keeps one durable process owner while adding bounded
Rust artifact operations and selected analysis backends. Exact test and
deployment receipts determine its qualified state.

The #84 continuation is described in [FULL_INTEGRATION.md](FULL_INTEGRATION.md),
including model sessions, richer static formats, fixed application manifests,
Java engines and offline web observations. Source-bound results and environment limits are indexed in
[QUALIFICATION_20261103.md](QUALIFICATION_20261103.md).

## Baselines and compatibility

| Input | Source identity |
| --- | --- |
| Native runtime convergence | `e1eb14ae8eff2fc2c3565a86a36b10dd44eac915` |
| X230 R9 | `94d7fecdb02f5a7ef3d5ff072665360eb0115e0f` |
| REA foundation #78 | `d54654c3b028ffcce3439f97ca9b15ca3d88492c` |
| Weight workbench #82 | `cc85ca47e1c074c94800fae5d1726f410a449847` |
| R10 work in progress | Independent [source snapshot](R10_SOURCE_SNAPSHOT_SHA256.json) |
| Behavior reference | Exact `rea-agents@6.8.0` [package pin](PUBLISHED_6_8_0_ORACLE.json) |

The original R10 worktree is left intact. Pending-record ownership transfer is
combined with the native final-use entry callback. Borrowed receipt decoding
retains full schema validation and materializes selected originals; inventory
digests retain the existing canonical bytes. Typed file observations reuse the
original read helpers without parsing unrelated inode-write code.

Empty `weight_workers` and `rea_static_profiles` are omitted from serialized
configuration, preserving the pre-analysis policy digest. An absent
`native_client` is omitted from an existing weight profile's identity. Enabling
or changing a profile deliberately changes its identity.

## Capability routes

| Interface | Execution and result |
| --- | --- |
| `rea_inspect_artifact` | Existing small-file Rust preview for ELF, PE, Mach-O, WASM, GGUF, safetensors and ZIP |
| `rea_inspect_model` | Isolated Rust GGUF/safetensors parser, paginated tensors/metadata, header or full-file commitment |
| `rea_read_model` | At most 64 KiB of exact bytes from a pinned file range or known tensor extent |
| `rea_inspect_archive` | Isolated classic-ZIP directory/local-header index, entry-role filtering and pagination |
| `rea_verify_evidence` | Existing REA semantic digest and selected schema checks, with explicit non-full-schema qualification |
| `rea_retain_preview`, `rea_read_preview` | Existing immutable native preview storage and restart retrieval |
| `rea_static_profiles/start/status/read/cancel` | Existing jobs owner with pinned GNU readelf/objdump or optional fixed JADX/Ghidra providers |
| `weight_profiles/open/call/status/read/close` | Existing resident model worker; optional pinned native Rust socket client |
| `weight_artifact_patch`, `weight_artifact_restore` | Rust immutable safetensors transformation and exact reverse patch |
| `weight_linear_forward` | Rust CPU F32 Linear calculation from a pinned file or verified private artifact ID |

Resident-worker tools require `weight_workers`; static-provider tools require
`rea_static_profiles`. Native artifact and Linear tools work independently of
these profiles under an enabled runtime policy and admitted controller roots.

## Large files and evidence scope

The controller opens the source once beneath approved roots and passes a
duplicate read-only descriptor to a helper of the same Rust executable. Payload
bytes are not copied into an IPC request. Controller and worker compare the
descriptor observation, file size and bounded structure commitments. The
controller independently hashes the reported structure and rechecks the same
descriptor before returning.

| Resource | Model reader | Archive reader |
| --- | --- | --- |
| Header or central directory | 16 MiB | 16 MiB |
| Retained index | 32 MiB | 32 MiB |
| Directory row ceiling | 100,000 | 50,000 |
| Page | 1–256 rows | 1–256 entries |
| Response | 1 MiB | 1 MiB |
| Full-hash buffer | 64 KiB | 64 KiB |
| Raw model range | 1–65,536 bytes | No member-extraction API |

Continuation pages require both the previous observation token and structure
SHA-256. An observation token detects filesystem changes; it is not a content
digest. Header/index identity does not verify every payload byte. Explicit full
hashing reads every byte with a bounded buffer and 300-second deadline.

GGUF v2/v3 and both byte orders are supported. F32/F16 storage extents are
checked; quantized/unknown layouts remain unverified and are not inferred from
neighboring offsets. Safetensors validates unique JSON members, dimensions,
declared extents, contiguous payload coverage and known dtype lengths.

The archive reader supports classic single-volume ZIP, checks central/local
declarations and bounded extents, and identifies filename roles for manifest,
DEX, native library, resources, Java class and signature markers. ZIP64,
multipart archives and unsupported name encodings receive explicit errors.
APK/JAR labels are structural observations. This path does not decompress,
validate member CRC, authenticate signatures or prove an installable app.

Model/archive reports use versioned Hepta formats and explicitly set
`rea_evidence_compatible=false`. They are not relabeled as REA `ev_` Evidence.
REA digest validation and retained small-file native previews retain their
existing independent contracts.

## Provider ownership and recovery

A GNU static profile narrows a central host policy with pinned runtime/backend
executables, SHA-256 values, exact GNU version, roots, operations and budgets.
Requests bind the complete profile, source hash and original idempotency key.
The caller cannot supply shell text or additional backend options.

For GNU providers, Linux seals the admitted backend and artifact in memfd snapshots. The artifact
snapshot defaults to a 64 MiB cap; its memory contract differs from the large
streaming readers. Each output stream is bounded. Selected header/build-id
summaries cite original stdout lines, and the controller recomputes them while
validating retained output. The analyzed artifact is never executed.

Optional JADX and Ghidra providers use verified installed Java launcher/JRE
paths instead of a sealed launcher snapshot. JADX seals its selected engine JAR;
Ghidra verifies the complete admitted `Ghidra/` installation subtree and exposes
only fixed import inventory. Their private scratch can remain after owner-level
interruption; observe the original job terminal before reconciling that scratch.
Exact engine pins, output limits and installation boundaries are documented in
[ELF_AND_JAVA.md](ELF_AND_JAVA.md).

Preview publication, static start, resident calls and native patch/restore take
effect-owner admission. A frozen owner cannot create these effects. Status,
retained results and original-job cancellation remain available. The original
job ID, request digest, host binding, output witness and process group remain
with the existing runtime; no second supervisor or recovery ledger is added.

`start` inherits the configured host's existing owner/reconciliation rules for
the same job/digest; isolated hosts use the existing jobctl path. `status` and
`read` never submit work. Preserve the complete request
after uncertainty and inspect its original identity. Cancellation requires
subsequent terminal observation before termination is considered confirmed.

## Native weight data and computation

Native patching accepts a full source SHA-256 and 1–1,024 exact element changes
to one F32/F16/BF16 tensor. Every change names its old little-endian bytes.
The source stays read-only; a streaming transformation produces a separate
candidate and source/candidate hashes. Exact no-ops preserve every source byte.
Linux publishes the synchronized model and reverse manifest together using an
exclusive directory rename. Reuse revalidates both manifest and file.

Restore reads a verified candidate ID, applies its inverse into another
artifact and requires the complete output hash to match the original parent.
It overwrites nothing. Limits are 2 GiB per model, 8 GiB/128 store objects and
300 seconds per transform. Incomplete staging consumes the same bounded store
budget; interruption is not a successful publication receipt. Details:
[NATIVE_ARTIFACTS.md](../weight-runtime/NATIVE_ARTIFACTS.md).

Native Linear computes `inputs × weightᵀ + bias` for one F32 tensor shaped
`[out_features, in_features]`. Tensor capture and complete-file hashing share
one streaming pass. Private artifacts use a verified ID and fixed model path;
caller paths under runtime state are refused. Tensor size, dimensions, batch,
output count and multiply-add count are bounded. Sequential F32 accumulation
can round differently from BLAS/GPU kernels on general inputs. Details:
[NATIVE_LINEAR.md](../weight-runtime/NATIVE_LINEAR.md).

## Distribution and remaining dependencies

| Route | Runtime dependency |
| --- | --- |
| Native artifact readers, Evidence digest, weight artifacts and Linear | Hepta Rust executable |
| GNU static analysis | Hepta plus the configured pinned GNU executable |
| Fixed JADX classes/sources and Ghidra import inventory | Hepta plus the admitted Java installation and engine files |
| General model probes, interventions and existing model adapters | Python/PyTorch worker; native Rust transport available |
| Existing remote process helpers | Existing Python/jobctl dependencies |
| Upstream differential harness | Exact Node REA package, outside the shipped runtime |

No Node REA supervisor or TypeScript implementation is shipped on the native
routes. Reference scripts remain development oracles. Python client fallback
remains for old profiles without a native-client pin, preserving their request
identities during migration. General Transformer graphs, tokenization,
F16/BF16 forward kernels and GPU execution still require their model backends.

## Reproduction

Use Rust 1.95.0 and locked dependencies on the development host. Both feature
sets have strict formatting/Clippy and isolated-test gates:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
cargo nextest run --locked --all-targets --no-default-features --test-threads 1 --retries 0 --no-fail-fast
```

Opt-in tests use `HEPTA_REA_STATIC_REAL_SSH=1` for `rea_static_external`,
`HEPTA_WEIGHT_TEST_PYTHON` for `weight_forward_external`, and additionally
`HEPTA_WEIGHT_REAL_SSH=1` plus `HEPTA_WEIGHT_TEST_WORKER` for
`weight_mcp_external`. Run the last test with `--ignored --test-threads=1`.
The fixture driver is `scripts/rea_static_fixtures.py --output-dir /absolute/new/dir`.

Static lifecycle injection uses a separately pinned synthetic slow engine;
actual GNU operations establish semantic output checks. Synthetic AMDGPU ELF
establishes structural observations, not real CUDA/ROCm execution. The
independent PyTorch comparison uses a held-out synthetic Linear task and does
not establish a production model improvement.
