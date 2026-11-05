# Frozen REA operation qualification

`scripts/rea_full_qualification.py operations` executes the original published
REA MCP and a separately identified native MCP. The original Rust matrix keeps
its five gates and now records an additional explicit build of the shipping
MCP binary. Operation qualification is a separate claim; a successful Rust test
matrix does not supply it.

The first profile is `rea-agents-6.8.0/inspect_elf_notes/v1`. The runner checks
every installed file against the frozen npm tarball before launching the actual
`scripts/rea.mjs mcp` entry point with both schema profiles set to `full`. It
records Node's binary and version separately from the protocol provider identity
`rea-elf-notes` / `REA ELF note parser` / `1`. Preserving that frozen protocol
identity does not describe the native implementation as a JavaScript engine.

```sh
python3 -B scripts/rea_full_qualification.py operations \
  --operation inspect_elf_notes \
  --repo /absolute/frozen/hepta-runtime \
  --binary /absolute/frozen/hepta-runtime-binary \
  --binary-sha256 EXACT_BINARY_SHA256 \
  --reference-package /absolute/install/node_modules/rea-agents \
  --reference-tarball /absolute/rea-agents-6.8.0.tgz \
  --node /absolute/node \
  --build-summary /absolute/original-build-summary.json \
  --build-summary-sha256 EXACT_ORIGINAL_BUILD_SUMMARY_SHA256 \
  --output-dir /absolute/new-private-operation-results
```

The output directory must be new. The profile currently requires the probed
Node 22.23.4 runtime. No network access, package installation, remote analysis
engine or device operation is required. The native runtime configuration names
only the private fixture workspace and an unused non-executable remote host.
The runner does not change `HOME` or reuse application state from another run.

## What the evidence contains

Each original request and response is retained in a bounded stdio transcript.
Individual case files retain the complete response, including JSON-RPC errors,
MCP `isError`, `structuredContent`, target-content provenance and text. JSON text
is parsed before comparison so object-key insertion order and whitespace do not
create a false difference. Non-JSON text is compared exactly. No provider,
Evidence, null, error detail or location field is removed from comparison.

The independently encoded byte fixtures cover ELF32/ELF64, both byte orders,
program/section tables and physical aliases, owner decoding, GNU records,
descriptor hashes, alignment and selected malformed/limit cases. The runner
also executes input omission/default/null/type/range/unknown-key cases and
transmits `1.0` and `1e0` literally to distinguish JSON integer semantics from a
Rust unsigned-integer deserializer. Successful observations are checked against
independent byte facts and an explicitly limited integer-only semantic-ID
calculation. That development checker is not a substitute for the production
ECMAScript floating-point canonicalizer.

The public `get_evidence_bundle` call checks complete retention, deterministic
record order, duplicate behavior and the summary/filter projections required
by notes records. A new MCP process must start with an empty session registry,
even when it uses the same native runtime configuration. This follows the
frozen original's in-memory session ownership; it does not invent automatic
cross-process persistence. The bundle tool's unrelated operations are not
qualified by these checks.

Source snapshots and Linux inotify observations bind the producer, fixtures,
tests and native source tree before and after execution. Package and binary
identities are checked again. EOF shutdown must complete under the original
owner; forced SIGTERM/SIGKILL is recorded as a failed lifecycle observation.
These artifacts provide local execution provenance. They do not defeat a
malicious operator who can rewrite both the repository and all evidence.

## Original build, source and executable binding

`scripts/rea_build_evidence.py` independently checks the original
`hepta.rea.full-qualification.v1` receipt before either MCP is launched and
checks its retained bytes again during offline consumption. Supplying a build
receipt requires both `--build-summary` and `--build-summary-sha256`. Omitting
both still permits finite behavioral comparisons, with
`build-source-attestation` remaining `OPEN`.

The build must be produced by the selected repository's own
`scripts/rea_full_qualification.py`. Its source identity is observed before and
after execution and must equal the corresponding source snapshot entry. Run
the complete matrix after all source, fixture and qualification-script changes
have been integrated. For example, an explicit zero-debug build profile is:

```sh
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
python3 -B scripts/rea_full_qualification.py \
  --repo /absolute/frozen/hepta-runtime \
  --cargo-home /absolute/existing/offline/cargo-home \
  --target-dir /absolute/task-exclusive-target \
  --output-dir /absolute/new-private-build-results \
  --jobs 4
```

The three version preflights precede all five existing gates: formatting, Clippy
with all features, Clippy without default features, and the corresponding two
nextest runs. Commands are reconstructed independently, including `--locked`,
`--offline`, `--all-targets`, one test thread, zero retries, the ignored default
filter and failure on zero selected tests. Both raw nextest logs must contain
one terminal summary showing a positive executed count and the same passed
count. Skipped tests do not count as passed. Successful exit codes, stored
summary labels and a handwritten `PASS` cannot supply that observation.

A ninth stage runs `cargo build --locked --offline --all-features --bin
hepta-runtime --message-format=json-render-diagnostics` with the same explicit
jobs and target directory. The retained Cargo JSON must identify exactly one
`hepta-runtime` binary artifact from the selected manifest and `src/main.rs`,
with the shipping `default` and `remote-fs` features, the expected executable
path and a successful terminal build event. The executable observed immediately
after that stage must equal the final build observation and the binary actually
selected for the operation run by byte count and SHA-256. Cargo's freshness
flag is retained; an offline dependency/target cache remains a trusted input.
The binary snapshots after each nextest run are historical observations only.
In particular, the no-default-feature run cannot establish production of the
MCP binary, whose Cargo target requires `remote-fs`.

The consumer also checks complete, identical before/after source inventories,
zero source-monitor events and no coverage loss, uninterrupted stage order,
toolchain identity, stage-exit and final log hashes, and the effective build
environment. The producer fingerprints the documented Rust/Cargo environment
selection, including `CARGO_BUILD_*`, `CARGO_PROFILE_*` and `CARGO_TARGET_*`.
`CARGO_PROFILE_DEV_DEBUG` and `CARGO_PROFILE_TEST_DEBUG` are recorded explicitly
as their actual string values or `null` when unset; they are checked against
the fingerprints. A zero-debug dev override must also match the compiler
artifact's debug profile. An older receipt without those observations cannot
authenticate the environment by assuming default values. This selection is
not an inventory of every system, linker, toolchain or dependency input.

The importer preserves the original summary, three source artifacts and
eighteen stage logs byte for byte in `build-evidence/`. It reads only the fixed
sibling filenames, refuses links and special files, enforces size bounds and
rechecks the copied originals. Absolute execution paths inside the original
summary remain metadata. They are not followed by the offline consumer, so an
unchanged bundle remains verifiable after relocation without the original
build directory or executing the compiler again. The summary digest supplied
by the caller pins the original receipt before import.

An earlier full-matrix receipt that lacks the explicit binary build, observed
producer or effective profile environment does not establish this new binding.
Neither does a custom receipt that records selected Rust checks. Such evidence
must be retained unchanged; it must not be upgraded by rewriting its status or
filling missing observations. Generate a new complete run from the integrated
source instead. Passing the build validator discharges only
`build-source-attestation` for the bound operation receipt, and establishes no
REA behavioral parity or lifecycle coverage by itself.

## Qualification index and refusal rules

The optional file
`docs/rea-native/compatibility/REA_6_8_0_QUALIFICATIONS.json` contains only a
schema and receipt references:

```json
{
  "schema": "hepta.rea.operation-qualifications.v1",
  "entries": [
    {
      "operation": "inspect_elf_notes",
      "profile": "rea-agents-6.8.0/inspect_elf_notes/v1",
      "report": "docs/qualification/SELECTED_RUN/qualification.json",
      "sha256": "EXACT_ORIGINAL_RECEIPT_SHA256"
    }
  ]
}
```

This is a shape example, not an installed qualification. Artifacts referenced
inside a receipt are relative to its directory, so an unchanged receipt and
its bytes can be archived and checked offline. Native/source execution paths
remain factual metadata, not local files that an offline check must execute.

`scripts/rea_operation_evidence.py` checks the pinned files and independently
replays comparisons from the original wire. It regenerates the required fixture
manifest from reviewed source, binds responses to their actual requests,
compares the schemas with the frozen ledger projection, and checks the current
source tree. Missing, duplicated or invented cases, changed numeric spellings,
stale source, symlinks, modified artifacts and a handwritten `PASS` do not
qualify an operation. The consumer never launches a subprocess or downloads
the original package.

The capability map may declare `operation_candidate`; that is an implementation
scope, not a qualification. `partial_operation`, `related_facility` and `absent`
cannot be promoted by a finite receipt. A candidate remains `OPEN` until every
required gate is independently established. With no index, the ledger retains
its previous inventory-only projection exactly.

## Required observations that remain open

The initial runner and consumer deliberately leave active cancellation and
deadline owner drainage, the complete overflow/compressed-name/independent
producer corpus, and oversized-result retention open. Build receipt validation
is implemented, but its requirement remains open for every run that has no
independently accepted original build bundle. `qualification.json` reports
those requirements, and the consumer derives them again from the retained
evidence. Passing the implemented comparisons returns a successful comparison
exit code but does not set `qualified` or close the operation. The remaining
mechanisms must be implemented and the original and native operations rerun
before this profile can become a complete operation qualification. Synthetic
validator fixtures and negative controls test refusal behavior; they are not
actual Rust matrix or operation qualification evidence.

The pinned npm package files are authenticated against the published tarball.
Transitive dependency files and system libraries are trusted external runtime
inputs; their versions or the REA version string alone are not presented as
authentication of those bytes.
