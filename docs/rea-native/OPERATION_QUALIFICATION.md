# Frozen REA operation qualification

`scripts/rea_full_qualification.py operations` executes the original published
REA MCP and a separately identified native MCP. The original Rust matrix CLI
and its five gates remain unchanged. Operation qualification is a separate
claim; a successful Rust test matrix does not supply it.

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

## Explicit unfinished gates in the initial executable profile

The initial runner and consumer deliberately leave active cancellation and
deadline owner drainage, the complete overflow/compressed-name/independent
producer corpus, original build-receipt validation and oversized-result
retention open. `qualification.json` reports those requirements, and the
consumer independently knows the same unfinished requirements. Passing the
implemented comparisons returns a successful comparison exit code but does
not set `qualified` or close the operation. The remaining mechanisms must be
implemented and the original and native operations rerun before this profile
can become a complete operation qualification.

The pinned npm package files are authenticated against the published tarball.
Transitive dependency files and system libraries are trusted external runtime
inputs; their versions or the REA version string alone are not presented as
authentication of those bytes.
