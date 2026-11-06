# Public Evidence bundle import

The native MCP entry point is `rea_import_evidence_bundle`, mapped to the frozen
REA 6.8.0 `import_evidence_bundle` contract. The handler is registered in
`src/mcp/server.rs`; `rea_evidence_import.rs` owns file admission, authentication,
publication and the public result. Imported JSON is data and is never executed.

## Contract and publication

The tool advertises the captured input/output schemas and original annotations.
The selected path must be absolute, nonempty and NUL-free. Original field-error
ordering, file errors, bundle authentication errors, wrong-kind single-record
errors and target-content provenance are retained. Frozen schema coercion can
throw `Cannot convert object to primitive value`; that case remains the original
plain-text error result, with no fabricated validation issues or retained data.

Authentication covers the seven bundle arrays, complete Evidence semantic IDs,
unique records, canonical manifests, residual-unknown shape and revision digests,
complete history chains, evidence and relationship references, current dependency
cycles and qualified resolution requirements. Process-capture records additionally
authenticate their `normalized_result` through the separately reviewed capture
schema, journal, finalization, coverage and commitment implementation. The parsed
capture projection is used for validation without replacing the retained source.

One session mutex publishes the entire authenticated candidate. Conflicting
records, conflicting revisions, invalid merged graphs and cancellation observed
at the final commit decision leave records, display metadata and all revisions unchanged.
Record-only imports preserve the existing complete record when semantic identity
and display metadata agree; changes to subject name, subject local path or caller
input path replace the record. Imports containing unknown history follow the
original full candidate merge and retain all revisions. Export and complete
bundle queries include that history; summary counts include every revision.

The retained record owns its file parser's property-order metadata. Fixed schema
objects use the frozen schema order; arbitrary JSON objects retain their actual
input order, including legitimate own `__proto__` data. Fixed schema objects
strip the original special `__proto__` key without stripping arbitrary payload
members. Imported order is private server state, not caller-supplied metadata.

## Cancellation and resource scope

An admitted owner retains its capacity and effect fence through file descriptor
cleanup, blocking authentication and the atomic session publication point.
Dropping an asynchronous waiter signals its blocking owner; it does not release
the running owner's permits. Completed records remain retained after publication.
The observed original SDK suppresses a response to a cancelled request. Tests
record that protocol observation separately from tool results, then require the
same session to answer a query and successfully accept another import.

The native profile remains bounded: Linux descriptor ownership and configured
workspace roots, a 128 MiB estimated materialization budget, a 16 MiB scalar-token ceiling, parser
depth 120 and at most two active import owners. Unsupported resource/platform
conditions return explicit native capability boundaries. These are documented
differences from the reference, not corruption findings or proof of complete
replacement. No platform signature or imported analysis claim is made true by
authentication of its Evidence identity.

## Reproducible qualification

The reference is the actual `rea-agents@6.8.0` npm package, source
`93b8b82db70279e40f484114cff9dc1958dc14ee`, tarball SHA-256
`8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb`.
Both tools below run the original Node MCP server and an explicitly supplied
native shipping binary against identical files and requests. They record the
binary/package identities, source before/after snapshots and source-change
observations. They never set replacement qualification to true.

- `scripts/rea_evidence_import_qualification.py` has a 118-comparison gate:
  complete replies and object order, input/file/integrity errors, idempotence,
  metadata replacement, complete revisions, merged-graph rollback, cold import,
  process capture, fixed-schema/free-JSON prototype keys, four original schema
  exception paths including standalone-record fallback, exact unknown-key labels including control characters, canonical
  exports and active-parser cancellation with session reuse.
- `scripts/rea_evidence_import_overflow.py` has a separate 22-comparison gate:
  actual APK parsing beyond the original response limit, complete export, public
  import into a new session, retained discovery, six complete digest pages,
  complete export, another cold public import and three byte-identical canonical
  exports. The original 10 MiB response budget is unchanged.

The controlled APK retains the original fixture and adds three declared unknown
digest entries of one MiB each. Tests require every digest byte to survive and
require `algorithm: unknown` and `matches_apk: null`; they do not assert signature
verification. No engine, captured process, device or external service is mocked
and then counted as a successful real operation. The process-capture data fixture
validates imported observations only and does not execute a process capture.

Each runner accepts `--binary`, `--binary-sha256`, `--reference-package`,
`--reference-tarball`, `--node`, `--repo` and a new `--output-dir`. The final
integration matrix and both runners must use the same frozen native binary.
Initial failing receipts remain preserved beside later corrections; successful
focused runs alone are not a final combination or replacement receipt.

Public unknown-management tools, all provider/resource/platform profiles, full
reference capability parity, real multi-host failure recovery and complete cost
comparison remain separate requirements. An evidence-file analysis view borrows
a parent; only this public import tool commits the complete bundle to a session.
