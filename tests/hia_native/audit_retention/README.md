# HIA audit retention policy

Target: `d3d75c30719db966b004756f610007a7c723729e`.
Compiler: `d3e2c90173cf733e42b299d0c4274df4b593a12f`.
Imported audited JSON helpers: source
`15f560cf20834b5a24844e0eb7e699dcc6dd81ec`, qualified handoff
`7e7d6ea01e792b142f38eb13d2c8e087d2172047`.

This package closes one private policy boundary. `native/audit_retention.hepta`
owns quota checks, ordered victim selection, pending short circuits, repeated
activity/archive queries, archived Record comparison, and partial removal state.
The external activity, archive-read and guarded-remove effects are explicit
requests. The actual filesystem and lifecycle modules must execute those effects
under the existing store lock when the caller composition is installed.

`ABI.md` is the callable contract. It uses exclusive continuation workspaces,
copies its initial typed input, preserves input vector order, and has no fixed
128/512 allocation capacity. Those numbers retain their original quota meaning.

## Frozen qualification

The complete source, input-only domain, actual native runner and inert readers
are frozen together before the CI reference/native run. The reference contains
the unchanged original `archived_copy_matches`, `retain_before_begin` and
`retain_for_batch` bodies, original thresholds, and exact generic Record type.
Mechanical effect fixtures expose the complete ordered boundary trace; they do
not choose victims or compute archive eligibility on behalf of HIA.

The domain contains 257 original/HIA paired scenarios. It includes both entry
points, owner/global boundaries, both directory-sync flags, pending and owner
short circuits, activity errors, ignored archive-read errors, removal errors,
partial false/error completion, repeated queries after a removal, every state
pair and representative optional elapsed-value pair, full u128 times, Unicode,
empty strings, duplicate IDs, original unsorted order, and 48 seeded typed-input
scenarios. No expected semantic result or expected wire is stored in this domain.

The native runner schedules independent workspaces round-robin. It records all
source/output/workspace bytes before and after every actual call, including
physical guard tails. It performs 44 additional native-only protocol refusal
controls on exact source/response framing, stale sequence values, wrong effect
types, capacities and completed actors. These are counted separately from the
257 original/HIA comparisons.

The retained original and native stdout must agree byte-for-byte, including
each effect argument and reply, final return/error token and complete ordered
remaining records. The independent reader also follows every intermediate
vector change and requires that only a successful remove changes the live
vector. It validates immutable owned input copies, all header bytes, full
buffer suffixes and all continuation links.

Twelve rebound physical mutants, two relocated admissions and two post-refusal
admissions exercise the reader. Each carries an inert guard proving no native
execution, child process, filesystem write or unadmitted read. The final reader
independently verifies every mutation, relocation, full source, original locked
dependency and compiler generation. No UNKNOWN process is replayed.

Ordinary semantic processes have 60 seconds, builds/fetch/vendor 900 seconds,
and each inert-reader stage 180 seconds. The CI job has 15 minutes. Failure or
timeout is preserved with the complete available archive; a later source
revision does not relabel it as a pass.

Runtime execution needs only the compiled HIA image and the specified buffers.
Rust is the reference; Python supplies authoring, mechanical qualification
framing and read-only evidence verification. Neither is a semantic fallback in
the HIA runtime.

Full audit persistence, actual caller composition, public handler qualification,
production activation and whole-runtime replacement remain outside this leaf.
