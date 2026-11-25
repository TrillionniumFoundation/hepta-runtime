# Finite Linux-local ELF operation profile v2

This profile composes actual public-MCP observations across the existing
operation, ELF/Evidence family and owned-lifecycle runners, plus a new fixed
format corpus and native readback capacity sequences. It is a separate,
explicitly bounded composition of observed components. It does not
change the original v1 receipts, the 229-operation ledger, its 18 families, or
the requirements for a complete REA replacement.

The profile identifier is
`rea-agents-6.8.0/inspect_elf_notes/linux-local/v2`. Its independent consumer is
`scripts/rea_operation_profile_v2.py`. A successful assessment says
`SCOPED_COMPOSITION_VERIFIED`, `scoped_composition_verified: true`,
`qualified: false`, `upstream_operation_qualified: false`, and
`ledger_promotions: 0`. This is a component result; it does not close the original
nine-gate replacement contract or any of the 229 operation rows.

## Fixed scope and evidence

The original package is `rea-agents@6.8.0`, with its existing frozen tarball,
2,398 installed-file inventory, catalog and Node 22.23.4 binary pins. Every
behavior runner launches the actual `scripts/rea.mjs mcp` and the selected
native `hepta-runtime mcp`, using private local fixture roots. It does not
contact a provider, modify an installed service or reuse application state.

The new corpus has 99 deterministically encoded ELF files, totaling 27,960
bytes. It covers ELF32/ELF64 in both byte orders, ordinary/zlib/Zstandard
section names, output-size and integer/range boundaries, unsupported name
codecs and compressed note storage, and seven unchanged decoder regressions
now exercised through public MCP. The zlib stored block and Zstandard raw
frame are encoded directly; compressor version or heuristics cannot change
the manifest. The consumer regenerates the complete ordered manifest and
verifies every retained fixture byte, response and request binding.

This set does not stand in for the historic 5,244-input standalone decoder
corpus or every possible compressed stream. That broader corpus and arbitrary
format coverage remain outside this profile. Successful responses must also
match independent header, byte-order, GNU descriptor and Evidence-ID facts.
Errors retain the complete original opaque MCP result; decoding embedded JSON
strings is a separate diagnostic, never permission to discard text differences.

| Gate within this profile | Required independently replayed observations |
| --- | --- |
| `contracts` | Original full schemas and native routes in actual `tools/list`; family contract comparisons. |
| `results` | All original v1 cases, all 99 format cases and all 50 family comparisons, including opaque response strings. |
| `evidence` | Independent record facts, semantic IDs, retained record sets and family export/import canonical bytes. |
| `typed_outcomes` | Fixed malformed/unsupported/error cases and actual owned cancellation/deadline outcomes. |
| `limits_and_cancellation` | Input, integer, decompression and 10 MiB output boundaries; active capture/worker cancellation and independent concurrent completion; actual 4-snapshot, 128 MiB aggregate and 64 MiB per-snapshot refusals. |
| `source_package_boundary` | Same complete selected source snapshot, frozen package/Node, native binary and independently replayed full original build matrix. |
| `format_architecture_corpus` | Exactly the original operation fixtures and regenerated 99-case corpus; no universal-format claim. |
| `retention_and_pagination` | Actual native immutable snapshot pages, exact complete-byte reconstruction, mutation, release, foreign-owner refusal and unchanged cursors/Evidence after cache refusal. |
| `effects_and_recovery` | Normal owner close, active EOF drain, empty new owner and explicit export/import recovery with failed imports preserving evidence. |

The lifecycle v2 consumer's reference deadline observation remains `OPEN`.
The frozen original parses in process, so it has no independent parser-worker
boundary corresponding to the native worker's deadline injection. This profile
requires the native 30-second worker-deadline observation and the original's
actual active-capture cancellation/EOF observations. It does not rename the
native extension as original deadline parity.

Readback is likewise the explicit native
`hepta.evidence-bundle-readback.v1` extension. Snapshot pagination does not add
an API to the frozen original. The three new capacity sequences retain every
actual request/response and canonical export. They prove count, aggregate-byte
and individual-snapshot boundaries with positive release/recovery controls.
They do not observe an active readback encoder's cancellation phase, every
provider, concurrent-fault, remote or cross-platform
case. It establishes explicit import into a new process, not implicit durable
session recovery. The exact exclusions are returned in every assessment.

## Produce and consume one combination

Freeze all implementation, fixture and qualification source first. Run the
unchanged `scripts/rea_full_qualification.py` full matrix with the required
Rust 1.95.0 and nextest 0.9.137. Keep its original summary and all artifacts.
The matrix includes formatting, both full Clippy and isolated nextest feature
configurations, and the actual all-feature native binary build. A custom
successful `cargo build` receipt cannot replace it.

Execute these five runners with that same native binary, exact original
package/Node and source checkout, using a new output directory for each:

1. `scripts/rea_operation_qualification.py` for the unchanged v1 operation.
2. `scripts/rea_elf_evidence_family_qualification.py` for complete retention,
   export/import and native pagination. Its selected real ELF is separately
   pinned and retained; it is not silently replaced with the synthetic fixture.
3. `scripts/rea_lifecycle_qualification.py` for owned active lifecycle v2.
4. `scripts/rea_elf_format_qualification.py` for the fixed format corpus.
5. `scripts/rea_readback_capacity_qualification.py` for native snapshot limits,
   exact accounting, cursor preservation and release recovery.

Supply the full build summary and digest to operation, family, format and capacity.
Supply that exact original summary as the lifecycle binary-source receipt.
Retain the actual failures if a producer cannot finish; a later attempt needs
a separate directory. All component consumers must replay from the final
same-source combination. Earlier source receipts cannot be relabeled.

The index contains only `schema`, `profile`, `operation`, the exact reviewed
`scope`, and five ordered `receipts`: operation, family, lifecycle, format,
readback_capacity.
Each reference contains only `role`, a relative `report` path and `sha256`.
No PASS, counts or gate verdicts are accepted from the index. Put the outputs
under an excluded `docs/qualification/` directory in the selected checkout
when consuming them, preserving the legacy operation consumer's path contract.

```sh
python3 -B scripts/rea_operation_profile_v2.py \
  --repo /absolute/exact-source-checkout \
  --index /absolute/exact-source-checkout/docs/qualification/run/index.json \
  --sha256 ORIGINAL_INDEX_SHA256
```

The consumer first replays each original receipt with its existing independent
validator. It then rejects mismatched source trees, binaries, Node executables
or build summaries, and verifies that lifecycle retained the same authenticated
build summary. Only those derived facts feed the nine gate decisions. A missing
observation remains OPEN. Existing legacy assessments remain included unchanged.

The source implements a qualification mechanism; this document records no
execution pass. Actual run identities, counts, failures and timings belong in
dated evidence. Unit tests exercise byte encodings and consumer refusal rules;
they are not native provider execution evidence.
