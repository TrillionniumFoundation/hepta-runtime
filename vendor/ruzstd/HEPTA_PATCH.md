# Local block bounds and sequence proofs for ruzstd 0.9.1

This directory contains the published ruzstd 0.9.1 crate with the six modified production files listed below and this provenance documentation. Its original license, version and Cargo manifests are retained. The original archive SHA-256 is `69e4ce4a039f42bf25920b95667e4d789e98749ab11bbb8d2c2936f788421bb5`. `UPSTREAM_SOURCE.json` preserves all 64 original file hashes under `upstream_files`, including the original bytes and hashes of modified files; `production_changes` separately records each modified file's upstream and current patched hashes. The remaining 58 original files match their recorded upstream hashes. The registry cache is not modified.

## Current source changes

1. Check the regenerated literal count against min(Window_Size, 128 KiB) before decoding the literals. This also covers the zero-sequence path.
2. Check the sum of executed sequence output and remaining literal tail before appending that tail. The existing per-sequence check alone did not include the final literals.
3. Add an optional caller-selected destination-capacity proof during sequence decoding, with a distinct `OutputCapacityExceeded` error. It tracks literals, decoded output, offset history and whether the preceding sequence prefix remains valid. Later invalid or missing input cannot be interpreted as an arbitrary complete sequence.
4. For incomplete extra fields, use only a lower bound justified by a complete FSE state and the high-order match-length bits actually present. If a complete valid sequence fills the destination and another sequence is declared, the next match has a minimum length of three bytes. Unknown or padded input bits do not establish the proof.

| Modified file | Change from the recorded upstream file |
| --- | --- |
| `src/decoding/block_decoder.rs` | Enforce the decoded literal block bound and connect the optional sequence-capacity proof to compressed-block decoding. |
| `src/decoding/errors.rs` | Add the typed destination-capacity error and its diagnostic. |
| `src/decoding/frame_decoder.rs` | Expose the optional capacity setting and retained output-byte count to the caller. |
| `src/decoding/scratch.rs` | Store the optional capacity and clear it when decoder scratch is reset. |
| `src/decoding/sequence_execution.rs` | Enforce the final literal-tail block bound and share the existing offset-history calculation with the capacity proof. |
| `src/decoding/sequence_section_decoder.rs` | Track validated sequence prefixes and prove capacity exhaustion only from complete lengths or justified lower bounds. |

The first two checks enforce format limits. The optional capacity hook defaults to `None`, persists until changed or decoder reset, and must be updated for each distinct destination. It assumes no external dictionary and does not bound raw blocks or zero-sequence literal copies; it is not a general output-budget API. The Runtime adapter restricts its use to the qualified 64-bit, small-history dispatch described in [ELF Zstandard destination error ordering](../../docs/rea-native/ELF_ZSTD_DESTINATION_DIFFERENTIAL.md). Ordinary format/window limits remain independent. Local changes follow the crate's existing MIT license. No native compression library is linked.

## Source history

| Commit | Contribution |
| --- | --- |
| `27da463554acb7f1b8bf0dc68727e3e1e3ddf062` | Import the recorded upstream crate and add the two complete decoded-block checks. |
| `70811ae0690076238ab89d4f3eb1476e2bc1f06c` | Add typed destination-capacity proofs across the six source files listed above. |
| `e74d2fb2e5e826f4450aad032757789bff8e56b0` | Restrict inference to known input and the caller's qualified decoder dispatch. |
| `56e50b54341e28862723eb4030ee610a06669c56` | Refine incomplete-field proofs to present high-order bit prefixes. |

The consolidation audit found that the original two-file `production_changes` inventory had not been refreshed after the three later commits. The corrected inventory records all six current patched hashes while preserving the original upstream hashes, archive identity and `root_base_commit`. This provenance repair changes no decoder source or frozen qualification evidence.

## Existing qualification boundaries

Independent actual REA 6.8.0 / Node v22.23.4 comparison established two over-limit sequence-tail negatives and three valid boundary/control positives. The root parser regression tests exercise these frames and the zero-sequence block cases directly against this dependency. The original failed comparison remains in the external qualification evidence.

The later destination-error comparison and its exact corpus, source history and remaining limits are recorded in the linked differential checkpoint. This provenance inventory does not rerun or extend those results. The full `inspect_elf_notes` operation, arbitrary malformed Zstd diagnostic equivalence, the full MCP contract, delivery/retention, and native operational limits require their separate gates.

Integration: keep ruzstd =0.9.1 with default-features=false and features std/hash; apply the root [patch.crates-io] entry ruzstd = { path = "vendor/ruzstd" }. Root Cargo.toml and Cargo.lock are maintained by the integration owner.
