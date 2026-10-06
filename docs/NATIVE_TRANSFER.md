# Native binary, remote documents and precise page/range edits

**Current update:** [LOCAL_HANDOFF_AND_FORMATS.md](LOCAL_HANDOFF_AND_FORMATS.md) describes the reviewed rich-render, real calculation, legacy-XLS and metadata-preservation implementation, together with exact handoff/reboot boundaries. Earlier unsupported-status statements below describe historical stages; consult the latest qualification receipt for installation status.
These operations are compiled MCP tools, not shell commands returned to the caller. Controller-local document access remains supported. Supplying an optional configured operator `host` to document tools selects a native version-bound file transfer to the controller parser and, for writes, checked atomic publication back to that host. No caller can provide an SSH destination, interpreter, helper program, file roots or sudo flag.

## Binary tools

- `file_info`: complete SHA256, byte size, POSIX mode and a version token from a regular file on the named operator host.
- `binary_read`: bounded base64 bytes, offsets and chunk SHA256. Pin the first returned `version` in subsequent requests. There is no total-file 1 MiB limit.
- `binary_write`: at most 1 MiB decoded, atomically replaces only the expected destination version. `expected_version: absent` is create-only and does not overwrite a racing creator.
- `binary_upload`: bounded chunks with an explicit upload ID and monotonic byte offsets. Matching chunk replay is accepted; changed replay bytes or gaps are refused. Size/SHA256-checked commit publishes once. Retained receipts let commit retries verify the destination rather than publish again. Abort never deletes committed output.

All target paths are descriptor-relative, and each component is opened without following symlinks. Special files and internal `.hepta-` sidecar destinations are rejected. File locks coordinate these native writers, not arbitrary applications. Source-version checks detect common concurrent changes but are not filesystem-wide compare-and-swap. A transport failure during publication must be reconciled from the destination and receipt. Short/failed uploads do not become visible automatically.

Replacement preserves supported POSIX permissions/group ownership. Destinations with extended attributes/ACLs, special ownership or special permission bits are refused instead of silently degrading metadata. Hard-link identity, creation time, complete metadata preservation and arbitrary symlink traversal are not claimed. New output is private. Files have no artificial total-size cap, but physical disk and operation-time limits still apply.

## Native remote documents and images

`document_read`, `document_write`, `document_edit` and `image_read` accept optional `host` and an absolute path on that host. Omit `host` for controller-local behavior. Configured read/write roots are checked before transfer and again by the descriptor-relative helper. Complete file SHA256 and version-bound chunks protect reads. Parser execution still uses the fixed administrator-selected isolated Python worker and its existing memory/time/result limits.

New content and edits are constructed privately before publication. Existing remote sources must match expected SHA256; the final write is additionally bound to their captured file version. Failures before publication leave the destination unchanged. Local parser scratch paths are not presented as target file locations. Output metadata identifies the actual host and native transfer path. Images return native MCP image blocks; bounded previews are not a lossless replacement for original bytes, which remain available via binary tools.

Document size remains capped at 32 MiB; binary transfer is the separate large-file path. The worker never executes document macros or downloads URLs. Files already containing active content are not declared safe merely because they can be read. This is trusted-account functionality, not a parser sandbox proof.

## PDF page editing

`pdf_edit` takes source and output fingerprints, a distinct `output_path`, and typed delete/insert operations. Insert accepts either basic markdown text or a source PDF plus its SHA256. Operations use zero-based indexes in the evolving page order. The original PDF is retained. Local and configured-host PDFs use the same native interface. Signed/encrypted sources are refused; an empty result, stale input and invalid page indexes fail without publication.

Page deletion is **not secure redaction**. Preservation of every PDF feature, signature, HTML/CSS/SVG rendering option and external attachment behavior is not claimed. Visual page rendering is part of qualification, separate from the parser's structural success.

## Worksheet range editing

`worksheet_edit` edits a bounded XLSX/XLSM range with a mandatory source SHA256, locally or on a named operator host. It patches selected OOXML worksheet cells rather than regenerating the entire workbook through a partial object model. Unselected package payloads and cell styles are retained. Ordinary scalar cells and formula strings are supported. Signed packages, merged sheets and special/shared/array formula layouts are refused.

Formula caches can become stale after any edit. The operation invalidates formula caches across worksheets, discards the old calculation chain where present, and requests calculation on open. It returns `formulas_recalculated: false` and `recalculation_required: true`. This is not a calculation engine; empty caches must not be represented as calculated results. Legacy XLS, full spreadsheet editing and automatic recalculation remain separate qualification items.

## Qualification and deployment

`tests/binary_file_tests.py` uses disposable filesystem fixtures. `tests/document_extended_tests.py` checks exact source/package preservation, errors, PDF rendering and remote publication logic. `tests/native_transport_acceptance.py` exercises actual authenticated MCP, target SSH, binary upload/download, remote DOCX, native remote image blocks, PDF page edits/renders and worksheet edits. `--url/--token-file/--host` runs that suite on an existing installed endpoint without changing its configuration.

Run the full six-host operator/lifecycle suite on the exact release, not only the new tests. Before an upgrade inspect active sessions; retain the old executable/unit/manifest and execute rollback qualification. A physical reboot requires a safe target workload state; never interrupt unrelated compilation, trading or generation merely to mark the reboot test complete. ChatGPT connection stays outside this stage.
