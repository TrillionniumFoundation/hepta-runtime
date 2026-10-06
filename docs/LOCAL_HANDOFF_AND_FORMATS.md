# Local handoff, physical restart, rich formats and metadata

This stage intentionally excludes ChatGPT custom-app/tunnel/workspace configuration. The exact release and installed-service receipts, not this feature description alone, establish qualification. Preserve Desktop Commander as the old-session and rescue route until required application work has been checkpointed or drained.

## Real physical restart scope

The X230 acceptance script checks the specific physical host and refuses active business workloads or containers. Only after an idle runner is paused and a second check passes are disposable durable-job and PTY fixtures started. A final workload check excludes only these exact fixtures, then requests an actual systemd reboot. It verifies a changed kernel boot ID, retained archive hashes, interrupted rather than duplicated old commands, successful new execution, and automatic runner/network-recovery service return. The controller and DC computer are not rebooted.

A recorded successful reboot is not a cold power-off/power-on cycle. The successful receipt identifies the installed controller artifact used at that time. Subsequent independent checks may revalidate the same boot and archives without repeating an unnecessary disruptive reboot. Never relabel a simulated boot-ID change as a physical reboot or imply that a running application survives target power loss.

## DC application handoff

A PID alone cannot transfer DC's live pipes, in-memory buffers or application state. Applications that expose checkpoints can be handed over with a concrete procedure: commit pending effects and output, save and verify a checkpoint, exit the old owner normally, then resume the same application state through a persistent native terminal or job. Commands already recorded in the checkpoint must not be executed a second time.

The disposable `checkpoint_handoff_fixture.py` and `checkpoint_handoff_acceptance.py` demonstrate this contract. The actual old process is started through DC; two uniquely identified effects produce total 5 and a fsynced journal/checkpoint. It exits cleanly. Native local MCP resumes the journal, refuses overlapping ownership, recognizes a replayed command, and appends only one new effect, producing total 12 with exactly three unique effects. The original journal bytes remain an exact prefix. This is a real application-supported checkpoint handoff, not transparent process reparenting or proof that every third-party application supports checkpoints.

`deploy/operator-call.py` provides a local native MCP client without DC protocol or a cloud connection. It takes one `{name, arguments}` JSON request from stdin and returns the native MCP result. It reads the existing private token directly from the installed configuration, never from command-line arguments. Each call has an explicit response identity and bounded output. Jobs and terminals belong to the runtime, not the short-lived client. A DC command may launch the CLI during qualification; that launch does not make the continued native job a DC-owned process.

Old business sessions that have already exited are recorded as drained, not artificially kept as migration blockers. Newly appearing concurrent sessions are inspected and retained, not killed to make a checklist green. Unrecoverable old DC output or unsupported application state must be declared, not reconstructed from guesses.

## Metadata-preserving replacement

The native binary and document publication paths share `file_metadata.py`. Before publication it captures UID, GID, mode, extended attributes and access-control lists through open file descriptors. Linux POSIX ACL attributes are applied after ordinary attributes, and Darwin uses descriptor-based copyfile/ACL operations. It verifies the target metadata and confirms that the source did not change before allowing publication. Metadata summaries contain names and hashes, not raw attribute values.

No permissions are granted to make a test pass: copying ownership or ACLs still requires the target account's existing OS rights. If exact preservation fails, the old destination remains unchanged. New files remain private. A content edit intentionally changes normal modification/change timestamps; this is not a backup-format promise to reproduce every timestamp or inode.

Atomic replacement of one name cannot preserve all hard-link identities. Hard-linked files, special execution/immutable flags and executable capabilities remain explicitly refused rather than silently split, cleared or propagated onto changed content. These restrictions describe unsupported semantics; they are not a claim of universal filesystem-copy parity.

## Rich PDF rendering and legacy XLS reads

`document_render` accepts HTML, Markdown or inline SVG and optional CSS. It produces PDF via the pinned WeasyPrint worker. Images/SVG/CSS resources must be explicitly listed as policy-checked, SHA256-bound assets referenced by `asset:name`. Implicit URL/local-file resources and active document elements are rejected. The fixed worker enforces resource, page, memory, CPU and response limits. Render warnings are returned. JavaScript execution, arbitrary browser behavior and pixel-identical output to a browser are not promised.

`document_read` now also reads legacy `.xls` sheets, including Unicode/scalar/date values and number formats. Legacy formula results are the stored results present in that file; formula-source extraction, macros and embedded-object execution are not performed. Exact original bytes remain available through binary reads.

## Genuine spreadsheet recalculation

`worksheet_recalculate` uses the pinned offline `formulas` engine to evaluate supported ordinary XLSX/XLSM formulas and writes actual calculated caches while preserving formula texts and unselected OOXML payloads. It is not a request for another application to calculate later. Cross-sheet dependencies, numbers, booleans, strings, blanks and error propagation are tested. Literal strings such as `="#N/A"` are distinguished from real Excel error tokens, including in the written OOXML cell type.

The accepted scope is deliberately explicit: bounded cells/dependency ranges and ordinary scalar formulas using the 1900 date system. Named ranges, external workbooks, 1904-date-system recalculation, shared/array/spilling formulas, circular references and dynamic/volatile or unsupported functions are refused before publication. No macros, custom caller functions, URLs or office process are executed. Formula-error count and individual error locations are returned rather than reported as successful numeric values. This implementation does not claim the Microsoft Excel calculation engine or universal workbook compatibility.

The dedicated parser environment is versioned separately from the older environment. Deployment must preserve the old parser and service drop-in for rollback, validate the new parser imports, and qualify the paired release after switching. Scientific libraries are restricted to one thread before import to keep the existing worker memory budget meaningful.
